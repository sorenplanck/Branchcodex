//! Durable encrypted custody for a single exact DOM/XMR recovery graph.
//!
//! This reuses the Store's retained Linux filesystem and exclusive lock boundary.
//! It is intentionally separate from the nonce/signing SessionStore inventory:
//! retaining recovery bytes does not mint a signing or broadcast capability.
//! An authenticated graph must be completely retained before DOM collateral is
//! armed; the chain observer must then confirm that collateral before XMR lock.

use super::{LinuxCapabilityError, RetainedDirectory, RetainedExclusiveLock, ValidatedComponent};
use cap_std::fs::Dir;
use dom_crypto::blake2b_256;
use dom_scriptless_crypto::{
    open_xmr_recovery_archive_v11, seal_xmr_recovery_archive_v11, OpenedXmrRecoveryArchiveV11,
    PrivateXmrRefundTransactionV11, VerifiedXmrRecoveryGraphV11, XmrRecoveryArchiveErrorV11,
    XmrRecoveryGraphBindingV11, XmrRecoverySealKeyV11, XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11,
};
use std::sync::Arc;

mod atomic_creation_v23;
mod execution_v12;

pub(super) fn is_registered_v22_component(name: &str) -> bool {
    matches!(
        name,
        "xmr-funding-observed-v22.bin" | ".xmr-funding-observed-v22.staging"
    )
}
pub use execution_v12::{
    PreparedXmrRecoveryAttemptV12, XmrRecoveryObservedExitV12, XmrRecoveryOperationV12,
};

const SCOPE_NAME: &str = "xmr-recovery-scope-v11.bin";
const LOCK_NAME: &str = "xmr-recovery-lock-v11.bin";
const ARCHIVE_NAME: &str = "xmr-recovery-archive-v11.bin";
const STAGING_NAME: &str = ".xmr-recovery-archive-v11.staging";
const SCOPE_MAGIC: &[u8; 8] = b"DOMXRSC1";
const SCOPE_LEN: usize = 8 + 1 + 5 * 32;

/// Expected owner profile, frozen before the initial retention. A counterparty
/// archive cannot silently acquire a private final refund on replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrRecoveryCustodyRoleV11 {
    /// Local share U owner: retains the adapted refund privately.
    PrivateRefundOwner,
    /// Local share T owner: retains only public cancel/punish and pre-signature.
    PublicCounterparty,
}

/// Externally authenticated exact scope. It is evidence requested by the caller,
/// never sufficient by itself to authorize funding or declare collateral armed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XmrRecoveryCustodyScopeV11 {
    /// Native public graph fields negotiated by both parties.
    pub binding: XmrRecoveryGraphBindingV11,
    /// Exact digest obtained from native graph verification.
    pub graph_digest: [u8; 32],
    /// Nonzero persistent identity of this selected leg's custody directory.
    pub custody_id: [u8; 32],
    /// Expected local private-share role.
    pub role: XmrRecoveryCustodyRoleV11,
}

/// Missing storage is distinct from substituted scope or invalid retained bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmrRecoveryCustodyErrorV11 {
    /// Required directory, companion file, or committed archive is absent.
    NotFound,
    /// An existing exact scope/archive differs from the requested session.
    Conflict,
    /// The sole retained directory lock belongs to another process.
    Busy,
    /// An inode, owner, mode, link, inventory or immutable record is invalid.
    InvalidStorage,
    /// An underlying retained filesystem primitive failed or is unavailable.
    Unavailable,
    /// Authenticated decryption or native recovery evidence verification failed.
    InvalidArchive,
}

impl core::fmt::Display for XmrRecoveryCustodyErrorV11 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "XMR recovery custody is absent",
            Self::Conflict => "XMR recovery custody scope conflicts",
            Self::Busy => "XMR recovery custody is already owned",
            Self::InvalidStorage => "XMR recovery custody storage is invalid",
            Self::Unavailable => "XMR recovery custody storage is unavailable",
            Self::InvalidArchive => "XMR recovery custody archive failed verification",
        })
    }
}

impl std::error::Error for XmrRecoveryCustodyErrorV11 {}
impl From<LinuxCapabilityError> for XmrRecoveryCustodyErrorV11 {
    fn from(error: LinuxCapabilityError) -> Self {
        match error {
            LinuxCapabilityError::NotFound => Self::NotFound,
            LinuxCapabilityError::AlreadyExists => Self::Conflict,
            LinuxCapabilityError::StoreBusy => Self::Busy,
            LinuxCapabilityError::OperationFailed { .. }
            | LinuxCapabilityError::UnsupportedFilesystem => Self::Unavailable,
            _ => Self::InvalidStorage,
        }
    }
}
impl From<XmrRecoveryArchiveErrorV11> for XmrRecoveryCustodyErrorV11 {
    fn from(_: XmrRecoveryArchiveErrorV11) -> Self {
        Self::InvalidArchive
    }
}
type Result<T> = core::result::Result<T, XmrRecoveryCustodyErrorV11>;

/// Sole locked owner of immutable recovery custody for one selected leg.
/// No method signs, grants funding, exposes a scalar or broadcasts a transaction.
/// Private byte access below is for a separately authorized execution boundary.
pub struct XmrRecoveryCustodyV11 {
    root: RetainedDirectory,
    retained_lock: RetainedExclusiveLock,
    scope: XmrRecoveryCustodyScopeV11,
    scope_bytes: Vec<u8>,
    envelope_digest: [u8; 32],
    archive: OpenedXmrRecoveryArchiveV11,
}

impl XmrRecoveryCustodyV11 {
    /// Create and durably publish the complete recovery archive. The parent is
    /// an already selected capability; this never opens an ambient path. A
    /// partial initialization before publication does not authorize any funding.
    pub fn create(
        parent: Dir,
        root_name: &str,
        scope: XmrRecoveryCustodyScopeV11,
        graph: &VerifiedXmrRecoveryGraphV11,
        key: XmrRecoverySealKeyV11,
        private_refund: Option<&PrivateXmrRefundTransactionV11>,
    ) -> Result<Self> {
        Self::create_with_key_v23(parent, root_name, scope, graph, &key, private_refund)
    }

    fn create_with_key_v23(
        parent: Dir,
        root_name: &str,
        scope: XmrRecoveryCustodyScopeV11,
        graph: &VerifiedXmrRecoveryGraphV11,
        key: &XmrRecoverySealKeyV11,
        private_refund: Option<&PrivateXmrRefundTransactionV11>,
    ) -> Result<Self> {
        let scope_bytes = encode_scope(scope)?;
        if graph.binding() != &scope.binding
            || graph.graph_digest() != &scope.graph_digest
            || private_refund.is_some()
                != matches!(scope.role, XmrRecoveryCustodyRoleV11::PrivateRefundOwner)
        {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        // Validate and seal before creating any persistent state. In particular
        // a wrong U/private signature cannot leave an apparently initialized root.
        let envelope =
            seal_xmr_recovery_archive_v11(graph, scope.custody_id, &key, private_refund)?;
        let archive = open_archive(scope, &key, &envelope)?;
        let root = RetainedDirectory::create_under(
            Arc::new(parent),
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        root.create_immutable_file(&ValidatedComponent::registered(SCOPE_NAME)?, &scope_bytes)?;
        root.create_immutable_file(
            &ValidatedComponent::registered(LOCK_NAME)?,
            blake2b_256(&scope_bytes).as_bytes(),
        )?;
        let retained_lock = root.acquire_lock(&ValidatedComponent::registered(LOCK_NAME)?)?;
        let staging_component = ValidatedComponent::registered(STAGING_NAME)?;
        let staging = root.create_immutable_file(&staging_component, &envelope)?;
        root.rename_no_replace(
            &staging_component,
            &ValidatedComponent::registered(ARCHIVE_NAME)?,
            &staging,
        )?;
        let owner = Self {
            root,
            retained_lock,
            scope,
            scope_bytes,
            envelope_digest: *blake2b_256(&envelope).as_bytes(),
            archive,
        };
        owner.revalidate()?;
        Ok(owner)
    }

    /// Resume only existing custody. Missing directories/files are never
    /// replaced with new keys or an empty record. If a complete authenticated
    /// staged envelope survived a crash, finish its exact no-replace publication.
    /// A truncated stage is a hard refusal, not permission to change the graph.
    pub fn open_existing(
        parent: Dir,
        root_name: &str,
        scope: XmrRecoveryCustodyScopeV11,
        key: XmrRecoverySealKeyV11,
    ) -> Result<Self> {
        let scope_bytes = encode_scope(scope)?;
        let root = RetainedDirectory::open_under(
            Arc::new(parent),
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        let retained_lock = root.acquire_lock(&ValidatedComponent::registered(LOCK_NAME)?)?;
        require_scope_files(&root, &scope_bytes)?;
        let (final_exists, staged_exists) = inventory(&root)?;
        if final_exists && staged_exists {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        let name = if final_exists {
            ARCHIVE_NAME
        } else if staged_exists {
            STAGING_NAME
        } else {
            return Err(XmrRecoveryCustodyErrorV11::NotFound);
        };
        let component = ValidatedComponent::registered(name)?;
        let mut retained = root.open_file(&component, false)?;
        let envelope = retained.read_bounded(XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11)?;
        let archive = open_archive(scope, &key, &envelope)?;
        root.require_named_file_identity(&component, &retained)?;
        // Decryption and native graph verification finish before any recovery write.
        if staged_exists {
            root.rename_no_replace(
                &component,
                &ValidatedComponent::registered(ARCHIVE_NAME)?,
                &retained,
            )?;
        }
        let owner = Self {
            root,
            retained_lock,
            scope,
            scope_bytes,
            envelope_digest: *blake2b_256(&envelope).as_bytes(),
            archive,
        };
        owner.revalidate()?;
        Ok(owner)
    }

    /// Exact retained scope, for the parent Store's admission and journal link.
    pub const fn scope(&self) -> &XmrRecoveryCustodyScopeV11 {
        &self.scope
    }

    /// Inspect freshly checked native evidence. This also revalidates named
    /// inodes and the immutable ciphertext before giving it to the caller.
    pub fn with_graph<R>(
        &self,
        operation: impl FnOnce(&VerifiedXmrRecoveryGraphV11) -> R,
    ) -> Result<R> {
        self.revalidate()?;
        Ok(operation(self.archive.graph()))
    }

    /// Keep the completed U refund private while it crosses the authorized
    /// execution boundary. This custody check does not substitute for fresh
    /// canonical finality of cancel, unspent D, or a Store reveal-window permit.
    pub fn with_private_refund<R>(
        &self,
        operation: impl FnOnce(&PrivateXmrRefundTransactionV11) -> R,
    ) -> Result<R> {
        self.revalidate()?;
        self.archive.with_private_refund(|private| {
            let private = private.ok_or(XmrRecoveryCustodyErrorV11::Conflict)?;
            Ok(operation(private))
        })
    }

    /// Revalidate the exact retained filesystem ownership and immutable bytes.
    /// No state transition or submission authority is issued by this method.
    pub fn revalidate(&self) -> Result<()> {
        self.root.revalidate()?;
        self.retained_lock.revalidate()?;
        require_scope_files(&self.root, &self.scope_bytes)?;
        if inventory(&self.root)? != (true, false) {
            return Err(XmrRecoveryCustodyErrorV11::InvalidStorage);
        }
        let envelope = self.root.read_bounded_file(
            &ValidatedComponent::registered(ARCHIVE_NAME)?,
            XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11,
        )?;
        if blake2b_256(&envelope).as_bytes() != &self.envelope_digest {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        Ok(())
    }
}

fn open_archive(
    scope: XmrRecoveryCustodyScopeV11,
    key: &XmrRecoverySealKeyV11,
    envelope: &[u8],
) -> Result<OpenedXmrRecoveryArchiveV11> {
    let archive = open_xmr_recovery_archive_v11(
        scope.binding,
        scope.graph_digest,
        scope.custody_id,
        key,
        envelope,
    )?;
    if archive.has_private_refund()
        != matches!(scope.role, XmrRecoveryCustodyRoleV11::PrivateRefundOwner)
    {
        return Err(XmrRecoveryCustodyErrorV11::Conflict);
    }
    Ok(archive)
}

fn encode_scope(scope: XmrRecoveryCustodyScopeV11) -> Result<Vec<u8>> {
    if [
        scope.binding.chain_id,
        scope.binding.session_id,
        scope.binding.terms_hash,
        scope.graph_digest,
        scope.custody_id,
    ]
    .iter()
    .any(|value| *value == [0; 32])
    {
        return Err(XmrRecoveryCustodyErrorV11::Conflict);
    }
    let mut out = Vec::with_capacity(SCOPE_LEN);
    out.extend_from_slice(SCOPE_MAGIC);
    out.push(match scope.role {
        XmrRecoveryCustodyRoleV11::PrivateRefundOwner => 1,
        XmrRecoveryCustodyRoleV11::PublicCounterparty => 2,
    });
    for bytes in [
        scope.binding.chain_id,
        scope.binding.session_id,
        scope.binding.terms_hash,
        scope.graph_digest,
        scope.custody_id,
    ] {
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn require_scope_files(root: &RetainedDirectory, scope: &[u8]) -> Result<()> {
    if root.read_bounded_file(&ValidatedComponent::registered(SCOPE_NAME)?, SCOPE_LEN)? != scope
        || root.read_bounded_file(&ValidatedComponent::registered(LOCK_NAME)?, 32)?
            != blake2b_256(scope).as_bytes()
    {
        return Err(XmrRecoveryCustodyErrorV11::Conflict);
    }
    Ok(())
}

fn inventory(root: &RetainedDirectory) -> Result<(bool, bool)> {
    let mut names = [false; 4];
    root.scan_independent(|name, _identity| {
        if execution_v12::is_execution_component_v12(name) {
            return Ok(());
        }
        let index = match name {
            SCOPE_NAME => 0,
            LOCK_NAME => 1,
            ARCHIVE_NAME => 2,
            STAGING_NAME => 3,
            _ => return Err(LinuxCapabilityError::InvalidDirectoryEntry),
        };
        if names[index] {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        names[index] = true;
        Ok(())
    })?;
    if !names[0] || !names[1] {
        return Err(XmrRecoveryCustodyErrorV11::NotFound);
    }
    Ok((names[2], names[3]))
}
