//! Fixed, secret-free write-ahead records for native XMR recovery execution.
//! Records retain exact identities, never U or a final refund signature.

use super::super::session_store::VerifiedXmrRecoveryExecutionAuthorityV12;
use super::*;
use dom_scriptless_chain_adapter::{canonical_transaction_hash_v1, SubmissionReceiptV1};

const RECORD_MAGIC: &[u8; 8] = b"DOMXRE12";
const RECORD_LEN: usize = 8 + 2 + 7 * 32;
const EXIT_NAME: &str = "xmr-exit-observed-v12.bin";
const EXIT_STAGING: &str = ".xmr-exit-observed-v12.staging";

/// Public DOM exit which the native observer has reported. This journal tag
/// carries no claim that XMR was swept, and is never a funding authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrRecoveryObservedExitV12 {
    /// Canonical DOM adaptor refund exposed U; XMR sweeping is a later action.
    DomRefundShareRevealed,
    /// Canonical ordinary DOM compensation, without XMR refund or T exposure.
    DomCompensated,
}

/// Exactly one signed transaction in the negotiated C -> D recovery graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrRecoveryOperationV12 {
    /// Ordinary height-locked C -> D cancellation, which exposes neither share.
    Cancel,
    /// Private final adaptor refund D -> DOM funder, exposing U at submission.
    Refund,
    /// Ordinary D -> XMR funder payment: compensation in DOM, without T or U.
    Compensate,
}

impl XmrRecoveryOperationV12 {
    fn tag(self) -> u8 {
        match self {
            Self::Cancel => 1,
            Self::Refund => 2,
            Self::Compensate => 3,
        }
    }
    fn names(self, admitted: bool) -> (&'static str, &'static str) {
        match (self, admitted) {
            (Self::Cancel, false) => (
                "xmr-cancel-attempt-v12.bin",
                ".xmr-cancel-attempt-v12.staging",
            ),
            (Self::Refund, false) => (
                "xmr-refund-attempt-v12.bin",
                ".xmr-refund-attempt-v12.staging",
            ),
            (Self::Compensate, false) => (
                "xmr-compensate-attempt-v12.bin",
                ".xmr-compensate-attempt-v12.staging",
            ),
            (Self::Cancel, true) => (
                "xmr-cancel-admitted-v12.bin",
                ".xmr-cancel-admitted-v12.staging",
            ),
            (Self::Refund, true) => (
                "xmr-refund-admitted-v12.bin",
                ".xmr-refund-admitted-v12.staging",
            ),
            (Self::Compensate, true) => (
                "xmr-compensate-admitted-v12.bin",
                ".xmr-compensate-admitted-v12.staging",
            ),
        }
    }
}

/// Same-custody immutable write-ahead identity, issued only after fsync.
/// This does not authorize transmission without the runtime's fresh graph scan.
pub struct PreparedXmrRecoveryAttemptV12 {
    scope: XmrRecoveryCustodyScopeV11,
    funding_tx_hash: [u8; 32],
    operation: XmrRecoveryOperationV12,
    transaction_hash: [u8; 32],
}

impl PreparedXmrRecoveryAttemptV12 {
    /// Exact requested graph operation.
    pub const fn operation(&self) -> XmrRecoveryOperationV12 {
        self.operation
    }
    /// Canonical hash derived from the retained native transaction bytes.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
}

impl XmrRecoveryCustodyV11 {
    /// Persist the first actual XMR funding observation separately from a send
    /// attempt. This is historical audit data, never fresh spend authority.
    /// A restart still requires a new exact quorum/view-key observation.
    pub fn retain_xmr_funding_observed_v22(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
    ) -> Result<()> {
        self.revalidate()?;
        authority
            .require_custody(self)
            .map_err(|_| XmrRecoveryCustodyErrorV11::Conflict)?;
        let proof = authority
            .xmr_funding_observation_v22()
            .map_err(|_| XmrRecoveryCustodyErrorV11::Conflict)?;
        let mut bytes = b"DOM-XMR-FUNDING-OBSERVED-V22\0".to_vec();
        for value in [
            authority.chain_id(),
            authority.session_id(),
            authority.terms_hash(),
            authority.graph_digest(),
            authority.custody_id(),
            authority.funding_tx_hash(),
            authority.xmr_setup_binding_hash(),
            authority.xmr_funding_tx_hash(),
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&proof.output_index().to_be_bytes());
        let binding_len = bytes.len();
        bytes.extend_from_slice(proof.block_hash());
        bytes.extend_from_slice(&proof.block_height().to_be_bytes());
        bytes.extend_from_slice(&proof.confirmations().to_be_bytes());
        bytes.extend_from_slice(proof.evidence_digest());
        bytes.extend_from_slice(blake2b_256(&bytes).as_bytes());
        let name = "xmr-funding-observed-v22.bin";
        let staging = ".xmr-funding-observed-v22.staging";
        for (component_name, is_staging) in [(name, false), (staging, true)] {
            let component = ValidatedComponent::registered(component_name)?;
            match self.root.open_file(&component, false) {
                Ok(mut file) => {
                    let old = file.read_bounded(bytes.len())?;
                    self.root.require_named_file_identity(&component, &file)?;
                    if old.len() == bytes.len() {
                        if old[..binding_len] != bytes[..binding_len]
                            || blake2b_256(&old[..old.len() - 32]).as_bytes()
                                != &old[old.len() - 32..]
                        {
                            return Err(XmrRecoveryCustodyErrorV11::Conflict);
                        }
                        // Preserve the first complete observation. A later tip
                        // or reorg does not rewrite historical audit evidence.
                        return publish_exact_record(&self.root, name, staging, &old);
                    }
                    if !is_staging || !bytes.starts_with(&old) {
                        return Err(XmrRecoveryCustodyErrorV11::Conflict);
                    }
                    self.root.unlink_verified_file(&component, &file)?;
                }
                Err(LinuxCapabilityError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        publish_exact_record(&self.root, name, staging, &bytes)
    }

    /// Fsync a secret-free identity for the privately retained XMR candidate.
    /// This marker is audit data only: neither it nor a raw digest authorizes
    /// broadcast, establishes Monero finality, or enables DOM compensation.
    /// The concrete funding producer verifies the signed candidate independently
    /// and must obtain fresh canonical DOM collateral after this write.
    pub fn retain_xmr_funding_attempt_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        setup_hash: [u8; 32],
        xmr_transaction_hash: [u8; 32],
        raw_fingerprint: [u8; 32],
    ) -> Result<()> {
        self.revalidate()?;
        authority
            .require_custody(self)
            .map_err(|_| XmrRecoveryCustodyErrorV11::Conflict)?;
        if self.scope.role != XmrRecoveryCustodyRoleV11::PublicCounterparty
            || [setup_hash, xmr_transaction_hash, raw_fingerprint].contains(&[0; 32])
            || setup_hash != authority.xmr_setup_binding_hash()
            || xmr_transaction_hash != authority.xmr_funding_tx_hash()
        {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        let mut bytes = b"DOM-XMR-PRIVATE-FUNDING-ATTEMPT-V12\0".to_vec();
        for value in [
            authority.chain_id(),
            authority.session_id(),
            authority.terms_hash(),
            authority.graph_digest(),
            authority.custody_id(),
            authority.funding_tx_hash(),
            setup_hash,
            xmr_transaction_hash,
            raw_fingerprint,
        ] {
            bytes.extend_from_slice(&value);
        }
        publish_exact_record(
            &self.root,
            "xmr-funding-attempt-v12.bin",
            ".xmr-funding-attempt-v12.staging",
            &bytes,
        )
    }

    /// Persist a public observation checkpoint before returning an economic
    /// exit to the route coordinator. This is audit storage, not finality:
    /// reopening MUST re-observe the exact graph through the native scanner.
    /// Only that opaque fresh observation can authorize route completion.
    /// A different terminal tx or exit tag conflicts with retained history.
    pub fn retain_recovery_exit_checkpoint_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        exit: XmrRecoveryObservedExitV12,
        transaction_hash: [u8; 32],
        finality_digest: [u8; 32],
    ) -> Result<()> {
        self.revalidate()?;
        authority
            .require_custody(self)
            .map_err(|_| XmrRecoveryCustodyErrorV11::Conflict)?;
        if transaction_hash == [0; 32] || finality_digest == [0; 32] {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        let operation = match exit {
            XmrRecoveryObservedExitV12::DomRefundShareRevealed => XmrRecoveryOperationV12::Refund,
            XmrRecoveryObservedExitV12::DomCompensated => XmrRecoveryOperationV12::Compensate,
        };
        if operation == XmrRecoveryOperationV12::Compensate
            || self.scope.role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner
        {
            if transaction_hash != self.recovery_transaction_hash_v12(operation)? {
                return Err(XmrRecoveryCustodyErrorV11::Conflict);
            }
        }
        let attempt = PreparedXmrRecoveryAttemptV12 {
            scope: self.scope,
            funding_tx_hash: authority.funding_tx_hash(),
            operation,
            transaction_hash,
        };
        let mut bytes = record_bytes(&attempt, false);
        // Separate record-class domain: an observation is not a locally
        // submitted transaction, and never manufactures a broadcast marker.
        bytes[9] = 2;
        bytes.extend_from_slice(&finality_digest);
        let checksum = *blake2b_256(&bytes).as_bytes();
        bytes.extend_from_slice(&checksum);
        let component = ValidatedComponent::registered(EXIT_NAME)?;
        match self.root.read_bounded_file(&component, RECORD_LEN + 64) {
            Ok(existing) => {
                if existing.len() != RECORD_LEN + 64
                    || existing[..RECORD_LEN] != bytes[..RECORD_LEN]
                    || blake2b_256(&existing[..RECORD_LEN + 32]).as_bytes()
                        != &existing[RECORD_LEN + 32..]
                {
                    return Err(XmrRecoveryCustodyErrorV11::Conflict);
                }
                // Keep the first exact checkpoint. A later valid snapshot has
                // a different tip/evidence digest without changing the exit.
                Ok(())
            }
            Err(LinuxCapabilityError::NotFound) => {
                let staging = ValidatedComponent::registered(EXIT_STAGING)?;
                match self.root.open_file(&staging, false) {
                    Ok(mut retained) => {
                        let old = retained.read_bounded(RECORD_LEN + 64)?;
                        self.root.require_named_file_identity(&staging, &retained)?;
                        if old.len() == RECORD_LEN + 64 {
                            if old[..RECORD_LEN] != bytes[..RECORD_LEN]
                                || blake2b_256(&old[..RECORD_LEN + 32]).as_bytes()
                                    != &old[RECORD_LEN + 32..]
                            {
                                return Err(XmrRecoveryCustodyErrorV11::Conflict);
                            }
                            // Preserve a complete old snapshot even when the
                            // fresh native scan now has a later tip.
                            return publish_exact_record(&self.root, EXIT_NAME, EXIT_STAGING, &old);
                        }
                        let stable = old.len().min(RECORD_LEN);
                        if old[..stable] != bytes[..stable] {
                            return Err(XmrRecoveryCustodyErrorV11::Conflict);
                        }
                        // Only a proper, non-authoritative audit prefix is
                        // discarded. Fresh canonical evidence is required by
                        // the native observer before it calls this method.
                        self.root.unlink_verified_file(&staging, &retained)?;
                    }
                    Err(LinuxCapabilityError::NotFound) => {}
                    Err(error) => return Err(error.into()),
                }
                publish_exact_record(&self.root, EXIT_NAME, EXIT_STAGING, &bytes)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Write the exact selected operation before any RPC call. An interrupted
    /// write can resume only its exact public prefix, under the retained lock.
    /// The final refund stays in encrypted custody and is never journaled.
    pub fn prepare_recovery_attempt_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        operation: XmrRecoveryOperationV12,
    ) -> Result<PreparedXmrRecoveryAttemptV12> {
        self.revalidate()?;
        authority
            .require_custody(self)
            .map_err(|_| XmrRecoveryCustodyErrorV11::Conflict)?;
        require_operation_role(self.scope.role, operation)?;
        let transaction_hash = self.recovery_transaction_hash_v12(operation)?;
        let attempt = PreparedXmrRecoveryAttemptV12 {
            scope: self.scope,
            funding_tx_hash: authority.funding_tx_hash(),
            operation,
            transaction_hash,
        };
        self.retain_execution_record_v12(&attempt, false)?;
        Ok(attempt)
    }

    /// Retain economic admission only from the real chain adapter's opaque
    /// receipt for exactly the write-ahead transaction. A changed txid is a
    /// hard conflict; a timeout creates no receipt and leaves the attempt live.
    pub fn retain_recovery_admission_v12(
        &self,
        attempt: &PreparedXmrRecoveryAttemptV12,
        receipt: &SubmissionReceiptV1,
    ) -> Result<()> {
        self.require_attempt_v12(attempt)?;
        if receipt.tx_hash() != attempt.transaction_hash || !receipt.is_economically_admitted() {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        self.retain_execution_record_v12(attempt, true)
    }

    /// Revalidate a write-ahead identity against exact retained custody and its
    /// durable marker. Neither a caller-provided hash nor missing marker works.
    pub fn require_attempt_v12(&self, attempt: &PreparedXmrRecoveryAttemptV12) -> Result<()> {
        self.revalidate()?;
        if attempt.scope != self.scope
            || attempt.funding_tx_hash == [0; 32]
            || attempt.transaction_hash != self.recovery_transaction_hash_v12(attempt.operation)?
        {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        let component = ValidatedComponent::registered(attempt.operation.names(false).0)?;
        if self.root.read_bounded_file(&component, RECORD_LEN)? != record_bytes(attempt, false) {
            return Err(XmrRecoveryCustodyErrorV11::Conflict);
        }
        Ok(())
    }

    fn recovery_transaction_hash_v12(
        &self,
        operation: XmrRecoveryOperationV12,
    ) -> Result<[u8; 32]> {
        match operation {
            XmrRecoveryOperationV12::Cancel => {
                canonical_transaction_hash_v1(self.archive.graph().cancel_bytes())
                    .map_err(|_| XmrRecoveryCustodyErrorV11::InvalidArchive)
            }
            XmrRecoveryOperationV12::Compensate => {
                canonical_transaction_hash_v1(self.archive.graph().punish_bytes())
                    .map_err(|_| XmrRecoveryCustodyErrorV11::InvalidArchive)
            }
            XmrRecoveryOperationV12::Refund => {
                self.with_private_refund(|private| *private.transaction_hash())
            }
        }
    }

    fn retain_execution_record_v12(
        &self,
        attempt: &PreparedXmrRecoveryAttemptV12,
        admitted: bool,
    ) -> Result<()> {
        let (name, staging) = attempt.operation.names(admitted);
        publish_exact_record(&self.root, name, staging, &record_bytes(attempt, admitted))
    }
}

fn require_operation_role(
    role: XmrRecoveryCustodyRoleV11,
    operation: XmrRecoveryOperationV12,
) -> Result<()> {
    match (role, operation) {
        (_, XmrRecoveryOperationV12::Cancel)
        | (XmrRecoveryCustodyRoleV11::PrivateRefundOwner, XmrRecoveryOperationV12::Refund)
        | (XmrRecoveryCustodyRoleV11::PublicCounterparty, XmrRecoveryOperationV12::Compensate) => {
            Ok(())
        }
        _ => Err(XmrRecoveryCustodyErrorV11::Conflict),
    }
}

fn record_bytes(attempt: &PreparedXmrRecoveryAttemptV12, admitted: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_LEN);
    out.extend_from_slice(RECORD_MAGIC);
    out.push(attempt.operation.tag());
    out.push(u8::from(admitted));
    for bytes in [
        attempt.scope.binding.chain_id,
        attempt.scope.binding.session_id,
        attempt.scope.binding.terms_hash,
        attempt.scope.graph_digest,
        attempt.scope.custody_id,
        attempt.funding_tx_hash,
        attempt.transaction_hash,
    ] {
        out.extend_from_slice(&bytes);
    }
    out
}

pub(super) fn publish_exact_record(
    root: &RetainedDirectory,
    name: &str,
    staging_name: &str,
    bytes: &[u8],
) -> Result<()> {
    let destination = ValidatedComponent::registered(name)?;
    let staging = ValidatedComponent::registered(staging_name)?;
    match root.open_file(&destination, false) {
        Ok(mut retained) => {
            retained.require_exact_bytes(bytes)?;
            root.require_named_file_identity(&destination, &retained)?;
            // A rename removes staging atomically. Both files together cannot
            // be a legitimate interrupted publication under this sole lock.
            return match root.open_file(&staging, false) {
                Err(LinuxCapabilityError::NotFound) => Ok(()),
                Ok(_) => Err(XmrRecoveryCustodyErrorV11::Conflict),
                Err(error) => Err(error.into()),
            };
        }
        Err(LinuxCapabilityError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    let staged = match root.open_file(&staging, false) {
        Ok(mut retained) => {
            let actual = retained.read_bounded(bytes.len())?;
            root.require_named_file_identity(&staging, &retained)?;
            if actual == bytes {
                retained
            } else if bytes.starts_with(&actual) {
                // No RPC is permitted before final publication. Removing an
                // exact proper prefix cannot erase an externalization fact.
                root.unlink_verified_file(&staging, &retained)?;
                root.create_immutable_file(&staging, bytes)?
            } else {
                return Err(XmrRecoveryCustodyErrorV11::Conflict);
            }
        }
        Err(LinuxCapabilityError::NotFound) => root.create_immutable_file(&staging, bytes)?,
        Err(error) => return Err(error.into()),
    };
    root.rename_no_replace(&staging, &destination, &staged)?;
    Ok(())
}

pub(super) fn is_execution_component_v12(name: &str) -> bool {
    if name == EXIT_NAME
        || name == EXIT_STAGING
        || name == "xmr-funding-attempt-v12.bin"
        || name == ".xmr-funding-attempt-v12.staging"
        || name == "xmr-funding-observed-v22.bin"
        || name == ".xmr-funding-observed-v22.staging"
    {
        return true;
    }
    [
        XmrRecoveryOperationV12::Cancel,
        XmrRecoveryOperationV12::Refund,
        XmrRecoveryOperationV12::Compensate,
    ]
    .iter()
    .any(|kind| {
        [false, true].iter().any(|admitted| {
            let names = kind.names(*admitted);
            name == names.0 || name == names.1
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct TestRoot(std::path::PathBuf);
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn test_root() -> core::result::Result<(TestRoot, RetainedDirectory), Box<dyn std::error::Error>>
    {
        let path = std::env::temp_dir().join(format!(
            "dom-xmr-recovery-execution-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        let cleanup = TestRoot(path.clone());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let parent = Arc::new(Dir::from_std_file(std::fs::File::open(&path)?));
        let root = RetainedDirectory::create_under(
            parent,
            ValidatedComponent::operator_selected_root("custody")?,
        )?;
        Ok((cleanup, root))
    }

    #[test]
    fn interrupted_public_markers_resume_exactly_and_retries_do_not_replace_history(
    ) -> core::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0x31; RECORD_LEN];
        for cut in [0, 1, 9, 64, RECORD_LEN - 1, RECORD_LEN] {
            let (_cleanup, root) = test_root()?;
            let (name, staging) = XmrRecoveryOperationV12::Cancel.names(false);
            root.create_immutable_file(&ValidatedComponent::registered(staging)?, &bytes[..cut])?;
            publish_exact_record(&root, name, staging, &bytes)?;
            publish_exact_record(&root, name, staging, &bytes)?;
            assert_eq!(
                root.read_bounded_file(&ValidatedComponent::registered(name)?, RECORD_LEN)?,
                bytes
            );
            let mut changed = bytes.clone();
            changed[RECORD_LEN - 1] ^= 1;
            assert!(publish_exact_record(&root, name, staging, &changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn a_conflicting_stage_is_not_treated_as_an_absent_or_interrupted_transaction(
    ) -> core::result::Result<(), Box<dyn std::error::Error>> {
        let (_cleanup, root) = test_root()?;
        let (name, staging) = XmrRecoveryOperationV12::Compensate.names(false);
        root.create_immutable_file(&ValidatedComponent::registered(staging)?, &[0xFF])?;
        assert_eq!(
            publish_exact_record(&root, name, staging, &[0x31; RECORD_LEN]),
            Err(XmrRecoveryCustodyErrorV11::Conflict)
        );
        assert!(matches!(
            root.open_file(&ValidatedComponent::registered(name)?, false),
            Err(LinuxCapabilityError::NotFound)
        ));
        Ok(())
    }

    #[test]
    fn compensation_and_refund_cannot_cross_local_share_roles() {
        for role in [
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner,
            XmrRecoveryCustodyRoleV11::PublicCounterparty,
        ] {
            assert!(require_operation_role(role, XmrRecoveryOperationV12::Cancel).is_ok());
        }
        assert!(require_operation_role(
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner,
            XmrRecoveryOperationV12::Refund
        )
        .is_ok());
        assert!(require_operation_role(
            XmrRecoveryCustodyRoleV11::PublicCounterparty,
            XmrRecoveryOperationV12::Compensate
        )
        .is_ok());
        assert!(require_operation_role(
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner,
            XmrRecoveryOperationV12::Compensate
        )
        .is_err());
        assert!(require_operation_role(
            XmrRecoveryCustodyRoleV11::PublicCounterparty,
            XmrRecoveryOperationV12::Refund
        )
        .is_err());
    }
}
