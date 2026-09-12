//! Purpose-separated native DOM vaults for the universal participant runtime.
//!
//! Names and public storage identities commit to the exact authenticated wallet
//! binding. Encryption uses a keyed, domain-separated derivation from the
//! already retained route secret seal key; no public digest is an unlock key.

use std::sync::Arc;

use blake2::{
    digest::{consts::U32, KeyInit, Mac, Update},
    Blake2bMac,
};
use cap_std::fs::Dir;
use dom_actuator::DomSessionBindingV1;
use dom_scriptless_crypto::{Passphrase, StorageIdsV1};
use dom_scriptless_store::{BudgetPolicyV1, ContractsNonceVaultV1};
use zeroize::{Zeroize, Zeroizing};

use crate::production_chain_signers::ProductionChainSignerErrorV1;

/// Durability barrier through a real descriptor.
///
/// The cap-std directory handle is O_PATH on Linux: *at() calls resolve
/// through it, but fsync on an O_PATH descriptor fails with EBADF whatever
/// the directory is, so "." is reopened as a plain directory fd first. This
/// mirrors `sync_directory` in the btc-vault and btc-live stores.
fn fsync_capability_dir(dir: &cap_std::fs::Dir) -> Result<(), rustix::io::Errno> {
    use std::os::fd::AsFd as _;
    let fd = rustix::fs::openat(
        dir.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    rustix::fs::fsync(fd.as_fd())
}

/// Opaque, zeroizing handoff of the existing externally managed sealing key.
/// No getter, serialization or Clone is exposed.
pub(crate) struct ProductionXmrGraphVaultKeyV23(Zeroizing<[u8; 32]>);
impl ProductionXmrGraphVaultKeyV23 {
    pub(crate) fn retain(key: &Zeroizing<[u8; 32]>) -> Self {
        Self(key.clone())
    }
    pub(crate) fn mount(
        self,
        parent: Arc<Dir>,
        policy: BudgetPolicyV1,
        _startup_allows_create: bool,
    ) -> ProductionXmrGraphVaultProvisionerV23 {
        ProductionXmrGraphVaultProvisionerV23 {
            key: self,
            parent,
            policy,
        }
    }
}

/// Derived session IDs only exist after real bilateral template formation.
/// This owner defers provisioning without exposing its private unlock material.
pub(crate) struct ProductionXmrGraphVaultProvisionerV23 {
    key: ProductionXmrGraphVaultKeyV23,
    parent: Arc<Dir>,
    policy: BudgetPolicyV1,
}
impl ProductionXmrGraphVaultProvisionerV23 {
    /// A separate Funding root, admitted by its own durable F7 resource journal.
    /// An absent Ready root is never created, even after process restart.
    pub(crate) fn provision_funding_v23(
        &self,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: DomSessionBindingV1,
        chain: dom_adaptor::TrustedChainIdV1,
    ) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
        if chain.as_bytes() != &binding.chain_id() {
            return Err(ProductionChainSignerErrorV1::InvalidBinding);
        }
        let _bound = dom_actuator::DomContractsActuatorV1::bind(store, binding)
            .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
        store
            .with_xmr_bounded_funding_vault_v23(chain, binding.session_id(), |state| {
                // This callback never calls Contracts: its operation lock remains
                // held until the complete physical vault and Ready are durable.
                provision_vault(
                    Arc::clone(&self.parent),
                    binding,
                    ProductionDomVaultPurposeV12::Funding,
                    &self.key.0,
                    self.policy.clone(),
                    state == dom_scriptless_store::XmrFundingVaultProvisioningStateV23::Started,
                    true,
                )
                .map_err(|_| dom_scriptless_store::SessionStoreError::Quarantined)
            })
            .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)
    }

    /// Claim provisioning follows consumed native F7, before any local nonce.
    pub(crate) fn provision_claim_v23(
        &self,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: DomSessionBindingV1,
        chain: dom_adaptor::TrustedChainIdV1,
    ) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
        if chain.as_bytes() != &binding.chain_id() {
            return Err(ProductionChainSignerErrorV1::InvalidBinding);
        }
        let _bound = dom_actuator::DomContractsActuatorV1::bind(store, binding)
            .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
        store
            .with_xmr_bounded_claim_vault_v23(chain, binding.session_id(), |state| {
                // No Contracts calls inside this callback: its lock spans Ready.
                provision_vault(
                    Arc::clone(&self.parent),
                    binding,
                    ProductionDomVaultPurposeV12::Claim,
                    &self.key.0,
                    self.policy.clone(),
                    state == dom_scriptless_store::XmrClaimVaultProvisioningStateV23::Started,
                    true,
                )
                .map_err(|_| dom_scriptless_store::SessionStoreError::Quarantined)
            })
            .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)
    }

    pub(crate) fn provision(
        &self,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: DomSessionBindingV1,
        purpose: ProductionDomVaultPurposeV12,
    ) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
        if !matches!(
            purpose,
            ProductionDomVaultPurposeV12::XmrCancel
                | ProductionDomVaultPurposeV12::XmrRefundU
                | ProductionDomVaultPurposeV12::XmrCompensation
        ) {
            return Err(ProductionChainSignerErrorV1::InvalidBinding);
        }
        use dom_scriptless_store::{
            XmrGraphRecoverySigningEdgeV23 as Edge, XmrGraphResourceKindV23 as Kind,
            XmrGraphResourceStateV23 as State,
        };
        let edge = match purpose {
            ProductionDomVaultPurposeV12::XmrCancel => Edge::Cancel,
            ProductionDomVaultPurposeV12::XmrRefundU => Edge::RefundAdaptor,
            ProductionDomVaultPurposeV12::XmrCompensation => Edge::Compensation,
            _ => return Err(ProductionChainSignerErrorV1::InvalidBinding),
        };
        let permit = store
            .prepare_xmr_graph_resource_v23(binding.session_id(), edge, Kind::NonceVault)
            .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
        let vault = provision_vault(
            Arc::clone(&self.parent),
            binding,
            purpose,
            &self.key.0,
            self.policy.clone(),
            permit.state() == State::Started,
            true,
        )?;
        store
            .mark_xmr_graph_resource_ready_v23(permit)
            .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
        Ok(vault)
    }
}

/// Closed purpose registry. The native vault retains a lifetime session
/// tombstone, so two different signing purposes never share one root.
#[derive(Clone, Copy)]
pub(crate) enum ProductionDomVaultPurposeV12 {
    SharedOutput,
    Funding,
    Claim,
    Refund,
    XmrCancel,
    XmrCompensation,
    XmrRefundU,
}

impl ProductionDomVaultPurposeV12 {
    const fn tag(self) -> u8 {
        match self {
            Self::SharedOutput => 1,
            Self::Funding => 2,
            Self::Claim => 3,
            Self::Refund => 4,
            Self::XmrCancel => 5,
            Self::XmrCompensation => 6,
            Self::XmrRefundU => 7,
        }
    }
}

/// Open the exact native vault, or create an absent root only while the trusted
/// provisioning caller explicitly owns creation. Existing corrupt, replaced,
/// symlinked or incorrectly unlocked roots never fall back to creation.
///
/// A partially initialized native root is left intact for its native recovery
/// procedure; this function does not repair or erase cryptographic authority.
pub(crate) fn provision_dom_vault_v12(
    parent: Arc<Dir>,
    binding: DomSessionBindingV1,
    purpose: ProductionDomVaultPurposeV12,
    route_secret_seal_key: &[u8; 32],
    policy: BudgetPolicyV1,
    allow_create: bool,
) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
    provision_vault(
        parent,
        binding,
        purpose,
        route_secret_seal_key,
        policy,
        allow_create,
        false,
    )
}

/// V13 bootstrap publishes only a complete, empty native vault. Incomplete
/// private staging is quarantined on a fresh preparation retry; it has never
/// carried a shared contribution or a nonce, nor been exposed by this API.
pub(crate) fn provision_bootstrap_vault_v13(
    parent: Arc<Dir>,
    binding: DomSessionBindingV1,
    root_key: &[u8; 32],
    policy: BudgetPolicyV1,
    allow_create: bool,
) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
    provision_vault(
        parent,
        binding,
        ProductionDomVaultPurposeV12::SharedOutput,
        root_key,
        policy,
        allow_create,
        true,
    )
}

fn provision_vault(
    parent: Arc<Dir>,
    binding: DomSessionBindingV1,
    purpose: ProductionDomVaultPurposeV12,
    route_secret_seal_key: &[u8; 32],
    policy: BudgetPolicyV1,
    allow_create: bool,
    atomic_empty: bool,
) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
    if *route_secret_seal_key == [0; 32] {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    let mut context = Vec::with_capacity(161);
    context.extend_from_slice(&binding.route_id());
    context.extend_from_slice(&binding.session_id());
    context.extend_from_slice(&binding.chain_id());
    context.extend_from_slice(&binding.terms_digest());
    context.extend_from_slice(&binding.participant().participant_id());
    context.push(purpose.tag());
    let name_digest = public_digest(b"DOM-INTEROPD/DOM-VAULT-NAME/V12\0", &context);
    let root_name = format!("dom-vault-v12-{}", hex::encode(name_digest));
    let mut kdf = <Blake2bMac<U32> as KeyInit>::new_from_slice(route_secret_seal_key)
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
    blake2::digest::Mac::update(&mut kdf, b"DOM-INTEROPD/DOM-VAULT-UNLOCK/V12\0");
    blake2::digest::Mac::update(&mut kdf, &context);
    let mut derived = Zeroizing::new(<[u8; 32]>::from(kdf.finalize().into_bytes()));
    let passphrase = Passphrase::new(hex::encode(derived.as_slice()).into_bytes())
        .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
    derived.zeroize();
    match parent.symlink_metadata(&root_name) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ProductionChainSignerErrorV1::DomStateRefused);
            }
            ContractsNonceVaultV1::open_production(parent, &root_name, passphrase, policy)
                .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && allow_create => {
            let ids = StorageIdsV1::new(
                public_digest(b"DOM-INTEROPD/DOM-CONTRACTS-WALLET-ID/V12\0", &context),
                public_digest(b"DOM-INTEROPD/DOM-NONCE-VAULT-ID/V12\0", &context),
            )
            .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
            if atomic_empty {
                create_empty_bootstrap_vault_v13(parent, &root_name, ids, passphrase, policy)
            } else {
                ContractsNonceVaultV1::create_production(
                    parent,
                    &root_name,
                    ids,
                    &passphrase,
                    policy,
                )
                .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)
            }
        }
        Err(_) => Err(ProductionChainSignerErrorV1::DomStateRefused),
    }
}

fn public_digest(domain: &[u8], context: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut hash = blake2::Blake2b::<U32>::new();
    Digest::update(&mut hash, domain);
    Digest::update(&mut hash, context);
    Digest::finalize(hash).into()
}

fn create_empty_bootstrap_vault_v13(
    parent: Arc<Dir>,
    name: &str,
    ids: StorageIdsV1,
    passphrase: Passphrase,
    policy: BudgetPolicyV1,
) -> Result<ContractsNonceVaultV1, ProductionChainSignerErrorV1> {
    use cap_std::fs::{DirBuilder, DirBuilderExt as _, MetadataExt as _};
    use std::os::fd::AsFd;
    use ProductionChainSignerErrorV1::DomStateRefused as Refused;
    let staging = format!("bootstrap-staging-v13-{name}");
    match parent.symlink_metadata(&staging) {
        Ok(meta) => {
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.mode() & 0o7777 != 0o700
                || meta.uid() != rustix::process::getuid().as_raw()
            {
                return Err(Refused);
            }
            // Only the V13 empty-vault creator receives this staging parent.
            // It returns no authority until after the atomic final rename.
            // Keep incomplete bytes for inspection; never repair/delete them.
            let mut suffix = [0; 16];
            getrandom::getrandom(&mut suffix).map_err(|_| Refused)?;
            let quarantine = format!("bootstrap-quarantine-v13-{}", hex::encode(suffix));
            rustix::fs::renameat_with(
                parent.as_fd(),
                &staging,
                parent.as_fd(),
                &quarantine,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| Refused)?;
            fsync_capability_dir(&parent).map_err(|_| Refused)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Refused),
    }
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent
        .create_dir_with(&staging, &builder)
        .map_err(|_| Refused)?;
    fsync_capability_dir(&parent).map_err(|_| Refused)?;
    let stage = Arc::new(parent.open_dir(&staging).map_err(|_| Refused)?);
    // No share generation can occur in this function: only native empty
    // inventory creation, close, publication and strict native reopening.
    let vault = ContractsNonceVaultV1::create_production(
        Arc::clone(&stage),
        name,
        ids,
        &passphrase,
        policy.clone(),
    )
    .map_err(|_| Refused)?;
    drop(vault);
    fsync_capability_dir(&stage).map_err(|_| Refused)?;
    rustix::fs::renameat_with(
        stage.as_fd(),
        name,
        parent.as_fd(),
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| Refused)?;
    fsync_capability_dir(&parent).map_err(|_| Refused)?;
    fsync_capability_dir(&stage).map_err(|_| Refused)?;
    ContractsNonceVaultV1::open_production(parent, name, passphrase, policy).map_err(|_| Refused)
}
