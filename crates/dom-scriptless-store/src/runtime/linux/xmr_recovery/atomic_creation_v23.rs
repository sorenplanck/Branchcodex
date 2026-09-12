//! Complete archive publication before exporting any custody owner.
use super::*;
use cap_std::fs::{DirBuilder, DirBuilderExt as _, MetadataExt as _};
use rand_core::RngCore;
use std::os::fd::AsFd;

impl XmrRecoveryCustodyV11 {
    /// Caller holds the Contracts operation lock and has checked an exact
    /// Started receipt with no Ready tombstone. This is not a public repair API.
    pub(in super::super) fn create_atomically_v23(
        parent: Dir,
        root_name: &str,
        scope: XmrRecoveryCustodyScopeV11,
        graph: &VerifiedXmrRecoveryGraphV11,
        key: XmrRecoverySealKeyV11,
        private_refund: Option<&PrivateXmrRefundTransactionV11>,
    ) -> Result<Self> {
        use XmrRecoveryCustodyErrorV11::{Conflict, InvalidStorage, Unavailable};
        ValidatedComponent::operator_selected_root(root_name)?;
        match parent.symlink_metadata(root_name) {
            Ok(_) => return Err(Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Unavailable),
        }
        let staging = format!("xmr-custody-stage-v23-{root_name}");
        ValidatedComponent::operator_selected_root(&staging)?;
        match parent.symlink_metadata(&staging) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.mode() & 0o7777 != 0o700
                    || metadata.uid() != rustix::process::getuid().as_raw()
                {
                    return Err(InvalidStorage);
                }
                let retained_staging = RetainedDirectory::open_under(
                    Arc::new(parent.try_clone().map_err(|_| Unavailable)?),
                    ValidatedComponent::operator_selected_root(&staging)?,
                )?;
                retained_staging.revalidate()?;
                // The stage has never exported an owner. Preserve interrupted
                // bytes for inspection instead of overwriting or deleting them.
                let mut random = [0u8; 16];
                rand_core::OsRng
                    .try_fill_bytes(&mut random)
                    .map_err(|_| Unavailable)?;
                let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
                let quarantine = format!("xmr-custody-quarantine-v23-{suffix}");
                rustix::fs::renameat_with(
                    parent.as_fd(),
                    &staging,
                    parent.as_fd(),
                    &quarantine,
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(|_| Unavailable)?;
                super::super::fsync_capability_dir(&parent).map_err(|_| Unavailable)?;
                let retained_quarantine = RetainedDirectory::open_under(
                    Arc::new(parent.try_clone().map_err(|_| Unavailable)?),
                    ValidatedComponent::operator_selected_root(&quarantine)?,
                )?;
                retained_staging
                    .identity
                    .require_same(&retained_quarantine.identity)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Unavailable),
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(&staging, &builder)
            .map_err(|_| Unavailable)?;
        super::super::fsync_capability_dir(&parent).map_err(|_| Unavailable)?;
        let retained_stage = RetainedDirectory::open_under(
            Arc::new(parent.try_clone().map_err(|_| Unavailable)?),
            ValidatedComponent::operator_selected_root(&staging)?,
        )?;
        let stage = Arc::clone(&retained_stage.descriptor);
        let owner = Self::create_with_key_v23(
            stage.try_clone().map_err(|_| Unavailable)?,
            root_name,
            scope,
            graph,
            &key,
            private_refund,
        )?;
        owner.revalidate()?;
        let checked_root = RetainedDirectory::open_under(
            Arc::clone(&stage),
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        owner.root.identity.require_same(&checked_root.identity)?;
        drop(owner);
        retained_stage.revalidate()?;
        checked_root.revalidate()?;
        rustix::fs::renameat_with(
            stage.as_fd(),
            root_name,
            parent.as_fd(),
            root_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| Unavailable)?;
        super::super::fsync_capability_dir(&parent).map_err(|_| Unavailable)?;
        super::super::fsync_capability_dir(&stage).map_err(|_| Unavailable)?;
        // Rebind the retained directory to its final name after rename. The
        // same private key is borrowed internally, never exported or derived.
        let published = Self::open_existing(parent, root_name, scope, key)?;
        checked_root
            .identity
            .require_same(&published.root.identity)?;
        Ok(published)
    }
}
