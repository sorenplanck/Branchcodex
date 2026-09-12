//! Read-only progress observations, followed by quiescent production replay.
//! A poll is never an admission capability or proof of final settlement.
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionPathRoleV1,
    ProductionRoutePinsV1, PRODUCTION_CREATE_CONFIG_FILE_V11,
};
use route_executor::{CanonicalCodecV1, DurableRouteStoreV1, RouteSnapshotV1, SecretVisibilityV1};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

pub(in super::super) struct RouteObserverV23 {
    database: PathBuf,
    pins: ProductionRoutePinsV1,
    previous: Option<RouteSnapshotV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RouteHeartbeatV23 {
    epoch: u64,
    updated_at: u64,
    expires_at: u64,
}

impl RouteHeartbeatV23 {
    pub(super) fn advanced_from(self, before: Self) -> bool {
        self.epoch >= before.epoch
            && self.updated_at > before.updated_at
            && self.expires_at > before.expires_at
    }
}

impl RouteObserverV23 {
    pub(in super::super) fn new(state: &Path) -> Result<Self> {
        crate::production_config::validate_state_dir(state)?;
        let path = state.join(PRODUCTION_CREATE_CONFIG_FILE_V11);
        let file = owned_file(&path)?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err("scenario manifest exceeds canonical bound".into());
        }
        let config = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &bytes,
            ProductionBootstrapModeV1::Create,
        )?;
        let database = state.join(config.relative_path(ProductionPathRoleV1::RouteStore));
        Ok(Self {
            database,
            pins: config.pins(),
            previous: None,
        })
    }

    pub(in super::super) fn route_id(&self) -> [u8; 32] {
        self.pins.route_id
    }

    /// A terminal snapshot alone can predate process startup. Require a fresh
    /// durable heartbeat by the pinned process owner to prove actual reopening.
    pub(super) fn heartbeat(&self) -> Result<RouteHeartbeatV23> {
        let _held = owned_file(&self.database)?;
        let connection = Connection::open_with_flags(
            &self.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(500))?;
        let (owner, epoch, updated, expires): (Vec<u8>, i64, i64, i64) = connection.query_row(
            "SELECT owner_id,fencing_epoch,updated_at_unix_ms,lease_until_unix_ms
             FROM route_leases WHERE route_id=?1",
            [self.pins.route_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if owner.as_slice() != self.pins.process_owner_id
            || epoch <= 0
            || updated < 0
            || expires < updated
        {
            return Err("scenario route heartbeat owner or bounds mismatch".into());
        }
        Ok(RouteHeartbeatV23 {
            epoch: epoch as u64,
            updated_at: updated as u64,
            expires_at: expires as u64,
        })
    }

    pub(in super::super) fn poll(&mut self) -> Result<Option<RouteSnapshotV1>> {
        match std::fs::symlink_metadata(&self.database) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let held = owned_file(&self.database)?;
        let before = held.metadata()?;
        // Opening the real Store here would compete for its exclusive process
        // lock. This observer cannot migrate, repair, create or commit a row.
        let connection = Connection::open_with_flags(
            &self.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(500))?;
        let after = std::fs::symlink_metadata(&self.database)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("scenario route database changed during observation".into());
        }
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='route_snapshots')",
            [], |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = connection.query_row(
            "SELECT CASE WHEN length(snapshot_bytes) BETWEEN 1 AND ?2 THEN snapshot_bytes ELSE NULL END,
                    CASE WHEN length(snapshot_hash)=32 THEN snapshot_hash ELSE NULL END,
                    revision, last_event_seq
             FROM route_snapshots WHERE route_id=?1",
            rusqlite::params![self.pins.route_id.as_slice(), route_executor::MAX_CANONICAL_BYTES_V1 as i64],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional()?;
        let Some((bytes, stored_hash, revision, sequence)) = row else {
            return Ok(None);
        };
        let snapshot = RouteSnapshotV1::decode_canonical(&bytes)?;
        let domain = b"DOM-ROUTE-SNAPSHOT-V1";
        let mut commitment = Vec::with_capacity(16 + domain.len() + bytes.len());
        commitment.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        commitment.extend_from_slice(domain);
        commitment.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        commitment.extend_from_slice(&bytes);
        if stored_hash.as_slice() != route_executor::digest_bytes_v1(&commitment)
            || snapshot.encode_canonical()? != bytes
            || snapshot.route_id != self.pins.route_id
            || u64::try_from(revision)? != snapshot.revision
            || u64::try_from(sequence)? != snapshot.last_event_sequence
        {
            return Err("scenario snapshot scope or commitment mismatch".into());
        }
        if let Some(previous) = &self.previous {
            if snapshot.revision < previous.revision
                || snapshot.last_event_sequence < previous.last_event_sequence
                || (snapshot.revision == previous.revision && snapshot != *previous)
                || (matches!(
                    previous.secret_visibility,
                    SecretVisibilityV1::Public { .. }
                ) && !matches!(
                    snapshot.secret_visibility,
                    SecretVisibilityV1::Public { .. }
                ))
            {
                return Err("scenario durable state regressed".into());
            }
        }
        self.previous = Some(snapshot.clone());
        Ok(Some(snapshot))
    }

    /// Caller must stop/reap this database's daemon before taking its lock.
    pub(super) fn require_exit_only_reopen_stopped_v24(&self, crash_revision: u64) -> Result<()> {
        use route_executor::{ActionKindV1, HealthStateV1, RouteEventV1};
        let expected = self.replay_stopped()?;
        let store = DurableRouteStoreV1::open_existing(&self.database)?;
        if store.audit_external_custody_only_v1(self.pins.route_id)? != expected {
            return Err("quiescent recovery snapshot changed between full audits".into());
        }
        let journal = store.journal(self.pins.route_id)?;
        let mut recovery_seen = false;
        for entry in journal
            .iter()
            .filter(|entry| entry.resulting_revision > crash_revision)
        {
            match &entry.event {
                RouteEventV1::SetHealth {
                    target: HealthStateV1::RecoveryOnly,
                    ..
                } => {
                    recovery_seen = true;
                }
                RouteEventV1::CommitAction(intent)
                    if recovery_seen && intent.kind == ActionKindV1::Funding =>
                {
                    return Err(
                        "new funding committed after durable recovery-only transition".into(),
                    );
                }
                _ => {}
            }
        }
        if !recovery_seen {
            return Err("reopened survivor never recorded authenticated RecoveryOnly".into());
        }
        Ok(())
    }

    /// Caller must stop/reap this database's daemon before taking its lock.
    pub(super) fn replay_stopped(&self) -> Result<RouteSnapshotV1> {
        let store = DurableRouteStoreV1::open_existing(&self.database)?;
        let snapshot = store.audit_external_custody_only_v1(self.pins.route_id)?;
        let checkpoint = store.audit_frozen_admission_checkpoint_v2(self.pins.route_id)?;
        if checkpoint.network_id != self.pins.network_id
            || checkpoint.route_id != self.pins.route_id
            || checkpoint.registry_manifest_digest != self.pins.registry_manifest_digest
            || checkpoint.registry_epoch < self.pins.registry_minimum_epoch
            || checkpoint.upstream_terms_digest != self.pins.upstream_terms_digest
            || checkpoint.downstream_terms_digest != self.pins.downstream_terms_digest
            || checkpoint.participant_bindings_digest != self.pins.participant_bindings_digest
            || checkpoint.relay_binding_digest != self.pins.relay_binding_digest
            || checkpoint.registry_authority_set_digest != self.pins.registry_authority_set_digest
            || checkpoint.time_policy_authority_set_digest
                != self.pins.time_policy_authority_set_digest
            || checkpoint.time_evidence_authority_set_digest
                != self.pins.time_evidence_authority_set_digest
            || snapshot.bindings.as_ref() != Some(&checkpoint.bindings)
        {
            return Err("scenario journal admission differs from original manifest".into());
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| snapshot.revision < previous.revision)
        {
            return Err("scenario replay lost an observed durable revision".into());
        }
        Ok(snapshot)
    }
}

pub(super) fn owned_file(path: &Path) -> Result<File> {
    let named = std::fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || named.mode() & 0o7777 != 0o600
        || named.nlink() != 1
        || named.uid() != rustix::process::geteuid().as_raw()
        || std::fs::canonicalize(path)? != path
    {
        return Err("scenario requires original private regular files".into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.uid() != rustix::process::geteuid().as_raw()
    {
        return Err("scenario private file changed while opening".into());
    }
    Ok(file)
}
