//! SQLite durable store for Monero sweep operations.
//!
//! One row per `(settlement_id, kind)`. The exact signed sweep bytes are
//! written once and never rewritten; every later mutation moves the stage
//! and monotone facts around them. Replay is by `attempt_id`, so a crash
//! between a daemon call and the durable write converges to one outcome.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};

use crate::model::{
    Digest32, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrFinalityFactsV1, XmrOperationLocatorV1,
    XmrOperationViewV1, XmrReconciliationKindV1, XmrTxStageV1,
};

mod remote_custody_v23;
#[cfg(test)]
mod remote_custody_v23_tests;
pub use remote_custody_v23::XmrRemoteCustodyDigestsV23;

const CUSTODY_DOMAIN_V1: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/CUSTODY/V1\0";
const MUTATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/MUTATION/V1\0";
/// Frozen sidecar bound for a raw Monero transaction.
pub const MAX_RAW_TX_BYTES_V1: usize = 128 * 1024;

type Result<T> = core::result::Result<T, XmrActuatorErrorV1>;

/// Commitment to exact retained bytes.
pub fn custody_digest_v1(raw_transaction: &[u8]) -> Result<Digest32> {
    digest_parts(
        CUSTODY_DOMAIN_V1,
        &[
            &(raw_transaction.len() as u64).to_be_bytes(),
            raw_transaction,
        ],
    )
}

// The daemon publishes this owner row under its exclusive retained file
// lock. Checking it under the same SQLite write transaction prevents an old
// native handle from writing after a later open advances the physical owner.
fn require_production_owner_v12(
    connection: &Connection,
    binding: Digest32,
    epoch: u64,
) -> Result<()> {
    if binding == [0; 32] || epoch == 0 || epoch > i64::MAX as u64 {
        return Err(XmrActuatorErrorV1::InvalidInput);
    }
    let row: Option<(Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT binding,family,epoch FROM universal_actuator_owner_v11 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    match row {
        Some((retained, 4, retained_epoch))
            if retained.as_slice() == binding.as_slice() && retained_epoch == epoch as i64 =>
        {
            Ok(())
        }
        _ => Err(XmrActuatorErrorV1::Conflict),
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    if out == [0; 32] {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    Ok(out)
}

/// Identity of one attempted mutation, for idempotent replay.
pub(crate) fn mutation_id_v1(
    locator: XmrOperationLocatorV1,
    attempt_id: Digest32,
    kind: u8,
) -> Result<Digest32> {
    digest_parts(
        MUTATION_DOMAIN_V1,
        &[
            &locator.settlement_id,
            &[locator.kind.tag()],
            &attempt_id,
            &[kind],
        ],
    )
}

/// Durable Monero operation store.
pub struct XmrOperationStoreV1 {
    connection: Mutex<Connection>,
    production_owner_v12: Option<(Digest32, u64)>,
}

impl core::fmt::Debug for XmrOperationStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrOperationStoreV1")
            .finish_non_exhaustive()
    }
}

impl XmrOperationStoreV1 {
    /// Opens only an existing initialized store. This production recovery
    /// path never creates a file or repairs a missing schema.
    pub fn open_existing_production(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(XmrActuatorErrorV1::StorageUnavailable);
        }
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        let check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
        if check != "ok" {
            return Err(XmrActuatorErrorV1::Corrupt);
        }
        // Preparing every persisted field refuses truncated/foreign schemas.
        // No CREATE or ALTER statement is run during recovery.
        connection.prepare("SELECT settlement_id,kind,network_id,fencing_epoch,revision,stage,tx_hash,key_image,custody_digest,raw_transaction,final_height,final_block_hash,final_evidence,reconciliation FROM xmr_operation_v1 LIMIT 0")
            .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
        connection
            .prepare("SELECT mutation_id,settlement_id,kind,revision FROM xmr_mutation_v1 LIMIT 0")
            .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
            production_owner_v12: None,
        })
    }

    /// Opens an existing native store for exactly the retained universal
    /// production owner. The binding and local epoch are rechecked inside
    /// every write transaction, including identical replays. Route and
    /// coordinator fencing epochs remain independent of this local epoch.
    pub fn open_existing_fenced_v12(
        path: impl AsRef<Path>,
        expected_binding: Digest32,
        expected_epoch: u64,
    ) -> Result<Self> {
        let mut store = Self::open_existing_production(path)?;
        {
            let connection = store.lock()?;
            require_production_owner_v12(&connection, expected_binding, expected_epoch)?;
        }
        store.production_owner_v12 = Some((expected_binding, expected_epoch));
        Ok(store)
    }

    fn require_mutation_owner_v12(&self, connection: &Connection, lease_epoch: u64) -> Result<()> {
        if let Some((binding, epoch)) = self.production_owner_v12 {
            if lease_epoch != epoch {
                return Err(XmrActuatorErrorV1::Conflict);
            }
            require_production_owner_v12(connection, binding, epoch)?;
        }
        Ok(())
    }

    /// Opens or creates the durable store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection =
            Connection::open(path).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS xmr_operation_v1(
                   settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
                   kind INTEGER NOT NULL,
                   network_id BLOB NOT NULL CHECK(length(network_id)=32),
                   fencing_epoch INTEGER NOT NULL,
                   revision INTEGER NOT NULL,
                   stage INTEGER NOT NULL,
                   tx_hash BLOB NOT NULL CHECK(length(tx_hash)=32),
                   key_image BLOB NOT NULL CHECK(length(key_image)=32),
                   custody_digest BLOB NOT NULL CHECK(length(custody_digest)=32),
                   raw_transaction BLOB NOT NULL,
                   final_height INTEGER,
                   final_block_hash BLOB,
                   final_evidence BLOB,
                   reconciliation INTEGER,
                   PRIMARY KEY(settlement_id, kind)
                 );
                 CREATE TABLE IF NOT EXISTS xmr_remote_custody_v23(
                   settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
                   kind INTEGER NOT NULL,
                   marker BLOB NOT NULL CHECK(length(marker)=329),
                   PRIMARY KEY(settlement_id,kind)
                 );
                 CREATE TABLE IF NOT EXISTS xmr_mutation_v1(
                   mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id)=32),
                   settlement_id BLOB NOT NULL,
                   kind INTEGER NOT NULL,
                   revision INTEGER NOT NULL
                 );",
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
            production_owner_v12: None,
        })
    }

    /// Retains exact signed sweep bytes exactly once.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        tx_hash: Digest32,
        key_image: Digest32,
        raw_transaction: &[u8],
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        self.prepare_signed_scoped_v23(
            lease,
            locator,
            tx_hash,
            key_image,
            raw_transaction,
            None,
            now_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_signed_scoped_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        tx_hash: Digest32,
        key_image: Digest32,
        raw_transaction: &[u8],
        remote: Option<XmrRemoteCustodyDigestsV23>,
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        if now_unix_ms == 0 || !lease.is_live_at(now_unix_ms) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        if locator.settlement_id == [0; 32]
            || tx_hash == [0; 32]
            || key_image == [0; 32]
            || raw_transaction.is_empty()
            || raw_transaction.len() > MAX_RAW_TX_BYTES_V1
        {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let custody = custody_digest_v1(raw_transaction)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        self.require_mutation_owner_v12(&transaction, lease.fencing_epoch)?;
        if let Some(existing) = read_row(&transaction, locator)? {
            let retained_remote = remote_custody_v23::read(
                &transaction,
                locator,
                existing.network_id,
                existing.view.tx_hash,
                existing.view.key_image,
                existing.custody_digest,
            )?;
            if retained_remote != remote
                || lease.fencing_epoch < existing.view.fencing_epoch
                || existing.custody_digest != custody
                || existing.view.tx_hash != tx_hash
                || existing.view.key_image != key_image
                || existing.network_id != lease.network_id
            {
                return Err(XmrActuatorErrorV1::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
            return Ok(existing.view);
        }
        if remote_custody_v23::read(
            &transaction,
            locator,
            lease.network_id,
            tx_hash,
            key_image,
            custody,
        )?
        .is_some()
        {
            return Err(XmrActuatorErrorV1::Corrupt);
        }
        transaction
            .execute(
                "INSERT INTO xmr_operation_v1(
                   settlement_id, kind, network_id, fencing_epoch, revision, stage,
                   tx_hash, key_image, custody_digest, raw_transaction
                 ) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9)",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    lease.network_id.as_slice(),
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| XmrActuatorErrorV1::InvalidInput)?,
                    i64::from(XmrTxStageV1::Signed.tag()),
                    tx_hash.as_slice(),
                    key_image.as_slice(),
                    custody.as_slice(),
                    raw_transaction,
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        if let Some(digests) = remote {
            remote_custody_v23::insert(
                &transaction,
                locator,
                lease.network_id,
                tx_hash,
                key_image,
                custody,
                digests,
            )?;
        }
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    /// The exact retained bytes, for byte-identical retransmission only.
    pub fn retained_transaction(&self, locator: XmrOperationLocatorV1) -> Result<Vec<u8>> {
        let connection = self.lock()?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT raw_transaction FROM xmr_operation_v1
                 WHERE settlement_id=?1 AND kind=?2",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag())
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        bytes.ok_or(XmrActuatorErrorV1::NotFound)
    }

    /// Read-only operational result under the current physical/network fence.
    /// General historical view() remains available without mutation authority.
    pub(crate) fn checked_view_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        now: u64,
    ) -> Result<XmrOperationViewV1> {
        if now == 0 {
            return Err(XmrActuatorErrorV1::InvalidTime);
        }
        if !lease.is_live_at(now) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        self.require_mutation_owner_v12(&transaction, lease.fencing_epoch)?;
        let row = read_row(&transaction, locator)?.ok_or(XmrActuatorErrorV1::NotFound)?;
        if row.network_id != lease.network_id || lease.fencing_epoch < row.view.fencing_epoch {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        Ok(row.view)
    }

    /// Current projection, including historical reads by an old owner.
    pub fn view(&self, locator: XmrOperationLocatorV1) -> Result<XmrOperationViewV1> {
        let connection = self.lock()?;
        read_row(&connection, locator)?
            .map(|row| row.view)
            .ok_or(XmrActuatorErrorV1::NotFound)
    }

    /// Records a stage transition under `attempt_id`, idempotently.
    pub(crate) fn apply_mutation(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        mutation_kind: u8,
        now_unix_ms: u64,
        transition: impl FnOnce(&XmrOperationViewV1) -> Result<StageTransitionV1>,
    ) -> Result<XmrOperationViewV1> {
        if !lease.is_live_at(now_unix_ms) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        if attempt_id == [0; 32] {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let mutation_id = mutation_id_v1(locator, attempt_id, mutation_kind)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        self.require_mutation_owner_v12(&transaction, lease.fencing_epoch)?;
        let row = read_row(&transaction, locator)?.ok_or(XmrActuatorErrorV1::NotFound)?;
        if row.network_id != lease.network_id {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        // A stale fence may read, never write.
        if lease.fencing_epoch < row.view.fencing_epoch {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        let replayed: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM xmr_mutation_v1 WHERE mutation_id=?1",
                params![mutation_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        if replayed.is_some() {
            transaction
                .commit()
                .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
            return Ok(row.view);
        }
        let step = transition(&row.view)?;
        let revision = row
            .view
            .revision
            .checked_add(1)
            .ok_or(XmrActuatorErrorV1::Corrupt)?;
        transaction
            .execute(
                "UPDATE xmr_operation_v1
                 SET stage=?1, revision=?2, fencing_epoch=?3,
                     final_height=?4, final_block_hash=?5, final_evidence=?6, reconciliation=?7
                 WHERE settlement_id=?8 AND kind=?9",
                params![
                    i64::from(step.stage.tag()),
                    i64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| XmrActuatorErrorV1::InvalidInput)?,
                    step.finality
                        .map(|f| i64::try_from(f.final_height))
                        .transpose()
                        .map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                    step.finality.map(|f| f.final_block_hash.to_vec()),
                    step.finality.map(|f| f.final_evidence_digest.to_vec()),
                    step.reconciliation
                        .map(|k| i64::from(reconciliation_tag(k))),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO xmr_mutation_v1(mutation_id, settlement_id, kind, revision)
                 VALUES(?1,?2,?3,?4)",
                params![
                    mutation_id.as_slice(),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    i64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)
    }
}

/// One durable stage transition.
pub(crate) struct StageTransitionV1 {
    pub(crate) stage: XmrTxStageV1,
    pub(crate) finality: Option<XmrFinalityFactsV1>,
    pub(crate) reconciliation: Option<XmrReconciliationKindV1>,
}

pub(crate) struct RetainedRowV1 {
    pub(crate) view: XmrOperationViewV1,
    pub(crate) network_id: Digest32,
    pub(crate) custody_digest: Digest32,
}

const fn reconciliation_tag(kind: XmrReconciliationKindV1) -> u8 {
    match kind {
        XmrReconciliationKindV1::KeyImageUnspentAbsent => 1,
        XmrReconciliationKindV1::Observed => 2,
        XmrReconciliationKindV1::Final => 3,
        XmrReconciliationKindV1::Unknown => 4,
    }
}

fn reconciliation_from_tag(value: i64) -> Option<XmrReconciliationKindV1> {
    match value {
        1 => Some(XmrReconciliationKindV1::KeyImageUnspentAbsent),
        2 => Some(XmrReconciliationKindV1::Observed),
        3 => Some(XmrReconciliationKindV1::Final),
        4 => Some(XmrReconciliationKindV1::Unknown),
        _ => None,
    }
}

fn read_row(
    connection: &Connection,
    locator: XmrOperationLocatorV1,
) -> Result<Option<RetainedRowV1>> {
    let row = connection
        .query_row(
            "SELECT network_id, fencing_epoch, revision, stage, tx_hash, key_image,
                    custody_digest, final_height, final_block_hash, final_evidence,
                    reconciliation, raw_transaction
             FROM xmr_operation_v1 WHERE settlement_id=?1 AND kind=?2",
            params![
                locator.settlement_id.as_slice(),
                i64::from(locator.kind.tag())
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    let Some((
        network,
        fence,
        revision,
        stage,
        tx_hash,
        key_image,
        custody,
        final_height,
        final_block_hash,
        final_evidence,
        reconciliation,
        raw_transaction,
    )) = row
    else {
        return Ok(None);
    };
    let network_id: Digest32 = network
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let tx_hash: Digest32 = tx_hash
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let key_image: Digest32 = key_image
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let custody_digest: Digest32 = custody
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    if raw_transaction.is_empty()
        || raw_transaction.len() > MAX_RAW_TX_BYTES_V1
        || custody_digest_v1(&raw_transaction)? != custody_digest
    {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    remote_custody_v23::read(
        connection,
        locator,
        network_id,
        tx_hash,
        key_image,
        custody_digest,
    )?;
    let stage =
        XmrTxStageV1::from_tag(u8::try_from(stage).map_err(|_| XmrActuatorErrorV1::Corrupt)?)
            .ok_or(XmrActuatorErrorV1::Corrupt)?;
    let finality = match (final_height, final_block_hash, final_evidence) {
        (Some(height), Some(hash), Some(evidence)) => Some(XmrFinalityFactsV1 {
            final_height: u64::try_from(height).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            final_block_hash: hash.try_into().map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            final_evidence_digest: evidence
                .try_into()
                .map_err(|_| XmrActuatorErrorV1::Corrupt)?,
        }),
        (None, None, None) => None,
        _ => return Err(XmrActuatorErrorV1::Corrupt),
    };
    if matches!(stage, XmrTxStageV1::Final) != finality.is_some()
        && !matches!(stage, XmrTxStageV1::FinalityInvalidated)
    {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    let reconciliation = match reconciliation {
        Some(value) => Some(reconciliation_from_tag(value).ok_or(XmrActuatorErrorV1::Corrupt)?),
        None => None,
    };
    Ok(Some(RetainedRowV1 {
        view: XmrOperationViewV1 {
            locator,
            fencing_epoch: u64::try_from(fence).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            revision: u64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            stage,
            tx_hash,
            key_image,
            custody_digest,
            finality,
            reconciliation_kind: reconciliation,
        },
        network_id,
        custody_digest,
    }))
}

/// Frozen mutation tags.
pub(crate) const MUTATION_BROADCAST: u8 = 1;
pub(crate) const MUTATION_OBSERVE: u8 = 2;
pub(crate) const MUTATION_RECONCILE: u8 = 3;

#[cfg(test)]
mod production_owner_tests_v12 {
    use super::*;
    use crate::model::XmrOperationKindV1;

    fn publish_owner(path: &Path, binding: Digest32, epoch: u64) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE universal_actuator_owner_v11(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding BLOB NOT NULL,
            family INTEGER NOT NULL, epoch INTEGER NOT NULL);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO universal_actuator_owner_v11 VALUES(1,?1,4,?2)",
                params![binding.as_slice(), epoch as i64],
            )
            .unwrap();
    }

    fn lease(epoch: u64) -> XmrActuatorLeaseV1 {
        XmrActuatorLeaseV1::new([1; 32], [2; 32], [3; 32], epoch, 10_000).unwrap()
    }

    #[test]
    fn newer_physical_owner_fences_stale_native_handle_before_any_operation_moves() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("actuator.sqlite");
        drop(XmrOperationStoreV1::open(&path).unwrap());
        publish_owner(&path, [7; 32], 1);
        let old = XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 1).unwrap();
        let locator = XmrOperationLocatorV1 {
            settlement_id: [8; 32],
            kind: XmrOperationKindV1::Refund,
        };
        let old_lease = lease(1);
        let prepared = old
            .prepare_signed(&old_lease, locator, [5; 32], [6; 32], &[1, 2, 3], 100)
            .unwrap();
        let retained = old.retained_transaction(locator).unwrap();
        assert_eq!(
            old.checked_view_v23(&old_lease, locator, 101),
            Ok(prepared.clone())
        );
        assert_eq!(
            old.checked_view_v23(&old_lease, locator, 10_000),
            Err(XmrActuatorErrorV1::LeaseExpired)
        );
        // Simulate a later physical owner, without modifying the old operation
        // row: checking only that row's epoch would still accept the old lease.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE universal_actuator_owner_v11 SET epoch=2 WHERE singleton=1",
                [],
            )
            .unwrap();
        let new = XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 2).unwrap();
        let new_lease = lease(2);
        assert_eq!(
            old.prepare_signed(&old_lease, locator, [5; 32], [6; 32], &[1, 2, 3], 101),
            Err(XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(
            old.checked_view_v23(&old_lease, locator, 101),
            Err(XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(
            new.checked_view_v23(&old_lease, locator, 101),
            Err(XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(
            new.checked_view_v23(&new_lease, locator, 101),
            Ok(prepared.clone())
        );
        assert_eq!(
            old.prepare_signed(&new_lease, locator, [5; 32], [6; 32], &[1, 2, 3], 101),
            Err(XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(
            new.prepare_signed(&old_lease, locator, [5; 32], [6; 32], &[1, 2, 3], 101),
            Err(XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(
            old.apply_mutation(&old_lease, locator, [9; 32], 1, 101, |_| panic!(
                "stale owner must not reach transition"
            )),
            Err(XmrActuatorErrorV1::Conflict)
        );
        let replay = new
            .prepare_signed(&new_lease, locator, [5; 32], [6; 32], &[1, 2, 3], 101)
            .unwrap();
        assert_eq!(replay.custody_digest, prepared.custody_digest);
        assert_eq!(new.retained_transaction(locator).unwrap(), retained);
        let moved = new
            .apply_mutation(&new_lease, locator, [9; 32], 1, 102, |row| {
                Ok(StageTransitionV1 {
                    stage: row.stage,
                    finality: None,
                    reconciliation: None,
                })
            })
            .unwrap();
        assert_eq!(moved.fencing_epoch, 2);
        assert_eq!(moved.revision, prepared.revision + 1);
        assert_eq!(new.retained_transaction(locator).unwrap(), retained);
    }

    #[test]
    fn fenced_reopen_rejects_missing_transplanted_or_wrong_family_owner() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("actuator.sqlite");
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 1).is_err());
        assert!(!path.exists());
        drop(XmrOperationStoreV1::open(&path).unwrap());
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 1).is_err());
        publish_owner(&path, [7; 32], 1);
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [8; 32], 1).is_err());
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 2).is_err());
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], u64::MAX).is_err());
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE universal_actuator_owner_v11 SET family=3 WHERE singleton=1",
                [],
            )
            .unwrap();
        assert!(XmrOperationStoreV1::open_existing_fenced_v12(&path, [7; 32], 1).is_err());
    }
}
