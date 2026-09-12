//! Physical ownership for one selected SOL/XMR actuator. The root keeps the
//! returned guard alive for the entire lifetime of the returned actuator.
//! SQLite stores the scope and monotonically increasing fencing epoch; the
//! retained file lock excludes a second local process, including during crash
//! recovery. Recovery never creates a missing database or schema.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use solana_actuator::{DurableSolanaActuatorV1, SolanaOperationStoreV1};
use xmr_actuator::{DurableXmrActuatorV1, XmrOperationStoreV1};

use crate::production_config::ProductionChainFamilyV11;
use crate::production_provisioning::ProductionProvisioningStageStateV1 as Stage;
use crate::production_run::ProductionRunModeV1 as Mode;

const LOCK_HEADER: &[u8] = b"DOM-INTEROPD/ACTUATOR-OWNER/V11\0";
const OWNER_TABLE: &str = "universal_actuator_owner_v11";

pub(crate) enum ProductionUniversalActuatorV11 {
    Solana(DurableSolanaActuatorV1),
    Monero(DurableXmrActuatorV1),
}

pub(crate) struct ProductionUniversalActuatorGuardV11 {
    inner: Rc<PhysicalActuatorOwnerV11>,
}

struct PhysicalActuatorOwnerV11 {
    epoch: u64,
    binding: [u8; 32],
    family: ProductionChainFamilyV11,
    path: PathBuf,
    lock_path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    _lock: File,
}

impl ProductionUniversalActuatorGuardV11 {
    pub(crate) fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    /// The child receives a share of the actual process lock, not a copied
    /// epoch or a boolean permission. Dropping the root's guard cannot release
    /// exclusion while the child still holds this finite-lease issuer.
    pub(crate) fn lease_owner_v11(
        &self,
        authority_id: [u8; 32],
        owner_id: [u8; 32],
        network_id: [u8; 32],
        duration_ms: u64,
    ) -> Result<ProductionUniversalActuatorLeaseOwnerV11, Refusal> {
        if [authority_id, owner_id, network_id].contains(&[0; 32])
            || duration_ms == 0
            || duration_ms > 3_600_000
        {
            return Err(Refusal::Conflict);
        }
        self.inner.require_current()?;
        Ok(ProductionUniversalActuatorLeaseOwnerV11 {
            physical: Rc::clone(&self.inner),
            authority_id,
            owner_id,
            network_id,
            duration_ms,
        })
    }
}

/// Closed production lease issuer, bound to one physical selected store.
/// It can extend only the existing epoch under a held local process lock.
pub(crate) struct ProductionUniversalActuatorLeaseOwnerV11 {
    physical: Rc<PhysicalActuatorOwnerV11>,
    authority_id: [u8; 32],
    owner_id: [u8; 32],
    network_id: [u8; 32],
    duration_ms: u64,
}

impl PhysicalActuatorOwnerV11 {
    fn require_current(&self) -> Result<(), Refusal> {
        require_same_inode(&self._lock, &self.lock_path, self.uid)?;
        require_regular(&self.path, self.uid)?;
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| Refusal::Unavailable)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(Refusal::Conflict);
        }
        let connection = open_no_create(&self.path)?;
        let row = owner_row(&connection)?.ok_or(Refusal::Conflict)?;
        require_owner(&row, self.binding, family_tag(self.family)?)?;
        if row.2 != self.epoch {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }
}

impl ProductionUniversalActuatorLeaseOwnerV11 {
    pub(crate) fn require_scope(
        &self,
        family: ProductionChainFamilyV11,
        authority_id: [u8; 32],
        network_id: [u8; 32],
        epoch: u64,
    ) -> Result<(), Refusal> {
        if self.physical.family != family
            || self.authority_id != authority_id
            || self.network_id != network_id
            || self.physical.epoch != epoch
        {
            return Err(Refusal::Conflict);
        }
        self.physical.require_current()
    }

    pub(crate) fn solana_lease(
        &self,
        fee_payer: solana_types::SolanaPubkey,
        now: u64,
    ) -> Result<solana_actuator::SolanaActuatorLeaseV1, Refusal> {
        if self.physical.family != ProductionChainFamilyV11::Sol {
            return Err(Refusal::Conflict);
        }
        self.physical.require_current()?;
        let until = now.checked_add(self.duration_ms).ok_or(Refusal::Conflict)?;
        solana_actuator::SolanaActuatorLeaseV1::new(
            self.authority_id,
            self.owner_id,
            self.network_id,
            fee_payer,
            self.physical.epoch,
            until,
        )
        .map_err(|_| Refusal::Conflict)
    }

    pub(crate) fn xmr_lease(&self, now: u64) -> Result<xmr_actuator::XmrActuatorLeaseV1, Refusal> {
        if self.physical.family != ProductionChainFamilyV11::Xmr {
            return Err(Refusal::Conflict);
        }
        self.physical.require_current()?;
        let until = now.checked_add(self.duration_ms).ok_or(Refusal::Conflict)?;
        xmr_actuator::XmrActuatorLeaseV1::new(
            self.authority_id,
            self.owner_id,
            self.network_id,
            self.physical.epoch,
            until,
        )
        .map_err(|_| Refusal::Conflict)
    }
}

pub(crate) fn open_universal_actuator_v11(
    path: &Path,
    binding: [u8; 32],
    family: ProductionChainFamilyV11,
    mode: Mode,
    stage_before: Stage,
    stage: Stage,
) -> Result<
    (
        ProductionUniversalActuatorV11,
        ProductionUniversalActuatorGuardV11,
    ),
    Refusal,
> {
    let tag = family_tag(family)?;
    if binding == [0; 32] || !path.is_absolute() {
        return Err(Refusal::Conflict);
    }
    let parent = path.parent().ok_or(Refusal::Conflict)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| Refusal::Unavailable)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Refusal::Conflict);
    }
    let owner = parent_metadata.uid();
    let create_prefix = matches!(
        (mode, stage_before, stage),
        (Mode::Create, Stage::Absent, Stage::Started)
    );
    let resume_prefix = matches!(
        (mode, stage_before, stage),
        (Mode::Create, Stage::Started, Stage::Started)
    );
    let reopen = matches!(
        (mode, stage_before, stage),
        (Mode::Create, Stage::Complete, Stage::Complete)
            | (Mode::ReopenExisting, Stage::Complete, Stage::Complete)
    );
    if !(create_prefix || resume_prefix || reopen) {
        return Err(Refusal::Conflict);
    }
    let lock_path = sibling(path, ".process.lock")?;
    let expected_lock = [LOCK_HEADER, &[tag], binding.as_slice()].concat();
    if create_prefix {
        for candidate in [
            path.to_owned(),
            sibling(path, "-wal")?,
            sibling(path, "-shm")?,
            lock_path.clone(),
        ] {
            require_absent(&candidate)?;
        }
    }
    // A crash may happen just after Started is durable and before the lock
    // file exists. That prefix is resumable only while the database is absent.
    let lock_absent = absent(&lock_path)?;
    if lock_absent && !(create_prefix || (resume_prefix && absent(path)?)) {
        return Err(Refusal::Unavailable);
    }
    let mut lock = if lock_absent {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| Refusal::Unavailable)?
    } else {
        require_regular(&lock_path, owner)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|_| Refusal::Unavailable)?
    };
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Refusal::Unavailable)?;
    require_same_inode(&lock, &lock_path, owner)?;
    if lock_absent {
        lock.write_all(&expected_lock)
            .map_err(|_| Refusal::Unavailable)?;
        lock.sync_all().map_err(|_| Refusal::Unavailable)?;
        sync_directory(parent)?;
    } else {
        let mut actual = Vec::new();
        (&mut lock)
            .take((expected_lock.len() + 1) as u64)
            .read_to_end(&mut actual)
            .map_err(|_| Refusal::Unavailable)?;
        if actual != expected_lock {
            // An interrupted first write leaves a strict prefix. It is safe
            // to finish that prefix only before any database exists and only
            // under the already-started provisioning journal and file lock.
            if !resume_prefix
                || !absent(path)?
                || !expected_lock.starts_with(&actual)
                || actual.len() >= expected_lock.len()
            {
                return Err(Refusal::Conflict);
            }
            lock.write_all(&expected_lock[actual.len()..])
                .map_err(|_| Refusal::Unavailable)?;
            lock.sync_all().map_err(|_| Refusal::Unavailable)?;
            sync_directory(parent)?;
        }
    }
    for auxiliary in [sibling(path, "-wal")?, sibling(path, "-shm")?] {
        if !absent(&auxiliary)? {
            require_regular(&auxiliary, owner)?;
        }
    }
    let db_absent = absent(path)?;
    if db_absent && reopen {
        return Err(Refusal::Unavailable);
    }
    let may_initialize = create_prefix || resume_prefix;
    if db_absent {
        if !may_initialize {
            return Err(Refusal::Unavailable);
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| Refusal::Unavailable)?;
        file.sync_all().map_err(|_| Refusal::Unavailable)?;
        sync_directory(parent)?;
    }
    require_regular(path, owner)?;
    let mut connection = open_no_create(path)?;
    let retained_owner = owner_row(&connection)?;
    let initialize_native = retained_owner.is_none();
    if initialize_native {
        if !may_initialize {
            return Err(Refusal::Conflict);
        }
        // No operation can have been dispatched before the bootstrap stage is
        // complete. A partial initial schema is repaired only if all existing
        // objects belong to this native family and every operation table is empty.
        require_empty_creation_prefix(&connection, family)?;
    } else {
        require_owner(
            retained_owner.as_ref().ok_or(Refusal::Conflict)?,
            binding,
            tag,
        )?;
    }
    drop(connection);
    let actuator = match (family, initialize_native) {
        (ProductionChainFamilyV11::Sol, true) => {
            drop(SolanaOperationStoreV1::open(path).map_err(|_| Refusal::Conflict)?);
            ProductionUniversalActuatorV11::Solana(DurableSolanaActuatorV1::new(
                SolanaOperationStoreV1::open_existing_production(path)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        (ProductionChainFamilyV11::Sol, false) => {
            ProductionUniversalActuatorV11::Solana(DurableSolanaActuatorV1::new(
                SolanaOperationStoreV1::open_existing_production(path)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        (ProductionChainFamilyV11::Xmr, true) => {
            drop(XmrOperationStoreV1::open(path).map_err(|_| Refusal::Conflict)?);
            ProductionUniversalActuatorV11::Monero(DurableXmrActuatorV1::new(
                XmrOperationStoreV1::open_existing_production(path)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        (ProductionChainFamilyV11::Xmr, false) => {
            ProductionUniversalActuatorV11::Monero(DurableXmrActuatorV1::new(
                XmrOperationStoreV1::open_existing_production(path)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        _ => return Err(Refusal::Conflict),
    };
    connection = open_no_create(path)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| Refusal::Unavailable)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| Refusal::Unavailable)?;
    let epoch = if initialize_native {
        tx.execute_batch(
            "CREATE TABLE universal_actuator_owner_v11(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            binding BLOB NOT NULL CHECK(length(binding)=32),
            family INTEGER NOT NULL CHECK(family IN (3,4)),
            epoch INTEGER NOT NULL CHECK(epoch>0));",
        )
        .map_err(|_| Refusal::Conflict)?;
        tx.execute("INSERT INTO universal_actuator_owner_v11(singleton,binding,family,epoch) VALUES(1,?1,?2,1)",
            params![binding.as_slice(), i64::from(tag)]).map_err(|_| Refusal::Unavailable)?;
        1_u64
    } else {
        let row = owner_row(&tx)?.ok_or(Refusal::Conflict)?;
        require_owner(&row, binding, tag)?;
        let next = row
            .2
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Refusal::Conflict)?;
        if tx
            .execute(
                "UPDATE universal_actuator_owner_v11 SET epoch=?1 WHERE singleton=1 AND epoch=?2",
                params![next as i64, row.2 as i64],
            )
            .map_err(|_| Refusal::Unavailable)?
            != 1
        {
            return Err(Refusal::Conflict);
        }
        next
    };
    tx.commit().map_err(|_| Refusal::Unavailable)?;
    sync_directory(parent)?;
    // The creation/reopen verifier above has authenticated the native schema.
    // After publishing this physical owner, retain only a native handle which
    // checks that exact owner again inside each SQLite write transaction.
    // This is a local storage fence, independent of coordinator/route epochs.
    drop(actuator);
    let actuator = match family {
        ProductionChainFamilyV11::Sol => {
            ProductionUniversalActuatorV11::Solana(DurableSolanaActuatorV1::new(
                SolanaOperationStoreV1::open_existing_fenced_v12(path, binding, epoch)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        ProductionChainFamilyV11::Xmr => {
            ProductionUniversalActuatorV11::Monero(DurableXmrActuatorV1::new(
                XmrOperationStoreV1::open_existing_fenced_v12(path, binding, epoch)
                    .map_err(|_| Refusal::Conflict)?,
            ))
        }
        _ => return Err(Refusal::Conflict),
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
    Ok((
        actuator,
        ProductionUniversalActuatorGuardV11 {
            inner: Rc::new(PhysicalActuatorOwnerV11 {
                epoch,
                binding,
                family,
                path: path.to_owned(),
                lock_path,
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: owner,
                _lock: lock,
            }),
        },
    ))
}

fn family_tag(family: ProductionChainFamilyV11) -> Result<u8, Refusal> {
    match family {
        ProductionChainFamilyV11::Sol => Ok(3),
        ProductionChainFamilyV11::Xmr => Ok(4),
        _ => Err(Refusal::Conflict),
    }
}

fn open_no_create(path: &Path) -> Result<Connection, Refusal> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| Refusal::Unavailable)
}

fn owner_row(connection: &Connection) -> Result<Option<(Vec<u8>, i64, u64)>, Refusal> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [OWNER_TABLE],
            |row| row.get(0),
        )
        .map_err(|_| Refusal::Conflict)?;
    if !exists {
        return Ok(None);
    }
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM universal_actuator_owner_v11",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Refusal::Conflict)?;
    if count != 1 {
        return Err(Refusal::Conflict);
    }
    let value: Option<(Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT binding,family,epoch FROM universal_actuator_owner_v11 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| Refusal::Conflict)?;
    let (binding, family, epoch) = value.ok_or(Refusal::Conflict)?;
    if epoch <= 0 {
        return Err(Refusal::Conflict);
    }
    Ok(Some((binding, family, epoch as u64)))
}

fn require_owner(row: &(Vec<u8>, i64, u64), binding: [u8; 32], family: u8) -> Result<(), Refusal> {
    if row.0.as_slice() != binding || row.1 != i64::from(family) || row.2 == 0 {
        return Err(Refusal::Conflict);
    }
    Ok(())
}

fn require_empty_creation_prefix(
    connection: &Connection,
    family: ProductionChainFamilyV11,
) -> Result<(), Refusal> {
    let tables = match family {
        ProductionChainFamilyV11::Sol => ["solana_operation_v1", "solana_mutation_v1"],
        ProductionChainFamilyV11::Xmr => ["xmr_operation_v1", "xmr_mutation_v1"],
        _ => return Err(Refusal::Conflict),
    };
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
        .map_err(|_| Refusal::Conflict)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| Refusal::Conflict)?;
    for row in rows {
        let (kind, name, table) = row.map_err(|_| Refusal::Conflict)?;
        if kind != "table" || name != table || !tables.contains(&table.as_str()) {
            return Err(Refusal::Conflict);
        }
        // Identifier is one of the two static constants above.
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(|_| Refusal::Conflict)?;
        if count != 0 {
            return Err(Refusal::Conflict);
        }
    }
    Ok(())
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, Refusal> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(Refusal::Conflict)?;
    Ok(path.with_file_name(format!("{name}{suffix}")))
}

fn absent(path: &Path) -> Result<bool, Refusal> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(Refusal::Unavailable),
    }
}

fn require_absent(path: &Path) -> Result<(), Refusal> {
    if absent(path)? {
        Ok(())
    } else {
        Err(Refusal::Conflict)
    }
}

fn require_regular(path: &Path, owner: u32) -> Result<(), Refusal> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Refusal::Conflict);
    }
    Ok(())
}

fn require_same_inode(file: &File, path: &Path, owner: u32) -> Result<(), Refusal> {
    require_regular(path, owner)?;
    let opened = file.metadata().map_err(|_| Refusal::Unavailable)?;
    let current = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
    if opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(Refusal::Conflict);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), Refusal> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| Refusal::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn v11_both_native_stores_refuse_absence_and_foreign_schema_on_reopen() {
        let root = root();
        let missing = root.path().join("missing.sqlite");
        assert!(XmrOperationStoreV1::open_existing_production(&missing).is_err());
        assert!(SolanaOperationStoreV1::open_existing_production(&missing).is_err());
        assert!(!missing.exists());
        let foreign = root.path().join("foreign.sqlite");
        let connection = Connection::open(&foreign).unwrap();
        connection
            .execute_batch("CREATE TABLE foreign_data(id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(connection);
        assert!(XmrOperationStoreV1::open_existing_production(&foreign).is_err());
        assert!(SolanaOperationStoreV1::open_existing_production(&foreign).is_err());
    }

    #[test]
    fn v11_selected_actuator_excludes_concurrent_owner_and_advances_only_exact_scope() {
        for family in [ProductionChainFamilyV11::Sol, ProductionChainFamilyV11::Xmr] {
            let root = root();
            let path = root.path().join("actuator.sqlite");
            let (actuator, guard) = open_universal_actuator_v11(
                &path,
                [7; 32],
                family,
                Mode::Create,
                Stage::Absent,
                Stage::Started,
            )
            .unwrap();
            assert_eq!(guard.epoch(), 1);
            assert!(open_universal_actuator_v11(
                &path,
                [7; 32],
                family,
                Mode::ReopenExisting,
                Stage::Complete,
                Stage::Complete
            )
            .is_err());
            drop(actuator);
            drop(guard);
            assert!(open_universal_actuator_v11(
                &path,
                [8; 32],
                family,
                Mode::ReopenExisting,
                Stage::Complete,
                Stage::Complete
            )
            .is_err());
            let (actuator, guard) = open_universal_actuator_v11(
                &path,
                [7; 32],
                family,
                Mode::ReopenExisting,
                Stage::Complete,
                Stage::Complete,
            )
            .unwrap();
            assert_eq!(guard.epoch(), 2);
            drop(actuator);
            drop(guard);
        }
    }

    #[test]
    fn v11_started_creation_finishes_only_its_own_truncated_lock_before_database_creation() {
        let root = root();
        let path = root.path().join("actuator.sqlite");
        let lock = sibling(&path, ".process.lock").unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap();
        file.write_all(&LOCK_HEADER[..7]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(open_universal_actuator_v11(
            &path,
            [7; 32],
            ProductionChainFamilyV11::Xmr,
            Mode::ReopenExisting,
            Stage::Complete,
            Stage::Complete
        )
        .is_err());
        assert!(!path.exists());
        let (actuator, guard) = open_universal_actuator_v11(
            &path,
            [7; 32],
            ProductionChainFamilyV11::Xmr,
            Mode::Create,
            Stage::Started,
            Stage::Started,
        )
        .unwrap();
        assert_eq!(guard.epoch(), 1);
        drop(actuator);
        drop(guard);
    }

    #[test]
    fn v11_child_renews_finite_native_lease_while_retaining_the_actual_process_lock() {
        let root = root();
        let path = root.path().join("actuator.sqlite");
        let (actuator, guard) = open_universal_actuator_v11(
            &path,
            [7; 32],
            ProductionChainFamilyV11::Xmr,
            Mode::Create,
            Stage::Absent,
            Stage::Started,
        )
        .unwrap();
        let owner = guard
            .lease_owner_v11([8; 32], [9; 32], [10; 32], 50)
            .unwrap();
        let lease = owner.xmr_lease(100).unwrap();
        drop(guard);
        assert!(open_universal_actuator_v11(
            &path,
            [7; 32],
            ProductionChainFamilyV11::Xmr,
            Mode::ReopenExisting,
            Stage::Complete,
            Stage::Complete
        )
        .is_err());
        let ProductionUniversalActuatorV11::Monero(actuator) = actuator else {
            panic!("XMR store");
        };
        let locator = xmr_actuator::XmrOperationLocatorV1 {
            settlement_id: [11; 32],
            kind: xmr_actuator::XmrOperationKindV1::Refund,
        };
        // This fixture tests the custody/lease boundary. The native child
        // verifies actual Monero consensus bytes before calling this store.
        assert_eq!(
            actuator.prepare_signed(&lease, locator, [12; 32], [13; 32], &[1, 2, 3], 150),
            Err(xmr_actuator::XmrActuatorErrorV1::LeaseExpired)
        );
        let renewed = owner.xmr_lease(150).unwrap();
        assert!(actuator
            .prepare_signed(&renewed, locator, [12; 32], [13; 32], &[1, 2, 3], 150)
            .is_ok());
        assert!(owner.xmr_lease(u64::MAX).is_err());
        let connection = open_no_create(&path).unwrap();
        connection
            .execute(
                "UPDATE universal_actuator_owner_v11 SET epoch=2 WHERE singleton=1",
                [],
            )
            .unwrap();
        // The old lease is still within its finite wall-clock lifetime and
        // the old operation still has epoch 1. The native write must observe
        // owner epoch 2 itself rather than depend on a later heartbeat.
        assert_eq!(
            actuator.prepare_signed(&renewed, locator, [12; 32], [13; 32], &[1, 2, 3], 175),
            Err(xmr_actuator::XmrActuatorErrorV1::Conflict)
        );
        assert_eq!(actuator.retained(locator).unwrap(), vec![1, 2, 3]);
        assert!(owner.xmr_lease(200).is_err());
    }
}
