//! Private append-only backing for a long native scenario. Every payload is
//! produced by the existing native ledger; storage never invents a block.
use super::*;
use rusqlite::{params, Connection, OpenFlags};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

pub(super) struct CampaignHistoryV24 {
    connection: Connection,
    path: PathBuf,
    maximum: u64,
    tip: u64,
    hash: String,
}

/// A frozen read transaction, not a capability to submit or sign. SQLite pages
/// retain every original block; no Vec of the entire campaign is constructed.
pub(crate) struct PublicDomHistoryPagesV24 {
    source: PublicSourceV24,
    tip: u64,
    maximum: u64,
}

enum PublicSourceV24 {
    Memory(Vec<Value>),
    Disk(Connection),
}

fn require_private_parent(parent: &Path) -> Result<()> {
    if !parent.is_absolute() {
        return Err("campaign history requires an absolute private parent".into());
    }
    let owner = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o022 != 0
            || (metadata.uid() != owner && metadata.uid() != 0)
        {
            return Err("campaign history unsafe ancestry".into());
        }
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err("campaign history parent is not privately owned".into());
    }
    Ok(())
}

impl CampaignHistoryV24 {
    pub(super) fn create(parent: &Path, blocks: &[Value], maximum: u64) -> Result<Self> {
        require_private_parent(parent)?;
        if blocks.is_empty() || blocks.len() > 4096 || maximum > Snapshot::MAX_CAMPAIGN_HEIGHT_V24 {
            return Err("campaign baseline or maximum bound".into());
        }
        let root = tempfile::Builder::new()
            .prefix("dom-history-v24-")
            .tempdir_in(parent)?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = root.path().join("history.sqlite");
        let connection = Connection::open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA cache_size=-2048; CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, payload BLOB NOT NULL, digest BLOB NOT NULL); CREATE TABLE transactions(hash TEXT PRIMARY KEY, height INTEGER NOT NULL);")?;
        let first = blocks.first().ok_or("campaign genesis absent")?;
        if first["height"].as_u64() != Some(0) {
            return Err("campaign genesis absent".into());
        }
        let mut owner = Self {
            connection,
            path,
            maximum,
            tip: 0,
            hash: String::new(),
        };
        owner.begin_batch()?;
        for block in blocks {
            owner.insert(block, owner.hash.is_empty())?;
        }
        owner.commit_batch()?;
        owner.require_private_files()?;
        // The parent fixture owns retention/cleanup, including after helpers
        // are reaped. Do not delete the evidence when this owner is dropped.
        std::fs::File::open(root.path())?.sync_all()?;
        let _retained = root.keep();
        Ok(owner)
    }
    pub(super) fn maximum(&self) -> u64 {
        self.maximum
    }
    pub(super) fn begin_batch(&self) -> Result<()> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }
    pub(super) fn commit_batch(&self) -> Result<()> {
        self.connection.execute_batch("COMMIT")?;
        self.require_private_files()?;
        Ok(())
    }
    fn require_private_files(&self) -> Result<()> {
        // SQLite inherits the already-0600 database mode for WAL/SHM. Check
        // companions too; evidence retention keeps the entire private folder,
        // not just the main database while readers can still retain WAL pages.
        for path in [
            self.path.clone(),
            self.path.with_extension("sqlite-wal"),
            self.path.with_extension("sqlite-shm"),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == rustix::process::geteuid().as_raw()
                        && metadata.mode() & 0o077 == 0 => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && path != self.path => {
                }
                _ => return Err("campaign history or WAL companion ownership".into()),
            }
        }
        Ok(())
    }
    pub(super) fn append(&mut self, block: &Value) -> Result<()> {
        self.insert(block, false)
    }
    fn insert(&mut self, block: &Value, genesis: bool) -> Result<()> {
        let height = block["height"].as_u64().ok_or("campaign block height")?;
        let hash = block["block_hash"].as_str().ok_or("campaign block hash")?;
        if height > self.maximum
            || hash.len() != 64
            || (genesis && height != 0)
            || (!genesis
                && (self.tip.checked_add(1) != Some(height)
                    || block["previous_block_hash"].as_str() != Some(self.hash.as_str())))
        {
            return Err("campaign history discontinuity".into());
        }
        let payload = serde_json::to_vec(block)?;
        if payload.len() > MAX_PAYLOAD {
            return Err("campaign block payload bound".into());
        }
        let digest = dom_crypto::blake2b_256(&payload);
        let sql_height = i64::try_from(height)?;
        self.connection.execute(
            "INSERT INTO blocks(height,hash,payload,digest) VALUES(?1,?2,?3,?4)",
            params![sql_height, hash, payload, digest.as_bytes().as_slice()],
        )?;
        for tx in block["transactions"]
            .as_array()
            .ok_or("campaign transactions absent")?
        {
            let tx_hash = tx["tx_hash"].as_str().ok_or("campaign transaction hash")?;
            self.connection.execute(
                "INSERT INTO transactions(hash,height) VALUES(?1,?2)",
                params![tx_hash, sql_height],
            )?;
        }
        self.tip = height;
        self.hash = hash.to_owned();
        Ok(())
    }
    pub(super) fn block(&self, height: u64) -> Result<Value> {
        read_block(&self.connection, height, self.tip)
    }
    pub(super) fn inclusion(&self, hash: &[u8; 32]) -> Result<u64> {
        let height: i64 = self.connection.query_row(
            "SELECT height FROM transactions WHERE hash=?1",
            [hex::encode(hash)],
            |row| row.get(0),
        )?;
        let height = u64::try_from(height)?;
        if height > self.tip {
            return Err("campaign inclusion exceeds retained tip".into());
        }
        Ok(height)
    }
    pub(super) fn reader(&self) -> Result<PublicDomHistoryPagesV24> {
        self.require_private_files()?;
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err("campaign history file ownership".into());
        }
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute_batch("PRAGMA cache_size=-2048; BEGIN")?;
        let tip = read_block(&connection, self.tip, self.tip)?;
        if tip["block_hash"].as_str() != Some(self.hash.as_str()) {
            return Err("campaign frozen tip mismatch".into());
        }
        Ok(PublicDomHistoryPagesV24 {
            source: PublicSourceV24::Disk(connection),
            tip: self.tip,
            maximum: self.maximum,
        })
    }
}

fn read_block(connection: &Connection, height: u64, tip: u64) -> Result<Value> {
    if height > tip {
        return Err("campaign read exceeds frozen tip".into());
    }
    let (bytes, digest, hash): (Option<Vec<u8>>, Vec<u8>, String) = connection.query_row(
        "SELECT CASE WHEN length(payload)<=?2 THEN payload ELSE NULL END,digest,hash FROM blocks WHERE height=?1",params![i64::try_from(height)?,i64::try_from(MAX_PAYLOAD)?], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    let bytes = bytes.ok_or("campaign read payload bound")?;
    if dom_crypto::blake2b_256(&bytes).as_bytes().as_slice() != digest {
        return Err("campaign payload integrity".into());
    }
    let block: Value = serde_json::from_slice(&bytes)?;
    if block["height"].as_u64() != Some(height)
        || block["block_hash"].as_str() != Some(hash.as_str())
    {
        return Err("campaign indexed scope mismatch".into());
    }
    Ok(block)
}

impl PublicDomHistoryPagesV24 {
    pub(super) fn memory(blocks: Vec<Value>, tip: u64, maximum: u64) -> Result<Self> {
        if blocks.is_empty() || blocks.len() > 4096 || tip > maximum {
            return Err("public memory history bound".into());
        }
        Ok(Self {
            source: PublicSourceV24::Memory(blocks),
            tip,
            maximum,
        })
    }
    pub(crate) fn maximum_height(&self) -> u64 {
        self.maximum
    }
    pub(crate) fn tip_height(&self) -> u64 {
        self.tip
    }
    pub(crate) fn page(&self, from: u64, count: u64) -> Result<Vec<Value>> {
        if count == 0
            || count > 64
            || from
                > self
                    .tip
                    .checked_add(1)
                    .ok_or("public history height overflow")?
        {
            return Err("public history page bound".into());
        }
        let end = from
            .checked_add(count - 1)
            .ok_or("public history page overflow")?
            .min(self.tip);
        let mut page = Vec::new();
        for height in from..=end {
            let block = match &self.source {
                PublicSourceV24::Disk(connection) => read_block(connection, height, self.tip)?,
                PublicSourceV24::Memory(blocks) => blocks
                    .iter()
                    .find(|block| block["height"].as_u64() == Some(height))
                    .ok_or("public history height absent")?
                    .clone(),
            };
            page.push(block);
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Storage/closed-schema test data only: these rows are not native coinbase
    // or chain-authority capabilities and are never fed to the daemon.
    fn block(height: u64) -> Value {
        let hash = hex::encode(dom_crypto::blake2b_256(&height.to_be_bytes()).as_bytes());
        let previous = if height == 0 {
            hex::encode([0u8; 32])
        } else {
            hex::encode(dom_crypto::blake2b_256(&(height - 1).to_be_bytes()).as_bytes())
        };
        json!({"height":height,"block_hash":hash,"previous_block_hash":previous,"transactions":[]})
    }
    fn parent() -> Result<tempfile::TempDir> {
        let home = std::env::var_os("HOME").ok_or("test private home absent")?;
        let root = tempfile::Builder::new()
            .prefix(".dom-history-test-")
            .tempdir_in(home)?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(root)
    }
    #[test]
    fn campaign_pages_preserve_original_absolute_heights_and_request_bounds_v24() -> Result<()> {
        let parent = parent()?;
        let mut history = CampaignHistoryV24::create(parent.path(), &[block(0)], 47083)?;
        history.begin_batch()?;
        for height in 1..=4100 {
            history.append(&block(height))?;
        }
        history.commit_batch()?;
        let reader = history.reader()?;
        let page = reader.page(4090, 64)?;
        assert_eq!(page.len(), 11);
        assert_eq!(page[0], block(4090));
        assert_eq!(page[6], block(4096));
        assert_eq!(page[10], block(4100));
        assert!(reader.page(0, 65).is_err());
        assert!(reader.page(0, 0).is_err());
        assert!(reader.page(4102, 1).is_err());
        assert!(reader.page(4101, 1)?.is_empty());
        assert_eq!(reader.maximum_height(), 47083);
        assert_eq!(reader.tip_height(), 4100);
        let identity = json!({"tip_height":4100,"tip_hash":block(4100)["block_hash"],"network_magic":7,"chain_id":"chain"});
        let request=format!("GET /chain/scan/scriptless/v1?from=4094&to=4100&expected_network_magic=7&expected_chain_id=chain&anchor_hash={} HTTP/1.1",block(4093)["block_hash"].as_str().unwrap());
        let response: Value = serde_json::from_slice(&window_v24::scan_response_with_reader_v24(
            &request,
            &identity,
            |height| history.block(height),
        )?)?;
        assert_eq!(response["blocks"].as_array().unwrap().len(), 7);
        assert_eq!(response["blocks"][2]["height"], json!(4096));
        let mut wrong = identity.clone();
        wrong["tip_hash"] = json!(hex::encode([9u8; 32]));
        assert!(
            window_v24::scan_response_with_reader_v24(&request, &wrong, |height| history
                .block(height))
            .is_err()
        );
        drop(reader);
        let path = history.path.clone();
        drop(history);
        assert!(
            path.is_file(),
            "helper drop must retain original evidence under fixture parent"
        );
        drop(parent);
        assert!(!path.exists(), "parent owns final cleanup");
        Ok(())
    }
    #[test]
    fn campaign_reader_rejects_truncated_or_mutated_storage_v24() -> Result<()> {
        for mutate in [false, true] {
            let parent = parent()?;
            let history = CampaignHistoryV24::create(parent.path(), &[block(0), block(1)], 32)?;
            if mutate {
                history.connection.execute(
                    "UPDATE blocks SET payload=?1 WHERE height=0",
                    [b"{}".as_slice()],
                )?;
            } else {
                history
                    .connection
                    .execute("DELETE FROM blocks WHERE height=0", [])?;
            }
            let reader = history.reader()?;
            assert!(reader.page(0, 2).is_err());
        }
        Ok(())
    }
    #[test]
    fn campaign_append_refuses_skips_and_negotiated_limit_overflow_v24() -> Result<()> {
        let parent = parent()?;
        let mut history = CampaignHistoryV24::create(parent.path(), &[block(0)], 1)?;
        assert!(history.append(&block(2)).is_err());
        history.append(&block(1))?;
        assert!(history.append(&block(2)).is_err());
        assert_eq!(history.reader()?.tip_height(), 1);
        assert!(CampaignHistoryV24::create(
            parent.path(),
            &[block(0)],
            Snapshot::MAX_CAMPAIGN_HEIGHT_V24 + 1
        )
        .is_err());
        Ok(())
    }
    #[test]
    fn campaign_frozen_reader_does_not_block_native_history_publication_v24() -> Result<()> {
        let parent = parent()?;
        let mut history = CampaignHistoryV24::create(parent.path(), &[block(0)], 8)?;
        let frozen = history.reader()?;
        history.begin_batch()?;
        history.append(&block(1))?;
        history.commit_batch()?;
        assert_eq!(frozen.tip_height(), 0);
        assert!(frozen.page(1, 1)?.is_empty());
        assert_eq!(history.reader()?.page(1, 1)?, vec![block(1)]);
        history.require_private_files()?;
        Ok(())
    }
}
