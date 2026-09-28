//! Durable transition log for the DXF1 prepared-liquidity fast handoff.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::fast_handoff::{
    FastHandoff, FastHandoffBinding, FastHandoffError, FastHandoffPhase, DXF1_PROTOCOL,
};

const MAGIC: &[u8] = b"DXF1/fast-handoff-journal/v2\0";
const MAX_FILE_BYTES: u64 = 4096;

#[derive(Debug)]
pub enum FastHandoffJournalError {
    Io(io::Error),
    Locked,
    Binding,
    Corrupt,
    Denied(FastHandoffError),
    Poisoned,
}

impl From<io::Error> for FastHandoffJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct FastHandoffJournal {
    file: File,
    binding: FastHandoffBinding,
    state: FastHandoff,
    last_digest: [u8; 32],
    poisoned: bool,
}

fn header(binding: FastHandoffBinding) -> Vec<u8> {
    let policy = binding.policy();
    let mut bytes = MAGIC.to_vec();
    bytes.extend(DXF1_PROTOCOL);
    for value in [
        binding.operation(),
        binding.dom_chain(),
        binding.dom_funding(),
        binding.xmr_reserve(),
        binding.dom_claim(),
        binding.xmr_payment_intent(),
    ] {
        bytes.extend(value);
    }
    for value in [
        policy.active_deadline_seconds(),
        policy.minimum_dom_funding_confirmations(),
        policy.maximum_dom_claim_inclusion_blocks(),
        policy.minimum_dom_claim_confirmations(),
        policy.claim_until(),
    ] {
        bytes.extend(value.to_le_bytes());
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend(digest);
    bytes
}

fn open_file(path: &Path, create: bool) -> Result<File, FastHandoffJournalError> {
    if !create {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(FastHandoffJournalError::Corrupt);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(create)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => FastHandoffJournalError::Locked,
        std::fs::TryLockError::Error(error) => FastHandoffJournalError::Io(error),
    })?;
    Ok(file)
}

fn sync_parent(path: &Path) -> Result<(), FastHandoffJournalError> {
    File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(FastHandoffJournalError::Binding)?,
    )?
    .sync_all()?;
    Ok(())
}

fn payload_len(tag: u8) -> Option<usize> {
    match tag {
        1 => Some(73),
        2 | 3 => Some(48),
        4 => Some(40),
        5 => Some(72),
        6 => Some(72),
        7 => Some(64),
        8 => Some(112),
        _ => None,
    }
}

fn take_id(input: &mut &[u8]) -> Result<[u8; 32], FastHandoffError> {
    if input.len() < 32 {
        return Err(FastHandoffError::WrongOrder);
    }
    let (value, rest) = input.split_at(32);
    *input = rest;
    value.try_into().map_err(|_| FastHandoffError::WrongOrder)
}

fn take_u64(input: &mut &[u8]) -> Result<u64, FastHandoffError> {
    if input.len() < 8 {
        return Err(FastHandoffError::WrongOrder);
    }
    let (value, rest) = input.split_at(8);
    *input = rest;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| FastHandoffError::WrongOrder)?,
    ))
}

fn apply(state: &mut FastHandoff, event: &[u8]) -> Result<(), FastHandoffError> {
    let mut input = &event[1..];
    let result = match event[0] {
        1 => {
            let funding = take_id(&mut input)?;
            let confirmations = take_u64(&mut input)?;
            let reserve = take_id(&mut input)?;
            let mature = match input.first().copied() {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(FastHandoffError::WrongOrder),
            };
            input = &input[1..];
            state.record_ready(funding, confirmations, reserve, mature)
        }
        2 => {
            let claim = take_id(&mut input)?;
            let target = take_u64(&mut input)?;
            let elapsed = take_u64(&mut input)?;
            state.record_dom_claim_exposure(claim, target, elapsed)
        }
        3 => {
            let claim = take_id(&mut input)?;
            let next_height = take_u64(&mut input)?;
            let elapsed = take_u64(&mut input)?;
            state.record_dom_daemon_admission(claim, next_height, elapsed)
        }
        4 => {
            let payment = take_id(&mut input)?;
            let elapsed = take_u64(&mut input)?;
            state.record_xmr_release_commitment(payment, elapsed)
        }
        5 => {
            let intent = take_id(&mut input)?;
            let transaction = take_id(&mut input)?;
            let elapsed = take_u64(&mut input)?;
            state.record_xmr_daemon_admission(intent, transaction, elapsed)
        }
        6 => {
            let claim = take_id(&mut input)?;
            let height = take_u64(&mut input)?;
            let block = take_id(&mut input)?;
            state.record_dom_claim_inclusion(claim, height, block)
        }
        7 => {
            let claim = take_id(&mut input)?;
            let block = take_id(&mut input)?;
            state.record_dom_claim_reorg(claim, block)
        }
        8 => {
            let claim = take_id(&mut input)?;
            let inclusion_height = take_u64(&mut input)?;
            let inclusion_block = take_id(&mut input)?;
            let tip_height = take_u64(&mut input)?;
            let tip_block = take_id(&mut input)?;
            state
                .record_dom_claim_finality(
                    claim,
                    inclusion_height,
                    inclusion_block,
                    tip_height,
                    tip_block,
                )
                .map(|_| ())
        }
        _ => Err(FastHandoffError::WrongOrder),
    };
    if !input.is_empty() {
        return Err(FastHandoffError::WrongOrder);
    }
    result
}

impl FastHandoffJournal {
    pub fn create(
        path: &Path,
        binding: FastHandoffBinding,
    ) -> Result<Self, FastHandoffJournalError> {
        let header = header(binding);
        let mut file = open_file(path, true)?;
        file.write_all(&header)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            file,
            binding,
            state: FastHandoff::new(binding),
            last_digest: header[header.len() - 32..].try_into().unwrap(),
            poisoned: false,
        })
    }

    pub fn open(path: &Path, binding: FastHandoffBinding) -> Result<Self, FastHandoffJournalError> {
        let header = header(binding);
        let mut file = open_file(path, false)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE_BYTES as usize
            || bytes.len() < header.len()
            || bytes[..header.len()] != header
        {
            return Err(FastHandoffJournalError::Corrupt);
        }
        let mut state = FastHandoff::new(binding);
        let mut previous: [u8; 32] = header[header.len() - 32..].try_into().unwrap();
        let mut input = &bytes[header.len()..];
        while !input.is_empty() {
            let event_len = 1 + payload_len(input[0]).ok_or(FastHandoffJournalError::Corrupt)?;
            if input.len() < event_len + 32 {
                return Err(FastHandoffJournalError::Corrupt);
            }
            let (event, rest) = input.split_at(event_len);
            let (checksum, rest) = rest.split_at(32);
            let mut hash = Sha256::new();
            hash.update(previous);
            hash.update(event);
            let calculated: [u8; 32] = hash.finalize().into();
            if checksum != calculated || apply(&mut state, event).is_err() {
                return Err(FastHandoffJournalError::Corrupt);
            }
            previous = calculated;
            input = rest;
        }
        Ok(Self {
            file,
            binding,
            state,
            last_digest: previous,
            poisoned: false,
        })
    }

    pub fn state(&self) -> Result<FastHandoff, FastHandoffJournalError> {
        if self.poisoned {
            Err(FastHandoffJournalError::Poisoned)
        } else {
            Ok(self.state)
        }
    }

    fn append(&mut self, event: Vec<u8>) -> Result<(), FastHandoffJournalError> {
        self.state()?;
        let mut next = self.state;
        apply(&mut next, &event).map_err(FastHandoffJournalError::Denied)?;
        let mut hash = Sha256::new();
        hash.update(self.last_digest);
        hash.update(&event);
        let checksum: [u8; 32] = hash.finalize().into();
        self.poisoned = true;
        self.file.write_all(&event)?;
        self.file.write_all(&checksum)?;
        self.file.sync_all()?;
        self.state = next;
        self.last_digest = checksum;
        self.poisoned = false;
        Ok(())
    }

    pub fn record_ready(
        &mut self,
        funding: [u8; 32],
        confirmations: u64,
        reserve: [u8; 32],
        mature: bool,
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![1];
        event.extend(funding);
        event.extend(confirmations.to_le_bytes());
        event.extend(reserve);
        event.push(u8::from(mature));
        self.append(event)
    }

    pub fn record_dom_claim_exposure(
        &mut self,
        claim: [u8; 32],
        target: u64,
        elapsed: u64,
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![2];
        event.extend(claim);
        event.extend(target.to_le_bytes());
        event.extend(elapsed.to_le_bytes());
        self.append(event)
    }

    pub fn record_dom_daemon_admission(
        &mut self,
        claim: [u8; 32],
        next_height: u64,
        elapsed: u64,
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![3];
        event.extend(claim);
        event.extend(next_height.to_le_bytes());
        event.extend(elapsed.to_le_bytes());
        self.append(event)
    }

    pub fn record_xmr_release_commitment(
        &mut self,
        payment: [u8; 32],
        elapsed: u64,
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![4];
        event.extend(payment);
        event.extend(elapsed.to_le_bytes());
        self.append(event)
    }

    pub fn record_xmr_daemon_admission(
        &mut self,
        intent: [u8; 32],
        transaction: [u8; 32],
        elapsed: u64,
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![5];
        event.extend(intent);
        event.extend(transaction);
        event.extend(elapsed.to_le_bytes());
        self.append(event)
    }

    pub fn record_dom_claim_inclusion(
        &mut self,
        claim: [u8; 32],
        height: u64,
        canonical_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![6];
        event.extend(claim);
        event.extend(height.to_le_bytes());
        event.extend(canonical_block);
        self.append(event)
    }

    pub fn record_dom_claim_reorg(
        &mut self,
        claim: [u8; 32],
        orphaned_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![7];
        event.extend(claim);
        event.extend(orphaned_block);
        self.append(event)
    }

    pub fn record_dom_claim_finality(
        &mut self,
        claim: [u8; 32],
        inclusion_height: u64,
        inclusion_block: [u8; 32],
        tip_height: u64,
        tip_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        let mut event = vec![8];
        event.extend(claim);
        event.extend(inclusion_height.to_le_bytes());
        event.extend(inclusion_block);
        event.extend(tip_height.to_le_bytes());
        event.extend(tip_block);
        self.append(event)
    }

    pub fn authorize_refund(&self, height: u64) -> Result<(), FastHandoffJournalError> {
        self.state()?
            .authorize_refund(height)
            .map_err(FastHandoffJournalError::Denied)
    }

    pub const fn binding(&self) -> FastHandoffBinding {
        self.binding
    }

    pub fn completed(&self) -> Result<bool, FastHandoffJournalError> {
        Ok(self.state()?.phase() == FastHandoffPhase::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fast_handoff::FastHandoffPolicy;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dxf1-fast-journal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn journal(&self) -> PathBuf {
            self.0.join("handoff.wal")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn binding() -> FastHandoffBinding {
        FastHandoffBinding::new(
            id(1),
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn restart_preserves_irreversible_xmr_release_and_rebroadcast() {
        let scratch = Scratch::new();
        let path = scratch.journal();
        let mut journal = FastHandoffJournal::create(&path, binding()).unwrap();
        journal.record_ready(id(3), 2, id(4), true).unwrap();
        journal.record_dom_claim_exposure(id(5), 95, 1).unwrap();
        journal.record_dom_daemon_admission(id(5), 95, 2).unwrap();
        journal.record_xmr_release_commitment(id(6), 3).unwrap();
        drop(journal);

        let mut journal = FastHandoffJournal::open(&path, binding()).unwrap();
        assert!(matches!(
            journal.authorize_refund(u64::MAX),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::RefundPermanentlyForbidden
            ))
        ));
        assert!(journal.state().unwrap().rebroadcast_required());
        journal
            .record_xmr_daemon_admission(id(6), id(7), 4)
            .unwrap();
        assert!(journal.completed().unwrap());
        journal
            .record_dom_claim_inclusion(id(5), 96, id(8))
            .unwrap();
        journal
            .record_dom_claim_finality(id(5), 96, id(8), 97, id(9))
            .unwrap();
        drop(journal);
        let journal = FastHandoffJournal::open(&path, binding()).unwrap();
        let state = journal.state().unwrap();
        assert!(state.dom_claim_finalized());
        assert_eq!(state.dom_claim_canonical_block(), Some(id(8)));
        assert_eq!(state.dom_claim_finality_tip(), Some(id(9)));
    }

    #[test]
    fn binding_order_and_checksums_are_fail_closed() {
        let scratch = Scratch::new();
        let path = scratch.journal();
        let mut journal = FastHandoffJournal::create(&path, binding()).unwrap();
        assert!(journal.record_dom_claim_exposure(id(5), 95, 1).is_err());
        journal.record_ready(id(3), 2, id(4), true).unwrap();
        drop(journal);

        let changed = FastHandoffBinding::new(
            id(1),
            id(2),
            id(3),
            id(4),
            id(5),
            id(7),
            FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            FastHandoffJournal::open(&path, changed),
            Err(FastHandoffJournalError::Corrupt)
        ));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            FastHandoffJournal::open(&path, binding()),
            Err(FastHandoffJournalError::Corrupt)
        ));
    }

    #[test]
    fn unsafe_permissions_are_rejected() {
        let scratch = Scratch::new();
        let path = scratch.journal();
        drop(FastHandoffJournal::create(&path, binding()).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            FastHandoffJournal::open(&path, binding()),
            Err(FastHandoffJournalError::Corrupt)
        ));
    }
}
