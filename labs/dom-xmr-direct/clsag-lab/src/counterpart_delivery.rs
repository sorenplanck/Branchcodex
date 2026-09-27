//! Durable exact-byte delivery of an ALREADY OWED counterpart, on a trusted
//! local Unix filesystem. Caller verifies the canonical first payment, native
//! intent and chain observations. This module does not authenticate a node,
//! establish finality, authorize refunds or reapply the initial-release deadline.
//! A failed/ambiguous send never restores privacy. Every attempt requires a
//! fresh observation; no cached inclusion is treated as permanent settlement.

use crate::claim_resume::{digest, take, MAX_RECORD_BYTES};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAGIC: &[u8] = b"DXP1/counterpart-delivery/v1\0";
const EXPOSED: &[u8] = b"possibly-exposed/v1";

/// Identifies the original approved operation and exact first payment.
/// Construct ONLY after native/canonical verification. Fields are commitments,
/// not chain proofs. `manifest` pins the pre-release immutable manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryBinding {
    pub manifest: [u8; 32],
    pub first_claim: [u8; 32],
    pub first_block: [u8; 32],
    pub first_height: u64,
    pub target_chain: [u8; 32],
}

impl DeliveryBinding {
    fn encode(self) -> Result<Vec<u8>, DeliveryError> {
        if [
            self.manifest,
            self.first_claim,
            self.first_block,
            self.target_chain,
        ]
        .contains(&[0; 32])
        {
            return Err(DeliveryError::Binding);
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.manifest);
        bytes.extend(self.first_claim);
        bytes.extend(self.first_block);
        bytes.extend(self.first_height.to_le_bytes());
        bytes.extend(self.target_chain);
        Ok(bytes)
    }
}

#[derive(Debug)]
pub enum DeliveryError {
    Io(io::Error),
    Locked,
    Binding,
    Corrupt,
    Poisoned,
    NeedsReconciliation,
}
impl From<io::Error> for DeliveryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    /// RPC error, partial view or insufficient evidence. NEVER implies absence.
    Unknown,
    InPool,
    Included {
        block: [u8; 32],
        height: u64,
    },
    /// Exact transaction absent AND input unspent in a coherent fresh snapshot.
    /// Caller also revalidates the obligation; an RPC "not found" is insufficient.
    AbsentAndUnspent,
    ConflictingSpend {
        transaction: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryAction {
    Reconcile,
    MonitorPool,
    MonitorInclusion,
    RetryExactBytes,
    ResolveConflict,
}

pub struct CounterpartDelivery {
    file: File,
    binding: DeliveryBinding,
    payload: Vec<u8>,
    record_digest: [u8; 32],
    exposed: bool,
    poisoned: bool,
}

fn open_file(path: &Path, create: bool) -> Result<File, DeliveryError> {
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(create)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => DeliveryError::Locked,
        std::fs::TryLockError::Error(e) => DeliveryError::Io(e),
    })?;
    if !file.metadata()?.is_file() {
        return Err(DeliveryError::Corrupt);
    }
    Ok(file)
}
fn sync_directory(path: &Path) -> Result<(), DeliveryError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(DeliveryError::Binding)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

impl CounterpartDelivery {
    pub fn create(
        path: &Path,
        binding: DeliveryBinding,
        payload: &[u8],
    ) -> Result<Self, DeliveryError> {
        if payload.is_empty() || payload.len() > MAX_RECORD_BYTES {
            return Err(DeliveryError::Binding);
        }
        let mut header = binding.encode()?;
        header.extend((payload.len() as u32).to_le_bytes());
        header.extend(payload);
        let record_digest = digest(&header);
        header.extend(record_digest);
        let mut file = open_file(path, true)?;
        file.write_all(&header)?;
        file.sync_all()?;
        sync_directory(path)?;
        Ok(Self {
            file,
            binding,
            payload: payload.to_vec(),
            record_digest,
            exposed: false,
            poisoned: false,
        })
    }

    /// No create-on-missing or tail repair. A complete record is resynced on
    /// reopen in case the creator died before syncing the directory entry.
    pub fn open(path: &Path, expected: DeliveryBinding) -> Result<Self, DeliveryError> {
        let prefix = expected.encode()?;
        let mut file = open_file(path, false)?;
        let mut bytes = vec![];
        (&mut file)
            .take((prefix.len() + 4 + MAX_RECORD_BYTES + 64 + EXPOSED.len() + 1) as u64)
            .read_to_end(&mut bytes)?;
        let mut rest = bytes
            .strip_prefix(prefix.as_slice())
            .ok_or(DeliveryError::Binding)?;
        let len = u32::from_le_bytes(take(&mut rest).ok_or(DeliveryError::Corrupt)?) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(DeliveryError::Corrupt);
        }
        let (payload, tail) = rest.split_at_checked(len).ok_or(DeliveryError::Corrupt)?;
        let mut tail = tail;
        let record_digest: [u8; 32] = take(&mut tail).ok_or(DeliveryError::Corrupt)?;
        if digest(&bytes[..prefix.len() + 4 + len]) != record_digest {
            return Err(DeliveryError::Corrupt);
        }
        let exposed = if tail.is_empty() {
            false
        } else {
            let mut event = EXPOSED.to_vec();
            event.extend(Sha256::digest([record_digest.as_slice(), EXPOSED].concat()));
            if tail != event {
                return Err(DeliveryError::Corrupt);
            }
            true
        };
        file.sync_all()?;
        sync_directory(path)?;
        Ok(Self {
            file,
            binding: expected,
            payload: payload.to_vec(),
            record_digest,
            exposed,
            poisoned: false,
        })
    }

    pub fn binding(&self) -> DeliveryBinding {
        self.binding
    }
    pub fn payload_digest(&self) -> [u8; 32] {
        digest(&self.payload)
    }
    pub fn possibly_exposed(&self) -> Result<bool, DeliveryError> {
        if self.poisoned {
            Err(DeliveryError::Poisoned)
        } else {
            Ok(self.exposed)
        }
    }
    /// Returning these already-completed bytes is NOT an authorization to send.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn reconcile(
        &self,
        chain: [u8; 32],
        transaction_digest: [u8; 32],
        observation: Observation,
    ) -> Result<DeliveryAction, DeliveryError> {
        self.possibly_exposed()?;
        if chain != self.binding.target_chain || transaction_digest != self.payload_digest() {
            return Err(DeliveryError::Binding);
        }
        Ok(match observation {
            Observation::Unknown => DeliveryAction::Reconcile,
            Observation::InPool => DeliveryAction::MonitorPool,
            Observation::Included { block, .. } if block != [0; 32] => {
                DeliveryAction::MonitorInclusion
            }
            Observation::Included { .. } => return Err(DeliveryError::Binding),
            Observation::AbsentAndUnspent => DeliveryAction::RetryExactBytes,
            Observation::ConflictingSpend { transaction } if transaction != [0; 32] => {
                DeliveryAction::ResolveConflict
            }
            Observation::ConflictingSpend { .. } => return Err(DeliveryError::Binding),
        })
    }

    /// Only returns the originally persisted bytes, after fsync of possible
    /// exposure. No new signature, fee bump or deadline reset is offered.
    pub fn prepare_attempt(
        &mut self,
        chain: [u8; 32],
        transaction_digest: [u8; 32],
        fresh: Observation,
    ) -> Result<&[u8], DeliveryError> {
        if self.reconcile(chain, transaction_digest, fresh)? != DeliveryAction::RetryExactBytes {
            return Err(DeliveryError::NeedsReconciliation);
        }
        if !self.exposed {
            self.poisoned = true;
            let mut event = EXPOSED.to_vec();
            event.extend(Sha256::digest(
                [self.record_digest.as_slice(), EXPOSED].concat(),
            ));
            self.file.write_all(&event)?;
            self.file.sync_all()?;
            self.exposed = true;
            self.poisoned = false;
        }
        Ok(&self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_exposure_write_poisoning_blocks_same_handle_retry() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "delivery-io-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let binding = DeliveryBinding {
            manifest: [1; 32],
            first_claim: [2; 32],
            first_block: [3; 32],
            first_height: 7,
            target_chain: [4; 32],
        };
        let mut journal = CounterpartDelivery::create(&path, binding, b"claim").unwrap();
        let original = std::fs::read(&path).unwrap();
        let hash = journal.payload_digest();
        journal.file = File::open(&path).unwrap();
        journal.file.try_lock().unwrap();
        assert!(matches!(
            journal.prepare_attempt(binding.target_chain, hash, Observation::AbsentAndUnspent),
            Err(DeliveryError::Io(_))
        ));
        assert!(matches!(
            journal.prepare_attempt(binding.target_chain, hash, Observation::AbsentAndUnspent),
            Err(DeliveryError::Poisoned)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }
}
