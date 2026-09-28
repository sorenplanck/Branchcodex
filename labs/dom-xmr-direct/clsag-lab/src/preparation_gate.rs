//! Exclusive local preparation decision, established BEFORE shared funding.
//! Every cooperative adaptor/release path must honor this gate. It does not
//! prove peer behavior, chain state, refund safety after exposure or timing.
//! Trusted private directory, honest fsync and cooperative advisory locking
//! are required; hostile replacement/backup rollback are not defended here.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const MAGIC: &[u8] = b"DXP1/preparation-decision/v1\0";
const HEADER: usize = MAGIC.len() + 64 + 8 + 32;
const EVENT: usize = 1 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationBinding {
    /// Original recovery link, itself bound to reservation, roles and capsule.
    pub capsule_link: [u8; 64],
    pub received: u64,
}
impl PreparationBinding {
    fn header(self) -> Result<Vec<u8>, GateError> {
        if self.capsule_link == [0; 64] || self.received == 0 {
            return Err(GateError::Binding);
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.capsule_link);
        bytes.extend(self.received.to_le_bytes());
        bytes.extend(Sha256::digest(&bytes));
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationState {
    Private,
    /// Transition occurs BEFORE adaptor/signature release, even if IO fails.
    ExchangePossible {
        operation: [u8; 32],
    },
    /// Only this pinned recovery job may use the pre-exchange recovery path.
    RecoveryOnly {
        job: [u8; 32],
    },
}

#[derive(Debug)]
pub enum GateError {
    Io(io::Error),
    Locked,
    Binding,
    Corrupt,
    Denied,
    Poisoned,
}
impl From<io::Error> for GateError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct PreparationGate {
    file: File,
    header_digest: [u8; 32],
    state: PreparationState,
    poisoned: bool,
}

fn open_file(path: &Path, create: bool) -> Result<File, GateError> {
    if !create {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o600 {
            return Err(GateError::Corrupt);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(create)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => GateError::Locked,
        std::fs::TryLockError::Error(e) => GateError::Io(e),
    })?;
    if !file.metadata()?.is_file() {
        return Err(GateError::Corrupt);
    }
    Ok(file)
}
fn sync_parent(path: &Path) -> Result<(), GateError> {
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(GateError::Binding)?,
    )?
    .sync_all()?;
    Ok(())
}
impl PreparationGate {
    /// Only before any shared funding/adaptor disclosure, never fallback for
    /// a missing or damaged existing operation. Parent must already be durable.
    pub fn create(path: &Path, binding: PreparationBinding) -> Result<Self, GateError> {
        let header = binding.header()?;
        let mut file = open_file(path, true)?;
        file.write_all(&header)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            file,
            header_digest: header[HEADER - 32..].try_into().unwrap(),
            state: PreparationState::Private,
            poisoned: false,
        })
    }

    pub fn open(path: &Path, binding: PreparationBinding) -> Result<Self, GateError> {
        let header = binding.header()?;
        let mut file = open_file(path, false)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take((HEADER + EVENT + 1) as u64)
            .read_to_end(&mut bytes)?;
        if !matches!(bytes.len(),n if n==HEADER || n==HEADER+EVENT) {
            return Err(GateError::Corrupt);
        }
        if bytes[..HEADER] != header {
            return Err(GateError::Binding);
        }
        let header_digest = header[HEADER - 32..].try_into().unwrap();
        let state = if bytes.len() == HEADER {
            PreparationState::Private
        } else {
            let event = &bytes[HEADER..];
            let mut hash = Sha256::new();
            hash.update(header_digest);
            hash.update(&event[..33]);
            if hash.finalize().as_slice() != &event[33..] {
                return Err(GateError::Corrupt);
            }
            let target: [u8; 32] = event[1..33].try_into().unwrap();
            if target == [0; 32] {
                return Err(GateError::Binding);
            }
            match event[0] {
                1 => PreparationState::ExchangePossible { operation: target },
                2 => PreparationState::RecoveryOnly { job: target },
                _ => return Err(GateError::Corrupt),
            }
        };
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            file,
            header_digest,
            state,
            poisoned: false,
        })
    }

    pub fn state(&self) -> Result<PreparationState, GateError> {
        if self.poisoned {
            Err(GateError::Poisoned)
        } else {
            Ok(self.state)
        }
    }
    fn decide(&mut self, tag: u8, target: [u8; 32]) -> Result<(), GateError> {
        if self.state()? != PreparationState::Private || target == [0; 32] {
            return Err(GateError::Denied);
        }
        self.poisoned = true;
        let mut event = vec![tag];
        event.extend(target);
        let mut hash = Sha256::new();
        hash.update(self.header_digest);
        hash.update(&event);
        event.extend(hash.finalize());
        self.file.write_all(&event)?;
        self.file.sync_all()?;
        self.state = match tag {
            1 => PreparationState::ExchangePossible { operation: target },
            2 => PreparationState::RecoveryOnly { job: target },
            _ => unreachable!(),
        };
        self.poisoned = false;
        Ok(())
    }
    /// Call BEFORE entering adaptor/signature exchange. Failure or cancellation
    /// afterward never restores Private. Not itself initial-claim permission.
    pub fn begin_exchange(&mut self, operation: [u8; 32]) -> Result<(), GateError> {
        self.decide(1, operation)
    }
    /// A retry of the SAME job may retain recovery exclusivity; never grants
    /// extra time, resets exposure, recreates nonces, or authorizes a network send.
    pub fn claim_recovery(&mut self, job: [u8; 32]) -> Result<(), GateError> {
        match self.state()? {
            PreparationState::Private => self.decide(2, job),
            PreparationState::RecoveryOnly { job: original }
                if original == job && job != [0; 32] =>
            {
                Ok(())
            }
            _ => Err(GateError::Denied),
        }
    }
    /// Pair this with the original InitialClaimJournal/chain reconciliation.
    /// RecoveryOnly, even with a stale in-memory adaptor, denies exchange sends.
    pub fn require_exchange(&self, operation: [u8; 32]) -> Result<(), GateError> {
        match self.state()? {
            PreparationState::ExchangePossible {
                operation: original,
            } if original == operation && operation != [0; 32] => Ok(()),
            _ => Err(GateError::Denied),
        }
    }
}
