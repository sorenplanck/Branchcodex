//! Experimental write-ahead gate for the INITIAL claim only, on a trusted local
//! Unix filesystem. This is not a complete recovery executor or a signing store.
//! The containing directory must already be durable and private to the operator;
//! every writer must respect the advisory lock. Backup rollback, deletion,
//! malicious local writers and filesystems which lie about fsync are not covered.
//! No signature, witness, nonce or private share is stored here.
//!
//! Keep the original policy after restart. Missing/corrupt records must never
//! trigger creation of a replacement operation. Exposure is sticky, including
//! failed RPC, cancellation and a crash before the actual send. Reconciliation
//! of canonical claims/refunds belongs to a separate executor; this gate neither
//! authorizes a refund nor cancels the obligation to pay an owed counterpart.

use std::{
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use dom_core::Timestamp;
use sha2::{Digest, Sha256};

use crate::time_bounds::{
    AssumedClaimDelays, AssumedXmrRecoveryWindow, InitialClaimOrder, TimingError,
};

const MAGIC: &[u8] = b"DXP1/initial-release/v1\0";
const EVENT_LEN: usize = 1 + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseState {
    Private,
    ExposurePossible,
    InitialReleaseClosed,
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    Locked,
    InvalidRecord,
    BindingMismatch,
    PayloadMismatch,
    NeedsReconciliation,
    InitialReleaseClosed,
    Poisoned,
    Timing(TimingError),
}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Immutable expected policy, reconstructed from the original operation's
/// validated artifacts, never from a new disclosure timestamp. The operation
/// binding must cover chains, roles, both reserves, adaptors and refund terms.
/// Hashing does not authenticate that input or establish timing assumptions.
#[derive(Clone)]
pub struct ReleasePolicy {
    operation: [u8; 32],
    window: AssumedXmrRecoveryWindow,
    order: InitialClaimOrder,
    delays: AssumedClaimDelays,
    claim_digest: [u8; 32],
}

pub fn claim_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DXP1/initial-release/transaction/v1");
    hash.update(bytes);
    hash.finalize().into()
}

impl ReleasePolicy {
    pub fn new(
        operation: [u8; 32],
        window: &AssumedXmrRecoveryWindow,
        order: InitialClaimOrder,
        delays: AssumedClaimDelays,
        claim_digest: [u8; 32],
    ) -> Result<Self, JournalError> {
        if operation == [0; 32] || claim_digest == [0; 32] {
            return Err(JournalError::BindingMismatch);
        }
        window
            .check_initial_claim_release(window.disclosed_at(), order, delays)
            .map_err(JournalError::Timing)?;
        Ok(Self {
            operation,
            window: window.clone(),
            order,
            delays,
            claim_digest,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.operation);
        bytes.extend(self.window.capsule_binding());
        bytes.extend(self.window.disclosed_at().0.to_le_bytes());
        bytes.extend(self.window.earliest_adversarial().0.to_le_bytes());
        bytes.extend(self.window.latest_honest().0.to_le_bytes());
        bytes.extend(self.window.candidates().to_le_bytes());
        bytes.push(match self.order {
            InitialClaimOrder::XmrFirst => 1,
            InitialClaimOrder::DomFirst => 2,
        });
        bytes.extend(self.delays.xmr_resolution_secs.to_le_bytes());
        bytes.extend(self.delays.observation_secs.to_le_bytes());
        bytes.extend(self.delays.dom_resolution_secs.to_le_bytes());
        bytes.extend(self.claim_digest);
        bytes
    }
}

pub struct InitialClaimJournal {
    file: File,
    policy: ReleasePolicy,
    prepared_at: Timestamp,
    header_digest: [u8; 32],
    state: ReleaseState,
    poisoned: bool,
}

fn locked_file(path: &Path, create: bool) -> Result<File, JournalError> {
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(create)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => JournalError::Locked,
        std::fs::TryLockError::Error(error) => JournalError::Io(error),
    })?;
    if !file.metadata()?.is_file() {
        return Err(JournalError::InvalidRecord);
    }
    Ok(file)
}

impl InitialClaimJournal {
    /// Once-only creation. Never call this as fallback for failed `open`.
    pub fn create(
        path: &Path,
        policy: ReleasePolicy,
        prepared_at: Timestamp,
    ) -> Result<Self, JournalError> {
        policy
            .window
            .check_initial_claim_release(prepared_at, policy.order, policy.delays)
            .map_err(JournalError::Timing)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(JournalError::InvalidRecord)?;
        let directory = File::open(parent)?;
        let mut file = locked_file(path, true)?;
        let mut header = policy.encode();
        header.extend(prepared_at.0.to_le_bytes());
        let header_digest: [u8; 32] = Sha256::digest(&header).into();
        header.extend(header_digest);
        file.write_all(&header)?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Self {
            file,
            policy,
            prepared_at,
            header_digest,
            state: ReleaseState::Private,
            poisoned: false,
        })
    }

    /// Strict replay: a partial event is NOT discarded as an uncommitted tail.
    /// It denies all sends and must be reconciled outside this gate.
    pub fn open(path: &Path, expected: ReleasePolicy) -> Result<Self, JournalError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(JournalError::InvalidRecord)?;
        let directory = File::open(parent)?;
        let mut file = locked_file(path, false)?;
        let expected_bytes = expected.encode();
        let prefix_len = expected_bytes.len();
        let header_len = prefix_len + 8 + 32;
        let mut bytes = Vec::new();
        (&mut file)
            .take((header_len + EVENT_LEN + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() != header_len && bytes.len() != header_len + EVENT_LEN {
            return Err(JournalError::InvalidRecord);
        }
        let header_digest: [u8; 32] = Sha256::digest(&bytes[..header_len - 32]).into();
        if bytes[header_len - 32..header_len] != header_digest {
            return Err(JournalError::InvalidRecord);
        }
        if bytes[..prefix_len] != expected_bytes {
            return Err(JournalError::BindingMismatch);
        }
        let prepared_at = Timestamp(u64::from_le_bytes(
            bytes[prefix_len..prefix_len + 8].try_into().unwrap(),
        ));
        expected
            .window
            .check_initial_claim_release(prepared_at, expected.order, expected.delays)
            .map_err(JournalError::Timing)?;
        let state = if bytes.len() == header_len {
            ReleaseState::Private
        } else {
            let event = &bytes[header_len..];
            let mut hash = Sha256::new();
            hash.update(header_digest);
            hash.update(&event[..9]);
            let digest: [u8; 32] = hash.finalize().into();
            if event[9..] != digest {
                return Err(JournalError::InvalidRecord);
            }
            match event[0] {
                1 => {
                    let checked_at = Timestamp(u64::from_le_bytes(event[1..9].try_into().unwrap()));
                    if checked_at < prepared_at {
                        return Err(JournalError::InvalidRecord);
                    }
                    expected
                        .window
                        .check_initial_claim_release(checked_at, expected.order, expected.delays)
                        .map_err(JournalError::Timing)?;
                    ReleaseState::ExposurePossible
                }
                2 => ReleaseState::InitialReleaseClosed,
                _ => return Err(JournalError::InvalidRecord),
            }
        };
        // A previous creator may have died after writing a complete header
        // but before syncing its directory entry. Seeing those bytes after a
        // process restart does not prove their durability against power loss.
        // Complete both syncs before a reopened Private record can authorize IO.
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Self {
            file,
            policy: expected,
            prepared_at,
            header_digest,
            state,
            poisoned: false,
        })
    }

    pub fn state(&self) -> Result<ReleaseState, JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(self.state)
        }
    }

    fn persist(&mut self, state: ReleaseState, now: Timestamp) -> Result<(), JournalError> {
        // Sticky before the first write: an IO error is never permission to retry.
        self.poisoned = true;
        let mut event = vec![match state {
            ReleaseState::ExposurePossible => 1,
            ReleaseState::InitialReleaseClosed => 2,
            ReleaseState::Private => return Err(JournalError::InvalidRecord),
        }];
        event.extend(now.0.to_le_bytes());
        let mut hash = Sha256::new();
        hash.update(self.header_digest);
        hash.update(&event);
        event.extend(hash.finalize());
        self.file.write_all(&event)?;
        self.file.sync_all()?;
        self.state = state;
        self.poisoned = false;
        Ok(())
    }

    /// Record POSSIBLE exposure before calling a network closure. Returns the
    /// closure's result verbatim; even a rejected RPC cannot restore Private.
    /// Rechecks time AFTER fsync so storage latency consumes the same deadline.
    /// A caller can still be descheduled between the last check and network IO;
    /// bounding that interval remains an explicit protocol assumption.
    pub async fn release_once<T, F: Future<Output = T>>(
        &mut self,
        payload: &[u8],
        mut clock: impl FnMut() -> Timestamp,
        send: impl FnOnce() -> F,
    ) -> Result<T, JournalError> {
        match self.state()? {
            ReleaseState::ExposurePossible => return Err(JournalError::NeedsReconciliation),
            ReleaseState::InitialReleaseClosed => return Err(JournalError::InitialReleaseClosed),
            ReleaseState::Private => (),
        }
        if claim_digest(payload) != self.policy.claim_digest {
            return Err(JournalError::PayloadMismatch);
        }
        let now = clock();
        let before = if now < self.prepared_at {
            Err(TimingError::InvalidAssumption)
        } else {
            self.policy.window.check_initial_claim_release(
                now,
                self.policy.order,
                self.policy.delays,
            )
        };
        if let Err(error) = before {
            self.persist(ReleaseState::InitialReleaseClosed, now)?;
            return Err(JournalError::Timing(error));
        }
        self.persist(ReleaseState::ExposurePossible, now)?;
        let after = clock();
        if after < now {
            return Err(JournalError::Timing(TimingError::InvalidAssumption));
        }
        self.policy
            .window
            .check_initial_claim_release(after, self.policy.order, self.policy.delays)
            .map_err(JournalError::Timing)?;
        Ok(send().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        time_bounds::AssumedDirectRecoveryCosts,
        xmr_recovery::{XmrDirectRecoveryLink, XmrRecoveryRoster},
    };
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
    use frost::Participant;

    #[tokio::test]
    async fn failed_write_poisoning_prevents_network_and_same_handle_retry() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "release-io-error-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("initial.wal");
        let roster =
            XmrRecoveryRoster::new([3; 32], [Scalar::from(7u64) * G, Scalar::from(11u64) * G])
                .unwrap();
        let role = Participant::new(2).unwrap();
        let link = XmrDirectRecoveryLink::new(
            &roster,
            role,
            roster.recovery_domain(role).unwrap(),
            roster.share_key(role).unwrap(),
            [9; 32],
        )
        .unwrap();
        let window = AssumedXmrRecoveryWindow::from_direct_costs(
            &link,
            Timestamp(1000),
            30,
            Timestamp(1035),
            AssumedDirectRecoveryCosts {
                opening_and_check_secs: 60,
                overhead_secs: 5,
            },
        )
        .unwrap();
        let policy = ReleasePolicy::new(
            [5; 32],
            &window,
            InitialClaimOrder::XmrFirst,
            AssumedClaimDelays {
                xmr_resolution_secs: 1,
                observation_secs: 1,
                dom_resolution_secs: 1,
            },
            claim_digest(b"claim"),
        )
        .unwrap();
        let mut journal = InitialClaimJournal::create(&path, policy, Timestamp(1005)).unwrap();
        let original = std::fs::read(&path).unwrap();
        // Fault injection at the descriptor boundary; does not change the
        // public API or weaken the normal exclusive-lock path.
        journal.file = File::open(&path).unwrap();
        journal.file.try_lock().unwrap();
        assert!(matches!(
            journal
                .release_once(
                    b"claim",
                    || Timestamp(1005),
                    || async { panic!("write failed") }
                )
                .await,
            Err(JournalError::Io(_))
        ));
        assert!(matches!(journal.state(), Err(JournalError::Poisoned)));
        assert!(matches!(
            journal
                .release_once(
                    b"claim",
                    || Timestamp(1005),
                    || async { panic!("poisoned") }
                )
                .await,
            Err(JournalError::Poisoned)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }
}
