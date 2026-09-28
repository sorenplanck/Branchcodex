//! Daemon-facing DXF1 authority.
//!
//! The authority records the DOM exposure and the irreversible XMR decision
//! before it invokes either chain port. A failed or cancelled RPC therefore
//! leaves a recoverable obligation in the journal instead of reopening the
//! conflicting path. The authority obtains absolute observations from the
//! system clock itself; the journal-bound start and every later observation
//! survive restart, and a clock rollback fails closed.

use std::{
    convert::Infallible,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::{
    journal::{FastHandoffJournal, FastHandoffJournalError},
    state::{FastHandoff, FastHandoffBinding, FastHandoffError, FastHandoffPhase},
};

fn observed_at() -> Result<u64, FastHandoffJournalError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| FastHandoffJournalError::Denied(FastHandoffError::ActiveDeadlineExceeded))
}

fn xmr_submission_deadline(
    binding: FastHandoffBinding,
    observation: u64,
    now: Instant,
) -> Result<Instant, FastHandoffJournalError> {
    let elapsed = observation
        .checked_sub(binding.active_window_started_at())
        .ok_or(FastHandoffJournalError::Denied(
            FastHandoffError::ActiveDeadlineExceeded,
        ))?;
    let remaining = binding
        .policy()
        .active_deadline_seconds()
        .checked_sub(elapsed)
        // Epoch observations are truncated to whole seconds. Reserve the
        // final complete second for validating and fsyncing daemon admission.
        .and_then(|remaining| remaining.checked_sub(1))
        .filter(|remaining| *remaining != 0)
        .ok_or(FastHandoffJournalError::Denied(
            FastHandoffError::ActiveDeadlineExceeded,
        ))?;
    now.checked_add(Duration::from_secs(remaining))
        .ok_or(FastHandoffJournalError::Denied(
            FastHandoffError::ActiveDeadlineExceeded,
        ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomClaimAdmission {
    pub transaction_id: [u8; 32],
    pub daemon_next_height: u64,
}

pub trait DomClaimPort {
    type Error;

    /// Submit the port-owned durable Claim bound by `expected_transaction_id`.
    fn submit_bound_claim(
        &mut self,
        expected_transaction_id: [u8; 32],
    ) -> Result<DomClaimAdmission, Self::Error>;
}

pub struct DomClaimFn<Function>(pub Function);

impl<Function, Error> DomClaimPort for DomClaimFn<Function>
where
    Function: FnMut([u8; 32]) -> Result<DomClaimAdmission, Error>,
{
    type Error = Error;

    fn submit_bound_claim(
        &mut self,
        expected_transaction_id: [u8; 32],
    ) -> Result<DomClaimAdmission, Self::Error> {
        (self.0)(expected_transaction_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmrPreparedIdentity {
    pub transaction_id: [u8; 32],
    pub transaction_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmrPreparedPayment {
    pub transaction_id: [u8; 32],
    pub transaction: Vec<u8>,
}

pub trait XmrPaymentPort {
    type Error;

    /// Prepare the committed payment, or restore the exact bytes after restart.
    fn prepare_or_restore_exact_payment(
        &mut self,
        expected_payment_intent: [u8; 32],
        expected: Option<XmrPreparedIdentity>,
    ) -> Result<XmrPreparedPayment, Self::Error>;
}

pub struct XmrPaymentFn<Function>(pub Function);

impl<Function, Error> XmrPaymentPort for XmrPaymentFn<Function>
where
    Function: FnMut([u8; 32], Option<XmrPreparedIdentity>) -> Result<XmrPreparedPayment, Error>,
{
    type Error = Error;

    fn prepare_or_restore_exact_payment(
        &mut self,
        expected_payment_intent: [u8; 32],
        expected: Option<XmrPreparedIdentity>,
    ) -> Result<XmrPreparedPayment, Self::Error> {
        (self.0)(expected_payment_intent, expected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmrDaemonAdmission {
    pub transaction_id: [u8; 32],
}

pub trait XmrSubmissionPort {
    type Error;

    /// Submit the exact signed bytes already persisted by the authority.
    fn submit_exact_payment(
        &mut self,
        expected_transaction_id: [u8; 32],
        transaction: &[u8],
        deadline: Instant,
    ) -> Result<XmrDaemonAdmission, Self::Error>;
}

pub struct XmrSubmissionFn<Function>(pub Function);

impl<Function, Error> XmrSubmissionPort for XmrSubmissionFn<Function>
where
    Function: FnMut([u8; 32], &[u8], Instant) -> Result<XmrDaemonAdmission, Error>,
{
    type Error = Error;

    fn submit_exact_payment(
        &mut self,
        expected_transaction_id: [u8; 32],
        transaction: &[u8],
        deadline: Instant,
    ) -> Result<XmrDaemonAdmission, Self::Error> {
        (self.0)(expected_transaction_id, transaction, deadline)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedXmrSubmission {
    identity: XmrPreparedIdentity,
    transaction: Vec<u8>,
}

impl PreparedXmrSubmission {
    pub const fn identity(&self) -> XmrPreparedIdentity {
        self.identity
    }

    pub fn transaction(&self) -> &[u8] {
        &self.transaction
    }
}

#[derive(Debug)]
pub enum FastHandoffAuthorityError<PortError = Infallible> {
    Journal(FastHandoffJournalError),
    Port(PortError),
    WrongPhase,
    MismatchedDaemonTransaction,
}

impl<PortError> From<FastHandoffJournalError> for FastHandoffAuthorityError<PortError> {
    fn from(error: FastHandoffJournalError) -> Self {
        Self::Journal(error)
    }
}

pub struct FastHandoffAuthority {
    journal: FastHandoffJournal,
    recovered_xmr_commitment: bool,
}

impl FastHandoffAuthority {
    pub fn create_ready(
        path: &Path,
        binding: FastHandoffBinding,
        dom_funding_confirmations: u64,
        xmr_reserve_mature: bool,
    ) -> Result<Self, FastHandoffJournalError> {
        let now = observed_at()?;
        let active_elapsed = now.checked_sub(binding.active_window_started_at()).ok_or(
            FastHandoffJournalError::Denied(FastHandoffError::ActiveDeadlineExceeded),
        )?;
        if active_elapsed > binding.policy().active_deadline_seconds() {
            return Err(FastHandoffJournalError::Denied(
                FastHandoffError::ActiveDeadlineExceeded,
            ));
        }
        let mut preflight = FastHandoff::new(binding);
        preflight
            .record_ready(
                binding.dom_funding(),
                dom_funding_confirmations,
                binding.xmr_reserve(),
                xmr_reserve_mature,
            )
            .map_err(FastHandoffJournalError::Denied)?;
        let mut journal = FastHandoffJournal::create(path, binding)?;
        journal.record_ready(
            binding.dom_funding(),
            dom_funding_confirmations,
            binding.xmr_reserve(),
            xmr_reserve_mature,
        )?;
        Ok(Self {
            journal,
            recovered_xmr_commitment: false,
        })
    }

    pub fn open(path: &Path, binding: FastHandoffBinding) -> Result<Self, FastHandoffJournalError> {
        let journal = FastHandoffJournal::open(path, binding)?;
        let recovered_xmr_commitment = matches!(
            journal.state()?.phase(),
            FastHandoffPhase::XmrReleaseCommitted | FastHandoffPhase::XmrTransactionPrepared
        );
        Ok(Self {
            journal,
            recovered_xmr_commitment,
        })
    }

    pub fn binding(&self) -> FastHandoffBinding {
        self.journal.binding()
    }

    pub fn journal(&self) -> &FastHandoffJournal {
        &self.journal
    }

    /// Persist exposure before calling the DOM daemon. Reopening after an RPC
    /// failure resumes from `DomClaimExposed` and resubmits the same bytes.
    pub fn admit_dom_claim<Port: DomClaimPort>(
        &mut self,
        target_height: u64,
        port: &mut Port,
    ) -> Result<DomClaimAdmission, FastHandoffAuthorityError<Port::Error>> {
        let binding = self.journal.binding();
        match self.journal.state()?.phase() {
            FastHandoffPhase::Ready => self.journal.record_dom_claim_exposure(
                binding.dom_claim(),
                target_height,
                observed_at()?,
            )?,
            FastHandoffPhase::DomClaimExposed => {}
            _ => return Err(FastHandoffAuthorityError::WrongPhase),
        }
        let admission = port
            .submit_bound_claim(binding.dom_claim())
            .map_err(FastHandoffAuthorityError::Port)?;
        if admission.transaction_id != binding.dom_claim() {
            return Err(FastHandoffAuthorityError::MismatchedDaemonTransaction);
        }
        self.journal.record_dom_daemon_admission(
            admission.transaction_id,
            admission.daemon_next_height,
            observed_at()?,
        )?;
        Ok(admission)
    }

    pub fn commit_xmr_release(&mut self) -> Result<(), FastHandoffJournalError> {
        self.journal.record_xmr_release_commitment(
            self.journal.binding().xmr_payment_intent(),
            observed_at()?,
        )
    }

    /// Prepare the exact XMR transaction only after the committed journal has
    /// been reopened. Its byte digest is synchronized before the caller can
    /// send the bytes to `monerod`.
    pub fn prepare_committed_xmr<Port: XmrPaymentPort>(
        &mut self,
        port: &mut Port,
    ) -> Result<PreparedXmrSubmission, FastHandoffAuthorityError<Port::Error>> {
        if !self.recovered_xmr_commitment {
            return Err(FastHandoffAuthorityError::WrongPhase);
        }
        let state = self.journal.state()?;
        let expected = match state.phase() {
            FastHandoffPhase::XmrReleaseCommitted => None,
            FastHandoffPhase::XmrTransactionPrepared => Some(XmrPreparedIdentity {
                transaction_id: state
                    .xmr_transaction()
                    .ok_or(FastHandoffAuthorityError::WrongPhase)?,
                transaction_digest: state
                    .xmr_transaction_digest()
                    .ok_or(FastHandoffAuthorityError::WrongPhase)?,
            }),
            _ => return Err(FastHandoffAuthorityError::WrongPhase),
        };
        let intent = self.journal.binding().xmr_payment_intent();
        let prepared = port
            .prepare_or_restore_exact_payment(intent, expected)
            .map_err(FastHandoffAuthorityError::Port)?;
        if prepared.transaction_id == [0; 32] || prepared.transaction.is_empty() {
            return Err(FastHandoffAuthorityError::MismatchedDaemonTransaction);
        }
        let identity = XmrPreparedIdentity {
            transaction_id: prepared.transaction_id,
            transaction_digest: Sha256::digest(&prepared.transaction).into(),
        };
        if let Some(expected) = expected {
            if identity != expected {
                return Err(FastHandoffAuthorityError::MismatchedDaemonTransaction);
            }
        } else {
            self.journal.record_xmr_transaction_prepared(
                intent,
                identity.transaction_id,
                identity.transaction_digest,
                observed_at()?,
            )?;
        }
        Ok(PreparedXmrSubmission {
            identity,
            transaction: prepared.transaction,
        })
    }

    /// Submit the exact persisted XMR bytes through the daemon port and record
    /// only its acknowledgement. Callers cannot complete the authority by
    /// supplying a transaction id directly.
    pub fn submit_prepared_xmr<Port: XmrSubmissionPort>(
        &mut self,
        submission: &PreparedXmrSubmission,
        port: &mut Port,
    ) -> Result<XmrDaemonAdmission, FastHandoffAuthorityError<Port::Error>> {
        let state = self.journal.state()?;
        if state.phase() != FastHandoffPhase::XmrTransactionPrepared
            || state.xmr_transaction() != Some(submission.identity.transaction_id)
            || state.xmr_transaction_digest() != Some(submission.identity.transaction_digest)
        {
            return Err(FastHandoffAuthorityError::WrongPhase);
        }
        let deadline =
            xmr_submission_deadline(self.journal.binding(), observed_at()?, Instant::now())?;
        let admission = port
            .submit_exact_payment(
                submission.identity.transaction_id,
                submission.transaction(),
                deadline,
            )
            .map_err(FastHandoffAuthorityError::Port)?;
        if Instant::now() > deadline {
            return Err(FastHandoffAuthorityError::Journal(
                FastHandoffJournalError::Denied(FastHandoffError::ActiveDeadlineExceeded),
            ));
        }
        if admission.transaction_id != submission.identity.transaction_id {
            return Err(FastHandoffAuthorityError::MismatchedDaemonTransaction);
        }
        self.journal.record_xmr_daemon_admission(
            submission.identity.transaction_id,
            submission.identity.transaction_digest,
            observed_at()?,
        )?;
        Ok(admission)
    }

    pub fn record_dom_claim_inclusion(
        &mut self,
        height: u64,
        canonical_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        self.journal.record_dom_claim_inclusion(
            self.journal.binding().dom_claim(),
            height,
            canonical_block,
        )
    }

    pub fn record_dom_claim_reorg(
        &mut self,
        orphaned_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        self.journal
            .record_dom_claim_reorg(self.journal.binding().dom_claim(), orphaned_block)
    }

    /// Re-submit the same bound Claim when canonical monitoring marked it as
    /// removed. The durable reorg event already carries the obligation, so an
    /// RPC failure leaves `rebroadcast_required` set for the next restart.
    pub fn rebroadcast_dom_claim<Port: DomClaimPort>(
        &mut self,
        port: &mut Port,
    ) -> Result<DomClaimAdmission, FastHandoffAuthorityError<Port::Error>> {
        if !self.journal.state()?.rebroadcast_required() {
            return Err(FastHandoffAuthorityError::WrongPhase);
        }
        let expected = self.journal.binding().dom_claim();
        let admission = port
            .submit_bound_claim(expected)
            .map_err(FastHandoffAuthorityError::Port)?;
        if admission.transaction_id != expected {
            return Err(FastHandoffAuthorityError::MismatchedDaemonTransaction);
        }
        Ok(admission)
    }

    pub fn record_dom_claim_finality(
        &mut self,
        inclusion_height: u64,
        inclusion_block: [u8; 32],
        tip_height: u64,
        tip_block: [u8; 32],
    ) -> Result<(), FastHandoffJournalError> {
        self.journal.record_dom_claim_finality(
            self.journal.binding().dom_claim(),
            inclusion_height,
            inclusion_block,
            tip_height,
            tip_block,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{FastHandoffError, FastHandoffPolicy};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dxf1-authority-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
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
        let active_window_started_at = observed_at().unwrap();
        FastHandoffBinding::new(
            id(1),
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            active_window_started_at,
            FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
        )
        .unwrap()
    }

    #[derive(Default)]
    struct DomPort {
        calls: usize,
        fail: bool,
        wrong_id: bool,
    }

    impl DomClaimPort for DomPort {
        type Error = &'static str;

        fn submit_bound_claim(
            &mut self,
            expected_transaction_id: [u8; 32],
        ) -> Result<DomClaimAdmission, Self::Error> {
            self.calls += 1;
            if self.fail {
                return Err("DOM unavailable");
            }
            Ok(DomClaimAdmission {
                transaction_id: if self.wrong_id {
                    id(99)
                } else {
                    expected_transaction_id
                },
                daemon_next_height: 95,
            })
        }
    }

    #[derive(Default)]
    struct XmrSubmitPort {
        calls: usize,
        wrong_id: bool,
        lose_response_after_acceptance: bool,
        submitted: Vec<Vec<u8>>,
    }

    impl XmrSubmissionPort for XmrSubmitPort {
        type Error = &'static str;

        fn submit_exact_payment(
            &mut self,
            expected_transaction_id: [u8; 32],
            transaction: &[u8],
            deadline: Instant,
        ) -> Result<XmrDaemonAdmission, Self::Error> {
            self.calls += 1;
            assert!(deadline > Instant::now());
            assert_eq!(expected_transaction_id, id(7));
            assert_eq!(transaction, b"exact signed XMR transaction");
            self.submitted.push(transaction.to_vec());
            if self.lose_response_after_acceptance {
                return Err("XMR response lost after acceptance");
            }
            Ok(XmrDaemonAdmission {
                transaction_id: if self.wrong_id { id(99) } else { id(7) },
            })
        }
    }

    #[derive(Default)]
    struct XmrPort {
        calls: usize,
    }

    impl XmrPaymentPort for XmrPort {
        type Error = &'static str;

        fn prepare_or_restore_exact_payment(
            &mut self,
            expected_payment_intent: [u8; 32],
            expected: Option<XmrPreparedIdentity>,
        ) -> Result<XmrPreparedPayment, Self::Error> {
            self.calls += 1;
            assert_eq!(expected_payment_intent, id(6));
            let transaction = b"exact signed XMR transaction".to_vec();
            let identity = XmrPreparedIdentity {
                transaction_id: id(7),
                transaction_digest: Sha256::digest(&transaction).into(),
            };
            if let Some(expected) = expected {
                assert_eq!(expected, identity);
            }
            Ok(XmrPreparedPayment {
                transaction_id: identity.transaction_id,
                transaction,
            })
        }
    }

    #[test]
    fn daemon_order_survives_dom_failure_and_xmr_restart() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        let binding = binding();
        let mut authority = FastHandoffAuthority::create_ready(&path, binding, 2, true).unwrap();
        let mut dom = DomPort {
            fail: true,
            ..DomPort::default()
        };
        assert!(matches!(
            authority.admit_dom_claim(95, &mut dom),
            Err(FastHandoffAuthorityError::Port("DOM unavailable"))
        ));
        assert_eq!(
            authority.journal().state().unwrap().phase(),
            FastHandoffPhase::DomClaimExposed
        );
        drop(authority);

        dom.fail = false;
        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        authority.admit_dom_claim(95, &mut dom).unwrap();
        authority.commit_xmr_release().unwrap();
        let mut premature_xmr = XmrPort::default();
        assert!(matches!(
            authority.prepare_committed_xmr(&mut premature_xmr),
            Err(FastHandoffAuthorityError::WrongPhase)
        ));
        assert_eq!(premature_xmr.calls, 0);
        drop(authority);

        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        assert!(matches!(
            authority.journal().authorize_refund(u64::MAX),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::RefundPermanentlyForbidden
            ))
        ));
        let mut xmr = XmrPort::default();
        let submission = authority.prepare_committed_xmr(&mut xmr).unwrap();
        assert_eq!(submission.transaction(), b"exact signed XMR transaction");
        drop(authority);

        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        let restored = authority.prepare_committed_xmr(&mut xmr).unwrap();
        assert_eq!(restored.identity(), submission.identity());
        assert_eq!(restored.transaction(), submission.transaction());
        let mut submit = XmrSubmitPort::default();
        authority
            .submit_prepared_xmr(&restored, &mut submit)
            .unwrap();
        assert!(authority.journal().completed().unwrap());
        assert_eq!(dom.calls, 2);
        assert_eq!(xmr.calls, 2);
        assert_eq!(submit.calls, 1);
    }

    #[test]
    fn mismatched_dom_ack_never_unlocks_xmr() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        let binding = binding();
        let mut authority = FastHandoffAuthority::create_ready(&path, binding, 2, true).unwrap();
        let mut dom = DomPort {
            wrong_id: true,
            ..DomPort::default()
        };
        assert!(matches!(
            authority.admit_dom_claim(95, &mut dom),
            Err(FastHandoffAuthorityError::MismatchedDaemonTransaction)
        ));
        assert!(authority.commit_xmr_release().is_err());
    }

    #[test]
    fn mismatched_xmr_daemon_ack_never_completes() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        let binding = binding();
        let mut authority = FastHandoffAuthority::create_ready(&path, binding, 2, true).unwrap();
        let mut dom = DomPort::default();
        authority.admit_dom_claim(95, &mut dom).unwrap();
        authority.commit_xmr_release().unwrap();
        drop(authority);
        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        let submission = authority
            .prepare_committed_xmr(&mut XmrPort::default())
            .unwrap();
        let mut submit = XmrSubmitPort {
            wrong_id: true,
            ..XmrSubmitPort::default()
        };
        assert!(matches!(
            authority.submit_prepared_xmr(&submission, &mut submit),
            Err(FastHandoffAuthorityError::MismatchedDaemonTransaction)
        ));
        assert!(!authority.journal().completed().unwrap());
    }

    #[test]
    fn ambiguous_xmr_acceptance_restarts_with_the_same_bytes() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        let binding = binding();
        let mut authority = FastHandoffAuthority::create_ready(&path, binding, 2, true).unwrap();
        authority
            .admit_dom_claim(95, &mut DomPort::default())
            .unwrap();
        authority.commit_xmr_release().unwrap();
        drop(authority);

        let mut payment = XmrPort::default();
        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        let prepared = authority.prepare_committed_xmr(&mut payment).unwrap();
        let mut lost = XmrSubmitPort {
            lose_response_after_acceptance: true,
            ..XmrSubmitPort::default()
        };
        assert!(matches!(
            authority.submit_prepared_xmr(&prepared, &mut lost),
            Err(FastHandoffAuthorityError::Port(
                "XMR response lost after acceptance"
            ))
        ));
        assert_eq!(lost.submitted, vec![prepared.transaction().to_vec()]);
        assert_eq!(
            authority.journal().state().unwrap().phase(),
            FastHandoffPhase::XmrTransactionPrepared
        );
        assert!(matches!(
            authority.journal().authorize_refund(u64::MAX),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::RefundPermanentlyForbidden
            ))
        ));
        drop(authority);

        let mut authority = FastHandoffAuthority::open(&path, binding).unwrap();
        let restored = authority.prepare_committed_xmr(&mut payment).unwrap();
        assert_eq!(restored, prepared);
        let mut reconciled = XmrSubmitPort::default();
        authority
            .submit_prepared_xmr(&restored, &mut reconciled)
            .unwrap();
        assert_eq!(reconciled.submitted, vec![prepared.transaction().to_vec()]);
        assert!(authority.journal().completed().unwrap());
        assert_eq!(payment.calls, 2);
    }

    #[test]
    fn unusable_reserve_never_creates_an_authority_journal() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        assert!(matches!(
            FastHandoffAuthority::create_ready(&path, binding(), 1, true),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::WrongOrder
            ))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn expired_active_window_never_creates_an_authority_journal() {
        let scratch = Scratch::new();
        let path = scratch.0.join("handoff.wal");
        let current = observed_at().unwrap();
        let expired = FastHandoffBinding::new(
            id(1),
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            current - 181,
            FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            FastHandoffAuthority::create_ready(&path, expired, 2, true),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::ActiveDeadlineExceeded
            ))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn xmr_rpc_deadline_expires_before_irreversible_submission() {
        let binding = binding();
        let now = Instant::now();
        assert!(
            xmr_submission_deadline(binding, binding.active_window_started_at() + 178, now).is_ok()
        );
        assert!(matches!(
            xmr_submission_deadline(binding, binding.active_window_started_at() + 179, now),
            Err(FastHandoffJournalError::Denied(
                FastHandoffError::ActiveDeadlineExceeded
            ))
        ));
    }
}
