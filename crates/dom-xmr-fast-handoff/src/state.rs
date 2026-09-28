//! DXF1 prepared-liquidity fast handoff for a direct DOM/XMR swap.
//!
//! Both reserves are funded, confirmed and recoverable before the active clock
//! starts. The exact DOM claim is exposed and accepted by the DOM daemon first.
//! Only then may the exact XMR payment be durably committed and submitted.
//! DXF1 does not call mempool admission finality: safety is conditional on the
//! immutable DOM claim remaining valid for the configured bounded-inclusion
//! margin. Once XMR release is committed, the coordinator can only rebroadcast
//! that claim; it can never fall back to the conflicting DOM refund.

use std::fmt;

/// Domain tag for the new prepared-liquidity protocol.
pub const DXF1_PROTOCOL: &[u8] = b"DXF1/DOM-XMR-fast-handoff/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastHandoffError {
    InvalidBinding,
    InvalidPolicy,
    WrongOrder,
    DifferentTransaction,
    ActiveDeadlineExceeded,
    ClaimMarginExhausted,
    RefundPermanentlyForbidden,
}

impl fmt::Display for FastHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Immutable timing and preparation requirements for one DXF1 operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastHandoffPolicy {
    active_deadline_seconds: u64,
    minimum_dom_funding_confirmations: u64,
    maximum_dom_claim_inclusion_blocks: u64,
    minimum_dom_claim_confirmations: u64,
    claim_until: u64,
}

impl FastHandoffPolicy {
    pub fn new(
        active_deadline_seconds: u64,
        minimum_dom_funding_confirmations: u64,
        maximum_dom_claim_inclusion_blocks: u64,
        minimum_dom_claim_confirmations: u64,
        claim_until: u64,
    ) -> Result<Self, FastHandoffError> {
        if active_deadline_seconds == 0
            || active_deadline_seconds > 180
            || minimum_dom_funding_confirmations == 0
            || maximum_dom_claim_inclusion_blocks == 0
            || minimum_dom_claim_confirmations == 0
            || claim_until == 0
        {
            return Err(FastHandoffError::InvalidPolicy);
        }
        Ok(Self {
            active_deadline_seconds,
            minimum_dom_funding_confirmations,
            maximum_dom_claim_inclusion_blocks,
            minimum_dom_claim_confirmations,
            claim_until,
        })
    }

    pub const fn active_deadline_seconds(self) -> u64 {
        self.active_deadline_seconds
    }

    pub const fn minimum_dom_funding_confirmations(self) -> u64 {
        self.minimum_dom_funding_confirmations
    }

    pub const fn maximum_dom_claim_inclusion_blocks(self) -> u64 {
        self.maximum_dom_claim_inclusion_blocks
    }

    pub const fn minimum_dom_claim_confirmations(self) -> u64 {
        self.minimum_dom_claim_confirmations
    }

    pub const fn claim_until(self) -> u64 {
        self.claim_until
    }

    pub const fn first_refund_height(self) -> Option<u64> {
        self.claim_until.checked_add(1)
    }

    /// Last target height at which XMR may be released under the bound.
    pub const fn last_safe_claim_target_height(self) -> Option<u64> {
        let inclusion_span = self.maximum_dom_claim_inclusion_blocks - 1;
        let confirmation_span = self.minimum_dom_claim_confirmations - 1;
        match inclusion_span.checked_add(confirmation_span) {
            Some(span) => self.claim_until.checked_sub(span),
            None => None,
        }
    }

    /// Prove the configured inclusion bound ends before Refund can be valid.
    pub fn check_claim_target(self, target_height: u64) -> Result<u64, FastHandoffError> {
        if target_height == 0 {
            return Err(FastHandoffError::ClaimMarginExhausted);
        }
        let latest_assumed_inclusion = target_height
            .checked_add(self.maximum_dom_claim_inclusion_blocks - 1)
            .ok_or(FastHandoffError::ClaimMarginExhausted)?;
        let required_finality_height = latest_assumed_inclusion
            .checked_add(self.minimum_dom_claim_confirmations - 1)
            .ok_or(FastHandoffError::ClaimMarginExhausted)?;
        if required_finality_height > self.claim_until {
            return Err(FastHandoffError::ClaimMarginExhausted);
        }
        debug_assert!(Some(required_finality_height) < self.first_refund_height());
        Ok(latest_assumed_inclusion)
    }

    pub fn required_finality_height(self, target_height: u64) -> Result<u64, FastHandoffError> {
        self.check_claim_target(target_height)?
            .checked_add(self.minimum_dom_claim_confirmations - 1)
            .ok_or(FastHandoffError::ClaimMarginExhausted)
    }
}

/// Exact public artifacts fixed before either active leg is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastHandoffBinding {
    operation: [u8; 32],
    dom_chain: [u8; 32],
    dom_funding: [u8; 32],
    xmr_reserve: [u8; 32],
    dom_claim: [u8; 32],
    xmr_payment_intent: [u8; 32],
    active_window_started_at: u64,
    policy: FastHandoffPolicy,
}

impl FastHandoffBinding {
    // All six chain artifacts, the durable start time, and policy form one
    // indivisible binding; splitting construction would permit partial state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: [u8; 32],
        dom_chain: [u8; 32],
        dom_funding: [u8; 32],
        xmr_reserve: [u8; 32],
        dom_claim: [u8; 32],
        xmr_payment_intent: [u8; 32],
        active_window_started_at: u64,
        policy: FastHandoffPolicy,
    ) -> Result<Self, FastHandoffError> {
        let identifiers = [
            operation,
            dom_chain,
            dom_funding,
            xmr_reserve,
            dom_claim,
            xmr_payment_intent,
        ];
        if identifiers.contains(&[0; 32])
            || active_window_started_at == 0
            || dom_funding == xmr_reserve
            || dom_claim == xmr_payment_intent
        {
            return Err(FastHandoffError::InvalidBinding);
        }
        Ok(Self {
            operation,
            dom_chain,
            dom_funding,
            xmr_reserve,
            dom_claim,
            xmr_payment_intent,
            active_window_started_at,
            policy,
        })
    }

    pub const fn operation(self) -> [u8; 32] {
        self.operation
    }

    pub const fn dom_chain(self) -> [u8; 32] {
        self.dom_chain
    }

    pub const fn dom_funding(self) -> [u8; 32] {
        self.dom_funding
    }

    pub const fn xmr_reserve(self) -> [u8; 32] {
        self.xmr_reserve
    }

    pub const fn dom_claim(self) -> [u8; 32] {
        self.dom_claim
    }

    pub const fn xmr_payment_intent(self) -> [u8; 32] {
        self.xmr_payment_intent
    }

    pub const fn active_window_started_at(self) -> u64 {
        self.active_window_started_at
    }

    pub const fn policy(self) -> FastHandoffPolicy {
        self.policy
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastHandoffPhase {
    Preparing,
    Ready,
    DomClaimExposed,
    DomClaimAdmitted,
    XmrReleaseCommitted,
    XmrTransactionPrepared,
    Complete,
}

/// Secret-free state machine. Durable storage wraps these transitions later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastHandoff {
    binding: FastHandoffBinding,
    phase: FastHandoffPhase,
    claim_target_height: Option<u64>,
    latest_assumed_claim_height: Option<u64>,
    required_dom_finality_height: Option<u64>,
    dom_claim_canonical_height: Option<u64>,
    dom_claim_canonical_block: Option<[u8; 32]>,
    dom_claim_finality_tip: Option<[u8; 32]>,
    dom_claim_finalized: bool,
    xmr_transaction: Option<[u8; 32]>,
    xmr_transaction_digest: Option<[u8; 32]>,
    last_active_observation: Option<u64>,
    rebroadcast_required: bool,
}

impl FastHandoff {
    pub const fn new(binding: FastHandoffBinding) -> Self {
        Self {
            binding,
            phase: FastHandoffPhase::Preparing,
            claim_target_height: None,
            latest_assumed_claim_height: None,
            required_dom_finality_height: None,
            dom_claim_canonical_height: None,
            dom_claim_canonical_block: None,
            dom_claim_finality_tip: None,
            dom_claim_finalized: false,
            xmr_transaction: None,
            xmr_transaction_digest: None,
            last_active_observation: None,
            rebroadcast_required: false,
        }
    }

    pub const fn phase(self) -> FastHandoffPhase {
        self.phase
    }

    pub const fn latest_assumed_claim_height(self) -> Option<u64> {
        self.latest_assumed_claim_height
    }

    pub const fn rebroadcast_required(self) -> bool {
        self.rebroadcast_required
    }

    pub const fn required_dom_finality_height(self) -> Option<u64> {
        self.required_dom_finality_height
    }

    pub const fn dom_claim_finalized(self) -> bool {
        self.dom_claim_finalized
    }

    pub const fn dom_claim_canonical_block(self) -> Option<[u8; 32]> {
        self.dom_claim_canonical_block
    }

    pub const fn dom_claim_finality_tip(self) -> Option<[u8; 32]> {
        self.dom_claim_finality_tip
    }

    pub const fn xmr_transaction(self) -> Option<[u8; 32]> {
        self.xmr_transaction
    }

    pub const fn xmr_transaction_digest(self) -> Option<[u8; 32]> {
        self.xmr_transaction_digest
    }

    pub const fn last_active_observation(self) -> Option<u64> {
        self.last_active_observation
    }

    /// Enter the active interval only after both prepared reserves are usable.
    pub fn record_ready(
        &mut self,
        dom_funding: [u8; 32],
        dom_funding_confirmations: u64,
        xmr_reserve: [u8; 32],
        xmr_reserve_mature: bool,
    ) -> Result<(), FastHandoffError> {
        if self.phase != FastHandoffPhase::Preparing {
            return Err(FastHandoffError::WrongOrder);
        }
        if dom_funding != self.binding.dom_funding || xmr_reserve != self.binding.xmr_reserve {
            return Err(FastHandoffError::DifferentTransaction);
        }
        if dom_funding_confirmations < self.binding.policy.minimum_dom_funding_confirmations
            || !xmr_reserve_mature
        {
            return Err(FastHandoffError::WrongOrder);
        }
        self.phase = FastHandoffPhase::Ready;
        Ok(())
    }

    /// Record the exact DOM Claim before the first daemon send.
    pub fn record_dom_claim_exposure(
        &mut self,
        dom_claim: [u8; 32],
        target_height: u64,
        observed_at: u64,
    ) -> Result<(), FastHandoffError> {
        self.check_active_deadline(observed_at)?;
        if self.phase != FastHandoffPhase::Ready {
            return Err(FastHandoffError::WrongOrder);
        }
        if dom_claim != self.binding.dom_claim {
            return Err(FastHandoffError::DifferentTransaction);
        }
        let latest = self.binding.policy.check_claim_target(target_height)?;
        let finality = self
            .binding
            .policy
            .required_finality_height(target_height)?;
        self.claim_target_height = Some(target_height);
        self.latest_assumed_claim_height = Some(latest);
        self.required_dom_finality_height = Some(finality);
        self.rebroadcast_required = true;
        self.last_active_observation = Some(observed_at);
        self.phase = FastHandoffPhase::DomClaimExposed;
        Ok(())
    }

    /// Accept only an acknowledgement for the exact Claim already exposed.
    pub fn record_dom_daemon_admission(
        &mut self,
        dom_claim: [u8; 32],
        daemon_next_height: u64,
        observed_at: u64,
    ) -> Result<(), FastHandoffError> {
        self.check_active_deadline(observed_at)?;
        if self.phase != FastHandoffPhase::DomClaimExposed {
            return Err(FastHandoffError::WrongOrder);
        }
        if dom_claim != self.binding.dom_claim {
            return Err(FastHandoffError::DifferentTransaction);
        }
        let target = self
            .claim_target_height
            .ok_or(FastHandoffError::WrongOrder)?;
        if daemon_next_height < target {
            return Err(FastHandoffError::WrongOrder);
        }
        // Re-evaluate the bound at acknowledgement time. A stale RPC response
        // cannot consume the safety margin between exposure and admission.
        let latest = self.binding.policy.check_claim_target(daemon_next_height)?;
        let finality = self
            .binding
            .policy
            .required_finality_height(daemon_next_height)?;
        self.claim_target_height = Some(daemon_next_height);
        self.latest_assumed_claim_height = Some(latest);
        self.required_dom_finality_height = Some(finality);
        self.last_active_observation = Some(observed_at);
        self.phase = FastHandoffPhase::DomClaimAdmitted;
        Ok(())
    }

    /// Persist the irreversible XMR release decision before its RPC call.
    pub fn record_xmr_release_commitment(
        &mut self,
        xmr_payment_intent: [u8; 32],
        observed_at: u64,
    ) -> Result<(), FastHandoffError> {
        self.check_active_deadline(observed_at)?;
        if self.phase != FastHandoffPhase::DomClaimAdmitted {
            return Err(FastHandoffError::WrongOrder);
        }
        if xmr_payment_intent != self.binding.xmr_payment_intent {
            return Err(FastHandoffError::DifferentTransaction);
        }
        self.last_active_observation = Some(observed_at);
        self.phase = FastHandoffPhase::XmrReleaseCommitted;
        Ok(())
    }

    /// Bind the exact signed Monero bytes before their first daemon RPC.
    pub fn record_xmr_transaction_prepared(
        &mut self,
        xmr_payment_intent: [u8; 32],
        xmr_transaction: [u8; 32],
        xmr_transaction_digest: [u8; 32],
        observed_at: u64,
    ) -> Result<(), FastHandoffError> {
        self.check_active_deadline(observed_at)?;
        if self.phase != FastHandoffPhase::XmrReleaseCommitted {
            return Err(FastHandoffError::WrongOrder);
        }
        if xmr_payment_intent != self.binding.xmr_payment_intent
            || xmr_transaction == [0; 32]
            || xmr_transaction_digest == [0; 32]
        {
            return Err(FastHandoffError::DifferentTransaction);
        }
        self.xmr_transaction = Some(xmr_transaction);
        self.xmr_transaction_digest = Some(xmr_transaction_digest);
        self.last_active_observation = Some(observed_at);
        self.phase = FastHandoffPhase::XmrTransactionPrepared;
        Ok(())
    }

    /// Finish only after the Monero daemon accepted the exact prepared spend.
    pub fn record_xmr_daemon_admission(
        &mut self,
        xmr_transaction: [u8; 32],
        xmr_transaction_digest: [u8; 32],
        observed_at: u64,
    ) -> Result<(), FastHandoffError> {
        self.check_active_deadline(observed_at)?;
        if self.phase != FastHandoffPhase::XmrTransactionPrepared {
            return Err(FastHandoffError::WrongOrder);
        }
        if self.xmr_transaction != Some(xmr_transaction)
            || self.xmr_transaction_digest != Some(xmr_transaction_digest)
        {
            return Err(FastHandoffError::DifferentTransaction);
        }
        self.last_active_observation = Some(observed_at);
        self.phase = FastHandoffPhase::Complete;
        Ok(())
    }

    /// Record eventual canonical inclusion without changing active completion.
    pub fn record_dom_claim_inclusion(
        &mut self,
        dom_claim: [u8; 32],
        height: u64,
        canonical_block: [u8; 32],
    ) -> Result<(), FastHandoffError> {
        if !matches!(
            self.phase,
            FastHandoffPhase::DomClaimAdmitted
                | FastHandoffPhase::XmrReleaseCommitted
                | FastHandoffPhase::XmrTransactionPrepared
                | FastHandoffPhase::Complete
        ) {
            return Err(FastHandoffError::WrongOrder);
        }
        if dom_claim != self.binding.dom_claim || canonical_block == [0; 32] {
            return Err(FastHandoffError::DifferentTransaction);
        }
        if self.dom_claim_canonical_height.is_some() || self.dom_claim_canonical_block.is_some() {
            return Err(FastHandoffError::WrongOrder);
        }
        let latest = self
            .latest_assumed_claim_height
            .ok_or(FastHandoffError::WrongOrder)?;
        if height > latest {
            return Err(FastHandoffError::ClaimMarginExhausted);
        }
        self.dom_claim_canonical_height = Some(height);
        self.dom_claim_canonical_block = Some(canonical_block);
        self.dom_claim_finality_tip = None;
        self.dom_claim_finalized = false;
        self.rebroadcast_required = false;
        Ok(())
    }

    /// Record the required canonical depth during the recovery window.
    pub fn record_dom_claim_finality(
        &mut self,
        dom_claim: [u8; 32],
        inclusion_height: u64,
        inclusion_block: [u8; 32],
        tip_height: u64,
        tip_block: [u8; 32],
    ) -> Result<u64, FastHandoffError> {
        if dom_claim != self.binding.dom_claim || inclusion_block == [0; 32] || tip_block == [0; 32]
        {
            return Err(FastHandoffError::DifferentTransaction);
        }
        if self.dom_claim_canonical_height != Some(inclusion_height)
            || self.dom_claim_canonical_block != Some(inclusion_block)
            || (tip_height == inclusion_height && tip_block != inclusion_block)
            || self.dom_claim_finalized
        {
            return Err(FastHandoffError::WrongOrder);
        }
        let depth = tip_height
            .checked_sub(inclusion_height)
            .and_then(|value| value.checked_add(1))
            .ok_or(FastHandoffError::WrongOrder)?;
        if depth < self.binding.policy.minimum_dom_claim_confirmations
            || tip_height > self.binding.policy.claim_until
        {
            return Err(FastHandoffError::ClaimMarginExhausted);
        }
        self.dom_claim_finality_tip = Some(tip_block);
        self.dom_claim_finalized = true;
        Ok(depth)
    }

    /// A reorg after XMR commitment restores the exact rebroadcast obligation.
    pub fn record_dom_claim_reorg(
        &mut self,
        dom_claim: [u8; 32],
        orphaned_block: [u8; 32],
    ) -> Result<(), FastHandoffError> {
        if dom_claim != self.binding.dom_claim || orphaned_block == [0; 32] {
            return Err(FastHandoffError::DifferentTransaction);
        }
        if self.dom_claim_canonical_height.is_none()
            || self.dom_claim_canonical_block != Some(orphaned_block)
        {
            return Err(FastHandoffError::WrongOrder);
        }
        self.dom_claim_canonical_height = None;
        self.dom_claim_canonical_block = None;
        self.dom_claim_finality_tip = None;
        self.dom_claim_finalized = false;
        self.rebroadcast_required = true;
        Ok(())
    }

    /// Refund is available only when no XMR release was ever committed.
    pub fn authorize_refund(&self, height: u64) -> Result<(), FastHandoffError> {
        if matches!(
            self.phase,
            FastHandoffPhase::XmrReleaseCommitted
                | FastHandoffPhase::XmrTransactionPrepared
                | FastHandoffPhase::Complete
        ) {
            return Err(FastHandoffError::RefundPermanentlyForbidden);
        }
        let first_refund = self
            .binding
            .policy
            .first_refund_height()
            .ok_or(FastHandoffError::InvalidPolicy)?;
        if height < first_refund {
            return Err(FastHandoffError::WrongOrder);
        }
        Ok(())
    }

    fn check_active_deadline(&self, observed_at: u64) -> Result<(), FastHandoffError> {
        let elapsed = observed_at
            .checked_sub(self.binding.active_window_started_at)
            .ok_or(FastHandoffError::ActiveDeadlineExceeded)?;
        if self
            .last_active_observation
            .is_some_and(|previous| observed_at < previous)
            || elapsed > self.binding.policy.active_deadline_seconds
        {
            Err(FastHandoffError::ActiveDeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            1_000,
            FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
        )
        .unwrap()
    }

    fn ready() -> FastHandoff {
        let mut handoff = FastHandoff::new(binding());
        handoff.record_ready(id(3), 2, id(4), true).unwrap();
        handoff
    }

    #[test]
    fn happy_path_completes_without_waiting_for_a_new_block() {
        let mut handoff = ready();
        handoff.record_dom_claim_exposure(id(5), 95, 1_004).unwrap();
        handoff
            .record_dom_daemon_admission(id(5), 95, 1_007)
            .unwrap();
        handoff.record_xmr_release_commitment(id(6), 1_008).unwrap();
        handoff
            .record_xmr_transaction_prepared(id(6), id(7), id(8), 1_009)
            .unwrap();
        handoff
            .record_xmr_daemon_admission(id(7), id(8), 1_010)
            .unwrap();
        assert_eq!(handoff.phase(), FastHandoffPhase::Complete);
        assert_eq!(handoff.latest_assumed_claim_height(), Some(97));
        assert!(handoff.rebroadcast_required());
        assert_eq!(
            handoff.authorize_refund(101),
            Err(FastHandoffError::RefundPermanentlyForbidden)
        );
    }

    #[test]
    fn xmr_cannot_move_before_exact_dom_daemon_admission() {
        let mut handoff = ready();
        assert_eq!(
            handoff.record_xmr_release_commitment(id(6), 1_001),
            Err(FastHandoffError::WrongOrder)
        );
        handoff.record_dom_claim_exposure(id(5), 95, 1_002).unwrap();
        assert_eq!(
            handoff.record_dom_daemon_admission(id(9), 95, 1_003),
            Err(FastHandoffError::DifferentTransaction)
        );
        assert_eq!(
            handoff.record_xmr_release_commitment(id(6), 1_004),
            Err(FastHandoffError::WrongOrder)
        );
    }

    #[test]
    fn admission_rechecks_margin_and_deadline() {
        let mut handoff = ready();
        assert_eq!(
            handoff.record_dom_claim_exposure(id(5), 99, 1_001),
            Err(FastHandoffError::ClaimMarginExhausted)
        );
        handoff.record_dom_claim_exposure(id(5), 97, 1_001).unwrap();
        assert_eq!(
            handoff.record_dom_daemon_admission(id(5), 98, 1_002),
            Err(FastHandoffError::ClaimMarginExhausted)
        );

        let mut late = ready();
        assert_eq!(
            late.record_dom_claim_exposure(id(5), 95, 1_181),
            Err(FastHandoffError::ActiveDeadlineExceeded)
        );

        let mut rollback = ready();
        rollback
            .record_dom_claim_exposure(id(5), 95, 1_002)
            .unwrap();
        assert_eq!(
            rollback.record_dom_daemon_admission(id(5), 95, 1_001),
            Err(FastHandoffError::ActiveDeadlineExceeded)
        );
    }

    #[test]
    fn refund_is_possible_only_before_any_xmr_commitment() {
        let handoff = ready();
        assert_eq!(
            handoff.authorize_refund(100),
            Err(FastHandoffError::WrongOrder)
        );
        handoff.authorize_refund(101).unwrap();

        let mut released = ready();
        released
            .record_dom_claim_exposure(id(5), 95, 1_001)
            .unwrap();
        released
            .record_dom_daemon_admission(id(5), 95, 1_002)
            .unwrap();
        released
            .record_xmr_release_commitment(id(6), 1_003)
            .unwrap();
        assert_eq!(
            released.authorize_refund(u64::MAX),
            Err(FastHandoffError::RefundPermanentlyForbidden)
        );
    }

    #[test]
    fn reorg_restores_claim_obligation_without_reopening_refund() {
        let mut handoff = ready();
        handoff.record_dom_claim_exposure(id(5), 95, 1_001).unwrap();
        handoff
            .record_dom_daemon_admission(id(5), 95, 1_002)
            .unwrap();
        handoff.record_xmr_release_commitment(id(6), 1_003).unwrap();
        handoff
            .record_xmr_transaction_prepared(id(6), id(7), id(11), 1_004)
            .unwrap();
        handoff
            .record_xmr_daemon_admission(id(7), id(11), 1_005)
            .unwrap();
        handoff
            .record_dom_claim_inclusion(id(5), 96, id(8))
            .unwrap();
        assert_eq!(
            handoff.record_dom_claim_inclusion(id(5), 96, id(8)),
            Err(FastHandoffError::WrongOrder)
        );
        assert_eq!(
            handoff.record_dom_claim_finality(id(5), 96, id(9), 97, id(10)),
            Err(FastHandoffError::WrongOrder)
        );
        assert_eq!(
            handoff.record_dom_claim_finality(id(5), 96, id(8), 97, id(9)),
            Ok(2)
        );
        assert!(handoff.dom_claim_finalized());
        assert!(!handoff.rebroadcast_required());
        assert_eq!(
            handoff.record_dom_claim_reorg(id(5), id(9)),
            Err(FastHandoffError::WrongOrder)
        );
        handoff.record_dom_claim_reorg(id(5), id(8)).unwrap();
        assert_eq!(handoff.dom_claim_canonical_block(), None);
        assert_eq!(handoff.dom_claim_finality_tip(), None);
        assert!(!handoff.dom_claim_finalized());
        assert!(handoff.rebroadcast_required());
        assert_eq!(
            handoff.authorize_refund(101),
            Err(FastHandoffError::RefundPermanentlyForbidden)
        );
    }

    #[test]
    fn inclusion_bound_is_strictly_before_refund_boundary() {
        let policy = binding().policy();
        assert_eq!(policy.last_safe_claim_target_height(), Some(97));
        assert_eq!(policy.check_claim_target(97), Ok(99));
        assert_eq!(policy.required_finality_height(97), Ok(100));
        assert_eq!(policy.first_refund_height(), Some(101));
        assert_eq!(
            policy.check_claim_target(98),
            Err(FastHandoffError::ClaimMarginExhausted)
        );
    }

    #[test]
    fn unusable_reserves_and_malformed_bindings_fail_closed() {
        let mut handoff = FastHandoff::new(binding());
        assert_eq!(
            handoff.record_ready(id(3), 1, id(4), true),
            Err(FastHandoffError::WrongOrder)
        );
        assert_eq!(
            handoff.record_ready(id(3), 2, id(4), false),
            Err(FastHandoffError::WrongOrder)
        );
        assert_eq!(
            FastHandoffPolicy::new(181, 2, 3, 2, 100),
            Err(FastHandoffError::InvalidPolicy)
        );
        assert_eq!(
            FastHandoffBinding::new(
                [0; 32],
                id(2),
                id(3),
                id(4),
                id(5),
                id(6),
                1_000,
                FastHandoffPolicy::new(180, 2, 3, 2, 100).unwrap(),
            ),
            Err(FastHandoffError::InvalidBinding)
        );
    }
}
