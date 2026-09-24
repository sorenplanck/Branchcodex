//! Continuously drive a selected DOM/XMR recovery graph after peer loss.
//!
//! The owner comes from the same Contracts opening and DOM child client used
//! by normal execution. A fresh native Store grant and fresh canonical scan are
//! mandatory on every tick, including restart and an ambiguous submission.

use crate::production_child_dom::ProductionDomXmrRecoveryClientV12;
use adapter_dom_real::{
    DomXmrRecoveryProgressV12, RealDomError, VerifiedDomXmrFundingPrerequisiteV12,
};
use dom_scriptless_store::{
    ContractsSessionStoreV1, PreparedOperationalXmrFundingGateV12, SessionStoreError,
    XmrRecoveryCustodyV11,
};
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::rc::Rc;

pub(crate) struct ProductionXmrRecoveryDriverV12 {
    store: Rc<ContractsSessionStoreV1>,
    gate: Rc<PreparedOperationalXmrFundingGateV12>,
    custody: Rc<XmrRecoveryCustodyV11>,
    client: ProductionDomXmrRecoveryClientV12,
}

impl ProductionXmrRecoveryDriverV12 {
    /// Same-Store gate for the DOM consumer of an already public U refund.
    pub(crate) fn refund_gate_v23(&self) -> &dom_scriptless_store::PreparedF7FundingGateV12 {
        &self.gate
    }

    pub(crate) fn observe_refund_reorg_v23(
        &self,
        checkpoint: &[u8],
        transaction: [u8; 32],
        budget: std::time::Duration,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRefundRevalidationV23, adapter_dom_real::RealDomError>
    {
        let started = std::time::Instant::now();
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)?;
        let remaining = budget
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or(adapter_dom_real::RealDomError::Chain(
                dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
            ))?;
        self.client.observe_refund_reorg_v23(
            &authority,
            &self.custody,
            checkpoint,
            transaction,
            remaining,
        )
    }

    pub(crate) fn new(
        store: Rc<ContractsSessionStoreV1>,
        gate: Rc<PreparedOperationalXmrFundingGateV12>,
        custody: Rc<XmrRecoveryCustodyV11>,
        client: ProductionDomXmrRecoveryClientV12,
    ) -> Result<Self, Refusal> {
        // Attachment is deliberately possible before funding. Actual execution
        // below still needs both signed ready votes and exact committed funding.
        store
            .validate_xmr_recovery_attachment_v12(&gate, &custody)
            .map_err(map_store)?;
        Ok(Self {
            store,
            gate,
            custody,
            client,
        })
    }

    /// Static recovery readiness from the same gate and actual private archive.
    /// No funding commit, final U bytes, chain observation or broadcast grant.
    pub(crate) fn refund_readiness_v23(
        &self,
    ) -> Result<dom_scriptless_store::VerifiedXmrRefundReadinessV23, SessionStoreError> {
        self.store
            .verify_xmr_refund_readiness_v23(&self.gate, &self.custody)
    }

    pub(crate) fn require_attachment(&self, terms_hash: [u8; 32]) -> Result<(), Refusal> {
        if self.custody.scope().binding.terms_hash != terms_hash {
            return Err(Refusal::Conflict);
        }
        self.store
            .validate_xmr_recovery_attachment_v12(&self.gate, &self.custody)
            .map_err(map_store)
    }

    pub(crate) fn require_refund_binding(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        template: [u8; 32],
        point: [u8; 33],
        minimum: u32,
        max_reorg: u32,
    ) -> Result<(), Refusal> {
        self.require_attachment(self.custody.scope().binding.terms_hash)?;
        if minimum == 0 || max_reorg < minimum {
            return Err(Refusal::Conflict);
        }
        self.custody
            .with_graph(|graph| {
                if graph.binding().session_id != session
                    || graph.binding().chain_id != chain
                    || graph.refund_pre_signature().template_hash() != &template
                    || graph.refund_pre_signature().refund_adaptor_point() != point
                {
                    return Err(Refusal::Conflict);
                }
                Ok(())
            })
            .map_err(|_| Refusal::Conflict)?
    }

    pub(crate) fn observe_refund_share(
        &self,
    ) -> Result<adapter_dom_real::VerifiedDomRefundSecretV11, Refusal> {
        self.observe_refund_share_bounded_v23(default_recovery_budget_v27()?)
    }

    pub(crate) fn observe_refund_share_bounded_v23(
        &self,
        budget: std::time::Duration,
    ) -> Result<adapter_dom_real::VerifiedDomRefundSecretV11, Refusal> {
        let deadline = recovery_deadline_v23(std::time::Instant::now(), budget)?;
        self.observe_refund_share_until_v24(deadline)
    }

    pub(crate) fn observe_refund_share_until_v24(
        &self,
        deadline: std::time::Instant,
    ) -> Result<adapter_dom_real::VerifiedDomRefundSecretV11, Refusal> {
        with_public_refund_deadline_v24(deadline, |deadline| {
            let authority = self
                .store
                .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
                .map_err(map_store)?;
            match self
                .client
                .observe_until_v24(&authority, &self.custody, deadline)
                .map_err(map_real)?
            {
                adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(secret) => Ok(secret),
                adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Compensated(_) => {
                    // The recovery pump observes and records compensation in
                    // separate ticks. Until its durable route marker arrives,
                    // the route may still ask for U. Refuse that competing
                    // refund without terminating the writer that must record
                    // compensation; a compensated graph never supplies U.
                    Err(Refusal::Unavailable)
                }
                _ => Err(Refusal::Unavailable),
            }
        })
    }

    /// Run independently of Relay polling/peer availability. No operation here
    /// needs a new counterparty signature after collateral has been committed.
    /// U revelation and DOM compensation are deliberately different variants;
    /// only the XMR actuator can later report an actual refunded XMR sweep.
    pub(crate) fn tick(&self) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        self.tick_bounded_v23(default_recovery_budget_v27()?)
    }

    pub(crate) fn tick_bounded_v23(
        &self,
        budget: std::time::Duration,
    ) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        let started = std::time::Instant::now();
        let deadline = recovery_deadline_v23(started, budget)?;
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        self.client
            .advance(&authority, &self.custody, deadline)
            .map_err(map_real)
    }

    /// Compensation requires the real selected Monero observer's fresh proof.
    /// A recorded DOM collateral transaction cannot stand in for paid XMR.
    pub(crate) fn tick_with_funding(
        &self,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        self.tick_with_funding_bounded_v23(funding, default_recovery_budget_v27()?)
    }

    pub(crate) fn tick_with_funding_bounded_v23(
        &self,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
        budget: std::time::Duration,
    ) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        let started = std::time::Instant::now();
        let deadline = recovery_deadline_v23(started, budget)?;
        let authority = self
            .store
            .authorize_xmr_recovery_with_funding_v12(&self.gate, &self.custody, funding)
            .map_err(map_store)?;
        self.custody
            .retain_xmr_funding_observed_v22(&authority)
            .map_err(|_| Refusal::Conflict)?;
        self.client
            .advance(&authority, &self.custody, deadline)
            .map_err(map_real)
    }

    /// Close the exact route leg through its sole fenced writer, preserving
    /// the distinction between a DOM payout and an actual XMR sweep refund.
    pub(crate) fn record_compensation_with_funding<C: crate::supervisor::Clock>(
        &self,
        supervisor: &mut crate::supervisor::RouteSupervisorV1<C>,
        leg: route_executor::LegIdV1,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
        observed: &adapter_dom_real::VerifiedDomCompensationObservationV11,
    ) -> Result<route_executor::CommitOutcomeV1, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_with_funding_v12(&self.gate, &self.custody, funding)
            .map_err(map_store)?;
        self.custody
            .retain_xmr_funding_observed_v22(&authority)
            .map_err(|_| Refusal::Conflict)?;
        // The pump may have waited for XMR availability after observing this
        // DOM exit. Its cached token is only an exact identity hint: acquire a
        // new canonical DOM observation before crossing the terminal writer.
        // On restart the immutable exit checkpoint is likewise not finality.
        commit_reobserved_compensation_v23(
            compensation_identity_v23(observed),
            || match self
                .client
                .observe(&authority, &self.custody)
                .map_err(map_real)?
            {
                adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Compensated(fresh) => {
                    Ok(Some((compensation_identity_v23(&fresh), fresh)))
                }
                adapter_dom_real::VerifiedDomXmrRecoveryStateV11::CollateralReady(_)
                | adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Cancelled(_) => Ok(None),
                adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(_) => {
                    Err(Refusal::Conflict)
                }
            },
            |fresh| {
                fresh.require_recent_v12().map_err(map_real)?;
                // The DOM scan may itself have exhausted the funding proof's
                // lifetime. Retry observation, never downgrade it to authority.
                authority
                    .require_xmr_funding_observed_v12()
                    .map_err(map_store)?;
                supervisor
                    .record_dom_compensation_v12(leg, &authority, &self.custody, &fresh)
                    .map_err(|error| match error {
                        crate::supervisor::RouteSupervisorErrorV1::StoreAuthorityBusy
                        | crate::supervisor::RouteSupervisorErrorV1::Clock(_)
                        | crate::supervisor::RouteSupervisorErrorV1::Store(
                            route_executor::RouteStoreErrorV1::StorageUnavailable
                            | route_executor::RouteStoreErrorV1::LeaseExpired
                            | route_executor::RouteStoreErrorV1::RevisionConflict,
                        ) => Refusal::Unavailable,
                        // The Store repeats the two freshness checks made just
                        // above and reports a failure as InvalidMaterial. If
                        // either proof has aged past its bound in between, the
                        // refusal is that race and is retried with a new
                        // observation, exactly like the checks above. Any other
                        // InvalidMaterial is still a conflict.
                        crate::supervisor::RouteSupervisorErrorV1::Store(
                            route_executor::RouteStoreErrorV1::InvalidMaterial,
                        ) if fresh.require_recent_v12().is_err()
                            || authority.require_xmr_funding_observed_v12().is_err() =>
                        {
                            Refusal::Unavailable
                        }
                        _ => Refusal::Conflict,
                    })
            },
        )
    }

    /// Called only with the actual locally retained and independently verified
    /// funding candidate. The durable intent precedes a second fresh DOM scan;
    /// exact broadcaster submission cannot substitute another transaction.
    pub(crate) fn broadcast_private_funding(
        &self,
        terms_hash: [u8; 32],
        setup_hash: [u8; 32],
        candidate: &xmr_rpc_broadcast_blocking::PreparedPrivateFundingV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), Refusal> {
        self.require_attachment(terms_hash)?;
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        let verified = candidate.verified().transaction();
        if setup_hash != authority.xmr_setup_binding_hash()
            || verified.tx_hash != authority.xmr_funding_tx_hash()
        {
            return Err(Refusal::Conflict);
        }
        self.custody
            .retain_xmr_funding_attempt_v12(
                &authority,
                setup_hash,
                verified.tx_hash,
                verified.raw_fingerprint,
            )
            .map_err(|_| Refusal::Conflict)?;
        let prerequisite = match broadcast.submission_deadline_v24() {
            Some(deadline) => self.verify_funding_prerequisite_bounded_v23(
                deadline.saturating_duration_since(std::time::Instant::now()),
            )?,
            None => self.verify_funding_prerequisite()?,
        };
        if prerequisite.collateral().finality().terms_hash() != terms_hash {
            return Err(Refusal::Conflict);
        }
        candidate
            .with_raw(|raw| broadcast.submit_exact(verified.tx_hash, raw))
            .map(|_| ())
            .map_err(|error| match error {
                xmr_spend_port::SpendPortError::Retryable => Refusal::Unavailable,
                xmr_spend_port::SpendPortError::Rejected => Refusal::Conflict,
            })
    }

    /// Call at the actual selected-XMR funding boundary, not just bootstrap.
    /// The returned opaque evidence has no persisted/raw reconstruction path.
    pub(crate) fn verify_funding_prerequisite(
        &self,
    ) -> Result<VerifiedDomXmrFundingPrerequisiteV12, Refusal> {
        self.verify_funding_prerequisite_bounded_v23(default_recovery_budget_v27()?)
    }

    pub(crate) fn verify_funding_prerequisite_bounded_v23(
        &self,
        budget: std::time::Duration,
    ) -> Result<VerifiedDomXmrFundingPrerequisiteV12, Refusal> {
        let started = std::time::Instant::now();
        let deadline = recovery_deadline_v23(started, budget)?;
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        self.client
            .verify_funding_prerequisite(&authority, &self.custody, deadline)
            .map_err(map_real)
    }

    /// A fresh chain token plus a stable PUBLIC event digest for peer retries.
    /// The stable digest names U's graph/transaction, not an observation time.
    pub(crate) fn observe_remote_refund_event_v23(
        &self,
    ) -> Result<(adapter_dom_real::VerifiedDomRefundSecretV11, [u8; 32]), Refusal> {
        self.observe_remote_refund_event_bounded_v24(default_recovery_budget_v27()?)
    }

    pub(crate) fn observe_remote_refund_event_bounded_v24(
        &self,
        budget: std::time::Duration,
    ) -> Result<(adapter_dom_real::VerifiedDomRefundSecretV11, [u8; 32]), Refusal> {
        let deadline = recovery_deadline_v23(std::time::Instant::now(), budget)?;
        self.observe_remote_refund_event_until_v24(deadline)
    }

    pub(crate) fn observe_remote_refund_event_until_v24(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(adapter_dom_real::VerifiedDomRefundSecretV11, [u8; 32]), Refusal> {
        with_public_refund_deadline_v24(deadline, |deadline| {
            let observed = self.observe_refund_share_until_v24(deadline)?;
            observed.require_recent_v23().map_err(map_real)?;
            let digest = self
                .store
                .native_xmr_refund_transport_public_evidence_v23(
                    &self.gate,
                    &self.custody,
                    observed.finality().transaction_hash(),
                )
                .map_err(map_store)?;
            observed.require_recent_v23().map_err(map_real)?;
            Ok((observed, digest))
        })
    }

    /// Install ONLY the public-message permission after this driver's exact
    /// graph has yielded a fresh U. An old checkpoint cannot enter this API.
    pub(crate) fn retain_remote_refund_transport_v23(
        &self,
        request_bytes: &[u8],
        observed: &adapter_dom_real::VerifiedDomRefundSecretV11,
    ) -> Result<(), Refusal> {
        observed.require_recent_v23().map_err(map_real)?;
        let scope = self.custody.scope();
        let request = xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(request_bytes)
            .map_err(|_| Refusal::Conflict)?;
        if observed.session_id() != scope.binding.session_id
            || observed.chain_id() != scope.binding.chain_id
            || observed.finality().terms_hash() != scope.binding.terms_hash
            || observed.finality().graph_digest() != scope.graph_digest
            || request.action != xmr_remote_sweep_wire::RemoteSweepActionV23::Refund
            || request.session_id != scope.binding.session_id
            || request.terms_digest != scope.binding.terms_hash
            || !observed.expose(|big_endian| {
                // Byte identity only. The actual cross-curve recovery and
                // proof validation remain in the dedicated sweep authority.
                let mut little_endian = *big_endian;
                little_endian.reverse();
                little_endian == request.public_spend_share
            })
        {
            return Err(Refusal::Conflict);
        }
        self.store
            .retain_native_xmr_refund_transport_v23(
                &self.gate,
                &self.custody,
                request_bytes,
                observed.finality().transaction_hash(),
            )
            .map_err(map_store)?;
        observed.require_recent_v23().map_err(map_real)
    }
}

/// Admit and finish one public read without ever converting its cutoff to a
/// duration. The closure receives the exact Instant supplied by the caller.
fn with_public_refund_deadline_v24<T>(
    deadline: std::time::Instant,
    operation: impl FnOnce(std::time::Instant) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero() && *duration <= std::time::Duration::from_secs(60))
        .ok_or(Refusal::Unavailable)?;
    // Remaining time is checked only; it is never used to start another clock.
    let _ = remaining;
    let value = operation(deadline)?;
    if std::time::Instant::now() >= deadline {
        return Err(Refusal::Unavailable);
    }
    Ok(value)
}

fn recovery_deadline_v23(
    started: std::time::Instant,
    budget: std::time::Duration,
) -> Result<std::time::Instant, Refusal> {
    if budget.is_zero() || budget > std::time::Duration::from_secs(60) {
        return Err(Refusal::Unavailable);
    }
    // Narrow to the route-step ceiling when one is armed: this is the single
    // constructor every bounded recovery call goes through, so clamping here
    // covers the whole family at once. Per-call budgets do not compose, and
    // several of these run inside one step.
    started
        .checked_add(budget)
        .map(adapter_dom_real::route_step_deadline_v27::clamp_v27)
        .filter(|deadline| *deadline > std::time::Instant::now())
        .ok_or(Refusal::Unavailable)
}

/// Sixty seconds is each unnamed caller's own budget; when a route-step or
/// pump ceiling is armed on this thread, narrow to what it leaves. Budgets do
/// not compose across one step, and these observations all run inside one.
fn default_recovery_budget_v27() -> Result<std::time::Duration, Refusal> {
    route_step_deadline::remaining(std::time::Duration::from_secs(60)).ok_or(Refusal::Unavailable)
}

#[cfg(test)]
mod recovery_deadline_tests_v23 {
    use super::*;
    #[test]
    fn public_refund_passes_exact_instant_and_expiry_calls_nothing_v24() -> Result<(), Refusal> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let seen = with_public_refund_deadline_v24(deadline, |outer| {
            assert_eq!(outer, deadline);
            with_public_refund_deadline_v24(outer, |inner| Ok(inner))
        })?;
        assert_eq!(seen, deadline);
        let calls = std::cell::Cell::new(0);
        let expired = std::time::Instant::now();
        assert_eq!(
            with_public_refund_deadline_v24(expired, |_| {
                calls.set(calls.get() + 1);
                Ok(())
            }),
            Err(Refusal::Unavailable)
        );
        assert_eq!(calls.get(), 0);
        Ok(())
    }
    #[test]
    fn driver_keeps_the_initial_absolute_deadline_and_refuses_exhausted_budget_v23(
    ) -> Result<(), Refusal> {
        let now = std::time::Instant::now();
        let budget = std::time::Duration::from_secs(1);
        let expected = now.checked_add(budget).ok_or(Refusal::Unavailable)?;
        assert_eq!(recovery_deadline_v23(now, budget)?, expected);
        assert!(recovery_deadline_v23(now, std::time::Duration::ZERO).is_err());
        assert!(recovery_deadline_v23(now, std::time::Duration::from_secs(61)).is_err());
        let expired = now
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or(Refusal::Unavailable)?;
        assert!(recovery_deadline_v23(expired, budget).is_err());
        Ok(())
    }
}

/// Stable economic identity, deliberately excluding tip, containing block and
/// finality digest: a fresh canonical scan may legitimately follow a reorg.
type CompensationIdentityV23 = [[u8; 32]; 7];

fn compensation_identity_v23(
    observed: &adapter_dom_real::VerifiedDomCompensationObservationV11,
) -> CompensationIdentityV23 {
    let finality = observed.finality();
    [
        finality.chain_id(),
        finality.session_id(),
        finality.terms_hash(),
        finality.graph_digest(),
        finality.funding_tx_hash(),
        finality.transaction_hash(),
        *dom_crypto::blake2b_256(observed.canonical_transaction_v22()).as_bytes(),
    ]
}

// This is the terminal driver handoff, not a constructor for native evidence.
// The productive callback receives only the newly observed opaque token.
fn commit_reobserved_compensation_v23<O, R>(
    expected: CompensationIdentityV23,
    observe: impl FnOnce() -> Result<Option<(CompensationIdentityV23, O)>, Refusal>,
    commit: impl FnOnce(O) -> Result<R, Refusal>,
) -> Result<R, Refusal> {
    let (identity, fresh) = observe()?.ok_or(Refusal::Unavailable)?;
    if identity != expected {
        return Err(Refusal::Conflict);
    }
    commit(fresh)
}

#[cfg(test)]
mod compensation_handoff_tests {
    use super::*;
    use std::cell::Cell;

    fn identity() -> CompensationIdentityV23 {
        std::array::from_fn(|index| [index as u8 + 1; 32])
    }

    #[test]
    fn delayed_compensation_handoff_commits_only_the_new_observation() {
        // These counters are test tokens, never native finality evidence.
        // The old pump observation can survive arbitrary XMR unavailability;
        // the terminal callback must receive the new DOM scan's token instead.
        let retained_snapshot = 1;
        let new_snapshot = 2;
        let scans = Cell::new(0);
        let committed = commit_reobserved_compensation_v23(
            identity(),
            || {
                scans.set(scans.get() + 1);
                Ok(Some((identity(), new_snapshot)))
            },
            Ok,
        );
        assert_eq!(committed, Ok(new_snapshot));
        assert_ne!(committed, Ok(retained_snapshot));
        assert_eq!(scans.get(), 1);
    }

    #[test]
    fn reorg_or_temporarily_absent_compensation_never_reaches_the_writer() {
        assert_eq!(
            commit_reobserved_compensation_v23::<(), ()>(
                identity(),
                || Ok(None),
                |_| panic!("a retained checkpoint is not current finality"),
            ),
            Err(Refusal::Unavailable)
        );
        // A later fresh canonical observation of the same economic exit can
        // complete; block/tip identities are authenticated by the scanner.
        assert_eq!(
            commit_reobserved_compensation_v23(identity(), || Ok(Some((identity(), ()))), Ok),
            Ok(())
        );
    }

    #[test]
    fn changed_compensation_scope_or_transaction_stays_a_hard_conflict() {
        for index in 0..7 {
            let mut changed = identity();
            changed[index][0] ^= 1;
            assert_eq!(
                commit_reobserved_compensation_v23::<(), ()>(
                    identity(),
                    || Ok(Some((changed, ()))),
                    |_| panic!("foreign compensation must not close this leg"),
                ),
                Err(Refusal::Conflict)
            );
        }
        for refusal in [Refusal::Unavailable, Refusal::Conflict] {
            assert_eq!(
                commit_reobserved_compensation_v23::<(), ()>(
                    identity(),
                    || Err(refusal),
                    |_| panic!("an observation failure must not reach the writer"),
                ),
                Err(refusal)
            );
            assert_eq!(
                commit_reobserved_compensation_v23::<(), ()>(
                    identity(),
                    || Ok(Some((identity(), ()))),
                    |_| Err(refusal),
                ),
                Err(refusal)
            );
        }
    }
}

fn map_store(error: SessionStoreError) -> Refusal {
    match error {
        SessionStoreError::Filesystem
        | SessionStoreError::StoreBusy
        | SessionStoreError::FundingAuthorityUnavailable => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}

fn map_real(error: RealDomError) -> Refusal {
    match error {
        RealDomError::EvidenceNotFound
        | RealDomError::InsufficientConfirmations
        | RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
        )
        | RealDomError::Store(
            SessionStoreError::Filesystem
            | SessionStoreError::StoreBusy
            | SessionStoreError::FundingAuthorityUnavailable,
        ) => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}
