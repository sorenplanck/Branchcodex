//! Lightweight gate regressions. Dispatch requests come from the real durable
//! coordinator, not fabricated capabilities. Instrumented boundaries refuse
//! economic work: these are not chain/signature/readiness tests.
#![cfg(target_os = "linux")]

use super::*;
use crate::supervisor::{
    ManualClockV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1, RouteSupervisorV1,
};
use route_executor::{DurableRouteStoreV1, FrozenBindingsV1, LegIdV1, RouteEventV1};
use settlement_coordinator::{
    CompositeSettlementPlanV1, DurableSettlementCoordinatorV1, PlanAuthorityRefusalV1,
    PlanAuthorizationRequestV1, PlanAuthorizationV1, SecretRequirementV1, SettlementChildPlanV1,
    SettlementFaceV1, SettlementLegV1, SettlementPlanAuthorityV1, SettlementPlanBindingsV1,
};
use std::{error::Error, os::unix::fs::PermissionsExt};

const ROUTE: [u8; 32] = [1; 32];
type TestResult = Result<(), Box<dyn Error>>;

fn temporary() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(temporary)
}

#[derive(Default)]
struct RecordingAuthority {
    actions: Vec<ActionKindV1>,
    dispatches: Vec<ChildDispatchRequestV1>,
    reconciliations: Vec<ChildReconciliationRequestV1>,
    observations: Vec<ChildObservationRequestV1>,
}

impl RouteActionAuthority for RecordingAuthority {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        self.actions.push(request.action());
        Err(AuthorityRefusalV1::Inconsistent)
    }
}

impl SettlementChildAuthorityV1 for RecordingAuthority {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.dispatches.push(*request);
        Err(ChildAuthorityRefusalV1::Refused)
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.reconciliations.push(*request);
        Ok(ChildReconciliationOutcomeV1::Unknown {
            evidence_digest: [91; 32],
        })
    }
}

impl SettlementChildObserverV1 for RecordingAuthority {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.observations.push(*request);
        Ok(ChildObservationOutcomeV1::Pending {
            evidence_digest: [92; 32],
        })
    }
}

fn supervisor(
    directory: &std::path::Path,
) -> Result<RouteSupervisorV1<ManualClockV1>, Box<dyn Error>> {
    let mut store = DurableRouteStoreV1::create(&directory.join("route.sqlite"))?;
    let owner = [2; 32];
    store.create_route(ROUTE, 90)?;
    let lease = store.acquire_lease(ROUTE, owner, 90, 1_000)?.lease();
    // Test-only admission fixture; no production constructor is loosened.
    store.apply_event(
        lease,
        0,
        [3; 32],
        &RouteEventV1::FreezeTerms(FrozenBindingsV1 {
            terms_digest: [4; 32],
            profile_bundle_digest: [5; 32],
            deployment_bundle_digest: [6; 32],
        }),
        90,
    )?;
    Ok(RouteSupervisorV1::acquire(
        store,
        ROUTE,
        owner,
        RouteSupervisorConfigV1::new(1_000, 200, 100, 8)?,
        ManualClockV1::new(100)?,
    )?)
}

#[test]
fn action_gate_blocks_only_new_funding_and_preserves_inner_refusals_v23() -> TestResult {
    let temporary = temporary()?;
    let mut supervisor = supervisor(temporary.path())?;
    let window = ProductionFundingWindowV23::new(ROUTE);
    let mut guard = window.guard(RecordingAuthority::default());
    for action in [
        ActionKindV1::Funding,
        ActionKindV1::Claim,
        ActionKindV1::Refund,
    ] {
        let expected = if action == ActionKindV1::Funding {
            AuthorityRefusalV1::Unavailable
        } else {
            AuthorityRefusalV1::Inconsistent
        };
        assert!(matches!(
            supervisor.authorize_action([20; 32], LegIdV1::Upstream, action, &mut guard),
            Err(RouteSupervisorErrorV1::RouteActionAuthority(error)) if error == expected
        ));
    }
    assert_eq!(
        guard.inner.actions,
        [ActionKindV1::Claim, ActionKindV1::Refund]
    );
    window.observed_all_before_deadline(Instant::now());
    assert!(matches!(
        supervisor.authorize_action(
            [21; 32],
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &mut guard
        ),
        Err(RouteSupervisorErrorV1::RouteActionAuthority(
            AuthorityRefusalV1::Inconsistent
        ))
    ));
    assert_eq!(guard.inner.actions.last(), Some(&ActionKindV1::Funding));
    window.close();
    let before = guard.inner.actions.len();
    assert!(matches!(
        supervisor.authorize_action(
            [22; 32],
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &mut guard
        ),
        Err(RouteSupervisorErrorV1::RouteActionAuthority(
            AuthorityRefusalV1::Unavailable
        ))
    ));
    assert_eq!(guard.inner.actions.len(), before);
    Ok(())
}

#[test]
fn action_gate_rejects_wrong_route_even_when_open_v23() -> TestResult {
    let temporary = temporary()?;
    let mut supervisor = supervisor(temporary.path())?;
    let window = ProductionFundingWindowV23::new([99; 32]);
    window.observed_all_before_deadline(Instant::now());
    let mut guard = window.guard(RecordingAuthority::default());
    for action in [
        ActionKindV1::Funding,
        ActionKindV1::Claim,
        ActionKindV1::Refund,
    ] {
        assert!(matches!(
            supervisor.authorize_action([20; 32], LegIdV1::Upstream, action, &mut guard),
            Err(RouteSupervisorErrorV1::RouteActionAuthority(
                AuthorityRefusalV1::Refused
            ))
        ));
    }
    assert!(guard.inner.actions.is_empty());
    Ok(())
}

struct PlanAuthority;
impl SettlementPlanAuthorityV1 for PlanAuthority {
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        PlanAuthorizationV1::new([81; 32], request.plan_digest(), [82; 32], 20_000)
            .map_err(|_| PlanAuthorityRefusalV1::Refused)
    }
}

fn dispatch(action: SettlementActionV1) -> Result<ChildDispatchRequestV1, Box<dyn Error>> {
    use settlement_coordinator::ChildExposureV1;
    let temporary = temporary()?;
    let claim = action == SettlementActionV1::Claim;
    let children =
        [(SettlementFaceV1::Monero, 40), (SettlementFaceV1::Dom, 50)].map(|(face, tag)| {
            SettlementChildPlanV1 {
                face,
                exposure: if claim {
                    ChildExposureV1::UsesPublicSecret
                } else {
                    ChildExposureV1::NonSecret
                },
                chain_id: [tag; 32],
                expected_transaction_id: [tag + 1; 32],
                intent_digest: [tag + 2; 32],
                custody_digest: [tag + 3; 32],
            }
        });
    let plan = CompositeSettlementPlanV1::new(
        SettlementPlanBindingsV1 {
            route_id: ROUTE,
            effect_id: [10; 32],
            settlement_id: [11; 32],
            leg: SettlementLegV1::Upstream,
            action,
            fencing_epoch: 1,
            semantic_digest: [12; 32],
            terms_digest: [13; 32],
            registry_digest: [14; 32],
            dom_profile_digest: [15; 32],
            dom_deployment_digest: [16; 32],
            counterparty_profile_digest: [17; 32],
            counterparty_deployment_digest: [18; 32],
        },
        if claim {
            SecretRequirementV1::AlreadyPublic
        } else {
            SecretRequirementV1::None
        },
        claim.then_some([19; 32]),
        children,
    )?;
    let mut coordinator = DurableSettlementCoordinatorV1::create(
        &temporary.path().join("coordinator.sqlite"),
        [80; 32],
        [81; 32],
        10_000,
    )?;
    let view = coordinator.install_plan(&mut PlanAuthority, plan, 10_001)?;
    let lease = coordinator
        .acquire_lease(view.plan_id, [83; 32], 1, 10_002, 1_000)?
        .lease();
    Ok(*coordinator
        .prepare_next_child_call(lease, 10_003)?
        .request())
}

#[test]
fn dispatch_gate_requires_live_funding_but_does_not_rewrite_recovery_v23() -> TestResult {
    let window = ProductionFundingWindowV23::new(ROUTE);
    let mut guard = window.guard(RecordingAuthority::default());
    let funding = dispatch(SettlementActionV1::Funding)?;
    assert_eq!(
        guard.externalize_child(&funding),
        Err(ChildAuthorityRefusalV1::Unavailable)
    );
    assert!(guard.inner.dispatches.is_empty());
    for action in [SettlementActionV1::Claim, SettlementActionV1::Refund] {
        let request = dispatch(action)?;
        assert_eq!(
            guard.externalize_child(&request),
            Err(ChildAuthorityRefusalV1::Refused)
        );
        assert_eq!(guard.inner.dispatches.last(), Some(&request));
    }
    window.observed_all_before_deadline(Instant::now());
    assert_eq!(
        guard.externalize_child(&funding),
        Err(ChildAuthorityRefusalV1::Refused)
    );
    assert_eq!(guard.inner.dispatches.last(), Some(&funding));
    window.close();
    let before = guard.inner.dispatches.len();
    assert_eq!(
        guard.externalize_child(&funding),
        Err(ChildAuthorityRefusalV1::Unavailable)
    );
    assert_eq!(guard.inner.dispatches.len(), before);
    Ok(())
}

#[test]
fn child_gate_never_substitutes_another_route_permission_v23() -> TestResult {
    let window = ProductionFundingWindowV23::new([99; 32]);
    window.observed_all_before_deadline(Instant::now());
    let mut guard = window.guard(RecordingAuthority::default());
    for action in [
        SettlementActionV1::Funding,
        SettlementActionV1::Claim,
        SettlementActionV1::Refund,
    ] {
        assert_eq!(
            guard.externalize_child(&dispatch(action)?),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }
    assert!(guard.inner.dispatches.is_empty());
    Ok(())
}

#[test]
fn closed_gate_preserves_exact_reconciliation_and_unknown_outcome_v23() -> TestResult {
    let window = ProductionFundingWindowV23::new(ROUTE);
    let mut guard = window.guard(RecordingAuthority::default());
    let request = ChildReconciliationRequestV1 {
        dispatch: dispatch(SettlementActionV1::Funding)?,
        current_route_fencing_epoch: 2,
        current_coordinator_fencing_epoch: 3,
        reconciliation_attempt_id: [90; 32],
    };
    assert_eq!(
        guard.reconcile_child(&request)?,
        ChildReconciliationOutcomeV1::Unknown {
            evidence_digest: [91; 32]
        }
    );
    assert_eq!(guard.inner.reconciliations, [request]);
    assert!(guard.inner.dispatches.is_empty());
    Ok(())
}

#[test]
fn funding_finality_observation_is_not_disabled_by_closed_funding_v23() -> TestResult {
    let window = ProductionFundingWindowV23::new(ROUTE);
    let mut guard = window.guard(RecordingAuthority::default());
    let d = dispatch(SettlementActionV1::Funding)?;
    let request = ChildObservationRequestV1 {
        plan_id: d.plan_id(),
        plan_digest: d.plan_digest(),
        route_id: d.route_id(),
        effect_id: d.effect_id(),
        settlement_id: d.settlement_id(),
        leg: d.leg(),
        action: d.action(),
        semantic_digest: d.semantic_digest(),
        route_fencing_epoch: d.route_fencing_epoch(),
        terms_digest: d.terms_digest(),
        registry_digest: d.registry_digest(),
        profile_digest: d.profile_digest(),
        deployment_digest: d.deployment_digest(),
        child_index: d.child_index(),
        face: d.face(),
        exposure: d.exposure(),
        chain_id: d.chain_id(),
        transaction_id: d.expected_transaction_id(),
        intent_digest: d.intent_digest(),
        custody_digest: d.custody_digest(),
        prior_finality_evidence_digest: Some([93; 32]),
        observation_attempt_id: [94; 32],
    };
    assert_eq!(
        guard.observe_child(&request)?,
        ChildObservationOutcomeV1::Pending {
            evidence_digest: [92; 32]
        }
    );
    assert_eq!(guard.inner.observations, [request]);
    assert!(guard.inner.dispatches.is_empty());
    Ok(())
}

#[test]
fn late_observation_completion_never_grants_a_fresh_sixty_seconds_v23() -> TestResult {
    let window = ProductionFundingWindowV23::new(ROUTE);
    let old_start = Instant::now()
        .checked_sub(Duration::from_secs(61))
        .ok_or("monotonic test origin")?;
    window.observed_all_before_deadline(old_start);
    assert!(!window.available());
    assert_eq!(window.remaining(), Duration::ZERO);
    let mut guard = window.guard(RecordingAuthority::default());
    assert_eq!(
        guard.externalize_child(&dispatch(SettlementActionV1::Funding)?),
        Err(ChildAuthorityRefusalV1::Unavailable)
    );
    assert!(guard.inner.dispatches.is_empty());
    Ok(())
}

#[test]
fn zero_scan_budget_is_retryable_but_corrupt_chain_evidence_is_not_v23() {
    use crate::production_contracts::ProductionFundingErrorV20;
    use adapter_dom_real::RealDomError;
    use dom_scriptless_chain_adapter::ChainAdapterError;
    assert!(ProductionFundingErrorV20::Observation(RealDomError::Chain(
        ChainAdapterError::TemporarilyUnavailable,
    ))
    .retryable());
    assert!(!ProductionFundingErrorV20::Binding.retryable());
    assert!(!ProductionFundingErrorV20::Observation(RealDomError::LockPoisoned).retryable());
}

#[test]
fn deadline_getter_preserves_original_scope_and_shared_revocation_v23() {
    let window = ProductionFundingWindowV23::new(ROUTE);
    let consumer = window.clone();
    assert!(consumer.deadline_for_route(ROUTE).is_none());
    let start = Instant::now();
    window.observed_all_before_deadline(start);
    assert_eq!(
        consumer.deadline_for_route(ROUTE),
        Some(start + Duration::from_secs(60))
    );
    assert_eq!(
        consumer.deadline_for_route(ROUTE),
        window.deadline_for_route(ROUTE)
    );
    assert!(consumer.deadline_for_route([99; 32]).is_none());
    window.close();
    assert!(consumer.deadline_for_route(ROUTE).is_none());
}
