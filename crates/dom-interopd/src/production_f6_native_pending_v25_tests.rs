//! Activation-state tests, not a substitute for the real principal proof tests.
use super::*;
use crate::production_f6_lifecycle::ProductionPendingAuthorityV1;
use std::cell::Cell;

struct AwaitingFactory {
    calls: Rc<Cell<usize>>,
    refuse: Rc<Cell<bool>>,
}

impl pair_factory_seal::Sealed for AwaitingFactory {}
impl ProductionF6PairAuthoritiesFactoryV2 for AwaitingFactory {
    fn bind_pair(
        &mut self,
        _upstream_wire: route_transport::RouteWireContextV1,
        _upstream_rfq: RfqV2,
        _downstream_wire: route_transport::RouteWireContextV1,
        _downstream_rfq: RfqV2,
    ) -> Result<AuthenticatedProductionF6PairBindingV7, ProductionF6ActivationRefusalV2> {
        self.calls.set(self.calls.get() + 1);
        if self.refuse.get() {
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        } else {
            Err(ProductionF6ActivationRefusalV2::Awaiting(
                ProductionPendingAuthorityV1::AdapterTerms {
                    position: SettlementPositionV2::Downstream,
                },
            ))
        }
    }

    fn build_authorities(
        &mut self,
        _upstream_binding: ProductionSolverF6BindingV2,
        _upstream_terminal: ProductionRouteTerminalAuthorityV2,
        _downstream_binding: ProductionSolverF6BindingV2,
        _downstream_terminal: ProductionRouteTerminalAuthorityV2,
    ) -> Result<
        (ProductionF6AuthoritiesV2, ProductionF6AuthoritiesV2),
        ProductionF6ActivationRefusalV2,
    > {
        panic!("awaiting principal must never reach terminal/authority construction")
    }
}

fn fixture() -> (
    ProductionF6PairActivationStateV2,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
) {
    use rfq::v2::{
        NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, RfqRequestV2, RouteV2,
    };
    use rfq::{
        AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId, PolicyId, RfqModeV1,
        RouteLegV1,
    };
    let clock = NegotiationClockV2 {
        chain_id: ChainId([1; 32]),
        profile_digest: [2; 32],
        authority_scope: [3; 32],
        kind: NativeClockKindV2::BlockHeight,
    };
    let rfq = |position, session| {
        RfqV2::create(RfqRequestV2 {
            initiator: ParticipantId([4; 32]),
            route: RouteV2 {
                composition_id: [5; 32],
                position,
                legs: [
                    RouteLegV1 {
                        chain_id: ChainId([1; 32]),
                        asset: AssetId([6; 32]),
                        direction: LegDirectionV1::UserGives,
                    },
                    RouteLegV1 {
                        chain_id: ChainId([7; 32]),
                        asset: AssetId([8; 32]),
                        direction: LegDirectionV1::UserReceives,
                    },
                ],
            },
            mode: RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            fee_limit: FeeLimitV1 {
                dom_max: 2,
                counterparty_max: 3,
            },
            negotiation_clock: clock,
            quote_deadline: NegotiationInstantV2 { clock, value: 1000 },
            assurance_policy_ref: PolicyId([9; 32]),
            policy_version: 1,
            session_id: session,
        })
        .unwrap()
    };
    let wire = |session_id| route_transport::RouteWireContextV1 {
        network_id: [10; 32],
        session_id,
        route_id: [11; 32],
        roster_snapshot: [12; 32],
        policy_version: 1,
    };
    let calls = Rc::new(Cell::new(0));
    let refuse = Rc::new(Cell::new(false));
    let state = ProductionF6PairActivationStateV2 {
        route_store: None, // No database needed: this boundary must never touch it.
        route_id: [11; 32],
        composition_v2_digest: [5; 32],
        upstream_solver: ParticipantId([13; 32]),
        downstream_solver: ParticipantId([14; 32]),
        dom_chain_id: ChainId([1; 32]),
        upstream_binding: None,
        downstream_binding: None,
        upstream_wire: Some(wire([15; 32])),
        downstream_wire: Some(wire([16; 32])),
        upstream_rfq: Some(rfq(SettlementPositionV2::Upstream, [15; 32])),
        downstream_rfq: Some(rfq(SettlementPositionV2::Downstream, [16; 32])),
        authority_factory: Some(Box::new(AwaitingFactory {
            calls: Rc::clone(&calls),
            refuse: Rc::clone(&refuse),
        })),
        pending_authority_v25: None,
        upstream_ready: None,
        downstream_ready: None,
        upstream_active: false,
        downstream_active: false,
        runtime: None,
        poisoned: false,
    };
    (state, calls, refuse)
}

#[test]
fn awaiting_principal_retains_exact_factory_and_both_rfq_inputs_v25() {
    let (mut state, calls, _) = fixture();
    let original = (
        state.upstream_wire,
        state.downstream_wire,
        state.upstream_rfq,
        state.downstream_rfq,
    );
    for turn in 1..=4 {
        state.complete_pair_if_ready().unwrap();
        assert_eq!(calls.get(), turn);
        assert!(!state.poisoned);
        assert!(state.authority_factory.is_some());
        assert!(state.runtime.is_none());
        assert!(state.upstream_ready.is_none() && state.downstream_ready.is_none());
        assert_eq!(
            (
                state.upstream_wire,
                state.downstream_wire,
                state.upstream_rfq,
                state.downstream_rfq
            ),
            original
        );
        assert!(matches!(
            state.take_bound_authorities(SettlementPositionV2::Upstream),
            Err(ProductionF6ActivationRefusalV2::Awaiting(
                ProductionPendingAuthorityV1::AdapterTerms {
                    position: SettlementPositionV2::Downstream
                }
            ))
        ));
    }
}

#[test]
fn principal_binding_refusal_still_poisoned_and_never_treated_as_wait_v25() {
    let (mut state, calls, refuse) = fixture();
    state.complete_pair_if_ready().unwrap();
    refuse.set(true);
    assert!(matches!(
        state.complete_pair_if_ready(),
        Err(ProductionF6ActivationRefusalV2::InvalidBinding)
    ));
    assert!(state.poisoned);
    assert!(state.authority_factory.is_none());
    assert!(state.runtime.is_none());
    assert_eq!(calls.get(), 2);
}

#[test]
fn changed_rfq_while_waiting_is_refused_without_rebinding_factory_v25() {
    let (mut state, calls, _) = fixture();
    state.complete_pair_if_ready().unwrap();
    let mut changed = state.upstream_rfq.unwrap();
    changed.session_id = [42; 32];
    assert!(matches!(
        state.register(
            SettlementPositionV2::Upstream,
            state.upstream_wire.unwrap(),
            changed
        ),
        Err(ProductionF6ActivationRefusalV2::InvalidBinding)
    ));
    assert!(state.poisoned);
    assert_eq!(calls.get(), 1);
    assert!(state.runtime.is_none());
}
