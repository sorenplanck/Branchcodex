//! Tests the real router with instrumented child boundaries, not chain E2E.
#[path = "production_route_same_family_v22_tests.rs"]
mod same_family_v22_tests;
use super::*;
use crate::production_route_topology::ProductionLegTopologyV4;
use settlement_coordinator::ChildExposureV1;
use std::{cell::RefCell, rc::Rc};

const FACES: [SettlementFaceV1; 4] = [
    SettlementFaceV1::Bitcoin,
    SettlementFaceV1::Evm,
    SettlementFaceV1::Monero,
    SettlementFaceV1::Solana,
];
type Calls = Rc<RefCell<Vec<(u8, &'static str, SettlementLegV1, [u8; 32])>>>;

fn chain(face: SettlementFaceV1) -> [u8; 32] {
    [match face {
        SettlementFaceV1::Dom => 9,
        SettlementFaceV1::Evm => 10,
        SettlementFaceV1::Bitcoin => 11,
        SettlementFaceV1::Monero => 12,
        SettlementFaceV1::Solana => 13,
    }; 32]
}

fn topology(a: SettlementFaceV1, b: SettlementFaceV1) -> ProductionRouteTopologyV4 {
    ProductionRouteTopologyV4 {
        route_id: [1; 32],
        composition_digest: [2; 32],
        dom_chain_id: chain(SettlementFaceV1::Dom),
        terms_digest: [5; 32],
        registry_digest: [6; 32],
        dom_profile_digest: [50; 32],
        dom_deployment_digest: [51; 32],
        legs: [
            ProductionLegTopologyV4 {
                settlement_id: [31; 32],
                face: a,
                chain_id: chain(a),
                profile_digest: [40; 32],
                deployment_digest: [41; 32],
            },
            ProductionLegTopologyV4 {
                settlement_id: [32; 32],
                face: b,
                chain_id: chain(b),
                profile_digest: [42; 32],
                deployment_digest: [43; 32],
            },
        ],
    }
}

struct RecordingPort {
    face: SettlementFaceV1,
    id: u8,
    settlement: Option<[u8; 32]>,
    calls: Calls,
}
impl ProductionSettlementChildPortV1 for RecordingPort {
    fn face(&self) -> SettlementFaceV1 {
        self.face
    }
    fn settlement_id(&self) -> Option<[u8; 32]> {
        self.settlement
    }
    fn materialize(
        &mut self,
        r: ProductionChildMaterializationRequestV1,
        _: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        self.calls
            .borrow_mut()
            .push((self.id, "materialize", r.leg, r.settlement_id));
        Ok(SettlementChildPlanV1 {
            face: self.face,
            exposure: r.exposure,
            chain_id: chain(self.face),
            expected_transaction_id: [self.id; 32],
            intent_digest: r.semantic_digest,
            custody_digest: [self.id; 32],
        })
    }
    fn externalize(
        &mut self,
        r: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.calls
            .borrow_mut()
            .push((self.id, "externalize", r.leg(), r.settlement_id()));
        Err(ChildAuthorityRefusalV1::Unavailable)
    }
    fn reconcile(
        &mut self,
        r: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.calls.borrow_mut().push((
            self.id,
            "reconcile",
            r.dispatch.leg(),
            r.dispatch.settlement_id(),
        ));
        Err(ChildAuthorityRefusalV1::Unavailable)
    }
    fn observe(
        &mut self,
        r: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.calls
            .borrow_mut()
            .push((self.id, "observe", r.leg, r.settlement_id));
        Ok(ChildObservationOutcomeV1::Pending {
            evidence_digest: [self.id; 32],
        })
    }
}

fn port(
    face: SettlementFaceV1,
    id: u8,
    settlement: Option<[u8; 32]>,
    calls: &Calls,
) -> Box<dyn ProductionSettlementChildPortV1> {
    Box::new(RecordingPort {
        face,
        id,
        settlement,
        calls: Rc::clone(calls),
    })
}

fn router(
    a: SettlementFaceV1,
    b: SettlementFaceV1,
    calls: &Calls,
) -> ProductionSettlementChildRouterV1 {
    ProductionSettlementChildRouterV1::from_leg_ports_v4(
        topology(a, b),
        port(SettlementFaceV1::Dom, 90, None, calls),
        [
            port(a, 31, Some([31; 32]), calls),
            port(b, 32, Some([32; 32]), calls),
        ],
    )
    .expect("two independently bound ports")
}

fn request(leg: SettlementLegV1) -> ProductionChildMaterializationRequestV1 {
    ProductionChildMaterializationRequestV1 {
        route_id: [1; 32],
        effect_id: [3; 32],
        settlement_id: [if leg == SettlementLegV1::Upstream {
            31
        } else {
            32
        }; 32],
        leg,
        action: SettlementActionV1::Funding,
        fencing_epoch: 1,
        semantic_digest: [4; 32],
        terms_digest: [5; 32],
        registry_digest: [6; 32],
        profile_digest: [if leg == SettlementLegV1::Upstream {
            40
        } else {
            42
        }; 32],
        deployment_digest: [if leg == SettlementLegV1::Upstream {
            41
        } else {
            43
        }; 32],
        route_scope_digest: [14; 32],
        composition_digest: [2; 32],
        role_plan_digest: [15; 32],
        source_scope_digest: [16; 32],
        public_secret_evidence_digest: [0; 32],
        exposure: ChildExposureV1::NonSecret,
    }
}

fn observation(
    r: ProductionChildMaterializationRequestV1,
    face: SettlementFaceV1,
) -> ChildObservationRequestV1 {
    ChildObservationRequestV1 {
        plan_id: [20; 32],
        plan_digest: [21; 32],
        route_id: r.route_id,
        effect_id: r.effect_id,
        settlement_id: r.settlement_id,
        leg: r.leg,
        action: r.action,
        semantic_digest: r.semantic_digest,
        route_fencing_epoch: r.fencing_epoch,
        terms_digest: r.terms_digest,
        registry_digest: r.registry_digest,
        profile_digest: r.profile_digest,
        deployment_digest: r.deployment_digest,
        child_index: 0,
        face,
        exposure: r.exposure,
        chain_id: chain(face),
        transaction_id: [22; 32],
        intent_digest: [23; 32],
        custody_digest: [24; 32],
        prior_finality_evidence_digest: None,
        observation_attempt_id: [25; 32],
    }
}

#[test]
fn all_sixteen_pairs_keep_two_counterparties_and_dom_independent() {
    let mut pairs = 0;
    let mut route_traces = Vec::new();
    for a in FACES {
        for b in FACES {
            let calls = Calls::default();
            let mut router = router(a, b, &calls);
            let mut trace = Vec::new();
            // Interleave both directions, retries, refunds and observations. Even
            // same-chain/same-family requests must retain their settlement owner.
            for _ in 0..2 {
                for action in [SettlementActionV1::Funding, SettlementActionV1::Refund] {
                    for (leg, face, id) in [
                        (SettlementLegV1::Downstream, b, 32),
                        (SettlementLegV1::Upstream, a, 31),
                    ] {
                        let mut r = request(leg);
                        r.action = action;
                        let plan = router
                            .materialize_child(face, r, None)
                            .expect("counterparty");
                        assert_eq!(plan.custody_digest, [id; 32]);
                        assert_eq!(
                            calls.borrow().last(),
                            Some(&(id, "materialize", leg, [id; 32]))
                        );
                        trace.push(serde_json::json!({"phase": "materialize", "action": format!("{action:?}"),
                    "leg": format!("{leg:?}"), "requested_face": format!("{face:?}"),
                    "returned_face": format!("{:?}", plan.face), "owner": plan.custody_digest[0],
                    "settlement": r.settlement_id[0], "chain": plan.chain_id[0]}));
                        let observed = router
                            .observe_child(&observation(r, face))
                            .expect("observe");
                        assert_eq!(
                            observed,
                            ChildObservationOutcomeV1::Pending {
                                evidence_digest: [id; 32]
                            }
                        );
                        assert_eq!(calls.borrow().last(), Some(&(id, "observe", leg, [id; 32])));
                        let ChildObservationOutcomeV1::Pending { evidence_digest } = observed
                        else {
                            unreachable!("assertion above requires pending")
                        };
                        trace.push(
                            serde_json::json!({"phase": "observe", "action": format!("{action:?}"),
                    "leg": format!("{leg:?}"), "requested_face": format!("{face:?}"),
                    "returned_face": format!("{face:?}"), "owner": evidence_digest[0],
                    "settlement": r.settlement_id[0], "chain": chain(face)[0]}),
                        );
                        let mut dom_request = r;
                        dom_request.profile_digest = [50; 32];
                        dom_request.deployment_digest = [51; 32];
                        let dom = router
                            .materialize_child(SettlementFaceV1::Dom, dom_request, None)
                            .expect("DOM");
                        assert_eq!(dom.face, SettlementFaceV1::Dom);
                        assert_eq!(
                            calls.borrow().last(),
                            Some(&(90, "materialize", leg, [id; 32]))
                        );
                        trace.push(serde_json::json!({"phase": "materialize", "action": format!("{action:?}"),
                    "leg": format!("{leg:?}"), "requested_face": "Dom", "returned_face": format!("{:?}", dom.face),
                    "owner": dom.custody_digest[0], "settlement": r.settlement_id[0], "chain": dom.chain_id[0]}));
                    }
                }
            }
            assert_eq!(calls.borrow().len(), 24);
            route_traces.push(serde_json::json!({"upstream": format!("{a:?}"),
            "downstream": format!("{b:?}"), "trace": trace}));
            pairs += 1;
        }
    }
    assert_eq!(pairs, 16);
    if let Some(path) = std::env::var_os("DOM_INTEROP_V4_ROUTE_TRACE") {
        let artifact = serde_json::json!({"schema": "DOM-ROUTER-V4", "chain_e2e": false,
            "scope": "real-router-instrumented-children", "routes": route_traces});
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&artifact).expect("public trace JSON"),
        )
        .expect("export public routing trace");
    }
}

#[test]
fn transplanted_route_leg_settlement_and_face_never_reach_a_child() {
    for a in FACES {
        for b in FACES {
            let calls = Calls::default();
            let mut router = router(a, b, &calls);
            let valid = request(SettlementLegV1::Upstream);
            let mut mutations = [valid; 3];
            mutations[0].route_id = [99; 32];
            mutations[1].leg = SettlementLegV1::Downstream;
            mutations[2].settlement_id = [32; 32];
            for r in mutations {
                assert!(matches!(
                    router.materialize_child(a, r, None),
                    Err(ChildAuthorityRefusalV1::Conflict)
                ));
                assert!(matches!(
                    router.observe_child(&observation(r, a)),
                    Err(ChildAuthorityRefusalV1::Conflict)
                ));
                assert!(router
                    .materialize_child(SettlementFaceV1::Dom, r, None)
                    .is_err());
            }
            for wrong in FACES.into_iter().filter(|face| *face != a) {
                assert!(router.materialize_child(wrong, valid, None).is_err());
                assert!(router.observe_child(&observation(valid, wrong)).is_err());
            }
            let mut scopes = [valid; 5];
            scopes[0].composition_digest = [99; 32];
            scopes[1].profile_digest = [99; 32];
            scopes[2].deployment_digest = [99; 32];
            scopes[3].terms_digest = [99; 32];
            scopes[4].registry_digest = [99; 32];
            for r in scopes {
                assert!(router.materialize_child(a, r, None).is_err());
            }
            let mut wrong_chain = observation(valid, a);
            wrong_chain.chain_id = [99; 32];
            assert!(router.observe_child(&wrong_chain).is_err());
            assert!(calls.borrow().is_empty());
        }
    }
}

#[test]
fn same_family_constructor_refuses_reversed_or_unbound_owners() {
    for face in FACES {
        let calls = Calls::default();
        for (first, second) in [
            (Some([32; 32]), Some([31; 32])),
            (None, Some([32; 32])),
            (Some([31; 32]), Some([31; 32])),
        ] {
            assert!(ProductionSettlementChildRouterV1::from_leg_ports_v4(
                topology(face, face),
                port(SettlementFaceV1::Dom, 90, None, &calls),
                [
                    port(face, 31, first, &calls),
                    port(face, 32, second, &calls)
                ]
            )
            .is_err());
        }
        assert!(calls.borrow().is_empty());
    }
}

#[test]
fn topology_refuses_ambiguous_or_missing_dom_and_settlement_identities() {
    let base = || topology(SettlementFaceV1::Bitcoin, SettlementFaceV1::Evm);
    let mut cases = [base(), base(), base(), base(), base(), base()];
    cases[0].dom_chain_id = [0; 32];
    cases[1].legs[1].settlement_id = cases[1].legs[0].settlement_id;
    cases[2].legs[0].chain_id = cases[2].dom_chain_id;
    cases[3].legs[1].chain_id = cases[3].legs[0].chain_id;
    cases[4].legs[0].face = SettlementFaceV1::Dom;
    cases[5].legs[1].deployment_digest = [0; 32];
    for case in cases {
        assert!(case.validate().is_err());
    }
}

#[test]
fn bitcoin_handoff_cannot_cross_same_family_leg_or_composition() {
    let calls = Calls::default();
    let mut router = router(SettlementFaceV1::Bitcoin, SettlementFaceV1::Bitcoin, &calls);
    let expected = ProductionBitcoinExtractionHandoffScopeV1 {
        route_id: [1; 32],
        composition_digest: [2; 32],
        chain_id: chain(SettlementFaceV1::Bitcoin),
        expected_txid: None,
        leg: SettlementLegV1::Upstream,
        settlement_id: [31; 32],
    };
    let mut cases = [expected; 4];
    cases[0].leg = SettlementLegV1::Downstream;
    cases[1].settlement_id = [32; 32];
    cases[2].composition_digest = [99; 32];
    cases[3].chain_id = chain(SettlementFaceV1::Evm);
    for case in cases {
        assert!(matches!(
            router.take_bitcoin_public_extraction_handoff(case),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
    }
}

struct TestPlanAuthority;
impl settlement_coordinator::SettlementPlanAuthorityV1 for TestPlanAuthority {
    fn authorize_plan(
        &mut self,
        request: settlement_coordinator::PlanAuthorizationRequestV1<'_>,
    ) -> Result<
        settlement_coordinator::PlanAuthorizationV1,
        settlement_coordinator::PlanAuthorityRefusalV1,
    > {
        settlement_coordinator::PlanAuthorizationV1::new(
            [0xA1; 32],
            request.plan_digest(),
            [0xA2; 32],
            20_000,
        )
        .map_err(|_| settlement_coordinator::PlanAuthorityRefusalV1::Refused)
    }
}

#[test]
fn coordinator_reopen_reconciles_the_original_leg_for_all_sixteen_pairs(
) -> Result<(), Box<dyn std::error::Error>> {
    use settlement_coordinator::{
        CompositeSettlementPlanV1, DurableSettlementCoordinatorV1, SecretRequirementV1,
        SettlementPlanBindingsV1,
    };
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    let mut case = 0;
    for a in FACES {
        for b in FACES {
            for (leg, face, id) in [
                (SettlementLegV1::Upstream, a, 31),
                (SettlementLegV1::Downstream, b, 32),
            ] {
                let calls = Calls::default();
                let mut child_router = router(a, b, &calls);
                let r = request(leg);
                let child = child_router.materialize_child(face, r, None)?;
                let mut dom_request = r;
                dom_request.semantic_digest = [90; 32];
                dom_request.profile_digest = [50; 32];
                dom_request.deployment_digest = [51; 32];
                let dom =
                    child_router.materialize_child(SettlementFaceV1::Dom, dom_request, None)?;
                let plan = CompositeSettlementPlanV1::new(
                    SettlementPlanBindingsV1 {
                        route_id: r.route_id,
                        effect_id: r.effect_id,
                        settlement_id: r.settlement_id,
                        leg,
                        action: r.action,
                        fencing_epoch: r.fencing_epoch,
                        semantic_digest: r.semantic_digest,
                        terms_digest: r.terms_digest,
                        registry_digest: r.registry_digest,
                        dom_profile_digest: [50; 32],
                        dom_deployment_digest: [51; 32],
                        counterparty_profile_digest: r.profile_digest,
                        counterparty_deployment_digest: r.deployment_digest,
                    },
                    SecretRequirementV1::None,
                    None,
                    [child, dom],
                )?;
                let path = temporary.path().join(format!("coordinator-{case}.sqlite"));
                let mut coordinator =
                    DurableSettlementCoordinatorV1::create(&path, [0xB1; 32], [0xA1; 32], 10_000)?;
                let view = coordinator.install_plan(&mut TestPlanAuthority, plan, 10_001)?;
                let lease = coordinator
                    .acquire_lease(view.plan_id, [0xC5; 32], 1, 10_002, 1_000)?
                    .lease();
                let pending = coordinator.prepare_next_child_call(lease, 10_003)?;
                let attempt = pending.request().attempt_id();
                assert!(matches!(
                    child_router.externalize_child(pending.request()),
                    Err(ChildAuthorityRefusalV1::Unavailable)
                ));
                assert_eq!(
                    calls.borrow().last(),
                    Some(&(id, "externalize", leg, [id; 32]))
                );
                // Simulate process loss after persisted dispatch. Reopen the real
                // SQLite coordinator and a fresh router; no raw dispatch is forged.
                drop(pending);
                drop(coordinator);
                drop(child_router);
                let mut coordinator =
                    DurableSettlementCoordinatorV1::open_existing(&path, [0xB1; 32], [0xA1; 32])?;
                let mut child_router = router(a, b, &calls);
                let reconciliation = coordinator.prepare_current_reconciliation(lease, 10_004)?;
                assert_eq!(reconciliation.request().dispatch.attempt_id(), attempt);
                assert!(matches!(
                    child_router.reconcile_child(reconciliation.request()),
                    Err(ChildAuthorityRefusalV1::Unavailable)
                ));
                assert_eq!(
                    calls.borrow().last(),
                    Some(&(id, "reconcile", leg, [id; 32]))
                );
                // Another route must refuse the retained request before a new
                // child boundary is touched, even if both families are identical.
                let before = calls.borrow().len();
                let mut wrong = topology(a, b);
                wrong.route_id = [99; 32];
                let mut wrong_router = ProductionSettlementChildRouterV1::from_leg_ports_v4(
                    wrong,
                    port(SettlementFaceV1::Dom, 90, None, &calls),
                    [
                        port(a, 31, Some([31; 32]), &calls),
                        port(b, 32, Some([32; 32]), &calls),
                    ],
                )?;
                assert!(matches!(
                    wrong_router.reconcile_child(reconciliation.request()),
                    Err(ChildAuthorityRefusalV1::Conflict)
                ));
                assert_eq!(calls.borrow().len(), before);
                case += 1;
            }
        }
    }
    assert_eq!(case, 32);
    Ok(())
}
