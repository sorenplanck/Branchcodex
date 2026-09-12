//! Same-family routing regressions adapted from the supplied three-test excerpt.
//! Instrumented child ports return Pending: these are not chain-finality,
//! executed-refund, or persistent crash-recovery tests.

use super::*;

#[test]
fn same_family_claim_and_pending_observation_keep_the_position_owner() {
    for face in FACES {
        let calls = Calls::default();
        let mut router = router(face, face, &calls);
        for (leg, id) in [
            (SettlementLegV1::Upstream, 31),
            (SettlementLegV1::Downstream, 32),
        ] {
            let mut r = request(leg);
            r.action = SettlementActionV1::Claim;
            let plan = router.materialize_child(face, r, None).expect("claim plan");
            assert_eq!(plan.custody_digest, [id; 32], "{face:?} {leg:?}");
            let mut observed = observation(r, face);
            observed.custody_digest = [id; 32];
            assert_eq!(
                router.observe_child(&observed).expect("observe"),
                ChildObservationOutcomeV1::Pending {
                    evidence_digest: [id; 32]
                }
            );
        }
        assert_eq!(
            *calls.borrow(),
            vec![
                (31, "materialize", SettlementLegV1::Upstream, [31; 32]),
                (31, "observe", SettlementLegV1::Upstream, [31; 32]),
                (32, "materialize", SettlementLegV1::Downstream, [32; 32]),
                (32, "observe", SettlementLegV1::Downstream, [32; 32]),
            ],
            "no extra or cross-position calls for {face:?}"
        );
    }
}

#[test]
fn same_family_refund_plan_leaves_the_other_claim_owner_untouched() {
    for face in FACES {
        let calls = Calls::default();
        let mut router = router(face, face, &calls);
        let mut refund = request(SettlementLegV1::Upstream);
        refund.action = SettlementActionV1::Refund;
        let plan = router
            .materialize_child(face, refund, None)
            .expect("upstream refund plan");
        assert_eq!(plan.custody_digest, [31; 32]);
        assert_eq!(
            *calls.borrow(),
            vec![(31, "materialize", SettlementLegV1::Upstream, [31; 32])]
        );
        let mut claim = request(SettlementLegV1::Downstream);
        claim.action = SettlementActionV1::Claim;
        let plan = router
            .materialize_child(face, claim, None)
            .expect("downstream claim plan");
        assert_eq!(plan.custody_digest, [32; 32], "{face:?}");
        assert_eq!(
            *calls.borrow(),
            vec![
                (31, "materialize", SettlementLegV1::Upstream, [31; 32]),
                (32, "materialize", SettlementLegV1::Downstream, [32; 32]),
            ]
        );
    }
}

#[test]
fn reconstructing_a_same_family_router_preserves_both_position_owners() {
    for face in FACES {
        let before = {
            let calls = Calls::default();
            let mut router = router(face, face, &calls);
            [SettlementLegV1::Upstream, SettlementLegV1::Downstream].map(|leg| {
                router
                    .materialize_child(face, request(leg), None)
                    .expect("first router")
                    .custody_digest
            })
        };
        assert_eq!(before, [[31; 32], [32; 32]]);
        let calls = Calls::default();
        let mut router = router(face, face, &calls);
        for (index, leg) in [SettlementLegV1::Upstream, SettlementLegV1::Downstream]
            .into_iter()
            .enumerate()
        {
            let plan = router
                .materialize_child(face, request(leg), None)
                .expect("reconstructed router");
            assert_eq!(plan.custody_digest, before[index], "{face:?} {leg:?}");
        }
        assert_eq!(
            *calls.borrow(),
            vec![
                (31, "materialize", SettlementLegV1::Upstream, [31; 32]),
                (32, "materialize", SettlementLegV1::Downstream, [32; 32]),
            ]
        );
    }
}
