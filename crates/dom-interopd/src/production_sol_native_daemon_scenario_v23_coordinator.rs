//! Public progress correlation for DOM↔SOL aggregate actions, never a signing
//! or settlement authority. Complete journal replay requires a stopped owner.
use super::*;
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionPathRoleV1,
    ProductionRoutePinsV1, PRODUCTION_CREATE_CONFIG_FILE_V11,
};
use route_executor::ActionStateV1;
use settlement_coordinator::{
    ChildStageV1, CompositeSettlementPlanV1, DurableSettlementCoordinatorV1, SettlementActionV1,
    SettlementFaceV1, SettlementLegV1,
};
// `matches_signature` is exercised by the unit vector below; the claim
// scenario correlates by aggregate identity and replayed child finality.
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub(in super::super) struct CoordinatorObserverV23 {
    path: PathBuf,
    pins: ProductionRoutePinsV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct NativeSolActionV23 {
    pub aggregate_id: [u8; 32],
    pub sol_id: [u8; 32],
    pub dom_id: [u8; 32],
    pub sol_final: bool,
}

impl NativeSolActionV23 {
    /// True only for the coordinator identity of this exact retained signature.
    pub(in super::super) fn matches_signature(&self, signature: [u8; 64]) -> bool {
        signature != [0; 64] && self.sol_id == sol_child_identity(signature)
    }
}

/// Independent observer of `production_child_solana::transaction_id_v1`:
/// domain || u64_be(64) || signature. Do not change producer identities.
pub(super) fn sol_child_identity(signature: [u8; 64]) -> [u8; 32] {
    let mut bytes = b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/TRANSACTION-ID/V1\0".to_vec();
    bytes.extend_from_slice(&64u64.to_be_bytes());
    bytes.extend_from_slice(&signature);
    *dom_crypto::blake2b_256(&bytes).as_bytes()
}

impl CoordinatorObserverV23 {
    pub(in super::super) fn new(state: &Path) -> Result<Self> {
        let file = observer::owned_file(&state.join(PRODUCTION_CREATE_CONFIG_FILE_V11))?;
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("coordinator manifest bound".into());
        }
        let config = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &bytes,
            ProductionBootstrapModeV1::Create,
        )?;
        Ok(Self {
            path: state.join(config.relative_path(ProductionPathRoleV1::CoordinatorStore)),
            pins: config.pins(),
        })
    }

    pub(super) fn replay_stopped(
        &self,
        snapshot: &RouteSnapshotV1,
        leg: LegIdV1,
        kind: ActionKindV1,
    ) -> Result<Option<NativeSolActionV23>> {
        let state = snapshot.leg(leg).action(kind);
        let Some(effect) = state.effect() else {
            return Ok(None);
        };
        let store = DurableSettlementCoordinatorV1::open_existing(
            &self.path,
            self.pins.coordinator_id,
            self.pins.coordinator_plan_authority_id,
        )?;
        let stored = store.load_plan_for_effect(effect.effect_id)?;
        let view = stored.view();
        require_action_binding(
            self.pins.route_id,
            snapshot,
            leg,
            kind,
            state,
            stored.plan(),
            view.aggregate_action_id,
        )?;
        if state.progress() == ActionProgressV1::Final
            && view.stage != settlement_coordinator::AggregateStageV1::Final
        {
            return Err("final route action lacks authenticated coordinator finality".into());
        }
        if view.children.iter().any(|child| {
            !matches!(child.face, SettlementFaceV1::Dom | SettlementFaceV1::Solana)
        }) {
            return Err("scenario coordinator family mismatch".into());
        }
        let sol = view
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Solana)
            .ok_or("replayed SOL child absent")?;
        let dom = view
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Dom)
            .ok_or("replayed DOM child absent")?;
        let (Some(sol_id), Some(dom_id)) = (sol.transaction_id, dom.transaction_id) else {
            return Ok(None);
        };
        Ok(Some(NativeSolActionV23 {
            aggregate_id: view.aggregate_action_id,
            sol_id,
            dom_id,
            sol_final: sol.stage == ChildStageV1::Final,
        }))
    }
}

fn require_action_binding(
    route_id: [u8; 32],
    snapshot: &RouteSnapshotV1,
    leg: LegIdV1,
    kind: ActionKindV1,
    state: &ActionStateV1,
    plan: &CompositeSettlementPlanV1,
    aggregate: [u8; 32],
) -> Result<()> {
    let bindings = plan.bindings();
    let effect = state.effect().ok_or("coordinator effect absent")?;
    let expected_leg = match leg {
        LegIdV1::Upstream => SettlementLegV1::Upstream,
        LegIdV1::Downstream => SettlementLegV1::Downstream,
    };
    let expected_action = match kind {
        ActionKindV1::Funding => SettlementActionV1::Funding,
        ActionKindV1::Claim => SettlementActionV1::Claim,
        ActionKindV1::Refund => SettlementActionV1::Refund,
    };
    if snapshot.route_id != route_id
        || bindings.route_id != snapshot.route_id
        || bindings.effect_id != effect.effect_id
        || bindings.fencing_epoch != effect.fencing_epoch
        || bindings.semantic_digest != effect.semantic_digest
        || bindings.leg != expected_leg
        || bindings.action != expected_action
        || effect.expected_transaction_id != Some(aggregate)
        || state.transaction_id().is_some_and(|id| id != aggregate)
        || snapshot
            .bindings
            .as_ref()
            .is_none_or(|frozen| frozen.terms_digest != bindings.terms_digest)
    {
        return Err("coordinator plan is not the exact durable route action".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use route_executor::{EffectReferenceV1, FrozenBindingsV1};
    use settlement_coordinator::{
        CanonicalSettlementPlanV1, ChildExposureV1, SecretRequirementV1, SettlementChildPlanV1,
        SettlementPlanBindingsV1,
    };

    fn fixture() -> Result<(RouteSnapshotV1, CompositeSettlementPlanV1)> {
        let bindings = SettlementPlanBindingsV1 {
            route_id: [1; 32],
            effect_id: [2; 32],
            settlement_id: [3; 32],
            leg: SettlementLegV1::Upstream,
            action: SettlementActionV1::Funding,
            fencing_epoch: 1,
            semantic_digest: [4; 32],
            terms_digest: [5; 32],
            registry_digest: [6; 32],
            dom_profile_digest: [7; 32],
            dom_deployment_digest: [8; 32],
            counterparty_profile_digest: [9; 32],
            counterparty_deployment_digest: [10; 32],
        };
        let child = |face, chain, tx, salt| SettlementChildPlanV1 {
            face,
            exposure: ChildExposureV1::NonSecret,
            chain_id: [chain; 32],
            expected_transaction_id: tx,
            intent_digest: [salt; 32],
            custody_digest: [salt + 1; 32],
        };
        let plan = CompositeSettlementPlanV1::new(
            bindings,
            SecretRequirementV1::None,
            None,
            [
                child(SettlementFaceV1::Dom, 11, [12; 32], 13),
                child(
                    SettlementFaceV1::Solana,
                    15,
                    sol_child_identity([16; 64]),
                    17,
                ),
            ],
        )?;
        let mut snapshot = RouteSnapshotV1::new([1; 32])?;
        snapshot.bindings = Some(FrozenBindingsV1 {
            terms_digest: [5; 32],
            profile_bundle_digest: [20; 32],
            deployment_bundle_digest: [21; 32],
        });
        snapshot.upstream.funding = ActionStateV1::Committed(EffectReferenceV1 {
            effect_id: [2; 32],
            fencing_epoch: 1,
            semantic_digest: [4; 32],
            contains_route_secret: false,
            expected_transaction_id: Some([22; 32]),
        });
        Ok((snapshot, plan))
    }

    #[test]
    fn sol_signature_identity_is_the_length_prefixed_child_digest_v25() {
        use blake2::{
            digest::{Update, VariableOutput},
            Blake2bVar,
        };
        let signature = [7; 64];
        let action = NativeSolActionV23 {
            aggregate_id: [9; 32],
            sol_id: sol_child_identity(signature),
            dom_id: [10; 32],
            sol_final: false,
        };
        assert!(action.matches_signature(signature));
        assert!(!action.matches_signature([0; 64]));
        assert!(!action.matches_signature([8; 64]));
        let mut hash = Blake2bVar::new(32).unwrap();
        hash.update(b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/TRANSACTION-ID/V1\0");
        hash.update(&[0, 0, 0, 0, 0, 0, 0, 64]);
        hash.update(&[7; 64]);
        let mut expected = [0; 32];
        hash.finalize_variable(&mut expected).unwrap();
        assert_eq!(action.sol_id, expected);
    }

    #[test]
    fn canonical_sol_plan_must_match_exact_route_effect_leg_action_and_aggregate() -> Result<()> {
        let (snapshot, plan) = fixture()?;
        let decoded = CompositeSettlementPlanV1::decode_canonical(&plan.encode_canonical()?)?;
        let state = &snapshot.upstream.funding;
        assert!(require_action_binding(
            [1; 32],
            &snapshot,
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            state,
            &decoded,
            [22; 32]
        )
        .is_ok());
        for (route, leg, action, aggregate) in [
            ([2; 32], LegIdV1::Upstream, ActionKindV1::Funding, [22; 32]),
            (
                [1; 32],
                LegIdV1::Downstream,
                ActionKindV1::Funding,
                [22; 32],
            ),
            ([1; 32], LegIdV1::Upstream, ActionKindV1::Refund, [22; 32]),
            ([1; 32], LegIdV1::Upstream, ActionKindV1::Funding, [16; 32]),
        ] {
            assert!(require_action_binding(
                route, &snapshot, leg, action, state, &decoded, aggregate
            )
            .is_err());
        }
        Ok(())
    }
}
