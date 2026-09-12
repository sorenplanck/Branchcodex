//! Public progress correlation, never a signing/settlement authority. Live
//! reads are read-only; complete native journal replay requires a stopped owner.
use super::*;
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionPathRoleV1,
    ProductionRoutePinsV1, PRODUCTION_CREATE_CONFIG_FILE_V11,
};
use route_executor::{ActionKindV1, ActionStateV1};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use settlement_coordinator::{
    CanonicalSettlementPlanV1, ChildStageV1, CompositeSettlementPlanV1,
    DurableSettlementCoordinatorV1, SettlementActionV1, SettlementFaceV1, SettlementLegV1,
};
use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(super) struct CoordinatorObserverV23 {
    path: PathBuf,
    pins: ProductionRoutePinsV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeActionV23 {
    pub aggregate_id: [u8; 32],
    pub xmr_id: [u8; 32],
    pub dom_id: [u8; 32],
    pub xmr_dispatched: bool,
    pub xmr_externalized: bool,
    pub xmr_final: bool,
}

impl NativeActionV23 {
    pub(super) fn matches_xmr(&self, raw_hash: [u8; 32]) -> bool {
        raw_hash != [0; 32] && self.xmr_id == xmr_child_identity(raw_hash)
    }
}

pub(super) fn xmr_child_identity(raw_hash: [u8; 32]) -> [u8; 32] {
    // Independent observer of the existing ProductionXmrChildPortV1 encoding:
    // domain || u64_be(32) || raw tx hash. Do not change producer identities.
    let mut bytes = b"DOM-INTEROP/INTEROPD/XMR-CHILD/TRANSACTION-ID/V1\0".to_vec();
    bytes.extend_from_slice(&32u64.to_be_bytes());
    bytes.extend_from_slice(&raw_hash);
    *dom_crypto::blake2b_256(&bytes).as_bytes()
}

impl CoordinatorObserverV23 {
    pub(super) fn new(state: &Path) -> Result<Self> {
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

    pub(super) fn poll(
        &self,
        snapshot: &RouteSnapshotV1,
        leg: LegIdV1,
        kind: ActionKindV1,
    ) -> Result<Option<NativeActionV23>> {
        let state = snapshot.leg(leg).action(kind);
        let Some(effect) = state.effect() else {
            return Ok(None);
        };
        let held = observer::owned_file(&self.path)?;
        let before = held.metadata()?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(500))?;
        let after = std::fs::symlink_metadata(&self.path)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("coordinator inode changed".into());
        }
        let transaction = connection.unchecked_transaction()?;
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = transaction.query_row(
            "SELECT plan_id,plan_bytes,plan_digest,aggregate_action_id FROM settlement_plans WHERE route_id=?1 AND effect_id=?2",
            [snapshot.route_id.as_slice(), effect.effect_id.as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional()?;
        let Some((plan_id, bytes, digest, aggregate)) = row else {
            return Ok(None);
        };
        if bytes.len() > 4096 {
            return Err("coordinator canonical plan bound".into());
        }
        let plan = CompositeSettlementPlanV1::decode_canonical(&bytes)?;
        let aggregate = digest32(aggregate)?;
        if plan.canonical_digest()? != digest32(digest)? {
            return Err("coordinator plan digest mismatch".into());
        }
        self.require_plan(snapshot, leg, kind, state, &plan, aggregate)?;
        let mut statement = transaction.prepare(
            "SELECT child_index,face_tag,expected_tx_id,stage_tag,externalization_evidence,finality_evidence,chain_id,exposure_tag,pending_attempt_id,pending_call_digest FROM settlement_children WHERE plan_id=?1 ORDER BY child_index LIMIT 3")?;
        let rows = statement.query_map([plan_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, u8>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u8>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, u8>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        })?;
        let mut xmr = None;
        let mut dom = None;
        let mut count = 0;
        for row in rows {
            let (index, face, id, stage, external, finality, chain, exposure, attempt, call) = row?;
            if index != count || !(0..2).contains(&index) || !(1..=5).contains(&stage) {
                return Err("coordinator child cardinality/stage".into());
            }
            let index = usize::try_from(index)
                .map_err(|_| "coordinator child index outside canonical range")?;
            let id = digest32(id)?;
            let chain = digest32(chain)?;
            let exposure = match exposure {
                1 => settlement_coordinator::ChildExposureV1::NonSecret,
                2 => settlement_coordinator::ChildExposureV1::FirstSecretExposure,
                3 => settlement_coordinator::ChildExposureV1::UsesPublicSecret,
                _ => return Err("coordinator child exposure tag".into()),
            };
            let face = match face {
                1 => SettlementFaceV1::Dom,
                4 => SettlementFaceV1::Monero,
                _ => return Err("scenario coordinator family mismatch".into()),
            };
            if let Some(child) = plan.materialized_child(index) {
                if child.face != face
                    || child.expected_transaction_id != id
                    || child.chain_id != chain
                    || child.exposure != exposure
                {
                    return Err("coordinator child differs from canonical plan".into());
                }
            } else {
                let settlement_coordinator::SettlementChildrenV1::FirstExposureStaged {
                    deferred,
                    ..
                } = plan.child_layout()
                else {
                    return Err("missing canonical child".into());
                };
                if index != 1
                    || deferred.face != face
                    || deferred.chain_id != chain
                    || exposure != settlement_coordinator::ChildExposureV1::UsesPublicSecret
                {
                    return Err("deferred coordinator family mismatch".into());
                }
            }
            if (stage >= 3 && external.map(digest32).transpose()?.is_none())
                || (stage == 4 && finality.map(digest32).transpose()?.is_none())
                || (stage == 2
                    && (attempt.map(digest32).transpose()?.is_none()
                        || call.map(digest32).transpose()?.is_none()))
            {
                return Err("coordinator child evidence absent".into());
            }
            match face {
                SettlementFaceV1::Monero => {
                    if xmr
                        .replace((id, stage >= 2, stage >= 3, stage == 4))
                        .is_some()
                    {
                        return Err("duplicate XMR child".into());
                    }
                }
                SettlementFaceV1::Dom => {
                    if dom.replace(id).is_some() {
                        return Err("duplicate DOM child".into());
                    }
                }
                _ => unreachable!(),
            }
            count += 1;
        }
        // A staged claim may legitimately not have its second child yet.
        if count != 2 {
            return Ok(None);
        }
        let (xmr_id, xmr_dispatched, xmr_externalized, xmr_final) =
            xmr.ok_or("XMR child absent")?;
        Ok(Some(NativeActionV23 {
            aggregate_id: aggregate,
            xmr_id,
            dom_id: dom.ok_or("DOM child absent")?,
            xmr_externalized,
            xmr_dispatched,
            xmr_final,
        }))
    }

    pub(super) fn replay_stopped(
        &self,
        snapshot: &RouteSnapshotV1,
        leg: LegIdV1,
        kind: ActionKindV1,
    ) -> Result<Option<NativeActionV23>> {
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
        self.require_plan(
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
        let xmr = view
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Monero)
            .ok_or("replayed XMR child absent")?;
        let dom = view
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Dom)
            .ok_or("replayed DOM child absent")?;
        let (Some(xmr_id), Some(dom_id)) = (xmr.transaction_id, dom.transaction_id) else {
            return Ok(None);
        };
        Ok(Some(NativeActionV23 {
            aggregate_id: view.aggregate_action_id,
            xmr_id,
            dom_id,
            xmr_dispatched: !matches!(xmr.stage, ChildStageV1::Planned | ChildStageV1::Deferred),
            xmr_externalized: matches!(
                xmr.stage,
                ChildStageV1::Externalized
                    | ChildStageV1::Final
                    | ChildStageV1::FinalityInvalidated
            ),
            xmr_final: xmr.stage == ChildStageV1::Final,
        }))
    }

    fn require_plan(
        &self,
        snapshot: &RouteSnapshotV1,
        leg: LegIdV1,
        kind: ActionKindV1,
        state: &ActionStateV1,
        plan: &CompositeSettlementPlanV1,
        aggregate: [u8; 32],
    ) -> Result<()> {
        require_action_binding(
            self.pins.route_id,
            snapshot,
            leg,
            kind,
            state,
            plan,
            aggregate,
        )
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

fn digest32(bytes: Vec<u8>) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "coordinator identity length")?;
    if bytes == [0; 32] {
        return Err("zero coordinator identity".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use route_executor::{EffectReferenceV1, FrozenBindingsV1};
    use settlement_coordinator::{
        ChildExposureV1, SecretRequirementV1, SettlementChildPlanV1, SettlementPlanBindingsV1,
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
                    SettlementFaceV1::Monero,
                    15,
                    xmr_child_identity([16; 32]),
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
    fn raw_native_hash_domain_child_and_route_aggregate_are_distinct() {
        let raw = [7; 32];
        let action = NativeActionV23 {
            aggregate_id: [9; 32],
            xmr_id: xmr_child_identity(raw),
            dom_id: [10; 32],
            xmr_dispatched: true,
            xmr_externalized: false,
            xmr_final: false,
        };
        assert!(action.matches_xmr(raw));
        assert!(!action.matches_xmr(action.xmr_id));
        assert!(!action.matches_xmr(action.aggregate_id));
        assert!(!action.matches_xmr([0; 32]));
        // Public wire vector, independently fed through the variable-output
        // Blake2 primitive rather than the production domain digest wrapper.
        use blake2::{
            digest::{Update, VariableOutput},
            Blake2bVar,
        };
        let mut hash = Blake2bVar::new(32).unwrap();
        hash.update(b"DOM-INTEROP/INTEROPD/XMR-CHILD/TRANSACTION-ID/V1\0");
        hash.update(&[0, 0, 0, 0, 0, 0, 0, 32]);
        hash.update(&[7; 32]);
        let mut expected = [0; 32];
        hash.finalize_variable(&mut expected).unwrap();
        assert_eq!(action.xmr_id, expected);
    }

    #[test]
    fn canonical_plan_must_match_exact_route_effect_leg_action_and_aggregate() -> Result<()> {
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
        let mut wrong = snapshot.clone();
        let ActionStateV1::Committed(effect) = &mut wrong.upstream.funding else {
            unreachable!()
        };
        effect.fencing_epoch += 1;
        assert!(require_action_binding(
            [1; 32],
            &wrong,
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &wrong.upstream.funding,
            &decoded,
            [22; 32]
        )
        .is_err());
        Ok(())
    }
}
