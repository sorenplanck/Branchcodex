//! Resolve the crash cut: one native deposit is final while the aggregate
//! route action remains Committed. A pending call alone proves nothing.
use super::*;
use f7_anchor_authority::families_v11::{F7FundingIdV11, VerifiedXmrFundingV11};
use route_executor::{ActionStateV1, EffectReferenceV1};
use settlement_coordinator::{
    AggregateStageV1, ChildExposureV1, ChildStageV1, DurableSettlementCoordinatorV1,
    SettlementActionV1, SettlementFaceV1, SettlementLegV1, StoredSettlementPlanV1,
};

/// A candidate is only a request to perform real native verification. It is
/// neither a funding observation nor permission to open historical F6.
pub(crate) struct HistoricalXmrFundingCandidateV24 {
    leg: LegIdV1,
    effect: EffectReferenceV1,
    stored: StoredSettlementPlanV1,
}

#[derive(Clone)]
pub(super) struct NativeCommittedFundingV24 {
    leg: LegIdV1,
    effect: EffectReferenceV1,
    // This commitment includes the verified exact output index (the native
    // verifier hashes it), tx/setup, canonical block and observation scope.
    // Never serialize this capability or turn it into a funding grant.
    evidence_digest: Digest32,
}

impl NativeCommittedFundingV24 {
    pub(super) fn matches(&self, snapshot: &RouteSnapshotV1) -> bool {
        !snapshot.aborted_unfunded
            && self.evidence_digest != ZERO_DIGEST
            && matches!(&snapshot.leg(self.leg).funding,
                ActionStateV1::Committed(effect) if effect == &self.effect)
    }
}

impl AuthenticatedProductionInputsV1 {
    pub(crate) fn historical_xmr_funding_candidate_v24(
        &self,
        coordinator: &DurableSettlementCoordinatorV1,
        leg: LegIdV1,
    ) -> Result<Option<HistoricalXmrFundingCandidateV24>, ProductionInputErrorV1> {
        let snapshot = self.audited_recovery_snapshot_v24()?;
        if snapshot.aborted_unfunded
            || (snapshot.health != HealthStateV1::RecoveryOnly
                && self.current_time_ancestry_ready())
            || self.monero_session(leg).is_none()
        {
            return Ok(None);
        }
        let ActionStateV1::Committed(effect) = &snapshot.leg(leg).funding else {
            return Ok(None);
        };
        // This is the coordinator's complete canonical journal/call replay,
        // not an unchecked SQLite projection or a scenario-shaped snapshot.
        let stored = coordinator
            .load_plan_for_effect(effect.effect_id)
            .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?;
        require_native_plan(self, &snapshot, leg, effect, &stored)?;
        let child = stored
            .view()
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Monero)
            .ok_or(ProductionInputErrorV1::RouteStateRefused)?;
        if matches!(child.stage, ChildStageV1::Planned | ChildStageV1::Deferred) {
            return Ok(None);
        }
        Ok(Some(HistoricalXmrFundingCandidateV24 {
            leg,
            effect: effect.clone(),
            stored,
        }))
    }
}

impl HistoricalXmrFundingCandidateV24 {
    /// Consume fresh evidence minted only by verify_xmr_funding_v11, then
    /// re-audit both durable owners. Neither facts nor a pending call can mint
    /// this exit-only capability through a public constructor.
    pub(crate) fn authenticate(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        coordinator: &DurableSettlementCoordinatorV1,
        funding: VerifiedXmrFundingV11,
    ) -> Result<HistoricalF6RecoveryV24, ProductionInputErrorV1> {
        let error = || ProductionInputErrorV1::RouteStateRefused;
        let current = inputs
            .historical_xmr_funding_candidate_v24(coordinator, self.leg)?
            .ok_or_else(error)?;
        if current.effect != self.effect || current.stored != self.stored {
            return Err(error());
        }
        let session = inputs.monero_session(self.leg).ok_or_else(error)?;
        let setup = session.setup();
        if funding.funding_id() != &F7FundingIdV11::Hash32(setup.funding_tx_hash())
            || funding.setup_binding_hash() != &setup.binding_hash()
            || funding.facts().settlement_id() != &setup.settlement_id()
            || funding.facts().terms_hash() != &setup.terms_hash()
            || funding.facts().chain_registry_id() != &session.deployment().profile().chain_id.0
            || funding.block_height() == 0
            || funding.block_hash() == &ZERO_DIGEST
            || funding.evidence_digest() == &ZERO_DIGEST
            || funding.confirmations()
                < match self.leg {
                    LegIdV1::Upstream => inputs.composition.upstream(),
                    LegIdV1::Downstream => inputs.composition.downstream(),
                }
                .counterparty_leg
                .finality
                .min_confirmations
            || funding.facts().age() > std::time::Duration::from_secs(60)
        {
            return Err(error());
        }
        Ok(HistoricalF6RecoveryV24 {
            route_id: inputs.admission.route_id(),
            composition: inputs.composition.binding_digest(),
            frozen: inputs.admission.frozen_bindings().clone(),
            native_committed: Some(NativeCommittedFundingV24 {
                leg: self.leg,
                effect: self.effect,
                evidence_digest: *funding.evidence_digest(),
            }),
        })
    }
}

fn require_native_plan(
    inputs: &AuthenticatedProductionInputsV1,
    snapshot: &RouteSnapshotV1,
    leg: LegIdV1,
    effect: &EffectReferenceV1,
    stored: &StoredSettlementPlanV1,
) -> Result<(), ProductionInputErrorV1> {
    let error = || ProductionInputErrorV1::RouteStateRefused;
    let session = inputs.monero_session(leg).ok_or_else(error)?;
    let setup = session.setup();
    let binding = stored.plan().bindings();
    if stored.view().stage == AggregateStageV1::FailedClosed
        || binding.route_id != snapshot.route_id
        || binding.effect_id != effect.effect_id
        || binding.fencing_epoch != effect.fencing_epoch
        || binding.semantic_digest != effect.semantic_digest
        || binding.leg
            != match leg {
                LegIdV1::Upstream => SettlementLegV1::Upstream,
                LegIdV1::Downstream => SettlementLegV1::Downstream,
            }
        || binding.action != SettlementActionV1::Funding
        || binding.settlement_id != setup.settlement_id()
        || binding.terms_digest != inputs.admission.frozen_bindings().terms_digest
        || binding.registry_digest != inputs.admission.registry_digest()
        || binding.dom_profile_digest != inputs.admission.dom_profile_digest()
        || binding.dom_deployment_digest
            != inputs
                .admission
                .dom_deployment_capability()
                .map_err(|_| error())?
                .registry_digest()
        || binding.counterparty_profile_digest != session.deployment().profile_digest()
        || binding.counterparty_deployment_digest
            != crate::production_child_xmr::resolved_monero_deployment_digest_v1(
                session.deployment(),
            )
            .map_err(|_| error())?
        || effect.contains_route_secret
        || effect.expected_transaction_id != Some(stored.view().aggregate_action_id)
    {
        return Err(error());
    }
    let children = stored.plan().materialized_children().map_err(|_| error())?;
    let xmr = children
        .iter()
        .find(|child| child.face == SettlementFaceV1::Monero)
        .ok_or_else(error)?;
    if children
        .iter()
        .filter(|child| child.face == SettlementFaceV1::Monero)
        .count()
        != 1
        || children
            .iter()
            .filter(|child| child.face == SettlementFaceV1::Dom)
            .count()
            != 1
    {
        return Err(error());
    }
    // Reproduce the stable V1 descriptor, including exact destination/amount;
    // a matching tx hash with a substituted custody descriptor is insufficient.
    let custody = descriptor_digest(
        b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-CUSTODY/V1\0",
        &[
            &setup.settlement_id(),
            &setup.funding_tx_hash(),
            &setup.expected_amount_piconero().to_be_bytes(),
            &setup.combined_spend_public_key(),
        ],
    );
    let tx = descriptor_digest(
        b"DOM-INTEROP/INTEROPD/XMR-CHILD/TRANSACTION-ID/V1\0",
        &[&setup.funding_tx_hash()],
    );
    let intent = descriptor_digest(
        b"DOM-INTEROP/INTEROPD/XMR-CHILD/INTENT/V1\0",
        &[&setup.settlement_id(), &[1], &custody],
    );
    if xmr.chain_id != session.deployment().profile().chain_id.0
        || xmr.exposure != ChildExposureV1::NonSecret
        || xmr.expected_transaction_id != tx
        || xmr.custody_digest != custody
        || xmr.intent_digest != intent
        || stored
            .view()
            .children
            .iter()
            .find(|child| child.face == SettlementFaceV1::Monero)
            .is_none_or(|child| child.transaction_id != Some(tx))
    {
        return Err(error());
    }
    Ok(())
}

fn descriptor_digest(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let mut bytes = domain.to_vec();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    *dom_crypto::blake2b_256(&bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_exit_witness_never_generalizes_a_committed_effect_or_fabricates_finality() {
        let effect = EffectReferenceV1 {
            effect_id: [2; 32],
            fencing_epoch: 7,
            semantic_digest: [3; 32],
            contains_route_secret: false,
            expected_transaction_id: Some([4; 32]),
        };
        let mut snapshot = RouteSnapshotV1::new([1; 32]).unwrap();
        snapshot.upstream.funding = ActionStateV1::Committed(effect.clone());
        // This is only the final private scope-check unit seam. Production
        // construction above still requires opaque native funding evidence.
        let witnessed = NativeCommittedFundingV24 {
            leg: LegIdV1::Upstream,
            effect: effect.clone(),
            evidence_digest: [5; 32],
        };
        let original = snapshot.clone();
        assert!(!has_externalized_funding(&snapshot));
        assert!(witnessed.matches(&snapshot));
        assert_eq!(snapshot, original);
        for field in 0..5 {
            let mut altered = effect.clone();
            match field {
                0 => altered.effect_id[0] ^= 1,
                1 => altered.fencing_epoch += 1,
                2 => altered.semantic_digest[0] ^= 1,
                3 => altered.expected_transaction_id = Some([9; 32]),
                _ => altered.contains_route_secret = true,
            }
            snapshot.upstream.funding = ActionStateV1::Committed(altered);
            assert!(!witnessed.matches(&snapshot));
        }
        snapshot = original;
        snapshot.aborted_unfunded = true;
        assert!(!witnessed.matches(&snapshot));
    }

    #[test]
    fn native_descriptor_pins_amount_destination_and_exact_transaction() {
        let domain = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-CUSTODY/V1\0";
        let original = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let digest = |values: &[[u8; 32]; 4]| {
            descriptor_digest(domain, &[&values[0], &values[1], &values[2], &values[3]])
        };
        let expected = digest(&original);
        for field in 0..4 {
            let mut altered = original;
            altered[field][0] ^= 1;
            assert_ne!(digest(&altered), expected);
        }
        assert_ne!(
            descriptor_digest(domain, &[&[1, 2], &[3]]),
            descriptor_digest(domain, &[&[1], &[2, 3]])
        );
    }
}
