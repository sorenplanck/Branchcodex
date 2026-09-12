//! Threshold-signed role enrollment, explicitly not an executable Claim plan.
//! The template hashes are supplied only by the bilateral native Store origin.
use super::*;
use dom_final_claim_binding::{
    ComposedFinalClaimRolePlanInputV1, FinalClaimRevealModeV1, FinalClaimRoleSelectionV1,
    FinalClaimSecretSourceScopeInputV1, FinalClaimSecretSourceV1,
};

pub(super) const MAGIC_V23: &[u8; 8] = b"DOMF6A23";
pub(super) const VERSION_V23: u16 = 23;
pub(super) const DOMAIN_V23: &[u8] = b"DOM-INTEROP/INTEROPD/F6-AUTHORITY-ENROLLMENT/V23\0";
const ENROLLMENT_BYTES: usize = 2 * (32 + 3 * 32 + 33);

#[derive(Clone)]
pub(super) enum ClaimPlanProfileV23 {
    Bound {
        role_plan: ComposedFinalClaimRolePlanV1,
        upstream: FinalClaimSecretSourceScopeV1,
        downstream: FinalClaimSecretSourceScopeV1,
    },
    Enrollment(NativeClaimEnrollmentV23),
}

#[derive(Clone)]
pub(super) struct NativeClaimEnrollmentV23 {
    /// Closed profile: downstream local first exposure; upstream depends on
    /// that exact downstream DOM claim becoming publicly verified.
    /// Per-position terms hash, T owner, DOM sender, counterparty claimer, T.
    bytes: [u8; ENROLLMENT_BYTES],
}

impl NativeClaimEnrollmentV23 {
    pub(super) fn from_composition(
        composition: &ComposedBindingV2,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        let terms = [composition.upstream(), composition.downstream()];
        if terms[0].session_id == terms[1].session_id
            || terms[0].settlement_id == terms[1].settlement_id
            || terms[0].adaptor_point_sec1 != terms[1].adaptor_point_sec1
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let common_origin = composition.downstream().dom_leg.beneficiary;
        let mut bytes = [0; ENROLLMENT_BYTES];
        for (index, terms) in terms.into_iter().enumerate() {
            terms
                .validate()
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            let owner = terms.counterparty_leg.refund_to;
            let claimer = terms.dom_leg.refund_to;
            if owner == claimer
                || !terms.roster.contains(&owner)
                || !terms.roster.contains(&claimer)
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            let start = index * 161;
            bytes[start..start + 32].copy_from_slice(
                &terms
                    .terms_hash()
                    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
            );
            bytes[start + 32..start + 64].copy_from_slice(&common_origin.0);
            bytes[start + 64..start + 96].copy_from_slice(&owner.0);
            bytes[start + 96..start + 128].copy_from_slice(&claimer.0);
            bytes[start + 128..start + 161].copy_from_slice(&terms.adaptor_point_sec1);
        }
        Ok(Self { bytes })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn decode(
        reader: &mut BundleReaderV7<'_>,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        Ok(Self {
            bytes: reader.take::<ENROLLMENT_BYTES>()?,
        })
    }

    fn require_composition(
        &self,
        composition: &ComposedBindingV2,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        if self.bytes != Self::from_composition(composition)?.bytes {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        Ok(())
    }
}

impl ClaimPlanProfileV23 {
    pub(super) fn validate_scope(
        &self,
        route: Digest32,
        scope: Digest32,
        composition: Digest32,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        if let Self::Bound { role_plan, .. } = self {
            if role_plan.route_id() != route
                || role_plan.route_scope_digest() != scope
                || role_plan.composition_binding_digest() != composition
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        }
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        composition: &ComposedBindingV2,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        match self {
            Self::Bound {
                role_plan,
                upstream,
                downstream,
            } => {
                role_plan
                    .authenticate(
                        composition.upstream(),
                        composition.downstream(),
                        upstream.clone(),
                        downstream.clone(),
                    )
                    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
                Ok(())
            }
            Self::Enrollment(value) => value.require_composition(composition),
        }
    }

    pub(super) fn into_bound(
        self,
    ) -> Result<
        (
            ComposedFinalClaimRolePlanV1,
            FinalClaimSecretSourceScopeV1,
            FinalClaimSecretSourceScopeV1,
        ),
        ProductionF6ActivationRefusalV2,
    > {
        match self {
            Self::Bound {
                role_plan,
                upstream,
                downstream,
            } => Ok((role_plan, upstream, downstream)),
            Self::Enrollment(_) => Err(ProductionF6ActivationRefusalV2::InvalidBinding),
        }
    }

    pub(super) fn materialize(
        self,
        route_id: Digest32,
        composition: &ComposedBindingV2,
        bindings: [&dom_scriptless_store::VerifiedXmrRefundTemplateBindingV23; 2],
    ) -> Result<
        (
            ComposedFinalClaimRolePlanV1,
            FinalClaimSecretSourceScopeV1,
            FinalClaimSecretSourceScopeV1,
        ),
        ProductionF6ActivationRefusalV2,
    > {
        let Self::Enrollment(enrollment) = self else {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        };
        enrollment.require_composition(composition)?;
        let mut sources = Vec::with_capacity(2);
        let mut selections = Vec::with_capacity(2);
        let source_terms = composition.downstream();
        let source_template = bindings[1].claim_template_hash();
        for (index, (terms, binding)) in [composition.upstream(), composition.downstream()]
            .into_iter()
            .zip(bindings)
            .enumerate()
        {
            if binding.route_id() != route_id
                || binding.trusted_chain_id().as_bytes() != &terms.dom_leg.chain_id.0
                || binding.session_id() != terms.session_id.0
                || binding.terms_hash()
                    != terms
                        .terms_hash()
                        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?
                || binding.participant_ids() != terms.roster.map(|id| id.0)
                || binding.claim_template_hash() == [0; 32]
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            let owner = source_terms.dom_leg.beneficiary;
            let sender = terms.dom_leg.beneficiary;
            let (secret_source, reveal_mode) = if index == 0 {
                (
                    FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23,
                    FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
                )
            } else {
                (
                    FinalClaimSecretSourceV1::LocalOrigin,
                    FinalClaimRevealModeV1::DomRevealsFirst,
                )
            };
            let source = FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
                secret_source,
                reveal_mode,
                route_id,
                composition_binding_digest: composition.binding_digest(),
                source_chain_id: source_terms.dom_leg.chain_id,
                source_settlement_id: source_terms.settlement_id,
                source_session_id: source_terms.session_id,
                source_claim_template_hash: source_template,
                adaptor_point_sec1: terms.adaptor_point_sec1,
                adaptor_secret_origin_id: owner,
                dom_claim_sender_id: sender,
            })
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            selections.push(
                FinalClaimRoleSelectionV1::new(
                    owner,
                    sender,
                    terms.dom_leg.refund_to,
                    reveal_mode,
                    secret_source,
                    source.clone(),
                )
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
            );
            sources.push(source);
        }
        let [upstream_selection, downstream_selection]: [FinalClaimRoleSelectionV1; 2] = selections
            .try_into()
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let role_plan = ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id,
            route_scope_digest: composition.route_scope_digest(),
            composition_binding_digest: composition.binding_digest(),
            upstream_terms: composition.upstream(),
            downstream_terms: composition.downstream(),
            upstream_selection,
            downstream_selection,
        })
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let [upstream, downstream]: [FinalClaimSecretSourceScopeV1; 2] = sources
            .try_into()
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        Ok((role_plan, upstream, downstream))
    }
}
