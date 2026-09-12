//! A cross-leg source is authenticated against the exact downstream plan.
//! It is not a local-secret capability and cannot be installed downstream.
use super::*;

pub(super) fn validate_cross_leg_source_v23(
    plan: &ComposedFinalClaimRolePlanV1,
    scope: &FinalClaimSecretSourceScopeV1,
    leg: ComposedSettlementLegV1,
    terms: &SettlementTermsV1,
) -> Result<(), FinalClaimBindingError> {
    if scope.secret_source() != FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23 {
        return Ok(());
    }
    let upstream = plan.entry(ComposedSettlementLegV1::Upstream);
    let downstream = plan.entry(ComposedSettlementLegV1::Downstream);
    if leg != ComposedSettlementLegV1::Upstream
        || scope.route_id() != plan.route_id()
        || scope.composition_binding_digest() != plan.composition_binding_digest()
        || scope.source_chain_id() != terms.dom_leg.chain_id
        || scope.source_settlement_id() != downstream.settlement_id()
        || scope.source_session_id() != downstream.session_id()
        || downstream.settlement_id() == upstream.settlement_id()
        || downstream.session_id() == upstream.session_id()
        || downstream.secret_source() != FinalClaimSecretSourceV1::LocalOrigin
        || downstream.reveal_mode() != FinalClaimRevealModeV1::DomRevealsFirst
        || upstream.secret_source() != FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23
        || scope.adaptor_secret_origin_id() != downstream.adaptor_secret_origin_id()
        || scope.adaptor_secret_origin_id() != downstream.dom_claim_sender_id()
        || scope.dom_claim_sender_id() != upstream.dom_claim_sender_id()
    {
        return Err(FinalClaimBindingError::SourceScopeMismatch);
    }
    // Reconstruct the entire downstream source commitment, including the
    // genuine template hash, rather than accepting just a shared T or route ID.
    let downstream_source =
        FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
            secret_source: FinalClaimSecretSourceV1::LocalOrigin,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            route_id: scope.route_id(),
            composition_binding_digest: scope.composition_binding_digest(),
            source_chain_id: scope.source_chain_id(),
            source_settlement_id: scope.source_settlement_id(),
            source_session_id: scope.source_session_id(),
            source_claim_template_hash: scope.source_claim_template_hash(),
            adaptor_point_sec1: scope.adaptor_point_sec1(),
            adaptor_secret_origin_id: scope.adaptor_secret_origin_id(),
            dom_claim_sender_id: downstream.dom_claim_sender_id(),
        })?;
    if downstream_source.digest() != downstream.secret_source_scope_digest() {
        return Err(FinalClaimBindingError::SourceScopeMismatch);
    }
    Ok(())
}
