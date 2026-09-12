//! Exact selected-route binding of the native XMR economic graph verifier.
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;
use dom_scriptless_crypto::{FrozenSharedOutputV1, VerifiedXmrRecoveryGraphV11};
use route_executor::LegIdV1;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11;
pub(crate) use xmr_refund_policy::economic_graph::{
    VerifiedXmrEconomicRecoveryGraphV11 as ProductionXmrEconomicGraphV11,
    XmrPayoutValueProofV11 as ProductionXmrPayoutValueProofV11,
};

/// Resolve enrollment only through its same-open Contracts authority.
pub(crate) fn resolve_xmr_refund_bundle_v23<'a>(
    inputs: &'a AuthenticatedProductionInputsV1,
    leg: LegIdV1,
    native_owner: Option<&'a ProductionRelayStage12OwnerV1>,
) -> Result<&'a crate::production_inputs::ProductionXmrRefundBundleV1, Refusal> {
    let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
    match (session.refund_bundle(), session.native_enrollment_v23()) {
        (Some(refund), None) if native_owner.is_none() => Ok(refund),
        (None, Some(_)) => {
            let setup = native_owner
                .ok_or(Refusal::Conflict)?
                .bound_xmr_setup_v23(leg)
                .map_err(|_| Refusal::Conflict)?;
            let binding = setup.binding();
            if binding.route_id() != session.route_id()
                || binding.session_id() != session.session_id()
                || binding.terms_digest() != session.terms_digest()
                || setup.setup().binding_hash() != session.setup().binding_hash()
                || setup.genesis() != session.deployment().deployment().genesis_hash
            {
                return Err(Refusal::Conflict);
            }
            setup.refund_bundle_v23().map_err(|_| Refusal::Conflict)
        }
        _ => Err(Refusal::Conflict),
    }
}

pub(crate) fn authenticate_xmr_economic_graph_v11(
    inputs: &AuthenticatedProductionInputsV1,
    leg: LegIdV1,
    native_owner: Option<&ProductionRelayStage12OwnerV1>,
    policy: ValidatedXmrCompensationPolicyV11,
    graph: &VerifiedXmrRecoveryGraphV11,
    collateral: &FrozenSharedOutputV1,
    payouts: &[ProductionXmrPayoutValueProofV11; 2],
) -> Result<ProductionXmrEconomicGraphV11, Refusal> {
    let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
    let terms = match leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let refund = resolve_xmr_refund_bundle_v23(inputs, leg, native_owner)?;
    if graph.binding().refund_adaptor_point != refund.adaptor_point_sec1
        || dom_adaptor::canonical_template_v1(graph.refund_template())
            .map_err(|_| Refusal::Conflict)?
            .1
            != refund.template_hash
        || graph.binding().terms_hash != session.setup().terms_hash()
    {
        return Err(Refusal::Conflict);
    }
    xmr_refund_policy::economic_graph::verify_xmr_economic_recovery_graph_v11(
        terms, policy, graph, collateral, payouts,
    )
    .map_err(|_| Refusal::Conflict)
}
