//! Both entrypoints share the same canonical public writer. Planning produces
//! no authority handle; first-export re-runs the production decoder afterward.
use super::*;
use crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23;

pub(crate) fn encode_native_xmr_bundle_v23(
    admitted: &AuthenticatedProductionInputsV1,
    leg: LegIdV1,
    descriptor: ProductionUniversalLegV11,
    compensation_policy: &XmrCompensationPolicyV11,
    resources: NativeXmrBundleResourcesV23,
) -> Result<(ProductionUniversalLegV11, Vec<u8>), Box<dyn std::error::Error>> {
    let terms = match leg {
        LegIdV1::Upstream => admitted.composition().upstream(),
        LegIdV1::Downstream => admitted.composition().downstream(),
    };
    let session = admitted
        .monero_session(leg)
        .ok_or("native XMR admission missing")?;
    let (descriptor, bytes) =
        encode_native_xmr_wire_v23(session, terms, descriptor, compensation_policy, resources)?;
    ProductionUniversalLegAuthorityV11::decode(&bytes, &descriptor, admitted, leg)?;
    Ok((descriptor, bytes))
}

pub(crate) fn encode_native_xmr_bundle_from_plan_v23(
    plan: &NativeDaemonPlanningContextV23,
    leg: LegIdV1,
    descriptor: ProductionUniversalLegV11,
    compensation_policy: &XmrCompensationPolicyV11,
    resources: NativeXmrBundleResourcesV23,
) -> Result<(ProductionUniversalLegV11, Vec<u8>), Box<dyn std::error::Error>> {
    let terms = match leg {
        LegIdV1::Upstream => plan.composition().upstream(),
        LegIdV1::Downstream => plan.composition().downstream(),
    };
    encode_native_xmr_wire_v23(
        plan.monero_session(leg),
        terms,
        descriptor,
        compensation_policy,
        resources,
    )
}
