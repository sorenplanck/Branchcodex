//! Rebuild dynamic Noise children from retained, authenticated Relay owners.
use super::*;

pub(super) fn attach_xmr_signing_noise_v23(
    owner: &ProductionRelayStage12OwnerV1,
    leg: LegIdV1,
    link: &ProductionRelayNetworkLinkV1,
    local_database: relay::production::RelayDatabaseIdV1,
    timeout: Duration,
    session: ProductionNoiseRelaySessionV1,
) -> Result<ProductionNoiseRelaySessionV1, ProductionCompositeLoopErrorV1> {
    use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23 as Edge;
    let scopes = [
        owner.xmr_signing_noise_scope_v23(leg, Edge::Cancel),
        owner.xmr_signing_noise_scope_v23(leg, Edge::Compensation),
    ];
    let [cancel, compensation] = scopes;
    let (cancel, compensation) = match (cancel, compensation) {
        (None, None) => return Ok(session),
        (Some(cancel), Some(compensation)) => (cancel, compensation),
        _ => return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration),
    };
    if cancel.3 == [0; 32] || cancel.3 != compensation.3 {
        return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
    }
    let make = |(chain, wire, references, _): (
        dom_adaptor::TrustedChainIdV1,
        route_transport::RouteWireContextV1,
        [dom_scriptless_store::SessionTransportIdentityReferenceV1; 2],
        [u8; 32],
    )| {
        ProductionNoiseRelaySessionV1::new(
            link.noise_role(),
            ProductionNoiseRelayRouteContextV1::new(
                *chain.as_bytes(),
                wire.network_id,
                wire.route_id,
                wire.session_id,
            )
            .map_err(map_noise_error)?,
            references,
            ProductionNoiseRelayDatabasePairV1::new(
                local_database,
                link.remote_relay_database_id(),
            )
            .map_err(map_noise_error)?,
            timeout,
        )
        .map_err(map_noise_error)
    };
    session
        .with_xmr_recovery_v23([make(cancel)?, make(compensation)?])
        .map_err(map_noise_error)
}
