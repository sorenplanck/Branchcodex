//! Additional harness restriction, not a replacement for production admission.
//! No DNS, remote RPC origin, or non-loopback Relay endpoint may be launched.
//! The caller still owns the local servers; this is not an OS network sandbox.
use super::Result;
use std::{net::SocketAddr, path::Path};

fn local_http(endpoint: &str) -> Result<()> {
    if endpoint.len() > 128 || !endpoint.is_ascii() {
        return Err("harness endpoint rejected".into());
    }
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or("harness requires local plain HTTP")?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    // SocketAddr accepts only numeric IP literals with an explicit port. Do
    // not resolve localhost or permit credentials, redirects-as-URLs or paths.
    let address: SocketAddr = authority
        .parse()
        .map_err(|_| "harness requires a numeric local HTTP authority")?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("harness remote or unassigned HTTP endpoint refused".into());
    }
    Ok(())
}

pub(super) fn require_local_services(state: &Path) -> Result<()> {
    require_local_services_for_families_v25(
        state,
        [crate::production_config::ProductionChainFamilyV11::Xmr; 2],
    )
}

/// Each position must carry exactly the service of its selected family. An
/// XMR-only pair keeps the original refusal of every other selected service.
pub(super) fn require_local_services_for_families_v25(
    state: &Path,
    families: [crate::production_config::ProductionChainFamilyV11; 2],
) -> Result<()> {
    use crate::production_config::ProductionChainFamilyV11;
    use crate::production_config::{read_owner_file_bounded, ProductionConfigErrorV1};
    use crate::production_relay_network_config::{
        load_production_relay_network_config_v1, ProductionRelayLinkPositionV1,
    };
    use crate::production_route_services::{RouteServicesV8, ServiceV8, FILE_V8};
    let dom = crate::production_node::load_production_node_config_v1(state)
        .map_err(|_| "harness DOM configuration unavailable")?;
    local_http(dom.endpoint().as_str())?;
    // Require the selected-family document. The compatibility fallback is not
    // an acceptable way to hide BTC/EVM services in an XMR-only scenario.
    let bytes = read_owner_file_bounded(
        &state.join(FILE_V8),
        131_072,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| "harness selected services unavailable")?;
    let services =
        RouteServicesV8::decode(&bytes).map_err(|_| "harness selected services rejected")?;
    for (leg, family) in services.legs.into_iter().zip(families) {
        match (leg.service, family) {
            (ServiceV8::Monero { endpoints, .. }, ProductionChainFamilyV11::Xmr)
            | (ServiceV8::Solana { endpoints, .. }, ProductionChainFamilyV11::Sol) => {
                for endpoint in endpoints {
                    local_http(&endpoint)?;
                }
            }
            _ if families == [ProductionChainFamilyV11::Xmr; 2] => {
                return Err("harness requires XMR-only selected services".into())
            }
            _ => return Err("harness selected service differs from its position family".into()),
        }
    }
    let relay = load_production_relay_network_config_v1(state)
        .map_err(|_| "harness Relay configuration unavailable")?;
    for position in [
        ProductionRelayLinkPositionV1::Upstream,
        ProductionRelayLinkPositionV1::Downstream,
    ] {
        let address = relay.link(position).address();
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err("harness non-local Relay endpoint refused".into());
        }
    }
    Ok(())
}

#[test]
fn binary_harness_refuses_dns_remote_and_ambiguous_http_origins() {
    for endpoint in [
        "http://127.0.0.1:18081",
        "http://127.0.0.1:18081/",
        "http://[::1]:18081/",
    ] {
        assert!(local_http(endpoint).is_ok());
    }
    for endpoint in [
        "https://127.0.0.1:18081",
        "http://localhost:18081",
        "http://192.0.2.1:18081",
        "http://0.0.0.0:18081",
        "http://[::]:18081",
        "http://127.0.0.1:0",
        "http://127.0.0.1",
        "http://127.0.0.1:18081/path",
        "http://127.0.0.1:18081//",
        "http://user@127.0.0.1:18081",
        "http://127.0.0.1:18081?redirect=remote",
        "http://127.0.0.1:18081#remote",
        "http://127.0.0.1:18081\n",
    ] {
        assert!(local_http(endpoint).is_err());
    }
}
