use super::*;
use crate::production_route_topology::ProductionLegTopologyV4;

fn service(face: Face, port: u16) -> ServiceV8 {
    let url = format!("http://127.0.0.1:{port}");
    match face {
        Face::Evm => ServiceV8::Evm {
            endpoint: url,
            refund_timeout_seconds: 30,
        },
        Face::Bitcoin => ServiceV8::Bitcoin {
            endpoint: url,
            wallet: format!("wallet-{port}"),
            cookie: PathBuf::from("/owned/core.cookie"),
        },
        Face::Solana => ServiceV8::Solana {
            endpoints: vec![url],
            quorum: 1,
        },
        Face::Monero => ServiceV8::Monero {
            endpoints: vec![url],
            quorum: 1,
        },
        Face::Dom => panic!("DOM is the center, not a counterparty"),
    }
}
fn fixture(a: Face, b: Face) -> (RouteServicesV8, ProductionRouteTopologyV4) {
    let legs = [
        ProductionLegTopologyV4 {
            settlement_id: [10; 32],
            face: a,
            chain_id: [20; 32],
            profile_digest: [30; 32],
            deployment_digest: [40; 32],
        },
        ProductionLegTopologyV4 {
            settlement_id: [11; 32],
            face: b,
            chain_id: [21; 32],
            profile_digest: [31; 32],
            deployment_digest: [41; 32],
        },
    ];
    let topology = ProductionRouteTopologyV4 {
        route_id: [1; 32],
        composition_digest: [2; 32],
        dom_chain_id: [3; 32],
        terms_digest: [4; 32],
        registry_digest: [5; 32],
        dom_profile_digest: [6; 32],
        dom_deployment_digest: [7; 32],
        legs,
    };
    let document = RouteServicesV8 {
        version: 8,
        route_id: topology.route_id,
        composition_digest: topology.composition_digest,
        registry_digest: topology.registry_digest,
        legs: [
            LegServicesV8 {
                settlement_id: legs[0].settlement_id,
                chain_id: legs[0].chain_id,
                service: service(a, 18081),
            },
            LegServicesV8 {
                settlement_id: legs[1].settlement_id,
                chain_id: legs[1].chain_id,
                service: service(b, 28081),
            },
        ],
    };
    (document, topology)
}
const FAMILIES: [Face; 4] = [Face::Evm, Face::Bitcoin, Face::Solana, Face::Monero];

#[test]
fn v8_all_sixteen_service_pairs_roundtrip_without_required_btc_or_evm() {
    let mut exports = Vec::new();
    for a in FAMILIES {
        for b in FAMILIES {
            let (document, topology) = fixture(a, b);
            let bytes = document.canonical_bytes().unwrap();
            let decoded = RouteServicesV8::decode(&bytes).unwrap();
            assert!(decoded == document);
            assert!(decoded.require_topology(&topology).is_ok());
            exports.push(
                serde_json::json!({"upstream": format!("{a:?}"), "downstream": format!("{b:?}"),
            "dom_chain_id": topology.dom_chain_id,
            "document": String::from_utf8(bytes).unwrap()}),
            );
        }
    }
    if let Some(path) = std::env::var_os("DOM_INTEROP_V8_ROUTE_SERVICES") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({"schema": 8,
            "chain_e2e": false, "routes": exports}))
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn v8_route_scope_and_leg_transplants_refuse_in_every_pair() {
    for a in FAMILIES {
        for b in FAMILIES {
            let (document, topology) = fixture(a, b);
            let mut changed = document.clone();
            changed.legs.swap(0, 1);
            assert!(changed.require_topology(&topology).is_err());
            for field in 0..7 {
                let mut changed = document.clone();
                match field {
                    0 => changed.route_id[0] ^= 1,
                    1 => changed.composition_digest[0] ^= 1,
                    2 => changed.registry_digest[0] ^= 1,
                    3 => changed.legs[0].settlement_id[0] ^= 1,
                    4 => changed.legs[1].settlement_id[0] ^= 1,
                    5 => changed.legs[0].chain_id[0] ^= 1,
                    _ => changed.legs[1].chain_id[0] ^= 1,
                }
                assert!(changed.require_topology(&topology).is_err());
            }
        }
    }
}

#[test]
fn v8_dom_cannot_be_removed_or_replaced_by_an_endpoint() {
    let (document, mut topology) = fixture(Face::Solana, Face::Monero);
    topology.dom_chain_id = [0; 32];
    assert!(document.require_topology(&topology).is_err());
    topology.dom_chain_id = topology.legs[0].chain_id;
    assert!(document.require_topology(&topology).is_err());
    let bytes = document.canonical_bytes().unwrap();
    let text = String::from_utf8(bytes)
        .unwrap()
        .replace("\"SOL\"", "\"DOM\"");
    assert!(RouteServicesV8::decode(text.as_bytes()).is_err());
}

#[test]
fn v8_same_family_same_network_keeps_distinct_settlements() {
    for face in FAMILIES {
        let (mut document, mut topology) = fixture(face, face);
        topology.legs[1].chain_id = topology.legs[0].chain_id;
        document.legs[1].chain_id = document.legs[0].chain_id;
        assert!(document.require_topology(&topology).is_ok());
        document.legs[1].settlement_id = document.legs[0].settlement_id;
        assert!(document.canonical_bytes().is_err());
    }
}

#[test]
fn v8_canonical_json_refuses_duplicate_fields_truncation_and_trailing_bytes() {
    let (document, _) = fixture(Face::Solana, Face::Monero);
    let bytes = document.canonical_bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(RouteServicesV8::decode(&bytes[..end]).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    for invalid in [
        text.replace("\"version\":8", "\"version\":8,\"version\":8"),
        text.replace("\"version\":8", "\"version\":8,\"ignored\":true"),
        text.replace("\"version\":8", "\"version\":true"),
        text.replace("\"version\":8", "\"version\":9"),
        text.clone() + "\n",
    ] {
        assert!(RouteServicesV8::decode(invalid.as_bytes()).is_err());
    }
}

#[test]
fn v8_duplicate_quorum_nodes_weak_quorum_and_credential_urls_refuse() {
    let endpoints = vec![
        "http://127.0.0.1:18081".to_owned(),
        "http://127.0.0.1:18081/".to_owned(),
    ];
    assert!(ServiceV8::Solana {
        endpoints: endpoints.clone(),
        quorum: 2
    }
    .validate()
    .is_err());
    assert!(ServiceV8::Monero {
        endpoints,
        quorum: 1
    }
    .validate()
    .is_err());
    for endpoint in [
        "http://user:pass@127.0.0.1:18081",
        "http://example.com:80",
        "https://example.com/token",
    ] {
        assert!(ServiceV8::Evm {
            endpoint: endpoint.to_owned(),
            refund_timeout_seconds: 30
        }
        .validate()
        .is_err());
    }
}
