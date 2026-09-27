//! Milestone 0: the manifest this crate writes is the manifest the daemon reads.
//!
//! No artifact is signed yet, so nothing here claims the daemon would admit the
//! route -- authentication reads the artifacts and would refuse. What is
//! established is narrower and is the precondition for everything after it: the
//! bytes are the daemon's own canonical encoding of a V11 route carrying two
//! Solana positions, they decode back to an equivalent configuration, and the
//! create/reopen pair is a pair rather than two unrelated files.

use dom_interopd::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;

/// Stands in for a cluster genesis hash. Any nonzero value works here; the live
/// leg reads the real one from its harness.
/// The two clusters the route's two counterparty positions sit on. Different, because
/// the route-time policy refuses a pair that shares a chain id.
const UPSTREAM_CLUSTER: [u8; 32] = [0x7c; 32];
const DOWNSTREAM_CLUSTER: [u8; 32] = [0x8d; 32];

fn plan() -> SolanaRouteBootstrapPlanV1 {
    SolanaRouteBootstrapPlanV1::both_positions_on_solana(UPSTREAM_CLUSTER, DOWNSTREAM_CLUSTER)
}

#[test]
fn a_v11_route_with_two_solana_positions_encodes_and_decodes_unchanged() {
    for mode in [
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapModeV1::ReopenExisting,
    ] {
        let config = plan().config(mode).expect("the plan builds a V11 config");
        let bytes = config
            .canonical_bytes()
            .expect("the daemon's own encoder emits it");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(&bytes, mode)
            .expect("the daemon's own decoder accepts it");
        assert_eq!(
            decoded
                .canonical_bytes()
                .expect("the decoded config re-encodes"),
            bytes,
            "a decode/encode round trip changed the manifest"
        );
        let fields = decoded
            .universal_v11()
            .expect("the decoded config carries the universal V11 family");
        assert!(
            fields
                .legs
                .iter()
                .all(|leg| leg.family == ProductionChainFamilyV11::Sol),
            "a position of this route is not Solana"
        );
        assert_ne!(
            fields.legs[0].settlement_id, fields.legs[1].settlement_id,
            "the two positions are the same settlement"
        );
    }
}

#[test]
fn the_pins_are_declared_as_placeholders() {
    // Until the signed artifacts exist, a manifest from this crate is structurally
    // valid and would be refused at authentication. The type says so, so that a
    // later reader does not mistake a passing round trip for an admitted route.
    assert!(!plan().artifact_pins_are_complete());
}

#[test]
fn both_manifests_are_written_and_each_belongs_to_its_own_mode() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let [create, reopen] = plan()
        .write_manifests(directory.path())
        .expect("both manifests are written");
    assert_eq!(
        create.file_name().and_then(|name| name.to_str()),
        Some(PRODUCTION_CREATE_CONFIG_FILE_V11)
    );
    assert_eq!(
        reopen.file_name().and_then(|name| name.to_str()),
        Some(PRODUCTION_REOPEN_CONFIG_FILE_V11)
    );

    let create_bytes = std::fs::read(&create).expect("the create manifest is readable");
    let reopen_bytes = std::fs::read(&reopen).expect("the reopen manifest is readable");
    assert_ne!(
        create_bytes, reopen_bytes,
        "the two manifests are byte-identical, so one of them carries the wrong mode"
    );

    // Each decodes in its own mode, and neither decodes in the other's: a loader
    // that accepted the create manifest as a reopen would reopen a route it was
    // asked to create.
    ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &create_bytes,
        ProductionBootstrapModeV1::Create,
    )
    .expect("the create manifest decodes as create");
    ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &reopen_bytes,
        ProductionBootstrapModeV1::ReopenExisting,
    )
    .expect("the reopen manifest decodes as reopen");
    assert!(
        ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &create_bytes,
            ProductionBootstrapModeV1::ReopenExisting,
        )
        .is_err(),
        "the create manifest decoded as a reopen"
    );
    assert!(
        ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &reopen_bytes,
            ProductionBootstrapModeV1::Create,
        )
        .is_err(),
        "the reopen manifest decoded as a create"
    );
}
