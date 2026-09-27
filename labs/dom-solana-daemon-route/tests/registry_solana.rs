//! The registry artifact: a signed manifest carrying one Solana chain, installed
//! into the store the daemon opens, with the authority bundle beside it.
//!
//! What this establishes is that the first artifact of the bootstrap exists and is
//! self-consistent: the manifest validates, the digest the store installed is the
//! digest that was signed, and the plan's pins stop being labels for the four
//! values the registry determines.

use dom_solana_daemon_route::{
    registry::{provision, SolanaChainFactsV1},
    SolanaRouteBootstrapPlanV1,
};

/// The three facts a live cluster supplies. The values are stand-ins here; the leg
/// laboratory reads the real ones from its harness and its attestation.
fn solana_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x7c; 32],
        escrow_program: [0x3c; 32],
        program_data_hash: [0x44; 32],
        network: chain_profile::SolanaNetworkV1::LocalValidator,
        max_fee_lamports: 50_000,
    }
}

const NETWORK: [u8; 32] = [0x90; 32];

#[test]
fn a_signed_registry_with_one_solana_chain_installs_and_reports_its_digest() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let facts = solana_facts();
    let provisioned = provision(
        directory.path(),
        "artifacts/registry.v1.sqlite3",
        "artifacts/registry-authorities.v1",
        NETWORK,
        7,
        &facts,
    )
    .expect("the registry provisions");

    assert_eq!(provisioned.network_id, NETWORK);
    assert_eq!(provisioned.epoch, 7);
    assert_eq!(provisioned.solana_chain_id, facts.genesis_hash);
    assert_ne!(provisioned.manifest_digest, [0; 32]);
    assert_ne!(provisioned.authority_set_digest, [0; 32]);
    assert_ne!(
        provisioned.dom_chain_id, provisioned.solana_chain_id,
        "the DOM hub and the Solana position are the same chain"
    );
    assert!(
        directory.path().join("artifacts/registry.v1.sqlite3").exists(),
        "the registry store was not created where the layout says it is"
    );
    assert!(
        directory
            .path()
            .join("artifacts/registry-authorities.v1")
            .exists(),
        "the authority bundle was not written"
    );
}

#[test]
fn binding_the_registry_turns_four_pins_into_measurements() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let provisioned = provision(
        directory.path(),
        "artifacts/registry.v1.sqlite3",
        "artifacts/registry-authorities.v1",
        NETWORK,
        7,
        &solana_facts(),
    )
    .expect("the registry provisions");

    let bare = SolanaRouteBootstrapPlanV1::both_positions_on_cluster([0x7c; 32]);
    assert_eq!(bare.measured_pin_count(), 0);
    let bound = bare.with_registry(provisioned);
    assert_eq!(bound.measured_pin_count(), 4);
    assert_eq!(
        bound.network_id, NETWORK,
        "a bound plan must take the registry's network id, not keep its own"
    );
    // Fifteen pins still to go, and the plan says so rather than implying a route
    // the daemon would admit.
    assert!(bound.pins_are_placeholders());
}

#[test]
fn a_plan_bound_to_a_registry_still_encodes_its_manifest() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let provisioned = provision(
        directory.path(),
        "artifacts/registry.v1.sqlite3",
        "artifacts/registry-authorities.v1",
        NETWORK,
        7,
        &solana_facts(),
    )
    .expect("the registry provisions");
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_cluster([0x7c; 32])
        .with_registry(provisioned);
    let written = plan
        .write_manifests(directory.path())
        .expect("both manifests are written with measured registry pins");
    assert_eq!(written.len(), 2);
}
