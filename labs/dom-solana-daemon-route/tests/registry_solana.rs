//! The registry artifact: a signed manifest carrying the DOM hub and the two Solana
//! clusters, installed into the store the daemon opens, with the authority bundle
//! beside it.
//!
//! What this establishes is that the first artifact of the bootstrap exists and is
//! self-consistent: the manifest validates, the digest the store installed is the
//! digest that was signed, and the plan's pins stop being labels for the four values
//! the registry determines.
//!
//! Two clusters, because a route has two counterparty positions and
//! `RouteTimePolicyV2::from_registry` refuses a pair that shares a chain id unless
//! the DOM/XMR mainnet profile is selected. One of these tests asserts that refusal
//! directly, at the point where this crate can still explain it, rather than letting
//! it surface later as `InvalidPolicy` from a component that knows nothing about
//! Solana.

mod common;

use common::{downstream_facts, upstream_facts, NETWORK, NOW_SECONDS};
use dom_solana_daemon_route::{
    registry::{provision, RegistryProvisioningInputV1, SolanaChainFactsV1},
    SolanaRouteBootstrapPlanV1,
};

fn input<'a>(
    directory: &'a std::path::Path,
    upstream: &'a SolanaChainFactsV1,
    downstream: &'a SolanaChainFactsV1,
) -> RegistryProvisioningInputV1<'a> {
    RegistryProvisioningInputV1 {
        state_dir: directory,
        registry_relative: "artifacts/registry.v1.sqlite3",
        authorities_relative: "artifacts/registry-authorities.v1",
        network_id: NETWORK,
        epoch: 7,
        now_seconds: NOW_SECONDS,
        valid_from_offset_seconds: 86_400,
        valid_until_offset_seconds: 86_400,
        upstream,
        downstream,
    }
}

#[test]
fn a_signed_registry_with_both_solana_clusters_installs_and_reports_its_digests() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let up = upstream_facts();
    let down = downstream_facts();
    let provisioned =
        provision(&input(directory.path(), &up, &down)).expect("the registry provisions");

    assert_eq!(provisioned.network_id, NETWORK);
    assert_eq!(provisioned.epoch, 7);
    assert_eq!(provisioned.upstream_chain_id, up.genesis_hash);
    assert_eq!(provisioned.downstream_chain_id, down.genesis_hash);
    assert_ne!(provisioned.manifest_digest, [0; 32]);
    assert_ne!(provisioned.authority_set_digest, [0; 32]);
    // Measured from the installed registry, not derived here. Both terms must carry
    // it as their DOM leg's adapter profile hash or the route-time policy refuses
    // them with RegistryMismatch.
    assert_ne!(provisioned.dom_profile_digest, [0; 32]);
    assert_ne!(
        provisioned.dom_chain_id, provisioned.upstream_chain_id,
        "a counterparty position may not sit on the DOM hub's own chain"
    );
    assert_ne!(
        provisioned.dom_chain_id, provisioned.downstream_chain_id,
        "a counterparty position may not sit on the DOM hub's own chain"
    );
    // The window the policy's own window has to fit inside.
    assert!(provisioned.valid_from_seconds < NOW_SECONDS);
    assert!(provisioned.expires_at_seconds > NOW_SECONDS);
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

/// The refusal that shaped this route.
///
/// A route whose two counterparty positions sit on ONE cluster cannot be authorised:
/// `RouteTimePolicyV2::from_registry` rejects it, and the exception carved out for
/// DOM/XMR mainnet exists because on Monero the two roles genuinely share one chain
/// and carry an extra equality constraint to make that safe. Refusing here, where the
/// two clusters are named, says so in terms of the thing the caller passed.
#[test]
fn one_cluster_on_both_positions_is_refused_with_the_reason() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let up = upstream_facts();
    let same = upstream_facts();
    let error = provision(&input(directory.path(), &up, &same))
        .expect_err("one cluster on both positions is not a route the daemon can admit");
    assert!(
        error.contains("different clusters"),
        "the refusal must name the reason, not just fail: {error}"
    );
}

#[test]
fn binding_the_registry_turns_four_pins_into_measurements() {
    let directory = tempfile::tempdir().expect("a private working directory");
    let up = upstream_facts();
    let down = downstream_facts();
    let provisioned =
        provision(&input(directory.path(), &up, &down)).expect("the registry provisions");

    let bare = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        up.genesis_hash,
        down.genesis_hash,
    );
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
    let up = upstream_facts();
    let down = downstream_facts();
    let provisioned =
        provision(&input(directory.path(), &up, &down)).expect("the registry provisions");
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        up.genesis_hash,
        down.genesis_hash,
    )
    .with_registry(provisioned);
    let written = plan
        .write_manifests(directory.path())
        .expect("both manifests are written with measured registry pins");
    assert_eq!(written.len(), 2);
}
