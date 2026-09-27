//! The Relay roster artifact, and the one pin it determines.
//!
//! The decisive assertion here is a reimplementation of nothing: `validate_roster_terms`
//! is private to the daemon, so this test states the same four conditions it checks
//! and asserts them against the bundle as decoded from the file. If they hold, the
//! daemon's own check holds, because they are the whole of it.

mod common;

use common::{provision_all, RELAY_ROSTER};
use dom_interopd::{ProductionRelayRosterBundleV1, ProductionRoutePositionV1};
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;

fn decoded(provisioned: &common::Provisioned) -> ProductionRelayRosterBundleV1 {
    let bytes = std::fs::read(provisioned.directory.path().join(RELAY_ROSTER))
        .expect("the roster artifact was written");
    ProductionRelayRosterBundleV1::decode_canonical(&bytes)
        .expect("the roster artifact decodes strictly")
}

#[test]
fn the_artifact_decodes_and_hashes_to_the_pin_it_declares() {
    let provisioned = provision_all();
    let bundle = decoded(&provisioned);
    let pin = provisioned
        .plan
        .roster
        .expect("the plan carries the provisioned roster");

    assert_eq!(
        bundle.bundle_digest().expect("the bundle digests"),
        pin.relay_binding_digest
    );
    // The daemon refuses the bundle on any of these three before looking at a member.
    assert_eq!(bundle.network_id(), provisioned.plan.network_id);
    assert_eq!(bundle.route_id(), provisioned.plan.route_id);
    assert_eq!(
        bundle.legs()[0].position,
        ProductionRoutePositionV1::Upstream
    );
    assert_eq!(
        bundle.legs()[1].position,
        ProductionRoutePositionV1::Downstream
    );
}

#[test]
fn each_leg_carries_exactly_what_its_terms_say() {
    let provisioned = provision_all();
    let bundle = decoded(&provisioned);

    for (leg, terms) in bundle
        .legs()
        .iter()
        .zip([&provisioned.upstream, &provisioned.downstream])
    {
        // Condition one and two of `validate_roster_terms`.
        assert_eq!(
            leg.session_id, terms.session_id.0,
            "a roster leg bound to another session is a roster for another settlement"
        );
        assert_eq!(leg.policy_version, terms.policy_version);
        // Condition three: exactly the terms' roster, in the terms' order.
        assert_eq!(
            leg.members.map(|member| member.participant_id),
            terms.roster
        );
    }
}

#[test]
fn every_member_key_is_a_valid_bip340_key_and_no_two_are_equal() {
    let provisioned = provision_all();
    let bundle = decoded(&provisioned);
    // Condition four, run through the same context type the daemon builds.
    let secp = btc_crypto::SecpContext::new(&[0xd4; 32]);
    let mut seen = Vec::new();
    for leg in bundle.legs() {
        for member in leg.members {
            secp.validate_xonly_key(&member.xonly_key)
                .expect("a roster member key the daemon would accept");
            assert_ne!(member.xonly_key, [0; 32]);
            seen.push(member.xonly_key);
        }
    }
    let distinct: std::collections::BTreeSet<[u8; 32]> = seen.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        seen.len(),
        "two participants sharing a key would make their envelopes indistinguishable"
    );
}

#[test]
fn the_two_positions_get_distinct_sessions_and_distinct_snapshots() {
    let provisioned = provision_all();
    let bundle = decoded(&provisioned);
    let [upstream, downstream] = bundle.legs();

    // `validate_shape` refuses either collision, and it is right to: two positions
    // sharing a session or a snapshot would let one position's envelope be replayed
    // as the other's.
    assert_ne!(upstream.session_id, downstream.session_id);
    assert_ne!(upstream.roster_snapshot, downstream.roster_snapshot);
    assert_ne!(upstream.roster_snapshot, [0; 32]);
    assert_ne!(downstream.roster_snapshot, [0; 32]);
}

#[test]
fn one_member_initiates_and_the_other_solves() {
    let provisioned = provision_all();
    let bundle = decoded(&provisioned);
    for leg in bundle.legs() {
        assert_eq!(leg.members[0].role, relay::SenderRoleV1::Initiator);
        assert_eq!(leg.members[1].role, relay::SenderRoleV1::Solver);
        // Neither may observe: an observer does not sign, so a roster that named one
        // as a settlement participant would be naming a party that cannot act.
        for member in leg.members {
            assert_ne!(member.role, relay::SenderRoleV1::Observer);
        }
    }
}

/// What the roster adds, and nothing else. Same reason as in the terms suite: the
/// count comes from a plan carrying only the artifacts this one depends on.
#[test]
fn binding_the_roster_turns_one_more_pin_into_a_measurement() {
    let provisioned = provision_all();
    let before = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        provisioned.upstream_facts.genesis_hash,
        provisioned.downstream_facts.genesis_hash,
    )
    .with_registry(provisioned.registry)
    .with_terms(provisioned.plan.terms.expect("the provisioned terms"));
    assert_eq!(before.measured_pin_count(), 7);

    let after = before.with_roster(provisioned.plan.roster.expect("the provisioned roster"));
    assert_eq!(
        after.measured_pin_count(),
        8,
        "relay_binding_digest"
    );
    assert!(after.pins_are_placeholders());
}
