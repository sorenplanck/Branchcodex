//! The two terms artifacts, and the three pins they determine.
//!
//! What this establishes is that the pair of terms this bootstrap writes is the pair
//! the daemon would read: each file is the canonical bytes of valid terms whose
//! `terms_hash()` is the pin, their ordered scope is the pin the time authority
//! signs over, and the counterparty chain each one names is the Solana chain the
//! registry declares -- which is the lookup that makes the daemon demand a Solana
//! session binding for that position at all.
//!
//! The shared fixture runs `solana_profile::validate_setup` over both provisioned
//! positions before any test asserts anything, because that is the function
//! `authenticate_participant_bundle` itself calls: if it accepts the profile, the
//! terms and the binding together, the position authenticates. So every test in this
//! directory starts from a route that would pass that check.

mod common;

use common::{provision_all, DOWNSTREAM_TERMS, UPSTREAM_TERMS};
use dom_solana_daemon_route::SolanaRouteBootstrapPlanV1;
use kaystra_core::terms::SettlementTermsV1;

#[test]
fn each_artifact_is_the_canonical_bytes_of_the_terms_its_pin_names() {
    let provisioned = provision_all();
    let pins = provisioned
        .plan
        .terms
        .expect("the plan carries the provisioned terms");

    for (relative, expected, terms) in [
        (
            UPSTREAM_TERMS,
            pins.upstream_terms_digest,
            &provisioned.upstream,
        ),
        (
            DOWNSTREAM_TERMS,
            pins.downstream_terms_digest,
            &provisioned.downstream,
        ),
    ] {
        let bytes = std::fs::read(provisioned.directory.path().join(relative))
            .unwrap_or_else(|error| panic!("{relative} was not written: {error}"));
        let decoded = SettlementTermsV1::decode(&bytes).expect("the artifact decodes strictly");
        // `decode_terms` refuses anything that is not its own canonical encoding,
        // and then refuses a digest that is not the pin. Both, in that order.
        assert_eq!(
            decoded.canonical_bytes().expect("valid terms encode"),
            bytes,
            "{relative} is not the canonical encoding of what it decodes to"
        );
        assert_eq!(
            decoded.terms_hash().expect("valid terms hash"),
            expected,
            "{relative} does not hash to the pin the bootstrap declares"
        );
        assert_eq!(&decoded, terms, "{relative} is not the terms that were frozen");
    }
}

#[test]
fn the_scope_pin_is_the_ordered_pair_and_not_either_alone() {
    let provisioned = provision_all();
    let pins = provisioned.plan.terms.expect("the provisioned terms");

    assert_eq!(
        route_time_anchor::route_scope_digest(&provisioned.upstream, &provisioned.downstream)
            .expect("the scope digests"),
        pins.route_scope_digest
    );
    // Order is part of the scope: the same two terms in the other order are a
    // different route, and the time authority would be signing over that one.
    assert_ne!(
        route_time_anchor::route_scope_digest(&provisioned.downstream, &provisioned.upstream)
            .expect("the scope digests"),
        pins.route_scope_digest
    );
}

#[test]
fn each_position_names_the_cluster_the_registry_declares_for_it() {
    let provisioned = provision_all();
    for (terms, facts) in [
        (&provisioned.upstream, provisioned.upstream_facts),
        (&provisioned.downstream, provisioned.downstream_facts),
    ] {
        assert_eq!(
            terms.counterparty_leg.chain_id.0, facts.genesis_hash,
            "the daemon resolves the position's chain by this id; a mismatch resolves nothing"
        );
        assert_eq!(
            terms.counterparty_leg.mechanism,
            kaystra_core::types::LockMechanism::CrossCurveConditionLock
        );
    }
    // The route-time policy refuses two counterparty legs that share a chain id, so
    // this inequality is not incidental to the fixture: it is the shape of the route.
    assert_ne!(
        provisioned.upstream.counterparty_leg.chain_id,
        provisioned.downstream.counterparty_leg.chain_id,
        "RouteTimePolicyV2::from_registry refuses a route whose counterparty positions \
         share a chain unless the DOM/XMR mainnet profile is selected"
    );
    assert_ne!(
        provisioned.upstream.settlement_id, provisioned.downstream.settlement_id,
        "a route is two distinct settlements"
    );
    assert_ne!(
        provisioned.upstream.session_id,
        provisioned.downstream.session_id
    );
}

#[test]
fn the_two_positions_are_the_two_claim_orders() {
    let provisioned = provision_all();
    // Upstream begins on Solana: the DOM side claims first, so the DOM refund
    // height is the chosen anchor and the escrow deadline is derived past it.
    // Downstream ends on Solana: the escrow deadline is chosen and the DOM refund
    // height is derived past that. The observable difference is which side's
    // deadline sits further out relative to the anchor, and it is the reason the
    // second claimant always has a window.
    let upstream_escrow = deadline_seconds(&provisioned.upstream);
    let downstream_escrow = deadline_seconds(&provisioned.downstream);
    let upstream_height = dom_height(&provisioned.upstream);
    let downstream_height = dom_height(&provisioned.downstream);

    assert!(
        downstream_escrow > upstream_escrow,
        "the downstream position chose a one-hour escrow deadline; the upstream derived a \
         shorter one from its DOM height ({downstream_escrow} vs {upstream_escrow})"
    );
    assert!(
        downstream_height > upstream_height,
        "the downstream DOM refund height is derived past its chosen escrow deadline, so it \
         must sit beyond the upstream's chosen height ({downstream_height} vs {upstream_height})"
    );
}

fn deadline_seconds(terms: &SettlementTermsV1) -> u64 {
    match terms.counterparty_leg.deadline {
        kaystra_core::types::TimelockSpec::TimestampSeconds { value } => value,
        other => panic!("a Solana escrow deadline is a wall-clock second, not {other:?}"),
    }
}

fn dom_height(terms: &SettlementTermsV1) -> u64 {
    match terms.dom_leg.deadline {
        kaystra_core::types::TimelockSpec::BlockHeight { value } => value,
        other => panic!("a DOM refund is height-locked, not {other:?}"),
    }
}

/// The coherence `validate_composition_registry_parts` demands, asserted here on the
/// provisioned pair rather than discovered when the daemon refuses the route.
///
/// That function refuses unless, for BOTH positions: the DOM leg names the hub's
/// chain and its native asset, the DOM leg's finality equals the hub's exactly, the
/// DOM deadline is a height, the counterparty leg's finality equals the resolved
/// chain profile's exactly, and the counterparty mechanism and deadline are the pair
/// its chain kind admits -- for Solana, a cross-curve condition lock on a wall-clock
/// second.
#[test]
fn both_terms_satisfy_the_registry_coherence_the_daemon_refuses_without() {
    let provisioned = provision_all();
    for terms in [&provisioned.upstream, &provisioned.downstream] {
        assert_eq!(terms.dom_leg.chain_id.0, provisioned.dom_chain_id);
        assert_eq!(terms.dom_leg.asset_id.0, provisioned.dom_asset_id);
        assert_eq!(
            terms.dom_leg.finality,
            dom_solana_daemon_route::registry::dom_finality(),
            "the hub's finality and the DOM leg's must be the same value, not merely similar"
        );
        assert!(matches!(
            terms.dom_leg.deadline,
            kaystra_core::types::TimelockSpec::BlockHeight { .. }
        ));
        assert_eq!(
            terms.counterparty_leg.finality,
            dom_solana_daemon_route::registry::solana_finality()
        );
        assert!(matches!(
            terms.counterparty_leg.deadline,
            kaystra_core::types::TimelockSpec::TimestampSeconds { .. }
        ));
        assert_eq!(
            terms.counterparty_leg.mechanism,
            kaystra_core::types::LockMechanism::CrossCurveConditionLock
        );
    }
}

/// What the terms add, and nothing else.
///
/// Asserted against a plan carrying only the registry and the terms, not against the
/// shared fixture's plan: the fixture provisions every artifact built so far, so a
/// count taken from it would change every time a later artifact lands and would stop
/// saying anything about the terms.
#[test]
fn binding_the_terms_turns_three_more_pins_into_measurements() {
    let provisioned = provision_all();
    let pins = provisioned.plan.terms.expect("the provisioned terms");

    let registry_only = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        provisioned.upstream_facts.genesis_hash,
        provisioned.downstream_facts.genesis_hash,
    )
    .with_registry(provisioned.registry);
    assert_eq!(registry_only.measured_pin_count(), 4);

    let with_terms = registry_only.with_terms(pins);
    assert_eq!(
        with_terms.measured_pin_count(),
        7,
        "upstream_terms_digest, downstream_terms_digest and route_scope_digest"
    );
    assert!(
        !with_terms.artifact_pins_are_complete(),
        "six artifact pins are still labels and the plan must keep saying so"
    );
}
