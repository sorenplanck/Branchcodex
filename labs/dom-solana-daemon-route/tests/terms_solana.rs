//! The two terms artifacts, and the three pins they determine.
//!
//! What this establishes is that the pair of terms this bootstrap writes is the pair
//! the daemon would read: each file is the canonical bytes of valid terms whose
//! `terms_hash()` is the pin, their ordered scope is the pin the time authority
//! signs over, and the counterparty chain each one names is the Solana chain the
//! registry declares -- which is the lookup that makes the daemon demand a Solana
//! session binding for that position at all.
//!
//! The decisive assertion is `solana_profile::validate_setup`, because that is the
//! function `authenticate_participant_bundle` itself calls: if it accepts the
//! profile, the terms and the binding together, the position authenticates.

use dom_solana_daemon_route::{
    registry::{provision as provision_registry, SolanaChainFactsV1},
    terms::{
        provision as provision_terms, RouteTermsInputV1, SolanaPositionAccountsV1,
        SolanaPositionTermsPlanV1,
    },
    SolanaRouteBootstrapPlanV1,
};
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use solana_types::SolanaPubkey;

const NETWORK: [u8; 32] = [0x90; 32];
const UPSTREAM_TERMS: &str = "artifacts/upstream-terms.v1";
const DOWNSTREAM_TERMS: &str = "artifacts/downstream-terms.v1";

fn solana_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x7c; 32],
        escrow_program: [0x3c; 32],
        program_data_hash: [0x44; 32],
        network: chain_profile::SolanaNetworkV1::LocalValidator,
        max_fee_lamports: 50_000,
    }
}

/// Distinct, non-zero accounts. A zero funder is refused by `validate_setup`, so
/// these are named rather than defaulted.
fn accounts(seed: u8) -> SolanaPositionAccountsV1 {
    SolanaPositionAccountsV1 {
        funder: SolanaPubkey([seed; 32]),
        beneficiary: SolanaPubkey([seed.wrapping_add(1); 32]),
        refund_recipient: SolanaPubkey([seed.wrapping_add(2); 32]),
        amount: 5_000_000,
    }
}

fn position(seed: u8) -> SolanaPositionTermsPlanV1 {
    SolanaPositionTermsPlanV1 {
        settlement_id: [seed; 32],
        session_id: [seed.wrapping_add(0x40); 32],
        dom_beneficiary: ParticipantId([seed.wrapping_add(0x80); 32]),
        dom_refund_to: ParticipantId([seed.wrapping_add(0xa0); 32]),
        dom_amount_noms: 4_000_000,
        accounts: accounts(seed),
    }
}

struct Provisioned {
    directory: tempfile::TempDir,
    plan: SolanaRouteBootstrapPlanV1,
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    solana_chain_id: [u8; 32],
    dom_chain_id: [u8; 32],
    dom_asset_id: [u8; 32],
}

fn provision_all() -> Provisioned {
    let directory = tempfile::tempdir().expect("a private working directory");
    // Separate from the state directory on purpose: the leg's setup store is not a
    // path role of the daemon's layout.
    let provisioning = tempfile::tempdir().expect("a private provisioning directory");
    let leg_store_dir = provisioning.path().join("leg");
    let facts = solana_facts();
    let registry = provision_registry(
        directory.path(),
        "artifacts/registry.v1.sqlite3",
        "artifacts/registry-authorities.v1",
        NETWORK,
        7,
        &facts,
    )
    .expect("the registry provisions");

    let input = RouteTermsInputV1 {
        state_dir: directory.path(),
        upstream_relative: UPSTREAM_TERMS,
        downstream_relative: DOWNSTREAM_TERMS,
        registry: &registry,
        solana: &facts,
        provisioning_dir: &leg_store_dir,
        upstream: position(0x11),
        downstream: position(0x22),
        now_seconds: 1_800_000_000,
        dom_anchor_height: 1,
    };
    let (terms, positions) = provision_terms(&input).expect("both positions establish");
    let solana_chain_id = registry.solana_chain_id;
    let dom_chain_id = registry.dom_chain_id;
    let dom_asset_id = registry.dom_asset_id;
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_cluster(facts.genesis_hash)
        .with_registry(registry)
        .with_terms(terms);
    let [upstream, downstream] = positions;

    // The check the daemon itself performs on a Solana position, run here on the
    // artifacts as provisioned rather than on values assembled for the assertion.
    for provisioned in [&upstream, &downstream] {
        solana_profile::validate_setup(
            &provisioned.profile,
            &provisioned.terms,
            provisioned.binding.clone(),
        )
        .expect("the position authenticates under the profile the terms commit to");
    }

    Provisioned {
        directory,
        plan,
        upstream: upstream.terms,
        downstream: downstream.terms,
        solana_chain_id,
        dom_chain_id,
        dom_asset_id,
    }
}

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
fn both_positions_name_the_solana_chain_the_registry_declares() {
    let provisioned = provision_all();
    for terms in [&provisioned.upstream, &provisioned.downstream] {
        assert_eq!(
            terms.counterparty_leg.chain_id.0, provisioned.solana_chain_id,
            "the daemon resolves the position's chain by this id; a mismatch resolves nothing"
        );
        assert_eq!(
            terms.counterparty_leg.mechanism,
            kaystra_core::types::LockMechanism::CrossCurveConditionLock
        );
    }
    assert_ne!(
        provisioned.upstream.settlement_id, provisioned.downstream.settlement_id,
        "a route is two distinct settlements even on one cluster"
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

#[test]
fn the_terms_move_three_pins_and_leave_the_rest_declared_placeholders() {
    let provisioned = provision_all();
    assert_eq!(
        provisioned.plan.measured_pin_count(),
        7,
        "four from the registry and three from the terms"
    );
    assert!(
        provisioned.plan.pins_are_placeholders(),
        "twelve pins are still labels and the plan must keep saying so"
    );
}
