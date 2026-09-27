//! The provisioned route every test in this directory asserts against.
//!
//! One fixture, built once per test: the signed registry, then both positions
//! established through the leg laboratory, then the Relay roster derived from the
//! terms. Each test then asserts one property of it, so a failure names which
//! property broke rather than which test happened to run first.
//!
// One shared module compiled into each test binary, so items a given binary does not
// reach are not dead code in the crate -- only in that binary.
#![allow(dead_code)]

use dom_solana_daemon_route::{
    registry::{provision as provision_registry, SolanaChainFactsV1},
    participants::provision as provision_participants,
    roster::provision as provision_roster,
    terms::{
        provision as provision_terms, ProvisionedPositionV1, RouteTermsInputV1,
        SolanaPositionAccountsV1, SolanaPositionTermsPlanV1,
    },
    SolanaRouteBootstrapPlanV1,
};
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use solana_types::SolanaPubkey;

pub const NETWORK: [u8; 32] = [0x90; 32];
pub const UPSTREAM_TERMS: &str = "artifacts/upstream-terms.v1";
pub const DOWNSTREAM_TERMS: &str = "artifacts/downstream-terms.v1";
pub const RELAY_ROSTER: &str = "artifacts/relay-roster.v1";
pub const PARTICIPANT_BINDINGS: &str = "artifacts/participant-bindings.v1";

pub fn solana_facts() -> SolanaChainFactsV1 {
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
pub fn accounts(seed: u8) -> SolanaPositionAccountsV1 {
    SolanaPositionAccountsV1 {
        funder: SolanaPubkey([seed; 32]),
        beneficiary: SolanaPubkey([seed.wrapping_add(1); 32]),
        refund_recipient: SolanaPubkey([seed.wrapping_add(2); 32]),
        amount: 5_000_000,
    }
}

pub fn position(seed: u8) -> SolanaPositionTermsPlanV1 {
    SolanaPositionTermsPlanV1 {
        settlement_id: [seed; 32],
        session_id: [seed.wrapping_add(0x40); 32],
        dom_beneficiary: ParticipantId([seed.wrapping_add(0x80); 32]),
        dom_refund_to: ParticipantId([seed.wrapping_add(0xa0); 32]),
        dom_amount_noms: 4_000_000,
        accounts: accounts(seed),
    }
}

pub struct Provisioned {
    pub directory: tempfile::TempDir,
    pub plan: SolanaRouteBootstrapPlanV1,
    pub upstream: SettlementTermsV1,
    pub downstream: SettlementTermsV1,
    pub solana_chain_id: [u8; 32],
    pub dom_chain_id: [u8; 32],
    pub dom_asset_id: [u8; 32],
    /// The established positions, kept whole: the participant bindings are built
    /// from these, and only these carry the profile and the DLEQ binding.
    pub upstream_setup: ProvisionedPositionV1,
    pub downstream_setup: ProvisionedPositionV1,
    pub facts: SolanaChainFactsV1,
}

pub fn provision_all() -> Provisioned {
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

    // The roster is a function of the frozen terms, so it is provisioned after them
    // and from them, never alongside.
    let roster = provision_roster(
        directory.path(),
        RELAY_ROSTER,
        plan.network_id,
        plan.route_id,
        &upstream.terms,
        &downstream.terms,
    )
    .expect("the roster provisions from both terms");
    let plan = plan.with_roster(roster);

    // The participant bindings carry the two setups the leg produced, so they are
    // provisioned from the established positions and not from the terms alone.
    let participants = provision_participants(
        directory.path(),
        PARTICIPANT_BINDINGS,
        plan.route_id,
        &upstream,
        &downstream,
    )
    .expect("the participant bindings provision from both setups");
    let plan = plan.with_participants(participants);

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
        upstream_setup: upstream.clone(),
        downstream_setup: downstream.clone(),
        facts,
        upstream: upstream.terms,
        downstream: downstream.terms,
        solana_chain_id,
        dom_chain_id,
        dom_asset_id,
    }
}

