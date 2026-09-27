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
    registry::{
        provision as provision_registry, ProvisionedSolanaRegistryV1,
        RegistryProvisioningInputV1, SolanaChainFactsV1,
    },
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

/// A trusted second that is neither zero nor near an overflow, so the manifest's
/// window, the policy's window and the two schedules can all be expressed relative to
/// it. Fixed rather than read from the clock: a fixture whose artifacts change with
/// the wall clock cannot be reasoned about when it fails.
pub const NOW_SECONDS: u64 = 1_800_000_000;

/// The two clusters, one per position.
///
/// They are DIFFERENT clusters, and not by preference: `RouteTimePolicyV2::from_registry`
/// refuses a route whose two counterparty legs carry the same chain id unless the
/// DOM/XMR mainnet profile is selected. So a Solana route in both directions is
/// `Solana(A) -> DOM -> Solana(B)`.
pub fn upstream_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x7c; 32],
        escrow_program: [0x3c; 32],
        program_data_hash: [0x44; 32],
        network: chain_profile::SolanaNetworkV1::LocalValidator,
        max_fee_lamports: 50_000,
    }
}

pub fn downstream_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x8d; 32],
        escrow_program: [0x4e; 32],
        program_data_hash: [0x55; 32],
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
    pub dom_chain_id: [u8; 32],
    pub dom_asset_id: [u8; 32],
    /// The established positions, kept whole: the participant bindings are built
    /// from these, and only these carry the profile and the DLEQ binding.
    pub upstream_setup: ProvisionedPositionV1,
    pub downstream_setup: ProvisionedPositionV1,
    /// The two clusters, as the registry entries were built from them.
    pub upstream_facts: SolanaChainFactsV1,
    pub downstream_facts: SolanaChainFactsV1,
    /// The provisioned registry itself, so a test can rebuild the plan with only the
    /// artifacts its own subject depends on and assert what that one artifact adds.
    pub registry: ProvisionedSolanaRegistryV1,
}

pub fn provision_all() -> Provisioned {
    let directory = tempfile::tempdir().expect("a private working directory");
    // Separate from the state directory on purpose: the leg's setup store is not a
    // path role of the daemon's layout.
    let provisioning = tempfile::tempdir().expect("a private provisioning directory");
    let leg_store_dir = provisioning.path().join("leg");
    let upstream_facts = upstream_facts();
    let downstream_facts = downstream_facts();
    let registry = provision_registry(&RegistryProvisioningInputV1 {
        state_dir: directory.path(),
        registry_relative: "artifacts/registry.v1.sqlite3",
        authorities_relative: "artifacts/registry-authorities.v1",
        network_id: NETWORK,
        epoch: 7,
        now_seconds: NOW_SECONDS,
        // Wide enough that the route-time policy's own window fits inside it, which the
        // policy requires of the manifest that authorises it.
        valid_from_offset_seconds: 86_400,
        valid_until_offset_seconds: 86_400,
        upstream: &upstream_facts,
        downstream: &downstream_facts,
    })
    .expect("the registry provisions");

    let input = RouteTermsInputV1 {
        state_dir: directory.path(),
        upstream_relative: UPSTREAM_TERMS,
        downstream_relative: DOWNSTREAM_TERMS,
        registry: &registry,
        upstream_solana: &upstream_facts,
        downstream_solana: &downstream_facts,
        provisioning_dir: &leg_store_dir,
        upstream: position(0x11),
        downstream: position(0x22),
        now_seconds: NOW_SECONDS,
        dom_anchor_height: 1,
    };
    let (terms, positions) = provision_terms(&input).expect("both positions establish");
    let dom_chain_id = registry.dom_chain_id;
    let dom_asset_id = registry.dom_asset_id;
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        upstream_facts.genesis_hash,
        downstream_facts.genesis_hash,
    )
    .with_registry(registry) // Copy, so the value above stays usable
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
        registry,
        upstream_setup: upstream.clone(),
        downstream_setup: downstream.clone(),
        upstream_facts,
        downstream_facts,
        upstream: upstream.terms,
        downstream: downstream.terms,
        dom_chain_id,
        dom_asset_id,
    }
}

