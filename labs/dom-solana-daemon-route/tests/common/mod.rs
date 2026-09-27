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
    declared_inputs,
    registry::{
        provision as provision_registry, ProvisionedSolanaRegistryV1,
        RegistryProvisioningInputV1, SolanaChainFactsV1,
    },
    participants::provision as provision_participants,
    roster::provision as provision_roster,
    route_time::{provision as provision_route_time, ChainObservationV1, RouteTimeInputV1},
    terms::{
        provision as provision_terms, ProvisionedPositionV1, RouteTermsInputV1,
        SolanaPositionAccountsV1, SolanaPositionTermsPlanV1,
    },
    RouteIdentitiesV1, SolanaRouteBootstrapPlanV1,
};
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use solana_types::SolanaPubkey;

pub const NETWORK: [u8; 32] = [0x90; 32];
pub const UPSTREAM_TERMS: &str = "artifacts/upstream-terms.v1";
pub const DOWNSTREAM_TERMS: &str = "artifacts/downstream-terms.v1";
pub const RELAY_ROSTER: &str = "artifacts/relay-roster.v1";
pub const PARTICIPANT_BINDINGS: &str = "artifacts/participant-bindings.v1";
pub const TIME_POLICY: &str = "artifacts/time-policy.v1";
pub const TIME_EVIDENCE: &str = "artifacts/time-evidence.v1";

/// One chain's observation, chosen to satisfy the rules `validate_checkpoint` applies.
///
/// * every hash non-zero, and the tip's distinct from the anchor's, because a tip at
///   the anchor's own height must carry the anchor's own hash;
/// * the interval 240 seconds wide, inside the policy's 600-second ceiling;
/// * its lower endpoint in the past, so it is not further ahead than the 120 seconds of
///   future skew the policy admits;
/// * its upper endpoint recent enough that the observation is not later than
///   `time_upper + 900`;
/// * the tip five blocks past the anchor, which clears
///   `anchor_height + min_confirmations - 1` for a policy requiring one confirmation.
pub fn observation(seed: u8, anchor_height: u64) -> ChainObservationV1 {
    ChainObservationV1 {
        anchor_height,
        anchor_hash: [seed; 32],
        parent_hash: [seed.wrapping_add(1); 32],
        time_lower_seconds: NOW_SECONDS - 300,
        time_upper_seconds: NOW_SECONDS - 60,
        tip_height: anchor_height + 5,
        tip_hash: [seed.wrapping_add(2); 32],
        canonicality_evidence_digest: [seed.wrapping_add(3); 32],
    }
}

/// A trusted second that is neither zero nor near an overflow, so the manifest's
/// window, the policy's window and the two schedules can all be expressed relative to
/// it. Fixed rather than read from the clock: a fixture whose artifacts change with
/// the wall clock cannot be reasoned about when it fails.
pub const NOW_SECONDS: u64 = 1_800_000_000;

/// The DOM chain position everything is anchored at.
///
/// ONE value, used both to plan the schedule and to build the hub checkpoint, because
/// they are the same chain position. The first version planned the schedule from height
/// one and told the evidence the hub was at height nine hundred, which put the upstream
/// DOM refund height six hundred blocks BEHIND the hub's own anchor -- and the route
/// ladder refused it with `DeadlinePassed`, correctly.
pub const DOM_ANCHOR_HEIGHT: u64 = 1;

/// The laboratory passphrase that opens the Contracts transport identity authority.
///
/// A laboratory holds one and says so. A deployment's belongs to whoever holds the
/// identity, and the ceremony reads it from stdin for exactly that reason.
pub const IDENTITY_PASSPHRASE: &[u8] = b"a laboratory contracts identity passphrase";

/// The two clusters, one per position.
///
/// They are DIFFERENT clusters, and not by preference: `RouteTimePolicyV2::from_registry`
/// refuses a route whose two counterparty legs carry the same chain id unless the
/// DOM/XMR mainnet profile is selected. So a Solana route in both directions is
/// `Solana(A) -> DOM -> Solana(B)`.
/// The six declared identities, fixed for the fixture.
///
/// Declared BEFORE the roster and the participant bindings are provisioned, because
/// `route_id` is one of them and both of those artifacts carry it: the roster bundle and
/// the participant bundle are each refused if their route id is not the pinned one. The
/// first version of this fixture provisioned them from the placeholder id and declared
/// the real one afterwards, and the loader answered `PinMismatch` -- correctly.
pub fn identities() -> RouteIdentitiesV1 {
    RouteIdentitiesV1 {
        route_id: [0x31; 32],
        process_owner_id: [0x32; 32],
        coordinator_id: [0x33; 32],
        coordinator_plan_authority_id: [0x34; 32],
        actuator_bindings_digest: [0x35; 32],
        solver_inventory_binding_digest: [0x36; 32],
    }
}

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

/// The two parties of the route, shared by BOTH positions.
///
/// A route is two settlements between the same two participants, which is why
/// `RouteTimePolicyV2::from_registry` requires both terms to name the same DOM chain, the
/// same native asset and the same DOM adapter profile: the hub leg is one leg seen twice.
/// The Contracts bootstrap ceremony reads the same way -- it is bilateral, and a party
/// declares which legs it is in by which relay secrets it supplies.
///
/// An earlier fixture derived a different pair per position from the position's own seed.
/// Nothing had refused it yet, because nothing before the ceremony compares the two legs'
/// rosters, but it described a route whose two settlements were between four people.
pub const PARTY_A: ParticipantId = ParticipantId([0xa1; 32]);
pub const PARTY_B: ParticipantId = ParticipantId([0xb2; 32]);

pub fn position(seed: u8) -> SolanaPositionTermsPlanV1 {
    SolanaPositionTermsPlanV1 {
        settlement_id: [seed; 32],
        session_id: [seed.wrapping_add(0x40); 32],
        // Sorted by `LegPlanInputV1::roster`, so which one is beneficiary and which is
        // refund is the route's choice and not an ordering accident.
        dom_beneficiary: PARTY_A,
        dom_refund_to: PARTY_B,
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

impl Provisioned {
    /// The registry as the daemon resolves it: loaded from the store through the
    /// authenticated bundle, never from the manifest that was handed to the store.
    pub fn resolved_registry(&self) -> deployment_registry::ResolvedRegistryV1 {
        let bytes = std::fs::read(
            self.directory
                .path()
                .join("artifacts/registry-authorities.v1"),
        )
        .expect("the authority bundle was written");
        let bundle = dom_interopd::ProductionAuthorityBundleV1::decode_canonical(&bytes)
            .expect("the authority bundle decodes");
        deployment_registry::RegistryStoreV1::open_existing(
            &self.directory.path().join("artifacts/registry.v1.sqlite3"),
        )
        .expect("the registry store opens")
        .load_current(
            bundle.registry(),
            &btc_crypto::SecpContext::new(&[0x5a; 32]),
            deployment_registry::RegistryValidationPolicyV1 {
                now_seconds: NOW_SECONDS,
                expected_network_id: self.registry.network_id,
                minimum_epoch: self.registry.epoch,
            },
        )
        .expect("the registry loads")
        .expect("the store holds a current registry")
    }
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
        dom_anchor_height: DOM_ANCHOR_HEIGHT,
    };
    let (terms, positions) = provision_terms(&input).expect("both positions establish");
    let dom_chain_id = registry.dom_chain_id;
    let dom_asset_id = registry.dom_asset_id;
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        upstream_facts.genesis_hash,
        downstream_facts.genesis_hash,
    )
    // Identities first: the roster and the participant bindings below carry the route id,
    // and the loader refuses either one whose route id is not the pinned one.
    .with_identities(identities())
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
    // artifacts as provisioned rather than on values assembled for the assertion --
    // and with the digest the daemon resolves, which is the registry's chain-profile
    // digest and not the adapter profile's own hash.
    for (provisioned, expected) in [
        (&upstream, registry.upstream_profile_digest),
        (&downstream, registry.downstream_profile_digest),
    ] {
        solana_profile::validate_setup_with_profile_digest(
            &provisioned.profile,
            &provisioned.terms,
            provisioned.binding.clone(),
            expected,
        )
        .expect("the position authenticates against the registry-resolved profile digest");
    }

    // The time authority: the policy is rebuilt from the registry and both terms by the
    // daemon's own constructor, so it is provisioned last, from everything before it.
    let route_time = provision_route_time(&RouteTimeInputV1 {
        state_dir: directory.path(),
        registry_relative: "artifacts/registry.v1.sqlite3",
        authorities_relative: "artifacts/registry-authorities.v1",
        policy_relative: TIME_POLICY,
        evidence_relative: TIME_EVIDENCE,
        registry: &registry,
        upstream: &upstream.terms,
        downstream: &downstream.terms,
        now_seconds: NOW_SECONDS,
        provisioning_dir: &leg_store_dir,
        // The hub's anchor is the DOM position the schedule was planned from, not an
        // unrelated height.
        hub: observation(0x61, DOM_ANCHOR_HEIGHT),
        upstream_chain: observation(0x71, 4_000),
        downstream_chain: observation(0x81, 5_000),
        sequence: 1,
    })
    .expect("the time policy and its evidence provision");
    let plan = plan.with_route_time(route_time);

    // The Contracts budget policy: an input the layout requires and the ceremony plan
    // names, so it belongs to provisioning the route like the identity authority below.
    declared_inputs::write_contracts_budget_policy(
        directory.path(),
        SolanaRouteBootstrapPlanV1::contracts_budget_policy_relative(),
        b"a budget policy this deployment decided",
    )
    .expect("the Contracts budget policy");

    // The Contracts transport identity authority. Part of provisioning the route, not of
    // one test: the ceremony plans name it, and the layout requires it to exist.
    declared_inputs::create_contracts_transport_identity(
        directory.path(),
        SolanaRouteBootstrapPlanV1::contracts_transport_identity_relative(),
        IDENTITY_PASSPHRASE,
    )
    .expect("the transport identity authority");

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

