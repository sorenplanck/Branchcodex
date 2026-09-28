//! One complete laboratory route, provisioned end to end.
//!
//! Everything this crate writes, in the order the artifacts depend on each other: the
//! signed registry, both frozen terms, the Relay roster, the participant bindings, the
//! signed time policy and evidence, the Contracts budget policy and the transport identity
//! authority.
//!
//! # Why this is not test code
//!
//! It began as a test fixture, and that was wrong twice over. A ceremony has to be driven
//! by a program rather than by a test harness -- `bootstrap_command_v13` is a command that
//! reads a plan from a path and secrets from stdin -- so the route it is given has to be
//! provisionable outside `cargo test`. And a fixture that provisions half the route lets a
//! path the ceremony names go missing without anything noticing, which is exactly what
//! happened twice while the plans were being written.
//!
//! # What is laboratory about it
//!
//! The values: two stand-in clusters, one participant pair, one passphrase, one set of
//! chain observations. A deployment supplies its own and holds its own secrets. Every
//! module this calls says the same thing about its own material -- the condition scalar,
//! the authority keys, the roster secrets -- and this one says it about the route.

use std::path::Path;

use kaystra_core::types::ParticipantId;
use solana_types::SolanaPubkey;

use crate::ceremony::CeremonyPlanInputV1;
use crate::declared_inputs;
use crate::participants::provision as provision_participants;
use crate::registry::{
    provision as provision_registry, ProvisionedSolanaRegistryV1, RegistryProvisioningInputV1,
    SolanaChainFactsV1,
};
use crate::roster::{provision as provision_roster, ProvisionedRelayRosterV1};
use crate::route_time::{provision as provision_route_time, ChainObservationV1, RouteTimeInputV1};
use crate::terms::{
    provision as provision_terms, ProvisionedPositionV1, ProvisionedRouteTermsV1,
    RouteTermsInputV1, SolanaPositionAccountsV1, SolanaPositionTermsPlanV1,
};
use crate::{RouteIdentitiesV1, SolanaRouteBootstrapPlanV1};

/// The interop network this laboratory route belongs to.
pub const NETWORK: [u8; 32] = [0x90; 32];

/// The trusted second the tests provision around.
///
/// Fixed, because a route whose artifacts change with the wall clock cannot be reasoned
/// about when it fails. That is right for a test and WRONG for the ceremony: `load_context`
/// validates the registry with `SystemTime::now()`, not with a trusted second from the
/// plan, so a route anchored on a fictional time is refused as not yet valid -- with
/// `Binding`, which says nothing about clocks.
///
/// So the second is a parameter of [`provision`]. Tests pass this constant; anything that
/// will hand the route to the ceremony passes the real clock.
pub const NOW_SECONDS: u64 = 1_800_000_000;

/// The real clock, for a route that will be handed to the ceremony.
pub fn now_seconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|error| format!("the system clock is before the epoch: {error}"))
}

/// The DOM chain position everything is anchored at.
///
/// ONE value, used both to plan the schedules and to build the hub checkpoint, because
/// they are the same chain position. Planning from one height and telling the evidence the
/// hub was at another puts a refund deadline behind the hub's own anchor, and the route
/// ladder refuses that with `DeadlinePassed`.
pub const DOM_ANCHOR_HEIGHT: u64 = 1;

/// The laboratory passphrase that opens the Contracts transport identity authority.
pub const IDENTITY_PASSPHRASE: &str = "a laboratory contracts identity passphrase";

/// The passphrase a run offers for the DOM wallet.
///
/// Distinct from [`IDENTITY_PASSPHRASE`] because the secret stream refuses any two secrets
/// that repeat, and the two passphrases are compared against each other and against every
/// key. It is laboratory material: the wallet these provisioning steps place is a stand-in,
/// and replacing both with deployment material is the operator's step.
pub const WALLET_PASSPHRASE: &str = "a laboratory dom wallet passphrase";

/// The intent both positions of this route execute.
pub const ROUTE_INTENT: [u8; 32] = [0x49; 32];

/// Where each party's Contracts transport identity authority lives.
///
/// TWO of them, because each party opens its own with its own passphrase, and because the
/// ceremony derives that party's participant id from the identity it opens. The layout
/// declares one such directory -- the local daemon's -- so the first is inside the state
/// directory and the second is beside it, under the provisioning root. The ceremony plan
/// takes an absolute path, so it does not care which.
pub const IDENTITY_PARTY_0: &str = "state/contracts/transport-identity-v1";
pub const IDENTITY_PARTY_1: &str = "identity-party-1/transport-identity-v1";

/// The layout paths this route provisions into, named once.
pub const REGISTRY_STORE: &str = "artifacts/registry.v1.sqlite3";
pub const REGISTRY_AUTHORITIES: &str = "artifacts/registry-authorities.v1";
pub const UPSTREAM_TERMS: &str = "artifacts/upstream-terms.v1";
pub const DOWNSTREAM_TERMS: &str = "artifacts/downstream-terms.v1";
pub const RELAY_ROSTER: &str = "artifacts/relay-roster.v1";
pub const PARTICIPANT_BINDINGS: &str = "artifacts/participant-bindings.v1";
pub const TIME_POLICY: &str = "artifacts/time-policy.v1";
pub const TIME_EVIDENCE: &str = "artifacts/time-evidence.v1";

/// The upstream cluster: where the operation that BEGINS on Solana settles.
pub fn upstream_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x7c; 32],
        escrow_program: [0x3c; 32],
        program_data_hash: [0x44; 32],
        network: chain_profile::SolanaNetworkV1::LocalValidator,
        max_fee_lamports: 50_000,
    }
}

/// The downstream cluster: where the operation that ENDS on Solana settles. A different
/// cluster, because the route-time policy refuses two counterparty legs on one chain.
pub fn downstream_facts() -> SolanaChainFactsV1 {
    SolanaChainFactsV1 {
        genesis_hash: [0x8d; 32],
        escrow_program: [0x4e; 32],
        program_data_hash: [0x55; 32],
        network: chain_profile::SolanaNetworkV1::LocalValidator,
        max_fee_lamports: 50_000,
    }
}

/// The six declared identities.
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

/// Distinct, non-zero accounts. A zero funder is refused by `validate_setup`.
pub fn accounts(seed: u8) -> SolanaPositionAccountsV1 {
    SolanaPositionAccountsV1 {
        funder: SolanaPubkey([seed; 32]),
        beneficiary: SolanaPubkey([seed.wrapping_add(1); 32]),
        refund_recipient: SolanaPubkey([seed.wrapping_add(2); 32]),
        amount: 5_000_000,
    }
}

/// One position's plan. The two parties are the same on both; only the settlement and the
/// session differ, because a route is two settlements between the same two people.
///
/// The parties are passed in rather than chosen: a participant id is derived from that
/// participant's identity key, so it is not available until the identities exist.
pub fn position(seed: u8, parties: [ParticipantId; 2]) -> SolanaPositionTermsPlanV1 {
    SolanaPositionTermsPlanV1 {
        settlement_id: [seed; 32],
        session_id: [seed.wrapping_add(0x40); 32],
        dom_beneficiary: parties[0],
        dom_refund_to: parties[1],
        dom_amount_noms: 4_000_000,
        accounts: accounts(seed),
    }
}

/// One chain's observation, chosen to satisfy what `validate_checkpoint` requires: every
/// hash non-zero with the tip's distinct from the anchor's, an interval inside the policy's
/// width ceiling whose lower end is not further ahead than the future skew and whose upper
/// end is recent enough for the observation, and a tip clearing the anchor's confirmations.
pub fn observation(seed: u8, anchor_height: u64, now_seconds: u64) -> ChainObservationV1 {
    ChainObservationV1 {
        anchor_height,
        anchor_hash: [seed; 32],
        parent_hash: [seed.wrapping_add(1); 32],
        time_lower_seconds: now_seconds - 300,
        time_upper_seconds: now_seconds - 60,
        tip_height: anchor_height + 5,
        tip_hash: [seed.wrapping_add(2); 32],
        canonicality_evidence_digest: [seed.wrapping_add(3); 32],
    }
}

/// Everything one provisioned route is.
#[derive(Clone, Debug)]
pub struct LaboratoryRouteV1 {
    pub plan: SolanaRouteBootstrapPlanV1,
    pub registry: ProvisionedSolanaRegistryV1,
    pub terms: ProvisionedRouteTermsV1,
    pub roster: ProvisionedRelayRosterV1,
    pub upstream: ProvisionedPositionV1,
    pub downstream: ProvisionedPositionV1,
    pub upstream_facts: SolanaChainFactsV1,
    pub downstream_facts: SolanaChainFactsV1,
    /// The second this route was provisioned around. Everything that later hands it to the
    /// daemon or to the ceremony must use the same one.
    pub now_seconds: u64,
    /// The two parties, in the order the roster names them: ascending, because
    /// `SettlementTermsV1::validate` refuses an unsorted roster.
    pub parties: [ParticipantId; 2],
    /// Each party's identity authority, in party order.
    pub identity_stores: [std::path::PathBuf; 2],
    /// Each party's identity key, in party order, so a caller can check that a plan names the
    /// participant its own authority derives.
    pub identity_keys: [[u8; 33]; 2],
    /// The direction each party's roster role implies, in party order.
    pub identity_directions: [dom_adaptor::DirectionV1; 2],
}

/// Provision the whole route into `state_dir`, using `provisioning_dir` for everything the
/// daemon's layout does not declare.
pub fn provision(
    state_dir: &Path,
    provisioning_dir: &Path,
    now_seconds: u64,
) -> Result<LaboratoryRouteV1, String> {
    let leg_store_dir = provisioning_dir.join("leg");
    let upstream_facts = upstream_facts();
    let downstream_facts = downstream_facts();

    let registry = provision_registry(&RegistryProvisioningInputV1 {
        state_dir,
        registry_relative: REGISTRY_STORE,
        authorities_relative: REGISTRY_AUTHORITIES,
        network_id: NETWORK,
        epoch: 7,
        now_seconds,
        // Wide enough that the route-time policy's own window fits inside it, which the
        // policy requires of the manifest that authorises it.
        valid_from_offset_seconds: 86_400,
        valid_until_offset_seconds: 86_400,
        upstream: &upstream_facts,
        downstream: &downstream_facts,
    })?;

    // The two identity authorities, and the participant ids they speak for.
    //
    // A participant id is NOT a label this crate may choose: `audit_retained_participant_id_v1`
    // recomputes it from the identity's Schnorr key and the DOM chain id and refuses anything
    // else. So the identities come before the terms, and the terms name what they derive.
    let mut pairs = Vec::with_capacity(2);
    for (index, (root, relative)) in [
        (state_dir, IDENTITY_PARTY_0),
        (provisioning_dir, IDENTITY_PARTY_1),
    ]
    .into_iter()
    .enumerate()
    {
        let key = declared_inputs::create_contracts_transport_identity(
            root,
            relative,
            IDENTITY_PASSPHRASE.as_bytes(),
        )?;
        // The direction does not enter the derivation; the roster role it implies does.
        let direction = if index == 0 {
            dom_adaptor::DirectionV1::Initiator
        } else {
            dom_adaptor::DirectionV1::Responder
        };
        let participant = ParticipantId(declared_inputs::participant_id_for_identity(
            registry.dom_genesis_hash,
            registry.dom_network_magic,
            &key,
            direction,
        )?);
        pairs.push((participant, root.join(relative), key, direction));
    }

    // Sorted as PAIRS, never as two lists.
    //
    // The roster needs its members ascending -- `SettlementTermsV1::validate` refuses an
    // unsorted roster and the relay bundle's shape check refuses members that do not ascend
    // -- and a participant id is derived from an identity, so sorting the ids alone
    // renumbers them out from under the authorities they came from. A plan would then pair
    // one party's participant id with the other party's identity, and the ceremony would
    // open that identity, derive its participant id and find the plan naming someone else.
    //
    // That refusal is `Binding`, and it is a COIN FLIP: the identities are generated fresh
    // each run, so the sort swaps about half the time. The ceremony completed on one run and
    // refused on the next with no relevant change between them, which is what sent this
    // hunting through the intent hash and the adaptor point before the evidence named it.
    pairs.sort_by_key(|(participant, ..)| *participant);
    if pairs[0].0 == pairs[1].0 {
        return Err("both identities derived the same participant".to_owned());
    }
    let parties = [pairs[0].0, pairs[1].0];
    let identity_stores = [pairs[0].1.clone(), pairs[1].1.clone()];
    // The key and the direction travel INSIDE the pair for the same reason the store does:
    // the sort reorders the parties, so anything indexed by the pre-sort position afterwards
    // is the same defect wearing a different name.
    let identity_keys = [pairs[0].2, pairs[1].2];
    let identity_directions = [pairs[0].3, pairs[1].3];

    let (terms, positions) = provision_terms(&RouteTermsInputV1 {
        state_dir,
        upstream_relative: UPSTREAM_TERMS,
        downstream_relative: DOWNSTREAM_TERMS,
        registry: &registry,
        upstream_solana: &upstream_facts,
        downstream_solana: &downstream_facts,
        provisioning_dir: &leg_store_dir,
        // One intent for the route, because a route is one intent carried out as two
        // settlements. `ComposedBindingV2::bind` refuses two.
        intent_hash: ROUTE_INTENT,
        upstream: position(0x11, parties),
        downstream: position(0x22, parties),
        now_seconds,
        dom_anchor_height: DOM_ANCHOR_HEIGHT,
    })?;
    let [upstream, downstream] = positions;

    // Identities before the roster and the bindings: both carry the route id, and the
    // loader refuses either one whose route id is not the pinned one.
    let plan = SolanaRouteBootstrapPlanV1::both_positions_on_solana(
        upstream_facts.genesis_hash,
        downstream_facts.genesis_hash,
    )
    .with_identities(identities())
    .with_registry(registry)
    .with_terms(terms);

    let roster = provision_roster(
        state_dir,
        RELAY_ROSTER,
        plan.network_id,
        plan.route_id,
        &upstream.terms,
        &downstream.terms,
    )?;
    let plan = plan.with_roster(roster);

    let participants = provision_participants(
        state_dir,
        PARTICIPANT_BINDINGS,
        plan.route_id,
        &upstream,
        &downstream,
    )?;
    let plan = plan.with_participants(participants);

    let route_time = provision_route_time(&RouteTimeInputV1 {
        state_dir,
        registry_relative: REGISTRY_STORE,
        authorities_relative: REGISTRY_AUTHORITIES,
        policy_relative: TIME_POLICY,
        evidence_relative: TIME_EVIDENCE,
        registry: &registry,
        upstream: &upstream.terms,
        downstream: &downstream.terms,
        now_seconds,
        provisioning_dir: &leg_store_dir,
        hub: observation(0x61, DOM_ANCHOR_HEIGHT, now_seconds),
        upstream_chain: observation(0x71, 4_000, now_seconds),
        downstream_chain: observation(0x81, 5_000, now_seconds),
        sequence: 1,
    })?;
    let plan = plan.with_route_time(route_time);

    // The budget policy the layout requires and the ceremony PARSES. The identity authorities
    // were created above, before the terms, because the participants are derived from them.
    declared_inputs::write_contracts_budget_policy(
        state_dir,
        SolanaRouteBootstrapPlanV1::contracts_budget_policy_relative(),
    )?;

    Ok(LaboratoryRouteV1 {
        plan,
        registry,
        terms,
        roster,
        upstream,
        downstream,
        upstream_facts,
        downstream_facts,
        now_seconds,
        parties,
        identity_stores,
        identity_keys,
        identity_directions,
    })
}

impl LaboratoryRouteV1 {
    /// The ceremony plan input this route implies.
    pub fn ceremony_input<'a>(&'a self, state_dir: &'a Path) -> CeremonyPlanInputV1<'a> {
        CeremonyPlanInputV1 {
            state_dir,
            registry: &self.registry,
            terms: &self.terms,
            roster: &self.roster,
            route_id: self.plan.route_id,
            parties: [self.parties[0].0, self.parties[1].0],
            identity_stores: [&self.identity_stores[0], &self.identity_stores[1]],
        }
    }
}
