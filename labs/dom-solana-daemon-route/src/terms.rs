//! The two frozen settlement terms of the route, and the Solana setup binding
//! each position is authenticated under.
//!
//! These three pins -- `upstream_terms_digest`, `downstream_terms_digest` and
//! `route_scope_digest` -- are what turn the route from a shape the manifest
//! encodes into a settlement the daemon can resolve, because the terms are where
//! the counterparty chain is named. `authenticate_participant_bundle` resolves a
//! position's chain by `terms.counterparty_leg.chain_id` through the authenticated
//! registry, and it is the resulting `ChainKindV1::Solana` that makes the daemon
//! demand a Solana session binding for that position at all.
//!
//! # Why the two positions are exactly the two claim orders
//!
//! The daemon states what its positions mean: `Upstream` is "counterparty funds the
//! DOM hub" and `Downstream` is "DOM hub funds the counterparty exit". For a route
//! whose counterparty positions are both Solana that reads:
//!
//! * `Upstream` -- the operation that BEGINS on Solana. Value enters the hub from
//!   the cluster, so the DOM side claims first and the DOM kernel's excess
//!   signature is what discloses the scalar. That is `ClaimOrderV1::DomFirst`, and
//!   its schedule is anchored by choosing the DOM refund height.
//! * `Downstream` -- the operation that ENDS on Solana. Value leaves the hub to the
//!   cluster, so the escrow `Claim` instruction discloses the scalar first. That is
//!   `ClaimOrderV1::SolanaFirst`, anchored by choosing the escrow deadline.
//!
//! So the route the daemon admits is not a new arrangement to be invented here: it
//! is the pair of claim orders the leg laboratory already executes against a live
//! cluster, one per position. That is why this module builds its artifacts by
//! calling that laboratory's `SolanaLegV1::establish` rather than assembling terms
//! of its own. `establish` needs no cluster -- it takes a setup store and an RNG --
//! and it returns both halves this bootstrap needs at once: the frozen terms, and
//! the `SolanaSetupBindingV1` whose DLEQ is the anchor `validate_setup` checks.
//!
//! # What provisioning a condition means here
//!
//! `establish` is the side that HOLDS the secret scalar: it generates the condition
//! and freezes the terms around its secp256k1 face. A real deployment has the two
//! participants do this between themselves, and the provisioner of a route never
//! sees the scalar. This laboratory provisioner generates it locally, which is
//! stated plainly rather than hidden: the artifacts it writes are a route this host
//! could settle by itself, and the split is a separate step, not an omission with
//! no consequence.

use std::path::Path;

use dom_core::{BlockHeight, Timestamp};
use dom_solana_direct_lab::{
    leg::{LegPlanInputV1, SolanaLegV1},
    time_bounds::{
        AssumedDomAnchor, AssumedLegDelaysV1, DomClockNetwork, RelativeDeadlineV1, ScheduleAnchorV1,
    },
};
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use route_time_anchor::route_scope_digest;
use sha2::{Digest, Sha256};
use solana_profile::{
    SolanaAdapterProfileV1, SolanaAssetV1, SolanaNetwork, SolanaSetupBindingV1,
};
use solana_setup_store::SolanaSetupStore;
use solana_types::SolanaPubkey;

use crate::registry::{
    dom_finality, solana_finality, ProvisionedSolanaRegistryV1, SolanaChainFactsV1,
};

/// Conservative observation delays the schedule is planned against.
///
/// Assumptions, not measurements, and deliberately generous: a schedule too tight
/// for a slow host turns into a refusal at planning time rather than a settlement
/// that cannot be claimed in time.
const DELAYS: AssumedLegDelaysV1 = AssumedLegDelaysV1 {
    solana_resolution_secs: 10,
    observation_secs: 5,
    dom_resolution_secs: 10,
};

/// The Solana accounts one position settles between, and the amount it moves.
///
/// On a live cluster all four come from the harness. Nothing here invents an
/// account: a zero funder is refused by `validate_setup`, so an unset field fails
/// closed instead of producing terms that look complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaPositionAccountsV1 {
    /// Pays the escrow and is refunded if the deadline passes.
    pub funder: SolanaPubkey,
    /// Receives the claim path.
    pub beneficiary: SolanaPubkey,
    /// Receives the refund path.
    pub refund_recipient: SolanaPubkey,
    /// Base units moved on the cluster: lamports for native SOL.
    pub amount: u64,
}

/// One position's full plan: the identifiers the daemon pins, and the Solana side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaPositionTermsPlanV1 {
    /// Exact settlement this position is.
    pub settlement_id: [u8; 32],
    /// Exact signing session this position is; never the settlement id.
    pub session_id: [u8; 32],
    /// The two DOM-side participants. They are what the relay roster must name.
    pub dom_beneficiary: ParticipantId,
    pub dom_refund_to: ParticipantId,
    /// Base units moved on the DOM side.
    pub dom_amount_noms: u64,
    /// The Solana accounts and amount.
    pub accounts: SolanaPositionAccountsV1,
}

/// Everything the provisioner is given that it does not derive.
#[derive(Clone, Copy, Debug)]
pub struct RouteTermsInputV1<'a> {
    /// The bootstrap state directory the layout is rooted at.
    pub state_dir: &'a Path,
    /// The layout's own relative path for `ProductionPathRoleV1::UpstreamTerms`.
    pub upstream_relative: &'a str,
    /// The layout's own relative path for `ProductionPathRoleV1::DownstreamTerms`.
    pub downstream_relative: &'a str,
    /// The registry these terms must agree with: it names the DOM hub, both clusters
    /// and every native asset.
    pub registry: &'a ProvisionedSolanaRegistryV1,
    /// The cluster the upstream position settles on, exactly as the registry entry was
    /// built from it. The escrow program id and the program-data hash are re-checked
    /// against the registry by the daemon, so they are taken from the same place here.
    pub upstream_solana: &'a SolanaChainFactsV1,
    /// The cluster the downstream position settles on. A different one: the route-time
    /// policy refuses two counterparty legs that share a chain.
    pub downstream_solana: &'a SolanaChainFactsV1,
    /// The position that begins on Solana.
    pub upstream: SolanaPositionTermsPlanV1,
    /// The position that ends on Solana.
    pub downstream: SolanaPositionTermsPlanV1,
    /// Where the leg laboratory's own setup store goes.
    ///
    /// Deliberately not inside `state_dir`: that tree is the daemon's layout, every
    /// entry of it is a path role the bootstrap declares, and the setup store is not
    /// one of them. Writing it there would put a file the daemon never named inside
    /// the directory it validates.
    pub provisioning_dir: &'a Path,
    /// Trusted wall clock, seconds. The schedule is planned from it.
    pub now_seconds: u64,
    /// The DOM chain height the schedule is anchored at.
    pub dom_anchor_height: u64,
}

/// One provisioned position, with everything the later artifacts need.
///
/// Not `Copy`: the terms carry metadata and the binding carries a DLEQ proof.
#[derive(Clone, Debug)]
pub struct ProvisionedPositionV1 {
    /// The frozen terms, exactly as the artifact on disk decodes them.
    pub terms: SettlementTermsV1,
    /// `terms_hash()`, which is the daemon's pin for this position.
    pub terms_digest: [u8; 32],
    /// The adapter profile the terms' `adapter_profile_hash` commits to.
    pub profile: SolanaAdapterProfileV1,
    /// The setup binding whose DLEQ authenticates this position. The participant
    /// bindings artifact is built from these.
    pub binding: SolanaSetupBindingV1,
}

/// The three pins the terms determine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedRouteTermsV1 {
    pub upstream_terms_digest: [u8; 32],
    pub downstream_terms_digest: [u8; 32],
    /// The ordered scope the V2 time authority signs over, which is a digest of
    /// both canonical terms in position order and not of either alone.
    pub route_scope_digest: [u8; 32],
}

/// The adapter profile both sides of a position read the leg under.
///
/// `require_immutable_program` is forced on. `SolanaAdapterProfileV1::new` leaves it
/// off for a local validator, and the daemon refuses a Solana position whose profile
/// does not require it -- so a local route that did not set it would provision an
/// artifact the daemon declines to authenticate.
fn profile(
    solana: &SolanaChainFactsV1,
) -> Result<SolanaAdapterProfileV1, String> {
    let network = match solana.network {
        chain_profile::SolanaNetworkV1::Devnet => SolanaNetwork::Devnet,
        chain_profile::SolanaNetworkV1::Testnet => SolanaNetwork::Testnet,
        chain_profile::SolanaNetworkV1::LocalValidator => SolanaNetwork::LocalValidator,
    };
    let mut profile = SolanaAdapterProfileV1::new(network, SolanaPubkey(solana.escrow_program), 3, 2)
        .map_err(|error| format!("adapter profile: {error:?}"))?;
    profile.require_immutable_program = true;
    // Native SOL only, for now: a token position needs the mint in the terms' asset
    // id and a token account per role, and `allow_legacy_spl` is inside
    // `profile_hash`, so the two are different profiles rather than one with a flag.
    profile.allow_legacy_spl = false;
    Ok(profile)
}

/// Build one position's plan input. The claim order is not a field: it follows from
/// which deadline the caller fixes, which is why `chosen_deadline` is the only place
/// the two positions differ in kind.
#[allow(clippy::too_many_arguments)]
fn plan_input(
    position: &SolanaPositionTermsPlanV1,
    input: &RouteTermsInputV1<'_>,
    solana: &SolanaChainFactsV1,
    solana_chain_id: [u8; 32],
    solana_asset_id: [u8; 32],
    solana_profile_digest: [u8; 32],
    chosen_deadline: ScheduleAnchorV1,
) -> LegPlanInputV1 {
    LegPlanInputV1 {
        settlement_id: position.settlement_id,
        session_id: position.session_id,
        intent_hash: derived(b"DOM-SOLANA-DAEMON-ROUTE/INTENT/V1\0", &position.settlement_id),
        solver_id: derived(b"DOM-SOLANA-DAEMON-ROUTE/SOLVER/V1\0", &position.settlement_id),
        dom_chain_id: input.registry.dom_chain_id,
        dom_asset_id: input.registry.dom_asset_id,
        dom_amount_noms: position.dom_amount_noms,
        dom_beneficiary: position.dom_beneficiary,
        dom_refund_to: position.dom_refund_to,
        // Read from the registry module, never restated: the daemon refuses a route
        // whose terms declare a finality the registry does not.
        dom_finality: dom_finality(),
        dom_fee_max: 1_000,
        // Measured from the installed registry, never derived here: the route-time
        // policy refuses terms whose DOM leg carries any other value.
        dom_leg_profile_hash: input.registry.dom_profile_digest,
        // The registry's chain-profile digest for this cluster, not the adapter
        // profile's own hash: three components of an admitted route compare the
        // counterparty leg's adapter_profile_hash with exactly this value.
        counterparty_profile_digest: Some(solana_profile_digest),
        cluster_genesis: solana_chain_id,
        solana_asset_id,
        asset: SolanaAssetV1::NativeSol,
        lamports: position.accounts.amount,
        funder: position.accounts.funder,
        beneficiary: position.accounts.beneficiary,
        refund_recipient: position.accounts.refund_recipient,
        funder_token_account: None,
        beneficiary_token_account: None,
        refund_token_account: None,
        solana_finality: solana_finality(),
        solana_fee_max: 100_000,
        program_data_hash: solana.program_data_hash,
        anchor: AssumedDomAnchor::new(
            BlockHeight(input.dom_anchor_height),
            Timestamp(input.now_seconds),
        ),
        now: Timestamp(input.now_seconds),
        network: DomClockNetwork::Regtest,
        validator_clock_ahead_secs: 0,
        delays: DELAYS,
        chosen_deadline,
        evidence_retention_blocks: 1_000,
        policy_version: 1,
    }
}

fn derived(domain: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(seed);
    hasher.finalize().into()
}

/// Freeze both positions, write both artifacts, and return the three pins.
///
/// The artifacts are written exactly as `decode_terms` reads them back: the
/// canonical bytes of valid terms, whose `terms_hash()` is the pin. A file this
/// writes and a pin this returns therefore agree by construction, and the test
/// re-derives both from the file rather than trusting the return value.
pub fn provision(
    input: &RouteTermsInputV1<'_>,
) -> Result<(ProvisionedRouteTermsV1, [ProvisionedPositionV1; 2]), String> {
    // One profile per cluster: the profile commits to the escrow program id, and the
    // two clusters run their own deployment of it.
    let upstream_profile = profile(input.upstream_solana)?;
    let downstream_profile = profile(input.downstream_solana)?;
    // The upstream position begins on Solana, so its DOM refund height is the
    // chosen anchor; the downstream ends on Solana, so its escrow deadline is.
    // Each order requires the LATER deadline for whoever claims second, and
    // `LegScheduleV1::plan` derives that second deadline rather than accepting one.
    let anchor = AssumedDomAnchor::new(
        BlockHeight(input.dom_anchor_height),
        Timestamp(input.now_seconds),
    );
    let now = Timestamp(input.now_seconds);
    // Both are expressed relative to the anchor and resolved against it, which is
    // what `RelativeDeadlineV1` exists for: a provisioner fixes how far ahead the
    // deadline sits, never an absolute value it would have to guess the tip for.
    //
    // 600 blocks is not arbitrary. `earliest_refund_time` subtracts the network's
    // future-block tolerance (120 s on regtest) from the anchor's timestamp plus one
    // second per block, so a gap smaller than that tolerance plus the DOM resolution
    // delay puts the DOM deadline at or before now and the schedule is refused for
    // leaving the first claimant no window at all.
    let upstream = establish(
        input,
        &upstream_profile,
        input.upstream_solana,
        input.registry.upstream_chain_id,
        input.registry.upstream_asset_id,
        input.registry.upstream_profile_digest,
        &input.upstream,
        RelativeDeadlineV1::DomRefundBlocksAhead(600)
            .resolve(&anchor, now)
            .map_err(|error| format!("upstream deadline: {error:?}"))?,
        "upstream",
    )?;
    let downstream = establish(
        input,
        &downstream_profile,
        input.downstream_solana,
        input.registry.downstream_chain_id,
        input.registry.downstream_asset_id,
        input.registry.downstream_profile_digest,
        &input.downstream,
        RelativeDeadlineV1::EscrowRefundSecondsAhead(3_600)
            .resolve(&anchor, now)
            .map_err(|error| format!("downstream deadline: {error:?}"))?,
        "downstream",
    )?;

    write_terms(
        &input.state_dir.join(input.upstream_relative),
        &upstream.terms,
    )?;
    write_terms(
        &input.state_dir.join(input.downstream_relative),
        &downstream.terms,
    )?;

    let scope = route_scope_digest(&upstream.terms, &downstream.terms)
        .map_err(|error| format!("route scope digest: {error:?}"))?;
    Ok((
        ProvisionedRouteTermsV1 {
            upstream_terms_digest: upstream.terms_digest,
            downstream_terms_digest: downstream.terms_digest,
            route_scope_digest: scope,
        },
        [upstream, downstream],
    ))
}

/// Establish one position through the leg laboratory, offline.
#[allow(clippy::too_many_arguments)]
fn establish(
    input: &RouteTermsInputV1<'_>,
    profile: &SolanaAdapterProfileV1,
    solana: &SolanaChainFactsV1,
    solana_chain_id: [u8; 32],
    solana_asset_id: [u8; 32],
    solana_profile_digest: [u8; 32],
    position: &SolanaPositionTermsPlanV1,
    chosen_deadline: ScheduleAnchorV1,
    label: &str,
) -> Result<ProvisionedPositionV1, String> {
    crate::owner_only::directory(input.provisioning_dir)?;
    let store = SolanaSetupStore::open(
        input
            .provisioning_dir
            .join(format!("solana-setup-{label}.sqlite3")),
    )
    .map_err(|error| format!("{label} setup store: {error:?}"))?;
    let plan = plan_input(
        position,
        input,
        solana,
        solana_chain_id,
        solana_asset_id,
        solana_profile_digest,
        chosen_deadline,
    );
    let established = SolanaLegV1::establish(&plan, profile, &store, &mut rand::rngs::OsRng)
        .map_err(|error| format!("{label} leg: {error:?}"))?;
    let leg = established.leg();
    let terms = leg.terms().clone();
    let terms_digest = terms
        .terms_hash()
        .map_err(|error| format!("{label} terms hash: {error:?}"))?;
    Ok(ProvisionedPositionV1 {
        terms,
        terms_digest,
        profile: *profile,
        binding: leg.setup().binding().clone(),
    })
}

fn write_terms(path: &Path, terms: &SettlementTermsV1) -> Result<(), String> {
    let bytes = terms
        .canonical_bytes()
        .map_err(|error| format!("terms bytes: {error:?}"))?;
    crate::owner_only::write(path, &bytes)
}
