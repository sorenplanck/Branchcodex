//! DOM<->Solana, both directions, against a real DOM node and a real Solana
//! cluster. Every transaction in these scenarios is submitted to a node: the DOM
//! ones through the node's own admission and miner paths, the Solana ones through
//! JSON-RPC to a validator that has the escrow deployed and its upgrade
//! authority revoked.
//!
//! Run them through the harness, which is what exports the values they refuse to
//! invent:
//!
//! ```text
//! bash scripts/f8-run-solana-live-v1.sh \
//!   cargo test --manifest-path labs/dom-solana-direct/Cargo.toml \
//!     --test solana_leg_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # What each scenario proves
//!
//! * `sol_to_dom` — DOM claims first. The DOM kernel's excess signature is the
//!   only place the scalar appears, the counterparty extracts it from the block
//!   the node accepted, and that extracted scalar claims the escrow.
//! * `dom_to_sol` — Solana claims first. The scalar appears in the escrow's
//!   instruction data and in its state account, and the DOM side completes its
//!   claim from what it read off the cluster.
//! * `both_refunds` — nobody claims. The escrow refuses `Refund` before its
//!   frozen deadline, accepts it after, and the DOM height-locked refund is
//!   refused before its height and accepted after. The adapted DOM claim, built
//!   and valid, loses to the confirmed refund.
//!
//! In all three, the two parties derive the settlement independently: one runs
//! `establish` and the other `accept` from nothing but the public input and the
//! DLEQ proof, into a separate setup store, and the two setups must agree.
//!
//! # Stated limits
//!
//! Both DOM participants run in this one process. The cryptography is real —
//! two shares, two nonces, possession proofs, a joint bulletproof — but the
//! separation of the two parties is simulated, and nothing here authenticates an
//! identity. The DOM chain is regtest. A local cluster is not mainnet-beta.

mod support;

use dom_core::{BlockHeight, Timestamp};
use dom_solana_direct_lab::{
    cluster::ClusterSessionV1,
    condition::ConditionOpeningV1,
    leg::{EstablishedLegV1, LegPlanInputV1, SolanaLegV1},
    time_bounds::{
        AssumedDomAnchor, AssumedLegDelaysV1, ClaimOrderV1, DomClockNetwork, RelativeDeadlineV1,
        ScheduleAnchorV1,
    },
};
use kaystra_core::{
    settlement_engine::ChainRecordV1,
    state::EvidenceRefV1,
    types::{ChainId, FinalityPolicyV1, ParticipantId},
};
use sha2::{Digest, Sha256};
use solana_evidence::{
    SolanaClaimEvidenceV1, SolanaEvidenceBodyV1, SolanaEvidenceEnvelopeV1, SolanaFundingEvidenceV1,
    SolanaRefundEvidenceV1,
};
use solana_kaystra_records::{claim_record, funding_record, refund_record};
use solana_kaystra_source::{VerifiedSolanaEventKind, VerifiedSolanaFeed};
use solana_observation_store::SqliteVerifiedSolanaFeed;
use solana_observer_pump::{observe_and_persist, PumpError};
use solana_observer::{ObservationKind, ObserverError, SolanaSettlementObserver};
use solana_profile::{SolanaAdapterProfileV1, SolanaAssetV1, SolanaNetwork};
use solana_program_attestation::{
    attest_immutable_program, code_hash, PROGRAM_DATA_METADATA_LEN,
};
use solana_secret_store::{EncryptedSqliteWitnessStore, SecretStoreMasterKey};
use solana_setup_store::SolanaSetupStore;
// The trait must be in scope to call `get_transaction` on the HTTP client.
use solana_rpc::{HttpSolanaRpc, SolanaRpc as _};
use solana_types::{
    Commitment, LegacyTokenAccount, SolanaAccountMeta, SolanaInstruction, SolanaPubkey,
    SolanaSignature, SYSTEM_PROGRAM_ID,
};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{
    dom_regtest::{FundedDom, CLAIM_FEE, RESERVE_VALUE},
    harness::{hex32, LiveEnvironment, CONFIRM_TIMEOUT},
};

/// One SOL. Well inside what the harness airdrops to each role.
const LAMPORTS: u64 = 1_000_000_000;

/// One whole token at the mint's six decimals, in base units. Well inside what
/// the harness mints to the funder.
const SPL_BASE_UNITS: u64 = 1_000_000;

/// Bounds on each step, deliberately generous: a bound that is too tight turns a
/// slow CI runner into a false refusal, and these are assumptions, not
/// measurements.
const DELAYS: AssumedLegDelaysV1 = AssumedLegDelaysV1 {
    solana_resolution_secs: 10,
    observation_secs: 5,
    dom_resolution_secs: 10,
};

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

/// Labels for the two DOM-leg participants. The DOM side's real identity is its
/// reserve share key; these are the terms' opaque participant ids, derived so
/// they are distinct, deterministic and bound to the settlement.
fn participant(settlement_id: &[u8; 32], role: &str) -> ParticipantId {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-SOLANA-DIRECT-LAB/participant/v1\0");
    hasher.update(settlement_id);
    hasher.update(role.as_bytes());
    ParticipantId(hasher.finalize().into())
}

/// The profile both parties use. `require_immutable_program` is forced on even
/// though `SolanaAdapterProfileV1::new` leaves it off for a local validator:
/// the harness really does revoke the upgrade authority and really does measure
/// the programdata account, so the local run enforces the same rule production
/// enforces instead of a weaker one.
fn profile(program_id: SolanaPubkey, allow_legacy_spl: bool) -> SolanaAdapterProfileV1 {
    let mut profile = SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program_id, 1, 1)
        .expect("a one-node local profile");
    profile.require_immutable_program = true;
    // `allow_legacy_spl` is inside `profile_hash`, which the terms bind, so a
    // native settlement and a token settlement are not the same profile and the
    // two sides of one leg must use the same one.
    profile.allow_legacy_spl = allow_legacy_spl;
    profile
}

/// What attestation established about the deployed program.
struct AttestedProgram {
    /// The canonical hash this project binds for a Solana program: `code_hash`
    /// over the program's code region, with its domain tag and length. This is the value
    /// the setup binding carries, not a hash of the whole account.
    code_hash: [u8; 32],
    deployment_slot: u64,
    observed_context_slot: u64,
    padding_bytes: usize,
}

/// Establish, through this project's own attestation, that the deployed program
/// is the one that was built and that nobody can replace it.
///
/// Three things are checked here and none of them is assumed:
///
/// 1. the bytes in the programdata account's code region are byte-for-byte the
///    object the `program` job built, and everything past them is zero padding.
///    This is the only non-circular link between the artifact and the chain: the
///    expected hash below is then determined by the built file plus the account's
///    length, so nothing about the on-chain content is taken on trust;
/// 2. `attest_immutable_program` re-reads both accounts THROUGH THE QUORUM the
///    profile declares, at `Finalized`, and enforces this project's rule for an
///    immutable program: loader ownership, both loader-state discriminants, an
///    absent upgrade authority, and that code hash;
/// 3. the programdata address the program account itself points at is the one the
///    harness reported.
///
/// The leg used to hand-roll (2) and bind a sha256 of the entire account. Using
/// the project's component instead means the leg binds what the rest of the system
/// binds, and it was that component's rule -- `Option` tag must be 0 -- that
/// forced the harness to revoke a real authority instead of loading one that
/// cannot sign.
fn attest_program(
    cluster: &ClusterSessionV1,
    environment: &LiveEnvironment,
    profile: &SolanaAdapterProfileV1,
) -> AttestedProgram {
    cluster
        .wait_for_finalized_slot(Duration::from_secs(120))
        .expect("the cluster finalizes a slot");
    let pool = cluster
        .quorum_pool(
            usize::from(profile.rpc_node_count),
            usize::from(profile.rpc_quorum),
        )
        .expect("a pool matching the profile's declared quorum");

    // The harness revoked the authority and saw it confirmed. Confirmed is not
    // finalized, and at `Finalized` the account can still carry the authority it
    // had before: run 36286771205 failed here with `UpgradeAuthorityPresent`
    // against a program whose revocation the harness had already verified. So wait
    // for the revocation to reach the commitment the attestation reads at -- which
    // is a different question from "has any slot been finalized", the one that was
    // being asked.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let snapshot = pool
            .account(environment.programdata, Commitment::Finalized)
            .expect("the quorum answers for the programdata account");
        let revoked = snapshot
            .as_ref()
            .is_some_and(|account| account.data.len() > 12 && account.data[12] == 0);
        if revoked {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the revocation did not reach finalized commitment within 120s"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // Read the region at the SAME commitment the attestation hashes it at, so the
    // bytes compared against the built object are the bytes attested.
    let account = pool
        .account(environment.programdata, Commitment::Finalized)
        .expect("the quorum answers for the programdata account")
        .expect("the programdata account exists")
        .data;
    assert!(
        account.len() > PROGRAM_DATA_METADATA_LEN,
        "programdata holds {} bytes, too few for the loader header and a program",
        account.len()
    );
    let region = &account[PROGRAM_DATA_METADATA_LEN..];
    let built = std::fs::read(&environment.program_so).unwrap_or_else(|error| {
        panic!(
            "cannot read the built object at {}: {error}",
            environment.program_so.display()
        )
    });
    assert!(
        region.len() >= built.len(),
        "the on-chain code region is {} bytes, smaller than the {} byte object built",
        region.len(),
        built.len()
    );
    assert_eq!(
        &region[..built.len()],
        built.as_slice(),
        "the bytes on chain are not the bytes the program job built"
    );
    let padding = &region[built.len()..];
    assert!(
        padding.iter().all(|byte| *byte == 0),
        "the {} bytes past the program are not zero padding; they begin {}",
        padding.len(),
        hex_bytes(&padding[..padding.len().min(16)])
    );

    let mut expected_region = built;
    expected_region.resize(region.len(), 0);
    let expected = code_hash(&expected_region);
    let attestation = attest_immutable_program(&pool, environment.program_id, expected)
        .expect("the deployed program attests as immutable and as the object built");
    assert_eq!(
        attestation.program_data_address, environment.programdata,
        "the program points at a different programdata account than the harness reported"
    );
    assert_eq!(attestation.code_hash, expected);
    AttestedProgram {
        code_hash: attestation.code_hash,
        deployment_slot: attestation.deployment_slot,
        observed_context_slot: attestation.observed_context_slot,
        padding_bytes: padding.len(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Fixture {
    environment: LiveEnvironment,
    cluster: ClusterSessionV1,
    profile: SolanaAdapterProfileV1,
    program: AttestedProgram,
}

impl Fixture {
    fn open() -> Self {
        let environment = LiveEnvironment::from_env();
        let profile = profile(environment.program_id, false);
        let cluster = ClusterSessionV1::connect(
            &environment.rpc_url,
            profile.max_signed_transaction_bytes as usize,
        )
        .expect("the harness cluster answers");
        assert_eq!(
            cluster.genesis(),
            environment.genesis,
            "the cluster this test reached is not the one the harness started"
        );
        let program = attest_program(&cluster, &environment, &profile);
        Self {
            environment,
            cluster,
            profile,
            program,
        }
    }
}

/// The public input both parties agree on. `chosen` fixes one deadline; the other
/// is derived, and which one is fixed decides the claim order.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn leg_input(
    fixture: &Fixture,
    settlement_id: [u8; 32],
    dom_chain_id: [u8; 32],
    anchor: AssumedDomAnchor,
    chosen_deadline: ScheduleAnchorV1,
    funder: SolanaPubkey,
    beneficiary: SolanaPubkey,
    refund_recipient: SolanaPubkey,
    now: Timestamp,
    asset: SolanaAssetV1,
    amount: u64,
) -> LegPlanInputV1 {
    // Token accounts belong to a token settlement and to no other; the leg
    // refuses a plan that mixes the two shapes.
    let token = |account: SolanaPubkey| match asset {
        SolanaAssetV1::NativeSol => None,
        SolanaAssetV1::LegacySpl { .. } => Some(account),
    };
    // Hoisted: the DOM leg's adapter profile hash is derived from this same asset id,
    // and computing it twice would let the two drift.
    let dom_asset_id: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-SOLANA-DIRECT-LAB/dom-asset/v1\0");
        hasher.update(dom_chain_id);
        hasher.finalize().into()
    };
    LegPlanInputV1 {
        settlement_id,
        session_id: {
            let mut hasher = Sha256::new();
            hasher.update(b"DOM-SOLANA-DIRECT-LAB/session/v1\0");
            hasher.update(settlement_id);
            hasher.finalize().into()
        },
        intent_hash: {
            let mut hasher = Sha256::new();
            hasher.update(b"DOM-SOLANA-DIRECT-LAB/intent/v1\0");
            hasher.update(settlement_id);
            hasher.finalize().into()
        },
        solver_id: participant(&settlement_id, "solver").0,
        dom_chain_id,
        dom_asset_id,
        dom_amount_noms: RESERVE_VALUE - CLAIM_FEE,
        dom_beneficiary: participant(&settlement_id, "dom-receiver"),
        dom_refund_to: participant(&settlement_id, "dom-refund"),
        dom_finality: FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 8,
        },
        dom_fee_max: CLAIM_FEE,
        // No registry in this laboratory, so the leg's own stable derivation.
        dom_leg_profile_hash: LegPlanInputV1::derived_dom_leg_profile_hash(
            dom_chain_id,
            dom_asset_id,
        ),
        cluster_genesis: fixture.environment.genesis.0,
        solana_asset_id: {
            // Native SOL has no mint, so it is named by the cluster it is native
            // to rather than by a zero mint that would look like a token. A token
            // is named by its mint, which is what distinguishes two of them.
            let mut hasher = Sha256::new();
            match asset {
                SolanaAssetV1::NativeSol => {
                    hasher.update(b"DOM-SOLANA-DIRECT-LAB/native-sol/v1\0");
                    hasher.update(fixture.environment.genesis.0);
                }
                SolanaAssetV1::LegacySpl { mint, decimals } => {
                    hasher.update(b"DOM-SOLANA-DIRECT-LAB/legacy-spl/v1\0");
                    hasher.update(fixture.environment.genesis.0);
                    hasher.update(mint.0);
                    hasher.update([decimals]);
                }
            }
            hasher.finalize().into()
        },
        asset,
        lamports: amount,
        funder,
        beneficiary,
        refund_recipient,
        funder_token_account: token(fixture.environment.funder_token),
        beneficiary_token_account: token(fixture.environment.beneficiary_token),
        refund_token_account: token(fixture.environment.refund_token),
        solana_finality: FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 32,
        },
        solana_fee_max: 100_000,
        program_data_hash: fixture.program.code_hash,
        anchor,
        now,
        network: DomClockNetwork::Regtest,
        validator_clock_ahead_secs: 0,
        delays: DELAYS,
        chosen_deadline,
        evidence_retention_blocks: 1_000,
        policy_version: 1,
    }
}

fn store(root: &Path, name: &str) -> SolanaSetupStore {
    SolanaSetupStore::open(root.join(name)).expect("a fresh setup store")
}

/// The encrypted witness store. Its master key comes from outside the store in a
/// real deployment; here it is a fixed non-zero value, which is what makes this a
/// laboratory and not a key-management scheme.
fn witness_store(root: &Path, name: &str) -> EncryptedSqliteWitnessStore {
    EncryptedSqliteWitnessStore::open(
        root.join(name),
        SecretStoreMasterKey::new([0x5a; 32]).expect("a non-zero master key"),
    )
    .expect("a fresh encrypted witness store")
}

/// Assert the escrow state account says exactly what this side of the leg
/// believes, and return it.
fn escrow_state(
    cluster: &ClusterSessionV1,
    leg: &SolanaLegV1,
) -> solana_escrow_wire::EscrowStateV1 {
    let data = cluster
        .account_data(leg.setup().state_pda())
        .expect("the escrow state account");
    leg.read_escrow_state(&data)
        .expect("the escrow state belongs to this leg")
}

/// A legacy token account as the cluster holds it.
fn token_account(cluster: &ClusterSessionV1, account: SolanaPubkey) -> LegacyTokenAccount {
    let data = cluster
        .account_data(account)
        .unwrap_or_else(|error| panic!("token account {}: {error}", account.to_base58()));
    LegacyTokenAccount::decode(&data)
        .unwrap_or_else(|_| panic!("{} is not a legacy token account", account.to_base58()))
}

fn assert_opening_agrees(left: &ConditionOpeningV1, right: &ConditionOpeningV1) {
    assert_eq!(
        left.escrow_claim_bytes(),
        right.escrow_claim_bytes(),
        "the scalar read off a chain is not the scalar the secret holder had"
    );
}

// ── observation ─────────────────────────────────────────────────────────────

/// An observer for this leg, under the finality policy the TERMS declare.
///
/// The leg used to read an escrow account at `Confirmed` and treat the
/// settlement as done, while `min_confirmations` and `max_reorg_depth` sat in the
/// frozen terms unread -- a declared policy that nothing enforced. The value is
/// now read back out of the terms, so the policy enforced is demonstrably the
/// policy agreed.
fn observer_for(fixture: &Fixture, leg: &SolanaLegV1) -> SolanaSettlementObserver<HttpSolanaRpc> {
    let pool = fixture
        .cluster
        .quorum_pool(
            usize::from(fixture.profile.rpc_node_count),
            usize::from(fixture.profile.rpc_quorum),
        )
        .expect("a pool matching the profile's declared quorum");
    let min_confirmations = leg.terms().counterparty_leg.finality.min_confirmations;
    SolanaSettlementObserver::new(
        pool,
        leg.setup().clone(),
        *leg.profile(),
        min_confirmations,
    )
    .expect("an observer for this leg's frozen setup")
}

/// The durable feed for one settlement. One file per settlement, because the feed
/// is bound to a settlement and its terms and refuses to be shared.
fn feed(root: &Path, name: &str, leg: &SolanaLegV1) -> SqliteVerifiedSolanaFeed {
    SqliteVerifiedSolanaFeed::open(
        root.join(name),
        solana_chain_id(leg),
        leg.setup().settlement_id(),
        leg.setup().terms_hash(),
    )
    .expect("a fresh verified observation feed")
}

/// Observe a landed transaction once it satisfies the declared finality, and
/// persist what was verified.
///
/// An observation that lives only in the observing process is lost with it, and a
/// leg that resumed would have to verify the chain again to learn what it already
/// knew -- or worse, act as though nothing had happened. Persisting is therefore
/// part of observing here, not a later convenience.
///
/// Only two outcomes are waited on: not yet finalized, and not yet deep enough.
/// Everything else is a disagreement between the chain and what this leg
/// believes, and is raised immediately rather than retried until a timeout turns
/// it into a vague one.
fn observe_when_final(
    observer: &SolanaSettlementObserver<HttpSolanaRpc>,
    feed: &SqliteVerifiedSolanaFeed,
    chain_id: ChainId,
    signature: SolanaSignature,
    kind: ObservationKind,
) -> SolanaEvidenceEnvelopeV1 {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        match observe_and_persist(observer, feed, chain_id, signature, kind) {
            Ok(envelope) => return envelope,
            Err(error) => {
                assert!(
                    matches!(
                        &error,
                        PumpError::Observer(
                            ObserverError::NotFinalized | ObserverError::InsufficientDepth
                        )
                    ),
                    "observing {kind:?} for {}: {error}",
                    signature.to_base58()
                );
                assert!(
                    Instant::now() < deadline,
                    "{kind:?} for {} never reached the declared finality: {error}",
                    signature.to_base58()
                );
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

/// The feed must hold exactly the observation that was just verified, at the slot
/// it was verified in, and its tip must have advanced to cover it. A feed that
/// answered nothing would leave a resumed leg blind while looking healthy.
fn assert_feed_holds(
    feed: &SqliteVerifiedSolanaFeed,
    kind: VerifiedSolanaEventKind,
    evidence: &EvidenceRefV1,
) {
    let events = feed
        .events(evidence.block_height, evidence.block_height)
        .expect("the feed answers for the observed slot");
    assert!(
        events
            .iter()
            .any(|event| event.kind == kind && event.evidence == *evidence),
        "the feed does not hold the {kind:?} observation at slot {}; it holds {events:?}",
        evidence.block_height
    );
    let tip = feed.tip().expect("the feed answers for its tip");
    assert!(
        tip.is_some_and(|slot| slot >= evidence.block_height),
        "the feed tip {tip:?} does not cover the observed slot {}",
        evidence.block_height
    );
}

/// The neutral record the observed evidence becomes, and the checks that make it
/// a record about THIS settlement.
///
/// Evidence a settlement layer cannot ingest is evidence about nothing, so the
/// conversion is part of observing, not a separate nicety. The converters
/// re-validate the envelope and re-require its binding to the expected settlement
/// and terms, so a mismatch is refused here rather than carried forward. What
/// comes back is pinned to a block anchor, which is what makes a later reorg
/// detectable at all.
fn assert_record_pins_evidence(
    record: &ChainRecordV1,
    leg: &SolanaLegV1,
    signature: SolanaSignature,
    slot: u64,
) -> EvidenceRefV1 {
    let evidence = match record {
        ChainRecordV1::Funding { evidence }
        | ChainRecordV1::Claim { evidence }
        | ChainRecordV1::Refund { evidence } => *evidence,
        ChainRecordV1::Reorg { .. } => panic!("a settlement step became a reorg record"),
    };
    assert_eq!(
        evidence.chain_id.0, leg.terms().counterparty_leg.chain_id.0,
        "the record names a different chain than the terms froze"
    );
    assert_eq!(
        evidence.tx_id, signature.digest32(),
        "the record points at a different transaction"
    );
    assert_eq!(evidence.block_height, slot);
    assert_ne!(
        evidence.block_anchor, [0; 32],
        "evidence with no block anchor cannot be reorg-checked"
    );
    evidence
}

fn solana_chain_id(leg: &SolanaLegV1) -> ChainId {
    leg.terms().counterparty_leg.chain_id
}

fn funding_evidence(envelope: &SolanaEvidenceEnvelopeV1) -> &SolanaFundingEvidenceV1 {
    match &envelope.body {
        SolanaEvidenceBodyV1::Funding(body) => body,
        other => panic!("expected funding evidence, got {other:?}"),
    }
}

fn claim_evidence(envelope: &SolanaEvidenceEnvelopeV1) -> &SolanaClaimEvidenceV1 {
    match &envelope.body {
        SolanaEvidenceBodyV1::Claim(body) => body,
        other => panic!("expected claim evidence, got {other:?}"),
    }
}

fn refund_evidence(envelope: &SolanaEvidenceEnvelopeV1) -> &SolanaRefundEvidenceV1 {
    match &envelope.body {
        SolanaEvidenceBodyV1::Refund(body) => body,
        other => panic!("expected refund evidence, got {other:?}"),
    }
}

/// Every evidence body carries the same frozen identifiers; checking them once
/// per observation is what makes the envelope evidence about THIS settlement.
fn assert_binds_leg(
    leg: &SolanaLegV1,
    program_code_hash: &[u8; 32],
    settlement_id: &[u8; 32],
    terms_hash: &[u8; 32],
    program_data_hash: &[u8; 32],
    amount: u64,
) {
    assert_eq!(settlement_id, &leg.setup().settlement_id());
    assert_eq!(terms_hash, &leg.setup().terms_hash());
    assert_eq!(program_data_hash, program_code_hash);
    assert_eq!(amount, leg.setup().amount());
}

// ── SOL -> DOM ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires the live harness: scripts/f8-run-solana-live-v1.sh"]
fn solana_live_sol_to_dom_reveals_through_the_dom_claim() {
    let fixture = Fixture::open();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the DOM node");
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xA1; 32];

    // The party giving SOL is also the party receiving DOM, and it is the one
    // that holds the secret: it claims DOM first and thereby discloses it.
    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);

    let prepared = runtime.block_on(FundedDom::prepare_unfunded(&directory.path().join("dom")));
    let now = Timestamp(now_seconds());
    // Fixing the DOM refund height is what makes this the DOM-first order: the
    // escrow deadline is then derived to be the later of the two.
    let mut dom = runtime.block_on(FundedDom::fund_for_solana_leg(
        prepared,
        RelativeDeadlineV1::DomRefundBlocksAhead(400),
        DELAYS,
        now,
    ));
    let schedule = dom.leg_schedule().expect("a Solana leg schedule");
    assert_eq!(schedule.order, ClaimOrderV1::DomFirst);

    let input = leg_input(
        &fixture,
        settlement_id,
        *dom.claim.chain(),
        dom.anchor(),
        schedule.chosen(),
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        SolanaAssetV1::NativeSol,
        LAMPORTS,
    );

    // The secret holder establishes; the counterparty accepts from the proof
    // alone, into its own store, and the two derivations must agree.
    let established = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &store(directory.path(), "giver-setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("the SOL giver establishes the condition");
    let accepted = SolanaLegV1::accept(
        &input,
        &fixture.profile,
        established.proof(),
        &store(directory.path(), "receiver-setup.sqlite"),
    )
    .expect("the SOL receiver accepts the condition");
    assert_eq!(accepted.setup().setup_id(), established.leg().setup().setup_id());
    assert_eq!(accepted.schedule(), &schedule);
    assert_eq!(
        established.leg().schedule(),
        &schedule,
        "the schedule the reserve was funded under is not the one the leg derived"
    );

    // ── the escrow is stood up and funded by the SOL giver ──────────────────
    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
    // Funding is settled only once it satisfies the finality the terms declare.
    let observer = observer_for(&fixture, &accepted);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &funding.settlement_id,
        &funding.terms_hash,
        &funding.program_data_hash,
        funding.amount,
    );
    let funding_chain_record = funding_record(
        solana_chain_id(&accepted),
        funding,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the funding evidence converts to a neutral record");
    let funding_ref =
        assert_record_pins_evidence(&funding_chain_record, &accepted, fund_signature, funding.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);
    let funded = escrow_state(&fixture.cluster, &accepted);
    assert_eq!(funded.status, solana_escrow_wire::EscrowStatus::Funded);
    assert_eq!(funded.funded_amount, LAMPORTS);
    assert_eq!(funded.revealed_secret_be, [0; 32]);

    // A claim with a foreign opening is refused before it is ever submitted.
    let foreign = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &store(directory.path(), "foreign-setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("a second, unrelated condition");
    assert!(
        accepted
            .claim_instruction(&foreign.opening().expect("the foreign opening"))
            .is_err(),
        "an opening from another condition must not become a claim"
    );

    // ── the DOM claim is completed with the secret and published ────────────
    let opening = established.opening().expect("the established opening");
    let offer = dom.offer(
        &established.leg().lock().dom_adaptor_point(),
        established.leg().setup().setup_id(),
    );
    let context = runtime.block_on(dom.context());
    let claim_transaction = offer
        .complete(opening.dom_secret(), &context)
        .expect("the adapted DOM claim");
    let (published, dom_height) = runtime.block_on(dom.include(&claim_transaction));

    // ── the counterparty extracts the scalar from the block it observed ─────
    let extracted = offer
        .extract(&published, &runtime.block_on(dom.context()))
        .expect("the scalar the published DOM claim discloses");
    let from_chain = accepted
        .opening_from_dom_secret(extracted)
        .expect("the extracted scalar opens both faces");
    assert_opening_agrees(&from_chain, &opening);

    // ── and claims the escrow with it ───────────────────────────────────────
    let before = fixture
        .cluster
        .lamports(sol_receiver.public())
        .expect("the receiver balance");
    let vault_before = fixture
        .cluster
        .lamports(accepted.setup().vault_pda())
        .expect("the vault balance");
    let claim_signature = fixture
        .cluster
        .execute(
            &[accepted
                .claim_instruction(&from_chain)
                .expect("a native claim instruction")],
            &sol_receiver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("claim the escrow with the disclosed scalar");
    let claimed = escrow_state(&fixture.cluster, &accepted);
    assert_eq!(claimed.status, solana_escrow_wire::EscrowStatus::Claimed);
    assert_eq!(claimed.revealed_secret_be, opening.escrow_claim_bytes());
    let after = fixture
        .cluster
        .lamports(sol_receiver.public())
        .expect("the receiver balance");
    assert!(
        after > before,
        "the beneficiary did not gain: {before} -> {after}"
    );
    assert!(
        after - before >= LAMPORTS - 1_000_000,
        "the beneficiary gained {} of {LAMPORTS} lamports",
        after - before
    );
    let vault_after = fixture
        .cluster
        .lamports(accepted.setup().vault_pda())
        .expect("the vault balance");
    assert_eq!(vault_before - vault_after, LAMPORTS);

    // Independent confirmation, through the quorum and at the declared depth:
    // the scalar the escrow accepted is the one the DOM claim disclosed. The
    // observer re-derives it from the claim instruction and re-checks it against
    // the cross-curve claim, so this is not the leg agreeing with itself.
    let claim_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        claim_signature,
        ObservationKind::Claim,
    );
    let claim = claim_evidence(&claim_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &claim.settlement_id,
        &claim.terms_hash,
        &claim.program_data_hash,
        claim.amount,
    );
    assert_eq!(claim.revealed_secret_be, opening.escrow_claim_bytes());
    let claim_chain_record = claim_record(
        solana_chain_id(&accepted),
        claim,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the claim evidence converts to a neutral record");
    let claim_ref =
        assert_record_pins_evidence(&claim_chain_record, &accepted, claim_signature, claim.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Claim, &claim_ref);
    assert_ne!(
        claim_ref.tx_id, funding_ref.tx_id,
        "funding and claim must not resolve to the same transaction"
    );

    // The DOM output is spendable and the reserve cannot be spent twice.
    let onward_height = runtime.block_on(dom.prove_onward_spend_and_reject_double_spend());

    fixture.environment.record(
        "sol_to_dom",
        serde_json::json!({
            "status": "passed",
            "claim_order": "DomFirst",
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&accepted.setup().setup_id()),
            "dom_refund_height": schedule.dom_refund_height.0,
            "escrow_refund_after_unix": schedule.escrow_refund_after.0,
            "dom_claim_height": dom_height,
            "dom_onward_spend_height": onward_height,
            "escrow_claim_signature": claim_signature.to_base58(),
            "revealed_scalar_matches": true,
            "observed_min_confirmations":
                accepted.terms().counterparty_leg.finality.min_confirmations,
            "funding_observed_slot": funding.slot,
            "claim_observed_slot": claim.slot,
            "claim_instruction_index": claim.instruction_index,
            "claim_terminal_state_hash": hex32(&claim.terminal_state_hash),
            "claim_vault_hash": hex32(&claim.vault_hash),
            "funding_record_block_anchor": hex32(&funding_ref.block_anchor),
            "claim_record_block_anchor": hex32(&claim_ref.block_anchor),
            "program_code_hash_bound": hex32(&fixture.program.code_hash),
            "program_code_padding_bytes": fixture.program.padding_bytes,
            "programdata_account_sha256_reported_by_harness":
                hex32(&fixture.environment.programdata_sha256),
            "deployment_slot": fixture.program.deployment_slot,
            "attestation_observed_slot": fixture.program.observed_context_slot,
            "upgrade_authority": "revoked, attested absent",
            "timing_bounds_proven": false,
        }),
    );
}

// ── DOM -> SOL ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires the live harness: scripts/f8-run-solana-live-v1.sh"]
fn solana_live_dom_to_sol_reveals_through_the_escrow_claim() {
    let fixture = Fixture::open();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the DOM node");
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xB2; 32];

    // Now the party receiving SOL holds the secret: it claims the escrow first,
    // publishing the scalar on Solana, and the DOM side follows.
    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);

    let prepared = runtime.block_on(FundedDom::prepare_unfunded(&directory.path().join("dom")));
    let now = Timestamp(now_seconds());
    // Fixing the escrow deadline makes this the Solana-first order: the DOM
    // refund height is then derived to be the later of the two.
    let mut dom = runtime.block_on(FundedDom::fund_for_solana_leg(
        prepared,
        RelativeDeadlineV1::EscrowRefundSecondsAhead(600),
        DELAYS,
        now,
    ));
    let schedule = dom.leg_schedule().expect("a Solana leg schedule");
    assert_eq!(schedule.order, ClaimOrderV1::SolanaFirst);

    let input = leg_input(
        &fixture,
        settlement_id,
        *dom.claim.chain(),
        dom.anchor(),
        schedule.chosen(),
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        SolanaAssetV1::NativeSol,
        LAMPORTS,
    );
    // Both durable halves live here: the registered binding in the setup store,
    // the encrypted witness in the witness store. The session itself is dropped
    // below, before anything is funded, so the claim later in this scenario can
    // only be made by a leg that rebuilt itself from those two.
    let receiver_store = store(directory.path(), "receiver-setup.sqlite");
    let receiver_witness = witness_store(directory.path(), "receiver-witness.sqlite");
    let established = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &receiver_store,
        &mut rand::thread_rng(),
    )
    .expect("the SOL receiver establishes the condition");
    let accepted = SolanaLegV1::accept(
        &input,
        &fixture.profile,
        established.proof(),
        &store(directory.path(), "giver-setup.sqlite"),
    )
    .expect("the SOL giver accepts the condition");
    assert_eq!(accepted.setup().setup_id(), established.leg().setup().setup_id());
    assert_eq!(accepted.schedule(), &schedule);

    established
        .persist_witness(&receiver_witness, &mut rand::thread_rng())
        .expect("the witness is stored encrypted at rest");
    let opening_before_restart = established
        .opening()
        .expect("the established opening")
        .escrow_claim_bytes();
    // The restart. Everything the secret holder had in memory is gone.
    drop(established);

    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
    // Funding is settled only once it satisfies the finality the terms declare.
    let observer = observer_for(&fixture, &accepted);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &funding.settlement_id,
        &funding.terms_hash,
        &funding.program_data_hash,
        funding.amount,
    );
    let funding_chain_record = funding_record(
        solana_chain_id(&accepted),
        funding,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the funding evidence converts to a neutral record");
    let funding_ref =
        assert_record_pins_evidence(&funding_chain_record, &accepted, fund_signature, funding.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);
    assert_eq!(
        escrow_state(&fixture.cluster, &accepted).status,
        solana_escrow_wire::EscrowStatus::Funded
    );

    // ── the restarted leg rebuilds its session and claims ───────────────────
    // Close the feed and reopen it from the same file: a restarted leg recovers
    // what was written, not what an open handle happened to still hold.
    drop(observations);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);

    let resumed = EstablishedLegV1::resume(
        &input,
        &fixture.profile,
        &receiver_store,
        &receiver_witness,
        &mut rand::thread_rng(),
    )
    .expect("a restarted leg rebuilds its session from the two durable halves");
    assert_eq!(
        resumed.leg().setup().setup_id(),
        accepted.setup().setup_id(),
        "the resumed leg is not the settlement that was registered"
    );
    assert_eq!(resumed.leg().schedule(), &schedule);
    let opening = resumed.opening().expect("the resumed opening");
    assert_eq!(
        opening.escrow_claim_bytes(),
        opening_before_restart,
        "the resumed session opens a different condition than the one registered"
    );
    let before = fixture
        .cluster
        .lamports(sol_receiver.public())
        .expect("the receiver balance");
    let claim_signature = fixture
        .cluster
        .execute(
            &[resumed
                .leg()
                .claim_instruction(&opening)
                .expect("a native claim instruction")],
            &sol_receiver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("claim the escrow");
    let after = fixture
        .cluster
        .lamports(sol_receiver.public())
        .expect("the receiver balance");
    assert!(after - before >= LAMPORTS - 1_000_000);

    // Observed at the declared depth before the DOM side acts on it: in this
    // direction the escrow claim is what discloses the scalar, so acting on a
    // claim that had not yet finalized would be acting on a disclosure the chain
    // could still take back.
    let claim_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        claim_signature,
        ObservationKind::Claim,
    );
    let claim = claim_evidence(&claim_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &claim.settlement_id,
        &claim.terms_hash,
        &claim.program_data_hash,
        claim.amount,
    );
    assert_eq!(claim.revealed_secret_be, opening.escrow_claim_bytes());
    let claim_chain_record = claim_record(
        solana_chain_id(&accepted),
        claim,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the claim evidence converts to a neutral record");
    let claim_ref =
        assert_record_pins_evidence(&claim_chain_record, &accepted, claim_signature, claim.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Claim, &claim_ref);
    assert_ne!(claim_ref.tx_id, funding_ref.tx_id);

    // ── the DOM side reads the scalar off the cluster, two ways ─────────────
    let from_state = accepted
        .opening_from_escrow_state(
            &fixture
                .cluster
                .account_data(accepted.setup().state_pda())
                .expect("the escrow state account"),
        )
        .expect("the claimed escrow state discloses the scalar");
    assert_opening_agrees(&from_state, &opening);

    let record = {
        let mut found = None;
        let started = std::time::Instant::now();
        while started.elapsed() < CONFIRM_TIMEOUT {
            if let Some(record) = fixture
                .cluster
                .rpc()
                .get_transaction(claim_signature, Commitment::Confirmed)
                .expect("the RPC answers for a confirmed signature")
            {
                found = Some(record);
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        found.expect("the claim transaction is retrievable from the cluster")
    };
    assert!(record.success);
    let escrow_instruction = record
        .instructions
        .iter()
        .find(|instruction| instruction.program_id == fixture.environment.program_id)
        .expect("the claim transaction carries an escrow instruction");
    let from_instruction = accepted
        .opening_from_escrow_claim_data(&escrow_instruction.data)
        .expect("the claim instruction data discloses the scalar");
    assert_opening_agrees(&from_instruction, &opening);

    // ── and completes the DOM claim with it ─────────────────────────────────
    let offer = dom.offer(
        &accepted.lock().dom_adaptor_point(),
        accepted.setup().setup_id(),
    );
    let context = runtime.block_on(dom.context());
    let claim_transaction = offer
        .complete(from_state.dom_secret(), &context)
        .expect("the adapted DOM claim");
    let (published, dom_height) = runtime.block_on(dom.include(&claim_transaction));
    // The DOM claim discloses the same scalar the escrow already published: the
    // two legs are opened by one witness, which is the whole mechanism.
    let extracted = offer
        .extract(&published, &runtime.block_on(dom.context()))
        .expect("the scalar the DOM claim discloses");
    assert_eq!(*extracted, opening.escrow_claim_bytes());
    let onward_height = runtime.block_on(dom.prove_onward_spend_and_reject_double_spend());

    fixture.environment.record(
        "dom_to_sol",
        serde_json::json!({
            "status": "passed",
            "claim_order": "SolanaFirst",
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&accepted.setup().setup_id()),
            "dom_refund_height": schedule.dom_refund_height.0,
            "escrow_refund_after_unix": schedule.escrow_refund_after.0,
            "escrow_claim_signature": claim_signature.to_base58(),
            "dom_claim_height": dom_height,
            "dom_onward_spend_height": onward_height,
            "scalar_read_from_state_and_instruction": true,
            "claimed_by_a_leg_resumed_from_durable_halves": true,
            "observed_min_confirmations":
                accepted.terms().counterparty_leg.finality.min_confirmations,
            "funding_observed_slot": funding.slot,
            "claim_observed_slot": claim.slot,
            "claim_terminal_state_hash": hex32(&claim.terminal_state_hash),
            "funding_record_block_anchor": hex32(&funding_ref.block_anchor),
            "claim_record_block_anchor": hex32(&claim_ref.block_anchor),
            "timing_bounds_proven": false,
        }),
    );
}

// ── neither side claims ─────────────────────────────────────────────────────

#[test]
#[ignore = "requires the live harness and waits for two real deadlines"]
fn solana_live_both_refunds_return_each_side() {
    let fixture = Fixture::open();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the DOM node");
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xC3; 32];

    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);

    let prepared = runtime.block_on(FundedDom::prepare_unfunded(&directory.path().join("dom")));
    let now = Timestamp(now_seconds());
    // A deliberately short escrow deadline, so both timeouts are reachable
    // inside one run. Ninety seconds leaves room for standing the escrow up
    // before the deadline, which the early-refusal check below depends on. The DOM refund height is derived from it and is therefore
    // the later of the two, exactly as the Solana-first order requires.
    let mut dom = runtime.block_on(FundedDom::fund_for_solana_leg(
        prepared,
        RelativeDeadlineV1::EscrowRefundSecondsAhead(90),
        DELAYS,
        now,
    ));
    let schedule = dom.leg_schedule().expect("a Solana leg schedule");

    let input = leg_input(
        &fixture,
        settlement_id,
        *dom.claim.chain(),
        dom.anchor(),
        schedule.chosen(),
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        SolanaAssetV1::NativeSol,
        LAMPORTS,
    );
    let established = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &store(directory.path(), "receiver-setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("establish the condition");
    let accepted = SolanaLegV1::accept(
        &input,
        &fixture.profile,
        established.proof(),
        &store(directory.path(), "giver-setup.sqlite"),
    )
    .expect("accept the condition");

    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
    // Funding is settled only once it satisfies the finality the terms declare.
    let observer = observer_for(&fixture, &accepted);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &funding.settlement_id,
        &funding.terms_hash,
        &funding.program_data_hash,
        funding.amount,
    );
    let funding_chain_record = funding_record(
        solana_chain_id(&accepted),
        funding,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the funding evidence converts to a neutral record");
    let funding_ref =
        assert_record_pins_evidence(&funding_chain_record, &accepted, fund_signature, funding.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);

    // Build the adapted DOM claim now, while the shares are still available. It
    // is valid; it must still lose to the confirmed refund below.
    let opening = established.opening().expect("the established opening");
    let offer = dom.offer(
        &accepted.lock().dom_adaptor_point(),
        accepted.setup().setup_id(),
    );
    let losing_claim = offer
        .complete(opening.dom_secret(), &runtime.block_on(dom.context()))
        .expect("a valid adapted DOM claim");

    // ── the escrow refuses its refund before the frozen deadline ────────────
    let cluster_now = fixture
        .cluster
        .cluster_unix_time()
        .expect("the cluster clock");
    assert!(
        cluster_now < accepted.setup().refund_after_unix(),
        "the deadline had already passed before the refusal could be observed"
    );
    fixture
        .cluster
        .expect_refusal(
            &[accepted.refund_instruction().expect("a refund instruction")],
            &sol_refund,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("an early refund must be refused");
    // A refusal that came from something other than the deadline would leave the
    // escrow equally untouched, so also require that nothing moved.
    let still_funded = escrow_state(&fixture.cluster, &accepted);
    assert_eq!(still_funded.status, solana_escrow_wire::EscrowStatus::Funded);
    assert_eq!(still_funded.funded_amount, LAMPORTS);

    // ── after it, the refund is accepted ───────────────────────────────────
    fixture
        .cluster
        .wait_for_cluster_time(
            accepted.setup().refund_after_unix(),
            Duration::from_secs(300),
        )
        .expect("the cluster clock reaches the frozen deadline");
    let before = fixture
        .cluster
        .lamports(sol_refund.public())
        .expect("the refund balance");
    let refund_signature = fixture
        .cluster
        .execute(
            &[accepted.refund_instruction().expect("a refund instruction")],
            &sol_refund,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("refund the escrow after its deadline");
    let after = fixture
        .cluster
        .lamports(sol_refund.public())
        .expect("the refund balance");
    assert!(after - before >= LAMPORTS - 1_000_000);
    let refunded = escrow_state(&fixture.cluster, &accepted);
    assert_eq!(refunded.status, solana_escrow_wire::EscrowStatus::Refunded);
    assert_eq!(
        refunded.revealed_secret_be, [0; 32],
        "a refund must not publish the scalar"
    );
    let refund_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        refund_signature,
        ObservationKind::Refund,
    );
    let refund = refund_evidence(&refund_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &refund.settlement_id,
        &refund.terms_hash,
        &refund.program_data_hash,
        refund.amount,
    );
    let refund_chain_record = refund_record(
        solana_chain_id(&accepted),
        refund,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the refund evidence converts to a neutral record");
    let refund_ref =
        assert_record_pins_evidence(&refund_chain_record, &accepted, refund_signature, refund.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Refund, &refund_ref);
    assert_ne!(refund_ref.tx_id, funding_ref.tx_id);

    // ── the DOM refund is refused before its height and accepted after ─────
    runtime.block_on(dom.assert_height_refund_locked());
    runtime.block_on(dom.mine_to_refund_height());
    let (refund_height, onward_height) = runtime.block_on(dom.include_height_refund_and_spend());
    assert!(refund_height >= schedule.dom_refund_height.0);
    runtime.block_on(dom.assert_spent_rejection(&losing_claim));

    fixture.environment.record(
        "both_refunds",
        serde_json::json!({
            "status": "passed",
            "claim_order": format!("{:?}", schedule.order),
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&accepted.setup().setup_id()),
            "escrow_refund_after_unix": schedule.escrow_refund_after.0,
            "escrow_refund_signature": refund_signature.to_base58(),
            "early_escrow_refund_refused": true,
            "dom_refund_height": schedule.dom_refund_height.0,
            "dom_refund_included_at": refund_height,
            "dom_onward_spend_height": onward_height,
            "valid_adapted_claim_lost_to_refund": true,
            "observed_min_confirmations":
                accepted.terms().counterparty_leg.finality.min_confirmations,
            "funding_observed_slot": funding.slot,
            "refund_observed_slot": refund.slot,
            "refund_terminal_state_hash": hex32(&refund.terminal_state_hash),
            "funding_record_block_anchor": hex32(&funding_ref.block_anchor),
            "refund_record_block_anchor": hex32(&refund_ref.block_anchor),
            "timing_bounds_proven": false,
        }),
    );
}

// ── SOL -> DOM, with a token instead of native SOL ──────────────────────────

#[test]
#[ignore = "requires the live harness: scripts/f8-run-solana-live-v1.sh"]
fn solana_live_spl_token_sol_to_dom_reveals_through_the_dom_claim() {
    let fixture = Fixture::open();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the DOM node");
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xD4; 32];

    // The same roles as the native scenario. What differs is the asset: the
    // escrow holds a legacy SPL balance in a token vault it owns, and the
    // terminal transfer goes to a token account owned by the beneficiary.
    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);
    let asset = SolanaAssetV1::LegacySpl {
        mint: fixture.environment.mint,
        decimals: fixture.environment.mint_decimals,
    };
    // A token profile is a different profile: `allow_legacy_spl` is inside the
    // profile hash the terms bind.
    let spl_profile = profile(fixture.environment.program_id, true);

    // The harness wired the accounts; check it rather than assume it, because a
    // destination owned by the wrong key is refused by the escrow at the very
    // last step, which is an expensive place to learn it.
    let funder_token = token_account(&fixture.cluster, fixture.environment.funder_token);
    assert_eq!(funder_token.mint, fixture.environment.mint);
    assert_eq!(funder_token.authority, sol_giver.public());
    assert!(
        funder_token.amount >= SPL_BASE_UNITS,
        "the funder holds {} base units, fewer than the {} to be escrowed",
        funder_token.amount,
        SPL_BASE_UNITS
    );
    let beneficiary_token =
        token_account(&fixture.cluster, fixture.environment.beneficiary_token);
    assert_eq!(beneficiary_token.authority, sol_receiver.public());
    assert_eq!(
        token_account(&fixture.cluster, fixture.environment.refund_token).authority,
        sol_refund.public()
    );

    let prepared = runtime.block_on(FundedDom::prepare_unfunded(&directory.path().join("dom")));
    let now = Timestamp(now_seconds());
    let mut dom = runtime.block_on(FundedDom::fund_for_solana_leg(
        prepared,
        RelativeDeadlineV1::DomRefundBlocksAhead(400),
        DELAYS,
        now,
    ));
    let schedule = dom.leg_schedule().expect("a Solana leg schedule");
    assert_eq!(schedule.order, ClaimOrderV1::DomFirst);

    let input = leg_input(
        &fixture,
        settlement_id,
        *dom.claim.chain(),
        dom.anchor(),
        schedule.chosen(),
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        asset,
        SPL_BASE_UNITS,
    );
    let established = SolanaLegV1::establish(
        &input,
        &spl_profile,
        &store(directory.path(), "giver-setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("the SOL giver establishes the condition");
    let accepted = SolanaLegV1::accept(
        &input,
        &spl_profile,
        established.proof(),
        &store(directory.path(), "receiver-setup.sqlite"),
    )
    .expect("the SOL receiver accepts the condition");
    assert_eq!(accepted.setup().setup_id(), established.leg().setup().setup_id());

    // ── the escrow is stood up and funded from the funder's token account ────
    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the token escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[accepted
                .fund_instruction()
                .expect("a token fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the token escrow");
    let observer = observer_for(&fixture, &accepted);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &funding.settlement_id,
        &funding.terms_hash,
        &funding.program_data_hash,
        funding.amount,
    );
    let funding_chain_record = funding_record(
        solana_chain_id(&accepted),
        funding,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the funding evidence converts to a neutral record");
    let funding_ref =
        assert_record_pins_evidence(&funding_chain_record, &accepted, fund_signature, funding.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);
    assert_eq!(funding.mint, fixture.environment.mint);

    // The escrow's own token vault, owned by the vault authority PDA, now holds
    // exactly the escrowed amount.
    let vault = token_account(&fixture.cluster, accepted.setup().vault_pda());
    assert_eq!(vault.mint, fixture.environment.mint);
    assert_eq!(vault.authority, accepted.setup().vault_authority());
    assert_eq!(vault.amount, SPL_BASE_UNITS);

    // ── the DOM claim is completed with the secret and published ─────────────
    let opening = established.opening().expect("the established opening");
    let offer = dom.offer(
        &established.leg().lock().dom_adaptor_point(),
        established.leg().setup().setup_id(),
    );
    let context = runtime.block_on(dom.context());
    let claim_transaction = offer
        .complete(opening.dom_secret(), &context)
        .expect("the adapted DOM claim");
    let (published, dom_height) = runtime.block_on(dom.include(&claim_transaction));
    let extracted = offer
        .extract(&published, &runtime.block_on(dom.context()))
        .expect("the scalar the published DOM claim discloses");
    let from_chain = accepted
        .opening_from_dom_secret(extracted)
        .expect("the extracted scalar opens both faces");
    assert_opening_agrees(&from_chain, &opening);

    // ── and the token escrow is claimed with it ──────────────────────────────
    let before = token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount;
    let claim_signature = fixture
        .cluster
        .execute(
            &[accepted
                .claim_instruction(&from_chain)
                .expect("a token claim instruction")],
            &sol_receiver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("claim the token escrow with the disclosed scalar");
    let claim_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        claim_signature,
        ObservationKind::Claim,
    );
    let claim = claim_evidence(&claim_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &claim.settlement_id,
        &claim.terms_hash,
        &claim.program_data_hash,
        claim.amount,
    );
    assert_eq!(claim.revealed_secret_be, opening.escrow_claim_bytes());
    assert_eq!(claim.mint, fixture.environment.mint);
    let claim_chain_record = claim_record(
        solana_chain_id(&accepted),
        claim,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the claim evidence converts to a neutral record");
    let claim_ref =
        assert_record_pins_evidence(&claim_chain_record, &accepted, claim_signature, claim.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Claim, &claim_ref);
    assert_ne!(claim_ref.tx_id, funding_ref.tx_id);

    // Exactly the escrowed amount moved, and it moved out of the vault: a token
    // transfer that credited the beneficiary from somewhere else would satisfy a
    // balance check on the destination alone.
    let after = token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount;
    assert_eq!(after - before, SPL_BASE_UNITS);
    assert_eq!(
        token_account(&fixture.cluster, accepted.setup().vault_pda()).amount,
        0,
        "the vault still holds a balance after paying the frozen principal"
    );

    let onward_height = runtime.block_on(dom.prove_onward_spend_and_reject_double_spend());

    fixture.environment.record(
        "spl_sol_to_dom",
        serde_json::json!({
            "status": "passed",
            "claim_order": "DomFirst",
            "asset": "legacy-spl",
            "mint": fixture.environment.mint.to_base58(),
            "mint_decimals": fixture.environment.mint_decimals,
            "base_units": SPL_BASE_UNITS,
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&accepted.setup().setup_id()),
            "token_vault": accepted.setup().vault_pda().to_base58(),
            "vault_authority": accepted.setup().vault_authority().to_base58(),
            "dom_claim_height": dom_height,
            "dom_onward_spend_height": onward_height,
            "escrow_claim_signature": claim_signature.to_base58(),
            "revealed_scalar_matches": true,
            "observed_min_confirmations":
                accepted.terms().counterparty_leg.finality.min_confirmations,
            "funding_observed_slot": funding.slot,
            "claim_observed_slot": claim.slot,
            "funding_record_block_anchor": hex32(&funding_ref.block_anchor),
            "claim_record_block_anchor": hex32(&claim_ref.block_anchor),
            "timing_bounds_proven": false,
        }),
    );
}

// ── what the escrow must refuse ─────────────────────────────────────────────

fn meta(pubkey: SolanaPubkey, is_signer: bool, is_writable: bool) -> SolanaAccountMeta {
    SolanaAccountMeta {
        pubkey,
        is_signer,
        is_writable,
    }
}

/// A native `Fund` whose funder is somebody else. Hand-built, because the leg's
/// own builder always names the funder the terms froze -- which is the point: the
/// refusal being tested is the program's, not the client's.
fn native_fund_by(leg: &SolanaLegV1, funder: SolanaPubkey) -> SolanaInstruction {
    SolanaInstruction {
        program_id: leg.setup().program_id(),
        accounts: vec![
            meta(funder, true, true),
            meta(leg.setup().state_pda(), false, true),
            meta(leg.setup().vault_pda(), false, true),
            meta(SYSTEM_PROGRAM_ID, false, false),
        ],
        data: solana_escrow_wire::EscrowInstructionV1::Fund.encode(),
    }
}

/// A native `Claim` with any secret and any destination, for the same reason.
fn native_claim_with(
    leg: &SolanaLegV1,
    revealed_secret_be: [u8; 32],
    destination: SolanaPubkey,
) -> SolanaInstruction {
    SolanaInstruction {
        program_id: leg.setup().program_id(),
        accounts: vec![
            meta(leg.setup().state_pda(), false, true),
            meta(leg.setup().vault_pda(), false, true),
            meta(destination, false, true),
        ],
        data: solana_escrow_wire::EscrowInstructionV1::Claim { revealed_secret_be }.encode(),
    }
}

/// Every path the escrow must refuse, and the property that makes a refusal worth
/// anything: nothing moved.
///
/// The four settlement scenarios prove what works. This one proves the rest, which
/// is the half that protects the money: a refusal that quietly changed the state
/// or drained the vault would pass a test that only checked for an error.
///
/// No DOM node is started. Every refusal here is the escrow's own, and the DOM
/// side of a leg is established by the scenarios that settle one. The DOM facts in
/// the plan are an assumption record and a chain id that nothing executes.
#[test]
#[ignore = "requires the live harness: scripts/f8-run-solana-live-v1.sh"]
fn solana_live_the_escrow_refuses_what_it_must() {
    let fixture = Fixture::open();
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xE5; 32];

    let funder = LiveEnvironment::keypair(&fixture.environment.funder);
    let beneficiary = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let refund = LiveEnvironment::keypair(&fixture.environment.refund);

    let now = Timestamp(now_seconds());
    let anchor = AssumedDomAnchor::new(BlockHeight(1), now);
    let chosen = RelativeDeadlineV1::DomRefundBlocksAhead(400)
        .resolve(&anchor, now)
        .expect("a DOM-first schedule choice");
    let input = leg_input(
        &fixture,
        settlement_id,
        [0xEE; 32],
        anchor,
        chosen,
        funder.public(),
        beneficiary.public(),
        refund.public(),
        now,
        SolanaAssetV1::NativeSol,
        LAMPORTS,
    );
    let established = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &store(directory.path(), "setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("establish the condition");
    let leg = established.leg();
    let opening = established.opening().expect("the established opening");

    // A refusal is only a refusal if nothing moved with it.
    let untouched = |status: solana_escrow_wire::EscrowStatus, funded: u64, step: &str| {
        let state = escrow_state(&fixture.cluster, leg);
        assert_eq!(state.status, status, "{step} changed the escrow status");
        assert_eq!(state.funded_amount, funded, "{step} changed the funded amount");
        assert_eq!(
            state.revealed_secret_be,
            if status == solana_escrow_wire::EscrowStatus::Claimed {
                opening.escrow_claim_bytes()
            } else {
                [0; 32]
            },
            "{step} changed the recorded secret"
        );
    };

    fixture
        .cluster
        .execute(
            &[leg.initialize_instruction()],
            &funder,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the escrow");
    untouched(solana_escrow_wire::EscrowStatus::Initialized, 0, "initialize");

    // Before funding.
    for (step, instruction, payer) in [
        (
            "a second initialize",
            leg.initialize_instruction(),
            &funder,
        ),
        (
            "a claim before funding",
            leg.claim_instruction(&opening).expect("a claim"),
            &beneficiary,
        ),
        (
            "a refund before funding",
            leg.refund_instruction().expect("a refund"),
            &refund,
        ),
        (
            "a fund by somebody who is not the frozen funder",
            native_fund_by(leg, beneficiary.public()),
            &beneficiary,
        ),
    ] {
        fixture
            .cluster
            .expect_refusal(&[instruction], payer, &[], CONFIRM_TIMEOUT)
            .unwrap_or_else(|error| panic!("{step} was not refused: {error}"));
        untouched(solana_escrow_wire::EscrowStatus::Initialized, 0, step);
    }

    let vault_before = fixture
        .cluster
        .lamports(leg.setup().vault_pda())
        .expect("the vault balance");
    fixture
        .cluster
        .execute(
            &[leg.fund_instruction().expect("a fund instruction")],
            &funder,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
    untouched(solana_escrow_wire::EscrowStatus::Funded, LAMPORTS, "fund");
    let vault_funded = fixture
        .cluster
        .lamports(leg.setup().vault_pda())
        .expect("the vault balance");
    assert_eq!(vault_funded - vault_before, LAMPORTS);

    // After funding, before any terminal step. The deadline has not passed, and a
    // wrong secret is inside the proved 252-bit domain so the refusal comes from
    // the curve check rather than from the wire decoder.
    assert!(
        fixture
            .cluster
            .cluster_unix_time()
            .expect("the cluster clock")
            < leg.setup().refund_after_unix(),
        "the frozen deadline had already passed before it could be tested"
    );
    for (step, instruction, payer) in [
        (
            "a second fund",
            leg.fund_instruction().expect("a fund instruction"),
            &funder,
        ),
        (
            "a claim with a wrong secret",
            native_claim_with(leg, [0x01; 32], beneficiary.public()),
            &beneficiary,
        ),
        (
            "a claim to a destination the terms did not name",
            native_claim_with(leg, opening.escrow_claim_bytes(), refund.public()),
            &refund,
        ),
        (
            "a refund before the frozen deadline",
            leg.refund_instruction().expect("a refund instruction"),
            &refund,
        ),
    ] {
        fixture
            .cluster
            .expect_refusal(&[instruction], payer, &[], CONFIRM_TIMEOUT)
            .unwrap_or_else(|error| panic!("{step} was not refused: {error}"));
        untouched(solana_escrow_wire::EscrowStatus::Funded, LAMPORTS, step);
        assert_eq!(
            fixture
                .cluster
                .lamports(leg.setup().vault_pda())
                .expect("the vault balance"),
            vault_funded,
            "{step} moved lamports out of the vault"
        );
    }

    // The one that must work, so the refusals above are not simply a broken escrow.
    let before = fixture
        .cluster
        .lamports(beneficiary.public())
        .expect("the beneficiary balance");
    fixture
        .cluster
        .execute(
            &[leg.claim_instruction(&opening).expect("a claim instruction")],
            &beneficiary,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("claim the escrow with the right secret");
    untouched(solana_escrow_wire::EscrowStatus::Claimed, 0, "the claim");
    let after = fixture
        .cluster
        .lamports(beneficiary.public())
        .expect("the beneficiary balance");
    assert!(after - before >= LAMPORTS - 1_000_000);
    let vault_after = fixture
        .cluster
        .lamports(leg.setup().vault_pda())
        .expect("the vault balance");
    assert_eq!(
        vault_funded - vault_after,
        LAMPORTS,
        "the claim moved something other than the frozen principal out of the vault"
    );

    // After the terminal step, both paths are closed.
    for (step, instruction, payer) in [
        (
            "a second claim",
            leg.claim_instruction(&opening).expect("a claim instruction"),
            &beneficiary,
        ),
        (
            "a refund after the claim",
            leg.refund_instruction().expect("a refund instruction"),
            &refund,
        ),
    ] {
        fixture
            .cluster
            .expect_refusal(&[instruction], payer, &[], CONFIRM_TIMEOUT)
            .unwrap_or_else(|error| panic!("{step} was not refused: {error}"));
        untouched(solana_escrow_wire::EscrowStatus::Claimed, 0, step);
    }

    fixture.environment.record(
        "escrow_refusals",
        serde_json::json!({
            "status": "passed",
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&leg.setup().setup_id()),
            "refused_before_funding": [
                "a second initialize",
                "a claim before funding",
                "a refund before funding",
                "a fund by somebody who is not the frozen funder",
            ],
            "refused_while_funded": [
                "a second fund",
                "a claim with a wrong secret",
                "a claim to a destination the terms did not name",
                "a refund before the frozen deadline",
            ],
            "refused_after_the_claim": ["a second claim", "a refund after the claim"],
            "state_and_vault_unchanged_after_every_refusal": true,
            "no_dom_node_started": true,
        }),
    );
}

// ── DOM -> SOL, with a token ────────────────────────────────────────────────

/// The token asset in the other claim order: the escrow claim is what discloses
/// the scalar, and the DOM side completes its claim from what it reads off the
/// cluster. Same escrow, same condition, a token instead of lamports.
#[test]
#[ignore = "requires the live harness: scripts/f8-run-solana-live-v1.sh"]
fn solana_live_spl_token_dom_to_sol_reveals_through_the_escrow_claim() {
    let fixture = Fixture::open();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the DOM node");
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xF6; 32];

    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);
    let asset = SolanaAssetV1::LegacySpl {
        mint: fixture.environment.mint,
        decimals: fixture.environment.mint_decimals,
    };
    let spl_profile = profile(fixture.environment.program_id, true);

    let prepared = runtime.block_on(FundedDom::prepare_unfunded(&directory.path().join("dom")));
    let now = Timestamp(now_seconds());
    let mut dom = runtime.block_on(FundedDom::fund_for_solana_leg(
        prepared,
        RelativeDeadlineV1::EscrowRefundSecondsAhead(600),
        DELAYS,
        now,
    ));
    let schedule = dom.leg_schedule().expect("a Solana leg schedule");
    assert_eq!(schedule.order, ClaimOrderV1::SolanaFirst);

    let input = leg_input(
        &fixture,
        settlement_id,
        *dom.claim.chain(),
        dom.anchor(),
        schedule.chosen(),
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        asset,
        SPL_BASE_UNITS,
    );
    // The SOL receiver holds the secret in this order.
    let established = SolanaLegV1::establish(
        &input,
        &spl_profile,
        &store(directory.path(), "receiver-setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("the SOL receiver establishes the condition");
    let accepted = SolanaLegV1::accept(
        &input,
        &spl_profile,
        established.proof(),
        &store(directory.path(), "giver-setup.sqlite"),
    )
    .expect("the SOL giver accepts the condition");
    assert_eq!(accepted.setup().setup_id(), established.leg().setup().setup_id());

    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the token escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[accepted
                .fund_instruction()
                .expect("a token fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the token escrow");
    let observer = observer_for(&fixture, &accepted);
    let observations = feed(directory.path(), "observations.sqlite", &accepted);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_binds_leg(
        &accepted,
        &fixture.program.code_hash,
        &funding.settlement_id,
        &funding.terms_hash,
        &funding.program_data_hash,
        funding.amount,
    );
    let funding_chain_record = funding_record(
        solana_chain_id(&accepted),
        funding,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the funding evidence converts to a neutral record");
    let funding_ref =
        assert_record_pins_evidence(&funding_chain_record, &accepted, fund_signature, funding.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Funding, &funding_ref);
    assert_eq!(
        token_account(&fixture.cluster, accepted.setup().vault_pda()).amount,
        SPL_BASE_UNITS
    );

    // ── the escrow claim discloses the scalar ────────────────────────────────
    let opening = established.opening().expect("the established opening");
    let before = token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount;
    let claim_signature = fixture
        .cluster
        .execute(
            &[established
                .leg()
                .claim_instruction(&opening)
                .expect("a token claim instruction")],
            &sol_receiver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("claim the token escrow");
    let claim_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(&accepted),
        claim_signature,
        ObservationKind::Claim,
    );
    let claim = claim_evidence(&claim_envelope);
    assert_eq!(claim.revealed_secret_be, opening.escrow_claim_bytes());
    assert_eq!(claim.mint, fixture.environment.mint);
    let claim_chain_record = claim_record(
        solana_chain_id(&accepted),
        claim,
        &accepted.setup().settlement_id(),
        &accepted.setup().terms_hash(),
    )
    .expect("the claim evidence converts to a neutral record");
    let claim_ref =
        assert_record_pins_evidence(&claim_chain_record, &accepted, claim_signature, claim.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Claim, &claim_ref);
    let after = token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount;
    assert_eq!(after - before, SPL_BASE_UNITS);

    // ── and the DOM side completes its claim from what the cluster published ─
    let from_state = accepted
        .opening_from_escrow_state(
            &fixture
                .cluster
                .account_data(accepted.setup().state_pda())
                .expect("the escrow state account"),
        )
        .expect("the claimed escrow state discloses the scalar");
    assert_opening_agrees(&from_state, &opening);
    let offer = dom.offer(
        &accepted.lock().dom_adaptor_point(),
        accepted.setup().setup_id(),
    );
    let context = runtime.block_on(dom.context());
    let claim_transaction = offer
        .complete(from_state.dom_secret(), &context)
        .expect("the adapted DOM claim");
    let (_, dom_height) = runtime.block_on(dom.include(&claim_transaction));
    let onward_height = runtime.block_on(dom.prove_onward_spend_and_reject_double_spend());

    fixture.environment.record(
        "spl_dom_to_sol",
        serde_json::json!({
            "status": "passed",
            "claim_order": "SolanaFirst",
            "asset": "legacy-spl",
            "mint": fixture.environment.mint.to_base58(),
            "base_units": SPL_BASE_UNITS,
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&accepted.setup().setup_id()),
            "escrow_claim_signature": claim_signature.to_base58(),
            "dom_claim_height": dom_height,
            "dom_onward_spend_height": onward_height,
            "funding_record_block_anchor": hex32(&funding_ref.block_anchor),
            "claim_record_block_anchor": hex32(&claim_ref.block_anchor),
            "timing_bounds_proven": false,
        }),
    );
}

// ── the token comes back ────────────────────────────────────────────────────

/// The token refund: the escrow returns the principal to the refund owner the
/// terms froze, through the vault authority PDA, after its frozen deadline.
///
/// No DOM node: the DOM height-locked refund is established by the native
/// `both_refunds` scenario, and what is unexercised anywhere is the escrow's token
/// return path -- a different transfer, a different authority, a different
/// destination check.
#[test]
#[ignore = "requires the live harness and waits for a real deadline"]
fn solana_live_spl_token_refund_returns_the_token() {
    let fixture = Fixture::open();
    let directory = tempfile::tempdir().expect("a private working directory");
    let settlement_id = [0xA7; 32];

    let sol_giver = LiveEnvironment::keypair(&fixture.environment.funder);
    let sol_receiver = LiveEnvironment::keypair(&fixture.environment.beneficiary);
    let sol_refund = LiveEnvironment::keypair(&fixture.environment.refund);
    let asset = SolanaAssetV1::LegacySpl {
        mint: fixture.environment.mint,
        decimals: fixture.environment.mint_decimals,
    };
    let spl_profile = profile(fixture.environment.program_id, true);

    let now = Timestamp(now_seconds());
    let anchor = AssumedDomAnchor::new(BlockHeight(1), now);
    let chosen = RelativeDeadlineV1::EscrowRefundSecondsAhead(90)
        .resolve(&anchor, now)
        .expect("a Solana-first schedule choice");
    let input = leg_input(
        &fixture,
        settlement_id,
        [0xEF; 32],
        anchor,
        chosen,
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
        asset,
        SPL_BASE_UNITS,
    );
    let established = SolanaLegV1::establish(
        &input,
        &spl_profile,
        &store(directory.path(), "setup.sqlite"),
        &mut rand::thread_rng(),
    )
    .expect("establish the condition");
    let leg = established.leg();

    fixture
        .cluster
        .execute(&[leg.initialize_instruction()], &sol_giver, &[], CONFIRM_TIMEOUT)
        .expect("initialize the token escrow");
    let fund_signature = fixture
        .cluster
        .execute(
            &[leg.fund_instruction().expect("a token fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the token escrow");
    let observer = observer_for(&fixture, leg);
    let observations = feed(directory.path(), "observations.sqlite", leg);
    let funding_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(leg),
        fund_signature,
        ObservationKind::Funding,
    );
    let funding = funding_evidence(&funding_envelope);
    assert_eq!(funding.mint, fixture.environment.mint);
    assert_eq!(
        token_account(&fixture.cluster, leg.setup().vault_pda()).amount,
        SPL_BASE_UNITS
    );

    // Before the deadline, the token stays where it is.
    assert!(
        fixture
            .cluster
            .cluster_unix_time()
            .expect("the cluster clock")
            < leg.setup().refund_after_unix()
    );
    fixture
        .cluster
        .expect_refusal(
            &[leg.refund_instruction().expect("a refund instruction")],
            &sol_refund,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("an early token refund must be refused");
    assert_eq!(
        token_account(&fixture.cluster, leg.setup().vault_pda()).amount,
        SPL_BASE_UNITS,
        "a refused refund moved tokens out of the vault"
    );

    // After it, the principal returns to the refund owner and nowhere else.
    fixture
        .cluster
        .wait_for_cluster_time(leg.setup().refund_after_unix(), Duration::from_secs(300))
        .expect("the cluster clock reaches the frozen deadline");
    let before = token_account(&fixture.cluster, fixture.environment.refund_token).amount;
    let beneficiary_before =
        token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount;
    let refund_signature = fixture
        .cluster
        .execute(
            &[leg.refund_instruction().expect("a refund instruction")],
            &sol_refund,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("refund the token escrow after its deadline");
    let refund_envelope = observe_when_final(
        &observer,
        &observations,
        solana_chain_id(leg),
        refund_signature,
        ObservationKind::Refund,
    );
    let refund = refund_evidence(&refund_envelope);
    assert_eq!(refund.mint, fixture.environment.mint);
    let refund_chain_record = refund_record(
        solana_chain_id(leg),
        refund,
        &leg.setup().settlement_id(),
        &leg.setup().terms_hash(),
    )
    .expect("the refund evidence converts to a neutral record");
    let refund_ref =
        assert_record_pins_evidence(&refund_chain_record, leg, refund_signature, refund.slot);
    assert_feed_holds(&observations, VerifiedSolanaEventKind::Refund, &refund_ref);

    let after = token_account(&fixture.cluster, fixture.environment.refund_token).amount;
    assert_eq!(after - before, SPL_BASE_UNITS);
    assert_eq!(
        token_account(&fixture.cluster, leg.setup().vault_pda()).amount,
        0,
        "the vault still holds tokens after returning the principal"
    );
    assert_eq!(
        token_account(&fixture.cluster, fixture.environment.beneficiary_token).amount,
        beneficiary_before,
        "a refund credited the beneficiary"
    );
    let state = escrow_state(&fixture.cluster, leg);
    assert_eq!(state.status, solana_escrow_wire::EscrowStatus::Refunded);
    assert_eq!(state.revealed_secret_be, [0; 32]);

    fixture.environment.record(
        "spl_refund",
        serde_json::json!({
            "status": "passed",
            "asset": "legacy-spl",
            "mint": fixture.environment.mint.to_base58(),
            "base_units": SPL_BASE_UNITS,
            "settlement_id": hex32(&settlement_id),
            "setup_id": hex32(&leg.setup().setup_id()),
            "escrow_refund_after_unix": leg.setup().refund_after_unix(),
            "escrow_refund_signature": refund_signature.to_base58(),
            "early_token_refund_refused": true,
            "refund_record_block_anchor": hex32(&refund_ref.block_anchor),
            "beneficiary_untouched": true,
            "no_dom_node_started": true,
        }),
    );
}
