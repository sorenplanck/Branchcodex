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

use dom_core::Timestamp;
use dom_solana_direct_lab::{
    cluster::ClusterSessionV1,
    condition::ConditionOpeningV1,
    leg::{EstablishedLegV1, LegPlanInputV1, SolanaLegV1},
    time_bounds::{AssumedLegDelaysV1, ClaimOrderV1, DomClockNetwork, RelativeDeadlineV1},
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
use solana_observer::{ObservationKind, ObserverError, SolanaSettlementObserver};
use solana_profile::{SolanaAdapterProfileV1, SolanaNetwork};
use solana_program_attestation::{
    attest_immutable_program, code_hash, PROGRAM_DATA_METADATA_LEN,
};
use solana_secret_store::{EncryptedSqliteWitnessStore, SecretStoreMasterKey};
use solana_setup_store::SolanaSetupStore;
// The trait must be in scope to call `get_transaction` on the HTTP client.
use solana_rpc::{HttpSolanaRpc, SolanaRpc as _};
use solana_types::{Commitment, SolanaPubkey, SolanaSignature};
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
fn profile(program_id: SolanaPubkey) -> SolanaAdapterProfileV1 {
    let mut profile = SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program_id, 1, 1)
        .expect("a one-node local profile");
    profile.require_immutable_program = true;
    profile.allow_legacy_spl = false;
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
        let profile = profile(environment.program_id);
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
fn leg_input(
    fixture: &Fixture,
    settlement_id: [u8; 32],
    dom: &FundedDom,
    funder: SolanaPubkey,
    beneficiary: SolanaPubkey,
    refund_recipient: SolanaPubkey,
    now: Timestamp,
) -> LegPlanInputV1 {
    let schedule = dom
        .leg_schedule()
        .expect("the reserve was funded for a Solana leg");
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
        dom_chain_id: *dom.claim.chain(),
        dom_asset_id: {
            let mut hasher = Sha256::new();
            hasher.update(b"DOM-SOLANA-DIRECT-LAB/dom-asset/v1\0");
            hasher.update(dom.claim.chain());
            hasher.finalize().into()
        },
        dom_amount_noms: RESERVE_VALUE - CLAIM_FEE,
        dom_beneficiary: participant(&settlement_id, "dom-receiver"),
        dom_refund_to: participant(&settlement_id, "dom-refund"),
        dom_finality: FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 8,
        },
        dom_fee_max: CLAIM_FEE,
        cluster_genesis: fixture.environment.genesis.0,
        solana_asset_id: {
            // Native SOL has no mint; name the asset by the cluster it is native
            // to rather than by a zero mint that would look like an SPL asset.
            let mut hasher = Sha256::new();
            hasher.update(b"DOM-SOLANA-DIRECT-LAB/native-sol/v1\0");
            hasher.update(fixture.environment.genesis.0);
            hasher.finalize().into()
        },
        lamports: LAMPORTS,
        funder,
        beneficiary,
        refund_recipient,
        solana_finality: FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 32,
        },
        solana_fee_max: 100_000,
        program_data_hash: fixture.program.code_hash,
        anchor: dom.anchor(),
        now,
        network: DomClockNetwork::Regtest,
        validator_clock_ahead_secs: 0,
        delays: DELAYS,
        chosen_deadline: schedule.chosen(),
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

/// Observe a landed transaction once it satisfies the declared finality.
///
/// Only two outcomes are waited on: not yet finalized, and not yet deep enough.
/// Everything else is a disagreement between the chain and what this leg
/// believes, and is raised immediately rather than retried until a timeout turns
/// it into a vague one.
fn observe_when_final(
    observer: &SolanaSettlementObserver<HttpSolanaRpc>,
    signature: SolanaSignature,
    kind: ObservationKind,
) -> SolanaEvidenceEnvelopeV1 {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        match observer.observe(signature, kind) {
            Ok(envelope) => return envelope,
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        ObserverError::NotFinalized | ObserverError::InsufficientDepth
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
        &dom,
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
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
    let funding_envelope = observe_when_final(&observer, fund_signature, ObservationKind::Funding);
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
    let claim_envelope = observe_when_final(&observer, claim_signature, ObservationKind::Claim);
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
        &dom,
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
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
    let funding_envelope = observe_when_final(&observer, fund_signature, ObservationKind::Funding);
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
    assert_eq!(
        escrow_state(&fixture.cluster, &accepted).status,
        solana_escrow_wire::EscrowStatus::Funded
    );

    // ── the restarted leg rebuilds its session and claims ───────────────────
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
    let claim_envelope = observe_when_final(&observer, claim_signature, ObservationKind::Claim);
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
        &dom,
        sol_giver.public(),
        sol_receiver.public(),
        sol_refund.public(),
        now,
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
    let funding_envelope = observe_when_final(&observer, fund_signature, ObservationKind::Funding);
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
    let refund_envelope = observe_when_final(&observer, refund_signature, ObservationKind::Refund);
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
            "refund_record_block_anchor": hex32(&refund_ref.block_anchor),
            "timing_bounds_proven": false,
        }),
    );
}
