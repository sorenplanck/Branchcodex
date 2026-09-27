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
    leg::{LegPlanInputV1, SolanaLegV1},
    time_bounds::{AssumedLegDelaysV1, ClaimOrderV1, DomClockNetwork, RelativeDeadlineV1},
};
use kaystra_core::types::{FinalityPolicyV1, ParticipantId};
use sha2::{Digest, Sha256};
use solana_profile::{SolanaAdapterProfileV1, SolanaNetwork};
use solana_setup_store::SolanaSetupStore;
// The trait must be in scope to call `get_transaction` on the HTTP client.
use solana_rpc::SolanaRpc as _;
use solana_types::{Commitment, SolanaPubkey};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
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

/// What the programdata account itself says, measured in this process rather
/// than taken from the harness.
struct ProgramDataFacts {
    sha256: [u8; 32],
    slot: u64,
    /// Which of the two unsignable authority shapes was found.
    authority: &'static str,
}

/// Read the programdata account and establish here that no upgrade can ever be
/// authorized, and what its bytes hash to.
///
/// The bincode `UpgradeableLoaderState::ProgramData` layout is a u32
/// discriminant (3), a u64 slot, then `Option<Pubkey>`: one tag byte and, when
/// the tag is 1, the 32-byte authority.
///
/// Two shapes are accepted, and only these two. An absent authority (tag 0) is
/// the shape a revoked mainnet deployment has. The all-zero address (tag 1 with
/// a zero key) is what `solana-test-validator --upgradeable-program ... none`
/// writes: it is the System Program's address, which nobody holds a key for and
/// which the runtime never presents as a transaction signer, so no upgrade can
/// be authorized under it either. Any other address is a real authority and
/// fails the test, naming the key.
fn programdata_facts(cluster: &ClusterSessionV1, programdata: SolanaPubkey) -> ProgramDataFacts {
    let data = cluster
        .account_data(programdata)
        .expect("the programdata account the loader created");
    assert!(
        data.len() > 45,
        "programdata account holds {} bytes, too few for a header and a program",
        data.len()
    );
    let discriminant = u32::from_le_bytes(
        data[..4]
            .try_into()
            .expect("four bytes for the loader state discriminant"),
    );
    assert_eq!(
        discriminant,
        3,
        "this is not a ProgramData account; its first 45 bytes are {}",
        hex_bytes(&data[..45])
    );
    let slot = u64::from_le_bytes(
        data[4..12]
            .try_into()
            .expect("eight bytes for the deployment slot"),
    );
    let authority = match data[12] {
        0 => "absent",
        1 => {
            let key: [u8; 32] = data[13..45]
                .try_into()
                .expect("thirty-two bytes for the authority");
            assert_eq!(
                key,
                [0u8; 32],
                "the program has a real upgrade authority ({}); the daemon requires a \
                 program nobody can replace",
                SolanaPubkey(key).to_base58()
            );
            "unsignable-system-address"
        }
        other => panic!(
            "the authority option tag is {other}, which is neither 0 nor 1; \
             the first 45 bytes are {}",
            hex_bytes(&data[..45])
        ),
    };
    let mut hasher = Sha256::new();
    hasher.update(&data);
    ProgramDataFacts {
        sha256: hasher.finalize().into(),
        slot,
        authority,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Fixture {
    environment: LiveEnvironment,
    cluster: ClusterSessionV1,
    profile: SolanaAdapterProfileV1,
    program_data_hash: [u8; 32],
    deployment_slot: u64,
    upgrade_authority: &'static str,
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
        let facts = programdata_facts(&cluster, environment.programdata);
        Self {
            environment,
            cluster,
            profile,
            program_data_hash: facts.sha256,
            deployment_slot: facts.slot,
            upgrade_authority: facts.authority,
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
        program_data_hash: fixture.program_data_hash,
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
    fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
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
            "programdata_sha256_measured_in_process": hex32(&fixture.program_data_hash),
            "programdata_sha256_reported_by_harness":
                hex32(&fixture.environment.programdata_sha256),
            "deployment_slot": fixture.deployment_slot,
            "upgrade_authority": fixture.upgrade_authority,
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
    let established = SolanaLegV1::establish(
        &input,
        &fixture.profile,
        &store(directory.path(), "receiver-setup.sqlite"),
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

    fixture
        .cluster
        .execute(
            &[accepted.initialize_instruction()],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("initialize the escrow");
    fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");
    assert_eq!(
        escrow_state(&fixture.cluster, &accepted).status,
        solana_escrow_wire::EscrowStatus::Funded
    );

    // ── the escrow claim publishes the scalar ───────────────────────────────
    let opening = established.opening().expect("the established opening");
    let before = fixture
        .cluster
        .lamports(sol_receiver.public())
        .expect("the receiver balance");
    let claim_signature = fixture
        .cluster
        .execute(
            &[established
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
    fixture
        .cluster
        .execute(
            &[accepted.fund_instruction().expect("a native fund instruction")],
            &sol_giver,
            &[],
            CONFIRM_TIMEOUT,
        )
        .expect("fund the escrow");

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
            "timing_bounds_proven": false,
        }),
    );
}
