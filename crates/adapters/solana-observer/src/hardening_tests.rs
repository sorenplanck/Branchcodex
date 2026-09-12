use super::*;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
};
use solana_profile::{SolanaNetwork, SolanaProofContextV1};
use solana_session_init::{finalize_session, prepare_route_secret};
use solana_setup_store::SolanaSetupStore;
use solana_types::{SolanaHash, SolanaInstruction};
const SETTLEMENT: [u8; 32] = [1; 32];
struct Fixture {
    setup: ValidatedSolanaSetup,
    revealed_secret_be: [u8; 32],
    _directory: tempfile::TempDir,
}
fn terms(adaptor: [u8; 33], profile_hash: [u8; 32], funder: SolanaPubkey) -> SettlementTermsV1 {
    let recipient = ParticipantId([0x31; 32]);
    let refund = ParticipantId([0x21; 32]);
    SettlementTermsV1 {
        settlement_id: SettlementId(SETTLEMENT),
        session_id: SessionId([2; 32]),
        intent_hash: IntentHash([3; 32]),
        solver_id: SolverId([4; 32]),
        roster: [refund, recipient],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId([0xD0; 32]),
            asset_id: AssetId([0xD1; 32]),
            amount: 500,
            beneficiary: refund,
            refund_to: recipient,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 1_000 },
            finality: FinalityPolicyV1 {
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
            adapter_profile_hash: [0xD2; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId([0x51; 32]),
            asset_id: AssetId([0x52; 32]),
            amount: 500,
            beneficiary: recipient,
            refund_to: refund,
            mechanism: LockMechanism::CrossCurveConditionLock,
            deadline: TimelockSpec::TimestampSeconds {
                value: 2_000_000_000,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 32,
            },
            adapter_profile_hash: profile_hash,
        },
        adaptor_point_sec1: adaptor,
        fee_limit: FeeLimitV1 {
            dom_max: 50,
            counterparty_max: 50,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 1_000,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: funder.0.to_vec(),
    }
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut rng = rand::thread_rng();
    let funder = SolanaPubkey([0x77; 32]);
    let program = SolanaPubkey([0x3a; 32]);
    let profile =
        SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program, 3, 2).expect("profile");
    let context = SolanaProofContextV1 {
        settlement_id: SETTLEMENT,
        chain_id: [0x51; 32],
        asset_id: [0x52; 32],
        amount: 500,
        beneficiary: [0x31; 32],
        refund_to: [0x21; 32],
        refund_after_unix: 2_000_000_000,
        min_confirmations: 1,
        max_reorg_depth: 32,
        asset: SolanaAssetV1::NativeSol,
        funder,
    };
    let route = prepare_route_secret(&profile, &context, &mut rng).expect("route secret");
    let revealed_secret_be = route.with_revealed_dom_secret(|r| r.expose_scalar_bytes());
    let frozen = terms(route.dom_adaptor_point().0, profile.profile_hash(), funder);
    let setup_store =
        SolanaSetupStore::open(directory.path().join("setup.sqlite")).expect("setup store");
    let session = finalize_session(
        &profile,
        &frozen,
        SolanaAssetV1::NativeSol,
        funder,
        [0xA5; 32],
        route,
        &setup_store,
    )
    .expect("session");
    Fixture {
        setup: session.setup().clone(),
        revealed_secret_be,
        _directory: directory,
    }
}

fn compile(ix: SolanaInstruction) -> SolanaCompiledInstruction {
    SolanaCompiledInstruction {
        program_id: ix.program_id,
        accounts: ix.accounts.into_iter().map(|a| a.pubkey).collect(),
        data: ix.data,
    }
}
fn transaction(instructions: Vec<SolanaCompiledInstruction>) -> SolanaTransactionRecord {
    SolanaTransactionRecord {
        slot: 42,
        signature: SolanaSignature([1; 64]),
        recent_blockhash: SolanaHash([2; 32]),
        success: true,
        instructions,
    }
}
#[test]
fn client_initialize_and_fund_selects_fund_at_its_real_account_position() {
    let f = fixture();
    let tx = transaction(vec![
        compile(solana_program_client::initialize(&f.setup)),
        compile(solana_program_client::fund(&f.setup, None).unwrap()),
    ]);
    let (index, ix, _) =
        select_settlement_instruction(&tx, &f.setup, ObservationKind::Funding).unwrap();
    assert_eq!(index, 1);
    validate_instruction_accounts(ix, &f.setup, ObservationKind::Funding).unwrap();
}
#[test]
fn ambiguous_funding_and_wrong_account_order_are_refused() {
    let f = fixture();
    let ix = compile(solana_program_client::fund(&f.setup, None).unwrap());
    assert!(select_settlement_instruction(
        &transaction(vec![ix.clone(), ix.clone()]),
        &f.setup,
        ObservationKind::Funding
    )
    .is_err());
    let mut wrong = ix;
    wrong.accounts.swap(0, 1);
    assert!(select_settlement_instruction(
        &transaction(vec![wrong]),
        &f.setup,
        ObservationKind::Funding
    )
    .is_err());
}
#[test]
fn client_terminal_instructions_validate_and_account_substitution_is_refused() {
    let f = fixture();
    for (kind, ix) in [
        (
            ObservationKind::Claim,
            solana_program_client::claim(&f.setup, f.revealed_secret_be, None).unwrap(),
        ),
        (
            ObservationKind::Refund,
            solana_program_client::refund(&f.setup, None).unwrap(),
        ),
    ] {
        let ix = compile(ix);
        let tx = transaction(vec![ix.clone()]);
        select_settlement_instruction(&tx, &f.setup, kind).unwrap();
        validate_instruction_accounts(&ix, &f.setup, kind).unwrap();
        for index in 0..ix.accounts.len() {
            let mut mutated = ix.clone();
            mutated.accounts[index] = SolanaPubkey([0xfe; 32]);
            assert!(validate_instruction_accounts(&mutated, &f.setup, kind).is_err());
        }
        let mut extra = ix;
        extra.accounts.push(SolanaPubkey([0xff; 32]));
        assert!(validate_instruction_accounts(&extra, &f.setup, kind).is_err());
    }
}
