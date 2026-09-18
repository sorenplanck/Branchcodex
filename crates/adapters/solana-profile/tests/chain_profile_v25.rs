//! V25 setup validation: the escrow pays authenticated Solana accounts and the
//! terms pin the registry chain-profile digest.
//!
//! Participant identities here are plain digests, as a DOM participant id is
//! in production, never Ed25519 keys: that is exactly the case V1 cannot pay.

use adapter_btc::timelock::ChainTimingBoundsV1;
use chain_profile::{ChainKindV1, ChainProfileV1, SolanaNetworkV1};
use kaystra_core::{terms::SettlementTermsV1, types::*};
use rand::{rngs::StdRng, SeedableRng};
use solana_profile::{
    proof_context_from_terms, proof_context_hash, require_chain_profile_v25,
    revalidate_setup_for_chain_profile_v25, setup_id, validate_setup,
    validate_setup_for_chain_profile_v25, SolanaAdapterProfileV1, SolanaAssetV1, SolanaNetwork,
    SolanaSetupAccountsV25, SolanaSetupBindingV1,
};
use solana_types::SolanaPubkey;
use xmr_dleq_sigma::{prove_bound, CrossCurveSecret252, ROLE_SOLANA_CONDITION_LOCK};

const PROGRAM: [u8; 32] = [13; 32];
const PROGRAM_DATA_HASH: [u8; 32] = [71; 32];
const DEADLINE: u64 = 2_000_000_000;

struct Built {
    profile: SolanaAdapterProfileV1,
    registry: ChainProfileV1,
    terms: SettlementTermsV1,
    binding: SolanaSetupBindingV1,
    accounts: SolanaSetupAccountsV25,
}

fn registry_profile() -> ChainProfileV1 {
    ChainProfileV1 {
        chain_id: ChainId([0x51; 32]),
        kind: ChainKindV1::Solana {
            network: SolanaNetworkV1::LocalValidator,
            escrow_program: PROGRAM,
            program_data_hash: PROGRAM_DATA_HASH,
        },
        timing: ChainTimingBoundsV1 {
            min_block_seconds: 1,
            max_block_seconds: 2,
            max_reorg_seconds: 128,
            observation_seconds: 5,
            broadcast_seconds: 5,
        },
        finality: FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 32,
        },
        native_asset: AssetId([0x52; 32]),
        allowed_assets: vec![],
    }
}

fn build() -> Built {
    let mut rng = StdRng::seed_from_u64(25);
    let mut witness = [0; 32];
    witness[0] = 9;
    let secret = CrossCurveSecret252::from_little_endian(witness).expect("secret");
    let profile = SolanaAdapterProfileV1::new_attested(
        SolanaNetwork::LocalValidator,
        SolanaPubkey(PROGRAM),
        1,
        1,
    )
    .expect("attested profile");
    let registry = registry_profile();
    let funder_participant = ParticipantId([0x21; 32]);
    let beneficiary_participant = ParticipantId([0x31; 32]);
    let accounts = SolanaSetupAccountsV25 {
        funder: SolanaPubkey([7; 32]),
        recipient: SolanaPubkey([8; 32]),
        refund_recipient: SolanaPubkey([7; 32]),
    };
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId([31; 32]),
        session_id: SessionId([2; 32]),
        intent_hash: IntentHash([3; 32]),
        solver_id: SolverId([4; 32]),
        roster: [funder_participant, beneficiary_participant],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId([0xd0; 32]),
            asset_id: AssetId([0xd1; 32]),
            amount: 500,
            beneficiary: funder_participant,
            refund_to: beneficiary_participant,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 1000 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 32,
            },
            adapter_profile_hash: [0xd2; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: registry.chain_id,
            asset_id: registry.native_asset,
            amount: 500,
            beneficiary: beneficiary_participant,
            refund_to: funder_participant,
            mechanism: LockMechanism::CrossCurveConditionLock,
            deadline: TimelockSpec::TimestampSeconds { value: DEADLINE },
            finality: registry.finality,
            adapter_profile_hash: registry.profile_digest().expect("registry digest"),
        },
        adaptor_point_sec1: secret.public_claim().expect("claim").secp_compressed,
        fee_limit: FeeLimitV1 {
            dom_max: 50,
            counterparty_max: 50,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 1000,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: vec![],
    };
    let asset = SolanaAssetV1::NativeSol;
    let context = proof_context_from_terms(&terms, asset, accounts.funder).expect("context");
    let context_hash = proof_context_hash(&profile, &context).expect("context hash");
    let dleq = prove_bound(
        &secret,
        terms.settlement_id.0,
        context_hash,
        ROLE_SOLANA_CONDITION_LOCK,
        &mut rng,
    )
    .expect("dleq");
    let pdas = solana_pda::derive_escrow_pdas(profile.program_id, terms.settlement_id.0)
        .expect("pdas");
    let mut binding = SolanaSetupBindingV1 {
        settlement_id: terms.settlement_id.0,
        terms_hash: terms.terms_hash().expect("terms hash"),
        dleq,
        program_id: profile.program_id,
        state_pda: pdas.state,
        vault_pda: pdas.native_vault,
        vault_authority: pdas.vault_authority,
        state_bump: pdas.state_bump,
        vault_bump: pdas.native_vault_bump,
        authority_bump: pdas.vault_authority_bump,
        asset,
        funder: accounts.funder,
        recipient: accounts.recipient,
        refund_recipient: accounts.refund_recipient,
        amount: 500,
        refund_after_unix: DEADLINE as i64,
        program_data_hash: PROGRAM_DATA_HASH,
        setup_id: [0; 32],
    };
    binding.setup_id = setup_id(&binding).expect("setup id");
    Built {
        profile,
        registry,
        terms,
        binding,
        accounts,
    }
}

#[test]
fn authenticated_accounts_are_paid_instead_of_participant_digests() {
    let built = build();
    let setup = validate_setup_for_chain_profile_v25(
        &built.profile,
        &built.terms,
        built.binding.clone(),
        &built.registry,
        built.accounts,
    )
    .expect("V25 setup");
    assert_eq!(setup.recipient(), built.accounts.recipient);
    assert_eq!(setup.refund_recipient(), built.accounts.funder);
    assert_ne!(setup.recipient().0, built.terms.counterparty_leg.beneficiary.0);
    assert_ne!(
        setup.refund_recipient().0,
        built.terms.counterparty_leg.refund_to.0
    );
    // The frozen V1 rule refuses this setup twice over: the recipient is not
    // the participant id and the terms carry the registry digest.
    assert!(validate_setup(&built.profile, &built.terms, built.binding).is_err());
}

#[test]
fn the_accounts_must_be_exactly_the_authenticated_ones() {
    let built = build();
    let refused = |accounts| {
        validate_setup_for_chain_profile_v25(
            &built.profile,
            &built.terms,
            built.binding.clone(),
            &built.registry,
            accounts,
        )
        .is_err()
    };
    assert!(refused(SolanaSetupAccountsV25 {
        recipient: SolanaPubkey([9; 32]),
        ..built.accounts
    }));
    assert!(refused(SolanaSetupAccountsV25 {
        refund_recipient: built.accounts.recipient,
        ..built.accounts
    }));
    assert!(refused(SolanaSetupAccountsV25 {
        funder: SolanaPubkey([9; 32]),
        ..built.accounts
    }));
    // Funder and recipient may never be the same account, even if both the
    // binding and the claimed accounts agree on it.
    let mut same = built.binding.clone();
    same.recipient = same.funder;
    same.setup_id = setup_id(&same).expect("setup id");
    assert!(validate_setup_for_chain_profile_v25(
        &built.profile,
        &built.terms,
        same,
        &built.registry,
        SolanaSetupAccountsV25 {
            recipient: built.accounts.funder,
            ..built.accounts
        },
    )
    .is_err());

    // Even when the public binding and supplied setup accounts agree, a
    // refund account different from the funder has no V25 authority path.
    let mut diverted = built.binding.clone();
    diverted.refund_recipient = SolanaPubkey([10; 32]);
    diverted.setup_id = setup_id(&diverted).expect("setup id");
    assert!(validate_setup_for_chain_profile_v25(
        &built.profile,
        &built.terms,
        diverted,
        &built.registry,
        SolanaSetupAccountsV25 {
            refund_recipient: SolanaPubkey([10; 32]),
            ..built.accounts
        },
    )
    .is_err());
}

#[test]
fn the_registry_profile_is_the_only_hash_authority() {
    let built = build();
    assert_eq!(
        require_chain_profile_v25(&built.terms, &built.profile, &built.registry)
            .expect("registry boundary"),
        built.registry.profile_digest().expect("digest")
    );
    // The operational adapter hash in the terms is refused under V25.
    let mut operational = built.terms.clone();
    operational.counterparty_leg.adapter_profile_hash = built.profile.profile_hash();
    assert!(require_chain_profile_v25(&operational, &built.profile, &built.registry).is_err());
    // A registry that pins another program data hash, program or cluster.
    let mut other_code = built.registry.clone();
    other_code.kind = ChainKindV1::Solana {
        network: SolanaNetworkV1::LocalValidator,
        escrow_program: PROGRAM,
        program_data_hash: [72; 32],
    };
    let mut other_program = built.registry.clone();
    other_program.kind = ChainKindV1::Solana {
        network: SolanaNetworkV1::LocalValidator,
        escrow_program: [14; 32],
        program_data_hash: PROGRAM_DATA_HASH,
    };
    let mut other_cluster = built.registry.clone();
    other_cluster.kind = ChainKindV1::Solana {
        network: SolanaNetworkV1::Devnet,
        escrow_program: PROGRAM,
        program_data_hash: PROGRAM_DATA_HASH,
    };
    for registry in [other_code, other_program, other_cluster] {
        assert!(validate_setup_for_chain_profile_v25(
            &built.profile,
            &built.terms,
            built.binding.clone(),
            &registry,
            built.accounts,
        )
        .is_err());
    }
    // The unattested local profile is refused even with matching facts.
    let unattested =
        SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, SolanaPubkey(PROGRAM), 1, 1)
            .expect("profile");
    assert!(require_chain_profile_v25(&built.terms, &unattested, &built.registry).is_err());
}

#[test]
fn revalidation_reproduces_the_same_setup_and_nothing_else() {
    let built = build();
    let setup = validate_setup_for_chain_profile_v25(
        &built.profile,
        &built.terms,
        built.binding,
        &built.registry,
        built.accounts,
    )
    .expect("V25 setup");
    let again =
        revalidate_setup_for_chain_profile_v25(&built.profile, &built.terms, &setup, &built.registry)
            .expect("revalidation");
    assert_eq!(again.binding_hash(), setup.binding_hash());
    let mut foreign = built.registry.clone();
    foreign.kind = ChainKindV1::Solana {
        network: SolanaNetworkV1::LocalValidator,
        escrow_program: PROGRAM,
        program_data_hash: [72; 32],
    };
    assert!(
        revalidate_setup_for_chain_profile_v25(&built.profile, &built.terms, &setup, &foreign)
            .is_err()
    );
}
