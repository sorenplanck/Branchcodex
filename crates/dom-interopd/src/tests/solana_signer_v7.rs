use super::*;
use kaystra_core::{terms::SettlementTermsV1, types::*};
use rand::{rngs::StdRng, SeedableRng};
use solana_profile::{SolanaAdapterProfileV1, SolanaNetwork, SolanaSetupBindingV1};
use std::sync::OnceLock;
use xmr_dleq_sigma::{prove_bound, CrossCurveSecret252, ROLE_SOLANA_CONDITION_LOCK};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    setup: ValidatedSolanaSetup,
    secret: [u8; 32],
}
fn fixture(spl: bool) -> &'static Fixture {
    static NATIVE: OnceLock<Fixture> = OnceLock::new();
    static TOKEN: OnceLock<Fixture> = OnceLock::new();
    (if spl { &TOKEN } else { &NATIVE }).get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(70 + u64::from(spl));
        let mut witness = [0; 32];
        witness[0] = 9;
        let secret = CrossCurveSecret252::from_little_endian(witness).unwrap();
        let funder = SolanaPubkey(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
        let recipient = SolanaPubkey(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        let profile = SolanaAdapterProfileV1::new(
            SolanaNetwork::LocalValidator,
            SolanaPubkey([13; 32]),
            3,
            2,
        )
        .unwrap();
        let asset = if spl {
            SolanaAssetV1::LegacySpl {
                mint: SolanaPubkey([70; 32]),
                decimals: 6,
            }
        } else {
            SolanaAssetV1::NativeSol
        };
        let mut roster = [ParticipantId(funder.0), ParticipantId(recipient.0)];
        roster.sort();
        let terms = SettlementTermsV1 {
            settlement_id: SettlementId([31 + u8::from(spl); 32]),
            session_id: SessionId([2; 32]),
            intent_hash: IntentHash([3; 32]),
            solver_id: SolverId([4; 32]),
            roster,
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([0xd0; 32]),
                asset_id: AssetId([0xd1; 32]),
                amount: 500,
                beneficiary: ParticipantId(funder.0),
                refund_to: ParticipantId(recipient.0),
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
                chain_id: ChainId([0x51; 32]),
                asset_id: AssetId([0x52; 32]),
                amount: 500,
                beneficiary: ParticipantId(recipient.0),
                refund_to: ParticipantId(funder.0),
                mechanism: LockMechanism::CrossCurveConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: 2_000_000_000,
                },
                finality: FinalityPolicyV1 {
                    min_confirmations: 1,
                    max_reorg_depth: 32,
                },
                adapter_profile_hash: profile.profile_hash(),
            },
            adaptor_point_sec1: secret.public_claim().unwrap().secp_compressed,
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
        let context = solana_profile::proof_context_from_terms(&terms, asset, funder).unwrap();
        let context_hash = solana_profile::proof_context_hash(&profile, &context).unwrap();
        let dleq = prove_bound(
            &secret,
            terms.settlement_id.0,
            context_hash,
            ROLE_SOLANA_CONDITION_LOCK,
            &mut rng,
        )
        .unwrap();
        let pdas =
            solana_pda::derive_escrow_pdas(profile.program_id, terms.settlement_id.0).unwrap();
        let mut binding = SolanaSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash().unwrap(),
            dleq,
            program_id: profile.program_id,
            state_pda: pdas.state,
            vault_pda: if spl {
                pdas.token_vault
            } else {
                pdas.native_vault
            },
            vault_authority: pdas.vault_authority,
            state_bump: pdas.state_bump,
            vault_bump: if spl {
                pdas.token_vault_bump
            } else {
                pdas.native_vault_bump
            },
            authority_bump: pdas.vault_authority_bump,
            asset,
            funder,
            recipient,
            refund_recipient: funder,
            amount: 500,
            refund_after_unix: 2_000_000_000,
            program_data_hash: [71; 32],
            setup_id: [0; 32],
        };
        binding.setup_id = solana_profile::setup_id(&binding).unwrap();
        Fixture {
            setup: solana_profile::validate_setup(&profile, &terms, binding).unwrap(),
            secret: secret.dom_secret_big_endian(),
        }
    })
}
fn accounts(spl: bool) -> Option<ProductionSolanaTokenAccountsV7> {
    spl.then_some(ProductionSolanaTokenAccountsV7 {
        source: SolanaPubkey([80; 32]),
        recipient: SolanaPubkey([81; 32]),
        refund: SolanaPubkey([82; 32]),
    })
}
fn binding(spl: bool, role: ProductionSolanaSignerRoleV7) -> ProductionSolanaSignerBindingV7 {
    let setup = fixture(spl).setup.clone();
    let account = if role == ProductionSolanaSignerRoleV7::Funder {
        setup.funder()
    } else {
        setup.recipient()
    };
    // Unit fixture bypasses only the production admission layer. Setup/PDA,
    // DLEQ, message construction and every signer check remain real.
    ProductionSolanaSignerBindingV7 {
        setup,
        accounts: accounts(spl),
        role,
        account,
        digest: [90 + u8::from(spl); 32],
    }
}
fn plan(spl: bool, action: SettlementActionV1) -> LegacyMessagePlan {
    let setup = &fixture(spl).setup;
    let secret = (action == SettlementActionV1::Claim).then_some(fixture(spl).secret);
    let payer = if action == SettlementActionV1::Claim {
        setup.recipient()
    } else {
        setup.funder()
    };
    build_legacy_message(
        payer,
        SolanaHash([50; 32]),
        &instructions_v7(setup, accounts(spl), action, secret).unwrap(),
    )
    .unwrap()
}
fn local(spl: bool, role: ProductionSolanaSignerRoleV7) -> ProductionSolanaLocalSignerV7 {
    ProductionSolanaLocalSignerV7::new(
        binding(spl, role),
        Zeroizing::new(
            [if role == ProductionSolanaSignerRoleV7::Funder {
                7
            } else {
                8
            }; 32],
        ),
    )
    .unwrap()
}

#[test]
fn v7_solana_native_and_spl_sign_fund_claim_refund() -> TestResult {
    let mut exported = Vec::new();
    for spl in [false, true] {
        for action in [
            SettlementActionV1::Funding,
            SettlementActionV1::Claim,
            SettlementActionV1::Refund,
        ] {
            let role = if action == SettlementActionV1::Claim {
                ProductionSolanaSignerRoleV7::Beneficiary
            } else {
                ProductionSolanaSignerRoleV7::Funder
            };
            let mut signer = local(spl, role);
            let plan = plan(spl, action);
            let signature = signer.sign_message(&plan.message)?;
            let transaction = assemble_signed_transaction(&plan, &[(signer.account(), signature)])?;
            let again = local(spl, role).sign_message(&plan.message)?;
            assert_eq!(signature, again);
            exported.push(serde_json::json!({"asset": if spl { "spl" } else { "sol" }, "action": format!("{action:?}"),
            "payer": hex::encode(signer.account().0), "message": hex::encode(&plan.message), "signature": hex::encode(signature.0),
            "transaction": hex::encode(transaction)}));
        }
    }
    if let Some(path) = std::env::var_os("DOM_INTEROP_V7_SOLANA_SIGNATURES") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &serde_json::json!({"schema": 7, "chain_e2e": false, "signatures": exported}),
            )?,
        )?;
    }
    Ok(())
}

#[test]
fn v7_solana_signer_rejects_wrong_roles_keys_secrets_and_arbitrary_transfer() {
    for spl in [false, true] {
        let funding = plan(spl, SettlementActionV1::Funding);
        let claim = plan(spl, SettlementActionV1::Claim);
        assert!(local(spl, ProductionSolanaSignerRoleV7::Beneficiary)
            .sign_message(&funding.message)
            .is_err());
        assert!(local(spl, ProductionSolanaSignerRoleV7::Funder)
            .sign_message(&claim.message)
            .is_err());
        assert!(ProductionSolanaLocalSignerV7::new(
            binding(spl, ProductionSolanaSignerRoleV7::Funder),
            Zeroizing::new([8; 32])
        )
        .is_err());
        let mut wrong = claim.message.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(local(spl, ProductionSolanaSignerRoleV7::Beneficiary)
            .sign_message(&wrong)
            .is_err());
        let close = build_legacy_message(
            fixture(spl).setup.funder(),
            SolanaHash([50; 32]),
            &[solana_program_client::close(&fixture(spl).setup)],
        )
        .unwrap();
        assert!(local(spl, ProductionSolanaSignerRoleV7::Funder)
            .sign_message(&close.message)
            .is_err());
    }
}

#[test]
fn v7_solana_signer_rejects_every_non_blockhash_byte_mutation() {
    for spl in [false, true] {
        let valid = plan(spl, SettlementActionV1::Funding);
        let message = &valid.message;
        let mut cursor = Cursor {
            bytes: message,
            at: 3,
        };
        let count = cursor.short().unwrap();
        cursor.take(count * 32).unwrap();
        let hash_start = cursor.at;
        for index in 0..message.len() {
            if (hash_start..hash_start + 32).contains(&index) {
                continue;
            }
            let mut changed = message.clone();
            changed[index] ^= 1;
            assert!(
                binding(spl, ProductionSolanaSignerRoleV7::Funder)
                    .validate_message(&changed)
                    .is_err(),
                "byte {index}"
            );
        }
        for end in 0..message.len() {
            assert!(message_shape(&message[..end]).is_err());
        }
        let mut trailing = message.clone();
        trailing.push(0);
        assert!(message_shape(&trailing).is_err());
    }
}

#[test]
fn v7_solana_unix_round_trip_and_retry_exact_bytes() -> TestResult {
    for spl in [false, true] {
        let (client, mut server) = UnixStream::pair()?;
        let worker = std::thread::spawn(move || {
            let mut signer = local(spl, ProductionSolanaSignerRoleV7::Funder);
            for _ in 0..2 {
                signer
                    .serve_once(&mut server, Duration::from_secs(5))
                    .unwrap();
            }
        });
        let mut signer = ProductionSolanaUnixSignerV7::new(
            binding(spl, ProductionSolanaSignerRoleV7::Funder),
            client,
            Duration::from_secs(5),
        )?;
        let message = plan(spl, SettlementActionV1::Funding).message;
        let a = signer.sign_message(&message)?;
        let b = signer.sign_message(&message)?;
        assert_eq!(a, b);
        worker.join().unwrap();
    }
    Ok(())
}

#[test]
fn v7_solana_wrong_reply_is_hard_error_and_poisoned_socket_cannot_retry() -> TestResult {
    let (client, mut server) = UnixStream::pair()?;
    let worker = std::thread::spawn(move || {
        let mut header = [0; 42];
        server.read_exact(&mut header).unwrap();
        let length = usize::from(u16::from_be_bytes([header[40], header[41]]));
        let mut body = vec![0; length];
        server.read_exact(&mut body).unwrap();
        let mut response = [0; 136];
        response[..8].copy_from_slice(RESPONSE);
        response[8..40].copy_from_slice(&[99; 32]);
        server.write_all(&response).unwrap();
    });
    let mut signer = ProductionSolanaUnixSignerV7::new(
        binding(false, ProductionSolanaSignerRoleV7::Funder),
        client,
        Duration::from_secs(5),
    )?;
    let message = plan(false, SettlementActionV1::Refund).message;
    assert!(matches!(
        signer.sign_message(&message),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        signer.sign_message(&message),
        Err(Error::Unavailable)
    ));
    worker.join().unwrap();
    Ok(())
}

#[test]
fn v7_solana_silent_peer_times_out_and_noncanonical_lengths_refuse() -> TestResult {
    let (client, _server) = UnixStream::pair()?;
    let mut signer = ProductionSolanaUnixSignerV7::new(
        binding(false, ProductionSolanaSignerRoleV7::Funder),
        client,
        Duration::from_millis(20),
    )?;
    assert!(matches!(
        signer.sign_message(&plan(false, SettlementActionV1::Refund).message),
        Err(Error::Unavailable)
    ));
    for bytes in [&[0x80, 0][..], &[0x80, 0x80, 0], &[0xff, 0xff, 4], &[0x80]] {
        assert!(Cursor { bytes, at: 0 }.short().is_err());
    }
    assert!(message_shape(&vec![0; MAX_MESSAGE + 1]).is_err());
    Ok(())
}

#[test]
fn v7_solana_token_accounts_are_explicit_and_vault_cannot_be_destination() {
    assert!(validate_token_accounts_v7(&fixture(false).setup, accounts(true)).is_err());
    assert!(validate_token_accounts_v7(&fixture(true).setup, None).is_err());
    let mut a = accounts(true).unwrap();
    a.refund = fixture(true).setup.vault_pda();
    assert!(validate_token_accounts_v7(&fixture(true).setup, Some(a)).is_err());
    let wrong_accounts = Some(ProductionSolanaTokenAccountsV7 {
        recipient: SolanaPubkey([84; 32]),
        ..accounts(true).unwrap()
    });
    let message = build_legacy_message(
        fixture(true).setup.recipient(),
        SolanaHash([50; 32]),
        &instructions_v7(
            &fixture(true).setup,
            wrong_accounts,
            SettlementActionV1::Claim,
            Some(fixture(true).secret),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(local(true, ProductionSolanaSignerRoleV7::Beneficiary)
        .sign_message(&message.message)
        .is_err());
}
