//! Native proof and SQLite tests. These are local custody tests, not swaps.
#[path = "support/enrollment_v23.rs"]
mod enrollment_v23;
use kaystra_core::{terms::SettlementTermsV1, types::*};
use xmr_crypto::combine_public_shares;
use xmr_dleq_nullifier_store::{DleqNullifierStore, NullifierError, RegistrationOutcome};
use xmr_dleq_sigma::{
    prove_bound, BoundCrossCurveProofV1, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE,
    ROLE_XMR_SHARED_SPEND,
};
use xmr_refund_adaptor::DomRefundAdaptorExecutor;
use xmr_refund_policy::{
    admit_refund_policy, NonCooperativeRefundCapability, ValidatedRefundPolicy,
    XmrRefundArtifactV1, XmrRefundModeV1,
};
use xmr_secret_store::{
    EncryptedSqliteSecretStore, SecretMaterialStore, SecretStoreError, SecretStoreMasterKey,
};
use xmr_session_init::{
    initialize_session_for_role_v11, initialize_session_guarded, resume_session_for_role_v11,
    SessionInitError, XmrLocalSessionSecretsV11, XmrLocalShareRoleV11,
};
use xmr_setup_profile::{
    proof_context_hash, validate_setup, ValidatedXmrSetup, XmrAdapterProfileV1, XmrNetwork,
    XmrProofContextV1, XmrSetupBindingV1,
};
use zeroize::Zeroizing;

fn scalar(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = value;
    bytes
}
struct Fixture {
    terms: SettlementTermsV1,
    setup: ValidatedXmrSetup,
    policy: ValidatedRefundPolicy,
    refund: BoundCrossCurveProofV1,
}
fn fixture() -> Fixture {
    let t = CrossCurveSecret252::from_little_endian(scalar(7)).unwrap();
    let u = CrossCurveSecret252::from_little_endian(scalar(11)).unwrap();
    let claim = t.public_claim().unwrap();
    let refund_claim = u.public_claim().unwrap();
    let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2).unwrap();
    let a = ParticipantId([1; 32]);
    let b = ParticipantId([2; 32]);
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId([4; 32]),
        session_id: SessionId([5; 32]),
        intent_hash: IntentHash([6; 32]),
        solver_id: SolverId([7; 32]),
        roster: [a, b],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId([8; 32]),
            asset_id: AssetId([9; 32]),
            amount: 100,
            beneficiary: b,
            refund_to: a,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 2,
            },
            adapter_profile_hash: [10; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId([11; 32]),
            asset_id: AssetId([12; 32]),
            amount: 100,
            beneficiary: a,
            refund_to: b,
            mechanism: LockMechanism::CrossCurveSharedSpend,
            deadline: TimelockSpec::TimestampSeconds {
                value: 1_900_000_000,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
            adapter_profile_hash: profile.profile_hash(),
        },
        adaptor_point_sec1: claim.secp_compressed,
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 10,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: vec![],
    };
    let context = proof_context_hash(
        &profile,
        &XmrProofContextV1 {
            settlement_id: terms.settlement_id.0,
            chain_id: terms.counterparty_leg.chain_id.0,
            asset_id: terms.counterparty_leg.asset_id.0,
            amount_piconero: 100,
            min_confirmations: 10,
            max_reorg_depth: 20,
        },
    )
    .unwrap();
    let mut rng = rand::thread_rng();
    let dleq = prove_bound(
        &t,
        terms.settlement_id.0,
        context,
        ROLE_XMR_SHARED_SPEND,
        &mut rng,
    )
    .unwrap();
    let refund = prove_bound(
        &u,
        terms.settlement_id.0,
        context,
        ROLE_XMR_REFUND_SHARE,
        &mut rng,
    )
    .unwrap();
    let executor = DomRefundAdaptorExecutor::new(refund_claim);
    let policy = admit_refund_policy(
        &terms,
        XmrNetwork::Stagenet,
        XmrRefundModeV1::AdaptorRefundRequired,
        Some(XmrRefundArtifactV1 {
            template_hash: [16; 32],
            adaptor_point_sec1: refund_claim.secp_compressed,
            executor_profile_hash: executor.profile_hash(),
            deadline: 1_900_000_000,
        }),
        None,
        Some(&executor),
    )
    .unwrap();
    let setup = validate_setup(
        &terms,
        &profile,
        XmrSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash().unwrap(),
            dleq,
            funding_tx_hash: [15; 32],
            expected_amount_piconero: 100,
            destination: "5FixtureDestination".into(),
            combined_spend_public_key: combine_public_shares(
                claim.ed_compressed,
                refund_claim.ed_compressed,
            )
            .unwrap(),
        },
        None,
    )
    .unwrap();
    Fixture {
        terms,
        setup,
        policy,
        refund,
    }
}
fn local(role: XmrLocalShareRoleV11, share: u8) -> XmrLocalSessionSecretsV11 {
    XmrLocalSessionSecretsV11 {
        role,
        spend_share: Zeroizing::new(scalar(share)),
        view_key: Zeroizing::new(scalar(13)),
    }
}

#[test]
fn both_roles_reopen_their_own_single_share_and_resume_after_registration_cut() {
    let f = fixture();
    let mut rng = rand::thread_rng();
    for (role, share) in [
        (XmrLocalShareRoleV11::ClaimReceiver, 11),
        (XmrLocalShareRoleV11::RefundReceiver, 7),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("secrets.sqlite");
        let registry = dir.path().join("nullifiers.sqlite");
        let store =
            EncryptedSqliteSecretStore::open(&db, SecretStoreMasterKey::new([9; 32]).unwrap())
                .unwrap();
        let nullifiers = DleqNullifierStore::open(&registry).unwrap();
        // Represents a process death between the two durable records.
        assert_eq!(
            nullifiers
                .register(
                    f.setup.settlement_id(),
                    f.setup.binding_hash(),
                    &f.setup.claim()
                )
                .unwrap(),
            RegistrationOutcome::Inserted
        );
        drop(nullifiers);
        drop(store);
        let store = EncryptedSqliteSecretStore::open_existing(
            &db,
            SecretStoreMasterKey::new([9; 32]).unwrap(),
        )
        .unwrap();
        let nullifiers = DleqNullifierStore::open_existing(&registry).unwrap();
        for _ in 0..2 {
            let done = initialize_session_for_role_v11(
                &f.setup,
                &store,
                &nullifiers,
                &f.policy,
                &f.refund,
                local(role, share),
                &mut rng,
            )
            .unwrap();
            assert_eq!(done.nullifier, RegistrationOutcome::Idempotent);
        }
        drop(store);
        let reopened = EncryptedSqliteSecretStore::open_existing(
            &db,
            SecretStoreMasterKey::new([9; 32]).unwrap(),
        )
        .unwrap();
        resume_session_for_role_v11(&f.setup, &reopened, &nullifiers, &f.policy, &f.refund, role)
            .unwrap();
        let wrong_role = match role {
            XmrLocalShareRoleV11::ClaimReceiver => XmrLocalShareRoleV11::RefundReceiver,
            XmrLocalShareRoleV11::RefundReceiver => XmrLocalShareRoleV11::ClaimReceiver,
        };
        assert_eq!(
            resume_session_for_role_v11(
                &f.setup,
                &reopened,
                &nullifiers,
                &f.policy,
                &f.refund,
                wrong_role
            ),
            Err(SessionInitError::InvalidKeyMaterial)
        );
        reopened
            .load(&f.setup.settlement_id(), &f.setup.terms_hash())
            .unwrap()
            .expose(|spend, view| {
                assert_eq!(*spend, scalar(share));
                assert_eq!(*view, scalar(13));
                assert_ne!(*spend, scalar(18));
            });
    }
}

#[test]
fn wrong_role_or_refund_proof_leaves_both_stores_unmodified() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let mut rng = rand::thread_rng();
    let store = EncryptedSqliteSecretStore::open(
        dir.path().join("secrets.sqlite"),
        SecretStoreMasterKey::new([9; 32]).unwrap(),
    )
    .unwrap();
    let nullifiers = DleqNullifierStore::open(dir.path().join("nullifiers.sqlite")).unwrap();
    assert!(matches!(
        initialize_session_for_role_v11(
            &f.setup,
            &store,
            &nullifiers,
            &f.policy,
            &f.refund,
            local(XmrLocalShareRoleV11::ClaimReceiver, 7),
            &mut rng
        ),
        Err(SessionInitError::InvalidKeyMaterial)
    ));
    let mut wrong = f.refund.clone();
    wrong.role = ROLE_XMR_SHARED_SPEND;
    assert!(matches!(
        initialize_session_for_role_v11(
            &f.setup,
            &store,
            &nullifiers,
            &f.policy,
            &wrong,
            local(XmrLocalShareRoleV11::ClaimReceiver, 11),
            &mut rng
        ),
        Err(SessionInitError::InvalidRefundProof)
    ));
    assert!(matches!(
        store.load(&f.setup.settlement_id(), &f.setup.terms_hash()),
        Err(SecretStoreError::NotFound)
    ));
    assert_eq!(
        nullifiers
            .register(
                f.setup.settlement_id(),
                f.setup.binding_hash(),
                &f.setup.claim()
            )
            .unwrap(),
        RegistrationOutcome::Inserted
    );
}

#[test]
fn funded_resume_never_repairs_a_missing_claim_or_secret_row() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.sqlite");
    let registry = dir.path().join("nullifiers.sqlite");
    let store =
        EncryptedSqliteSecretStore::open(&db, SecretStoreMasterKey::new([9; 32]).unwrap()).unwrap();
    let nullifiers = DleqNullifierStore::open(&registry).unwrap();
    assert_eq!(
        resume_session_for_role_v11(
            &f.setup,
            &store,
            &nullifiers,
            &f.policy,
            &f.refund,
            XmrLocalShareRoleV11::ClaimReceiver
        ),
        Err(SessionInitError::Nullifier(NullifierError::NotFound))
    );
    assert_eq!(
        nullifiers
            .register(
                f.setup.settlement_id(),
                f.setup.binding_hash(),
                &f.setup.claim()
            )
            .unwrap(),
        RegistrationOutcome::Inserted
    );
    assert_eq!(
        resume_session_for_role_v11(
            &f.setup,
            &store,
            &nullifiers,
            &f.policy,
            &f.refund,
            XmrLocalShareRoleV11::ClaimReceiver
        ),
        Err(SessionInitError::Store(SecretStoreError::NotFound))
    );
    assert!(matches!(
        store.load(&f.setup.settlement_id(), &f.setup.terms_hash()),
        Err(SecretStoreError::NotFound)
    ));
    initialize_session_for_role_v11(
        &f.setup,
        &store,
        &nullifiers,
        &f.policy,
        &f.refund,
        local(XmrLocalShareRoleV11::ClaimReceiver, 11),
        &mut rand::thread_rng(),
    )
    .unwrap();
    drop(store);
    drop(nullifiers);
    let wrong_key =
        EncryptedSqliteSecretStore::open_existing(&db, SecretStoreMasterKey::new([8; 32]).unwrap())
            .unwrap();
    let nullifiers = DleqNullifierStore::open_existing(&registry).unwrap();
    assert_eq!(
        resume_session_for_role_v11(
            &f.setup,
            &wrong_key,
            &nullifiers,
            &f.policy,
            &f.refund,
            XmrLocalShareRoleV11::ClaimReceiver
        ),
        Err(SessionInitError::Store(
            SecretStoreError::AuthenticationFailed
        ))
    );
}

#[test]
fn legacy_claim_receiver_cannot_store_u_for_a_different_refund_adaptor() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let other = CrossCurveSecret252::from_little_endian(scalar(17))
        .unwrap()
        .public_claim()
        .unwrap();
    let executor = DomRefundAdaptorExecutor::new(other);
    let wrong = admit_refund_policy(
        &f.terms,
        XmrNetwork::Stagenet,
        XmrRefundModeV1::AdaptorRefundRequired,
        Some(XmrRefundArtifactV1 {
            template_hash: [16; 32],
            adaptor_point_sec1: other.secp_compressed,
            executor_profile_hash: executor.profile_hash(),
            deadline: 1_900_000_000,
        }),
        None,
        Some(&executor),
    )
    .unwrap();
    let store = EncryptedSqliteSecretStore::open(
        dir.path().join("secrets.sqlite"),
        SecretStoreMasterKey::new([9; 32]).unwrap(),
    )
    .unwrap();
    let nullifiers = DleqNullifierStore::open(dir.path().join("nullifiers.sqlite")).unwrap();
    assert!(matches!(
        initialize_session_guarded(
            &f.setup,
            &store,
            &nullifiers,
            &wrong,
            scalar(11),
            scalar(13),
            &mut rand::thread_rng()
        ),
        Err(SessionInitError::Refund(
            xmr_refund_policy::RefundPolicyError::ScopeMismatch
        ))
    ));
    assert_eq!(
        nullifiers.require_registered(
            f.setup.settlement_id(),
            f.setup.binding_hash(),
            &f.setup.claim()
        ),
        Err(NullifierError::NotFound)
    );
    assert!(matches!(
        store.load(&f.setup.settlement_id(), &f.setup.terms_hash()),
        Err(SecretStoreError::NotFound)
    ));
    initialize_session_guarded(
        &f.setup,
        &store,
        &nullifiers,
        &f.policy,
        scalar(11),
        scalar(13),
        &mut rand::thread_rng(),
    )
    .unwrap();
}
