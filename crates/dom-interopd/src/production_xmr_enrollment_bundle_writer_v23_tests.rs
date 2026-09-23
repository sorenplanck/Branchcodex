use super::*;
use kaystra_core::types::*;
use xmr_dleq_sigma::{
    prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use xmr_refund_policy::compensation::XmrRecoveryAvailabilityV23;
use xmr_refund_policy::NonCooperativeRefundCapability as _;
use xmr_setup_profile::{
    proof_context_hash, validate_setup, XmrAdapterProfileV1, XmrNetwork, XmrProofContextV1,
    XmrSetupBindingV1,
};

struct Fixture {
    terms: SettlementTermsV1,
    enrollment: PreparedXmrShareEnrollmentV23,
    public: ProductionXmrEnrollmentBundleV23,
    policy: XmrCompensationPolicyV11,
    profile: XmrAdapterProfileV1,
    binding: XmrSetupBindingV1,
}

// One two-proof fixture for every positive/negative case below. No daemon
// graph, wallet, registry authority or fabricated admission is needed here.
fn fixture() -> Fixture {
    let scalar = |n| {
        let mut value = [0; 32];
        value[0] = n;
        value
    };
    let t = CrossCurveSecret252::from_little_endian(scalar(7)).unwrap();
    let u = CrossCurveSecret252::from_little_endian(scalar(11)).unwrap();
    let claim = t.public_claim().unwrap();
    let refund_claim = u.public_claim().unwrap();
    let point = |n| {
        let mut value = [n; 33];
        value[0] = 2;
        value
    };
    let policy = XmrCompensationPolicyV11 {
        settlement_id: [1; 32],
        session_id: [2; 32],
        dom_chain_id: [3; 32],
        xmr_chain_id: [4; 32],
        dom_funder: [5; 32],
        xmr_funder: [6; 32],
        claim_principal_commitment: point(7),
        claim_change_commitment: point(8),
        refund_recipient_commitment: point(9),
        compensation_recipient_commitment: point(10),
        quote_dom_numerator: 3,
        quote_xmr_denominator: 2,
        xmr_principal_piconero: 101,
        dom_principal_noms: 152,
        volatility_margin_bps: 2500,
        collateral_confirmations: 6,
        cancel_height: 100,
        compensation_height: 124,
        cooperative_window_blocks: 13,
        reveal_safety_blocks: 10,
        claim_fee_noms: 2,
        cancel_fee_noms: 3,
        refund_fee_noms: 2,
        compensation_fee_noms: 8,
        bounded_availability_v23: Some(XmrRecoveryAvailabilityV23 {
            maximum_unavailability_blocks: 1,
            observation_delay_blocks: 1,
            cancel_inclusion_blocks: 1,
            refund_inclusion_blocks: 1,
        }),
    };
    let a = ParticipantId(policy.dom_funder);
    let b = ParticipantId(policy.xmr_funder);
    let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2).unwrap();
    let finality = FinalityPolicyV1 {
        min_confirmations: 3,
        max_reorg_depth: 6,
    };
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId(policy.settlement_id),
        session_id: SessionId(policy.session_id),
        intent_hash: IntentHash([11; 32]),
        solver_id: SolverId([12; 32]),
        roster: [a, b],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(policy.dom_chain_id),
            asset_id: AssetId([13; 32]),
            amount: 152,
            beneficiary: b,
            refund_to: a,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality,
            adapter_profile_hash: [14; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(policy.xmr_chain_id),
            asset_id: AssetId([15; 32]),
            amount: 101,
            beneficiary: a,
            refund_to: b,
            mechanism: LockMechanism::CrossCurveSharedSpend,
            deadline: TimelockSpec::BlockHeight { value: 100_000 },
            finality,
            adapter_profile_hash: profile.profile_hash(),
        },
        adaptor_point_sec1: claim.secp_compressed,
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 3,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: Some(policy.policy_hash().unwrap()),
        policy_version: 1,
        metadata: vec![],
    };
    policy.validate_for(&terms).unwrap();
    let context = proof_context_hash(
        &profile,
        &XmrProofContextV1 {
            settlement_id: terms.settlement_id.0,
            chain_id: terms.counterparty_leg.chain_id.0,
            asset_id: terms.counterparty_leg.asset_id.0,
            amount_piconero: 101,
            min_confirmations: 3,
            max_reorg_depth: 6,
        },
    )
    .unwrap();
    let proof = prove_bound(
        &t,
        terms.settlement_id.0,
        context,
        ROLE_XMR_SHARED_SPEND,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let refund = prove_bound(
        &u,
        terms.settlement_id.0,
        context,
        ROLE_XMR_REFUND_SHARE,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let binding = XmrSetupBindingV1 {
        settlement_id: terms.settlement_id.0,
        terms_hash: terms.terms_hash().unwrap(),
        dleq: proof,
        funding_tx_hash: [17; 32],
        expected_amount_piconero: 101,
        destination: "5OfflineFixture".into(),
        combined_spend_public_key: xmr_crypto::combine_public_shares(
            claim.ed_compressed,
            refund_claim.ed_compressed,
        )
        .unwrap(),
    };
    let setup = validate_setup(&terms, &profile, binding.clone(), None).unwrap();
    let enrollment = xmr_session_init::prepare_xmr_share_enrollment_v23(&setup, &refund).unwrap();
    let public = ProductionXmrEnrollmentBundleV23::new(
        refund,
        refund_claim.secp_compressed,
        xmr_refund_adaptor::DomRefundAdaptorExecutor::new(refund_claim).profile_hash(),
        100_000,
        "5OfflineRefund".into(),
    )
    .unwrap();
    Fixture {
        terms,
        enrollment,
        public,
        policy,
        profile,
        binding,
    }
}

fn resources() -> ProductionXmrEnrollmentLegResourcesV23 {
    ProductionXmrEnrollmentLegResourcesV23 {
        local_participant_id: [5; 32],
        secret_store: "unopened/secrets.sqlite".into(),
        sidecar_socket: "unopened-sidecar/sidecar.sock".into(),
        sidecar_timeout_ms: 1000,
        custody_directory: "unopened-archive".into(),
        sealing_key_file: "unopened-keys/archive.key".into(),
        custody_id: [18; 32],
        nullifier_store: "unopened/nullifiers.sqlite".into(),
        private_funding: None,
    }
}

fn encode(
    f: &Fixture,
    r: ProductionXmrEnrollmentLegResourcesV23,
) -> Result<ProductionLegBundleV22, Refusal> {
    encode_xmr_enrollment_leg_authority_bundle_v23(&f.terms, &f.enrollment, &f.public, &f.policy, r)
}

#[test]
fn public_writer_is_canonical_non_authorizing_and_shares_decoder_refusals() {
    let f = fixture();
    let original = encode(&f, resources()).unwrap();
    let wire: WireV11 = serde_json::from_slice(original.bytes()).unwrap();
    assert_eq!(serde_json::to_vec(&wire).unwrap(), original.bytes());
    assert_eq!(
        original.digest(),
        ProductionUniversalLegV11::bundle_digest(original.bytes()).unwrap()
    );
    assert_eq!(wire.format, FORMAT);
    assert_eq!(wire.settlement_id, f.terms.settlement_id.0);
    assert_eq!(wire.terms_hash, f.terms.terms_hash().unwrap());
    let WireAuthorityV11::MoneroEnrollment(value) = wire.authority else {
        panic!("native enrollment discriminator required")
    };
    assert!(
        value.scope.is_none() && value.validated_compensation.is_none(),
        "writer must not mint runtime capabilities"
    );
    value
        .validate_enrollment_parameters_v23(
            &f.terms,
            f.enrollment.setup(),
            &f.enrollment,
            &f.public,
        )
        .unwrap();
    assert!(!String::from_utf8(original.bytes().to_vec())
        .unwrap()
        .contains("refund_template_hash"));
    // A real XMR funder must explicitly supply its independent candidate.
    let mut funder = resources();
    funder.local_participant_id = [6; 32];
    assert!(encode(&f, funder.clone()).is_err());
    funder.private_funding = Some(ProductionXmrEnrollmentFundingFileV23 {
        raw_transaction_file: "unopened-funding/candidate.raw".into(),
        max_fee_piconero: 3,
    });
    assert!(encode(&f, funder.clone()).is_ok());
    funder.private_funding.as_mut().unwrap().max_fee_piconero = 4;
    assert!(encode(&f, funder).is_err());

    // Encoding never opens these nonexistent stores/sockets/credential files.
    // Both sides use the same public checks: malformed wire and the same
    // malformed typed resource input must agree, without AuthenticatedInputs.
    let cases: [fn(&mut ProductionXmrEnrollmentLegResourcesV23); 8] = [
        |r| r.local_participant_id = [99; 32],
        |r| r.sidecar_timeout_ms = 0,
        |r| r.sidecar_timeout_ms = 60_001,
        |r| r.custody_id = [0; 32],
        |r| r.custody_directory = "nested/archive".into(),
        |r| r.secret_store = "../outside.sqlite".into(),
        |r| r.nullifier_store = r.secret_store.clone(),
        |r| r.sealing_key_file = "unopened".into(),
    ];
    for change in cases {
        let mut r = resources();
        change(&mut r);
        assert!(encode(&f, r.clone()).is_err());
        let mut parsed: WireV11 = serde_json::from_slice(original.bytes()).unwrap();
        let WireAuthorityV11::MoneroEnrollment(value) = &mut parsed.authority else {
            panic!("enrollment")
        };
        value.local_participant_id = r.local_participant_id;
        value.sidecar_timeout_ms = r.sidecar_timeout_ms;
        value.secret_store = r.secret_store;
        value.sidecar_socket = r.sidecar_socket;
        value.recovery_v23.directory = r.custody_directory;
        value.recovery_v23.custody_id = r.custody_id;
        value.recovery_v23.sealing_key_file = r.sealing_key_file;
        value.recovery_v23.nullifier_store = r.nullifier_store;
        assert!(value
            .validate_enrollment_parameters_v23(
                &f.terms,
                f.enrollment.setup(),
                &f.enrollment,
                &f.public
            )
            .is_err());
    }
    let mut receiver_candidate = resources();
    receiver_candidate.private_funding = Some(ProductionXmrEnrollmentFundingFileV23 {
        raw_transaction_file: "unopened-funding/candidate.raw".into(),
        max_fee_piconero: 1,
    });
    assert!(encode(&f, receiver_candidate).is_err());
    let mut other_terms = f.terms.clone();
    other_terms.session_id = SessionId([90; 32]);
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &other_terms,
        &f.enrollment,
        &f.public,
        &f.policy,
        resources()
    )
    .is_err());
    let mut other_policy = f.policy;
    other_policy.session_id = [90; 32];
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &f.terms,
        &f.enrollment,
        &f.public,
        &other_policy,
        resources()
    )
    .is_err());
    let mut unbounded = f.policy;
    unbounded.bounded_availability_v23 = None;
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &f.terms,
        &f.enrollment,
        &f.public,
        &unbounded,
        resources()
    )
    .is_err());
    let different_point = ProductionXmrEnrollmentBundleV23::new(
        f.public.proof().clone(),
        f.terms.adaptor_point_sec1,
        f.public.executor_profile_hash(),
        f.public.deadline(),
        f.public.refund_destination().into(),
    )
    .unwrap();
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &f.terms,
        &f.enrollment,
        &different_point,
        &f.policy,
        resources()
    )
    .is_err());
    let different_profile = ProductionXmrEnrollmentBundleV23::new(
        f.public.proof().clone(),
        *f.public.adaptor_point_sec1(),
        [91; 32],
        f.public.deadline(),
        f.public.refund_destination().into(),
    )
    .unwrap();
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &f.terms,
        &f.enrollment,
        &different_profile,
        &f.policy,
        resources()
    )
    .is_err());
    // Reuse the two existing proofs to authenticate a distinct terms hash:
    // the encoder must not transpose that valid SDK enrollment into this leg.
    let mut altered = f.terms.clone();
    altered.metadata.push(1);
    let mut binding = f.binding.clone();
    binding.terms_hash = altered.terms_hash().unwrap();
    let setup = validate_setup(&altered, &f.profile, binding, None).unwrap();
    let different_enrollment =
        xmr_session_init::prepare_xmr_share_enrollment_v23(&setup, f.public.proof()).unwrap();
    assert!(encode_xmr_enrollment_leg_authority_bundle_v23(
        &f.terms,
        &different_enrollment,
        &f.public,
        &f.policy,
        resources()
    )
    .is_err());
    // Public codec remains closed against legacy fields and silent downgrade.
    let mut json: serde_json::Value = serde_json::from_slice(original.bytes()).unwrap();
    json["authority"]["parameters"]["refund_template_hash"] = serde_json::json!(vec![1u8; 32]);
    assert!(serde_json::from_value::<WireV11>(json).is_err());
}
