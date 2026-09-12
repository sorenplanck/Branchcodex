//! Funding budgets must use the same validated policy as C's native proof.
use super::*;
use kaystra_core::types::*;
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;

#[path = "wallet_funding_xmr_v22_native_tests.rs"]
mod native;

fn fixture() -> (XmrCompensationPolicyV11, SettlementTermsV1) {
    let point = |byte: u8| {
        let mut result = [byte; 33];
        result[0] = 2;
        result
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
        compensation_height: 121,
        cooperative_window_blocks: 10,
        reveal_safety_blocks: 10,
        claim_fee_noms: 2,
        cancel_fee_noms: 3,
        refund_fee_noms: 2,
        compensation_fee_noms: 8,
        bounded_availability_v23: None,
    };
    let dom_funder = ParticipantId(policy.dom_funder);
    let xmr_funder = ParticipantId(policy.xmr_funder);
    let finality = FinalityPolicyV1 {
        min_confirmations: 3,
        max_reorg_depth: 6,
    };
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId(policy.settlement_id),
        session_id: SessionId(policy.session_id),
        intent_hash: IntentHash([11; 32]),
        solver_id: SolverId([12; 32]),
        roster: [dom_funder, xmr_funder],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(policy.dom_chain_id),
            asset_id: AssetId([13; 32]),
            amount: u128::from(policy.dom_principal_noms),
            beneficiary: xmr_funder,
            refund_to: dom_funder,
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
            beneficiary: dom_funder,
            refund_to: xmr_funder,
            mechanism: LockMechanism::CrossCurveSharedSpend,
            deadline: TimelockSpec::TimestampSeconds {
                value: 1_900_000_000,
            },
            finality,
            adapter_profile_hash: [16; 32],
        },
        adaptor_point_sec1: point(17),
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 3,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: Some(policy.policy_hash().expect("canonical policy")),
        policy_version: 1,
        metadata: vec![],
    };
    (policy, terms)
}

#[test]
fn xmr_funding_budget_uses_collateral_and_rejects_missing_or_substituted_policy() {
    let (policy, mut terms) = fixture();
    terms.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
    let validated = policy.validate_for(&terms).unwrap();
    assert_eq!(funding_budget(&terms, Some(&validated)).unwrap(), (201, 10));
    assert!(funding_budget(&terms, None).is_err());
    assert!(
        dom_adaptor::DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max,)
            .is_err(),
        "the tiny fixture fee cannot satisfy the ordinary recovery budget"
    );
    assert_ne!(
        u128::from(validated.collateral_noms()),
        terms.dom_leg.amount
    );

    let mut wrong_amount = terms.clone();
    wrong_amount.dom_leg.amount += 1;
    assert!(funding_budget(&wrong_amount, Some(&validated)).is_err());

    let mut wrong_session = terms.clone();
    wrong_session.session_id.0[0] ^= 1;
    assert!(funding_budget(&wrong_session, Some(&validated)).is_err());

    let mut changed_fee = terms.clone();
    changed_fee.fee_limit.dom_max += 1;
    assert!(funding_budget(&changed_fee, Some(&validated)).is_err());

    let mut changed_policy = policy.clone();
    changed_policy.volatility_margin_bps += 100;
    let mut changed_terms = terms.clone();
    changed_terms.assurance_policy_hash = Some(changed_policy.policy_hash().unwrap());
    let other = changed_policy.validate_for(&changed_terms).unwrap();
    assert!(funding_budget(&terms, Some(&other)).is_err());
}

#[test]
fn ordinary_funding_budget_remains_distinct_from_xmr_authority() {
    let (policy, mut terms) = fixture();
    terms.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
    terms.fee_limit.dom_max = 1_000_000;
    let validated = policy.validate_for(&terms).unwrap();
    terms.counterparty_leg.mechanism = LockMechanism::ConditionLock;
    assert!(funding_budget(&terms, Some(&validated)).is_err());
    let expected =
        dom_adaptor::DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max)
            .unwrap();
    assert_eq!(
        funding_budget(&terms, None).unwrap(),
        (expected.shared_value(), expected.funding_fee_ceiling())
    );
}
#[test]
fn xmr_v23_compensation_binding_preserves_authority_and_rejects_foreign_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::model::StoredDomSessionBindingPartsV1;
    use crate::DomParticipantV1;
    use deployment_registry::{DomNetworkV1, DomRuntimeIdentityV1};
    use dom_scriptless_crypto::XmrRecoveryGraphBindingV11;
    use xmr_refund_policy::compensation::XmrRecoveryAvailabilityV23;
    let (mut policy, mut terms) = fixture();
    policy.cooperative_window_blocks = 13;
    policy.compensation_height = 124;
    policy.bounded_availability_v23 = Some(XmrRecoveryAvailabilityV23 {
        maximum_unavailability_blocks: 1,
        observation_delay_blocks: 1,
        cancel_inclusion_blocks: 1,
        refund_inclusion_blocks: 1,
    });
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let validated = policy.validate_for(&terms)?;
    let parts = || StoredDomSessionBindingPartsV1 {
        route_id: [31; 32],
        session_id: policy.session_id,
        participant: DomParticipantV1::new(policy.dom_funder, 0).expect("fixture participant"),
        chain_id: policy.dom_chain_id,
        genesis_hash: [32; 32],
        runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
        terms_digest: *validated.terms_hash(),
        profile_digest: [33; 32],
        deployment_digest: [34; 32],
        asset_binding_digest: [35; 32],
        registry_epoch: 1,
        min_confirmations: 3,
        max_reorg_depth: 6,
    };
    let parent = DomSessionBindingV1::from_parts_for_store(parts())?;
    let graph = XmrRecoveryGraphBindingV11 {
        chain_id: policy.dom_chain_id,
        session_id: policy.session_id,
        terms_hash: *validated.terms_hash(),
        funding_commitment: [2; 33],
        cancelled_commitment: [3; 33],
        refund_recipient_commitment: policy.refund_recipient_commitment,
        punish_recipient_commitment: policy.compensation_recipient_commitment,
        claim_adaptor_point: [6; 33],
        refund_adaptor_point: [7; 33],
        cancel_height: policy.cancel_height,
        punish_height: policy.compensation_height,
        reveal_safety_blocks: policy.reveal_safety_blocks,
        cancel_fee: policy.cancel_fee_noms,
        refund_fee: policy.refund_fee_noms,
        punish_fee: policy.compensation_fee_noms,
    };
    // Identity-only fixture: no Store, signed graph, funding or signing grant.
    let hash = [41; 32];
    let auxiliary = parent.for_xmr_compensation_v23(&graph, &validated, hash)?;
    let expected =
        dom_scriptless_crypto::xmr_bounded_compensation_session_v23(&graph, &validated, hash)?;
    assert_eq!(
        auxiliary,
        DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
            session_id: expected,
            ..parts()
        })?
    );
    assert_ne!(expected, parent.session_id());
    assert!(parent
        .for_xmr_compensation_v23(&graph, &validated, [0; 32])
        .is_err());
    assert!(auxiliary
        .for_xmr_compensation_v23(&graph, &validated, hash)
        .is_err());
    let foreign = DomSessionBindingV1::from_parts_for_store(StoredDomSessionBindingPartsV1 {
        participant: DomParticipantV1::new([99; 32], 0)?,
        ..parts()
    })?;
    assert!(foreign
        .for_xmr_compensation_v23(&graph, &validated, hash)
        .is_err());
    let mut wrong_graph = graph;
    wrong_graph.punish_fee += 1;
    assert!(parent
        .for_xmr_compensation_v23(&wrong_graph, &validated, hash)
        .is_err());
    policy.bounded_availability_v23 = None;
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let legacy = policy.validate_for(&terms)?;
    assert!(parent
        .for_xmr_compensation_v23(&graph, &legacy, hash)
        .is_err());
    Ok(())
}
