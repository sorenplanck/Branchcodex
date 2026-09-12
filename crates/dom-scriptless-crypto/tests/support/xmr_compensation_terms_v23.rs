// Test-only economic/availability fixture. It proves neither authenticated
// participant consent nor payout ownership; native Store/wallet tests own that.
use super::*;
use kaystra_core::{terms::SettlementTermsV1, types::*};
use xmr_compensation_policy::{
    ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyV11, XmrRecoveryAvailabilityV23,
};

pub(super) fn policy_for(
    fixture: &mut Fixture,
    bounded: bool,
) -> TestResult<ValidatedXmrCompensationPolicyV11> {
    let policy = XmrCompensationPolicyV11 {
        settlement_id: [1; 32],
        session_id: SESSION,
        dom_chain_id: CHAIN,
        xmr_chain_id: [2; 32],
        dom_funder: [3; 32],
        xmr_funder: [4; 32],
        claim_principal_commitment: *fixture.claim.outputs[0].commitment.as_bytes(),
        claim_change_commitment: *fixture.funding.inputs[0].commitment.as_bytes(),
        refund_recipient_commitment: fixture.binding.refund_recipient_commitment,
        compensation_recipient_commitment: fixture.binding.punish_recipient_commitment,
        quote_dom_numerator: 1,
        quote_xmr_denominator: 1,
        xmr_principal_piconero: 9_000,
        dom_principal_noms: 9_000,
        volatility_margin_bps: 833, // ceil(9000 * .0833) = 750
        collateral_confirmations: 2,
        cancel_height: fixture.binding.cancel_height,
        compensation_height: fixture.binding.punish_height,
        cooperative_window_blocks: 6,
        reveal_safety_blocks: fixture.binding.reveal_safety_blocks,
        claim_fee_noms: 100,
        cancel_fee_noms: fixture.binding.cancel_fee,
        refund_fee_noms: fixture.binding.refund_fee,
        compensation_fee_noms: fixture.binding.punish_fee,
        bounded_availability_v23: bounded.then_some(XmrRecoveryAvailabilityV23 {
            maximum_unavailability_blocks: 1,
            observation_delay_blocks: 1,
            cancel_inclusion_blocks: 1,
            refund_inclusion_blocks: 1,
        }),
    };
    let finality = FinalityPolicyV1 {
        min_confirmations: 1,
        max_reorg_depth: 1,
    };
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId(policy.settlement_id),
        session_id: SessionId(SESSION),
        intent_hash: IntentHash([5; 32]),
        solver_id: SolverId([6; 32]),
        roster: [
            ParticipantId(policy.dom_funder),
            ParticipantId(policy.xmr_funder),
        ],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(CHAIN),
            asset_id: AssetId([7; 32]),
            amount: 9_000,
            beneficiary: ParticipantId(policy.xmr_funder),
            refund_to: ParticipantId(policy.dom_funder),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight {
                value: policy.cancel_height,
            },
            finality,
            adapter_profile_hash: [8; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(policy.xmr_chain_id),
            asset_id: AssetId([9; 32]),
            amount: 9_000,
            beneficiary: ParticipantId(policy.dom_funder),
            refund_to: ParticipantId(policy.xmr_funder),
            mechanism: LockMechanism::CrossCurveSharedSpend,
            deadline: TimelockSpec::TimestampSeconds {
                value: 1_900_000_000,
            },
            finality,
            adapter_profile_hash: [10; 32],
        },
        adaptor_point_sec1: fixture.binding.claim_adaptor_point,
        fee_limit: FeeLimitV1 {
            dom_max: 150,
            counterparty_max: 1,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: Some(policy.policy_hash().map_err(|e| e.to_string())?),
        policy_version: 1,
        metadata: vec![],
    };
    let validated = policy.validate_for(&terms).map_err(|e| e.to_string())?;
    fixture.binding.terms_hash = *validated.terms_hash();
    Ok(validated)
}
