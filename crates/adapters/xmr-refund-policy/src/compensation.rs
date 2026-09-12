//! Compatibility path for canonical XMR compensation terms.
//! Shared with the native signing layer without a dependency on signing here.
pub use xmr_compensation_policy::*;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kaystra_core::terms::SettlementTermsV1;
    use kaystra_core::types::*;

    pub(crate) fn fixture() -> (XmrCompensationPolicyV11, SettlementTermsV1) {
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
}
