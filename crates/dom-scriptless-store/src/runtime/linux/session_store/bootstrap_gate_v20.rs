//! Bootstrap -> native F7 gate, using authenticated public history only.
//! No template/key import, no reconstructed secret, no synthetic readiness.
use super::*;
use dom_final_claim_binding::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimRoleBindingInputV1,
    FinalClaimRoleBindingV1, FinalClaimSecretSourceScopeV1,
};
use dom_scriptless_crypto::{
    freeze_shared_output_statement_v1, SharedOutputContributionV1, SharedOutputInputsV1,
};

impl ContractsSessionStoreV1 {
    /// Canonical hash of the native DOM claim template this Store reconstructs
    /// for `session` from its authenticated bootstrap history, exactly as
    /// [`Self::prepare_bootstrapped_plain_f7_gate_v20`] does. A public value
    /// only: it lets a Solana enrollment commit its `LocalOrigin` source
    /// scope, which that gate then rebinds against this same reconstruction.
    pub fn bootstrapped_claim_template_hash_v25(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        let templates = {
            let _guard = self.operation_lock()?;
            if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
                return Err(SessionStoreError::InvalidTransition);
            }
            let record = self.read_bootstrap_wallet_keys_v18(session)?;
            if !matches!(
                record.terms.counterparty_leg.mechanism,
                kaystra_core::types::LockMechanism::ConditionLock
                    | kaystra_core::types::LockMechanism::CrossCurveConditionLock
            ) {
                return Err(SessionStoreError::InvalidTransition);
            }
            self.reconstruct_bootstrap_wallet_templates_v20(&record, chain.as_bytes())?
        };
        canonical_template_v1(templates.claim.transaction_template())
            .map(|(_, hash)| hash)
            .map_err(|_| SessionStoreError::Canonical)
    }

    /// Construct the EVM/Solana prefunding gate from the actual wallet/BP,
    /// bilateral DSC1 template and refund histories in this Store. Reopens
    /// require the same role, source, terms and exact native templates.
    /// BTC retains M.8; XMR requires its separate conditional recovery graph.
    pub fn prepare_bootstrapped_plain_f7_gate_v20(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        plan: &ComposedFinalClaimRolePlanV1,
        source: &FinalClaimSecretSourceScopeV1,
        leg: ComposedSettlementLegV1,
        now_unix_seconds: u64,
    ) -> Result<PreparedF7FundingGateV12, SessionStoreError> {
        let (terms, templates, collateral, refund, context) = {
            let _guard = self.operation_lock()?;
            if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified
                || now_unix_seconds == 0
                || plan.entry(leg).session_id().0 != session
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let record = self.read_bootstrap_wallet_keys_v18(session)?;
            if !matches!(
                record.terms.counterparty_leg.mechanism,
                kaystra_core::types::LockMechanism::ConditionLock
                    | kaystra_core::types::LockMechanism::CrossCurveConditionLock
            ) {
                return Err(SessionStoreError::InvalidTransition);
            }
            let templates =
                self.reconstruct_bootstrap_wallet_templates_v20(&record, chain.as_bytes())?;
            let current = self.load_session_locked(session)?;
            let bp = self.load_bp_transport_authority(session)?;
            let early = self.load_early_transport_authority(session)?;
            let records =
                self.authenticated_derived_transport_records(session, current.revision())?;
            let reveals = records
                .iter()
                .filter(|edge| edge.message_type == 0x04)
                .collect::<Vec<_>>();
            if reveals.len() != 2 {
                return Err(SessionStoreError::Quarantined);
            }
            let mut contributions = Vec::with_capacity(2);
            for participant_index in 0..2 {
                let id = bp.statement.participant_ids()[participant_index];
                let mut matching = reveals.iter().filter(|edge| edge.sender_id == id);
                let edge = matching.next().ok_or(SessionStoreError::Quarantined)?;
                if matching.next().is_some() {
                    return Err(SessionStoreError::Quarantined);
                }
                let reveal = EarlyShareRevealV1::from_bytes(
                    &edge.payload,
                    &chain,
                    bp.statement.participant_ids(),
                    &early.context_commitment,
                )
                .map_err(|_| SessionStoreError::Quarantined)?;
                if usize::from(reveal.participant_index()) != participant_index
                    || reveal.statement().participant_id() != id
                    || reveal.statement().session_id() != session
                {
                    return Err(SessionStoreError::Quarantined);
                }
                contributions.push(SharedOutputContributionV1 {
                    participant_index: participant_index as u16,
                    participant_id: id,
                    role: reveal.statement().role(),
                    commitment_share: reveal.statement().share_point(),
                    proof: reveal.proof().clone(),
                });
            }
            let collateral = freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
                chain_id: chain,
                session_id: session,
                contributions: &contributions,
                value_noms: bp.statement.value_noms(),
                terms_hash: current.terms_hash(),
                recovery_binding_hash: early.recovery_binding_hash,
            })
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
            if collateral.statement().statement_hash() != bp.statement.statement_hash() {
                return Err(SessionStoreError::Quarantined);
            }
            let refund = self.load_operational_final_refund_v2(session)?;
            self.authenticate_operational_final_refund_v2_at_terminal(
                session,
                refund.terminal_revision,
            )?;
            let context = DomTransactionValidationContextV1::new(
                current.chain().tip_height,
                *chain.as_bytes(),
                now_unix_seconds,
            );
            (
                record.terms,
                templates,
                collateral,
                refund.exact_transaction_bytes,
                context,
            )
        };
        // Public calls take their own operation lock. No nested lock and no
        // raw Store reopening is needed for the purpose-separated claim key.
        let roster =
            self.bootstrap_wallet_signing_roster_v18(chain, session, PurposeV1::ClaimAdaptor)?;
        let hash = |transaction: &Transaction| {
            canonical_template_v1(transaction)
                .map(|(_, hash)| hash)
                .map_err(|_| SessionStoreError::Canonical)
        };
        let role = FinalClaimRoleBindingV1::bind(
            &chain,
            FinalClaimRoleBindingInputV1 {
                terms: &terms,
                roster: &roster,
                role_plan: plan,
                source_scope: source,
                route_leg: leg,
                funding_template_hash: hash(templates.funding.transaction_template())?,
                claim_template_hash: hash(templates.claim.transaction_template())?,
                refund_template_hash: hash(templates.refund.transaction_template())?,
                shared_output_commitment: *collateral.aggregate_commitment(),
                claim_kernel_index: 0,
            },
        )
        .map_err(|_| SessionStoreError::InvalidTransition)?;
        self.prepare_or_resume_bootstrap_f7_gate_v20(
            chain,
            F7FundingGatePreparationV12 {
                role: &role,
                collateral: &collateral,
                funding_template: templates.funding.transaction_template(),
                claim_template: templates.claim.transaction_template(),
                recovery: F7RecoveryPreparationV12::PlainRefund {
                    refund_bytes: &refund,
                },
                context,
            },
        )
    }
}
