//! Consume an already public, canonical D -> refund. This is not the plain
//! refund broadcaster, does not reveal U, and never submits another transaction.

use super::*;
use adapter_dom_real::{VerifiedDomRefundSecretV11, VerifiedDomXmrRecoveryFinalityV11};
use dom_scriptless_store::{PreparedF7FundingGateV12, PreparedF7FundingSubmissionV12};

impl DomContractsActuatorV1<'_> {
    /// Read a previously authenticated native locator without pretending that
    /// its old chain observation is fresh. Only observation/reorg callers use
    /// this path; it cannot authorize a new broadcast.
    pub fn retained_native_xmr_refund_settlement_child_binding_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        now: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        let scope = self
            .session_store
            .expected_xmr_recovery_scope_v12(gate)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if scope.binding.chain_id != self.binding.chain_id()
            || scope.binding.session_id != self.binding.session_id()
            || scope.binding.terms_hash != self.binding.terms_digest()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let retained = control.settlement_child_binding(lease, custody_digest, now)?;
        self.require_settlement_child_binding(
            control,
            lease,
            custody_digest,
            DomActionV1::BroadcastRefund,
            retained.transaction_id(),
            now,
        )
    }

    /// Public audit bytes only; they are not finality or mutation authority.
    pub fn native_xmr_refund_checkpoint_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        now: u64,
    ) -> DomActuatorResult<Vec<u8>> {
        let binding = self.retained_native_xmr_refund_settlement_child_binding_v23(
            control,
            lease,
            custody_digest,
            gate,
            now,
        )?;
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now,
        )?;
        if retained.tx_hash != binding.transaction_id()
            || retained.minimum_confirmations != self.binding.min_confirmations()
            || retained.max_reorg_depth != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(retained.checkpoint_bytes)
    }

    /// Persist only a fresh native fork proof bound to this original journal.
    pub fn record_native_xmr_refund_reorg_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        proof: &adapter_dom_real::VerifiedDomXmrRefundReorgV23,
        now: u64,
    ) -> DomActuatorResult<DomFinalityRevalidationV1> {
        proof.require_recent_v23().map_err(map_reorg_error)?;
        let binding = self.retained_native_xmr_refund_settlement_child_binding_v23(
            control,
            lease,
            custody_digest,
            gate,
            now,
        )?;
        let scope = self
            .session_store
            .expected_xmr_recovery_scope_v12(gate)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let funding = self
            .session_store
            .retained_f7_funding_submission_v20(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
            .ok_or(DomActuatorError::ContractsAuthorityUnavailable)?;
        let old = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now,
        )?;
        if proof.chain_id() != self.binding.chain_id()
            || proof.session_id() != self.binding.session_id()
            || proof.terms_hash() != self.binding.terms_digest()
            || proof.graph_digest() != scope.graph_digest
            || proof.funding_tx_hash() != funding.tx_hash()
            || proof.transaction_hash() != binding.transaction_id()
            || proof.transaction_hash() != old.tx_hash
            || proof.prior_evidence_digest() != old.evidence_digest
            || proof.prior_block_height() != old.block_height
            || proof.prior_block_hash() != old.block_hash
            || proof.minimum_confirmations() != self.binding.min_confirmations()
            || proof.max_reorg_depth() != self.binding.max_reorg_depth()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        proof.require_recent_v23().map_err(map_reorg_error)?;
        control.record_terminal_reorg(
            lease,
            self.binding,
            DomTerminalReorgRecordV1 {
                kind: DomTerminalKindV1::Refund,
                tx_hash: proof.transaction_hash(),
                prior_evidence_digest: proof.prior_evidence_digest(),
                current_tip_height: proof.current_tip_height(),
                current_tip_hash: proof.current_tip_hash(),
                common_ancestor_height: proof.common_ancestor_height(),
                removed_depth: proof.removed_depth(),
                minimum_confirmations: proof.minimum_confirmations(),
                max_reorg_depth: proof.max_reorg_depth(),
                evidence_digest: proof.evidence_digest(),
            },
            now,
        )?;
        Ok(DomFinalityRevalidationV1::Invalidated {
            transaction_id: old.tx_hash,
            prior_evidence_digest: old.evidence_digest,
            prior_block_height: old.block_height,
            prior_block_hash: old.block_hash,
            reorg_evidence_digest: proof.evidence_digest(),
        })
    }

    /// Recover an invalidation committed before a coordinator crash. This is
    /// only a replay of the exact fenced record, never a new fork assertion.
    pub fn recover_native_xmr_refund_invalidation_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        now: u64,
    ) -> DomActuatorResult<Option<DomFinalityRevalidationV1>> {
        let binding = self.retained_native_xmr_refund_settlement_child_binding_v23(
            control,
            lease,
            custody_digest,
            gate,
            now,
        )?;
        let old = control.retained_terminal_invalidation(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now,
        )?;
        recover_terminal_invalidation(old, DomTerminalKindV1::Refund, binding.transaction_id())
    }

    /// Retain the exact native refund already observed final by the recovery
    /// authority, then install its coordinator locator. No private U is read.
    pub fn bind_native_xmr_refund_settlement_child_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomSettlementChildBindingRequestV1,
        gate: &PreparedF7FundingGateV12,
        observed: &VerifiedDomRefundSecretV11,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        self.require_settlement_child_request(request, DomActionV1::BroadcastRefund)?;
        let funding = self.require_native_xmr_refund_v23(gate, observed)?;
        control.retain_native_f7_refund_v20(
            lease,
            request.scope(),
            &funding,
            observed.finality().transaction_hash(),
            now_unix_ms,
        )?;
        observed.require_recent_v23().map_err(map_finality_error)?;
        control.persist_authenticated_settlement_child_binding(
            lease,
            request,
            observed.finality().transaction_hash(),
            now_unix_ms,
        )
    }

    /// Reauthenticate a retained native refund locator using a new canonical
    /// graph observation and the same owner-only Contracts gate.
    pub fn native_xmr_refund_settlement_child_binding_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        observed: &VerifiedDomRefundSecretV11,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomSettlementChildBindingV1> {
        self.require_native_xmr_refund_v23(gate, observed)?;
        let retained = self.require_settlement_child_binding(
            control,
            lease,
            custody_digest,
            DomActionV1::BroadcastRefund,
            observed.finality().transaction_hash(),
            now_unix_ms,
        )?;
        observed.require_recent_v23().map_err(map_finality_error)?;
        Ok(retained)
    }

    /// Persist native U-refund finality only after its exact locator exists.
    /// A newer tip retains the original durable evidence identity; fresh
    /// canonical observation, not that checkpoint, is the authority for replay.
    pub fn observe_native_xmr_refund_settlement_finality_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        observed: &VerifiedDomRefundSecretV11,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        self.native_xmr_refund_settlement_child_binding_v23(
            control,
            lease,
            custody_digest,
            gate,
            observed,
            now_unix_ms,
        )?;
        let finality = observed.finality();
        match control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now_unix_ms,
        ) {
            Ok(retained) => {
                require_same_native_inclusion_v23(&retained, finality)?;
                observed.require_recent_v23().map_err(map_finality_error)?;
                return Ok(terminal_finality_observation(&retained));
            }
            // The locator's completed refund operation has been authenticated
            // above. The writer still checks the exact BroadcastRefund stage;
            // this is not permission to overwrite corrupt/missing finality.
            Err(DomActuatorError::InvalidStage) => {}
            Err(error) => return Err(error),
        }
        observed.require_recent_v23().map_err(map_finality_error)?;
        control.record_terminal_finality(
            lease,
            self.binding,
            DomTerminalFinalityRecordV1 {
                kind: DomTerminalKindV1::Refund,
                tx_hash: finality.transaction_hash(),
                block_height: finality.block_height(),
                block_hash: finality.block_hash(),
                tip_height: finality.observed_tip_height(),
                tip_hash: finality.observed_tip_hash(),
                confirmation_depth: finality.confirmation_depth(),
                minimum_confirmations: finality.minimum_confirmations(),
                max_reorg_depth: finality.max_reorg_depth(),
                evidence_digest: finality.evidence_digest(),
                checkpoint_bytes: finality.checkpoint_bytes(),
            },
            now_unix_ms,
        )?;
        Ok(finality_observation(
            finality.transaction_hash(),
            finality.block_height(),
            finality.block_hash(),
            finality.evidence_digest(),
        ))
    }

    /// Reopening requires a fresh full graph scan. An inclusion change cannot
    /// be silently accepted or routed into the incompatible plain checkpoint
    /// decoder: it requires a separately authenticated reorganization proof.
    pub fn revalidate_native_xmr_refund_settlement_finality_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        custody_digest: [u8; 32],
        gate: &PreparedF7FundingGateV12,
        observed: &VerifiedDomRefundSecretV11,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomFinalityRevalidationV1> {
        self.native_xmr_refund_settlement_child_binding_v23(
            control,
            lease,
            custody_digest,
            gate,
            observed,
            now_unix_ms,
        )?;
        let retained = control.retained_terminal_checkpoint(
            lease,
            self.binding,
            DomTerminalKindV1::Refund,
            now_unix_ms,
        )?;
        require_same_native_inclusion_v23(&retained, observed.finality())?;
        observed.require_recent_v23().map_err(map_finality_error)?;
        Ok(DomFinalityRevalidationV1::StillFinal(
            terminal_finality_observation(&retained),
        ))
    }

    fn require_native_xmr_refund_v23(
        &self,
        gate: &PreparedF7FundingGateV12,
        observed: &VerifiedDomRefundSecretV11,
    ) -> DomActuatorResult<PreparedF7FundingSubmissionV12> {
        observed.require_recent_v23().map_err(map_finality_error)?;
        let scope = self
            .session_store
            .expected_xmr_recovery_scope_v12(gate)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let funding = self
            .session_store
            .retained_f7_funding_submission_v20(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
            .ok_or(DomActuatorError::ContractsAuthorityUnavailable)?;
        let finality = observed.finality();
        if scope.binding.session_id != self.binding.session_id()
            || scope.binding.chain_id != self.binding.chain_id()
            || scope.binding.terms_hash != self.binding.terms_digest()
            || finality.session_id() != scope.binding.session_id
            || finality.chain_id() != scope.binding.chain_id
            || finality.terms_hash() != scope.binding.terms_hash
            || finality.graph_digest() != scope.graph_digest
            || observed.refund_point() != scope.binding.refund_adaptor_point
            || observed.template_hash() == [0; 32]
            || funding.session_id() != finality.session_id()
            || funding.chain_id() != finality.chain_id()
            || funding.terms_hash() != finality.terms_hash()
            || funding.tx_hash() != finality.funding_tx_hash()
            || finality.minimum_confirmations() != self.binding.min_confirmations()
            || finality.max_reorg_depth() != self.binding.max_reorg_depth()
            || finality.confirmation_depth() < self.binding.min_confirmations()
            || finality.cancel_tx_hash().is_none_or(|cancel| {
                cancel == [0; 32]
                    || cancel == funding.tx_hash()
                    || cancel == finality.transaction_hash()
            })
            || finality.transaction_hash() == funding.tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        observed.require_recent_v23().map_err(map_finality_error)?;
        Ok(funding)
    }
}

fn require_same_native_inclusion_v23(
    retained: &crate::store::RetainedDomTerminalCheckpointV1,
    observed: &VerifiedDomXmrRecoveryFinalityV11,
) -> DomActuatorResult<()> {
    require_same_native_inclusion_facts_v23(
        retained,
        NativeRefundInclusionV23 {
            tx_hash: observed.transaction_hash(),
            block_height: observed.block_height(),
            block_hash: observed.block_hash(),
            minimum_confirmations: observed.minimum_confirmations(),
            max_reorg_depth: observed.max_reorg_depth(),
        },
    )
}

// Private comparison material only. There is deliberately no consumer API
// taking these facts instead of the scanner's unforgeable, fresh U token.
struct NativeRefundInclusionV23 {
    tx_hash: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    minimum_confirmations: u32,
    max_reorg_depth: u32,
}

fn require_same_native_inclusion_facts_v23(
    retained: &crate::store::RetainedDomTerminalCheckpointV1,
    observed: NativeRefundInclusionV23,
) -> DomActuatorResult<()> {
    if retained.kind != DomTerminalKindV1::Refund
        || retained.tx_hash != observed.tx_hash
        || retained.minimum_confirmations != observed.minimum_confirmations
        || retained.max_reorg_depth != observed.max_reorg_depth
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    if retained.block_height != observed.block_height || retained.block_hash != observed.block_hash
    {
        return Err(DomActuatorError::ReorgEvidenceRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained() -> crate::store::RetainedDomTerminalCheckpointV1 {
        crate::store::RetainedDomTerminalCheckpointV1 {
            kind: DomTerminalKindV1::Refund,
            tx_hash: [1; 32],
            block_height: 150,
            block_hash: [2; 32],
            minimum_confirmations: 6,
            max_reorg_depth: 12,
            evidence_digest: [3; 32],
            checkpoint_bytes: vec![4; 300],
        }
    }

    fn observed() -> NativeRefundInclusionV23 {
        NativeRefundInclusionV23 {
            tx_hash: [1; 32],
            block_height: 150,
            block_hash: [2; 32],
            minimum_confirmations: 6,
            max_reorg_depth: 12,
        }
    }

    #[test]
    fn native_refund_reobservation_preserves_original_receipt_checkpoint_v23() {
        let old = retained();
        assert!(require_same_native_inclusion_facts_v23(&old, observed()).is_ok());
        // No current tip/evidence is copied into the old journal identity.
        assert_eq!(old.evidence_digest, [3; 32]);
        assert_eq!(old.checkpoint_bytes, vec![4; 300]);
    }

    #[test]
    fn native_refund_reobservation_refuses_transaction_and_face_substitution_v23() {
        let mut other = observed();
        other.tx_hash = [9; 32];
        assert!(matches!(
            require_same_native_inclusion_facts_v23(&retained(), other),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        let mut other = retained();
        other.kind = DomTerminalKindV1::Claim;
        assert!(matches!(
            require_same_native_inclusion_facts_v23(&other, observed()),
            Err(DomActuatorError::CapabilityMismatch)
        ));
    }

    #[test]
    fn native_refund_reobservation_never_weakens_negotiated_policy_v23() {
        for change in [true, false] {
            let mut other = observed();
            if change {
                other.minimum_confirmations = 1;
            } else {
                other.max_reorg_depth = 13;
            }
            assert!(matches!(
                require_same_native_inclusion_facts_v23(&retained(), other),
                Err(DomActuatorError::CapabilityMismatch)
            ));
        }
    }

    #[test]
    fn native_refund_changed_inclusion_needs_real_reorg_authority_v23() {
        for change in [true, false] {
            let mut other = observed();
            if change {
                other.block_height += 1;
            } else {
                other.block_hash = [9; 32];
            }
            assert!(matches!(
                require_same_native_inclusion_facts_v23(&retained(), other),
                Err(DomActuatorError::ReorgEvidenceRequired)
            ));
        }
    }
}
