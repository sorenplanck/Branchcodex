//! Deadline-preserving DOM funding dispatch. Durable intent remains intact on
//! timeout; this module never turns an uncertain POST into a not-sent proof.
use super::*;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn require_live(deadline: Instant) -> DomActuatorResult<()> {
    if Instant::now() >= deadline {
        return Err(DomActuatorError::RpcAuthorityUnavailable);
    }
    Ok(())
}

impl DomContractsActuatorV1<'_> {
    /// Reconcile an uncertain funding send using only complete canonical chain
    /// evidence. This method cannot submit or re-sign the retained transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_funding_finality_until_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        trusted_chain_id: &TrustedChainIdV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        require_live(deadline)?;
        self.require_dom_runtime_binding(runtime)?;
        self.require_trusted_chain_binding(trusted_chain_id)?;
        let contract = self
            .session_store
            .real_dom_funding_facts_v20(*trusted_chain_id, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        if contract.chain_id() != &self.binding.chain_id()
            || evidence.tx_id != *contract.funding_tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        require_live(deadline)?;
        let finality = runtime
            .verified_funding_finality_until_v23(
                evidence,
                *contract.funding_tx_hash(),
                *contract.shared_output_commitment(),
                self.binding.min_confirmations(),
                self.binding.max_reorg_depth(),
                deadline,
            )
            .map_err(map_finality_error)?;
        let fresh_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok())
            .filter(|now| *now >= now_unix_ms)
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        require_live(deadline)?;
        let observed = self.persist_funding_finality(control, lease, finality, fresh_now)?;
        require_live(deadline)?;
        Ok(observed)
    }

    /// Revalidate and send native funding within the original route/lease
    /// deadline, including every context scan and the actual HTTP request.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_f7_funding_child_until_v23(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: &DomSettlementChildBindingV1,
        runtime: &RealDomRpcRuntimeV1,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> DomActuatorResult<Option<SubmissionReceiptV1>> {
        require_live(deadline)?;
        self.require_dom_runtime_binding(runtime)?;
        let native = self
            .session_store
            .retained_f7_funding_submission_v20(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        require_live(deadline)?;
        let Some(native) = native else {
            return Ok(None);
        };
        let request = binding.request();
        self.require_settlement_child_request(request, DomActionV1::BroadcastFunding)?;
        if binding.transaction_id() != native.tx_hash() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let context = runtime
            .current_transaction_validation_context_until_v23(deadline)
            .map_err(f7_runtime_error_v20)?;
        require_live(deadline)?;
        self.session_store
            .require_f7_funding_transmission_v20(self.binding.session_id(), context)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let fresh_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok())
            .filter(|now| *now >= now_unix_ms)
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        require_live(deadline)?;
        control.retain_native_f7_funding_v20(lease, request.scope(), &native, fresh_now)?;
        let retained = control.persist_authenticated_settlement_child_binding(
            lease,
            request,
            native.tx_hash(),
            fresh_now,
        )?;
        if retained.request() != request || retained.transaction_id() != binding.transaction_id() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        require_live(deadline)?;
        let receipt = runtime
            .submit_persisted_f7_funding_until_v23(&native, deadline)
            .map_err(f7_runtime_error_v20)?;
        if receipt.tx_hash() != native.tx_hash() || !receipt.is_economically_admitted() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        // No post-send `Unavailable` fabricated here: propagate an exact ACK
        // so the caller can durably retain the actual result, even after I/O.
        Ok(Some(receipt))
    }

    /// Submit legacy retained funding using the same bounded node boundary.
    /// Native callers must first select the native F7 path explicitly.
    pub fn dispatch_funding_broadcast_until_v23(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        broadcast: FundingBroadcastV1,
        deadline: Instant,
    ) -> DomActuatorResult<SubmissionReceiptV1> {
        require_live(deadline)?;
        self.require_dom_runtime_binding(runtime)?;
        let tx_hash = broadcast.funding_tx_hash();
        let retained_tx_hash = self
            .session_store
            .resend_funding_broadcast(self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
            .funding_tx_hash();
        require_live(deadline)?;
        let receipt =
            submit_after_funding_preflight(broadcast, tx_hash, retained_tx_hash, |exact| {
                runtime
                    .submit_persisted_funding_until_v23(exact, deadline)
                    .map_err(f7_runtime_error_v20)
            })?;
        if receipt.tx_hash() != tx_hash || !receipt.is_economically_admitted() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_dispatch_deadline_is_closed_at_its_boundary_v23() {
        assert!(matches!(
            require_live(Instant::now()),
            Err(DomActuatorError::RpcAuthorityUnavailable)
        ));
    }
}
