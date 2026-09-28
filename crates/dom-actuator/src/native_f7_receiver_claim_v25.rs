//! Receiver observation facade. Historical receipts never confer permission
//! to publish, and current finality always comes from the real DOM verifier.
use super::*;
use dom_scriptless_store::{F7ClaimReceiverStateV25, ObservedF7FinalClaimV15};

impl DomContractsActuatorV1<'_> {
    /// Return a historical receiver observation, or no receiver path for a
    /// sender/legacy session. An authenticated receiver still awaiting the
    /// public claim returns temporary authority unavailability, not sender
    /// permission and not a scope mismatch.
    pub fn f7_receiver_observation_v25(
        &self,
        chain: &TrustedChainIdV1,
    ) -> DomActuatorResult<Option<ObservedF7FinalClaimV15>> {
        self.require_trusted_chain_binding(chain)?;
        let Some(gate) = self
            .session_store
            .retained_f7_funding_gate_v19(*chain, self.binding.session_id())
            .map_err(final_claim_v14::map_f7_claim_store_error_v21)?
        else {
            return Ok(None);
        };
        match self
            .session_store
            .f7_claim_receiver_state_v25(&gate, *chain, self.binding.participant().participant_id())
            .map_err(final_claim_v14::map_f7_claim_store_error_v21)?
        {
            F7ClaimReceiverStateV25::Sender => Ok(None),
            F7ClaimReceiverStateV25::AwaitingObservation => {
                Err(DomActuatorError::ContractsAuthorityUnavailable)
            }
            F7ClaimReceiverStateV25::Observed(observed) => Ok(Some(observed)),
        }
    }

    /// Verify the exact receiver claim on the current chain, without creating
    /// a submission, admission, or control-plane finality checkpoint.
    pub fn verified_f7_receiver_claim_v25(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        chain: &TrustedChainIdV1,
        expected_transaction: [u8; 32],
    ) -> DomActuatorResult<VerifiedDomClaimFinalityV1> {
        self.require_dom_runtime_binding(runtime)?;
        let observed = self
            .f7_receiver_observation_v25(chain)?
            .ok_or(DomActuatorError::CapabilityMismatch)?;
        if observed.tx_hash() != expected_transaction {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let facts = self
            .session_store
            .f7_claim_receiver_facts_v15(
                *chain,
                self.binding.session_id(),
                self.binding.participant().participant_id(),
            )
            .map_err(final_claim_v14::map_f7_claim_store_error_v21)?
            .ok_or(DomActuatorError::ContractsAuthorityUnavailable)?;
        if facts.minimum_confirmations() != self.binding.min_confirmations()
            || facts.session_id() != observed.session_id()
            || facts.chain_id() != observed.chain_id()
            || facts.receiver_id() != observed.receiver_id()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence = EvidenceRefV1 {
            chain_id: kaystra_core::types::ChainId(observed.chain_id()),
            tx_id: expected_transaction,
            event_index: 0,
            block_height: 0,
            block_anchor: [0; 32],
        };
        // Bounded: the `_v15` sibling walks the chain from genesis with no
        // ceiling, and both production callers of this method run inside the
        // route step that holds the actuator lease. The budget is the same one
        // the runtime bounds a single external operation with, so a receiver
        // observation can never spend more than a quarter of the lease. Running
        // out yields `TemporarilyUnavailable`, which the callers already retry,
        // and the retained scan prefix means the next round resumes rather than
        // restarting.
        let deadline = adapter_dom_real::route_step_deadline_v27::clamp_v27(
            std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(30))
                .ok_or(DomActuatorError::RpcAuthorityUnavailable)?,
        );
        runtime
            .verified_f7_claim_finality_until_v26(
                &facts,
                &evidence,
                expected_transaction,
                self.binding.max_reorg_depth(),
                deadline,
            )
            .map_err(map_finality_error)
    }
}
