//! Receiver claim observation installed under the existing Contracts owner.
//! Only native public verification facts and the child-owned DOM scanner enter;
//! no unrelated chain, signer, secret database, or second RPC client is opened.
use super::ProductionContractsV1;
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use crate::relay_worker::ContractsRelayIngressErrorV1;
use adapter_dom_real::RealDomError;
use dom_actuator::{DomActuatorError, DomSessionBindingV1};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_store::SessionStoreError;
use route_transport::F6TransportPortV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionClaimReceiverErrorV15 {
    #[error("universal claim receiver binding differs from this Contracts owner")]
    Binding(#[from] DomActuatorError),
    #[error("universal claim receiver durable ancestry is invalid")]
    Store(#[from] SessionStoreError),
    #[error("universal claim receiver chain observation failed")]
    Observation(#[from] RealDomError),
    #[error("universal claim receiver Relay authority was rejected")]
    Ingress(#[from] ContractsRelayIngressErrorV1),
}
impl ProductionClaimReceiverErrorV15 {
    pub(crate) fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Store(SessionStoreError::StoreBusy | SessionStoreError::Filesystem)
                | Self::Observation(
                    RealDomError::LockPoisoned
                        | RealDomError::Chain(
                            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
                        )
                )
                | Self::Ingress(ContractsRelayIngressErrorV1::OwnerBusy)
        )
    }
}
#[must_use]
pub(crate) enum ProductionClaimReceiverStepV15 {
    NotReady,
    ClaimAbsent,
    AwaitingFinality,
    IngressInstalled,
}
impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    fn step_post_m8_receiver_v22(
        &mut self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: &ProductionDomF7ScannerAuthorityV1,
    ) -> Result<ProductionClaimReceiverStepV15, ProductionClaimReceiverErrorV15> {
        use ProductionClaimReceiverStepV15 as Step;
        let Some(pre) = self.store.post_m8_receiver_pre_signature_v22(
            chain,
            self.session_id,
            self.local_participant,
        )?
        else {
            return Ok(Step::NotReady);
        };
        let head = self.store.load_session(self.session_id)?;
        if matches!(
            head.phase(),
            dom_scriptless_store::SessionPhaseV1::ClaimBroadcast
                | dom_scriptless_store::SessionPhaseV1::Settled
        ) {
            return Ok(Step::IngressInstalled);
        }
        if matches!(
            head.phase(),
            dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                | dom_scriptless_store::SessionPhaseV1::Refunded
                | dom_scriptless_store::SessionPhaseV1::Aborted
                | dom_scriptless_store::SessionPhaseV1::FailedClosed
        ) {
            return Ok(Step::NotReady);
        }
        match self
            .store
            .resume_observed_final_claim_exposure_v2(chain, self.session_id)
        {
            Ok(_) => {}
            Err(SessionStoreError::SessionNotFound) => {
                let contract = self
                    .store
                    .real_dom_contract_facts_v2(chain, self.session_id)?;
                let round = self
                    .store
                    .retained_claim_round_facts_v2(chain, self.session_id)?;
                let verifier = adapter_dom_real::RealDomClaimVerifierV1::from_retained_facts_v2(
                    &round, &contract, &chain, &pre,
                )?;
                let observation = match scanner
                    .find_post_m8_receiver_claim_v22(&verifier, binding.min_confirmations())
                {
                    Ok(Some(observation)) => observation,
                    Ok(None) => return Ok(Step::ClaimAbsent),
                    Err(RealDomError::InsufficientConfirmations) => {
                        return Ok(Step::AwaitingFinality)
                    }
                    Err(error) => return Err(error.into()),
                };
                self.store
                    .revalidate_final_claim_chain_observation_v2(head.revision(), observation)?;
            }
            Err(error) => return Err(error.into()),
        }
        let ingress = self
            .store
            .prepare_operational_final_claim_ingress_authority_v2(chain, self.session_id)?;
        self.relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .handoff_m8_final_claim_v22(ingress)?;
        Ok(Step::IngressInstalled)
    }

    /// One bounded receiver operation. Native observation survives restart;
    /// reinstalling the ingress does not need a new claim or secret extraction.
    pub(crate) fn step_f7_claim_receiver_v15(
        &mut self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: &ProductionDomF7ScannerAuthorityV1,
    ) -> Result<ProductionClaimReceiverStepV15, ProductionClaimReceiverErrorV15> {
        self.validate_dom_binding(binding)?;
        let Some(facts) = self.store.f7_claim_receiver_facts_v15(
            chain,
            self.session_id,
            self.local_participant,
        )?
        else {
            return self.step_post_m8_receiver_v22(binding, chain, scanner);
        };
        if self
            .store
            .resume_f7_claim_observation_v15(chain, self.session_id)?
            .is_none()
        {
            let revision = self.store.load_session(self.session_id)?.revision();
            let observation = match scanner.find_f7_receiver_claim_v15(&facts) {
                Ok(Some(observation)) => observation,
                Ok(None) => return Ok(ProductionClaimReceiverStepV15::ClaimAbsent),
                Err(RealDomError::InsufficientConfirmations) => {
                    return Ok(ProductionClaimReceiverStepV15::AwaitingFinality)
                }
                Err(error) => return Err(error.into()),
            };
            // The move-only observation crosses CAS and both durable writes
            // before the 0x12 ingress can be minted. No scalar is read here.
            self.store
                .persist_f7_claim_observation_v15(chain, revision, observation)?;
        }
        let ingress = self
            .store
            .prepare_f7_final_claim_ingress_v15(chain, self.session_id)?;
        self.relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .handoff_f7_final_claim_v19(ingress)?;
        Ok(ProductionClaimReceiverStepV15::IngressInstalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v15_receiver_does_not_retry_substituted_evidence_or_corrupt_store() {
        for error in [
            ProductionClaimReceiverErrorV15::Observation(RealDomError::InvalidEvidence),
            ProductionClaimReceiverErrorV15::Store(SessionStoreError::Quarantined),
            ProductionClaimReceiverErrorV15::Store(SessionStoreError::InvalidTransition),
        ] {
            assert!(!error.retryable());
        }
        assert!(
            ProductionClaimReceiverErrorV15::Observation(RealDomError::Chain(
                dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
            ))
            .retryable()
        );
        assert!(ProductionClaimReceiverErrorV15::Store(SessionStoreError::StoreBusy).retryable());
    }
}
