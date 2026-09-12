//! Reobserve the exact downstream DOM Claim before any upstream private round.
//! The scanner produces the opaque observation; no caller scalar or hash grants it.
use super::*;
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn observe_downstream_claim_gate_v23<G: F6TransportPortV1>(
        &self,
        chain: TrustedChainIdV1,
        downstream: &ProductionContractsV1<G>,
        scanner: &ProductionDomF7ScannerAuthorityV1,
    ) -> Result<bool, ProductionF7RuntimeErrorV12> {
        use ProductionF7RuntimeErrorV12 as Error;
        if !self
            .store
            .native_downstream_claim_gate_required_v23(chain, self.session_id)?
        {
            return Ok(true);
        }
        let head = self.store.load_session(self.session_id)?;
        if head.irreversible().adaptor_secret_exposed
            || matches!(
                head.phase(),
                dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                    | dom_scriptless_store::SessionPhaseV1::Refunded
                    | dom_scriptless_store::SessionPhaseV1::FailedClosed
            )
        {
            return Ok(true);
        }
        if self
            .store
            .f7_claim_verification_facts_v15(chain, self.session_id, self.local_participant)?
            .is_some_and(|facts| facts.receiver_id() == self.local_participant)
        {
            // The receiver has already accepted 0x0f and must now observe its
            // own Claim. It cannot emit another upstream private round here.
            return Ok(true);
        }
        if self.session_id == downstream.session_id
            || self.local_participant != downstream.local_participant
        {
            return Err(Error::Scope);
        }
        // Store starts its freshness clock BEFORE the potentially blocking
        // scan, and reauthenticates both owners after it. No old observation
        // token can receive a new lifetime merely by being handed back.
        let mut scan_refusal = None;
        let result = self.store.with_verified_downstream_dom_claim_v23(
            chain,
            self.session_id,
            downstream.store.as_ref(),
            |facts| match scanner.find_f7_receiver_claim_v15(facts) {
                Ok(value) => Ok(value),
                Err(adapter_dom_real::RealDomError::InsufficientConfirmations) => Ok(None),
                Err(
                    adapter_dom_real::RealDomError::LockPoisoned
                    | adapter_dom_real::RealDomError::Chain(
                        dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
                    ),
                ) => {
                    scan_refusal = Some(Error::Evidence(
                        f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11::Unavailable,
                    ));
                    Err(dom_scriptless_store::SessionStoreError::Conflict)
                }
                Err(_) => {
                    scan_refusal = Some(Error::Scope);
                    Err(dom_scriptless_store::SessionStoreError::Conflict)
                }
            },
        );
        result.map_err(|error| scan_refusal.unwrap_or(Error::Store(error)))
    }
}
