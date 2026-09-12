//! Cross-leg public-revelation observation using only the retained owners.
use super::*;

impl ProductionRelayStage12OwnerV1 {
    pub(super) fn observe_upstream_dom_revelation_v23(
        &self,
        leg: LegIdV1,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
    ) -> Result<bool, crate::production_contracts::ProductionF7RuntimeErrorV12> {
        if leg != LegIdV1::Upstream {
            return Ok(true);
        }
        if self.upstream.trusted_chain_id != self.downstream.trusted_chain_id {
            return Err(crate::production_contracts::ProductionF7RuntimeErrorV12::Scope);
        }
        self.upstream.contracts.observe_downstream_claim_gate_v23(
            self.upstream.trusted_chain_id,
            &self.downstream.contracts,
            scanner,
        )
    }
}
