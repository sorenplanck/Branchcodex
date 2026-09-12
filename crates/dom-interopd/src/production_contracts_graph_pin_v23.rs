//! Narrow operation on the existing owners; no raw Store access is exposed.
use super::*;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn retain_xmr_graph_proposal_v23<G: F6TransportPortV1>(
        &self,
        cancelled: &ProductionContractsV1<G>,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        terms: &kaystra_core::SettlementTermsV1,
        templates: &xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
        keys: &xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22,
    ) -> Result<[u8; 32], SessionStoreError> {
        if self.session_id != templates.binding().session_id
            || self.route_id != route
            || cancelled.route_id != route
            || self.local_participant != cancelled.local_participant
            || self.remote_participant != cancelled.remote_participant
            || cancelled.session_id
                != xmr_refund_policy::graph_builder::xmr_cancelled_output_session_v12(
                    templates.policy(),
                )
        {
            return Err(SessionStoreError::Conflict);
        }
        self.store.retain_xmr_graph_proposal_v23(
            &cancelled.store,
            chain,
            route,
            terms,
            templates,
            keys,
        )
    }
}
