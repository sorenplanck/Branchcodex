//! Narrow operation on the existing encrypted fixture owner; no secret getter.
use super::*;

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn observe_claim_anchors_v23(
        &self,
        actor: usize,
        dom: &dom_scriptless_chain_adapter::DomHttpChainAdapterV1,
        request: &dom_scriptless_store::F7AnchorRequestBindingV12,
        produced: &xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12,
        deployment: &deployment_registry::ResolvedMoneroDeploymentV1,
        urls: &[String],
        sidecar: &mut xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12> {
        use f7_anchor_authority::families_v11::{
            verify_f7_xmr_bounded_anchor_authorization_v23, verify_xmr_funding_v11,
            DomXmrBoundedAnchorValidationRequestV23, XmrFundingObservationRequestV11,
        };
        let owner = self
            .actors
            .get(actor)
            .ok_or("invalid native observer actor")?;
        xmr_session_init::resume_session_for_role_v11(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            owner.role,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let funding = runtime.block_on(verify_xmr_funding_v11(
            XmrFundingObservationRequestV11 {
                terms: request.role().terms(),
                setup: &self.setup,
                profile: &self.profile,
                deployment,
                daemon_urls: urls,
            },
            sidecar,
            &owner.secrets,
        ))?;
        // The DOM adapter is blocking: never invoke it inside the Tokio runtime.
        // Reconstruct the exact same XMR scope for opaque proof authentication.
        drop(runtime);
        Ok(verify_f7_xmr_bounded_anchor_authorization_v23(
            dom,
            DomXmrBoundedAnchorValidationRequestV23 {
                role: request.role(),
                produced,
                refund_share_proof: &self.refund_proof,
                expected_dom_funding_txid: request.dom_funding_txid(),
                claim_round_start_transcript_hash: request.round_start_transcript_hash(),
                xmr: XmrFundingObservationRequestV11 {
                    terms: request.role().terms(),
                    setup: &self.setup,
                    profile: &self.profile,
                    deployment,
                    daemon_urls: urls,
                },
            },
            funding,
        )?)
    }
}
