//! Exact prefunding role from authenticated composition and native graph keys.
use super::*;
use dom_adaptor::{AcceptedSigningSessionV1, ParticipantIdentityV1, ParticipantRosterV1};
use dom_final_claim_binding::{FinalClaimRoleBindingInputV1, FinalClaimRoleBindingV1};

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn bind_xmr_graph_custody_role_v23(
        &self,
        setup: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
        chain: TrustedChainIdV1,
        templates: &xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
        keys: &xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22,
    ) -> Result<FinalClaimRoleBindingV1, ProductionBootstrapRuntimeErrorV16> {
        use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22 as Stage;
        use ProductionBootstrapRuntimeErrorV16::Binding as Refused;
        let (plan, source, leg) = setup.claim_context_v23().ok_or(Refused)?;
        if setup.binding().session_id() != self.session_id
            || setup.binding().route_id() != self.route_id
            || templates.binding().session_id != self.session_id
            || templates.binding().chain_id != *chain.as_bytes()
            || templates.binding().terms_hash != setup.binding().terms_digest()
        {
            return Err(Refused);
        }
        keys.require_graph(templates).map_err(|_| Refused)?;
        keys.require_route(self.route_id).map_err(|_| Refused)?;
        let accepted = self.store.resume_xmr_graph_signing_session_v23(
            self.session_id,
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        let mut participants = Vec::with_capacity(2);
        for identity in accepted.roster().entries() {
            let key = keys
                .key(
                    Stage::Claim,
                    *identity.participant_id(),
                    keys.template_hash(Stage::Claim),
                )
                .map_err(|_| Refused)?
                .clone();
            let participant = ParticipantIdentityV1::new(
                &chain,
                identity.identity_public_key().clone(),
                key,
                identity.direction(),
            )
            .map_err(|_| Refused)?;
            if participant.participant_id() != identity.participant_id() {
                return Err(Refused);
            }
            participants.push(participant);
        }
        let roster = ParticipantRosterV1::new(participants).map_err(|_| Refused)?;
        FinalClaimRoleBindingV1::bind(
            &chain,
            FinalClaimRoleBindingInputV1 {
                terms: setup.terms(),
                roster: &roster,
                role_plan: plan,
                source_scope: source,
                route_leg: *leg,
                funding_template_hash: keys.template_hash(Stage::Funding),
                claim_template_hash: keys.template_hash(Stage::Claim),
                refund_template_hash: keys.template_hash(Stage::Refund),
                shared_output_commitment: templates.binding().funding_commitment,
                claim_kernel_index: 0,
            },
        )
        .map_err(|_| Refused)
    }
}
