//! Same-Store late template binding, scoped to this Contracts owner.
use super::*;
use dom_scriptless_store::VerifiedXmrRefundTemplateBindingV23;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// Only a genuinely earlier native head is pending. Once the bilateral
    /// agreement revision exists, a missing origin is corruption, not waiting.
    pub(crate) fn poll_xmr_refund_template_binding_v23(
        &self,
        chain: TrustedChainIdV1,
    ) -> Result<Option<VerifiedXmrRefundTemplateBindingV23>, SessionStoreError> {
        use dom_scriptless_store::SessionPhaseV1 as Phase;
        let head = self.store.load_session(self.session_id)?;
        if head.revision() >= 19 {
            return self.resume_xmr_refund_template_binding_v23(chain).map(Some);
        }
        let legal = match head.revision() {
            17 => head.phase() == Phase::OutputFinalized,
            18 => head.phase() == Phase::TemplatesCommitted,
            _ => matches!(
                head.phase(),
                Phase::Created
                    | Phase::TermsCommitted
                    | Phase::SharesCommitted
                    | Phase::SharesRevealed
                    | Phase::BpCommonCommitted
                    | Phase::BpCommonEstablished
                    | Phase::BpNonceCommitted
                    | Phase::BpRound1Complete
                    | Phase::BpRound2Complete
            ),
        };
        if !legal
            || head.irreversible().funding_authorized
            || head.irreversible().any_signing_share_sent
            || head.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(None)
    }

    pub(crate) fn prepare_xmr_refund_template_binding_v23(
        &self,
        chain: TrustedChainIdV1,
    ) -> Result<VerifiedXmrRefundTemplateBindingV23, SessionStoreError> {
        let binding = self.store.prepare_xmr_refund_template_binding_v23(
            chain,
            self.route_id,
            self.session_id,
        )?;
        self.require_xmr_refund_template_owner_v23(&binding)?;
        Ok(binding)
    }

    pub(crate) fn resume_xmr_refund_template_binding_v23(
        &self,
        chain: TrustedChainIdV1,
    ) -> Result<VerifiedXmrRefundTemplateBindingV23, SessionStoreError> {
        let binding = self.store.resume_xmr_refund_template_binding_v23(
            chain,
            self.route_id,
            self.session_id,
        )?;
        self.require_xmr_refund_template_owner_v23(&binding)?;
        Ok(binding)
    }

    pub(crate) fn revalidate_xmr_refund_template_binding_v23(
        &self,
        binding: &VerifiedXmrRefundTemplateBindingV23,
    ) -> Result<(), SessionStoreError> {
        self.require_xmr_refund_template_owner_v23(binding)?;
        self.store
            .revalidate_xmr_refund_template_binding_v23(binding)
    }

    fn require_xmr_refund_template_owner_v23(
        &self,
        binding: &VerifiedXmrRefundTemplateBindingV23,
    ) -> Result<(), SessionStoreError> {
        let participants = binding.participant_ids();
        if binding.route_id() != self.route_id
            || binding.session_id() != self.session_id
            || self.local_participant == self.remote_participant
            || !participants.contains(&self.local_participant)
            || !participants.contains(&self.remote_participant)
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }
}
