//! Recovery-only share custody. Public graph material never substitutes for
//! a Store-issued signing session; every failed admission leaves all shares held.
use super::*;

impl DomXmrGraphSigningSharesV22 {
    /// Move only the D-to-DOM refund-adaptor excess after native admission.
    /// Funding and claim remain in wallet custody. This does not reserve a nonce
    /// or grant signing permission; the retained signer still needs its permit.
    pub fn take_refund_adaptor_share_v23(
        &mut self,
        store: &ContractsSessionStoreV1,
        templates: &xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        // Require the bounded V23 profile even though this round retains the
        // parent session; a legacy compensation graph is not interchangeable.
        templates
            .compensation_session_v23()
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        let graph = templates.binding();
        if graph.chain_id != self.binding.chain_id()
            || graph.session_id != self.binding.session_id()
            || graph.terms_hash != self.binding.terms_digest()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let hash = dom_adaptor::canonical_template_v1(templates.refund())
            .map_err(|_| DomActuatorError::CapabilityMismatch)?
            .1;
        let adaptor = PublicKey::from_compressed_bytes(&graph.refund_adaptor_point)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        self.require_recovery_custody_v23(
            store,
            self.binding,
            PurposeV1::RefundAdaptor,
            hash,
            Some(&adaptor),
            3,
        )?;
        self.take_recovery_index_v23(self.binding, 3)
    }

    pub(super) fn require_recovery_custody_v23(
        &self,
        store: &ContractsSessionStoreV1,
        binding: DomSessionBindingV1,
        purpose: PurposeV1,
        template_hash: [u8; 32],
        adaptor: Option<&PublicKey>,
        index: usize,
    ) -> DomActuatorResult<()> {
        if !matches!(
            (purpose, index),
            (PurposeV1::Refund, 2 | 4) | (PurposeV1::RefundAdaptor, 3)
        ) || template_hash == [0; 32]
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let _bound = DomContractsActuatorV1::bind(store, binding)?;
        let trusted = *self.proof_binding.trusted_chain_id();
        let edge = match index {
            2 => dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Cancel,
            3 => dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
            4 => dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Compensation,
            _ => return Err(DomActuatorError::CapabilityMismatch),
        };
        let accepted = store
            .resume_xmr_graph_signing_session_v23(binding.session_id(), edge)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let entries = accepted.roster().entries();
        let actual_hash = dom_adaptor::canonical_template_v1(accepted.transaction_template())
            .map_err(|_| DomActuatorError::CapabilityMismatch)?
            .1;
        if accepted.session_id() != &binding.session_id()
            || accepted.trusted_chain_id() != &trusted
            || trusted.as_bytes() != &binding.chain_id()
            || accepted.contract_kind() != ContractKindV1::WitnessOrTimeout
            || accepted.purpose() != purpose
            || accepted.kernel_index() != 0
            || actual_hash != template_hash
            || accepted.adaptor_point() != adaptor
            || entries.len() != 2
            || entries.iter().map(|entry| *entry.participant_id()).ne(self
                .proof_binding
                .roster()
                .iter()
                .copied())
            || entries[0].direction() == entries[1].direction()
            || !entries.iter().any(|entry| {
                entry.participant_id() == &binding.participant().participant_id()
                    && entry.direction() == self.proof_binding.role()
                    && entry.signing_public_key() == &self.keys[index]
            })
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    pub(super) fn take_recovery_index_v23(
        &mut self,
        binding: DomSessionBindingV1,
        index: usize,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        if !(2..=4).contains(&index) {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let share = self.shares[index]
            .take()
            .ok_or(DomActuatorError::InvalidStage)?;
        Ok(DomParticipantSigningShareV1::new(binding, share))
    }
}
