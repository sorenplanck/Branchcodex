//! Productive M.8 claim construction from the same retained native authority.
//! These read-only projections cannot mint signing authority or export secrets.
use super::*;
use dom_adaptor::{
    AdaptorSecret, ScriptlessTransactionTemplateV1, VerifiedClaimTransactionV1,
    VerifiedSharedOutputV1,
};

impl ContractsSessionStoreV1 {
    /// Public receiver inputs from the native M.8 gate and completed round.
    /// Missing pre-signature is a wait; a corrupt record or foreign role fails.
    pub fn post_m8_receiver_pre_signature_v22(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        participant: [u8; 32],
    ) -> Result<Option<[u8; AdaptorPreSignatureV1::ENCODED_LEN]>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = match self.load_m8_funding_gate_v2(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        if gate.role_binding.dom_chain_id().0 != *chain.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        if participant == gate.role_binding.dom_claim_sender_id().0 {
            return Ok(None);
        }
        if participant != gate.role_binding.final_claim_receiver_id().0 {
            return Err(SessionStoreError::InvalidTransition);
        }
        let pre = match self.load_post_anchor_claim_pre_signature_v2(session) {
            Ok(pre) => pre,
            Err(SessionStoreError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.audit_post_anchor_claim_authorization_state_v2(session)?;
        let issued = self.load_post_anchor_claim_authorization_v2(
            session,
            PostAnchorClaimAuthorizationStateV2::Issued,
        )?;
        require_post_anchor_role_v2(&issued, &gate)?;
        if pre.issuance_record_digest != issued.digest
            || pre.chain_id != issued.chain_id
            || pre.final_claim_role_binding_digest != issued.final_claim_role_binding_digest
            || pre.ready_binding_digest != issued.ready_binding_digest
            || pre.claim_template_hash != issued.claim_template_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Some(pre.pre_signature.to_bytes()))
    }

    /// True only for authenticated sender exposure, including a crash before
    /// its session successor or actuator mirror was repaired.
    pub fn post_m8_claim_exposed_v22(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        match self.load_operational_final_claim_exposure_v2(session) {
            Err(SessionStoreError::SessionNotFound) => {
                match self.load_operational_final_claim_admission_v2(session) {
                    Err(SessionStoreError::SessionNotFound) => Ok(false),
                    Err(error) => Err(error),
                    Ok(_) => Err(SessionStoreError::Quarantined),
                }
            }
            Err(error) => Err(error),
            Ok(_) => {
                self.authenticate_final_claim_exposure_lane_v2_with_completed(
                    chain, session, true,
                )?;
                Ok(true)
            }
        }
    }

    /// Reconstruct the exact prefunding claim template and authenticated roster.
    /// No caller-supplied transaction, signing key or replacement template enters.
    pub fn retained_post_m8_claim_template_v22(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        chain: TrustedChainIdV1,
    ) -> Result<(Transaction, ParticipantRosterV1, usize), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (issued, _, _) = self.authenticate_live_consumed_claim_authority_v2(authorization)?;
        if chain.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let gate = self.load_m8_funding_gate_v2(issued.session_id)?;
        require_post_anchor_role_v2(&issued, &gate)?;
        let role =
            FinalClaimRoleBindingV1::decode_canonical(&chain, gate.role_binding.canonical_bytes())
                .map_err(|_| SessionStoreError::Quarantined)?;
        let transaction = Transaction::from_bytes(&gate.claim_template_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (_, hash) =
            canonical_template_v1(&transaction).map_err(|_| SessionStoreError::Quarantined)?;
        if hash != issued.claim_template_hash || role.claim_template_hash() != hash {
            return Err(SessionStoreError::Quarantined);
        }
        Ok((
            transaction,
            role.roster().clone(),
            role.claim_kernel_index() as usize,
        ))
    }

    /// Adapt the authenticated completed M.8 DOM round. The returned transaction
    /// is linear and can leave this crate only through the native exposure sink.
    pub fn finalize_retained_post_m8_claim_v22(
        &self,
        authorization: &ConsumedClaimSigningAuthorizationV2,
        chain: TrustedChainIdV1,
        secret: &AdaptorSecret,
        validation_height: u64,
    ) -> Result<VerifiedClaimTransactionV1, SessionStoreError> {
        let pre = self.reconstruct_post_anchor_dom_claim_pre_signature_v2(authorization, chain)?;
        let transcript = *pre.reveal_transcript_hash();
        let pre = pre.into_pre_signature(self)?;
        let template = {
            let _guard = self.operation_lock()?;
            let (issued, _, _) =
                self.authenticate_live_consumed_claim_authority_v2(authorization)?;
            let signer = self.authenticate_local_transport_signer_binding(issued.session_id)?;
            if chain.as_bytes() != &issued.chain_id
                || signer.participant_id != issued.dom_claim_sender_id
                || secret
                    .public_point()
                    .map_err(|_| SessionStoreError::InvalidDomTransaction)?
                    != issued.adaptor_point
            {
                return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
            }
            let gate = self.load_m8_funding_gate_v2(issued.session_id)?;
            require_post_anchor_role_v2(&issued, &gate)?;
            let funding = self.load_m8_funding_commit_v2(issued.session_id)?;
            self.verify_m8_v2_commit_against_authority(&funding)?;
            if canonical_transaction_hash_v1(&funding.artifact.funding_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?
                != issued.dom_funding_id
            {
                return Err(SessionStoreError::Quarantined);
            }
            let funding = Transaction::from_bytes(&funding.artifact.funding_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?;
            let mut matching = funding.outputs.iter().filter(|output| {
                output.commitment.as_bytes() == &issued.dom_shared_output_commitment
            });
            let output = matching.next().ok_or(SessionStoreError::Quarantined)?;
            if matching.next().is_some() {
                return Err(SessionStoreError::Quarantined);
            }
            let shared = VerifiedSharedOutputV1::from_retained_output_v14(
                output,
                &issued.dom_shared_output_commitment,
            )
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
            let tx = Transaction::from_bytes(&gate.claim_template_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?;
            if tx.kernels.len() != 1 || gate.role_binding.claim_kernel_index() != 0 {
                return Err(SessionStoreError::Quarantined);
            }
            let template = ScriptlessTransactionTemplateV1::claim(
                &shared,
                tx.outputs,
                tx.kernels[0].clone(),
                tx.offset,
            )
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
            if template.template_hash() != &issued.claim_template_hash {
                return Err(SessionStoreError::Quarantined);
            }
            template
        };
        template
            .finalize_claim(
                &pre,
                secret,
                &transcript,
                chain.as_bytes(),
                validation_height,
            )
            .map_err(|_| SessionStoreError::InvalidDomTransaction)
    }
}
