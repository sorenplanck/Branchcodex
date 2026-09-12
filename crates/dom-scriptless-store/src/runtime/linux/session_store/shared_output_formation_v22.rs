//! Rebuild native formation evidence from the exact authenticated early journal.
use super::*;
use dom_scriptless_crypto::{
    freeze_shared_output_statement_v1, FrozenSharedOutputV1, SharedOutputContributionV1,
    SharedOutputInputsV1,
};

impl ContractsSessionStoreV1 {
    /// Revalidate both retained share proofs and the exact public value/statement.
    /// This produces formation evidence only, not a range proof or a funding
    /// authority. No private share, signing nonce or new journal row is created.
    pub fn retained_shared_output_formation_v22(
        &self,
        chain: TrustedChainIdV1,
        terms: [u8; 32],
        value_noms: u64,
        statement: &BpStatementV1,
        capsule: &RecoveryCapsule,
    ) -> Result<Option<FrozenSharedOutputV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let session = statement.session_id();
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        if current.terms_hash() != terms
            || terms == [0; 32]
            || statement.chain_id() != *chain.as_bytes()
            || roster.chain_id != *chain.as_bytes()
            || matches!(
                current.phase(),
                SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
            )
            || blake2b_256(capsule.as_bytes()).as_bytes() != statement.recovery_binding_hash()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let canonical = BpStatementV1::from_bytes(statement.to_bytes(), &chain)
            .map_err(|_| SessionStoreError::Canonical)?;
        if canonical.to_bytes() != statement.to_bytes() {
            return Err(SessionStoreError::Canonical);
        }
        if current.revision() < 6 {
            return Ok(None);
        }
        let authority = self.load_authenticated_early_signing_authority(session, &roster)?;
        if authority.terms_hash != terms
            || authority.recovery_binding_hash != *statement.recovery_binding_hash()
        {
            return Err(SessionStoreError::Conflict);
        }
        let records = self.authenticated_early_transport_prefix(session, current.revision())?;
        if records.len() != 6 {
            return Err(SessionStoreError::Quarantined);
        }
        let ids = authority
            .participants
            .each_ref()
            .map(|participant| participant.participant_id);
        let mut commitments = [None, None];
        let mut contributions = Vec::with_capacity(2);
        for (position, record) in records.iter().enumerate() {
            let expected = early_transport_expected_item(position, &roster)?;
            if record.revision != position as u64 + 1 || record.successor.phase() != expected.phase
            {
                return Err(SessionStoreError::Quarantined);
            }
            validate_early_transport_payload(
                &authority,
                expected,
                record.sender_id,
                record.message_type,
                &record.payload,
                &mut commitments,
            )?;
            if record.message_type == 0x04 {
                let reveal = EarlyShareRevealV1::from_bytes_against_frozen_context(
                    &record.payload,
                    chain.as_bytes(),
                    &ids,
                    &authority.context_commitment,
                )
                .map_err(|_| SessionStoreError::Canonical)?;
                let share = reveal.statement();
                contributions.push(SharedOutputContributionV1 {
                    participant_index: share.participant_index(),
                    participant_id: share.participant_id(),
                    role: share.role(),
                    commitment_share: share.share_point().clone(),
                    proof: dom_adaptor::ShareProofV1::from_bytes(&reveal.proof().to_bytes())
                        .map_err(|_| SessionStoreError::Canonical)?,
                });
            }
        }
        // Transport turn order is not a substitute for the canonical native
        // participant index (the initiator need not sort first by identity).
        contributions.sort_by_key(|contribution| contribution.participant_index);
        let frozen = freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
            chain_id: chain,
            session_id: session,
            contributions: &contributions,
            value_noms,
            terms_hash: terms,
            recovery_binding_hash: *statement.recovery_binding_hash(),
        })
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if frozen.statement().to_bytes() != statement.to_bytes() {
            return Err(SessionStoreError::Conflict);
        }
        Ok(Some(frozen))
    }
}
