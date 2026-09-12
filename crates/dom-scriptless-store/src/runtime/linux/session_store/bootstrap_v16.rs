//! Recovery of a completed bootstrap beneath later settlement phases.
use super::*;
#[path = "shared_output_formation_v22.rs"]
mod shared_output_formation_v22;

impl ContractsSessionStoreV1 {
    /// Authenticate a refund edge received in the same inbox batch as the
    /// preceding template/partial edge, before the runtime can install its
    /// next ingress. This is a bounded wait, never transport acceptance.
    pub fn bootstrap_refund_awaits_handoff_v18(
        &self,
        session: [u8; 32],
        signed: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed)?;
        if !matches!(envelope.message_type, 0x0c | 0x10) {
            return Ok(false);
        }
        if envelope.session_id != session {
            return Err(SessionStoreError::Canonical);
        }
        let current = self.load_session_locked(session)?;
        if !matches!(
            (envelope.message_type, current.phase()),
            (0x0c, SessionPhaseV1::TemplatesCommitted) | (0x10, SessionPhaseV1::RefundSigning)
        ) {
            return Ok(false);
        }
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let participant = roster
            .participants
            .iter()
            .find(|p| p.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        if envelope.chain_id != roster.chain_id
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    envelope.sender_id,
                    current.revision(),
                )?
        {
            return Err(SessionStoreError::Canonical);
        }
        envelope.verify(&participant.identity_key)?;
        let payload = envelope.payload(signed)?;
        if envelope.message_type == 0x0c {
            let template = self.load_template_transport_authority(session)?;
            if self.audit_operational_template_transport_prefix(
                session, &current, &roster, &template,
            )? != 2
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let commitment =
                NonceCommitmentV1::from_bytes(payload).map_err(|_| SessionStoreError::Canonical)?;
            if commitment.purpose() != PurposeV1::Refund
                || commitment.participant_index() != 0
                || roster.participants.first().map(|p| p.participant_id) != Some(envelope.sender_id)
            {
                return Err(SessionStoreError::Canonical);
            }
        } else {
            // Reconstruct the exact final transaction from all six native
            // signing edges. A different payload is a hard error, not a wait.
            let derived = self.derive_completed_operational_final_refund_at_terminal(
                &roster.chain_id,
                session,
                current.revision(),
            )?;
            if derived.canonical_sender_id != envelope.sender_id
                || derived.canonical_sender_sequence != envelope.sequence
                || derived.exact_transaction_bytes != payload
            {
                return Err(SessionStoreError::InvalidDomTransaction);
            }
        }
        Ok(true)
    }

    /// Return exact public refund bytes only after native 0x10 acceptance.
    /// A phase that has not reached the refund terminal returns `None`; an
    /// advanced phase missing its required refund history is a hard error.
    pub fn completed_bootstrap_refund_v18(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<Option<Vec<u8>>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session)?;
        if self.load_transport_roster(session)?.chain_id != *chain.as_bytes() {
            return Err(SessionStoreError::Canonical);
        }
        if matches!(
            current.phase(),
            SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        if matches!(
            current.phase(),
            SessionPhaseV1::Created
                | SessionPhaseV1::TermsCommitted
                | SessionPhaseV1::SharesCommitted
                | SessionPhaseV1::SharesRevealed
                | SessionPhaseV1::OutputFinalized
                | SessionPhaseV1::TemplatesCommitted
                | SessionPhaseV1::RefundSigning
        ) {
            return Ok(None);
        }
        let retained = self.load_operational_final_refund_v2(session)?;
        if chain.as_bytes() != &retained.chain_id {
            return Err(SessionStoreError::Canonical);
        }
        self.authenticate_operational_final_refund_v2_at_terminal(
            session,
            retained.terminal_revision,
        )?;
        let transport = self.authenticate_completed_operational_final_refund_at_terminal(
            session,
            retained.terminal_revision,
        )?;
        self.require_operational_final_refund_transport_head(&transport, &current)?;
        Ok(Some(retained.exact_transaction_bytes))
    }

    /// A canonical first template commitment can precede local construction
    /// data. Authenticate its sender, sequence and BP predecessor, but neither
    /// accept it nor authorize its unknown transaction hashes. The caller must
    /// keep it pending until exact templates can be independently rebuilt.
    pub fn template_commit_awaits_construction_v17(
        &self,
        session: [u8; 32],
        signed_bytes: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.message_type != 0x0b {
            return Ok(false);
        }
        if envelope.session_id != session {
            return Err(SessionStoreError::Canonical);
        }
        let current = self.load_session_locked(session)?;
        if current.phase() != SessionPhaseV1::OutputFinalized {
            return Ok(false);
        }
        match self.load_template_transport_authority(session) {
            Ok(_) => return Ok(false),
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let first = roster
            .participants
            .first()
            .ok_or(SessionStoreError::Canonical)?;
        if envelope.chain_id != roster.chain_id
            || envelope.sender_id != first.participant_id
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    first.participant_id,
                    current.revision(),
                )?
        {
            return Err(SessionStoreError::Canonical);
        }
        envelope.verify(&first.identity_key)?;
        let early = self.load_early_transport_authority(session)?;
        let initial = self.load_session_revision(session, 0)?;
        self.require_live_early_transport_authority(&early, &initial, &roster)?;
        let bp = self.load_bp_transport_authority(session)?;
        let start = self.load_session_revision(session, bp.round_start_revision)?;
        self.require_live_bp_transport_authority(&bp, &early, &start, &roster)?;
        if bp.round_start_revision.checked_add(11) != Some(current.revision()) {
            return Err(SessionStoreError::Quarantined);
        }
        let verifier = DomCollaborativeRangeProofV1::new(
            &bp.statement,
            bp.recovery_capsule.as_bytes().to_vec(),
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let _proof = self
            .audit_operational_bp_continuation(
                session,
                &current,
                &roster,
                &bp.statement,
                &verifier,
            )?
            .into_final_proof()?;
        let payload: [u8; 160] = envelope
            .payload(signed_bytes)?
            .try_into()
            .map_err(|_| SessionStoreError::Canonical)?;
        if !template_commit_payload_is_valid(&payload)
            || payload[96..128] != bp.statement.statement_hash()
            || payload[128..160] != *bp.statement.recovery_binding_hash()
        {
            return Err(SessionStoreError::Canonical);
        }
        Ok(true)
    }

    /// Reauthenticate both native template commitments, including after the
    /// session has advanced. The first 0x0b already changes the phase, so a
    /// phase-name check alone cannot prove bilateral completion.
    pub fn operational_templates_complete_v17(
        &self,
        authority: &PreparedOperationalTemplateTransportAuthorityV1,
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let authenticated = self.authenticate_prepared_template_transport_authority(authority)?;
        let current = self.load_session_locked(authenticated.session_id)?;
        if matches!(
            current.phase(),
            SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(authenticated.session_id)?;
        let count = self.audit_operational_template_transport_prefix(
            authenticated.session_id,
            &current,
            &roster,
            &authenticated,
        )?;
        Ok(count == 2)
    }

    /// Reauthenticate the immutable terminal BP prefix even when the current
    /// head has advanced into templates, funding, claim or refund. `None`
    /// means the authenticated session has not completed the BP choreography;
    /// missing/corrupt authority after that boundary is a hard error.
    pub fn completed_operational_bp_proof_v16(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        statement: &BpStatementV1,
        capsule: &RecoveryCapsule,
    ) -> Result<Option<AuthenticatedOperationalBpFinalProofV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        if chain.as_bytes() != &roster.chain_id
            || current.terms_hash() != terms
            || current.phase() == SessionPhaseV1::FailedClosed
            || terms == [0; 32]
            || statement.session_id() != session
            || statement.chain_id() != *chain.as_bytes()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let canonical = BpStatementV1::from_bytes(statement.to_bytes(), &chain)
            .map_err(|_| SessionStoreError::Canonical)?;
        if canonical.to_bytes() != statement.to_bytes()
            || blake2b_256(capsule.as_bytes()).as_bytes() != statement.recovery_binding_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let authority = match self.load_bp_transport_authority(session) {
            Ok(authority) => authority,
            Err(SessionStoreError::SessionNotFound) if current.revision() <= 6 => return Ok(None),
            Err(error) => return Err(error),
        };
        let early = self.load_early_transport_authority(session)?;
        let initial = self.load_session_revision(session, 0)?;
        self.require_live_early_transport_authority(&early, &initial, &roster)?;
        let start = self.load_session_revision(session, authority.round_start_revision)?;
        self.require_live_bp_transport_authority(&authority, &early, &start, &roster)?;
        let expected = BpTransportAuthorityRecordV1::new(&early, &start, &canonical, capsule)?;
        if expected.bytes != authority.bytes {
            return Err(SessionStoreError::Conflict);
        }
        let terminal_revision = authority
            .round_start_revision
            .checked_add(11)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        if current.revision() < terminal_revision {
            return Ok(None);
        }
        let terminal = self.load_session_revision(session, terminal_revision)?;
        let verifier = DomCollaborativeRangeProofV1::new(&canonical, capsule.as_bytes().to_vec())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        self.audit_operational_bp_continuation(session, &terminal, &roster, &canonical, &verifier)?
            .into_final_proof()
            .map(Some)
    }
}
