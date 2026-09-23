//! A closed native funding window pauses fresh signing, not durable recovery.
use super::*;

impl ContractsSessionStoreV1 {
    /// A first peer readiness vote can precede local gate construction. Keep
    /// only this authenticated next envelope pending under the completed native
    /// refund ingress. This grants no receipt, vote, custody or funding permit;
    /// the readiness digest must still match the real gate when it is installed.
    pub fn xmr_readiness_awaits_gate_v25(
        &self,
        prepared: &PreparedXmrGraphSigningIngressV23,
        signed: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed)?;
        if envelope.message_type != 0x17 {
            return Ok(false);
        }
        let session = *prepared.session_id();
        if envelope.session_id != session {
            return Err(SessionStoreError::Canonical);
        }
        match self.load_f7_gate_v12(session) {
            Ok(_) => return Ok(false),
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        let current = self.load_session_locked(session)?;
        if current.phase() != SessionPhaseV1::RefundSigning
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Ok(false);
        }
        self.require_xmr_refund_ingress_terminal_v23(prepared, session, current.revision())?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let first = roster
            .participants
            .first()
            .ok_or(SessionStoreError::Quarantined)?;
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
        let payload = envelope.payload(signed)?;
        if payload.len() != 32 || payload == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        Ok(true)
    }

    /// Authenticate the first funding nonce commitment when it arrives in the
    /// same Relay batch that completes bilateral readiness.
    ///
    /// The native funding owner still has to obtain a fresh chain observation,
    /// begin the retained signing round and install its linear ingress
    /// authority.  This read-only predicate grants none of those operations;
    /// it only proves that retaining the exact inbox row is a bounded protocol
    /// wait rather than an unprepared arbitrary message.
    pub fn xmr_funding_commitment_awaits_handoff_v25(
        &self,
        session: [u8; 32],
        signed: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed)?;
        if envelope.message_type != 0x0c {
            return Ok(false);
        }
        if envelope.session_id != session {
            return Err(SessionStoreError::Canonical);
        }
        let gate = match self.load_f7_gate_v12(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
        {
            return Ok(false);
        }
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if current.phase() != gate.phase
            || current.irreversible().funding_authorized
            || current.revision()
                != gate
                    .bound_revision
                    .checked_add(2)
                    .ok_or(SessionStoreError::Quarantined)?
            || self.f7_ready_count_v12(&gate, current.revision())? != 2
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Ok(false);
        }
        let (_, roster, _) = self.reconstruct_xmr_bounded_funding_roster_v23(&gate)?;
        let first = roster
            .entries()
            .first()
            .ok_or(SessionStoreError::Quarantined)?;
        if envelope.chain_id != gate.chain_id
            || envelope.sender_id != *first.participant_id()
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    *first.participant_id(),
                    current.revision(),
                )?
        {
            return Err(SessionStoreError::Canonical);
        }
        envelope.verify(first.identity_public_key())?;
        let commitment = NonceCommitmentV1::from_bytes(envelope.payload(signed)?)
            .map_err(|_| SessionStoreError::Canonical)?;
        if commitment.purpose() != PurposeV1::Funding
            || commitment.participant_index()
                != roster
                    .signing_index(first.participant_id())
                    .map_err(|_| SessionStoreError::Quarantined)?
            || commitment.nonce_reveal_hash() == &[0; 32]
        {
            return Err(SessionStoreError::Canonical);
        }
        Ok(true)
    }

    /// Read-only timing classification for the native XMR scheduler.
    /// `true` is not signing authority. The signer and transmission boundaries
    /// still revalidate the window immediately before their own operation.
    /// Only a valid native prefunding state can report a closed window; broken
    /// ancestry, substituted chain context, abort and terminal state are errors.
    pub fn xmr_funding_window_open_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
            || chain.as_bytes() != &gate.chain_id
            || context.chain_id() != &gate.chain_id
            || context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || current.irreversible().adaptor_secret_exposed
            || !matches!(
                (current.phase(), current.irreversible().funding_authorized),
                (SessionPhaseV1::RefundSigning, false) | (SessionPhaseV1::FundingAuthorized, true)
            )
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match require_f7_funding_window_v12(&gate, context.current_height()) {
            Ok(()) => Ok(true),
            // This exact helper reports this variant only for the signed
            // deadline/reveal margin. Never classify arbitrary Store errors.
            Err(SessionStoreError::FundingAuthorityUnavailable) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
