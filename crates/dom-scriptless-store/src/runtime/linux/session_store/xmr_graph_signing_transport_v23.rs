//! Native graph signing envelopes. The independent identity keystore consumes
//! Store-issued requests before exporting a signature; no raw signing shortcut.
use super::*;

/// Process-local ingress scope; callers cannot manufacture or retarget it.
pub struct PreparedXmrGraphSigningIngressV23 {
    store: [u8; 32],
    open_instance: [u8; 32],
    target: [u8; 32],
    edge: XmrGraphRecoverySigningEdgeV23,
    binding: [u8; 32],
}

impl PreparedXmrGraphSigningIngressV23 {
    /// Exact native recovery session authenticated by this ingress handle.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.target
    }
}

impl ContractsSessionStoreV1 {
    pub(in super::super) fn require_xmr_refund_ingress_terminal_v23(
        &self,
        prepared: &PreparedXmrGraphSigningIngressV23,
        session: [u8; 32],
        terminal_revision: u64,
    ) -> Result<(), SessionStoreError> {
        if prepared.store != self._store_id
            || prepared.open_instance != self.open_instance_id
            || prepared.target != session
            || prepared.edge != XmrGraphRecoverySigningEdgeV23::RefundAdaptor
        {
            return Err(SessionStoreError::Conflict);
        }
        let binding = self.authenticate_xmr_graph_signing_session_v23(session, prepared.edge)?;
        if prepared.binding != binding.digest
            || binding.start.revision().checked_add(6) != Some(terminal_revision)
        {
            return Err(SessionStoreError::Conflict);
        }
        let terminal = self.load_session_revision(session, terminal_revision)?;
        let round = self.audit_xmr_graph_signing_round_at_v23(&binding, &terminal, None)?;
        if round.accepted_messages.len() != 6 {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    /// Freeze an ingress scope only after authenticating the native binding and
    /// the real signed round prefix. It grants no signing or funding authority.
    pub fn prepare_xmr_graph_signing_ingress_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<PreparedXmrGraphSigningIngressV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let binding = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        self.audit_xmr_graph_signing_round_v23(&binding)?;
        Ok(PreparedXmrGraphSigningIngressV23 {
            store: self._store_id,
            open_instance: self.open_instance_id,
            target,
            edge,
            binding: binding.digest,
        })
    }

    /// Payload must come from the native nonce/share custodian. The Store does
    /// not create it: it checks the exact stage, participant, commitment opening
    /// or partial equation against the reauthenticated prefix before issuance.
    /// A remote turn or complete round returns None without creating a request.
    pub fn prepare_xmr_graph_signing_dsc1_request_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
        payload: &[u8],
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let binding = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        let current = self.load_session_locked(target)?;
        let round = self.audit_xmr_graph_signing_round_v23(&binding)?;
        let position = round.accepted_messages.len();
        if position == 6 {
            return Ok(None);
        }
        if position > 6
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || current.revision()
                != binding
                    .start
                    .revision()
                    .checked_add(position as u64)
                    .ok_or(SessionStoreError::CapacityExceeded)?
            || current.transcript_hash() != round.terminal_transcript
            || (position == 0 && current.phase() != binding.start.phase())
            || (position != 0 && current.phase() != SessionPhaseV1::RefundSigning)
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let protocol_index = position % 2;
        let stage = position / 2;
        let participant = binding
            .origin
            .roster
            .entries()
            .get(protocol_index)
            .ok_or(SessionStoreError::Quarantined)?;
        let signer = self.authenticate_local_transport_signer_binding(target)?;
        if signer.participant_id != *participant.participant_id() {
            return Ok(None);
        }
        let sequence = binding.sender_sequence_bases[protocol_index]
            .checked_add(stage as u64)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let authority_class = match stage {
            0 => OutboundDsc1AuthorityClassV1::XmrGraphNonceCommitV23,
            1 => OutboundDsc1AuthorityClassV1::XmrGraphNonceRevealV23,
            2 => OutboundDsc1AuthorityClassV1::XmrGraphPartialSignatureV23,
            _ => return Err(SessionStoreError::InvalidTransition),
        };
        let candidate = outbound_dsc1_candidate_bytes(&OutboundDsc1UnsignedFieldsV1 {
            message_type: 0x0c + stage as u8,
            chain_id: *binding.origin.chain.as_bytes(),
            session_id: target,
            sender_id: *participant.participant_id(),
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            payload,
        })?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_graph_signing_message_v23(
            &binding, &current, &envelope, &candidate, None,
        )?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class,
            chain_id: *binding.origin.chain.as_bytes(),
            session_id: target,
            sender_id: *participant.participant_id(),
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            predecessor: &current,
            authority_digest: binding.digest,
            payload,
        })
        .map(Some)
    }

    /// Accept only under a Store-issued native scope. Signature authentication
    /// precedes replay/equivocation handling, which precedes the live next gate.
    pub fn accept_xmr_graph_signing_ingress_v23(
        &self,
        prepared: &PreparedXmrGraphSigningIngressV23,
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if prepared.store != self._store_id || prepared.open_instance != self.open_instance_id {
            return Err(SessionStoreError::Conflict);
        }
        self.audit_transport()?;
        let binding =
            self.authenticate_xmr_graph_signing_session_v23(prepared.target, prepared.edge)?;
        if binding.digest != prepared.binding {
            return Err(SessionStoreError::Conflict);
        }
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if !(0x0c..=0x0e).contains(&envelope.message_type)
            || envelope.chain_id != *binding.origin.chain.as_bytes()
            || envelope.session_id != prepared.target
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(prepared.target)?;
        let identities = self.load_transport_identity_binding(prepared.target)?;
        require_transport_identity_binding(&roster, &identities)?;
        let participant = roster
            .participants
            .iter()
            .find(|entry| entry.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        envelope.verify(&participant.identity_key)?;
        let current = self.load_session_locked(prepared.target)?;
        let name = transport_message_name(
            prepared.target,
            envelope.sender_id,
            envelope.sequence,
            false,
        );
        match self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        ) {
            Ok(bytes) => {
                let retained = TransportMessageRecordV1::from_bytes(&bytes)?;
                self.authenticate_transport_record(&name, &retained)?;
                if retained.signed_bytes == signed_bytes {
                    return self.accept_transport_message_with_successor_locked(
                        signed_bytes,
                        &current,
                        None,
                    );
                }
                let failed = current.advance(
                    current.revision(),
                    SessionPhaseV1::FailedClosed,
                    current.transcript_hash(),
                    current.irreversible(),
                    current.chain(),
                    current.encrypted_payload(),
                )?;
                return self.accept_transport_message_with_successor_locked(
                    signed_bytes,
                    &current,
                    Some(&failed),
                );
            }
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let phase = self.require_next_graph_signing_message_v23(
            &binding,
            &current,
            &envelope,
            signed_bytes,
            None,
        )?;
        let transcript = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            participant.direction,
            envelope.message_type,
            phase,
        )?;
        let mut irreversible = current.irreversible();
        if envelope.message_type == 0x0e {
            irreversible.any_signing_share_sent = true;
        }
        let successor = current.advance(
            current.revision(),
            phase,
            transcript,
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let failed = current.advance(
            current.revision(),
            SessionPhaseV1::FailedClosed,
            current.transcript_hash(),
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        self.accept_transport_message_with_successor_locked(signed_bytes, &successor, Some(&failed))
    }
}
