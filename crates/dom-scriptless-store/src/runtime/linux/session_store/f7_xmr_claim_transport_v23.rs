//! Native bounded Claim transport; consumes ordinary identity-signing requests.
use super::*;
impl ContractsSessionStoreV1 {
    /// Payload must come from the native nonce/share custodian. The Store does
    /// not create it: it checks the exact stage, participant, commitment opening
    /// or partial equation against the reauthenticated prefix before issuance.
    /// A remote turn or complete round returns None without creating a request.
    pub fn prepare_xmr_bounded_claim_dsc1_request_v23(
        &self,
        chain: TrustedChainIdV1,
        target: [u8; 32],
        payload: &[u8],
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.prepare_xmr_bounded_claim_dsc1_request_locked_v23(chain, target, payload)
    }

    pub(in super::super::super) fn prepare_xmr_bounded_claim_dsc1_request_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        target: [u8; 32],
        payload: &[u8],
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        self.require_downstream_claim_gate_for_session_locked_v23(target)?;
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(target)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if chain != binding.chain {
            return Err(SessionStoreError::Conflict);
        }
        let current = self.load_session_locked(target)?;
        let round = self.audit_xmr_bounded_claim_current_round_v23(&binding, &current)?;
        let position = round.accepted.len();
        if position == 6 {
            return Ok(None);
        }
        if position > 6
            || !current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || current.transcript_hash() != round.terminal.transcript_hash()
            || (position == 0 && current.phase() != binding.start.phase())
            || (position != 0 && current.phase() != SessionPhaseV1::FundingConfirmed)
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let protocol_index = position % 2;
        let stage = position / 2;
        let participant = binding
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
            0 => OutboundDsc1AuthorityClassV1::OperationalSigningNonceCommitment,
            1 => OutboundDsc1AuthorityClassV1::OperationalSigningNonceReveal,
            2 => OutboundDsc1AuthorityClassV1::OperationalSigningPartialSignature,
            _ => return Err(SessionStoreError::InvalidTransition),
        };
        let candidate = outbound_dsc1_candidate_bytes(&OutboundDsc1UnsignedFieldsV1 {
            message_type: 0x0c + stage as u8,
            chain_id: *binding.chain.as_bytes(),
            session_id: target,
            sender_id: *participant.participant_id(),
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            payload,
        })?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_xmr_bounded_claim_message_v23(
            &binding, &current, &envelope, &candidate, None,
        )?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class,
            chain_id: *binding.chain.as_bytes(),
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
    pub fn accept_xmr_bounded_claim_transport_v23(
        &self,
        chain: TrustedChainIdV1,
        target: [u8; 32],
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.accept_xmr_bounded_claim_transport_locked_v23(chain, target, signed_bytes)
    }

    pub(in super::super::super) fn accept_xmr_bounded_claim_transport_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        target: [u8; 32],
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(target)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if chain != binding.chain {
            return Err(SessionStoreError::Conflict);
        }
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if !(0x0c..=0x0e).contains(&envelope.message_type)
            || envelope.chain_id != *binding.chain.as_bytes()
            || envelope.session_id != target
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(target)?;
        let identities = self.load_transport_identity_binding(target)?;
        require_transport_identity_binding(&roster, &identities)?;
        let participant = roster
            .participants
            .iter()
            .find(|entry| entry.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        envelope.verify(&participant.identity_key)?;
        let current = self.load_session_locked(target)?;
        let name = transport_message_name(target, envelope.sender_id, envelope.sequence, false);
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
        let phase = self.require_next_xmr_bounded_claim_message_v23(
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
