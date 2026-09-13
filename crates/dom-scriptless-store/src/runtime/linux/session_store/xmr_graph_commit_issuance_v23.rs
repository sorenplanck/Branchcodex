//! Store-owned graph commitment issuance and prepared ingress. Public evidence
//! is reconstructed before every unseen message; historical replay does not
//! require the parent to remain in the pre-funding phase forever.
use super::commit_context_v23::Context;
use super::*;

/// Process-only ingress scope issued by the owning Store after reconstruction.
pub struct PreparedXmrGraphCommitIngressV23 {
    store: [u8; 32],
    open_instance: [u8; 32],
    chain: TrustedChainIdV1,
    route: [u8; 32],
    session: [u8; 32],
    context: [u8; 32],
}
impl PreparedXmrGraphCommitIngressV23 {
    /// Exact parent session authenticated by this Store-owned ingress.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session
    }
}

impl ContractsSessionStoreV1 {
    /// Reauthenticate retained graph ancestry and issue an opening-bound ingress.
    pub fn prepare_xmr_graph_commit_ingress_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<PreparedXmrGraphCommitIngressV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        let context = self.authenticate_graph_commit_context_issuance_v23(chain, route, session)?;
        if self.audit_historical_xmr_graph_proposal_v23(chain, route, session)?
            != context.bindings[5]
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(PreparedXmrGraphCommitIngressV23 {
            store: self._store_id,
            open_instance: self.open_instance_id,
            chain,
            route,
            session,
            context: context.digest(),
        })
    }

    /// Accept a signed graph agreement through the exact retained ingress handle.
    pub fn accept_xmr_graph_commit_ingress_v23(
        &self,
        prepared: &PreparedXmrGraphCommitIngressV23,
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        {
            let _guard = self.operation_lock()?;
            let context = self.load_xmr_graph_commit_context_v23(prepared.session)?;
            if prepared.store != self._store_id
                || prepared.open_instance != self.open_instance_id
                || prepared.context != context.digest()
            {
                return Err(SessionStoreError::Conflict);
            }
        }
        // Dedicated ingress reauthenticates the immutable context under its lock.
        self.accept_prepared_xmr_graph_commit_transport_message_v23(
            prepared.chain,
            prepared.route,
            prepared.session,
            signed_bytes,
        )
    }

    /// Persist the next local identity-signing request for graph agreement.
    /// Sender, sequence, predecessor and payload all come from retained state.
    /// A peer turn or completed two-message prefix returns None without issuing
    /// anything. The identity Store must consume/sign/commit the returned
    /// request before any signed envelope may be exported.
    pub fn prepare_xmr_graph_commit_dsc1_signing_request_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let context = self.authenticate_graph_commit_context_issuance_v23(chain, route, session)?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        let position = self.audit_xmr_graph_commit_prefix_v23(session, &current, &roster, None)?;
        if position == 2 {
            return Ok(None);
        }
        // A remote turn is a wait only while this prefix is still live; do not
        // hide a terminal transition behind None merely because the peer is next.
        let expected_phase = if position == 0 {
            SessionPhaseV1::OutputFinalized
        } else {
            SessionPhaseV1::TemplatesCommitted
        };
        if current.irreversible().funding_authorized
            || current.phase() != expected_phase
            || current.revision()
                != context
                    .revision
                    .checked_add(position as u64)
                    .ok_or(SessionStoreError::CapacityExceeded)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let participant = roster
            .participants
            .get(position)
            .ok_or(SessionStoreError::InvalidTransition)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if signer.participant_id != participant.participant_id {
            return Ok(None);
        }
        self.require_live_graph_commit_reconstruction_v23(chain, route, session, &context)?;
        let sequence = self.transport_sequence_at_revision(
            session,
            participant.participant_id,
            context.revision,
        )?;
        let candidate = outbound_dsc1_candidate_bytes(&OutboundDsc1UnsignedFieldsV1 {
            message_type: 0x18,
            chain_id: *chain.as_bytes(),
            session_id: session,
            sender_id: participant.participant_id,
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            payload: &context.bindings[5],
        })?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_xmr_graph_commit_message_v23(
            session, &current, &roster, &envelope, &candidate, None,
        )?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::XmrGraphCommitV23,
            chain_id: *chain.as_bytes(),
            session_id: session,
            sender_id: participant.participant_id,
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            predecessor: &current,
            authority_digest: context.digest(),
            payload: &context.bindings[5],
        })
        .map(Some)
    }

    /// Dedicated ingress for a graph commitment. No caller supplies a successor
    /// phase, transcript or proposal digest. Exact replay and authenticated
    /// equivocation are processed against the durable logical message key
    /// before the live reconstruction gate, including after parent progression.
    pub fn accept_prepared_xmr_graph_commit_transport_message_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let context = self.authenticate_graph_commit_context_issuance_v23(chain, route, session)?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.message_type != 0x18
            || envelope.chain_id != *chain.as_bytes()
            || envelope.session_id != session
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let participant = roster
            .participants
            .iter()
            .find(|participant| participant.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        // Never allow unverified bytes to trigger the equivocation successor.
        envelope.verify(&participant.identity_key)?;
        let current = self.load_session_locked(session)?;
        let name = transport_message_name(session, envelope.sender_id, envelope.sequence, false);
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
        self.require_live_graph_commit_reconstruction_v23(chain, route, session, &context)?;
        let phase = self.require_next_xmr_graph_commit_message_v23(
            session,
            &current,
            &roster,
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
        let successor = current.advance(
            current.revision(),
            phase,
            transcript,
            current.irreversible(),
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

    // Historical context authentication: do not add a live phase gate here.
    fn authenticate_graph_commit_context_issuance_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<Context, SessionStoreError> {
        self.audit_xmr_graph_commit_context_v23(session)?;
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        if context.chain != *chain.as_bytes()
            || context.route != route
            || context.session != session
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(context)
    }

    fn require_live_graph_commit_reconstruction_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
        context: &Context,
    ) -> Result<(), SessionStoreError> {
        let reconstructed = self.reconstruct_xmr_graph_under_lock_v23(chain, route, session)?;
        let keys = &reconstructed.1;
        let proposal = keys.proposal().map_err(|_| SessionStoreError::Conflict)?;
        if proposal.digest() != context.bindings[5] {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }
}
