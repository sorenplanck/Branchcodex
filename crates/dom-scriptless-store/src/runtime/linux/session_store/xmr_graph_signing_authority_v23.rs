//! Distinct authority dispatch for graph-origin nonce and partial messages.
use super::signing_session_v23::GraphSigningSessionBindingV23;
use super::*;

impl ContractsSessionStoreV1 {
    // A target has exactly one graph origin for this purpose. Never fall back
    // to a legacy binding after seeing an inconsistent graph descriptor.
    pub(in super::super) fn graph_signing_edge_for_purpose_v23(
        &self,
        session: [u8; 32],
        purpose: PurposeV1,
    ) -> Result<Option<XmrGraphRecoverySigningEdgeV23>, SessionStoreError> {
        use XmrGraphRecoverySigningEdgeV23 as Edge;
        let candidates: &[Edge] = match purpose {
            PurposeV1::Refund => &[Edge::Cancel, Edge::Compensation],
            PurposeV1::RefundAdaptor => &[Edge::RefundAdaptor],
            _ => return Ok(None),
        };
        let mut selected = None;
        for &edge in candidates {
            let name = format!(
                "{}-{:02x}.xmr-graph-signing-session-v23",
                hex_lower(&session),
                edge as u8
            );
            match self
                .rosters
                .read_bounded_file(&ValidatedComponent::registered(&name)?, 264)
            {
                Ok(_) => {
                    if selected.replace(edge).is_some() {
                        return Err(SessionStoreError::Conflict);
                    }
                }
                Err(LinuxCapabilityError::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(selected)
    }

    pub(in super::super) fn authenticate_graph_signing_request_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
    ) -> Result<GraphSigningSessionBindingV23, SessionStoreError> {
        let purpose = signing_payload_purpose(request.message_type, &request.payload)?;
        let edge = self
            .graph_signing_edge_for_purpose_v23(request.session_id, purpose)?
            .ok_or(SessionStoreError::InvalidTransition)?;
        let binding = self.authenticate_xmr_graph_signing_session_v23(request.session_id, edge)?;
        if request.authority_digest != binding.digest
            || request.chain_id != *binding.origin.chain.as_bytes()
            || purpose != binding.origin.purpose
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        // Static authentication includes the exact historical predecessor and
        // candidate semantics, not just a rehashable descriptor comparison.
        let predecessor =
            self.load_session_revision(request.session_id, request.predecessor_revision)?;
        let candidate = self.outbound_dsc1_request_candidate_bytes(request)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_graph_signing_message_v23(
            &binding,
            &predecessor,
            &envelope,
            &candidate,
            None,
        )?;
        Ok(binding)
    }

    pub(in super::super) fn require_graph_signing_request_transition_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let binding = self.authenticate_graph_signing_request_v23(request)?;
        self.require_next_graph_signing_message_v23(&binding, current, envelope, bytes, None)
    }

    pub(in super::super) fn expected_graph_signing_request_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<([u8; 32], u64, [u8; 32]), SessionStoreError> {
        let binding = self.authenticate_graph_signing_request_v23(request)?;
        let candidate = self.outbound_dsc1_request_candidate_bytes(request)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_graph_signing_message_v23(
            &binding, current, &envelope, &candidate, None,
        )?;
        Ok((
            request.sender_id,
            request.sequence,
            current.transcript_hash(),
        ))
    }

    pub(in super::super) fn require_graph_signing_successor_v23(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        edge: XmrGraphRecoverySigningEdgeV23,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        let binding =
            self.authenticate_xmr_graph_signing_session_v23(current.session_id(), edge)?;
        let phase = self.require_next_graph_signing_message_v23(
            &binding,
            current,
            envelope,
            signed_bytes,
            recovery_scope,
        )?;
        let mut expected_flags = current.irreversible();
        if envelope.message_type == 0x0e {
            expected_flags.any_signing_share_sent = true;
        }
        if successor.phase() != phase
            || successor.irreversible() != expected_flags
            || successor.chain() != current.chain()
            || successor.encrypted_payload() != current.encrypted_payload()
            || successor.transcript_hash()
                != accepted_transport_transcript_hash(
                    &current.transcript_hash(),
                    &envelope.message_digest,
                    direction,
                    envelope.message_type,
                    phase,
                )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        // Created -> RefundSigning is a graph-only edge, never added to the
        // legacy transition table. Exact native successor remains mandatory.
        require_exact_successor(current, current.revision(), successor)
    }
}
