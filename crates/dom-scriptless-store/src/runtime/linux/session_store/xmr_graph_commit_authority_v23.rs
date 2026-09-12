//! Authenticators for Store-issued identity requests and historical successors.
use super::*;

impl ContractsSessionStoreV1 {
    pub(in super::super) fn require_static_graph_commit_request_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
    ) -> Result<(), SessionStoreError> {
        self.audit_xmr_graph_commit_context_v23(request.session_id)?;
        let context = self.load_xmr_graph_commit_context_v23(request.session_id)?;
        let chain = self.require_process_trusted_chain_v23(&context.chain)?;
        if request.authority_class != OutboundDsc1AuthorityClassV1::XmrGraphCommitV23
            || request.chain_id != context.chain
            || request.authority_digest != context.digest()
            || request.payload.as_slice() != context.bindings[5]
            || self.audit_historical_xmr_graph_proposal_v23(
                chain,
                context.route,
                request.session_id,
            )? != context.bindings[5]
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    pub(in super::super) fn expected_graph_commit_request_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<([u8; 32], u64, [u8; 32]), SessionStoreError> {
        // The owning dispatcher has already authenticated the static request.
        let roster = self.load_transport_roster(request.session_id)?;
        let candidate = self.outbound_dsc1_request_candidate_bytes(request)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
        self.require_next_xmr_graph_commit_message_v23(
            request.session_id,
            current,
            &roster,
            &envelope,
            &candidate,
            None,
        )?;
        Ok((
            request.sender_id,
            request.sequence,
            current.transcript_hash(),
        ))
    }

    pub(in super::super) fn require_graph_commit_successor_v23(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        let session = current.session_id();
        self.audit_xmr_graph_commit_context_v23(session)?;
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        let chain = self.require_process_trusted_chain_v23(&context.chain)?;
        if self.audit_historical_xmr_graph_proposal_v23(chain, context.route, session)?
            != context.bindings[5]
        {
            return Err(SessionStoreError::Conflict);
        }
        let roster = self.load_transport_roster(session)?;
        let phase = self.require_next_xmr_graph_commit_message_v23(
            session,
            current,
            &roster,
            envelope,
            signed_bytes,
            recovery_scope,
        )?;
        if successor.phase() != phase
            || successor.irreversible() != current.irreversible()
            || successor.chain() != current.chain()
            || successor.encrypted_payload() != current.encrypted_payload()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        require_transport_successor(current, envelope, direction, successor)
    }
}
