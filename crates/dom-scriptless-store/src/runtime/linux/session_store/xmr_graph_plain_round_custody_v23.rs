//! Custody proof for the two ordinary GraphV23 recovery signatures. The six
//! authenticated signing messages are terminal here: no synthetic 0x10 record,
//! RefundSigned transition, funding gate or adaptor-secret exposure is created.
use super::*;

impl ContractsSessionStoreV1 {
    /// Caller holds the Store operation lock. This is a historical audit, not
    /// a capability constructor for signing or funding.
    pub(in super::super) fn audit_graph_plain_auxiliary_round_v23(
        &self,
        parent_roster: &TransportRosterRecordV1,
        session: [u8; 32],
        expected_signed_tx: &[u8],
    ) -> Result<[u8; 32], SessionStoreError> {
        if session == [0; 32] || session == parent_roster.session_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        // Select only an existing, uniquely named native binding. A corrupt
        // GraphV23 binding must never fall back to legacy final-refund custody.
        let mut selected = None;
        self.rosters.scan_lexicographic(|name, node| {
            let Some((target, edge)) = parse_xmr_graph_signing_session_name_v23(name) else {
                return Ok(());
            };
            if target != session {
                return Ok(());
            }
            if node.node_type != ExpectedNodeType::RegularFile
                || !matches!(
                    edge,
                    XmrGraphRecoverySigningEdgeV23::Cancel
                        | XmrGraphRecoverySigningEdgeV23::Compensation
                )
                || selected.replace(edge).is_some()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            Ok(())
        })?;
        let edge = selected.ok_or(SessionStoreError::SessionNotFound)?;
        let binding = self.authenticate_xmr_graph_signing_session_v23(session, edge)?;
        let origin = &binding.origin;
        let parent = self.load_transport_roster(parent_roster.session_id)?;
        let parent_head = self.load_session_locked(parent_roster.session_id)?;
        let context = self.load_xmr_graph_commit_context_v23(parent_roster.session_id)?;
        let roster = self.load_transport_roster(session)?;
        if parent.bytes != parent_roster.bytes
            || origin.parent != parent_roster.session_id
            || origin.session != session
            || origin.chain.as_bytes() != &parent_roster.chain_id
            || origin.terms != parent_head.terms_hash()
            || origin.route != context.route
            || origin.terms != context.terms
            || origin.purpose != PurposeV1::Refund
            || origin.adaptor.is_some()
            || roster.chain_id != parent_roster.chain_id
            || roster.participants != parent_roster.participants
        {
            return Err(SessionStoreError::Quarantined);
        }
        let head = self.load_session_locked(session)?;
        if head.revision()
            != binding
                .start
                .revision()
                .checked_add(6)
                .ok_or(SessionStoreError::CapacityExceeded)?
            || head.phase() != SessionPhaseV1::RefundSigning
            || head.terms_hash() != origin.terms
            || !head.irreversible().any_signing_share_sent
            || head.irreversible().funding_authorized
            || head.irreversible().adaptor_secret_exposed
            || self.funding_gate_exists(session)?
            || self.m8_funding_gate_v2_exists(session)?
            || self.m8_funding_gate_exists(session)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let round = self.audit_xmr_graph_signing_round_v23(&binding)?;
        if round.accepted_messages.len() != 6 || round.terminal_transcript != head.transcript_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let signature = round
            .plain_signature
            .ok_or(SessionStoreError::Quarantined)?;
        let mut signed = origin.template.clone();
        if signed.kernels.len() != 1 || signed.kernels[0].excess_signature != [0; 65] {
            return Err(SessionStoreError::Quarantined);
        }
        signed.kernels[0].excess_signature = signature.to_bytes();
        let bytes = canonical_dom_transaction_bytes_v1(&signed)?;
        if bytes != expected_signed_tx {
            return Err(SessionStoreError::Quarantined);
        }
        let mut material = Vec::with_capacity(129 + bytes.len());
        material.push(edge as u8);
        material.extend_from_slice(&binding.digest);
        material.extend_from_slice(head.digest());
        material.extend_from_slice(&round.terminal_transcript);
        material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        material.extend_from_slice(&bytes);
        Ok(tagged_hash(
            "DOM:xmr-graph-plain-round-custody:v23",
            &material,
        ))
    }
}
