//! Native two-message graph commitment prefix. This is transport validation,
//! not graph signing admission or a funding/readiness grant.
use super::commit_context_v23::Context;
use super::*;

impl ContractsSessionStoreV1 {
    /// Audit actual signed records from the frozen revision through at most
    /// two graph commitments. Caller owns the operation lock and authenticates
    /// the frozen context/evidence independently; no full transport audit is
    /// invoked here, so this can be used while replaying a pending record.
    pub(in super::super) fn audit_xmr_graph_commit_prefix_v23(
        &self,
        session: [u8; 32],
        current: &SessionRecordV1,
        roster: &TransportRosterRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<usize, SessionStoreError> {
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        self.audit_graph_commit_prefix_from_context_v23(&context, current, roster, recovery_scope)
    }

    fn audit_graph_commit_prefix_from_context_v23(
        &self,
        context: &Context,
        current: &SessionRecordV1,
        roster: &TransportRosterRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<usize, SessionStoreError> {
        let session = context.session;
        require_graph_commit_participants_v23(roster)?;
        if current.session_id() != session
            || current.terms_hash() != context.terms
            || roster.session_id != session
            || roster.chain_id != context.chain
            || current.revision() < context.revision
        {
            return Err(SessionStoreError::Quarantined);
        }
        let end = context
            .revision
            .checked_add(2)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let prefix = format!("{}-", hex_lower(&session));
        let mut retained = Vec::new();
        self.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = self.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            retained.push((name.to_owned(), record));
            Ok(())
        })?;
        let mut records = Vec::new();
        for (name, record) in retained {
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            if envelope.session_id != session || record.equivocation {
                return Err(SessionStoreError::Quarantined);
            }
            let revision = record.successor.revision();
            // A third, premature or displaced graph commitment is never an
            // unrelated historical message, including during crash recovery.
            if envelope.message_type == 0x18 && !(context.revision < revision && revision <= end) {
                return Err(SessionStoreError::Quarantined);
            }
            if revision > current.revision()
                && recovery_scope.is_some_and(|scope| scope.is_exact_pending_record(&name, &record))
            {
                continue;
            }
            if revision > current.revision() {
                match self.load_session_revision(session, revision) {
                    Ok(durable) if durable.as_bytes() == record.successor.as_bytes() => {}
                    Err(SessionStoreError::SessionNotFound)
                        if revision
                            == current
                                .revision()
                                .checked_add(1)
                                .ok_or(SessionStoreError::Quarantined)? => {}
                    _ => return Err(SessionStoreError::Quarantined),
                }
                continue;
            }
            let durable = self.load_session_revision(session, revision)?;
            if durable.as_bytes() != record.successor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            if context.revision < revision && revision <= end {
                if envelope.message_type != 0x18 {
                    return Err(SessionStoreError::Quarantined);
                }
                records.push((revision, record, envelope, direction));
            }
        }
        records.sort_by_key(|(revision, _, _, _)| *revision);
        require_graph_commit_prefix_shape_v23(
            context.revision,
            current.revision(),
            current.phase(),
            &records.iter().map(|record| record.0).collect::<Vec<_>>(),
        )?;
        for (position, (revision, record, envelope, direction)) in records.iter().enumerate() {
            let expected_revision = context
                .revision
                .checked_add(position as u64 + 1)
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let participant = roster
                .participants
                .get(position)
                .ok_or(SessionStoreError::Quarantined)?;
            let sequence = self.transport_sequence_at_revision(
                session,
                participant.participant_id,
                context.revision,
            )?;
            let predecessor = self.load_session_revision(session, expected_revision - 1)?;
            if *revision != expected_revision
                || envelope.chain_id != context.chain
                || envelope.sender_id != participant.participant_id
                || envelope.sequence != sequence
                || *direction != participant.direction
                || envelope.payload(&record.signed_bytes)? != context.bindings[5]
                || record.successor.phase() != SessionPhaseV1::TemplatesCommitted
            {
                return Err(SessionStoreError::Quarantined);
            }
            require_transport_successor(&predecessor, envelope, *direction, &record.successor)
                .map_err(|_| SessionStoreError::Quarantined)?;
        }
        Ok(records.len())
    }

    /// Validate the next candidate before durable identity signing or ingress.
    /// Signature verification remains with the prepared ingress/commit owner;
    /// candidates here may still be unsigned. No caller-provided phase is used.
    pub(in super::super) fn require_next_xmr_graph_commit_message_v23(
        &self,
        session: [u8; 32],
        current: &SessionRecordV1,
        roster: &TransportRosterRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        if current.irreversible().funding_authorized
            || envelope.chain_id != context.chain
            || envelope.session_id != session
            || envelope.previous_transcript_hash != current.transcript_hash()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let position = self.audit_graph_commit_prefix_from_context_v23(
            &context,
            current,
            roster,
            recovery_scope,
        )?;
        let participant = roster
            .participants
            .get(position)
            .ok_or(SessionStoreError::InvalidTransition)?;
        let phase = if position == 0 {
            SessionPhaseV1::OutputFinalized
        } else {
            SessionPhaseV1::TemplatesCommitted
        };
        let sequence = self.transport_sequence_at_revision(
            session,
            participant.participant_id,
            context.revision,
        )?;
        if position >= 2
            || current.revision()
                != context
                    .revision
                    .checked_add(position as u64)
                    .ok_or(SessionStoreError::CapacityExceeded)?
            || current.phase() != phase
            || envelope.message_type != 0x18
            || envelope.sender_id != participant.participant_id
            || envelope.sequence != sequence
            || envelope.payload(signed_bytes)? != context.bindings[5]
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(SessionPhaseV1::TemplatesCommitted)
    }
}

/// The graph agreement has exactly two different identity owners. These are
/// transport-role order, NOT lexicographic signing-key order.
fn require_graph_commit_participants_v23(
    roster: &TransportRosterRecordV1,
) -> Result<(), SessionStoreError> {
    let [first, second] = &roster.participants;
    if first.participant_id == [0; 32]
        || second.participant_id == [0; 32]
        || first.participant_id == second.participant_id
        || first.identity_key == second.identity_key
        || first.direction != DirectionV1::Initiator
        || second.direction != DirectionV1::Responder
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

/// Only shape: the caller must still authenticate every envelope and successor.
/// FailedClosed may interrupt the prefix, but can never invent another commit.
fn require_graph_commit_prefix_shape_v23(
    start: u64,
    head: u64,
    phase: SessionPhaseV1,
    revisions: &[u64],
) -> Result<(), SessionStoreError> {
    let end = start
        .checked_add(2)
        .ok_or(SessionStoreError::CapacityExceeded)?;
    let visible = head
        .checked_sub(start)
        .ok_or(SessionStoreError::Quarantined)?
        .min(2) as usize;
    if revisions.len() > visible
        || revisions
            .iter()
            .enumerate()
            .any(|(index, revision)| start.checked_add(index as u64 + 1) != Some(*revision))
        || (phase != SessionPhaseV1::FailedClosed && revisions.len() != visible)
    {
        return Err(SessionStoreError::Quarantined);
    }
    if phase != SessionPhaseV1::FailedClosed && head <= end {
        let expected = if visible == 0 {
            SessionPhaseV1::OutputFinalized
        } else {
            SessionPhaseV1::TemplatesCommitted
        };
        if phase != expected {
            return Err(SessionStoreError::Quarantined);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::SecretKey;

    #[test]
    fn v23_graph_commit_prefix_requires_two_distinct_identity_owners(
    ) -> Result<(), SessionStoreError> {
        // Public roster validation only: no Store/journal/signature is created.
        let first_key = SecretKey::from_bytes(&[31; 32])
            .map_err(|_| SessionStoreError::Canonical)?
            .public_key();
        let second_key = SecretKey::from_bytes(&[32; 32])
            .map_err(|_| SessionStoreError::Canonical)?
            .public_key();
        let make = |ids: [[u8; 32]; 2], same_key: bool, roles: [DirectionV1; 2]| {
            TransportRosterRecordV1::new(
                [1; 32],
                [2; 32],
                [
                    SessionTransportParticipantV1 {
                        participant_id: ids[0],
                        identity_key: first_key.clone(),
                        direction: roles[0],
                    },
                    SessionTransportParticipantV1 {
                        participant_id: ids[1],
                        identity_key: if same_key {
                            first_key.clone()
                        } else {
                            second_key.clone()
                        },
                        direction: roles[1],
                    },
                ],
            )
        };
        let roles = [DirectionV1::Initiator, DirectionV1::Responder];
        // The IDs need not be lexicographically ordered in transport-role order.
        for ids in [[[3; 32], [4; 32]], [[4; 32], [3; 32]]] {
            require_graph_commit_participants_v23(&make(ids, false, roles))?;
        }
        for ids in [[[3; 32], [3; 32]], [[0; 32], [4; 32]], [[3; 32], [0; 32]]] {
            assert!(require_graph_commit_participants_v23(&make(ids, false, roles)).is_err());
        }
        assert!(
            require_graph_commit_participants_v23(&make([[3; 32], [4; 32]], true, roles)).is_err()
        );
        for wrong in [
            [DirectionV1::Initiator, DirectionV1::Initiator],
            [DirectionV1::Responder, DirectionV1::Responder],
            [DirectionV1::Responder, DirectionV1::Initiator],
        ] {
            assert!(
                require_graph_commit_participants_v23(&make([[3; 32], [4; 32]], false, wrong))
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn v23_graph_commit_prefix_shape_distinguishes_partial_replay_from_agreement(
    ) -> Result<(), SessionStoreError> {
        use SessionPhaseV1::{FailedClosed, OutputFinalized, RefundSigning, TemplatesCommitted};
        // This tests the exact shape helper used after storage authentication.
        // It is not evidence of a real crash replay or bilateral signatures.
        require_graph_commit_prefix_shape_v23(17, 17, OutputFinalized, &[])?;
        require_graph_commit_prefix_shape_v23(17, 18, TemplatesCommitted, &[18])?;
        require_graph_commit_prefix_shape_v23(17, 19, TemplatesCommitted, &[18, 19])?;
        require_graph_commit_prefix_shape_v23(17, 20, RefundSigning, &[18, 19])?;
        for (head, phase, records) in [
            (16, OutputFinalized, vec![]),
            (17, TemplatesCommitted, vec![]),
            (17, OutputFinalized, vec![18]),
            (18, TemplatesCommitted, vec![]),
            (18, OutputFinalized, vec![18]),
            (18, TemplatesCommitted, vec![18, 19]),
            (19, TemplatesCommitted, vec![18]),
            (19, TemplatesCommitted, vec![19]),
            (19, TemplatesCommitted, vec![18, 18]),
            (19, TemplatesCommitted, vec![19, 18]),
            (19, TemplatesCommitted, vec![18, 20]),
            (20, RefundSigning, vec![18, 19, 20]),
        ] {
            assert!(require_graph_commit_prefix_shape_v23(17, head, phase, &records).is_err());
        }
        require_graph_commit_prefix_shape_v23(17, 18, FailedClosed, &[])?;
        require_graph_commit_prefix_shape_v23(17, 19, FailedClosed, &[18])?;
        assert!(require_graph_commit_prefix_shape_v23(17, 18, FailedClosed, &[19]).is_err());
        assert!(require_graph_commit_prefix_shape_v23(17, 18, FailedClosed, &[18, 19]).is_err());
        assert!(
            require_graph_commit_prefix_shape_v23(u64::MAX, u64::MAX, FailedClosed, &[]).is_err()
        );
        Ok(())
    }
}
