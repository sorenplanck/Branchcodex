//! Graph-origin signing replay. No synthetic early/BP/template-commit records.
use super::public_signing_semantics_cache_v25::{verify_v25, PublicSigningScopeV25};
use super::signing_origin_v23::ReconstructedXmrGraphSigningOriginV23;
use super::signing_session_v23::GraphSigningSessionBindingV23;
use super::*;

struct GraphSemanticBindingV23<'a> {
    origin: &'a ReconstructedXmrGraphSigningOriginV23,
    template_hash: [u8; 32],
}

impl SigningSemanticBindingAccessV1 for GraphSemanticBindingV23<'_> {
    fn participant_count(&self) -> usize {
        self.origin.roster.entries().len()
    }
    fn participant(&self, index: usize) -> Option<SigningSemanticParticipantRefV1<'_>> {
        self.origin
            .roster
            .entries()
            .get(index)
            .map(|entry| SigningSemanticParticipantRefV1 {
                participant_id: entry.participant_id(),
                signing_public_key: entry.signing_public_key(),
                direction: entry.direction(),
            })
    }
    fn transaction_template(&self) -> &Transaction {
        &self.origin.template
    }
    fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }
    fn kernel_index(&self) -> usize {
        0
    }
    fn adaptor_point(&self) -> Option<&PublicKey> {
        self.origin.adaptor.as_ref()
    }
}

pub(super) struct GraphSigningRoundAuditV23 {
    pub(super) accepted_messages: Vec<Vec<u8>>,
    pub(super) terminal_transcript: [u8; 32],
    pub(super) plain_signature: Option<SchnorrSignature>,
}

impl ContractsSessionStoreV1 {
    // Binding has already been authenticated against the complete retained graph.
    // Authenticate every real identity envelope and durable successor as well.
    pub(super) fn audit_xmr_graph_signing_round_v23(
        &self,
        binding: &GraphSigningSessionBindingV23,
    ) -> Result<GraphSigningRoundAuditV23, SessionStoreError> {
        let current = self.load_session_locked(binding.origin.session)?;
        self.audit_xmr_graph_signing_round_at_v23(binding, &current, None)
    }

    pub(super) fn audit_xmr_graph_signing_round_at_v23(
        &self,
        binding: &GraphSigningSessionBindingV23,
        current: &SessionRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<GraphSigningRoundAuditV23, SessionStoreError> {
        let origin = &binding.origin;
        let start = self.load_session_revision(origin.session, binding.start.revision())?;
        if start.digest() != binding.start.digest()
            || start.transcript_hash() != binding.start.transcript_hash()
            || current.revision() < binding.start.revision()
            || !matches!(origin.purpose, PurposeV1::Refund | PurposeV1::RefundAdaptor)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let end = binding
            .start
            .revision()
            .checked_add(6)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let prefix = format!("{}-", hex_lower(&origin.session));
        let mut records = Vec::new();
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
            records.push((name.to_owned(), record));
            Ok(())
        })?;
        let mut round = Vec::new();
        for (name, record) in records {
            let (envelope, direction) = self.authenticate_transport_record(&name, &record)?;
            if record.equivocation {
                return Err(SessionStoreError::Quarantined);
            }
            let revision = record.successor.revision();
            if revision > current.revision()
                && recovery_scope.is_some_and(|scope| scope.is_exact_pending_record(&name, &record))
            {
                continue;
            }
            let durable = self.load_session_revision(origin.session, revision)?;
            if durable.as_bytes() != record.successor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            if revision > current.revision() || revision <= binding.start.revision() {
                continue;
            }
            if revision > end {
                if (0x0c..=0x0e).contains(&envelope.message_type)
                    && signing_payload_purpose(
                        envelope.message_type,
                        envelope.payload(&record.signed_bytes)?,
                    )? == origin.purpose
                {
                    return Err(SessionStoreError::Quarantined);
                }
                continue;
            }
            if !(0x0c..=0x0e).contains(&envelope.message_type)
                || signing_payload_purpose(
                    envelope.message_type,
                    envelope.payload(&record.signed_bytes)?,
                )? != origin.purpose
            {
                return Err(SessionStoreError::Quarantined);
            }
            round.push((revision, record, envelope, direction));
        }
        round.sort_by_key(|entry| entry.0);
        let expected_count = (current.revision() - binding.start.revision()).min(6) as usize;
        if round.len() != expected_count {
            return Err(SessionStoreError::Quarantined);
        }
        let mut predecessor = start;
        let mut accepted_messages = Vec::with_capacity(round.len());
        let mut reveal_transcript = None;
        for (index, (revision, record, envelope, direction)) in round.into_iter().enumerate() {
            let mut expected_flags = predecessor.irreversible();
            if envelope.message_type == 0x0e {
                expected_flags.any_signing_share_sent = true;
            }
            if revision != binding.start.revision() + index as u64 + 1
                || record.successor.phase() != SessionPhaseV1::RefundSigning
                || record.successor.irreversible() != expected_flags
                || record.successor.chain() != predecessor.chain()
                || record.successor.encrypted_payload() != predecessor.encrypted_payload()
            {
                return Err(SessionStoreError::Quarantined);
            }
            require_exact_successor(&predecessor, predecessor.revision(), &record.successor)?;
            let transcript = accepted_transport_transcript_hash(
                &predecessor.transcript_hash(),
                &envelope.message_digest,
                direction,
                envelope.message_type,
                SessionPhaseV1::RefundSigning,
            )?;
            if record.successor.transcript_hash() != transcript {
                return Err(SessionStoreError::Quarantined);
            }
            if index == 3 {
                reveal_transcript = Some(transcript);
            }
            accepted_messages.push(record.signed_bytes);
            predecessor = record.successor;
        }
        let (_, template_hash) = canonical_template_v1(&origin.template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let plain_signature = verify_v25(
            PublicSigningScopeV25::graph(
                origin.route,
                origin.parent,
                origin.terms,
                origin.input_session,
                origin.digest,
                binding.digest,
                *binding.start.digest(),
            ),
            origin.chain.as_bytes(),
            origin.session,
            origin.purpose,
            &GraphSemanticBindingV23 {
                origin,
                template_hash,
            },
            &SigningRoundSemanticViewV23 {
                round_start_transcript_hash: binding.start.transcript_hash(),
                sender_sequence_bases: binding.sender_sequence_bases,
                accepted_messages: &accepted_messages,
                terminal_transcript_hash: predecessor.transcript_hash(),
                reveal_transcript_hash: reveal_transcript,
            },
        )?;
        Ok(GraphSigningRoundAuditV23 {
            accepted_messages,
            terminal_transcript: predecessor.transcript_hash(),
            plain_signature,
        })
    }

    pub(super) fn require_next_graph_signing_message_v23(
        &self,
        binding: &GraphSigningSessionBindingV23,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let origin = &binding.origin;
        let round = self.audit_xmr_graph_signing_round_at_v23(binding, current, recovery_scope)?;
        let position = round.accepted_messages.len();
        let phase = if position == 0 {
            binding.start.phase()
        } else {
            SessionPhaseV1::RefundSigning
        };
        if position >= 6
            || current.phase() != phase
            || current.session_id() != origin.session
            || current.revision() != binding.start.revision() + position as u64
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || envelope.message_type != 0x0c + (position / 2) as u8
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let mut accepted = round.accepted_messages;
        accepted.push(signed_bytes.to_vec());
        let mut transcript = binding.start.transcript_hash();
        let mut reveal = None;
        for (index, bytes) in accepted.iter().enumerate() {
            let item = ParsedTransportEnvelopeV1::parse(bytes)?;
            let participant = &origin.roster.entries()[index % 2];
            transcript = advance_transcript_hash_v1(
                &transcript,
                &item.message_digest,
                participant.direction(),
                signing_phase_for_message(item.message_type).ok_or(SessionStoreError::Canonical)?,
            );
            if index == 3 {
                reveal = Some(transcript);
            }
        }
        let (_, template_hash) = canonical_template_v1(&origin.template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        verify_v25(
            PublicSigningScopeV25::graph(
                origin.route,
                origin.parent,
                origin.terms,
                origin.input_session,
                origin.digest,
                binding.digest,
                *binding.start.digest(),
            ),
            origin.chain.as_bytes(),
            origin.session,
            origin.purpose,
            &GraphSemanticBindingV23 {
                origin,
                template_hash,
            },
            &SigningRoundSemanticViewV23 {
                round_start_transcript_hash: binding.start.transcript_hash(),
                sender_sequence_bases: binding.sender_sequence_bases,
                accepted_messages: &accepted,
                terminal_transcript_hash: transcript,
                reveal_transcript_hash: reveal,
            },
        )?;
        Ok(SessionPhaseV1::RefundSigning)
    }

    /// Reissue the real native signing handle from graph ancestry and signed replay.
    pub fn resume_xmr_graph_signing_session_v23(
        &self,
        session: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let binding = self.authenticate_xmr_graph_signing_session_v23(session, edge)?;
        let current = self.load_session_locked(session)?;
        if current.irreversible().funding_authorized
            || !matches!(
                current.phase(),
                SessionPhaseV1::Created
                    | SessionPhaseV1::TemplatesCommitted
                    | SessionPhaseV1::RefundSigning
            )
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let round = self.audit_xmr_graph_signing_round_v23(&binding)?;
        let origin = binding.origin;
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id: origin.chain,
            session_id: session,
            contract_kind: ContractKindV1::WitnessOrTimeout,
            purpose: origin.purpose,
            roster: origin.roster,
            transaction_template: origin.template,
            kernel_index: 0,
            adaptor_point: origin.adaptor,
            initial_transcript_hash: binding.initial_transcript_hash,
            round_start_transcript_hash: binding.start.transcript_hash(),
            sender_sequence_bases: binding.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: binding.start.revision(),
            _session_record_digest: *binding.start.digest(),
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: None,
        })
    }
}
