//! Graph-origin signing replay. No synthetic early/BP/template-commit records.
use super::*;
use xmr_graph_proposal_v22::public_signing_semantics_cache_v25::{
    verify_v25, PublicSigningScopeV25,
};
#[path = "f7_xmr_funding_transport_v23.rs"]
mod transport_v23;
#[path = "f7_xmr_funding_vault_v23.rs"]
mod vault_provisioning_v23;
pub(in super::super) use vault_provisioning_v23::parse_xmr_funding_vault_name_v23;
pub use vault_provisioning_v23::{
    PreparedXmrFundingVaultProvisioningV23, XmrFundingVaultProvisioningStateV23,
};

pub(super) struct NativeXmrFundingOriginV23 {
    chain: TrustedChainIdV1,
    session: [u8; 32],
    purpose: PurposeV1,
    roster: ParticipantRosterV1,
    template: Transaction,
    adaptor: Option<PublicKey>,
}
pub(super) struct NativeXmrFundingBindingV23 {
    origin: NativeXmrFundingOriginV23,
    start: SessionRecordV1,
    sender_sequence_bases: [u64; 2],
    digest: [u8; 32],
}

struct FundingSemanticBindingV23<'a> {
    origin: &'a NativeXmrFundingOriginV23,
    template_hash: [u8; 32],
}

impl SigningSemanticBindingAccessV1 for FundingSemanticBindingV23<'_> {
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

pub(super) struct NativeXmrFundingRoundV23 {
    pub(super) accepted_messages: Vec<Vec<u8>>,
    pub(super) terminal_transcript: [u8; 32],
    pub(super) plain_signature: Option<SchnorrSignature>,
}

impl ContractsSessionStoreV1 {
    pub(super) fn reconstruct_xmr_bounded_funding_roster_v23(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<(TrustedChainIdV1, ParticipantRosterV1, Transaction), SessionStoreError> {
        use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22;

        let chain = self.require_process_trusted_chain_v23(&gate.chain_id)?;
        let reconstructed = self.reconstruct_xmr_graph_evidence_core_v23(
            chain,
            gate.role.route_id(),
            gate.session_id,
            false,
        )?;
        let (templates, keys) = (&reconstructed.0, &reconstructed.1);
        keys.require_graph(templates)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let hash = keys.template_hash(XmrGraphSigningStageV22::Funding);
        if hash != gate.role.funding_template_hash() {
            return Err(SessionStoreError::Quarantined);
        }
        let transport = self.load_transport_roster(gate.session_id)?;
        let identities = self.load_transport_identity_binding(gate.session_id)?;
        require_transport_identity_binding(&transport, &identities)?;
        let mut participants = Vec::with_capacity(2);
        for entry in transport.participants {
            let key = keys
                .key(XmrGraphSigningStageV22::Funding, entry.participant_id, hash)
                .map_err(|_| SessionStoreError::Quarantined)?
                .clone();
            let participant =
                ParticipantIdentityV1::new(&chain, entry.identity_key, key, entry.direction)
                    .map_err(|_| SessionStoreError::Quarantined)?;
            if participant.participant_id() != &entry.participant_id {
                return Err(SessionStoreError::Quarantined);
            }
            participants.push(participant);
        }
        participants.sort_by_key(|participant| *participant.participant_id());
        let roster =
            ParticipantRosterV1::new(participants).map_err(|_| SessionStoreError::Quarantined)?;
        Ok((chain, roster, templates.funding().clone()))
    }

    pub(in super::super) fn prepare_xmr_bounded_funding_transport_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedOperationalSigningTransportAuthorityV1, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(session)?;
        if chain != binding.origin.chain {
            return Err(SessionStoreError::Conflict);
        }
        self.audit_xmr_bounded_funding_round_v23(&binding)?;
        Ok(PreparedOperationalSigningTransportAuthorityV1 {
            trusted_chain_id: chain,
            session_id: session,
            purpose: PurposeV1::Funding,
            signing_binding_digest: binding.digest,
            round_start_revision: binding.start.revision(),
            round_start_record_digest: *binding.start.digest(),
            post_anchor: None,
            open_instance_id: self.open_instance_id,
        })
    }

    pub(in super::super) fn require_prepared_xmr_bounded_funding_transport_v23(
        &self,
        prepared: &PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(prepared.session_id)?;
        if prepared.open_instance_id != self.open_instance_id
            || prepared.purpose != PurposeV1::Funding
            || prepared.trusted_chain_id != binding.origin.chain
            || prepared.post_anchor.is_some()
            || prepared.signing_binding_digest != binding.digest
            || prepared.round_start_revision != binding.start.revision()
            || prepared.round_start_record_digest != *binding.start.digest()
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    pub(in super::super) fn xmr_bounded_funding_profile_locked_v23(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        match self.load_f7_gate_v12(session) {
            Ok(gate) => Ok(gate.profile == F7RecoveryProfileV23::XmrBounded),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(in super::super) fn require_xmr_bounded_funding_request_transition_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        predecessor: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(request.session_id)?;
        if request.authority_digest != binding.digest
            || request.chain_id != *binding.origin.chain.as_bytes()
            || request.predecessor_revision != predecessor.revision()
            || request.predecessor_record_digest != *predecessor.digest()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_next_xmr_bounded_funding_message_v23(
            &binding,
            predecessor,
            envelope,
            bytes,
            None,
        )
    }

    pub(in super::super) fn require_xmr_bounded_funding_successor_v23(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        recovery: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(current.session_id())?;
        let phase = self.require_next_xmr_bounded_funding_message_v23(
            &binding, current, envelope, bytes, recovery,
        )?;
        let transcript = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            direction,
            envelope.message_type,
            phase,
        )?;
        let mut flags = current.irreversible();
        if envelope.message_type == 0x0e {
            flags.any_signing_share_sent = true;
        }
        let expected = current.advance(
            current.revision(),
            phase,
            transcript,
            flags,
            current.chain(),
            current.encrypted_payload(),
        )?;
        if successor.as_bytes() != expected.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    pub(super) fn authenticate_xmr_bounded_funding_binding_v23(
        &self,
        session: [u8; 32],
    ) -> Result<NativeXmrFundingBindingV23, SessionStoreError> {
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_xmr_bounded_f7_ancestry_v23(&gate)?;
        let journal = self
            .optional_f7_funding_signing_v20(&gate)?
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        let start = journal.successor;
        let durable = self.load_session_revision(session, start.revision())?;
        if durable.as_bytes() != start.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        // A legacy Funding binding would imply a second origin for one nonce
        // domain. Never silently adopt or overwrite it.
        match self.load_signing_binding(session, PurposeV1::Funding) {
            Err(SessionStoreError::SessionNotFound) => {}
            Ok(_) => return Err(SessionStoreError::Conflict),
            Err(error) => return Err(error),
        }
        let (chain, roster, template) = self.reconstruct_xmr_bounded_funding_roster_v23(&gate)?;
        let mut bases = [0; 2];
        for (index, participant) in roster.entries().iter().enumerate() {
            bases[index] = self.transport_sequence_at_revision(
                session,
                *participant.participant_id(),
                start.revision(),
            )?;
            bases[index]
                .checked_add(2)
                .ok_or(SessionStoreError::CapacityExceeded)?;
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&gate.digest);
        bytes.extend_from_slice(start.as_bytes());
        for (index, participant) in roster.entries().iter().enumerate() {
            bytes.extend_from_slice(participant.participant_id());
            bytes.extend_from_slice(&participant.identity_public_key().to_compressed_bytes());
            bytes.extend_from_slice(&participant.signing_public_key().to_compressed_bytes());
            bytes.push(participant.direction().to_byte());
            bytes.extend_from_slice(&bases[index].to_le_bytes());
        }
        Ok(NativeXmrFundingBindingV23 {
            origin: NativeXmrFundingOriginV23 {
                chain,
                session,
                purpose: PurposeV1::Funding,
                roster,
                template,
                adaptor: None,
            },
            start,
            sender_sequence_bases: bases,
            digest: tagged_hash("DOM-INTEROP/XMR-BOUNDED-FUNDING-ORIGIN/V23\0", &bytes),
        })
    }

    /// Reissue only a native bounded Funding session after both real ready
    /// votes and its durable FundingAuthorized origin. No legacy binding reuse.
    pub fn resume_xmr_bounded_funding_signing_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.resume_xmr_bounded_funding_signing_locked_v23(chain, session)
    }

    pub(in super::super) fn resume_xmr_bounded_funding_signing_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(session)?;
        if chain != binding.origin.chain {
            return Err(SessionStoreError::Conflict);
        }
        let current = self.load_session_locked(session)?;
        if current.phase() != SessionPhaseV1::FundingAuthorized
            || !current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || current.revision()
                > binding
                    .start
                    .revision()
                    .checked_add(6)
                    .ok_or(SessionStoreError::CapacityExceeded)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let round = self.audit_xmr_bounded_funding_round_at_v23(&binding, &current, None)?;
        let initial_transcript_hash = initial_transcript_hash_v1(
            &chain,
            &session,
            ContractKindV1::WitnessOrTimeout,
            &binding.origin.roster,
        );
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id: chain,
            session_id: session,
            contract_kind: ContractKindV1::WitnessOrTimeout,
            purpose: PurposeV1::Funding,
            roster: binding.origin.roster,
            transaction_template: binding.origin.template,
            kernel_index: 0,
            adaptor_point: None,
            initial_transcript_hash,
            round_start_transcript_hash: binding.start.transcript_hash(),
            sender_sequence_bases: binding.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: binding.start.revision(),
            _session_record_digest: *binding.start.digest(),
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: None,
        })
    }

    pub(super) fn audit_xmr_bounded_funding_signature_v23(
        &self,
        session: [u8; 32],
        current: &SessionRecordV1,
        complete: bool,
    ) -> Result<Option<SchnorrSignature>, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(session)?;
        let count = current
            .revision()
            .checked_sub(binding.start.revision())
            .ok_or(SessionStoreError::Quarantined)?;
        if count > 6 || (complete && count != 6) {
            return Err(SessionStoreError::Quarantined);
        }
        let round = self.audit_xmr_bounded_funding_round_at_v23(&binding, current, None)?;
        if complete && round.plain_signature.is_none() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(round.plain_signature)
    }

    // Binding has already been authenticated against the complete retained graph.
    // Authenticate every real identity envelope and durable successor as well.
    pub(super) fn audit_xmr_bounded_funding_round_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
    ) -> Result<NativeXmrFundingRoundV23, SessionStoreError> {
        let current = self.load_session_locked(binding.origin.session)?;
        self.audit_xmr_bounded_funding_round_at_v23(binding, &current, None)
    }

    pub(super) fn audit_xmr_bounded_funding_round_at_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
        current: &SessionRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<NativeXmrFundingRoundV23, SessionStoreError> {
        let origin = &binding.origin;
        let start = self.load_session_revision(origin.session, binding.start.revision())?;
        if start.digest() != binding.start.digest()
            || start.transcript_hash() != binding.start.transcript_hash()
            || current.revision() < binding.start.revision()
            || origin.purpose != PurposeV1::Funding
        {
            return Err(SessionStoreError::Quarantined);
        }
        let end = binding
            .start
            .revision()
            .checked_add(6)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        // Collect fresh physical records in bounded passes, then retain the
        // same lexical authentication order and complete successor/round audit.
        let records = xmr_graph_proposal_v22::message_collect_v25::collect_untrusted_messages_v25(
            &self.messages,
            origin.session,
        )?;
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
                || record.successor.phase() != SessionPhaseV1::FundingAuthorized
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
                SessionPhaseV1::FundingAuthorized,
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
            PublicSigningScopeV25::funding(
                binding.digest,
                *binding.start.digest(),
                binding.start.terms_hash(),
            ),
            origin.chain.as_bytes(),
            origin.session,
            origin.purpose,
            &FundingSemanticBindingV23 {
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
        Ok(NativeXmrFundingRoundV23 {
            accepted_messages,
            terminal_transcript: predecessor.transcript_hash(),
            plain_signature,
        })
    }

    pub(super) fn require_next_xmr_bounded_funding_message_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let origin = &binding.origin;
        let round =
            self.audit_xmr_bounded_funding_round_at_v23(binding, current, recovery_scope)?;
        let position = round.accepted_messages.len();
        let phase = if position == 0 {
            binding.start.phase()
        } else {
            SessionPhaseV1::FundingAuthorized
        };
        if position >= 6
            || current.phase() != phase
            || current.session_id() != origin.session
            || current.revision() != binding.start.revision() + position as u64
            || !current.irreversible().funding_authorized
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
            PublicSigningScopeV25::funding(
                binding.digest,
                *binding.start.digest(),
                binding.start.terms_hash(),
            ),
            origin.chain.as_bytes(),
            origin.session,
            origin.purpose,
            &FundingSemanticBindingV23 {
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
        Ok(SessionPhaseV1::FundingAuthorized)
    }
}
