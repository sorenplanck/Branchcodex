//! Claim origin derived from a consumed native F7 authorization. No legacy
//! early-share or template-commit authority is manufactured for graph keys.
use super::*;
#[path = "f7_xmr_claim_round_v23.rs"]
mod round_v23;
#[path = "f7_xmr_claim_transport_v23.rs"]
mod transport_v23;
#[path = "f7_xmr_claim_vault_v23.rs"]
mod vault_v23;
pub(in super::super) use vault_v23::parse_xmr_claim_vault_name_v23;
pub use vault_v23::{PreparedXmrClaimVaultProvisioningV23, XmrClaimVaultProvisioningStateV23};
use xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningStageV22;

pub(super) struct NativeXmrClaimBindingV23 {
    pub(super) chain: TrustedChainIdV1,
    pub(super) issued: F7ClaimRecordV12,
    pub(super) start: SessionRecordV1,
    pub(super) roster: ParticipantRosterV1,
    pub(super) template: Transaction,
    pub(super) sender_sequence_bases: [u64; 2],
    pub(super) digest: [u8; 32],
}

impl SigningSemanticBindingAccessV1 for NativeXmrClaimBindingV23 {
    fn participant_count(&self) -> usize {
        self.roster.entries().len()
    }
    fn participant(&self, index: usize) -> Option<SigningSemanticParticipantRefV1<'_>> {
        self.roster
            .entries()
            .get(index)
            .map(|entry| SigningSemanticParticipantRefV1 {
                participant_id: entry.participant_id(),
                signing_public_key: entry.signing_public_key(),
                direction: entry.direction(),
            })
    }
    fn transaction_template(&self) -> &Transaction {
        &self.template
    }
    fn template_hash(&self) -> &[u8; 32] {
        &self.issued.claim_template_hash
    }
    fn kernel_index(&self) -> usize {
        0
    }
    fn adaptor_point(&self) -> Option<&PublicKey> {
        Some(&self.issued.adaptor_point)
    }
}

impl ContractsSessionStoreV1 {
    pub(super) fn authenticate_xmr_bounded_claim_binding_v23(
        &self,
        session: [u8; 32],
    ) -> Result<NativeXmrClaimBindingV23, SessionStoreError> {
        let (gate, issued, _) = self.authenticate_f7_claim_v12(session)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        // authenticate_f7_claim_v12 verifies the immutable consumed issuance,
        // funding commit, bilateral Ready and complete recovery ancestry.
        let chain = self.require_process_trusted_chain_v23(&gate.chain_id)?;
        let start = self.load_session_revision(session, issued.bound_session_revision)?;
        if start.digest() != &issued.bound_session_record_digest
            || start.transcript_hash() != issued.round_start_transcript_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        match self.load_signing_binding(session, PurposeV1::ClaimAdaptor) {
            Err(SessionStoreError::SessionNotFound) => {}
            Ok(_) => return Err(SessionStoreError::Conflict),
            Err(error) => return Err(error),
        }
        let (templates, keys) = self.reconstruct_xmr_graph_evidence_core_v23(
            chain,
            gate.role.route_id(),
            session,
            false,
        )?;
        keys.require_graph(&templates)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let hash = keys.template_hash(XmrGraphSigningStageV22::Claim);
        let template = templates.claim().clone();
        if hash != issued.claim_template_hash
            || hash != gate.role.claim_template_hash()
            || canonical_dom_transaction_bytes_v1(&template)? != gate.claim_template
            || gate.role.claim_kernel_index() != 0
            || gate.role.adaptor_point_sec1() != issued.adaptor_point.to_compressed_bytes()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let transport = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&transport, &identities)?;
        let mut participants = Vec::with_capacity(2);
        for entry in transport.participants {
            let key = keys
                .key(XmrGraphSigningStageV22::Claim, entry.participant_id, hash)
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
        participants.sort_by_key(|p| *p.participant_id());
        let roster =
            ParticipantRosterV1::new(participants).map_err(|_| SessionStoreError::Quarantined)?;
        if participant_roster_digest(&roster)
            != participant_roster_digest(
                FinalClaimRoleBindingV1::decode_canonical(&chain, gate.role.canonical_bytes())
                    .map_err(|_| SessionStoreError::Quarantined)?
                    .roster(),
            )
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut bases = [0; 2];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&gate.digest);
        bytes.extend_from_slice(&issued.digest);
        bytes.extend_from_slice(&issued.consumption_digest);
        bytes.extend_from_slice(start.as_bytes());
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&issued.adaptor_point.to_compressed_bytes());
        for (index, participant) in roster.entries().iter().enumerate() {
            bases[index] = self.transport_sequence_at_revision(
                session,
                *participant.participant_id(),
                start.revision(),
            )?;
            bases[index]
                .checked_add(2)
                .ok_or(SessionStoreError::CapacityExceeded)?;
            bytes.extend_from_slice(participant.participant_id());
            bytes.extend_from_slice(&participant.identity_public_key().to_compressed_bytes());
            bytes.extend_from_slice(&participant.signing_public_key().to_compressed_bytes());
            bytes.push(participant.direction().to_byte());
            bytes.extend_from_slice(&bases[index].to_le_bytes());
        }
        Ok(NativeXmrClaimBindingV23 {
            chain,
            issued,
            start,
            roster,
            template,
            sender_sequence_bases: bases,
            digest: tagged_hash("DOM-INTEROP/XMR-BOUNDED-CLAIM-ORIGIN/V23\0", &bytes),
        })
    }
}

impl ContractsSessionStoreV1 {
    pub(in super::super) fn prepare_xmr_bounded_claim_transport_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedOperationalSigningTransportAuthorityV1, SessionStoreError> {
        self.require_downstream_claim_gate_for_session_locked_v23(session)?;
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(session)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if chain != binding.chain {
            return Err(SessionStoreError::Conflict);
        }
        let current = self.load_session_locked(session)?;
        self.audit_xmr_bounded_claim_current_round_v23(&binding, &current)?;
        Ok(PreparedOperationalSigningTransportAuthorityV1 {
            trusted_chain_id: chain,
            session_id: session,
            purpose: PurposeV1::ClaimAdaptor,
            signing_binding_digest: binding.digest,
            round_start_revision: binding.start.revision(),
            round_start_record_digest: *binding.start.digest(),
            post_anchor: None,
            open_instance_id: self.open_instance_id,
        })
    }
    pub(in super::super) fn require_prepared_xmr_bounded_claim_transport_v23(
        &self,
        prepared: &PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(prepared.session_id)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if prepared.open_instance_id != self.open_instance_id
            || prepared.trusted_chain_id != binding.chain
            || prepared.purpose != PurposeV1::ClaimAdaptor
            || prepared.post_anchor.is_some()
            || prepared.signing_binding_digest != binding.digest
            || prepared.round_start_revision != binding.start.revision()
            || prepared.round_start_record_digest != *binding.start.digest()
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }
    pub(in super::super) fn require_xmr_bounded_claim_request_transition_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        predecessor: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(request.session_id)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if request.authority_digest != binding.digest
            || request.chain_id != *binding.chain.as_bytes()
            || request.predecessor_revision != predecessor.revision()
            || request.predecessor_record_digest != *predecessor.digest()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_next_xmr_bounded_claim_message_v23(
            &binding,
            predecessor,
            envelope,
            bytes,
            None,
        )
    }
    pub(super) fn require_xmr_bounded_claim_successor_v23(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        recovery: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(current.session_id())?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        let phase = self.require_next_xmr_bounded_claim_message_v23(
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
        if expected.as_bytes() != successor.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
    pub(super) fn xmr_claim_binding_record_v23(
        &self,
        binding: &NativeXmrClaimBindingV23,
    ) -> F7ClaimRoundBindingV12 {
        F7ClaimRoundBindingV12 {
            issuance_record_digest: binding.issued.digest,
            consumption_record_digest: binding.issued.consumption_digest,
            signing_binding_record_digest: binding.digest,
            roster_digest: participant_roster_digest(&binding.roster),
            round_start_record_digest: *binding.start.digest(),
            final_claim_role_binding_digest: binding.issued.final_claim_role_binding_digest,
            ready_binding_digest: binding.issued.ready_binding_digest,
        }
    }
    pub(super) fn require_xmr_claim_binding_record_v23(
        &self,
        binding: &NativeXmrClaimBindingV23,
    ) -> Result<(), SessionStoreError> {
        let expected = self.xmr_claim_binding_record_v23(binding);
        if self
            .read_f7_claim_binding_v12(binding.issued.session_id)?
            .encode()
            != expected.encode()
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
}

impl ContractsSessionStoreV1 {
    pub(super) fn derive_xmr_bounded_claim_pre_v23(
        &self,
        session: [u8; 32],
        revision: u64,
        recovery: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<F7PreRecordV12, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(session)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        let terminal = self.load_session_revision(session, revision)?;
        let round = self.audit_xmr_bounded_claim_round_at_v23(&binding, &terminal, recovery)?;
        if round.accepted.len() != 6 || round.terminal.as_bytes() != terminal.as_bytes() {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let pre_signature = round.pre_signature.ok_or(SessionStoreError::Quarantined)?;
        let reveal = round.reveal.ok_or(SessionStoreError::Quarantined)?;
        let sender = &binding.roster.entries()[0];
        let sequence = binding.sender_sequence_bases[0]
            .checked_add(3)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        if self.transport_sequence_at_revision(session, *sender.participant_id(), revision)?
            != sequence
        {
            return Err(SessionStoreError::Quarantined);
        }
        // Same public pre-signature transport codec, native origin digest.
        let mut bytes = b"DOMFCP12".to_vec();
        bytes.extend_from_slice(&revision.to_le_bytes());
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.push(sender.direction().to_byte());
        for hash in [
            session,
            *binding.chain.as_bytes(),
            binding.issued.digest,
            binding.issued.consumption_digest,
            binding.digest,
            terminal.transcript_hash(),
            *terminal.digest(),
            *sender.participant_id(),
            reveal,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&pre_signature.to_bytes());
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-PRE/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        Ok(F7PreRecordV12 {
            bytes,
            digest,
            session_id: session,
            chain_id: *binding.chain.as_bytes(),
            terminal_revision: revision,
            terminal_transcript_hash: terminal.transcript_hash(),
            terminal_record_digest: *terminal.digest(),
            canonical_sender_id: *sender.participant_id(),
            canonical_sender_sequence: sequence,
            canonical_sender_direction: sender.direction(),
            reveal_transcript_hash: reveal,
            pre_signature,
        })
    }
}
