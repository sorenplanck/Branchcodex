//! Six real Claim envelopes with authenticated projection-only refresh gaps.
use super::*;
use xmr_graph_proposal_v22::public_signing_semantics_cache_v25::{
    verify_v25, PublicSigningScopeV25,
};

pub(in super::super) struct NativeXmrClaimRoundV23 {
    pub(in super::super) accepted: Vec<Vec<u8>>,
    pub(in super::super) terminal: SessionRecordV1,
    pub(in super::super) reveal: Option<[u8; 32]>,
    pub(in super::super) pre_signature: Option<AdaptorPreSignatureV1>,
}
impl NativeXmrClaimRoundV23 {
    pub(in super::super) fn view<'a>(
        &'a self,
        binding: &NativeXmrClaimBindingV23,
    ) -> SigningRoundSemanticViewV23<'a> {
        SigningRoundSemanticViewV23 {
            round_start_transcript_hash: binding.start.transcript_hash(),
            sender_sequence_bases: binding.sender_sequence_bases,
            accepted_messages: &self.accepted,
            terminal_transcript_hash: self.terminal.transcript_hash(),
            reveal_transcript_hash: self.reveal,
        }
    }
}
impl ContractsSessionStoreV1 {
    pub(in super::super) fn audit_xmr_bounded_claim_round_at_v23(
        &self,
        binding: &NativeXmrClaimBindingV23,
        current: &SessionRecordV1,
        recovery: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<NativeXmrClaimRoundV23, SessionStoreError> {
        self.require_live_f7_claim_v12(&binding.issued, current)?;
        let records = self.authenticated_derived_transport_records_with_recovery_scope(
            binding.issued.session_id,
            current.revision(),
            recovery,
        )?;
        let mut terminal =
            self.load_session_revision(binding.issued.session_id, binding.start.revision())?;
        if terminal.as_bytes() != binding.start.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        let mut accepted = Vec::with_capacity(6);
        let mut reveal = None;
        for record in records
            .iter()
            .filter(|r| r.revision > binding.start.revision())
        {
            if record.revision > current.revision() {
                continue;
            }
            if !(0x0c..=0x0e).contains(&record.message_type)
                || record.purpose != Some(PurposeV1::ClaimAdaptor)
                || accepted.len() >= 6
            {
                return Err(SessionStoreError::Quarantined);
            }
            let predecessor = self.load_session_revision(
                binding.issued.session_id,
                record
                    .revision
                    .checked_sub(1)
                    .ok_or(SessionStoreError::Quarantined)?,
            )?;
            self.require_projection_only_session_lineage(&terminal, &predecessor)?;
            self.require_live_f7_claim_v12(&binding.issued, &predecessor)?;
            let successor =
                self.load_session_revision(binding.issued.session_id, record.revision)?;
            self.require_live_f7_claim_v12(&binding.issued, &successor)?;
            let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)?;
            let participant = binding
                .roster
                .entries()
                .get(accepted.len() % 2)
                .ok_or(SessionStoreError::Quarantined)?;
            let transcript = accepted_transport_transcript_hash(
                &predecessor.transcript_hash(),
                &envelope.message_digest,
                participant.direction(),
                envelope.message_type,
                SessionPhaseV1::FundingConfirmed,
            )?;
            let mut flags = predecessor.irreversible();
            if envelope.message_type == 0x0e {
                flags.any_signing_share_sent = true;
            }
            let expected = predecessor.advance(
                predecessor.revision(),
                SessionPhaseV1::FundingConfirmed,
                transcript,
                flags,
                predecessor.chain(),
                predecessor.encrypted_payload(),
            )?;
            if successor.as_bytes() != expected.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
            accepted.push(record.signed_bytes.clone());
            if accepted.len() == 4 {
                reveal = Some(transcript);
            }
            terminal = successor;
        }
        self.require_projection_only_session_lineage(&terminal, current)?;
        let mut round = NativeXmrClaimRoundV23 {
            accepted,
            terminal,
            reveal,
            pre_signature: None,
        };
        verify_v25(
            PublicSigningScopeV25::claim(
                binding.digest,
                *binding.start.digest(),
                binding.issued.terms_hash,
                binding.issued.digest,
                binding.issued.consumption_digest,
                binding.issued.issuance_id,
                binding.issued.gate_digest,
            ),
            binding.chain.as_bytes(),
            binding.issued.session_id,
            PurposeV1::ClaimAdaptor,
            binding,
            &round.view(binding),
        )?;
        if round.accepted.len() == 6 {
            round.pre_signature = Some(derive_claim_pre_signature_from_view_v23(
                binding.chain.as_bytes(),
                binding.issued.session_id,
                &binding.issued.claim_template_hash,
                &binding.issued.adaptor_point,
                binding,
                &round.view(binding),
            )?);
        }
        Ok(round)
    }

    pub(in super::super) fn require_next_xmr_bounded_claim_message_v23(
        &self,
        binding: &NativeXmrClaimBindingV23,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        recovery: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let mut round = self.audit_xmr_bounded_claim_round_at_v23(binding, current, recovery)?;
        let position = round.accepted.len();
        if position >= 6 || envelope.message_type != 0x0c + (position / 2) as u8 {
            return Err(SessionStoreError::InvalidTransition);
        }
        let direction = binding.roster.entries()[position % 2].direction();
        let transcript = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            direction,
            envelope.message_type,
            SessionPhaseV1::FundingConfirmed,
        )?;
        let mut flags = current.irreversible();
        if envelope.message_type == 0x0e {
            flags.any_signing_share_sent = true;
        }
        round.terminal = current.advance(
            current.revision(),
            SessionPhaseV1::FundingConfirmed,
            transcript,
            flags,
            current.chain(),
            current.encrypted_payload(),
        )?;
        round.accepted.push(bytes.to_vec());
        if position == 3 {
            round.reveal = Some(transcript);
        }
        verify_v25(
            PublicSigningScopeV25::claim(
                binding.digest,
                *binding.start.digest(),
                binding.issued.terms_hash,
                binding.issued.digest,
                binding.issued.consumption_digest,
                binding.issued.issuance_id,
                binding.issued.gate_digest,
            ),
            binding.chain.as_bytes(),
            binding.issued.session_id,
            PurposeV1::ClaimAdaptor,
            binding,
            &round.view(binding),
        )?;
        Ok(SessionPhaseV1::FundingConfirmed)
    }

    /// Resume only the consumed, process-owned native Claim origin. This is
    /// not a funding or secret-exposure capability and does not reserve a nonce.
    pub fn resume_xmr_bounded_claim_signing_v23(
        &self,
        chain: TrustedChainIdV1,
        authorization: &ConsumedF7ClaimAuthorizationV12,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.resume_xmr_bounded_claim_signing_locked_v23(chain, authorization)
    }
    pub(in super::super) fn resume_xmr_bounded_claim_signing_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        authorization: &ConsumedF7ClaimAuthorizationV12,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        self.require_f7_consumed_handle_v12(authorization)?;
        self.resume_xmr_bounded_claim_session_locked_v23(chain, authorization.session_id)
    }
    fn resume_xmr_bounded_claim_session_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let current = self.load_session_locked(session)?;
        let binding = self.authenticate_xmr_bounded_claim_binding_v23(session)?;
        self.require_xmr_claim_binding_record_v23(&binding)?;
        if chain != binding.chain {
            return Err(SessionStoreError::Conflict);
        }
        let round = self.audit_xmr_bounded_claim_current_round_v23(&binding, &current)?;
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id: chain,
            session_id: session,
            contract_kind: ContractKindV1::WitnessOrTimeout,
            purpose: PurposeV1::ClaimAdaptor,
            initial_transcript_hash: initial_transcript_hash_v1(
                &chain,
                &session,
                ContractKindV1::WitnessOrTimeout,
                &binding.roster,
            ),
            roster: binding.roster,
            transaction_template: binding.template,
            kernel_index: 0,
            adaptor_point: Some(binding.issued.adaptor_point),
            round_start_transcript_hash: binding.start.transcript_hash(),
            sender_sequence_bases: binding.sender_sequence_bases,
            accepted_messages: round.accepted,
            _session_revision: binding.start.revision(),
            _session_record_digest: *binding.start.digest(),
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: Some(binding.issued.consumption_digest),
        })
    }
}

impl ContractsSessionStoreV1 {
    // Completed Claim resumes through its authenticated 0x0f suffix, never
    // treating that suffix as a seventh nonce/share message.
    pub(in super::super) fn audit_xmr_bounded_claim_current_round_v23(
        &self,
        binding: &NativeXmrClaimBindingV23,
        current: &SessionRecordV1,
    ) -> Result<NativeXmrClaimRoundV23, SessionStoreError> {
        self.require_live_f7_claim_v12(&binding.issued, current)?;
        match self.read_f7_v12(binding.issued.session_id, "claim-pre", 4096) {
            Err(SessionStoreError::SessionNotFound) => {
                self.audit_xmr_bounded_claim_round_at_v23(binding, current, None)
            }
            Err(error) => Err(error),
            Ok(_) => {
                let pre = self.load_f7_pre_v12(binding.issued.session_id)?;
                self.require_f7_pre_head_v12(&pre, current)?;
                let terminal =
                    self.load_session_revision(binding.issued.session_id, pre.terminal_revision)?;
                self.audit_xmr_bounded_claim_round_at_v23(binding, &terminal, None)
            }
        }
    }
}
