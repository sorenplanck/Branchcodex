//! Durable DSC1 handoff for the native XMR claim/refund sweep.
//!
//! The Store authenticates identities, exact request/response pairing,
//! sequencing, restart recovery and exact retryable import. It deliberately does
//! not treat a canonical Monero transaction or proof bundle as valid: the
//! independent XMR actuator must verify the funding input, key image, RingCT,
//! payout and fee before it obtains broadcast authority.

use super::*;
use xmr_remote_sweep_wire::{
    RemoteSweepActionV23, RemoteSweepRequestV23, RemoteSweepResponseV23,
    MAX_REMOTE_SWEEP_REQUEST_BYTES_V23, MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23,
};

/// Move-only proof that one exact XMR sweep request is in the authenticated
/// DSC1 transcript of this Store opening.
pub struct AcceptedXmrRemoteSweepRequestV23 {
    session_id: [u8; 32],
    requester_id: [u8; 32],
    signer_id: [u8; 32],
    sequence: u64,
    message_digest: [u8; 32],
    record_digest: [u8; 32],
    payload: Vec<u8>,
    open_instance_id: [u8; 32],
}

impl AcceptedXmrRemoteSweepRequestV23 {
    /// Session containing the accepted request.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// DSC1 participant requesting use of the remote role-scoped share.
    pub const fn requester_id(&self) -> &[u8; 32] {
        &self.requester_id
    }
    /// Counterparty participant that must independently authorize the sweep.
    pub const fn signer_id(&self) -> &[u8; 32] {
        &self.signer_id
    }
    /// Exact accepted DSC1 `0x19` message digest.
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }
    /// Exact canonical public request payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

struct AuthenticatedXmrRemoteSweepRequestV23 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    signer_id: [u8; 32],
    message_digest: [u8; 32],
    record_digest: [u8; 32],
    payload: Vec<u8>,
}

/// Move-only proof that one exact XMR sweep response is durably paired with
/// an authenticated `0x19` request.  This is transport evidence, not Monero
/// transaction validity.
pub struct AcceptedXmrRemoteSweepResponseV23 {
    session_id: [u8; 32],
    signer_id: [u8; 32],
    sequence: u64,
    request_message_digest: [u8; 32],
    response_message_digest: [u8; 32],
    transaction_hash: [u8; 32],
    key_image: [u8; 32],
    response_wire_digest: [u8; 32],
    payload: Vec<u8>,
    record_digest: [u8; 32],
    open_instance_id: [u8; 32],
}

impl AcceptedXmrRemoteSweepResponseV23 {
    /// Session containing the accepted response.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Exact request message digest echoed inside the response.
    pub const fn request_message_digest(&self) -> &[u8; 32] {
        &self.request_message_digest
    }
    /// Exact accepted DSC1 `0x1a` message digest.
    pub const fn response_message_digest(&self) -> &[u8; 32] {
        &self.response_message_digest
    }
    /// Claimed Monero transaction hash; the actuator must recompute it.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
    /// Claimed spent key image; the actuator must derive and verify it.
    pub const fn key_image(&self) -> &[u8; 32] {
        &self.key_image
    }
    /// Digest of the canonical response wire bytes.
    pub const fn response_wire_digest(&self) -> &[u8; 32] {
        &self.response_wire_digest
    }
    /// Canonical response bytes, still requiring full cryptographic checking.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Retryable move-only handoff of one exact authenticated XMR response into
/// the independent verification boundary.
///
/// Neither construction nor possession authorizes broadcast.  The consumer
/// must decode both payloads again and verify funding provenance, request
/// pins, input ownership, RingCT, CLSAG, Bulletproof+, payout, fee, key image
/// and quorum-fetched ring members before creating an actuator capability.
pub struct PreparedXmrRemoteSweepImportV23 {
    session_id: [u8; 32],
    request_message_digest: [u8; 32],
    response_message_digest: [u8; 32],
    response_wire_digest: [u8; 32],
    transaction_hash: [u8; 32],
    key_image: [u8; 32],
    request_payload: Vec<u8>,
    response_payload: Vec<u8>,
}

impl PreparedXmrRemoteSweepImportV23 {
    /// Session owning this exact import.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Exact accepted request message digest.
    pub const fn request_message_digest(&self) -> &[u8; 32] {
        &self.request_message_digest
    }
    /// Exact accepted response message digest.
    pub const fn response_message_digest(&self) -> &[u8; 32] {
        &self.response_message_digest
    }
    /// Digest of the canonical inner response.
    pub const fn response_wire_digest(&self) -> &[u8; 32] {
        &self.response_wire_digest
    }
    /// Claimed transaction hash, to be recomputed from the exact raw bytes.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
    /// Claimed key image, to be independently derived and checked.
    pub const fn key_image(&self) -> &[u8; 32] {
        &self.key_image
    }
    /// Exact canonical request bytes.
    pub fn request_payload(&self) -> &[u8] {
        &self.request_payload
    }
    /// Exact canonical response bytes.
    pub fn response_payload(&self) -> &[u8] {
        &self.response_payload
    }
    /// Consumes this handle and returns both exact wire payloads. The Store may
    /// reissue the same immutable pair after a transient verifier/lease error.
    pub fn into_payloads(self) -> (Vec<u8>, Vec<u8>) {
        (self.request_payload, self.response_payload)
    }
}

impl ContractsSessionStoreV1 {
    fn require_xmr_remote_sweep_phase_v23(
        &self,
        request: &RemoteSweepRequestV23,
        phase: SessionPhaseV1,
    ) -> Result<(), SessionStoreError> {
        if request.action != RemoteSweepActionV23::Refund
            || !self.native_xmr_refund_transport_applies_v23(request.session_id)?
        {
            // The historical phase gate is unchanged for Claim and legacy.
            return require_xmr_remote_sweep_phase(request.action, phase);
        }
        if !matches!(
            phase,
            SessionPhaseV1::FundingBroadcast
                | SessionPhaseV1::FundingConfirmed
                | SessionPhaseV1::RefundEligible
                | SessionPhaseV1::RefundBroadcast
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.require_native_xmr_refund_transport_v23(request) {
            Ok(()) => Ok(()),
            Err(SessionStoreError::NativeXmrRefundTransportPendingV23) => {
                // A newly arrived request can precede this participant's own
                // canonical U scan. Never produce an acceptance receipt then.
                // Once ANY refund edge is retained, disappearance is corruption.
                let mut retained = false;
                self.scan_xmr_remote_sweep_records(|_, envelope, payload| {
                    if envelope.session_id == request.session_id {
                        retained |= match envelope.message_type {
                            0x19 => {
                                decode_xmr_request(payload)?.action == RemoteSweepActionV23::Refund
                            }
                            0x1a => {
                                let response = decode_xmr_response(payload)?;
                                let paired = self.load_xmr_remote_sweep_request_by_digest(
                                    response.request_message_digest(),
                                )?;
                                decode_xmr_request(&paired.payload)?.action
                                    == RemoteSweepActionV23::Refund
                            }
                            _ => false,
                        };
                    }
                    Ok(())
                })?;
                // Preparing a local DSC1 signature is already durable intent,
                // even when no signed message has reached the transport log.
                let mut failure = None;
                self.rosters
                    .scan_lexicographic(|name, node| {
                        if !name.ends_with(".outbound-dsc1-request") {
                            return Ok(());
                        }
                        if node.node_type != ExpectedNodeType::RegularFile {
                            return Err(LinuxCapabilityError::InvalidObject);
                        }
                        let outcome = (|| -> Result<(), SessionStoreError> {
                            let bytes = self.rosters.read_bounded_file(
                                &ValidatedComponent::registered(name)?,
                                OUTBOUND_DSC1_REQUEST_MAX_LEN,
                            )?;
                            let record = OutboundDsc1SigningRequestRecordV1::from_bytes(&bytes)?;
                            if outbound_dsc1_request_name(
                                record.session_id,
                                record.sender_id,
                                record.sequence,
                            ) != name
                            {
                                return Err(SessionStoreError::Quarantined);
                            }
                            if record.session_id == request.session_id
                                && record.message_type == 0x19
                            {
                                retained |= decode_xmr_request(&record.payload)?.action
                                    == RemoteSweepActionV23::Refund;
                            }
                            Ok(())
                        })();
                        if let Err(error) = outcome {
                            failure = Some(error);
                            return Err(LinuxCapabilityError::ExactBytesMismatch);
                        }
                        Ok(())
                    })
                    .map_err(|error| failure.take().unwrap_or_else(|| error.into()))?;
                Err(if retained {
                    SessionStoreError::Quarantined
                } else {
                    SessionStoreError::NativeXmrRefundTransportPendingV23
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Persists the exact outbound DSC1 `0x19` request selected by the local
    /// transport identity.  The request carries only public facts and a
    /// public-on-DOM scalar; the remote signer must reconstruct policy from
    /// its own retained route and custody state.
    pub fn prepare_xmr_remote_sweep_request_dsc1_signing_request(
        &self,
        session_id: [u8; 32],
        payload: &[u8],
    ) -> Result<PreparedDsc1SigningRequestV1, SessionStoreError> {
        let decoded = decode_xmr_request(payload)?;
        if decoded.session_id != session_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        self.require_xmr_remote_sweep_phase_v23(&decoded, current.phase())?;
        let roster = self.load_transport_roster(session_id)?;
        let local = self.authenticate_local_transport_signer_binding(session_id)?;
        let _ = xmr_counterparty(&roster, local.participant_id)?;
        let sequence = self.transport_sequence_at_revision(
            session_id,
            local.participant_id,
            current.revision(),
        )?;
        let authority_digest = xmr_remote_sweep_request_authority_digest(
            &self._store_id,
            &session_id,
            current.digest(),
            payload,
        );
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::XmrRemoteSweepRequestV23,
            chain_id: roster.chain_id,
            session_id,
            sender_id: local.participant_id,
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            predecessor: &current,
            authority_digest,
            payload,
        })
    }

    /// Accepts and durably journals one authenticated DSC1 `0x19` request.
    pub fn accept_xmr_remote_sweep_request_transport_message(
        &self,
        signed_bytes: &[u8],
    ) -> Result<AcceptedXmrRemoteSweepRequestV23, SessionStoreError> {
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.message_type != 0x19 {
            return Err(SessionStoreError::InvalidTransition);
        }
        let request = decode_xmr_request(envelope.payload(signed_bytes)?)?;
        if request.session_id != envelope.session_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(envelope.session_id)?;
        let roster = self.load_transport_roster(envelope.session_id)?;
        let requester = roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        // A missing local grant is a wait only for an authenticated request,
        // never a way to defer invalid signatures or a transplanted chain.
        envelope.verify(&requester.identity_key)?;
        if envelope.chain_id != roster.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_xmr_remote_sweep_phase_v23(&request, current.phase())?;
        let _signer_id = xmr_counterparty(&roster, requester.participant_id)?;
        self.require_unique_xmr_remote_sweep_request(
            envelope.session_id,
            &request,
            envelope.message_digest,
        )?;
        let transcript_hash = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            requester.direction,
            envelope.message_type,
            current.phase(),
        )?;
        let successor = current.advance(
            current.revision(),
            current.phase(),
            transcript_hash,
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
        match self.accept_transport_message_with_successor_locked(
            signed_bytes,
            &successor,
            Some(&failed),
        )? {
            DurableTransportOutcomeV1::Accepted(_) => self
                .load_accepted_xmr_remote_sweep_request_handle(
                    envelope.session_id,
                    envelope.sender_id,
                    envelope.sequence,
                ),
            DurableTransportOutcomeV1::EquivocationPersisted => Err(SessionStoreError::Conflict),
        }
    }

    /// Persists the requested counterparty's exact DSC1 `0x1a` response.
    pub fn prepare_xmr_remote_sweep_response_dsc1_signing_request(
        &self,
        accepted_request: &AcceptedXmrRemoteSweepRequestV23,
        response_payload: &[u8],
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let response = decode_xmr_response(response_payload)?;
        let _guard = self.operation_lock()?;
        let request = self.authenticate_accepted_xmr_remote_sweep_request(accepted_request)?;
        require_xmr_response_matches_request(&response, &request.payload, &request.message_digest)?;
        let current = self.load_session_locked(request.session_id)?;
        let decoded_request = decode_xmr_request(&request.payload)?;
        self.require_xmr_remote_sweep_phase_v23(&decoded_request, current.phase())?;
        let signer = self.authenticate_local_transport_signer_binding(request.session_id)?;
        if signer.participant_id != request.signer_id {
            return Ok(None);
        }
        let sequence = self.transport_sequence_at_revision(
            request.session_id,
            request.signer_id,
            current.revision(),
        )?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::XmrRemoteSweepResponseV23,
            chain_id: request.chain_id,
            session_id: request.session_id,
            sender_id: request.signer_id,
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            predecessor: &current,
            authority_digest: request.record_digest,
            payload: response_payload,
        })
        .map(Some)
    }

    /// Accepts one authenticated DSC1 `0x1a`, requiring its exact retained
    /// `0x19` predecessor and counterparty identity.
    pub fn accept_xmr_remote_sweep_response_transport_message(
        &self,
        signed_bytes: &[u8],
    ) -> Result<AcceptedXmrRemoteSweepResponseV23, SessionStoreError> {
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.message_type != 0x1a {
            return Err(SessionStoreError::InvalidTransition);
        }
        let response = decode_xmr_response(envelope.payload(signed_bytes)?)?;
        let _guard = self.operation_lock()?;
        let request =
            self.load_xmr_remote_sweep_request_by_digest(response.request_message_digest())?;
        require_xmr_response_matches_request(&response, &request.payload, &request.message_digest)?;
        let current = self.load_session_locked(envelope.session_id)?;
        let decoded_request = decode_xmr_request(&request.payload)?;
        self.require_xmr_remote_sweep_phase_v23(&decoded_request, current.phase())?;
        let roster = self.load_transport_roster(envelope.session_id)?;
        let signer = roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        if request.chain_id != envelope.chain_id
            || request.session_id != envelope.session_id
            || request.signer_id != envelope.sender_id
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_unique_xmr_remote_sweep_response(
            envelope.session_id,
            request.message_digest,
            envelope.message_digest,
        )?;
        let transcript_hash = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            signer.direction,
            envelope.message_type,
            current.phase(),
        )?;
        let successor = current.advance(
            current.revision(),
            current.phase(),
            transcript_hash,
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
        match self.accept_transport_message_with_successor_locked(
            signed_bytes,
            &successor,
            Some(&failed),
        )? {
            DurableTransportOutcomeV1::Accepted(_) => self
                .load_accepted_xmr_remote_sweep_response_handle(
                    envelope.session_id,
                    envelope.sender_id,
                    envelope.sequence,
                ),
            DurableTransportOutcomeV1::EquivocationPersisted => Err(SessionStoreError::Conflict),
        }
    }

    /// Discovers the unique accepted `0x19` that is pending for this Store's
    /// locally bound counterparty signer.
    ///
    /// The caller supplies no sequence, payload, identity or path.  All of
    /// those facts are recovered from authenticated retained records.  A
    /// request already answered by a durable `0x1a` is not pending; multiple
    /// eligible requests, equivocation or an invalid live phase fail closed.
    pub fn resume_pending_xmr_remote_sweep_request_for_local_signer(
        &self,
        session_id: [u8; 32],
    ) -> Result<Option<AcceptedXmrRemoteSweepRequestV23>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        let local = self.authenticate_local_transport_signer_binding(session_id)?;
        if local.chain_id != roster.chain_id {
            return Err(SessionStoreError::Quarantined);
        }
        let mut candidate = None;
        let mut answered = BTreeSet::new();
        self.scan_xmr_remote_sweep_records(|record, envelope, payload| {
            if envelope.session_id != session_id {
                return Ok(());
            }
            match envelope.message_type {
                0x19 => {
                    let request = decode_xmr_request(payload)?;
                    let signer_id = xmr_counterparty(&roster, envelope.sender_id)?;
                    if signer_id != local.participant_id {
                        return Ok(());
                    }
                    self.require_xmr_remote_sweep_phase_v23(&request, current.phase())?;
                    if record.equivocation
                        || candidate
                            .replace((
                                envelope.sender_id,
                                envelope.sequence,
                                envelope.message_digest,
                            ))
                            .is_some()
                    {
                        return Err(SessionStoreError::Conflict);
                    }
                }
                0x1a => {
                    let response = decode_xmr_response(payload)?;
                    if record.equivocation {
                        return Err(SessionStoreError::Conflict);
                    }
                    answered.insert(response.request_message_digest());
                }
                _ => {}
            }
            Ok(())
        })?;
        let Some((requester_id, sequence, message_digest)) = candidate else {
            return Ok(None);
        };
        if answered.contains(&message_digest) {
            return Ok(None);
        }
        self.load_accepted_xmr_remote_sweep_request_handle(session_id, requester_id, sequence)
            .map(Some)
    }

    /// Recovers the unique completed response produced by this Store's local
    /// signer without accepting a caller-selected digest, sequence or peer.
    /// This is restart readback for the responder, not the requester import
    /// capability; retries still recover only the same durable request/response.
    pub fn resume_completed_xmr_remote_sweep_response_for_local_signer(
        &self,
        session_id: [u8; 32],
    ) -> Result<Option<AcceptedXmrRemoteSweepResponseV23>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        let local = self.authenticate_local_transport_signer_binding(session_id)?;
        if local.chain_id != roster.chain_id {
            return Err(SessionStoreError::Quarantined);
        }
        let mut candidate = None;
        self.scan_xmr_remote_sweep_records(|record, envelope, payload| {
            if envelope.session_id != session_id || envelope.message_type != 0x1a {
                return Ok(());
            }
            if record.equivocation {
                return Err(SessionStoreError::Conflict);
            }
            let response = decode_xmr_response(payload)?;
            let request =
                self.load_xmr_remote_sweep_request_by_digest(response.request_message_digest())?;
            let decoded_request = decode_xmr_request(&request.payload)?;
            require_xmr_response_matches_request(
                &response,
                &request.payload,
                &request.message_digest,
            )?;
            self.require_xmr_remote_sweep_phase_v23(&decoded_request, current.phase())?;
            if request.chain_id != roster.chain_id
                || request.session_id != session_id
                || request.signer_id != local.participant_id
                || envelope.sender_id != local.participant_id
            {
                return Ok(());
            }
            if candidate
                .replace((envelope.sender_id, envelope.sequence))
                .is_some()
            {
                return Err(SessionStoreError::Conflict);
            }
            Ok(())
        })?;
        let Some((signer_id, sequence)) = candidate else {
            return Ok(None);
        };
        self.load_accepted_xmr_remote_sweep_response_handle(session_id, signer_id, sequence)
            .map(Some)
    }

    /// Recovers the unique outbound `0x19` authored by this Store's local
    /// requester. The caller cannot select its digest, sequence or payload.
    /// This lets a restart reuse the immutable canonical request even when a
    /// fresh F7 observation has a different tip-sensitive evidence digest.
    pub fn resume_xmr_remote_sweep_request_for_local_requester(
        &self,
        session_id: [u8; 32],
    ) -> Result<Option<AcceptedXmrRemoteSweepRequestV23>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session_id)?;
        let roster = self.load_transport_roster(session_id)?;
        let local = self.authenticate_local_transport_signer_binding(session_id)?;
        if local.chain_id != roster.chain_id {
            return Err(SessionStoreError::Quarantined);
        }
        let signer_id = xmr_counterparty(&roster, local.participant_id)?;
        let mut sequence = None;
        self.scan_xmr_remote_sweep_records(|record, envelope, payload| {
            if envelope.session_id == session_id && record.equivocation {
                return Err(SessionStoreError::Conflict);
            }
            if envelope.message_type != 0x19
                || envelope.session_id != session_id
                || envelope.sender_id != local.participant_id
            {
                return Ok(());
            }
            let request = decode_xmr_request(payload)?;
            self.require_xmr_remote_sweep_phase_v23(&request, current.phase())?;
            if sequence.replace(envelope.sequence).is_some() {
                return Err(SessionStoreError::Conflict);
            }
            Ok(())
        })?;
        let Some(sequence) = sequence else {
            return Ok(None);
        };
        let accepted = self.load_accepted_xmr_remote_sweep_request_handle(
            session_id,
            local.participant_id,
            sequence,
        )?;
        if accepted.signer_id != signer_id {
            return Err(SessionStoreError::Conflict);
        }
        Ok(Some(accepted))
    }

    /// Reissues an accepted `0x19` handle after restart.
    pub fn resume_xmr_remote_sweep_request(
        &self,
        session_id: [u8; 32],
        requester_id: [u8; 32],
        sequence: u64,
    ) -> Result<AcceptedXmrRemoteSweepRequestV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.load_accepted_xmr_remote_sweep_request_handle(session_id, requester_id, sequence)
    }

    /// Reissues the unique request whose complete canonical payload matches.
    pub fn resume_xmr_remote_sweep_request_exact(
        &self,
        session_id: [u8; 32],
        requester_id: [u8; 32],
        payload: &[u8],
    ) -> Result<AcceptedXmrRemoteSweepRequestV23, SessionStoreError> {
        let request = decode_xmr_request(payload)?;
        if request.session_id != session_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let _guard = self.operation_lock()?;
        let mut sequence = None;
        self.scan_xmr_remote_sweep_records(|record, envelope, candidate| {
            if envelope.message_type == 0x19
                && envelope.session_id == session_id
                && envelope.sender_id == requester_id
                && candidate == payload
            {
                if record.equivocation || sequence.replace(envelope.sequence).is_some() {
                    return Err(SessionStoreError::Conflict);
                }
            }
            Ok(())
        })?;
        self.load_accepted_xmr_remote_sweep_request_handle(
            session_id,
            requester_id,
            sequence.ok_or(SessionStoreError::SessionNotFound)?,
        )
    }

    /// Reissues the unique accepted response for an exact `0x19` digest.
    pub fn resume_xmr_remote_sweep_response_for_request(
        &self,
        session_id: [u8; 32],
        signer_id: [u8; 32],
        request_message_digest: [u8; 32],
    ) -> Result<AcceptedXmrRemoteSweepResponseV23, SessionStoreError> {
        if request_message_digest == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        let _guard = self.operation_lock()?;
        let mut sequence = None;
        self.scan_xmr_remote_sweep_records(|record, envelope, payload| {
            if envelope.message_type != 0x1a {
                return Ok(());
            }
            let response = decode_xmr_response(payload)?;
            if envelope.session_id == session_id
                && envelope.sender_id == signer_id
                && response.request_message_digest() == request_message_digest
            {
                if record.equivocation || sequence.replace(envelope.sequence).is_some() {
                    return Err(SessionStoreError::Conflict);
                }
            }
            Ok(())
        })?;
        self.load_accepted_xmr_remote_sweep_response_handle(
            session_id,
            signer_id,
            sequence.ok_or(SessionStoreError::SessionNotFound)?,
        )
    }

    /// Consumes an accepted response into a move-only import handoff. Exact
    /// retry is allowed because quorum/lease verification may be unavailable;
    /// durable uniqueness is enforced by response pairing/equivocation and by
    /// the actuator's atomic remote-custody marker.
    pub fn take_xmr_remote_sweep_for_import(
        &self,
        accepted: AcceptedXmrRemoteSweepResponseV23,
    ) -> Result<PreparedXmrRemoteSweepImportV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if accepted.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let durable = self.load_accepted_xmr_remote_sweep_response_handle(
            accepted.session_id,
            accepted.signer_id,
            accepted.sequence,
        )?;
        if durable.request_message_digest != accepted.request_message_digest
            || durable.response_message_digest != accepted.response_message_digest
            || durable.transaction_hash != accepted.transaction_hash
            || durable.key_image != accepted.key_image
            || durable.response_wire_digest != accepted.response_wire_digest
            || durable.payload != accepted.payload
            || durable.record_digest != accepted.record_digest
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let request =
            self.load_xmr_remote_sweep_request_by_digest(accepted.request_message_digest)?;
        let current = self.load_session_locked(accepted.session_id)?;
        let decoded_request = decode_xmr_request(&request.payload)?;
        self.require_xmr_remote_sweep_phase_v23(&decoded_request, current.phase())?;
        Ok(PreparedXmrRemoteSweepImportV23 {
            session_id: accepted.session_id,
            request_message_digest: accepted.request_message_digest,
            response_message_digest: accepted.response_message_digest,
            response_wire_digest: accepted.response_wire_digest,
            transaction_hash: accepted.transaction_hash,
            key_image: accepted.key_image,
            request_payload: request.payload,
            response_payload: accepted.payload,
        })
    }

    pub(super) fn require_bounded_xmr_remote_sweep_transport_edge(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        signed_bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let payload = envelope.payload(signed_bytes)?;
        let roster = self.load_transport_roster(current.session_id())?;
        if roster.chain_id != envelope.chain_id
            || current.session_id() != envelope.session_id
            || successor.phase() != current.phase()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match envelope.message_type {
            0x19 => {
                let request = decode_xmr_request(payload)?;
                if request.session_id != envelope.session_id {
                    return Err(SessionStoreError::InvalidTransition);
                }
                self.require_xmr_remote_sweep_phase_v23(&request, current.phase())?;
                xmr_counterparty(&roster, envelope.sender_id)?;
                self.require_unique_xmr_remote_sweep_request(
                    current.session_id(),
                    &request,
                    envelope.message_digest,
                )?;
            }
            0x1a => {
                let response = decode_xmr_response(payload)?;
                let request = self
                    .load_xmr_remote_sweep_request_by_digest(response.request_message_digest())?;
                require_xmr_response_matches_request(
                    &response,
                    &request.payload,
                    &request.message_digest,
                )?;
                let decoded_request = decode_xmr_request(&request.payload)?;
                self.require_xmr_remote_sweep_phase_v23(&decoded_request, current.phase())?;
                if request.chain_id != envelope.chain_id
                    || request.session_id != envelope.session_id
                    || request.signer_id != envelope.sender_id
                {
                    return Err(SessionStoreError::InvalidTransition);
                }
                self.require_unique_xmr_remote_sweep_response(
                    current.session_id(),
                    request.message_digest,
                    envelope.message_digest,
                )?;
            }
            _ => return Err(SessionStoreError::InvalidTransition),
        }
        require_transport_successor(current, envelope, direction, successor)
    }

    pub(super) fn require_static_xmr_remote_sweep_request_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
    ) -> Result<(), SessionStoreError> {
        let decoded = decode_xmr_request(&request.payload)?;
        let predecessor =
            self.load_session_revision(request.session_id, request.predecessor_revision)?;
        let expected = xmr_remote_sweep_request_authority_digest(
            &self._store_id,
            &request.session_id,
            predecessor.digest(),
            &request.payload,
        );
        let roster = self.load_transport_roster(request.session_id)?;
        if request.authority_digest != expected
            || request.chain_id != roster.chain_id
            || decoded.session_id != request.session_id
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        xmr_counterparty(&roster, request.sender_id)?;
        self.require_xmr_remote_sweep_phase_v23(&decoded, predecessor.phase())
    }

    pub(super) fn require_static_xmr_remote_sweep_response_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
    ) -> Result<(), SessionStoreError> {
        let response = decode_xmr_response(&request.payload)?;
        let linked =
            self.load_xmr_remote_sweep_request_by_digest(response.request_message_digest())?;
        require_xmr_response_matches_request(&response, &linked.payload, &linked.message_digest)?;
        if request.authority_digest != linked.record_digest
            || request.session_id != linked.session_id
            || request.chain_id != linked.chain_id
            || request.sender_id != linked.signer_id
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn load_accepted_xmr_remote_sweep_request_handle(
        &self,
        session_id: [u8; 32],
        requester_id: [u8; 32],
        sequence: u64,
    ) -> Result<AcceptedXmrRemoteSweepRequestV23, SessionStoreError> {
        let record =
            self.load_xmr_remote_sweep_transport_record(session_id, requester_id, sequence)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)?;
        if record.equivocation || envelope.message_type != 0x19 {
            return Err(SessionStoreError::InvalidTransition);
        }
        let payload = envelope.payload(&record.signed_bytes)?.to_vec();
        let _ = decode_xmr_request(&payload)?;
        let roster = self.load_transport_roster(session_id)?;
        Ok(AcceptedXmrRemoteSweepRequestV23 {
            session_id,
            requester_id,
            signer_id: xmr_counterparty(&roster, requester_id)?,
            sequence,
            message_digest: envelope.message_digest,
            record_digest: record.record_digest()?,
            payload,
            open_instance_id: self.open_instance_id,
        })
    }

    fn authenticate_accepted_xmr_remote_sweep_request(
        &self,
        handle: &AcceptedXmrRemoteSweepRequestV23,
    ) -> Result<AuthenticatedXmrRemoteSweepRequestV23, SessionStoreError> {
        if handle.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let issued = self.load_accepted_xmr_remote_sweep_request_handle(
            handle.session_id,
            handle.requester_id,
            handle.sequence,
        )?;
        if issued.signer_id != handle.signer_id
            || issued.message_digest != handle.message_digest
            || issued.record_digest != handle.record_digest
            || issued.payload != handle.payload
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = self.load_xmr_remote_sweep_transport_record(
            handle.session_id,
            handle.requester_id,
            handle.sequence,
        )?;
        let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)?;
        Ok(AuthenticatedXmrRemoteSweepRequestV23 {
            chain_id: envelope.chain_id,
            session_id: handle.session_id,
            signer_id: handle.signer_id,
            message_digest: handle.message_digest,
            record_digest: handle.record_digest,
            payload: handle.payload.clone(),
        })
    }

    fn load_xmr_remote_sweep_request_by_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<AuthenticatedXmrRemoteSweepRequestV23, SessionStoreError> {
        if digest == [0; 32] {
            return Err(SessionStoreError::Canonical);
        }
        let mut found = None;
        self.scan_xmr_remote_sweep_records(|record, envelope, payload| {
            if envelope.message_type != 0x19 || envelope.message_digest != digest {
                return Ok(());
            }
            if record.equivocation || found.is_some() {
                return Err(SessionStoreError::Conflict);
            }
            let _ = decode_xmr_request(payload)?;
            let roster = self.load_transport_roster(envelope.session_id)?;
            found = Some(AuthenticatedXmrRemoteSweepRequestV23 {
                chain_id: envelope.chain_id,
                session_id: envelope.session_id,
                signer_id: xmr_counterparty(&roster, envelope.sender_id)?,
                message_digest: envelope.message_digest,
                record_digest: record.record_digest()?,
                payload: payload.to_vec(),
            });
            Ok(())
        })?;
        found.ok_or(SessionStoreError::SessionNotFound)
    }

    fn load_accepted_xmr_remote_sweep_response_handle(
        &self,
        session_id: [u8; 32],
        signer_id: [u8; 32],
        sequence: u64,
    ) -> Result<AcceptedXmrRemoteSweepResponseV23, SessionStoreError> {
        let record =
            self.load_xmr_remote_sweep_transport_record(session_id, signer_id, sequence)?;
        let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)?;
        if record.equivocation || envelope.message_type != 0x1a {
            return Err(SessionStoreError::InvalidTransition);
        }
        let payload = envelope.payload(&record.signed_bytes)?.to_vec();
        let response = decode_xmr_response(&payload)?;
        let request =
            self.load_xmr_remote_sweep_request_by_digest(response.request_message_digest())?;
        require_xmr_response_matches_request(&response, &request.payload, &request.message_digest)?;
        Ok(AcceptedXmrRemoteSweepResponseV23 {
            session_id,
            signer_id,
            sequence,
            request_message_digest: request.message_digest,
            response_message_digest: envelope.message_digest,
            transaction_hash: response.transaction_hash(),
            key_image: response.key_image(),
            response_wire_digest: response
                .digest()
                .map_err(|_| SessionStoreError::Canonical)?,
            payload,
            record_digest: record.record_digest()?,
            open_instance_id: self.open_instance_id,
        })
    }

    fn load_xmr_remote_sweep_transport_record(
        &self,
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
    ) -> Result<TransportMessageRecordV1, SessionStoreError> {
        let name = transport_message_name(session_id, sender_id, sequence, false);
        let bytes = self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        let record = TransportMessageRecordV1::from_bytes(&bytes)?;
        self.authenticate_transport_record(&name, &record)?;
        Ok(record)
    }

    fn require_unique_xmr_remote_sweep_request(
        &self,
        session_id: [u8; 32],
        candidate: &RemoteSweepRequestV23,
        candidate_digest: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        self.scan_xmr_remote_sweep_records(|_, envelope, payload| {
            if envelope.message_type == 0x19 && envelope.session_id == session_id {
                let request = decode_xmr_request(payload)?;
                if request.funding_tx_hash == candidate.funding_tx_hash
                    && request.funding_output_index == candidate.funding_output_index
                    && envelope.message_digest != candidate_digest
                {
                    return Err(SessionStoreError::Conflict);
                }
            }
            Ok(())
        })
    }

    fn require_unique_xmr_remote_sweep_response(
        &self,
        session_id: [u8; 32],
        request_digest: [u8; 32],
        candidate_digest: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        self.scan_xmr_remote_sweep_records(|_, envelope, payload| {
            if envelope.message_type == 0x1a && envelope.session_id == session_id {
                let response = decode_xmr_response(payload)?;
                if response.request_message_digest() == request_digest
                    && envelope.message_digest != candidate_digest
                {
                    return Err(SessionStoreError::Conflict);
                }
            }
            Ok(())
        })
    }

    fn scan_xmr_remote_sweep_records<F>(&self, mut visit: F) -> Result<(), SessionStoreError>
    where
        F: FnMut(
            &TransportMessageRecordV1,
            &ParsedTransportEnvelopeV1,
            &[u8],
        ) -> Result<(), SessionStoreError>,
    {
        let mut failure = None;
        self.messages
            .scan_lexicographic(|name, node| {
                if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                if !name.ends_with(".message") {
                    return Ok(());
                }
                let outcome = (|| {
                    let bytes = self.messages.read_bounded_file(
                        &ValidatedComponent::registered(name)?,
                        TRANSPORT_MESSAGE_MAX_LEN,
                    )?;
                    let record = TransportMessageRecordV1::from_bytes(&bytes)?;
                    let (envelope, _) = self.authenticate_transport_record(name, &record)?;
                    if matches!(envelope.message_type, 0x19 | 0x1a) {
                        visit(&record, &envelope, envelope.payload(&record.signed_bytes)?)?;
                    }
                    Ok::<(), SessionStoreError>(())
                })();
                if let Err(error) = outcome {
                    failure = Some(error);
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                Ok(())
            })
            .map_err(|error| failure.take().unwrap_or_else(|| error.into()))?;
        Ok(())
    }
}

pub(super) fn validate_xmr_remote_sweep_payload(
    message_type: u8,
    payload: &[u8],
) -> Result<(), SessionStoreError> {
    match message_type {
        0x19 => {
            decode_xmr_request(payload)?;
        }
        0x1a => {
            decode_xmr_response(payload)?;
        }
        _ => return Err(SessionStoreError::InvalidTransition),
    }
    Ok(())
}

fn decode_xmr_request(payload: &[u8]) -> Result<RemoteSweepRequestV23, SessionStoreError> {
    if payload.len() > MAX_REMOTE_SWEEP_REQUEST_BYTES_V23 {
        return Err(SessionStoreError::Canonical);
    }
    RemoteSweepRequestV23::decode_exact(payload).map_err(|_| SessionStoreError::Canonical)
}

fn decode_xmr_response(payload: &[u8]) -> Result<RemoteSweepResponseV23, SessionStoreError> {
    if payload.len() > MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23 {
        return Err(SessionStoreError::Canonical);
    }
    RemoteSweepResponseV23::decode_exact(payload).map_err(|_| SessionStoreError::Canonical)
}

fn require_xmr_response_matches_request(
    response: &RemoteSweepResponseV23,
    request_payload: &[u8],
    request_message_digest: &[u8; 32],
) -> Result<(), SessionStoreError> {
    let request = decode_xmr_request(request_payload)?;
    response
        .validate_for_authenticated_request(&request, *request_message_digest)
        .map_err(|_| SessionStoreError::InvalidTransition)
}

fn require_xmr_remote_sweep_phase(
    action: RemoteSweepActionV23,
    phase: SessionPhaseV1,
) -> Result<(), SessionStoreError> {
    let valid = match action {
        RemoteSweepActionV23::Claim => matches!(
            phase,
            SessionPhaseV1::FundingConfirmed | SessionPhaseV1::ClaimBroadcast
        ),
        RemoteSweepActionV23::Refund => matches!(
            phase,
            SessionPhaseV1::RefundEligible | SessionPhaseV1::RefundBroadcast
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(SessionStoreError::InvalidTransition)
    }
}

fn xmr_counterparty(
    roster: &TransportRosterRecordV1,
    participant_id: [u8; 32],
) -> Result<[u8; 32], SessionStoreError> {
    if roster.participants[0].participant_id == participant_id {
        Ok(roster.participants[1].participant_id)
    } else if roster.participants[1].participant_id == participant_id {
        Ok(roster.participants[0].participant_id)
    } else {
        Err(SessionStoreError::InvalidTransition)
    }
}

fn xmr_remote_sweep_request_authority_digest(
    store_id: &[u8; 32],
    session_id: &[u8; 32],
    predecessor_digest: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(96 + payload.len());
    bytes.extend_from_slice(store_id);
    bytes.extend_from_slice(session_id);
    bytes.extend_from_slice(predecessor_digest);
    bytes.extend_from_slice(payload);
    tagged_hash(
        "DOM:contracts-xmr-remote-sweep-request-authority:v23",
        &bytes,
    )
}
