//! Portable PUBLIC early/BP evidence for native graph-record revalidation.
//! A decoded journal is untrusted. Verification always receives the owner's
//! authenticated roster and expected economic scope; it grants no signing.
use super::*;
use dom_scriptless_crypto::{
    freeze_shared_output_statement_v1, SharedOutputContributionV1, SharedOutputInputsV1,
};

const MAGIC: &[u8; 8] = b"DXOJ22\0\x01";
const MAX_BYTES: usize = 65536;

#[path = "xmr_graph_output_proof_cache_v24.rs"]
mod proof_cache_v24;

pub(super) struct XmrGraphOutputJournalV22 {
    early: EarlyTransportAuthorityRecordV1,
    bp: BpTransportAuthorityRecordV1,
    messages: [Vec<u8>; 17],
}

pub(super) struct ReconstructedXmrGraphOutputV22 {
    pub(super) formation: dom_scriptless_crypto::FrozenSharedOutputV1,
    pub(super) output: dom_adaptor::VerifiedSharedOutputV1,
    pub(super) proof_digest: [u8; 32],
}

impl XmrGraphOutputJournalV22 {
    /// Caller holds the Store operation lock and has audited native transport.
    pub(super) fn capture_locked(
        store: &ContractsSessionStoreV1,
        session: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        let early = store.load_early_transport_authority(session)?;
        let bp = store.load_bp_transport_authority(session)?;
        let mut ordered = BTreeMap::new();
        let prefix = format!("{}-", hex_lower(&session));
        store.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = store.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            store
                .authenticate_transport_record(name, &record)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.equivocation || record.successor.revision() > 17 {
                return Ok(());
            }
            let durable = store
                .load_session_revision(session, record.successor.revision())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if durable.as_bytes() != record.successor.as_bytes()
                || ordered
                    .insert(record.successor.revision(), record.signed_bytes)
                    .is_some()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            Ok(())
        })?;
        if ordered.len() != 17 || ordered.keys().copied().ne(1..=17) {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(Self {
            early,
            bp,
            messages: ordered
                .into_values()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| SessionStoreError::Canonical)?,
        })
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SessionStoreError> {
        let mut bytes = MAGIC.to_vec();
        for field in [self.early.bytes.as_slice(), self.bp.bytes.as_slice()]
            .into_iter()
            .chain(self.messages.iter().map(Vec::as_slice))
        {
            bytes.extend_from_slice(
                &u32::try_from(field.len())
                    .map_err(|_| SessionStoreError::CapacityExceeded)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(field);
            if bytes.len() > MAX_BYTES {
                return Err(SessionStoreError::CapacityExceeded);
            }
        }
        Ok(bytes)
    }

    /// Parsing does not authenticate the journal or confer an authority.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() > MAX_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(SessionStoreError::Canonical);
        }
        let mut position = 8usize;
        let mut field = || -> Result<&[u8], SessionStoreError> {
            let length_end = position
                .checked_add(4)
                .ok_or(SessionStoreError::Canonical)?;
            let length = u32::from_le_bytes(copy_array(
                bytes
                    .get(position..length_end)
                    .ok_or(SessionStoreError::Canonical)?,
            )?) as usize;
            let end = length_end
                .checked_add(length)
                .ok_or(SessionStoreError::Canonical)?;
            let value = bytes
                .get(length_end..end)
                .ok_or(SessionStoreError::Canonical)?;
            position = end;
            Ok(value)
        };
        let early = EarlyTransportAuthorityRecordV1::from_bytes(field()?)?;
        let bp = BpTransportAuthorityRecordV1::from_bytes(field()?)?;
        let mut messages = Vec::with_capacity(17);
        for _ in 0..17 {
            let message = field()?;
            ParsedTransportEnvelopeV1::parse(message)?;
            messages.push(message.to_vec());
        }
        if position != bytes.len() {
            return Err(SessionStoreError::Canonical);
        }
        let journal = Self {
            early,
            bp,
            messages: messages
                .try_into()
                .map_err(|_| SessionStoreError::Canonical)?,
        };
        if journal.encode()? != bytes {
            return Err(SessionStoreError::Canonical);
        }
        Ok(journal)
    }

    pub(super) fn verify(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        value: u64,
        roster: &TransportRosterRecordV1,
        expected: &dom_consensus::TransactionOutput,
    ) -> Result<[u8; 32], SessionStoreError> {
        let reconstructed = self.reconstruct(chain, session, terms, value, roster)?;
        if reconstructed.output.output() != expected {
            return Err(SessionStoreError::Conflict);
        }
        Ok(reconstructed.proof_digest)
    }

    /// Recreate native formation and range-proof objects from authenticated
    /// public messages. No private nonce or funding state is reconstructed.
    pub(super) fn reconstruct(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        value: u64,
        roster: &TransportRosterRecordV1,
    ) -> Result<ReconstructedXmrGraphOutputV22, SessionStoreError> {
        let early = &self.early;
        let bp = &self.bp;
        if early.chain_id != *chain.as_bytes()
            || early.session_id != session
            || early.terms_hash != terms
            || roster.chain_id != *chain.as_bytes()
            || bp.chain_id != early.chain_id
            || bp.session_id != session
            || bp.terms_hash != terms
            || bp.early_authority_digest != early.digest
            || bp.round_start_revision != 6
            || bp.statement.recovery_binding_hash() != &early.recovery_binding_hash
            || blake2b_256(bp.recovery_capsule.as_bytes()).as_bytes()
                != &early.recovery_binding_hash
        {
            return Err(SessionStoreError::Conflict);
        }
        for participant in &early.participants {
            let identity = roster
                .participants
                .iter()
                .find(|p| p.participant_id == participant.participant_id)
                .ok_or(SessionStoreError::Conflict)?;
            if identity.direction != participant.direction {
                return Err(SessionStoreError::Conflict);
            }
        }
        let ids = early.participants.each_ref().map(|p| p.participant_id);
        let mut transcript = early.initial_transcript_hash;
        let mut sequences = [0u64; 2];
        let mut commitments = [None, None];
        let mut contributions = Vec::with_capacity(2);
        let mut bp_payloads = Vec::with_capacity(11);
        for (position, bytes) in self.messages.iter().enumerate() {
            let envelope = ParsedTransportEnvelopeV1::parse(bytes)?;
            let identity_index = roster
                .participants
                .iter()
                .position(|p| p.participant_id == envelope.sender_id)
                .ok_or(SessionStoreError::Conflict)?;
            let identity = &roster.participants[identity_index];
            envelope.verify(&identity.identity_key)?;
            if envelope.chain_id != *chain.as_bytes()
                || envelope.session_id != session
                || envelope.sequence != sequences[identity_index]
                || envelope.previous_transcript_hash != transcript
            {
                return Err(SessionStoreError::Conflict);
            }
            sequences[identity_index] = sequences[identity_index]
                .checked_add(1)
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let payload = envelope.payload(bytes)?;
            let phase = if position < 6 {
                let expected = early_transport_expected_item(position, roster)?;
                validate_early_transport_payload(
                    early,
                    expected,
                    envelope.sender_id,
                    envelope.message_type,
                    payload,
                    &mut commitments,
                )?;
                if envelope.message_type == 0x04 {
                    let reveal = EarlyShareRevealV1::from_bytes_against_frozen_context(
                        payload,
                        chain.as_bytes(),
                        &ids,
                        &early.context_commitment,
                    )
                    .map_err(|_| SessionStoreError::Canonical)?;
                    let share = reveal.statement();
                    contributions.push(SharedOutputContributionV1 {
                        participant_index: share.participant_index(),
                        participant_id: share.participant_id(),
                        role: share.role(),
                        commitment_share: share.share_point().clone(),
                        proof: dom_adaptor::ShareProofV1::from_bytes(&reveal.proof().to_bytes())
                            .map_err(|_| SessionStoreError::Canonical)?,
                    });
                }
                expected.phase
            } else {
                let bp_position = position - 6;
                let expected_type = if bp_position < 10 {
                    0x05 + (bp_position / 2) as u8
                } else {
                    0x0a
                };
                if envelope.message_type != expected_type
                    || (bp_position < 10 && envelope.sender_id != ids[bp_position % 2])
                {
                    return Err(SessionStoreError::Conflict);
                }
                bp_payloads.push(payload);
                match expected_type {
                    0x05 => SessionPhaseV1::BpCommonCommitted,
                    0x06 => SessionPhaseV1::BpCommonEstablished,
                    0x07 => SessionPhaseV1::BpNonceCommitted,
                    0x08 => SessionPhaseV1::BpRound1Complete,
                    0x09 => SessionPhaseV1::BpRound2Complete,
                    0x0a => SessionPhaseV1::OutputFinalized,
                    _ => return Err(SessionStoreError::Canonical),
                }
            };
            transcript = accepted_transport_transcript_hash(
                &transcript,
                &envelope.message_digest,
                identity.direction,
                envelope.message_type,
                phase,
            )?;
            if position == 5 && transcript != bp.round_start_transcript_hash {
                return Err(SessionStoreError::Conflict);
            }
        }
        contributions.sort_by_key(|p| p.participant_index);
        let frozen = freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
            chain_id: chain,
            session_id: session,
            contributions: &contributions,
            value_noms: value,
            terms_hash: terms,
            recovery_binding_hash: early.recovery_binding_hash,
        })
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if frozen.statement().to_bytes() != bp.statement.to_bytes() {
            return Err(SessionStoreError::Conflict);
        }
        // All scope, identity, transcript and contribution checks above run
        // on EVERY reconstruction. Only deterministic public proof checking
        // can reuse an exact-byte success; this does not cache Store authority.
        let output = verified_public_output_v24(
            &bp.statement,
            &bp.recovery_capsule,
            &bp_payloads,
            frozen.aggregate_commitment(),
        )?;
        Ok(ReconstructedXmrGraphOutputV22 {
            formation: frozen,
            output,
            proof_digest: *blake2b_256(bp_payloads[10]).as_bytes(),
        })
    }
}

fn verified_public_output_v24(
    statement: &BpStatementV1,
    capsule: &RecoveryCapsule,
    payloads: &[&[u8]],
    commitment: &[u8; 33],
) -> Result<dom_adaptor::VerifiedSharedOutputV1, SessionStoreError> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<
        Mutex<proof_cache_v24::ExactProofCacheV24<dom_adaptor::VerifiedSharedOutputV1>>,
    > = OnceLock::new();
    let key = proof_cache_v24::key(
        statement.to_bytes(),
        capsule.as_bytes(),
        payloads,
        commitment,
    );
    proof_cache_v24::verified(
        CACHE.get_or_init(|| Mutex::new(proof_cache_v24::ExactProofCacheV24::new())),
        key,
        || verify_public_output_uncached_v24(statement, capsule, payloads, commitment),
    )
}

fn verify_public_output_uncached_v24(
    statement: &BpStatementV1,
    capsule: &RecoveryCapsule,
    payloads: &[&[u8]],
    commitment: &[u8; 33],
) -> Result<dom_adaptor::VerifiedSharedOutputV1, SessionStoreError> {
    // Miss, contention, poison or an uncacheable input uses BOTH original
    // verifiers. No signing or nonce operation lives here.
    verify_bp_payloads(statement, capsule, payloads)?;
    let output = dom_consensus::TransactionOutput::with_recovery_capsule(
        dom_crypto::pedersen::Commitment::from_compressed_bytes(commitment)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?,
        payloads[10].to_vec(),
        capsule,
    )
    .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    dom_adaptor::VerifiedSharedOutputV1::from_retained_output_v14(&output, commitment)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)
}

fn verify_bp_payloads(
    statement: &BpStatementV1,
    capsule: &RecoveryCapsule,
    payloads: &[&[u8]],
) -> Result<(), SessionStoreError> {
    if payloads.len() != 11 {
        return Err(SessionStoreError::Canonical);
    }
    let mut round1 = Vec::with_capacity(2);
    let mut round2 = Vec::with_capacity(2);
    let mut commitments = [[0u8; 32]; 2];
    for index in 0..2 {
        let common: [u8; 32] = copy_array(payloads[index])?;
        let reveal: [u8; 32] = copy_array(payloads[2 + index])?;
        let mut preimage = [0u8; 96];
        preimage[..32].copy_from_slice(&statement.statement_hash());
        preimage[32..64].copy_from_slice(&statement.participant_ids()[index]);
        preimage[64..].copy_from_slice(&reveal);
        if tagged_hash(DomainTag::BpCommonCommit.as_str(), &preimage) != common {
            return Err(SessionStoreError::Conflict);
        }
        commitments[index] = copy_array(payloads[4 + index])?;
        for (payload, length) in [
            (payloads[6 + index], BpRound1ShareV1::ENCODED_LEN),
            (payloads[8 + index], BpRound2ShareV1::ENCODED_LEN),
        ] {
            if payload.len() != length
                || payload[38..70] != statement.participant_ids()[index]
                || u16::from_le_bytes(copy_array(&payload[70..72])?) as usize != index
            {
                return Err(SessionStoreError::Conflict);
            }
        }
        let share = BpRound1ShareV1::from_bytes(payloads[6 + index], statement)
            .map_err(|_| SessionStoreError::Canonical)?;
        if share.reveal_commitment() != commitments[index] {
            return Err(SessionStoreError::Conflict);
        }
        round1.push(share);
        round2.push(
            BpRound2ShareV1::from_bytes(payloads[8 + index], statement)
                .map_err(|_| SessionStoreError::Canonical)?,
        );
    }
    AggregateBpRound1::new(statement, &commitments, &round1)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    AggregateBpRound2::new(statement, round2)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    let proof = RangeProof739::try_from(payloads[10]).map_err(|_| SessionStoreError::Canonical)?;
    DomCollaborativeRangeProofV1::new(statement, capsule.as_bytes().to_vec())
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?
        .verify_final(statement, &proof)
        .map_err(|_| SessionStoreError::InvalidDomTransaction)
}
