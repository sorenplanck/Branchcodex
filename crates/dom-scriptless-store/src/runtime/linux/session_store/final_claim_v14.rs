//! Universal F7 claim adaptation and irreversible, Store-owned exposure.
//!
//! No Bitcoin authority or caller-supplied signed transaction enters this path.
//! The retained native funding, claim template and six-message signing round
//! determine every byte. Submission is possible only after exposure and its
//! session successor are durable. Recovery reuses the retained transaction.
use super::*;
use dom_adaptor::{AdaptorSecret, ScriptlessTransactionTemplateV1, VerifiedSharedOutputV1};

pub(super) const EXPOSURE_MAX_V14: usize = OPERATIONAL_FINAL_CLAIM_EXPOSURE_V2_RECORD_MAX_LEN;
pub(super) const ADMISSION_LEN_V14: usize = 8 + 32 * 5 + 2 + 32;
const EXPOSURE_DOMAIN: &str = "DOM-INTEROP/F7-FINAL-EXPOSURE/V14\0";
const ADMISSION_DOMAIN: &str = "DOM-INTEROP/F7-FINAL-ADMISSION/V14\0";
const EXPOSURE_PREFIX: usize = 24 + 10 * 32;

/// Public action binding authenticated again at the native exposure boundary.
pub struct F7FinalClaimActionV14 {
    /// Actual local identity; must be the immutable claim sender.
    pub participant_id: [u8; 32],
    /// Commitment to the coordinator's authorized action and ownership fence.
    pub action_scope_digest: [u8; 32],
    /// Must equal the fresh native F7 DOM tip retained by the authorization.
    pub validation_height: u64,
}

/// Exact transaction held privately until its irreversible exposure is durable.
/// No constructor, byte accessor, Clone, Debug or serializer is provided.
pub struct PreparedF7FinalClaimSubmissionV14 {
    session_id: [u8; 32],
    chain_id: [u8; 32],
    tx_hash: [u8; 32],
    exposure_digest: [u8; 32],
    action_scope_digest: [u8; 32],
    open_instance_id: [u8; 32],
    bytes: Vec<u8>,
}
impl PreparedF7FinalClaimSubmissionV14 {
    /// Native leg session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Frozen DOM chain identity.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
    /// Identifier recomputed from the exact retained bytes.
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    /// Authenticated irreversible record identity.
    pub const fn exposure_digest(&self) -> [u8; 32] {
        self.exposure_digest
    }
    /// Exact retained route-action commitment.
    pub const fn action_scope_digest(&self) -> [u8; 32] {
        self.action_scope_digest
    }
    /// Send only the retained bytes through the concrete DOM adapter.
    /// The actuator must bind that adapter to the selected DOM deployment.
    pub fn submit_with(
        &self,
        adapter: &DomHttpChainAdapterV1,
    ) -> Result<SubmissionReceiptV1, ChainAdapterError> {
        adapter.submit_canonical_transaction(&self.bytes)
    }
}

/// Native admission of the exact exposed transaction, never a local success flag.
pub struct AdmittedF7FinalClaimV14 {
    session_id: [u8; 32],
    tx_hash: [u8; 32],
    exposure_digest: [u8; 32],
    admission_digest: [u8; 32],
    open_instance_id: [u8; 32],
    receipt_state: dom_scriptless_chain_adapter::SubmissionStateV1,
    relayed: bool,
    receipt_digest: [u8; 32],
}
impl AdmittedF7FinalClaimV14 {
    /// Native leg session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Exact economically admitted transaction.
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    /// Durable admission record identity.
    pub const fn admission_digest(&self) -> [u8; 32] {
        self.admission_digest
    }
    /// Exact irreversible exposure authenticated by this admission.
    pub const fn exposure_digest(&self) -> [u8; 32] {
        self.exposure_digest
    }
    /// Original authenticated node state, retained without manufacturing a receipt.
    pub const fn receipt_state(&self) -> dom_scriptless_chain_adapter::SubmissionStateV1 {
        self.receipt_state
    }
    /// Original authenticated relay fact.
    pub const fn was_relayed(&self) -> bool {
        self.relayed
    }
    /// Native commitment to the original receipt facts.
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

struct ExposureV14 {
    bytes: Vec<u8>,
    hashes: [[u8; 32]; 10],
    validation_height: u64,
    predecessor_revision: u64,
    transaction: Vec<u8>,
    successor: SessionRecordV1,
    digest: [u8; 32],
}
impl ExposureV14 {
    fn encode(
        hashes: [[u8; 32]; 10],
        validation_height: u64,
        predecessor_revision: u64,
        transaction: &[u8],
        successor: &SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let mut bytes = b"DOMFCX14".to_vec();
        bytes.extend_from_slice(&validation_height.to_le_bytes());
        bytes.extend_from_slice(&predecessor_revision.to_le_bytes());
        for value in hashes {
            bytes.extend_from_slice(&value);
        }
        put_blob(&mut bytes, transaction)?;
        put_blob(&mut bytes, successor.as_bytes())?;
        let digest = tagged_hash(EXPOSURE_DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < EXPOSURE_PREFIX + 8 + 32
            || bytes.len() > EXPOSURE_MAX_V14
            || &bytes[..8] != b"DOMFCX14"
            || tagged_hash(EXPOSURE_DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut hashes = [[0; 32]; 10];
        for (i, h) in hashes.iter_mut().enumerate() {
            *h = copy_array(&bytes[24 + i * 32..56 + i * 32])?;
        }
        if hashes.contains(&[0; 32]) {
            return Err(SessionStoreError::Quarantined);
        }
        let height = u64::from_le_bytes(copy_array(&bytes[8..16])?);
        let revision = u64::from_le_bytes(copy_array(&bytes[16..24])?);
        let mut cursor = EXPOSURE_PREFIX;
        let transaction =
            take_blob(bytes, &mut cursor, OPERATIONAL_FINAL_REFUND_PAYLOAD_MAX_LEN)?.to_vec();
        let successor =
            SessionRecordV1::from_bytes(take_blob(bytes, &mut cursor, SESSION_RECORD_MAX_LEN)?)?;
        if cursor != bytes.len() - 32
            || height == 0
            || successor.session_id() != hashes[0]
            || successor.revision()
                != revision
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
            || !successor.irreversible().adaptor_secret_exposed
            || canonical_transaction_hash_v1(&transaction)
                .map_err(|_| SessionStoreError::Quarantined)?
                != hashes[7]
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            hashes,
            validation_height: height,
            predecessor_revision: revision,
            transaction,
            successor,
            digest: copy_array(&bytes[bytes.len() - 32..])?,
        })
    }
    fn submission(&self, open_instance_id: [u8; 32]) -> PreparedF7FinalClaimSubmissionV14 {
        PreparedF7FinalClaimSubmissionV14 {
            session_id: self.hashes[0],
            chain_id: self.hashes[1],
            tx_hash: self.hashes[7],
            exposure_digest: self.digest,
            action_scope_digest: self.hashes[6],
            open_instance_id,
            bytes: self.transaction.clone(),
        }
    }
}

struct AdmissionV14 {
    bytes: Vec<u8>,
    session: [u8; 32],
    exposure: [u8; 32],
    txid: [u8; 32],
    digest: [u8; 32],
}
impl AdmissionV14 {
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != ADMISSION_LEN_V14
            || &bytes[..8] != b"DOMFAD14"
            || tagged_hash(ADMISSION_DOMAIN, &bytes[..ADMISSION_LEN_V14 - 32])
                != bytes[ADMISSION_LEN_V14 - 32..]
            || bytes[169] > 1
        {
            return Err(SessionStoreError::Quarantined);
        }
        for value in bytes[8..168].chunks_exact(32) {
            if value == [0; 32] {
                return Err(SessionStoreError::Quarantined);
            }
        }
        // Receipt state is rechecked against the native adapter tags below.
        let state = match bytes[168] {
            1 => dom_scriptless_chain_adapter::SubmissionStateV1::New,
            2 => dom_scriptless_chain_adapter::SubmissionStateV1::Mempool,
            3 => dom_scriptless_chain_adapter::SubmissionStateV1::Confirmed,
            _ => return Err(SessionStoreError::Quarantined),
        };
        dom_scriptless_chain_adapter::validate_submission_receipt_facts_v1(
            copy_array(&bytes[72..104])?,
            state,
            bytes[169] == 1,
            copy_array(&bytes[104..136])?,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            session: copy_array(&bytes[8..40])?,
            exposure: copy_array(&bytes[40..72])?,
            txid: copy_array(&bytes[72..104])?,
            digest: copy_array(&bytes[170..202])?,
        })
    }
}

struct ClaimSinkV14<'a> {
    store: &'a ContractsSessionStoreV1,
    authority: &'a ConsumedF7ClaimAuthorizationV12,
    action: &'a F7FinalClaimActionV14,
    chain: TrustedChainIdV1,
}
impl OperationalClaimTransactionSinkV1 for ClaimSinkV14<'_> {
    type Error = SessionStoreError;
    type PersistedClaim = PreparedF7FinalClaimSubmissionV14;
    fn persist_verified_claim(
        &mut self,
        claim: OperationalClaimPersistenceCapabilityV1,
    ) -> Result<Self::PersistedClaim, Self::Error> {
        self.store
            .persist_f7_claim_exposure_v14(self.authority, self.chain, self.action, claim)
    }
}

impl ContractsSessionStoreV1 {
    /// Adapt only the exact retained claim after fresh native F7 authorization
    /// and the accepted bilateral pre-signature, then persist before returning.
    /// The secret remains borrowed and never appears in a journal or error.
    pub fn finalize_and_persist_f7_claim_v14(
        &self,
        authority: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
        action: &F7FinalClaimActionV14,
        secret: &AdaptorSecret,
    ) -> Result<PreparedF7FinalClaimSubmissionV14, SessionStoreError> {
        let claim = {
            let _guard = self.operation_lock()?;
            let (gate, issued, current) =
                self.require_f7_claim_sender_v14(authority, chain, action)?;
            self.require_f7_claim_unexposed_v14(issued.session_id)?;
            let pre = self.load_f7_pre_v12(issued.session_id)?;
            self.require_f7_pre_accepted_v14(&pre, &current)?;
            let funding = self.load_f7_funding_v12(&gate)?;
            let funding = Transaction::from_bytes(&funding.funding_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?;
            let commitment = gate.role.shared_output_commitment();
            let mut outputs = funding
                .outputs
                .iter()
                .filter(|o| o.commitment.as_bytes() == &commitment);
            let shared = outputs.next().ok_or(SessionStoreError::Quarantined)?;
            if outputs.next().is_some() {
                return Err(SessionStoreError::Quarantined);
            }
            let shared = VerifiedSharedOutputV1::from_retained_output_v14(shared, &commitment)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
            let tx = Transaction::from_bytes(&gate.claim_template)
                .map_err(|_| SessionStoreError::Quarantined)?;
            if tx.kernels.len() != 1 {
                return Err(SessionStoreError::Quarantined);
            }
            let template = ScriptlessTransactionTemplateV1::claim(
                &shared,
                tx.outputs.clone(),
                tx.kernels[0].clone(),
                tx.offset,
            )
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
            if template.template_hash() != &issued.claim_template_hash {
                return Err(SessionStoreError::Quarantined);
            }
            template
                .finalize_claim(
                    &pre.pre_signature,
                    secret,
                    &pre.reveal_transcript_hash,
                    chain.as_bytes(),
                    action.validation_height,
                )
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?
        };
        // The sink reacquires the native operation lock and repeats all live
        // authority checks. No adapted bytes leave during this lock boundary.
        claim.persist_with_claim_sink_v1(&mut ClaimSinkV14 {
            store: self,
            authority,
            action,
            chain,
        })
    }

    fn require_f7_claim_sender_v14(
        &self,
        authority: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
        action: &F7FinalClaimActionV14,
    ) -> Result<(F7GateRecordV12, F7ClaimRecordV12, SessionRecordV1), SessionStoreError> {
        let (gate, issued, current) = self.require_f7_consumed_handle_v12(authority)?;
        let signer = self.authenticate_local_transport_signer_binding(issued.session_id)?;
        if chain.as_bytes() != &issued.chain_id
            || action.participant_id != signer.participant_id
            || signer.participant_id != gate.role.dom_claim_sender_id().0
            || signer.participant_id == gate.role.final_claim_receiver_id().0
            || action.action_scope_digest == [0; 32]
            || action.validation_height == 0
            || action.validation_height != current.chain().tip_height
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok((gate, issued, current))
    }
    pub(super) fn require_f7_pre_accepted_v14(
        &self,
        pre: &F7PreRecordV12,
        current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        self.require_f7_pre_head_v12(pre, current)?;
        if current.transcript_hash() == pre.terminal_transcript_hash {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(())
    }
    fn require_f7_claim_unexposed_v14(&self, session: [u8; 32]) -> Result<(), SessionStoreError> {
        for (name, max) in [
            ("claim-exposure-v14", EXPOSURE_MAX_V14),
            ("claim-admission-v14", ADMISSION_LEN_V14),
        ] {
            match self.read_f7_v12(session, name, max) {
                Err(SessionStoreError::SessionNotFound) => {}
                Ok(_) => return Err(SessionStoreError::Conflict),
                Err(e) => return Err(e),
            }
        }
        if self.operational_final_claim_observation_exists_v2(session)?
            || self.f7_final_claim_observation_exists_v15(session)?
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }
    fn persist_f7_claim_exposure_v14(
        &self,
        authority: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
        action: &F7FinalClaimActionV14,
        claim: OperationalClaimPersistenceCapabilityV1,
    ) -> Result<PreparedF7FinalClaimSubmissionV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (gate, issued, current) = self.require_f7_claim_sender_v14(authority, chain, action)?;
        self.require_f7_claim_unexposed_v14(issued.session_id)?;
        let pre = self.load_f7_pre_v12(issued.session_id)?;
        self.require_f7_pre_accepted_v14(&pre, &current)?;
        claim
            .verify(chain.as_bytes(), action.validation_height)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if claim.template_hash() != &issued.claim_template_hash
            || claim.shared_output_commitment() != &gate.role.shared_output_commitment()
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        self.verify_f7_final_claim_bytes_v14(
            &gate,
            &issued,
            &pre,
            claim.canonical_bytes(),
            action.validation_height,
        )?;
        let mut irreversible = current.irreversible();
        irreversible.adaptor_secret_exposed = true;
        let successor = current.advance(
            current.revision(),
            current.phase(),
            current.transcript_hash(),
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        require_final_claim_exposure_delta_v1(&current, &successor)?;
        let txid = canonical_transaction_hash_v1(claim.canonical_bytes())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let exposure = ExposureV14::encode(
            [
                issued.session_id,
                issued.chain_id,
                gate.digest,
                issued.digest,
                issued.consumption_digest,
                pre.digest,
                action.action_scope_digest,
                txid,
                *current.digest(),
                self.open_instance_id,
            ],
            action.validation_height,
            current.revision(),
            claim.canonical_bytes(),
            &successor,
        )?;
        self.publish_f7_v12(
            issued.session_id,
            "claim-exposure-v14",
            &exposure.bytes,
            EXPOSURE_MAX_V14,
        )?;
        test_crash_hook("f7-v14-final-after-exposure");
        self.persist_session_record(&successor)?;
        test_crash_hook("f7-v14-final-after-successor");
        let durable = self.authenticate_f7_exposure_v14(issued.session_id)?;
        if durable.bytes != exposure.bytes
            || self.load_session_locked(issued.session_id)?.as_bytes() != successor.as_bytes()
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(durable.submission(self.open_instance_id))
    }

    pub(super) fn verify_f7_final_claim_bytes_v14(
        &self,
        gate: &F7GateRecordV12,
        issued: &F7ClaimRecordV12,
        pre: &F7PreRecordV12,
        bytes: &[u8],
        height: u64,
    ) -> Result<(), SessionStoreError> {
        let tx =
            Transaction::from_bytes(bytes).map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if canonical_dom_transaction_bytes_v1(&tx)? != bytes
            || tx.kernels.len() != 1
            || tx.inputs.len() != 1
            || tx.inputs[0].commitment.as_bytes() != &gate.role.shared_output_commitment()
            || canonical_template_v1(&tx)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?
                .1
                != issued.claim_template_hash
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        dom_consensus::validate_transaction(
            &tx,
            &dom_consensus::ValidationContext {
                current_height: dom_core::BlockHeight(height),
                chain_id: issued.chain_id,
                now: dom_core::Timestamp(0),
            },
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let kernel = &tx.kernels[0];
        let key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let message = *scriptless_kernel_message_digest_v1(kernel).as_bytes();
        let final_signature = SchnorrSignature::from_bytes(&kernel.excess_signature)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        pre.pre_signature
            .verify_final_signature_opens_adaptor_point_v1(
                &final_signature,
                &FinalSignatureOpeningContextV1 {
                    expected_claim_template_hash: &issued.claim_template_hash,
                    expected_transcript_hash: &pre.reveal_transcript_hash,
                    signing_key: &key,
                    chain_id: &issued.chain_id,
                    kernel_message: &message,
                },
            )
            .map_err(|_| SessionStoreError::InvalidDomTransaction)
    }

    fn authenticate_f7_exposure_v14(
        &self,
        session: [u8; 32],
    ) -> Result<ExposureV14, SessionStoreError> {
        let exposure = ExposureV14::decode(&self.read_f7_v12(
            session,
            "claim-exposure-v14",
            EXPOSURE_MAX_V14,
        )?)?;
        let (gate, issued, current) = self.authenticate_f7_claim_v12(session)?;
        let predecessor = self.load_session_revision(session, exposure.predecessor_revision)?;
        let pre = self.load_f7_pre_v12(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if exposure.hashes[0] != session
            || exposure.hashes[1] != issued.chain_id
            || exposure.hashes[2] != gate.digest
            || exposure.hashes[3] != issued.digest
            || exposure.hashes[4] != issued.consumption_digest
            || exposure.hashes[5] != pre.digest
            || exposure.hashes[8] != *predecessor.digest()
            || signer.participant_id != gate.role.dom_claim_sender_id().0
            || exposure.validation_height != predecessor.chain().tip_height
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.require_live_f7_claim_v12(&issued, &predecessor)?;
        self.require_f7_pre_accepted_v14(&pre, &predecessor)?;
        require_final_claim_exposure_delta_v1(&predecessor, &exposure.successor)?;
        self.verify_f7_final_claim_bytes_v14(
            &gate,
            &issued,
            &pre,
            &exposure.transaction,
            exposure.validation_height,
        )?;
        if current.revision() < exposure.successor.revision() {
            if current.as_bytes() != predecessor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
        } else {
            if self
                .load_session_revision(session, exposure.successor.revision())?
                .as_bytes()
                != exposure.successor.as_bytes()
                || !current.irreversible().adaptor_secret_exposed
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(exposure)
    }

    /// Recover an exposed claim without new nonces, secret access or fresh
    /// funding authority. Complete the exact interrupted successor first.
    pub fn resume_f7_final_claim_submission_v14(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        participant: [u8; 32],
        action_scope_digest: [u8; 32],
    ) -> Result<PreparedF7FinalClaimSubmissionV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if chain.as_bytes() != &exposure.hashes[1]
            || signer.participant_id != participant
            || exposure.hashes[6] != action_scope_digest
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.read_f7_v12(session, "claim-admission-v14", ADMISSION_LEN_V14) {
            Ok(_) => {
                self.authenticate_f7_admission_v14(session)?;
                return Err(SessionStoreError::Conflict);
            }
            Err(SessionStoreError::SessionNotFound) => {}
            Err(e) => return Err(e),
        }
        let head = self.load_session_locked(session)?;
        if head.revision() < exposure.successor.revision() {
            self.persist_session_record(&exposure.successor)?;
        }
        let current = self.load_session_locked(session)?;
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(exposure.submission(self.open_instance_id))
    }

    /// Consume a native node receipt for exactly the transaction persisted by
    /// this Store opening. A different txid is a hard refusal, never absence.
    pub fn complete_f7_final_claim_admission_v14(
        &self,
        prepared: PreparedF7FinalClaimSubmissionV14,
        receipt: SubmissionReceiptV1,
    ) -> Result<AdmittedF7FinalClaimV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if prepared.open_instance_id != self.open_instance_id
            || receipt.tx_hash() != prepared.tx_hash
            || !receipt.is_economically_admitted()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let exposure = self.authenticate_f7_exposure_v14(prepared.session_id)?;
        if exposure.digest != prepared.exposure_digest
            || exposure.transaction != prepared.bytes
            || exposure.hashes[1] != prepared.chain_id
            || exposure.hashes[6] != prepared.action_scope_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        if self.load_session_locked(prepared.session_id)?.revision() < exposure.successor.revision()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.read_f7_v12(
            prepared.session_id,
            "claim-admission-v14",
            ADMISSION_LEN_V14,
        ) {
            Ok(_) => return self.admitted_f7_handle_v14(prepared.session_id),
            Err(SessionStoreError::SessionNotFound) => {}
            Err(e) => return Err(e),
        }
        let mut bytes = b"DOMFAD14".to_vec();
        for h in [
            prepared.session_id,
            exposure.digest,
            prepared.tx_hash,
            receipt.receipt_digest_v1(),
            self.open_instance_id,
        ] {
            bytes.extend_from_slice(&h);
        }
        bytes.push(receipt.state().tag_v1());
        bytes.push(u8::from(receipt.was_relayed()));
        let digest = tagged_hash(ADMISSION_DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        self.publish_f7_v12(
            prepared.session_id,
            "claim-admission-v14",
            &bytes,
            ADMISSION_LEN_V14,
        )?;
        test_crash_hook("f7-v14-final-after-admission");
        self.admitted_f7_handle_v14(prepared.session_id)
    }
    fn authenticate_f7_admission_v14(
        &self,
        session: [u8; 32],
    ) -> Result<AdmissionV14, SessionStoreError> {
        let admission = AdmissionV14::decode(&self.read_f7_v12(
            session,
            "claim-admission-v14",
            ADMISSION_LEN_V14,
        )?)?;
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        if admission.session != session
            || admission.exposure != exposure.digest
            || admission.txid != exposure.hashes[7]
            || self.load_session_locked(session)?.revision() < exposure.successor.revision()
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(admission)
    }
    fn admitted_f7_handle_v14(
        &self,
        session: [u8; 32],
    ) -> Result<AdmittedF7FinalClaimV14, SessionStoreError> {
        let a = self.authenticate_f7_admission_v14(session)?;
        Ok(AdmittedF7FinalClaimV14 {
            session_id: session,
            tx_hash: a.txid,
            exposure_digest: a.exposure,
            admission_digest: a.digest,
            open_instance_id: self.open_instance_id,
            receipt_state: match a.bytes[168] {
                1 => dom_scriptless_chain_adapter::SubmissionStateV1::New,
                2 => dom_scriptless_chain_adapter::SubmissionStateV1::Mempool,
                3 => dom_scriptless_chain_adapter::SubmissionStateV1::Confirmed,
                _ => return Err(SessionStoreError::Quarantined),
            },
            relayed: a.bytes[169] == 1,
            receipt_digest: copy_array(&a.bytes[104..136])?,
        })
    }
    /// Reauthenticate a durable node admission after restart; no RPC occurs.
    pub fn resume_f7_final_claim_admission_v14(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<AdmittedF7FinalClaimV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        if chain.as_bytes() != &exposure.hashes[1] {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.admitted_f7_handle_v14(session)
    }

    pub(super) fn audit_f7_final_claim_inventory_v14(
        &self,
        session: [u8; 32],
        kinds: &BTreeSet<F7ArtifactKindV12>,
    ) -> Result<(), SessionStoreError> {
        use F7ArtifactKindV12 as K;
        if self
            .load_session_locked(session)?
            .irreversible()
            .adaptor_secret_exposed
            && !kinds.contains(&K::ExposureV14)
            && !kinds.contains(&K::ObservationV15)
        {
            return Err(SessionStoreError::Quarantined);
        }
        if kinds.contains(&K::ExposureV14) {
            if !kinds.contains(&K::Pre) {
                return Err(SessionStoreError::Quarantined);
            }
            self.authenticate_f7_exposure_v14(session)?;
        }
        if kinds.contains(&K::AdmissionV14) {
            if !kinds.contains(&K::ExposureV14) {
                return Err(SessionStoreError::Quarantined);
            }
            self.authenticate_f7_admission_v14(session)?;
        }
        Ok(())
    }

    /// Plan only the exact successor embedded in a fully authenticated exposure.
    /// Called by prepared-open recovery before any Store capability is returned.
    /// No mutation occurs until the complete recovery plan has been validated.
    pub(in super::super) fn plan_f7_final_claim_exposures_v14(
        &self,
    ) -> Result<Vec<SessionRecordV1>, SessionStoreError> {
        self.audit_f7_artifact_inventory_v12()?;
        let (sessions, _, _) = self.census_f7_artifacts_v12()?;
        let mut successors = Vec::new();
        for (session, kinds) in sessions {
            if !kinds.contains(&F7ArtifactKindV12::ExposureV14) {
                continue;
            }
            let exposure = self.authenticate_f7_exposure_v14(session)?;
            if self.load_session_locked(session)?.revision() < exposure.successor.revision() {
                successors.push(exposure.successor);
            }
        }
        Ok(successors)
    }

    pub(in super::super) fn f7_final_claim_exposure_exists_v14(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        match self.read_f7_v12(session, "claim-exposure-v14", EXPOSURE_MAX_V14) {
            Ok(bytes) => {
                validate_final_claim_artifact_v14(session, F7ArtifactKindV12::ExposureV14, &bytes)?;
                Ok(true)
            }
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub(super) fn validate_final_claim_artifact_v14(
    session: [u8; 32],
    kind: F7ArtifactKindV12,
    bytes: &[u8],
) -> Result<(), SessionStoreError> {
    match kind {
        F7ArtifactKindV12::ExposureV14 if ExposureV14::decode(bytes)?.hashes[0] == session => {
            Ok(())
        }
        F7ArtifactKindV12::AdmissionV14 if AdmissionV14::decode(bytes)?.session == session => {
            Ok(())
        }
        _ => Err(SessionStoreError::Quarantined),
    }
}

impl ContractsSessionStoreV1 {
    /// Issue the exact native 0x12 only after the matching node admission.
    pub fn prepare_f7_final_claim_dsc1_request_v14(
        &self,
        admitted: &AdmittedF7FinalClaimV14,
    ) -> Result<PreparedDsc1SigningRequestV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if admitted.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let admission = self.authenticate_f7_admission_v14(admitted.session_id)?;
        let exposure = self.authenticate_f7_exposure_v14(admitted.session_id)?;
        if admission.digest != admitted.admission_digest
            || exposure.digest != admitted.exposure_digest
            || admission.txid != admitted.tx_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        let current = self.load_session_locked(admitted.session_id)?;
        self.require_f7_final_claim_send_head_v14(&exposure, &current)?;
        let signer = self.authenticate_local_transport_signer_binding(admitted.session_id)?;
        let sequence = self.transport_sequence_at_revision(
            admitted.session_id,
            signer.participant_id,
            current.revision(),
        )?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::UniversalFinalClaimV14,
            chain_id: exposure.hashes[1],
            session_id: admitted.session_id,
            sender_id: signer.participant_id,
            sequence,
            previous_transcript_hash: current.transcript_hash(),
            predecessor: &current,
            authority_digest: exposure.digest,
            payload: &exposure.transaction,
        })
    }

    fn require_f7_final_claim_send_head_v14(
        &self,
        exposure: &ExposureV14,
        current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_projection_only_session_lineage(&exposure.successor, current)
    }

    pub(in super::super) fn audit_f7_final_claim_request_v14(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let exposure = self.authenticate_f7_exposure_v14(request.session_id)?;
        self.authenticate_f7_admission_v14(request.session_id)?;
        let signer = self.authenticate_local_transport_signer_binding(request.session_id)?;
        if request.authority_class != OutboundDsc1AuthorityClassV1::UniversalFinalClaimV14
            || request.chain_id != exposure.hashes[1]
            || request.authority_digest != exposure.digest
            || request.sender_id != signer.participant_id
            || request.payload != exposure.transaction
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_f7_final_claim_send_head_v14(&exposure, current)
    }

    pub(in super::super) fn expected_f7_final_claim_request_v14(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<([u8; 32], u64, [u8; 32]), SessionStoreError> {
        self.audit_f7_final_claim_request_v14(request, current)?;
        Ok((
            request.sender_id,
            self.transport_sequence_at_revision(
                request.session_id,
                request.sender_id,
                current.revision(),
            )?,
            current.transcript_hash(),
        ))
    }

    pub(in super::super) fn require_f7_final_claim_transport_edge_v14(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let session = current.session_id();
        if self.f7_final_claim_observation_exists_v15(session)? {
            return self.require_f7_final_claim_receiver_edge_v15(
                current, envelope, bytes, direction, successor,
            );
        }
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        self.authenticate_f7_admission_v14(session)?;
        self.require_f7_final_claim_send_head_v14(&exposure, current)?;
        let gate = self.load_f7_gate_v12(session)?;
        let roster = self.load_transport_roster(session)?;
        let sender = roster
            .participants
            .iter()
            .find(|p| p.participant_id == gate.role.dom_claim_sender_id().0)
            .ok_or(SessionStoreError::Quarantined)?;
        envelope.verify(&sender.identity_key)?;
        if envelope.message_type != 0x12
            || envelope.session_id != session
            || envelope.chain_id != exposure.hashes[1]
            || envelope.sender_id != sender.participant_id
            || direction != sender.direction
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    sender.participant_id,
                    current.revision(),
                )?
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.payload(bytes)? != exposure.transaction
            || successor.phase() != SessionPhaseV1::ClaimBroadcast
            || successor.irreversible() != current.irreversible()
            || successor.chain() != current.chain()
            || successor.encrypted_payload() != current.encrypted_payload()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        require_exact_successor(current, current.revision(), successor)?;
        if successor.transcript_hash()
            != accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                direction,
                0x12,
                SessionPhaseV1::ClaimBroadcast,
            )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
}

/// Reauthenticated public facts for the native actuator mirror. These facts
/// carry no signing, exposure, submission or transport permission.
pub struct F7FinalClaimFactsV14 {
    session: [u8; 32],
    chain: [u8; 32],
    terms: [u8; 32],
    sender: [u8; 32],
    receiver: [u8; 32],
    template: [u8; 32],
    shared: [u8; 33],
    evidence: [u8; 32],
    minimum_confirmations: u32,
}
impl F7FinalClaimFactsV14 {
    /// Native session identity.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session
    }
    /// Native DOM chain identity.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain
    }
    /// Immutable economic terms.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms
    }
    /// Frozen claim sender.
    pub const fn sender(&self) -> [u8; 32] {
        self.sender
    }
    /// Frozen claim receiver.
    pub const fn receiver(&self) -> [u8; 32] {
        self.receiver
    }
    /// Retained unsigned claim commitment.
    pub const fn template_hash(&self) -> [u8; 32] {
        self.template
    }
    /// Retained funding output commitment.
    pub const fn shared_commitment(&self) -> [u8; 33] {
        self.shared
    }
    /// Separate V14 evidence domain; never a Bitcoin authority digest.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence
    }
    /// Frozen DOM finality requirement.
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }
}
fn final_claim_facts_v14(
    gate: &F7GateRecordV12,
    issued: &F7ClaimRecordV12,
) -> F7FinalClaimFactsV14 {
    let mut bytes = Vec::with_capacity(4 * 32);
    for h in [
        gate.digest,
        issued.digest,
        issued.consumption_digest,
        gate.role.digest(),
    ] {
        bytes.extend_from_slice(&h);
    }
    F7FinalClaimFactsV14 {
        session: issued.session_id,
        chain: issued.chain_id,
        terms: issued.terms_hash,
        sender: gate.role.dom_claim_sender_id().0,
        receiver: gate.role.final_claim_receiver_id().0,
        template: issued.claim_template_hash,
        shared: gate.role.shared_output_commitment(),
        evidence: tagged_hash("DOM-INTEROP/F7-FINAL-ACTUATOR/V14\0", &bytes),
        minimum_confirmations: gate.role.terms().dom_leg.finality.min_confirmations,
    }
}
impl ContractsSessionStoreV1 {
    /// Recheck a live process-bound F7 authority before the actuator prepares
    /// an action. Reading these facts alone grants no exposure permission.
    pub fn revalidate_f7_final_claim_authority_v14(
        &self,
        authority: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
        participant: [u8; 32],
    ) -> Result<F7FinalClaimFactsV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (gate, issued, _) = self.require_f7_consumed_handle_v12(authority)?;
        let signer = self.authenticate_local_transport_signer_binding(issued.session_id)?;
        if chain.as_bytes() != &issued.chain_id
            || signer.participant_id != participant
            || participant != gate.role.dom_claim_sender_id().0
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(final_claim_facts_v14(&gate, &issued))
    }
    /// Reload the exact immutable native role/evidence facts after exposure.
    /// This does not recreate a consumed live signing authority.
    pub fn exposed_f7_final_claim_facts_v14(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<F7FinalClaimFactsV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        if chain.as_bytes() != &exposure.hashes[1] {
            return Err(SessionStoreError::InvalidTransition);
        }
        let (gate, issued, _) = self.authenticate_f7_claim_v12(session)?;
        Ok(final_claim_facts_v14(&gate, &issued))
    }
}

/// Audited durable sender progress. A status is not a signing capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum F7FinalClaimProgressV14 {
    /// Fresh F7 and the completed participant round are still required.
    NeedsAdaptation,
    /// Exact exposed bytes may be retried through the native admission boundary.
    Exposed,
    /// Native node admission is durable; the actuator mirror may need repair.
    Admitted,
    /// Signed 0x12 is durable and awaits Relay reconciliation.
    TransportCommitted,
    /// Exact 0x12 handoff is durably reconciled; this is not chain finality.
    TransportReconciled,
}

impl ContractsSessionStoreV1 {
    /// Inspect the sender lane, distinguishing absent records from malformed
    /// records. Once exposure exists, no branch returns to adaptation.
    pub fn f7_final_claim_progress_v14(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<F7FinalClaimProgressV14, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_f7_artifact_inventory_v12()?;
        let gate = self.load_f7_gate_v12(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if gate.chain_id != *chain.as_bytes()
            || signer.participant_id != gate.role.dom_claim_sender_id().0
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if !self.f7_final_claim_exposure_exists_v14(session)? {
            return Ok(F7FinalClaimProgressV14::NeedsAdaptation);
        }
        self.authenticate_f7_exposure_v14(session)?;
        match self.authenticate_f7_admission_v14(session) {
            Err(SessionStoreError::SessionNotFound) => return Ok(F7FinalClaimProgressV14::Exposed),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let (_, request) = match self.authenticate_f7_final_transport_v14(chain, session) {
            Err(SessionStoreError::SessionNotFound) => {
                if self.load_session_locked(session)?.phase() != SessionPhaseV1::FundingConfirmed {
                    return Err(SessionStoreError::Quarantined);
                }
                return Ok(F7FinalClaimProgressV14::Admitted);
            }
            Err(error) => return Err(error),
            Ok(value) => value,
        };
        let committed =
            self.load_committed_outbound_dsc1(session, request.sender_id, request.sequence)?;
        match self.load_reconciled_outbound_dsc1(session, request.sender_id, request.sequence) {
            Err(SessionStoreError::SessionNotFound) => {
                Ok(F7FinalClaimProgressV14::TransportCommitted)
            }
            Err(error) => Err(error),
            Ok(reconciled) => {
                self.authenticate_reconciled_outbound_dsc1_record_locked(
                    &reconciled,
                    &committed,
                    &request,
                )?;
                Ok(F7FinalClaimProgressV14::TransportReconciled)
            }
        }
    }

    /// Revalidate the exact native 0x12 recovered by the generic outbox. No
    /// other message, opening, sender or sequence can be used as this handoff.
    pub fn revalidate_committed_f7_final_claim_transport_v14(
        &self,
        chain: TrustedChainIdV1,
        outbound: &CommittedOutboundDsc1V1,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        if outbound.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let (committed, _) =
            self.authenticate_f7_final_transport_v14(chain, outbound.session_id)?;
        if outbound.sender_id != committed.sender_id
            || outbound.sequence != committed.sequence
            || outbound.application_id != committed.application_id
            || outbound.message_digest != committed.message_digest
            || outbound.signed_bytes != committed.signed_bytes
            || outbound.request_id != committed.request_id
            || outbound.committed_record_digest != committed.digest
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn authenticate_f7_final_transport_v14(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<
        (
            CommittedOutboundDsc1RecordV1,
            OutboundDsc1SigningRequestRecordV1,
        ),
        SessionStoreError,
    > {
        let exposure = self.authenticate_f7_exposure_v14(session)?;
        self.authenticate_f7_admission_v14(session)?;
        if exposure.hashes[1] != *chain.as_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        let sequence = self.transport_sequence_at_revision(
            session,
            signer.participant_id,
            exposure.successor.revision(),
        )?;
        let request = self.load_outbound_dsc1_request(session, signer.participant_id, sequence)?;
        let predecessor = self.load_session_revision(session, request.predecessor_revision)?;
        self.audit_f7_final_claim_request_v14(&request, &predecessor)?;
        let committed =
            self.load_committed_outbound_dsc1(session, signer.participant_id, sequence)?;
        self.authenticate_committed_outbound_dsc1_record_locked(&committed, &request)?;
        let name = transport_message_name(session, signer.participant_id, sequence, false);
        let bytes = self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        let accepted = TransportMessageRecordV1::from_bytes(&bytes)?;
        self.authenticate_transport_record(&name, &accepted)?;
        let current = self.load_session_locked(session)?;
        if accepted.equivocation
            || accepted.signed_bytes != committed.signed_bytes
            || accepted.successor.phase() != SessionPhaseV1::ClaimBroadcast
            || self
                .load_session_revision(session, accepted.successor.revision())?
                .as_bytes()
                != accepted.successor.as_bytes()
            || current.revision() < accepted.successor.revision()
            || !current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok((committed, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission(state: u8, relayed: u8) -> Vec<u8> {
        let session = [41; 32];
        let exposure = [42; 32];
        let txid = [43; 32];
        let mut receipt = b"DOM:submission-receipt:v1".to_vec();
        receipt.extend_from_slice(&txid);
        receipt.extend_from_slice(&[state, relayed]);
        let receipt = *blake2b_256(&receipt).as_bytes();
        let mut bytes = b"DOMFAD14".to_vec();
        for h in [session, exposure, txid, receipt, [44; 32]] {
            bytes.extend_from_slice(&h);
        }
        bytes.extend_from_slice(&[state, relayed]);
        let digest = tagged_hash(ADMISSION_DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        bytes
    }
    fn redigest(bytes: &mut [u8]) {
        let end = bytes.len() - 32;
        let digest = tagged_hash(ADMISSION_DOMAIN, &bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }
    #[test]
    fn v14_admission_requires_native_economic_receipt_predicate() {
        for state in 0..=4 {
            for relayed in 0..=2 {
                let expected = (state == 1 || state == 2 || state == 3)
                    && relayed <= 1
                    && (state == 3 || relayed == 1);
                assert_eq!(
                    AdmissionV14::decode(&admission(state, relayed)).is_ok(),
                    expected
                );
            }
        }
    }
    #[test]
    fn v14_admission_detects_every_single_byte_mutation_and_truncation() {
        let valid = admission(3, 0);
        assert!(AdmissionV14::decode(&valid).is_ok());
        for i in 0..valid.len() {
            let mut mutation = valid.clone();
            mutation[i] ^= 1;
            assert!(AdmissionV14::decode(&mutation).is_err(), "byte {i}");
            assert!(AdmissionV14::decode(&valid[..i]).is_err(), "prefix {i}");
        }
        let mut oversized = valid;
        oversized.push(0);
        assert!(AdmissionV14::decode(&oversized).is_err());
    }
    #[test]
    fn v14_redigest_cannot_relabel_txid_or_receipt_facts() {
        let valid = admission(1, 1);
        for offset in [72, 104, 168, 169] {
            let mut mutation = valid.clone();
            mutation[offset] ^= 1;
            redigest(&mut mutation);
            assert!(
                AdmissionV14::decode(&mutation).is_err(),
                "receipt field {offset}"
            );
        }
        let mut wrong_session = valid.clone();
        wrong_session[8] ^= 1;
        redigest(&mut wrong_session);
        assert!(validate_final_claim_artifact_v14(
            [41; 32],
            F7ArtifactKindV12::AdmissionV14,
            &wrong_session
        )
        .is_err());
    }
    #[test]
    fn v14_admission_staging_accepts_only_valid_prefix_and_exact_final() {
        let valid = admission(3, 0);
        for length in 0..=valid.len() {
            assert!(validate_f7_artifact_staging_v12(
                [41; 32],
                F7ArtifactKindV12::AdmissionV14,
                &valid[..length]
            )
            .is_ok());
        }
        assert!(validate_f7_artifact_staging_v12(
            [40; 32],
            F7ArtifactKindV12::AdmissionV14,
            &valid
        )
        .is_err());
        assert!(
            validate_f7_artifact_staging_v12([41; 32], F7ArtifactKindV12::ExposureV14, &valid)
                .is_err()
        );
    }
}
