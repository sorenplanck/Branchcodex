//! Universal receiver observation and exact 0x12 ingress. All ancestry belongs
//! to the native F7 Store profile; no Bitcoin issuance is manufactured here.
use super::*;

pub(super) const OBSERVATION_PREFIX_V15: usize = 40 + 12 * 32;
pub(super) const OBSERVATION_MAX_V15: usize =
    OBSERVATION_PREFIX_V15 + 4 + SESSION_RECORD_MAX_LEN + 32;
const OBSERVATION_DOMAIN_V15: &str = "DOM-INTEROP/F7-CLAIM-OBSERVATION/V15\0";

/// Public verification material rederived from the complete retained F7 round.
/// It has no constructor and grants no signing or submission permission.
pub struct F7ClaimObserverFactsV15 {
    session: [u8; 32],
    chain: [u8; 32],
    template: [u8; 32],
    shared: [u8; 33],
    transcript: [u8; 32],
    message: [u8; 32],
    key: PublicKey,
    pre: AdaptorPreSignatureV1,
    receiver: [u8; 32],
    minimum_confirmations: u32,
}
impl F7ClaimObserverFactsV15 {
    /// Native session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session
    }
    /// Frozen DOM chain.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain
    }
    /// Signature-omitting template commitment.
    pub const fn template_hash(&self) -> [u8; 32] {
        self.template
    }
    /// Exact shared funding output.
    pub const fn shared_commitment(&self) -> [u8; 33] {
        self.shared
    }
    /// Transcript authenticated at the nonce reveal boundary.
    pub const fn reveal_transcript(&self) -> &[u8; 32] {
        &self.transcript
    }
    /// Retained kernel message.
    pub const fn kernel_message(&self) -> &[u8; 32] {
        &self.message
    }
    /// Aggregate public signing key.
    pub const fn signing_key(&self) -> &PublicKey {
        &self.key
    }
    /// Reconstructed and verified public adaptor pre-signature.
    pub const fn pre_signature(&self) -> &AdaptorPreSignatureV1 {
        &self.pre
    }
    /// Frozen receiver participant.
    pub const fn receiver_id(&self) -> [u8; 32] {
        self.receiver
    }
    /// Frozen DOM burial requirement.
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }
}

/// Durable observation, required before a receiver may request secret extraction.
/// This proves historical exposure, not current canonicality after a reorg.
pub struct ObservedF7FinalClaimV15 {
    session: [u8; 32],
    chain: [u8; 32],
    txid: [u8; 32],
    digest: [u8; 32],
    receiver: [u8; 32],
}
impl ObservedF7FinalClaimV15 {
    /// Native observed session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session
    }
    /// Native DOM chain.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain
    }
    /// Exact transaction whose observation became durable.
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.txid
    }
    /// Immutable observation commitment.
    pub const fn observation_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Receiver to whom the observation belongs.
    pub const fn receiver_id(&self) -> [u8; 32] {
        self.receiver
    }
}

/// Same-opening capability to accept only the observed sender's exact claim.
pub struct PreparedF7FinalClaimIngressV15 {
    trusted_chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    observation_record_digest: [u8; 32],
    tx_hash: [u8; 32],
    dom_claim_sender_id: [u8; 32],
    final_claim_receiver_id: [u8; 32],
    canonical_sender_sequence: u64,
    canonical_sender_direction: DirectionV1,
    ingress_transcript_hash: [u8; 32],
    open_instance_id: [u8; 32],
}
impl PreparedF7FinalClaimIngressV15 {
    /// Bound native session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Exact sender fixed by the pre-funding role binding.
    pub const fn sender_id(&self) -> &[u8; 32] {
        &self.dom_claim_sender_id
    }
    /// Exact receiver fixed by the pre-funding role binding.
    pub const fn receiver_id(&self) -> &[u8; 32] {
        &self.final_claim_receiver_id
    }
}

struct ObservationV15 {
    bytes: Vec<u8>,
    hashes: [[u8; 32]; 12],
    height: u64,
    tip_height: u64,
    predecessor_revision: u64,
    successor: SessionRecordV1,
    digest: [u8; 32],
}
impl ObservationV15 {
    fn encode(
        hashes: [[u8; 32]; 12],
        height: u64,
        tip_height: u64,
        predecessor_revision: u64,
        transaction_index: u32,
        successor: &SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let mut bytes = b"DOMFOB15".to_vec();
        for value in [height, tip_height, predecessor_revision] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&transaction_index.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for hash in hashes {
            bytes.extend_from_slice(&hash);
        }
        put_blob(&mut bytes, successor.as_bytes())?;
        let digest = tagged_hash(OBSERVATION_DOMAIN_V15, &bytes);
        bytes.extend_from_slice(&digest);
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < OBSERVATION_PREFIX_V15 + 4 + 32
            || bytes.len() > OBSERVATION_MAX_V15
            || &bytes[..8] != b"DOMFOB15"
            || bytes[36..40] != [0; 4]
            || tagged_hash(OBSERVATION_DOMAIN_V15, &bytes[..bytes.len() - 32])
                != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut hashes = [[0; 32]; 12];
        for (i, h) in hashes.iter_mut().enumerate() {
            *h = copy_array(&bytes[40 + i * 32..72 + i * 32])?;
        }
        if hashes.contains(&[0; 32]) {
            return Err(SessionStoreError::Quarantined);
        }
        let height = u64::from_le_bytes(copy_array(&bytes[8..16])?);
        let tip_height = u64::from_le_bytes(copy_array(&bytes[16..24])?);
        let predecessor_revision = u64::from_le_bytes(copy_array(&bytes[24..32])?);
        let mut cursor = OBSERVATION_PREFIX_V15;
        let successor =
            SessionRecordV1::from_bytes(take_blob(bytes, &mut cursor, SESSION_RECORD_MAX_LEN)?)?;
        if cursor != bytes.len() - 32
            || height == 0
            || tip_height < height
            || successor.session_id() != hashes[0]
            || successor.phase() != SessionPhaseV1::FundingConfirmed
            || successor.revision()
                != predecessor_revision
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
            || !successor.irreversible().adaptor_secret_exposed
            || successor.chain().tip_height != tip_height
            || successor.chain().tip_id != hashes[8]
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            hashes,
            height,
            tip_height,
            predecessor_revision,
            successor,
            digest: copy_array(&bytes[bytes.len() - 32..])?,
        })
    }
}

pub(super) fn validate_f7_observation_bytes_v15(
    session: [u8; 32],
    bytes: &[u8],
) -> Result<(), SessionStoreError> {
    if ObservationV15::decode(bytes)?.hashes[0] != session {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

impl ContractsSessionStoreV1 {
    /// Return receiver verification facts only once the retained round exists.
    /// A malformed/orphan artifact is an error, never a not-ready result.
    pub fn f7_claim_receiver_facts_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        participant: [u8; 32],
    ) -> Result<Option<F7ClaimObserverFactsV15>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.f7_claim_facts_locked_v15(chain, session, participant, true)
    }

    /// Reconstruct public claim verification facts for either frozen local role.
    /// This grants no signing, extraction, observation or submission authority.
    pub fn f7_claim_verification_facts_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        participant: [u8; 32],
    ) -> Result<Option<F7ClaimObserverFactsV15>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.f7_claim_facts_locked_v15(chain, session, participant, false)
    }

    fn f7_claim_facts_locked_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        participant: [u8; 32],
        receiver_only: bool,
    ) -> Result<Option<F7ClaimObserverFactsV15>, SessionStoreError> {
        self.audit_f7_artifact_inventory_v12()?;
        let (sessions, _, _) = self.census_f7_artifacts_v12()?;
        let Some(kinds) = sessions.get(&session) else {
            return Ok(None);
        };
        let gate = self.load_f7_gate_v12(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if chain.as_bytes() != &gate.chain_id || signer.participant_id != participant {
            return Err(SessionStoreError::InvalidTransition);
        }
        if (receiver_only && participant != gate.role.final_claim_receiver_id().0)
            || !kinds.contains(&F7ArtifactKindV12::Pre)
        {
            return Ok(None);
        }
        let (_, issued, current) = self.authenticate_f7_claim_v12(session)?;
        let pre = self.load_f7_pre_v12(session)?;
        if !kinds.contains(&F7ArtifactKindV12::ObservationV15)
            && !kinds.contains(&F7ArtifactKindV12::ExposureV14)
        {
            if current.phase() != SessionPhaseV1::FundingConfirmed {
                return Ok(None);
            }
            // The aggregate publication may not yet have arrived locally.
            if current.transcript_hash() == pre.terminal_transcript_hash {
                return Ok(None);
            }
            self.require_f7_pre_accepted_v14(&pre, &current)?;
        }
        let tx = Transaction::from_bytes(&gate.claim_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if tx.kernels.len() != 1 {
            return Err(SessionStoreError::Quarantined);
        }
        let key = PublicKey::from_compressed_bytes(tx.kernels[0].excess.as_bytes())
            .map_err(|_| SessionStoreError::Quarantined)?;
        Ok(Some(F7ClaimObserverFactsV15 {
            session,
            chain: gate.chain_id,
            template: issued.claim_template_hash,
            shared: gate.role.shared_output_commitment(),
            transcript: pre.reveal_transcript_hash,
            message: *scriptless_kernel_message_digest_v1(&tx.kernels[0]).as_bytes(),
            key,
            pre: pre.pre_signature,
            receiver: gate.role.final_claim_receiver_id().0,
            minimum_confirmations: gate.role.terms().dom_leg.finality.min_confirmations,
        }))
    }

    /// Persist a canonical observation before either ingress or extraction.
    /// The reversible tip projection is updated from this same observation
    /// before its exact exposure successor. No separately fetched tip enters
    /// and this receiver-only transition authorizes no signing or funding.
    pub fn persist_f7_claim_observation_v15(
        &self,
        chain: TrustedChainIdV1,
        expected_revision: u64,
        observation: VerifiedDomClaimObservationV1,
    ) -> Result<ObservedF7FinalClaimV15, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let session = *observation.session_id();
        if self.f7_final_claim_exposure_exists_v14(session)? {
            return Err(SessionStoreError::Conflict);
        }
        let (gate, issued, current) = self.authenticate_f7_claim_v12(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        let pre = self.load_f7_pre_v12(session)?;
        if chain.as_bytes() != &issued.chain_id
            || observation.chain_id() != chain.as_bytes()
            || observation.tag() != DomClaimObservationTagV1::CounterpartyClaimObserved
            || signer.participant_id != gate.role.final_claim_receiver_id().0
            || signer.participant_id == gate.role.dom_claim_sender_id().0
            || observation.template_hash() != &issued.claim_template_hash
            || observation.shared_output_commitment() != &gate.role.shared_output_commitment()
            || observation.adaptor_point().to_compressed_bytes() != gate.role.adaptor_point_sec1()
            || observation.kernel_index() != 0
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if self.f7_final_claim_observation_exists_v15(session)? {
            let retained = self.authenticate_f7_observation_v15(session)?;
            if retained.hashes[6] != *observation.tx_hash() {
                return Err(SessionStoreError::Conflict);
            }
            return self.observed_f7_handle_v15(session);
        }
        if current.revision() != expected_revision {
            return Err(SessionStoreError::Conflict);
        }
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_f7_pre_accepted_v14(&pre, &current)?;
        let location = observation.location();
        if !observed_claim_has_depth(
            location.block_height,
            location.block_hash,
            observation.observed_tip_height(),
            *observation.observed_tip_id(),
            gate.role.terms().dom_leg.finality.min_confirmations,
        ) {
            return Err(SessionStoreError::InvalidTransition);
        }
        // The same canonical claim observation supplies the tip. This is a
        // receiver-only projection after the signing round completed, never a
        // fresh funding/nonce authority. A crash here requires a fresh scan.
        let current = if current.chain().tip_height != observation.observed_tip_height()
            || current.chain().tip_id != *observation.observed_tip_id()
        {
            let mut projection = current.chain();
            projection.tip_height = observation.observed_tip_height();
            projection.tip_id = *observation.observed_tip_id();
            let projected = current.advance(
                current.revision(),
                current.phase(),
                current.transcript_hash(),
                current.irreversible(),
                projection,
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&projected)?;
            test_crash_hook("f7-v15-after-observation-projection");
            projected
        } else {
            current
        };
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
        let record = ObservationV15::encode(
            [
                session,
                issued.chain_id,
                gate.digest,
                issued.digest,
                issued.consumption_digest,
                pre.digest,
                *observation.tx_hash(),
                location.block_hash,
                *observation.observed_tip_id(),
                *current.digest(),
                self.open_instance_id,
                gate.role.digest(),
            ],
            location.block_height,
            observation.observed_tip_height(),
            current.revision(),
            location.transaction_index,
            &successor,
        )?;
        self.publish_f7_v12(
            session,
            "claim-observation-v15",
            &record.bytes,
            OBSERVATION_MAX_V15,
        )?;
        test_crash_hook("f7-v15-after-observation");
        self.persist_session_record(&successor)?;
        test_crash_hook("f7-v15-after-observation-successor");
        self.observed_f7_handle_v15(session)
    }

    pub(in super::super) fn f7_final_claim_observation_exists_v15(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        match self.read_f7_v12(session, "claim-observation-v15", OBSERVATION_MAX_V15) {
            Ok(bytes) => {
                validate_f7_observation_bytes_v15(session, &bytes)?;
                Ok(true)
            }
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
    fn authenticate_f7_observation_v15(
        &self,
        session: [u8; 32],
    ) -> Result<ObservationV15, SessionStoreError> {
        let record = ObservationV15::decode(&self.read_f7_v12(
            session,
            "claim-observation-v15",
            OBSERVATION_MAX_V15,
        )?)?;
        if self.f7_final_claim_exposure_exists_v14(session)? {
            return Err(SessionStoreError::Quarantined);
        }
        let (gate, issued, current) = self.authenticate_f7_claim_v12(session)?;
        let pre = self.load_f7_pre_v12(session)?;
        let predecessor = self.load_session_revision(session, record.predecessor_revision)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        if record.hashes[0] != session
            || record.hashes[1] != issued.chain_id
            || record.hashes[2] != gate.digest
            || record.hashes[3] != issued.digest
            || record.hashes[4] != issued.consumption_digest
            || record.hashes[5] != pre.digest
            || record.hashes[9] != *predecessor.digest()
            || record.hashes[11] != gate.role.digest()
            || signer.participant_id != gate.role.final_claim_receiver_id().0
            || !observed_claim_has_depth(
                record.height,
                record.hashes[7],
                record.tip_height,
                record.hashes[8],
                gate.role.terms().dom_leg.finality.min_confirmations,
            )
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.require_f7_pre_accepted_v14(&pre, &predecessor)?;
        require_final_claim_exposure_delta_v1(&predecessor, &record.successor)?;
        if current.revision() < record.successor.revision() {
            if current.as_bytes() != predecessor.as_bytes() {
                return Err(SessionStoreError::Quarantined);
            }
        } else if self
            .load_session_revision(session, record.successor.revision())?
            .as_bytes()
            != record.successor.as_bytes()
            || !current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }
    fn observed_f7_handle_v15(
        &self,
        session: [u8; 32],
    ) -> Result<ObservedF7FinalClaimV15, SessionStoreError> {
        let record = self.authenticate_f7_observation_v15(session)?;
        let current = self.load_session_locked(session)?;
        if current.revision() < record.successor.revision() {
            return Err(SessionStoreError::InvalidTransition);
        }
        let gate = self.load_f7_gate_v12(session)?;
        Ok(ObservedF7FinalClaimV15 {
            session,
            chain: record.hashes[1],
            txid: record.hashes[6],
            digest: record.digest,
            receiver: gate.role.final_claim_receiver_id().0,
        })
    }
    /// Reauthenticate historical observation after opening completed recovery.
    pub fn resume_f7_claim_observation_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<Option<ObservedF7FinalClaimV15>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if !self.f7_final_claim_observation_exists_v15(session)? {
            return Ok(None);
        }
        let observed = self.observed_f7_handle_v15(session)?;
        if observed.chain != *chain.as_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(Some(observed))
    }
    pub(super) fn audit_f7_observation_inventory_v15(
        &self,
        session: [u8; 32],
        kinds: &BTreeSet<F7ArtifactKindV12>,
    ) -> Result<(), SessionStoreError> {
        if kinds.contains(&F7ArtifactKindV12::ObservationV15) {
            if !kinds.contains(&F7ArtifactKindV12::Pre)
                || kinds.contains(&F7ArtifactKindV12::ExposureV14)
                || kinds.contains(&F7ArtifactKindV12::AdmissionV14)
            {
                return Err(SessionStoreError::Quarantined);
            }
            self.authenticate_f7_observation_v15(session)?;
        }
        Ok(())
    }
    pub(in super::super) fn plan_f7_claim_observations_v15(
        &self,
    ) -> Result<Vec<SessionRecordV1>, SessionStoreError> {
        self.audit_f7_artifact_inventory_v12()?;
        let (sessions, _, _) = self.census_f7_artifacts_v12()?;
        let mut successors = Vec::new();
        for (session, kinds) in sessions {
            if kinds.contains(&F7ArtifactKindV12::ObservationV15) {
                let record = self.authenticate_f7_observation_v15(session)?;
                if self.load_session_locked(session)?.revision() < record.successor.revision() {
                    successors.push(record.successor);
                }
            }
        }
        Ok(successors)
    }
}

impl ContractsSessionStoreV1 {
    /// Authenticate exact duplicates and retain signed conflicts using the native transport journal.
    pub fn accept_prepared_f7_final_claim_transport_v15(
        &self,
        authority: &PreparedF7FinalClaimIngressV15,
        signed_bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if authority.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let authenticated = self.authenticate_f7_final_claim_ingress_v15(
            authority.trusted_chain_id,
            authority.session_id,
        )?;
        if authenticated.observation_record_digest != authority.observation_record_digest
            || authenticated.tx_hash != authority.tx_hash
            || authenticated.dom_claim_sender_id != authority.dom_claim_sender_id
            || authenticated.final_claim_receiver_id != authority.final_claim_receiver_id
            || authenticated.canonical_sender_sequence != authority.canonical_sender_sequence
            || authenticated.canonical_sender_direction != authority.canonical_sender_direction
            || authenticated.ingress_transcript_hash != authority.ingress_transcript_hash
            || *authenticated.trusted_chain_id.as_bytes() != *authority.trusted_chain_id.as_bytes()
        {
            return Err(SessionStoreError::Quarantined);
        }
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.session_id != authenticated.session_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(envelope.session_id)?;
        let identities = self.load_transport_identity_binding(envelope.session_id)?;
        require_transport_identity_binding(&roster, &identities)?;
        if roster.chain_id != envelope.chain_id {
            return Err(SessionStoreError::Canonical);
        }
        let participant = roster
            .participants
            .iter()
            .find(|candidate| candidate.participant_id == envelope.sender_id)
            .ok_or(SessionStoreError::Canonical)?;
        envelope.verify(&participant.identity_key)?;
        if envelope.chain_id != *authenticated.trusted_chain_id.as_bytes()
            || envelope.sender_id != authenticated.dom_claim_sender_id
            || envelope.sequence != authenticated.canonical_sender_sequence
            || participant.direction != authenticated.canonical_sender_direction
        {
            return Err(SessionStoreError::InvalidTransition);
        }

        // A retained logical key is handled before the unseen-edge rules, for
        // the same reason as the `0x0f` round: an exact duplicate must
        // converge instead of being read as a second successor, and a validly
        // signed conflict must fail closed instead of surfacing as an ordinary
        // invalid payload.
        let retained_name = transport_message_name(
            envelope.session_id,
            envelope.sender_id,
            envelope.sequence,
            false,
        );
        let retained = match self.messages.read_bounded_file(
            &ValidatedComponent::registered(&retained_name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        ) {
            Ok(bytes) => Some(TransportMessageRecordV1::from_bytes(&bytes)?),
            Err(LinuxCapabilityError::NotFound) => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(retained) = retained {
            let (retained_envelope, retained_direction) =
                self.authenticate_transport_record(&retained_name, &retained)?;
            if retained.equivocation
                || retained_envelope.chain_id != *authenticated.trusted_chain_id.as_bytes()
                || retained_envelope.session_id != authenticated.session_id
                || retained_envelope.sender_id != authenticated.dom_claim_sender_id
                || retained_envelope.sequence != authenticated.canonical_sender_sequence
                || retained_envelope.message_type != 0x12
                || retained_direction != authenticated.canonical_sender_direction
                || canonical_transaction_hash_v1(retained_envelope.payload(&retained.signed_bytes)?)
                    .map_err(|_| SessionStoreError::Quarantined)?
                    != authenticated.tx_hash
            {
                return Err(SessionStoreError::Quarantined);
            }
            let current = self.load_session_locked(envelope.session_id)?;
            match self.accept_transport_message_with_successor_locked(signed_bytes, &current, None)
            {
                Ok(outcome) => return Ok(outcome),
                Err(SessionStoreError::InvalidTransition) => {}
                Err(error) => return Err(error),
            }
            let current = self.load_session_locked(envelope.session_id)?;
            let failed = current.advance(
                current.revision(),
                SessionPhaseV1::FailedClosed,
                current.transcript_hash(),
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )?;
            return self.accept_transport_message_with_successor_locked(
                signed_bytes,
                &current,
                Some(&failed),
            );
        }

        if envelope.previous_transcript_hash != authenticated.ingress_transcript_hash
            || envelope.message_type != 0x12
            || canonical_transaction_hash_v1(envelope.payload(signed_bytes)?)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?
                != authenticated.tx_hash
        {
            return Err(SessionStoreError::InvalidTransition);
        }

        let current = self.load_session_locked(envelope.session_id)?;
        if current.transcript_hash() != authenticated.ingress_transcript_hash
            || current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let transcript_hash = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            participant.direction,
            envelope.message_type,
            SessionPhaseV1::ClaimBroadcast,
        )?;
        // The irreversible flags carry over untouched: the session was already
        // exposed, and carrying the claim to the peer changes the phase only.
        let successor = current.advance(
            current.revision(),
            SessionPhaseV1::ClaimBroadcast,
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
        require_transport_successor(&current, &envelope, participant.direction, &successor)?;
        self.accept_transport_message_with_successor_locked(signed_bytes, &successor, Some(&failed))
    }
}

impl ContractsSessionStoreV1 {
    /// Authenticate an early 0x12 while its chain observation is still pending.
    /// This grants no receipt, exposure, extraction or broadcast authority. The
    /// durable Relay row must remain pending and be delivered again after the
    /// ordinary observation path issues its receiver ingress capability.
    pub fn f7_final_claim_awaits_observation_v16(
        &self,
        session: [u8; 32],
        local_participant: [u8; 32],
        signed_bytes: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let envelope = ParsedTransportEnvelopeV1::parse(signed_bytes)?;
        if envelope.session_id != session {
            return Err(SessionStoreError::InvalidTransition);
        }
        if envelope.message_type != 0x12 {
            return Ok(false);
        }
        self.audit_f7_artifact_inventory_v12()?;
        let (sessions, _, _) = self.census_f7_artifacts_v12()?;
        let Some(kinds) = sessions.get(&session) else {
            return Ok(false);
        };
        if kinds.contains(&F7ArtifactKindV12::ObservationV15) {
            return Ok(false);
        }
        if !kinds.contains(&F7ArtifactKindV12::Pre) {
            return Err(SessionStoreError::InvalidTransition);
        }
        let (gate, issued, current) = self.authenticate_f7_claim_v12(session)?;
        let signer = self.authenticate_local_transport_signer_binding(session)?;
        let pre = self.load_f7_pre_v12(session)?;
        if signer.participant_id != local_participant
            || local_participant != gate.role.final_claim_receiver_id().0
            || current.phase() != SessionPhaseV1::FundingConfirmed
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_f7_pre_accepted_v14(&pre, &current)?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let sender = roster
            .participants
            .iter()
            .find(|p| p.participant_id == gate.role.dom_claim_sender_id().0)
            .ok_or(SessionStoreError::Quarantined)?;
        envelope.verify(&sender.identity_key)?;
        if roster.chain_id != issued.chain_id
            || envelope.chain_id != issued.chain_id
            || envelope.sender_id != sender.participant_id
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    sender.participant_id,
                    current.revision(),
                )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.verify_f7_final_claim_bytes_v14(
            &gate,
            &issued,
            &pre,
            envelope.payload(signed_bytes)?,
            current.chain().tip_height,
        )?;
        Ok(true)
    }

    /// Install/reinstall receiver ingress from an observation, without an RPC
    /// call or another transition. Replays remain verifiable after acceptance.
    pub fn prepare_f7_final_claim_ingress_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedF7FinalClaimIngressV15, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.authenticate_f7_final_claim_ingress_v15(chain, session)
    }
    fn authenticate_f7_final_claim_ingress_v15(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedF7FinalClaimIngressV15, SessionStoreError> {
        let record = self.authenticate_f7_observation_v15(session)?;
        if record.hashes[1] != *chain.as_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        let gate = self.load_f7_gate_v12(session)?;
        let current = self.load_session_locked(session)?;
        if current.revision() < record.successor.revision() {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let sender = roster
            .participants
            .iter()
            .find(|p| p.participant_id == gate.role.dom_claim_sender_id().0)
            .ok_or(SessionStoreError::Quarantined)?;
        if roster.chain_id != *chain.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(PreparedF7FinalClaimIngressV15 {
            trusted_chain_id: chain,
            session_id: session,
            observation_record_digest: record.digest,
            tx_hash: record.hashes[6],
            dom_claim_sender_id: sender.participant_id,
            final_claim_receiver_id: gate.role.final_claim_receiver_id().0,
            canonical_sender_sequence: self.transport_sequence_at_revision(
                session,
                sender.participant_id,
                record.successor.revision(),
            )?,
            canonical_sender_direction: sender.direction,
            ingress_transcript_hash: record.successor.transcript_hash(),
            open_instance_id: self.open_instance_id,
        })
    }
    pub(in super::super) fn require_f7_final_claim_receiver_edge_v15(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let session = current.session_id();
        let record = self.authenticate_f7_observation_v15(session)?;
        let (gate, issued, _) = self.authenticate_f7_claim_v12(session)?;
        let pre = self.load_f7_pre_v12(session)?;
        let roster = self.load_transport_roster(session)?;
        let sender = roster
            .participants
            .iter()
            .find(|p| p.participant_id == gate.role.dom_claim_sender_id().0)
            .ok_or(SessionStoreError::Quarantined)?;
        envelope.verify(&sender.identity_key)?;
        if current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().adaptor_secret_exposed
            || envelope.message_type != 0x12
            || envelope.session_id != session
            || envelope.chain_id != issued.chain_id
            || envelope.sender_id != sender.participant_id
            || direction != sender.direction
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    session,
                    sender.participant_id,
                    record.successor.revision(),
                )?
            || envelope.previous_transcript_hash != current.transcript_hash()
            || canonical_transaction_hash_v1(envelope.payload(bytes)?)
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?
                != record.hashes[6]
            || successor.phase() != SessionPhaseV1::ClaimBroadcast
            || successor.irreversible() != current.irreversible()
            || successor.chain() != current.chain()
            || successor.encrypted_payload() != current.encrypted_payload()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_projection_only_session_lineage(&record.successor, current)?;
        self.verify_f7_final_claim_bytes_v14(
            &gate,
            &issued,
            &pre,
            envelope.payload(bytes)?,
            record.height,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        SessionChainProjectionV1, SessionIrreversibleV1, SessionRecordFieldsV1,
        SessionTxObservationV1,
    };

    fn sample() -> ObservationV15 {
        let mut hashes = [[7; 32]; 12];
        hashes[0] = [1; 32];
        hashes[8] = [8; 32];
        let successor = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: hashes[0],
                revision: 5,
                phase: SessionPhaseV1::FundingConfirmed,
                terms_hash: [2; 32],
                transcript_hash: [3; 32],
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: true,
                    funding_authorized: true,
                    adaptor_secret_exposed: true,
                    nonce_epoch: 2,
                },
                chain: SessionChainProjectionV1 {
                    tip_height: 102,
                    tip_id: hashes[8],
                    funding: SessionTxObservationV1::Confirmed {
                        block_id: [9; 32],
                        height: 90,
                    },
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            b"sealed fixture",
        )
        .expect("valid session fixture");
        ObservationV15::encode(hashes, 100, 102, 4, 3, &successor).expect("valid observation")
    }
    fn rehash(bytes: &mut [u8]) {
        let end = bytes.len() - 32;
        let digest = tagged_hash(OBSERVATION_DOMAIN_V15, &bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }

    #[test]
    fn v15_observation_codec_rejects_each_truncation_and_appended_byte() {
        let record = sample();
        for end in 0..record.bytes.len() {
            assert!(
                ObservationV15::decode(&record.bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut extra = record.bytes.clone();
        extra.push(0);
        rehash(&mut extra);
        assert!(ObservationV15::decode(&extra).is_err());
        assert_eq!(
            ObservationV15::decode(&record.bytes)
                .unwrap()
                .successor
                .as_bytes(),
            record.successor.as_bytes()
        );
    }

    #[test]
    fn v15_observation_codec_rejects_every_single_byte_mutation() {
        let record = sample();
        for index in 0..record.bytes.len() {
            let mut bytes = record.bytes.clone();
            bytes[index] ^= 1;
            assert!(ObservationV15::decode(&bytes).is_err(), "mutation {index}");
        }
    }

    #[test]
    fn v15_observation_codec_rejects_rehashed_semantic_corruption() {
        let record = sample();
        for offset in [0, 16, 24, 36, 40, 40 + 8 * 32, OBSERVATION_PREFIX_V15] {
            let mut bytes = record.bytes.clone();
            bytes[offset] ^= 1;
            rehash(&mut bytes);
            assert!(
                ObservationV15::decode(&bytes).is_err(),
                "semantic mutation {offset}"
            );
        }
        for index in 0..12 {
            let mut bytes = record.bytes.clone();
            bytes[40 + index * 32..72 + index * 32].fill(0);
            rehash(&mut bytes);
            assert!(
                ObservationV15::decode(&bytes).is_err(),
                "zero binding {index}"
            );
        }
        assert!(ObservationV15::encode(record.hashes, 0, 102, 4, 3, &record.successor).is_err());
        let mut overflow = record.bytes.clone();
        overflow[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        rehash(&mut overflow);
        assert!(ObservationV15::decode(&overflow).is_err());
    }

    #[test]
    fn v15_observation_staging_accepts_valid_prefixes_but_rejects_wrong_identity() {
        let record = sample();
        let kind = F7ArtifactKindV12::ObservationV15;
        for end in 0..=record.bytes.len() {
            assert!(
                validate_f7_artifact_staging_v12(record.hashes[0], kind, &record.bytes[..end])
                    .is_ok(),
                "prefix {end}"
            );
        }
        assert!(validate_f7_observation_bytes_v15([2; 32], &record.bytes).is_err());
        assert!(validate_f7_artifact_staging_v12([2; 32], kind, &record.bytes[..72]).is_err());
        assert!(validate_f7_artifact_staging_v12(
            record.hashes[0],
            F7ArtifactKindV12::ExposureV14,
            &record.bytes[..8]
        )
        .is_err());
    }

    #[test]
    fn v15_observation_requires_exposed_successor_and_exact_revision_and_tip() {
        let record = sample();
        assert!(ObservationV15::encode(record.hashes, 100, 101, 4, 3, &record.successor).is_err());
        assert!(ObservationV15::encode(record.hashes, 103, 102, 4, 3, &record.successor).is_err());
        assert!(ObservationV15::encode(record.hashes, 100, 102, 3, 3, &record.successor).is_err());
        let mut irreversible = record.successor.irreversible();
        irreversible.adaptor_secret_exposed = false;
        let unexposed = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: record.hashes[0],
                revision: 5,
                phase: SessionPhaseV1::FundingConfirmed,
                terms_hash: record.successor.terms_hash(),
                transcript_hash: record.successor.transcript_hash(),
                irreversible,
                chain: record.successor.chain(),
            },
            record.successor.encrypted_payload(),
        )
        .unwrap();
        assert!(ObservationV15::encode(record.hashes, 100, 102, 4, 3, &unexposed).is_err());
    }
}
