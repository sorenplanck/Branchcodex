//! Journaled F7 funding signing. Reuses the existing native six DSC1 signing
//! edges and nonce vault; no alternative signature implementation or raw import.
use super::*;

pub(super) const SIGNING_MAX_V20: usize = SESSION_RECORD_MAX_LEN + 108;
const SUFFIX: &str = "funding-signing-v20";
const MAGIC: &[u8; 8] = b"DOMFFS20";
const DOMAIN: &str = "DOM-INTEROP/F7-FUNDING-SIGNING/V20\0";

pub(super) struct F7FundingSigningV20 {
    bytes: Vec<u8>,
    gate: [u8; 32],
    predecessor: [u8; 32],
    pub(super) successor: SessionRecordV1,
}
impl F7FundingSigningV20 {
    fn new(
        gate: [u8; 32],
        predecessor: [u8; 32],
        successor: SessionRecordV1,
    ) -> Result<Self, SessionStoreError> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&gate);
        bytes.extend_from_slice(&predecessor);
        put_blob(&mut bytes, successor.as_bytes())?;
        bytes.extend_from_slice(&tagged_hash(DOMAIN, &bytes));
        Self::decode(&bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < 108
            || bytes.len() > SIGNING_MAX_V20
            || bytes[..8] != *MAGIC
            || tagged_hash(DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut cursor = 72;
        let successor =
            SessionRecordV1::from_bytes(take_blob(bytes, &mut cursor, SESSION_RECORD_MAX_LEN)?)?;
        if cursor + 32 != bytes.len()
            || successor.phase() != SessionPhaseV1::FundingAuthorized
            || !successor.irreversible().funding_authorized
            || successor.irreversible().adaptor_secret_exposed
            || bytes[8..40] == [0; 32]
            || bytes[40..72] == [0; 32]
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            gate: copy_array(&bytes[8..40])?,
            predecessor: copy_array(&bytes[40..72])?,
            successor,
        })
    }
}

impl ContractsSessionStoreV1 {
    pub(super) fn optional_f7_funding_signing_v20(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<Option<F7FundingSigningV20>, SessionStoreError> {
        let record = match self.read_f7_v12(gate.session_id, SUFFIX, SIGNING_MAX_V20) {
            Ok(bytes) => F7FundingSigningV20::decode(&bytes)?,
            Err(SessionStoreError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let predecessor = self.load_session_revision(
            gate.session_id,
            gate.bound_revision
                .checked_add(2)
                .ok_or(SessionStoreError::Quarantined)?,
        )?;
        let mut flags = predecessor.irreversible();
        flags.funding_authorized = true;
        let expected = predecessor.advance(
            predecessor.revision(),
            SessionPhaseV1::FundingAuthorized,
            predecessor.transcript_hash(),
            flags,
            predecessor.chain(),
            predecessor.encrypted_payload(),
        )?;
        if record.gate != gate.digest || record.predecessor != *predecessor.digest()
            || predecessor.phase() != gate.phase || predecessor.irreversible().funding_authorized
            || record.successor.as_bytes() != expected.as_bytes()
            || self.f7_ready_count_v12(gate, predecessor.revision())? != 2
            // The new runtime initially supports native ordinary recovery.
            // XMR cannot borrow this authority to bypass its recovery graph.
            || (gate.family == F7ExternalFamilyV11::Monero && gate.profile != F7RecoveryProfileV23::XmrBounded)
        {
            return Err(SessionStoreError::Quarantined);
        }
        require_f7_funding_window_v12(gate, predecessor.chain().tip_height)?;
        Ok(Some(record))
    }

    pub(super) fn audit_f7_funding_signing_v20(
        &self,
        gate: &F7GateRecordV12,
        record: &F7FundingSigningV20,
        current: &SessionRecordV1,
        complete: bool,
    ) -> Result<Option<SchnorrSignature>, SessionStoreError> {
        // Legitimate publish-before-successor cut: no nonce operation has an
        // accepted session yet. Only begin below can complete the exact CAS.
        if current.digest() == &record.predecessor && !complete {
            return Ok(None);
        }
        if current.phase() == SessionPhaseV1::FailedClosed && !complete {
            // A rejected signing edge may close the native session. Preserve
            // that terminal history without returning a spendable signature.
            let revision = current
                .revision()
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?;
            let predecessor = self.load_session_revision(gate.session_id, revision)?;
            if current.terms_hash() != predecessor.terms_hash()
                || current.irreversible() != predecessor.irreversible()
                || current.chain() != predecessor.chain()
                || current.encrypted_payload() != predecessor.encrypted_payload()
            {
                return Err(SessionStoreError::Quarantined);
            }
            require_exact_successor(&predecessor, predecessor.revision(), current)?;
            if predecessor.phase() != SessionPhaseV1::FundingAuthorized {
                return Err(SessionStoreError::Quarantined);
            }
            let _signature =
                self.audit_f7_funding_signing_v20(gate, record, &predecessor, false)?;
            return Ok(None);
        }
        let transaction = Transaction::from_bytes(&gate.funding_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (canonical, hash) =
            canonical_template_v1(&transaction).map_err(|_| SessionStoreError::Quarantined)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            return self.audit_xmr_bounded_funding_signature_v23(
                gate.session_id,
                current,
                complete,
            );
        }
        self.funding_authorized_signature_v20(
            gate.session_id,
            &gate.chain_id,
            &gate.terms_hash,
            &canonical,
            &hash,
            &record.successor,
            current,
            complete,
        )
    }

    /// Persist funding authorization before exposing a Funding-purpose signing
    /// session. A restart repairs only its exact retained successor.
    pub fn begin_f7_funding_signing_v20(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let (transaction, bound, native_bounded) = {
            let _guard = self.operation_lock()?;
            if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
                return Err(SessionStoreError::PolicyProfile);
            }
            let gate = self.load_f7_gate_v12(session)?;
            self.authenticate_f7_gate_ancestry_v12(&gate)?;
            let current = self.load_session_locked(session)?;
            if chain.as_bytes() != &gate.chain_id
                || context.chain_id() != &gate.chain_id
                || context.current_height() < current.chain().tip_height
                || context.now_unix_seconds() == 0
                || (gate.family == F7ExternalFamilyV11::Monero
                    && gate.profile != F7RecoveryProfileV23::XmrBounded)
                || self.operational_abort_transport_authority_exists(session)?
            {
                return Err(SessionStoreError::FundingAuthorityUnavailable);
            }
            let record = match self.optional_f7_funding_signing_v20(&gate)? {
                Some(record) => record,
                None => {
                    require_f7_funding_window_v12(&gate, context.current_height())?;
                    if current.phase() != gate.phase
                        || current.irreversible().funding_authorized
                        || current.revision()
                            != gate
                                .bound_revision
                                .checked_add(2)
                                .ok_or(SessionStoreError::Quarantined)?
                        || self.f7_ready_count_v12(&gate, current.revision())? != 2
                    {
                        return Err(SessionStoreError::FundingAuthorityUnavailable);
                    }
                    require_f7_funding_window_v12(&gate, current.chain().tip_height)?;
                    let mut flags = current.irreversible();
                    flags.funding_authorized = true;
                    let successor = current.advance(
                        current.revision(),
                        SessionPhaseV1::FundingAuthorized,
                        current.transcript_hash(),
                        flags,
                        current.chain(),
                        current.encrypted_payload(),
                    )?;
                    let record =
                        F7FundingSigningV20::new(gate.digest, *current.digest(), successor)?;
                    self.publish_f7_v12(session, SUFFIX, &record.bytes, SIGNING_MAX_V20)?;
                    test_crash_hook("f7-v20-funding-signing-after-record");
                    record
                }
            };
            if current.digest() == &record.predecessor {
                self.persist_session_record(&record.successor)?;
                test_crash_hook("f7-v20-funding-signing-after-successor");
            }
            let _signature = self.audit_f7_funding_signing_v20(
                &gate,
                &record,
                &self.load_session_locked(session)?,
                false,
            )?;
            let bound = match self.load_signing_binding(session, PurposeV1::Funding) {
                Ok(_) => true,
                Err(SessionStoreError::SessionNotFound) => false,
                Err(error) => return Err(error),
            };
            (
                Transaction::from_bytes(&gate.funding_template)
                    .map_err(|_| SessionStoreError::Quarantined)?,
                bound,
                gate.profile == F7RecoveryProfileV23::XmrBounded,
            )
        };
        if native_bounded {
            return self.resume_xmr_bounded_funding_signing_v23(chain, session);
        }
        if bound {
            return self.resume_operational_signing_session(chain, session, PurposeV1::Funding);
        }
        let roster =
            self.bootstrap_wallet_signing_roster_v18(chain, session, PurposeV1::Funding)?;
        // The native binder is restart-idempotent over the exact same roster,
        // template and canonical round prefix, including a pending local edge.
        self.bind_operational_signing_session(
            chain,
            session,
            ContractKindV1::WitnessOrTimeout,
            PurposeV1::Funding,
            roster,
            transaction,
            0,
            None,
        )
    }

    /// Aggregate only the six authenticated native funding edges, validate the
    /// exact transaction and durably commit it before returning submission bytes.
    pub fn complete_f7_funding_signing_v20(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<PreparedF7FundingSubmissionV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        if chain.as_bytes() != &gate.chain_id || context.chain_id() != &gate.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.read_f7_v12(session, "funding", COMMIT_MAX) {
            Ok(_) => {
                let commit = self.load_f7_funding_v12(&gate)?;
                let current = self.load_session_locked(session)?;
                if current.digest() == &commit.predecessor_digest {
                    self.persist_session_record(&commit.successor)?;
                } else if current.revision() < commit.successor.revision()
                    || self
                        .load_session_revision(session, commit.successor.revision())?
                        .as_bytes()
                        != commit.successor.as_bytes()
                {
                    return Err(SessionStoreError::Quarantined);
                }
                return Ok(f7_submission(&gate, commit.funding_bytes));
            }
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        let current = self.load_session_locked(session)?;
        if context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        // All six signatures may already be known to the peer. Persisting
        // their exact aggregate after expiry is recovery, not fresh funding.
        // The separate child transmission boundary rechecks the live window.
        let signing = self
            .optional_f7_funding_signing_v20(&gate)?
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        let signature = self
            .audit_f7_funding_signing_v20(&gate, &signing, &current, true)?
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        let mut transaction = Transaction::from_bytes(&gate.funding_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if transaction.kernels.len() != 1 {
            return Err(SessionStoreError::Quarantined);
        }
        transaction.kernels[0].excess_signature = signature.to_bytes();
        let bytes = canonical_dom_transaction_bytes_v1(&transaction)?;
        validate_exact_dom_transaction(&bytes, context)?;
        let successor = current.advance(
            current.revision(),
            SessionPhaseV1::FundingBroadcast,
            current.transcript_hash(),
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        let commit = F7FundingCommitV12::new(
            gate.digest,
            *current.digest(),
            &bytes,
            successor,
            context.now_unix_seconds(),
        )?;
        self.publish_f7_v12(session, "funding", &commit.bytes, COMMIT_MAX)?;
        test_crash_hook("f7-v20-funding-after-exact-bytes");
        self.persist_session_record(&commit.successor)?;
        test_crash_hook("f7-v20-funding-after-successor");
        let durable = self.load_f7_funding_v12(&gate)?;
        Ok(f7_submission(&gate, durable.funding_bytes))
    }
}
