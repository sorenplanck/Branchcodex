//! Authenticated F7 outbox facts for the coordinator's DOM child.
use super::*;

/// Funding-only observation facts. These never invent a refund transaction
/// identifier for an adaptor graph whose private U is not public yet.
pub struct RealDomFundingFactsV23 {
    chain_id: [u8; 32],
    shared_output_commitment: [u8; 33],
    funding_tx_hash: [u8; 32],
}
impl RealDomFundingFactsV23 {
    /// Authenticated DOM chain of the exact retained funding transaction.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }
    /// Shared collateral commitment actually created by that transaction.
    pub const fn shared_output_commitment(&self) -> &[u8; 33] {
        &self.shared_output_commitment
    }
    /// Canonical transaction identifier, never a template hash.
    pub const fn funding_tx_hash(&self) -> &[u8; 32] {
        &self.funding_tx_hash
    }
}

impl ContractsSessionStoreV1 {
    /// None means this existing session has no F7 profile. Missing committed
    /// funding below an existing gate is a refusal, never legacy fallback.
    pub fn retained_f7_funding_submission_v20(
        &self,
        session: [u8; 32],
    ) -> Result<Option<PreparedF7FundingSubmissionV12>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session)?;
        let gate = match self.load_f7_gate_v12(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => {
                let (inventory, _, _) = self.census_f7_artifacts_v12()?;
                if inventory.contains_key(&session) {
                    return Err(SessionStoreError::Quarantined);
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        if gate.family == F7ExternalFamilyV11::Monero
            && gate.profile != F7RecoveryProfileV23::XmrBounded
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let commit = match self.load_f7_funding_v12(&gate) {
            Err(SessionStoreError::SessionNotFound) => {
                return Err(SessionStoreError::FundingAuthorityUnavailable)
            }
            result => result?,
        };
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
        Ok(Some(f7_submission(&gate, commit.funding_bytes)))
    }

    /// Funding finality facts available before post-anchor claim issuance.
    /// The legacy reader is selected only in the absence of an F7 profile.
    pub fn real_dom_funding_facts_v20(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<RealDomFundingFactsV23, SessionStoreError> {
        let native = {
            let _guard = self.operation_lock()?;
            match self.load_f7_gate_v12(session) {
                Ok(gate) => {
                    if chain.as_bytes() != &gate.chain_id {
                        return Err(SessionStoreError::InvalidTransition);
                    }
                    self.authenticate_f7_gate_ancestry_v12(&gate)?;
                    let funding = self.load_f7_funding_v12(&gate)?;
                    Some(RealDomFundingFactsV23 {
                        chain_id: gate.chain_id,
                        shared_output_commitment: gate.role.shared_output_commitment(),
                        funding_tx_hash: *blake2b_256(&funding.funding_bytes).as_bytes(),
                    })
                }
                Err(SessionStoreError::SessionNotFound) => {
                    let (inventory, _, _) = self.census_f7_artifacts_v12()?;
                    if inventory.contains_key(&session) {
                        return Err(SessionStoreError::Quarantined);
                    }
                    None
                }
                Err(error) => return Err(error),
            }
        };
        match native {
            Some(facts) => Ok(facts),
            None => self
                .real_dom_contract_facts_v2(chain, session)
                .map(|facts| RealDomFundingFactsV23 {
                    chain_id: *facts.chain_id(),
                    shared_output_commitment: *facts.shared_output_commitment(),
                    funding_tx_hash: *facts.funding_tx_hash(),
                }),
        }
    }

    pub(in super::super) fn f7_plain_refund_hash_locked_v20(
        &self,
        session: [u8; 32],
    ) -> Result<Option<[u8; 32]>, SessionStoreError> {
        let gate = match self.load_f7_gate_v12(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => {
                let (inventory, _, _) = self.census_f7_artifacts_v12()?;
                if inventory.contains_key(&session) {
                    return Err(SessionStoreError::Quarantined);
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        if gate.family == F7ExternalFamilyV11::Monero {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(Some(*blake2b_256(&gate.refund_bytes).as_bytes()))
    }

    pub(in super::super) fn f7_plain_refund_broadcast_locked_v20(
        &self,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<Option<RefundBroadcastV1>, SessionStoreError> {
        if self.f7_plain_refund_hash_locked_v20(session)?.is_none() {
            return Ok(None);
        }
        // A claim exposure is published before its session-head CAS and
        // before the actuator attempt. Never reopen refund in that prefix,
        // even when the head still has adaptor_secret_exposed == false.
        if self.f7_final_claim_exposure_exists_v14(session)? {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let gate = self.load_f7_gate_v12(session)?;
        let funding = self.load_f7_funding_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if current.revision() < funding.successor.revision()
            || context.chain_id() != &gate.chain_id
            || context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || current.irreversible().adaptor_secret_exposed
            || !current.irreversible().funding_authorized
            || !matches!(
                current.phase(),
                SessionPhaseV1::FundingBroadcast
                    | SessionPhaseV1::FundingConfirmed
                    | SessionPhaseV1::ClaimSigning
                    | SessionPhaseV1::ClaimPrepared
                    | SessionPhaseV1::RefundEligible
                    | SessionPhaseV1::RefundBroadcast
                    | SessionPhaseV1::FailedClosed
            )
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        // Ordinary final refund carries a real native height-locked kernel.
        // The native validator enforces the signed deadline and all signatures.
        let refund = validate_exact_dom_transaction(&gate.refund_bytes, context)?;
        if canonical_template_v1(&refund)
            .map_err(|_| SessionStoreError::Quarantined)?
            .1
            != gate.role.refund_template_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        if current.phase() != SessionPhaseV1::RefundBroadcast {
            let successor = current.advance(
                current.revision(),
                SessionPhaseV1::RefundBroadcast,
                current.transcript_hash(),
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&successor)?;
            test_crash_hook("f7-v20-refund-after-broadcast-successor");
        }
        Ok(Some(RefundBroadcastV1 {
            exact_bytes: gate.refund_bytes,
        }))
    }

    pub(in super::super) fn authenticate_f7_plain_refund_locked_v20(
        &self,
        session: [u8; 32],
        candidate: &[u8],
    ) -> Result<Option<AuthenticatedContractsRefundV1>, SessionStoreError> {
        if self.f7_plain_refund_hash_locked_v20(session)?.is_none() {
            return Ok(None);
        }
        // A claim exposure is published before its session-head CAS and
        // before the actuator attempt. Never reopen refund in that prefix,
        // even when the head still has adaptor_secret_exposed == false.
        if self.f7_final_claim_exposure_exists_v14(session)? {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let gate = self.load_f7_gate_v12(session)?;
        let funding = self.load_f7_funding_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if !matches!(
            current.phase(),
            SessionPhaseV1::RefundBroadcast | SessionPhaseV1::Refunded
        ) || current.irreversible().adaptor_secret_exposed
            || candidate != gate.refund_bytes
            || current.revision() < funding.successor.revision()
            || self
                .load_session_revision(session, funding.successor.revision())?
                .as_bytes()
                != funding.successor.as_bytes()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        // The gate authenticated the complete native final-refund round. The
        // existing scanner's proof format holds public digests, not serialized
        // legacy authorities. Bind its two custody fields to the V12 gate and
        // V12 signed funding commit, whose domain tags differ from M.8 records.
        Ok(Some(AuthenticatedContractsRefundV1 {
            session_id: session,
            transaction_hash: *blake2b_256(candidate).as_bytes(),
            exact_bytes_digest: tagged_hash(REFUND_HASH_TAG, candidate),
            funding_artifact_digest: gate.digest,
            funding_consumption_digest: funding.digest,
            funding_broadcast_record_digest: *funding.successor.digest(),
            refund_phase_record_digest: *current.digest(),
        }))
    }

    /// This guard precedes a new private signing operation. Recovery of an
    /// already-issued DSC1 edge and aggregation remain possible after expiry.
    pub fn require_f7_funding_signing_window_v20(
        &self,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if context.chain_id() != &gate.chain_id
            || context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || current.phase() != SessionPhaseV1::FundingAuthorized
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_f7_funding_window_v12(&gate, context.current_height())
    }

    /// Deadline is rechecked at transmission after signing/materialization.
    pub fn require_f7_funding_transmission_v20(
        &self,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        let _funding = self.load_f7_funding_v12(&gate)?;
        if context.chain_id() != &gate.chain_id
            || context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || current.irreversible().adaptor_secret_exposed
            || !matches!(
                current.phase(),
                SessionPhaseV1::FundingBroadcast | SessionPhaseV1::FundingConfirmed
            )
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_f7_funding_window_v12(&gate, context.current_height())
    }
}
