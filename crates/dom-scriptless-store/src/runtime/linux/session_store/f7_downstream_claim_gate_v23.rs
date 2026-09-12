//! Same-opening proof gate for composed upstream Claim signing.
//! Persisted role bindings require this gate after every restart; the cache is
//! not an independently serializable authority and contains no scalar.
//! Its 60-second ceiling is only an additional condition: every existing F7
//! authorization, anchor/policy check and funding window remains mandatory.
use super::*;
use dom_final_claim_binding::{ComposedSettlementLegV1, FinalClaimSecretSourceV1};
use std::time::{Duration, Instant};

pub(in super::super) struct DownstreamClaimLeaseV23 {
    target_gate: [u8; 32],
    target_role: [u8; 32],
    source_scope: [u8; 32],
    observed_transaction: [u8; 32],
    observation_started: Instant,
}

impl ContractsSessionStoreV1 {
    pub(in super::super) fn require_downstream_claim_gate_for_session_locked_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let gate = self.load_f7_gate_v12(session)?;
        self.require_downstream_claim_gate_locked_v23(&gate)
    }

    pub(in super::super) fn require_downstream_claim_outbound_locked_v23(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
    ) -> Result<(), SessionStoreError> {
        let claim = matches!(
            request.authority_class,
            OutboundDsc1AuthorityClassV1::UniversalClaimPreSignatureV12
                | OutboundDsc1AuthorityClassV1::UniversalFinalClaimV14
        ) || (request.authority_class.is_operational_signing()
            && signing_payload_purpose(request.message_type, &request.payload)?
                == PurposeV1::ClaimAdaptor);
        if claim && self.xmr_bounded_funding_profile_locked_v23(request.session_id)? {
            self.require_downstream_claim_gate_for_session_locked_v23(request.session_id)?;
        }
        Ok(())
    }

    /// Read-only profile query. Missing pre-funding gate is pending, not an
    /// instruction to create authority or reconstruct a missing live journal.
    pub fn native_downstream_claim_gate_required_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = match self.load_f7_gate_v12(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        if chain.as_bytes() != &gate.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        requires(&gate)
    }

    /// The Store starts the clock before the real scanner callback and holds
    /// no operation lock while RPC runs. Opaque opening proof, native 0x0f and
    /// both immutable role bindings are checked again before authorizing use.
    /// Absence or failure invalidates the previous same-open proof immediately.
    pub fn with_verified_downstream_dom_claim_v23<F>(
        &self,
        chain: TrustedChainIdV1,
        target_session: [u8; 32],
        downstream: &ContractsSessionStoreV1,
        observe: F,
    ) -> Result<bool, SessionStoreError>
    where
        F: FnOnce(
            &F7ClaimObserverFactsV15,
        ) -> Result<Option<VerifiedDomClaimObservationV1>, SessionStoreError>,
    {
        let started = Instant::now();
        if std::ptr::eq(self, downstream) {
            return Err(SessionStoreError::InvalidTransition);
        }
        let target = {
            let _guard = self.operation_lock()?;
            let gate = self.load_f7_gate_v12(target_session)?;
            if chain.as_bytes() != &gate.chain_id || !requires(&gate)? {
                return Err(SessionStoreError::InvalidTransition);
            }
            self.process_downstream_claim_gates_v23
                .lock()
                .map_err(|_| SessionStoreError::Quarantined)?
                .remove(&target_session);
            gate
        };
        let source_session = target.role.source_scope().source_session_id().0;
        let (source, source_issued, source_pre, local) = {
            let _guard = downstream.operation_lock()?;
            let (gate, issued, _) = match downstream.authenticate_f7_claim_v12(source_session) {
                Ok(value) => value,
                Err(SessionStoreError::SessionNotFound) => return Ok(false),
                Err(error) => return Err(error),
            };
            let pre = match downstream.load_f7_pre_v12(source_session) {
                Ok(value) => value,
                Err(SessionStoreError::SessionNotFound) => return Ok(false),
                Err(error) => return Err(error),
            };
            let local = downstream
                .authenticate_local_transport_signer_binding(source_session)?
                .participant_id;
            require_source(&target, &gate)?;
            (gate, issued.digest, pre.digest, local)
        };
        let Some(facts) =
            downstream.f7_claim_verification_facts_v15(chain, source_session, local)?
        else {
            return Ok(false);
        };
        let Some(observation) = observe(&facts)? else {
            return Ok(false);
        };
        if started.elapsed() > Duration::from_secs(60)
            || observation.chain_id() != chain.as_bytes()
            || observation.session_id() != &source_session
            || observation.template_hash() != &facts.template_hash()
            || observation.shared_output_commitment() != &facts.shared_commitment()
            || observation.adaptor_point().to_compressed_bytes() != target.role.adaptor_point_sec1()
            || observation.adaptor_point().to_compressed_bytes() != source.role.adaptor_point_sec1()
            || observation.kernel_index() != source.role.claim_kernel_index()
            || !observed_claim_has_depth(
                observation.location().block_height,
                observation.location().block_hash,
                observation.observed_tip_height(),
                *observation.observed_tip_id(),
                facts.minimum_confirmations(),
            )
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        {
            let _guard = downstream.operation_lock()?;
            let (current, issued, _) = downstream.authenticate_f7_claim_v12(source_session)?;
            let pre = downstream.load_f7_pre_v12(source_session)?;
            if current.digest != source.digest
                || issued.digest != source_issued
                || pre.digest != source_pre
            {
                return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
            }
            require_source(&target, &current)?;
        }
        let _guard = self.operation_lock()?;
        let current = self.load_f7_gate_v12(target_session)?;
        if current.digest != target.digest || started.elapsed() > Duration::from_secs(60) {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.process_downstream_claim_gates_v23
            .lock()
            .map_err(|_| SessionStoreError::Quarantined)?
            .insert(
                target_session,
                DownstreamClaimLeaseV23 {
                    target_gate: current.digest,
                    target_role: current.role.digest(),
                    source_scope: current.role.source_scope().digest(),
                    observed_transaction: *observation.tx_hash(),
                    observation_started: started,
                },
            );
        self.require_downstream_claim_gate_locked_v23(&current)?;
        Ok(true)
    }

    pub(super) fn require_downstream_claim_gate_locked_v23(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<(), SessionStoreError> {
        if !requires(gate)? {
            return Ok(());
        }
        let leases = self
            .process_downstream_claim_gates_v23
            .lock()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let lease = leases
            .get(&gate.session_id)
            .ok_or(SessionStoreError::ClaimSigningAuthorityUnavailable)?;
        if lease.target_gate != gate.digest
            || lease.target_role != gate.role.digest()
            || lease.source_scope != gate.role.source_scope().digest()
            || lease.observed_transaction == [0; 32]
            || lease.observation_started.elapsed() > Duration::from_secs(60)
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(())
    }
}

fn requires(gate: &F7GateRecordV12) -> Result<bool, SessionStoreError> {
    if gate.role.secret_source() != FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23 {
        return Ok(false);
    }
    if gate.family != F7ExternalFamilyV11::Monero
        || gate.profile != F7RecoveryProfileV23::XmrBounded
        || gate.role.route_leg() != ComposedSettlementLegV1::Upstream
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(true)
}

fn require_source(
    target: &F7GateRecordV12,
    source: &F7GateRecordV12,
) -> Result<(), SessionStoreError> {
    let scope = target.role.source_scope();
    if source.role.route_leg() != ComposedSettlementLegV1::Downstream
        || source.role.secret_source() != FinalClaimSecretSourceV1::LocalOrigin
        || source.chain_id != target.chain_id
        || source.role.route_id() != target.role.route_id()
        || source.role.composition_binding_digest() != target.role.composition_binding_digest()
        || source.role.composed_role_plan_digest() != target.role.composed_role_plan_digest()
        || source.role.adaptor_point_sec1() != target.role.adaptor_point_sec1()
        || scope.source_chain_id().0 != source.chain_id
        || scope.source_settlement_id() != source.role.terms().settlement_id
        || scope.source_session_id().0 != source.session_id
        || scope.source_claim_template_hash() != source.role.claim_template_hash()
        || scope.adaptor_secret_origin_id() != source.role.adaptor_secret_origin_id()
        || scope.adaptor_secret_origin_id() != source.role.dom_claim_sender_id()
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}
