//! Native bounded-availability ancestry. No legacy template commitment or
//! ordinary final-refund envelope can stand in for the V23 graph transcripts.
use super::*;
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

impl ContractsSessionStoreV1 {
    /// Transfer only a completed parent U ingress into its exact native ready
    /// gate. This validates both process-bound handles and historical custody.
    pub fn require_xmr_bounded_ready_handoff_v23(
        &self,
        ingress: &PreparedXmrGraphSigningIngressV23,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        self.authenticate_xmr_bounded_f7_ancestry_v23(&gate)?;
        self.require_xmr_refund_ingress_terminal_v23(ingress, gate.session_id, gate.bound_revision)
    }

    /// Reopen only the exact native bounded profile; never adopt a legacy gate.
    /// First issuance requires the terminal native graph and durable Ready custody.
    pub fn prepare_or_resume_xmr_bounded_f7_gate_v23(
        &self,
        chain: TrustedChainIdV1,
        input: F7FundingGatePreparationV12<'_>,
    ) -> Result<PreparedF7FundingGateV12, SessionStoreError> {
        let F7RecoveryPreparationV12::XmrBoundedV23 {
            produced,
            custody,
            setup,
            ordinary_rounds,
        } = &input.recovery
        else {
            return Err(SessionStoreError::InvalidTransition);
        };
        let role = input.role;
        self.revalidate_xmr_ordinary_recovery_rounds_v11(
            ordinary_rounds,
            role,
            produced.graph(),
            produced.economic().policy(),
            custody,
        )?;
        let session = role.session_id().0;
        custody
            .revalidate()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let _guard = self.operation_lock()?;
        let terms = role
            .terms_hash()
            .map_err(|_| SessionStoreError::Canonical)?;
        if chain.as_bytes() != &role.dom_chain_id().0
            || input.context.chain_id() != chain.as_bytes()
            || input.context.now_unix_seconds() == 0
            || setup.terms_hash() != terms
            || setup.settlement_id() != role.settlement_id().0
            || setup.claim().secp_compressed != role.adaptor_point_sec1()
            || input.collateral.terms_hash() != &terms
            || input.collateral.aggregate_commitment() != &role.shared_output_commitment()
            || produced.economic().bp_statement_hash()
                != &input.collateral.statement().statement_hash()
            || canonical_dom_transaction_bytes_v1(input.funding_template)?
                != canonical_dom_transaction_bytes_v1(produced.graph().funding_template())?
            || canonical_dom_transaction_bytes_v1(input.claim_template)?
                != canonical_dom_transaction_bytes_v1(produced.graph().claim_template())?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        let scope = self.require_xmr_graph_custody_ready_locked_v23(
            role,
            produced,
            custody.scope().custody_id,
        )?;
        if &scope != custody.scope() {
            return Err(SessionStoreError::Conflict);
        }
        match self.load_f7_gate_v12(session) {
            Ok(gate) => {
                self.authenticate_xmr_bounded_f7_ancestry_v23(&gate)?;
                if gate.role.canonical_bytes()
                    != role
                        .canonical_bytes()
                        .map_err(|_| SessionStoreError::Canonical)?
                    || gate.custody_id != scope.custody_id
                    || gate.xmr_setup_binding_hash != setup.binding_hash()
                    || gate.xmr_funding_tx_hash != setup.funding_tx_hash()
                {
                    return Err(SessionStoreError::Conflict);
                }
                Ok(self.f7_handle_v12(&gate))
            }
            Err(SessionStoreError::SessionNotFound) => {
                let current = self.load_session_locked(session)?;
                let statement = input.collateral.statement();
                if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified
                    || current.phase() != SessionPhaseV1::RefundSigning
                    || current.irreversible().funding_authorized
                    || current.irreversible().adaptor_secret_exposed
                    || !current.irreversible().any_signing_share_sent
                    || input.context.current_height() < current.chain().tip_height
                    || role.terms().counterparty_leg.mechanism
                        != LockMechanism::CrossCurveSharedSpend
                    || ordinary_rounds.parent_session() != &session
                    || ordinary_rounds.parent_record_digest() != current.digest()
                    || ordinary_rounds.role_digest()
                        != &role.digest().map_err(|_| SessionStoreError::Canonical)?
                    || ordinary_rounds.custody_id() != &scope.custody_id
                    || ordinary_rounds.graph_digest() != produced.graph().graph_digest()
                    || statement.chain_id() != *chain.as_bytes()
                    || statement.session_id() != session
                    || self.funding_gate_exists(session)?
                    || self.m8_funding_gate_exists(session)?
                    || self.m8_funding_gate_v2_exists(session)?
                    || self.any_operational_issuance_exists(session)?
                    || self.any_operational_commit_exists(session)?
                    || self.operational_abort_transport_authority_exists(session)?
                {
                    return Err(SessionStoreError::FundingAuthorityUnavailable);
                }
                self.require_no_pre_anchor_claim_signing_evidence(session, current.revision())?;
                produced
                    .graph()
                    .require_claim_window(input.context.current_height())
                    .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
                let (cancel, compensation) = produced.ordinary_sessions();
                let gate = F7GateRecordV12::new(
                    role,
                    &current,
                    F7ExternalFamilyV11::Monero,
                    SessionPhaseV1::RefundSigning,
                    F7RecoveryProfileV23::XmrBounded,
                    statement.statement_hash(),
                    *statement.recovery_binding_hash(),
                    *produced.graph().graph_digest(),
                    scope.custody_id,
                    *ordinary_rounds.scope_digest(),
                    cancel,
                    compensation,
                    setup.binding_hash(),
                    setup.funding_tx_hash(),
                    encode_xmr_graph_binding_v12(produced.graph().binding()),
                    produced
                        .economic()
                        .policy()
                        .policy()
                        .to_bytes()
                        .map_err(|_| SessionStoreError::Canonical)?,
                    canonical_dom_transaction_bytes_v1(input.funding_template)?,
                    canonical_dom_transaction_bytes_v1(input.claim_template)?,
                    vec![],
                )?;
                self.authenticate_xmr_bounded_f7_ancestry_v23(&gate)?;
                require_f7_funding_window_v12(&gate, input.context.current_height())?;
                self.publish_f7_v12(session, "gate", &gate.bytes, GATE_MAX)?;
                let durable = self.load_f7_gate_v12(session)?;
                if durable.bytes != gate.bytes {
                    return Err(SessionStoreError::Quarantined);
                }
                self.authenticate_xmr_bounded_f7_ancestry_v23(&durable)?;
                test_crash_hook("f7-v23-after-bounded-gate");
                Ok(self.f7_handle_v12(&durable))
            }
            Err(error) => Err(error),
        }
    }

    // Historical: the live parent may already be funded. The bound revision
    // must be exactly the terminal of the native U round, before either vote.
    pub(super) fn authenticate_xmr_bounded_f7_ancestry_v23(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<ProducedXmrRecoveryGraphV12, SessionStoreError> {
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
            || gate.phase != SessionPhaseV1::RefundSigning
        {
            return Err(SessionStoreError::Quarantined);
        }
        let chain = self.require_process_trusted_chain_v23(&gate.chain_id)?;
        let role = FinalClaimRoleBindingV1::decode_canonical(&chain, gate.role.canonical_bytes())
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (scope, produced) =
            self.reconstruct_ready_xmr_graph_locked_v25(&role, gate.custody_id)?;
        let graph = produced.graph();
        let binding = self.authenticate_xmr_graph_signing_session_v23(
            gate.session_id,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        let bound = self.load_session_revision(gate.session_id, gate.bound_revision)?;
        let early = self.load_early_transport_authority(gate.session_id)?;
        let bp = self.load_bp_transport_authority(gate.session_id)?;
        let roster = self.load_transport_roster(gate.session_id)?;
        let identities = self.load_transport_identity_binding(gate.session_id)?;
        require_transport_identity_binding(&roster, &identities)?;
        let (cancel, compensation) = produced.ordinary_sessions();
        if binding.start.revision().checked_add(6) != Some(gate.bound_revision)
            || bound.digest() != &gate.bound_record_digest
            || bound.phase() != SessionPhaseV1::RefundSigning
            || bound.terms_hash() != gate.terms_hash
            || bound.irreversible().funding_authorized
            || bound.irreversible().adaptor_secret_exposed
            || !bound.irreversible().any_signing_share_sent
            || scope.graph_digest != gate.graph_digest
            || roster.chain_id != gate.chain_id
            || early.terms_hash != gate.terms_hash
            || bp.terms_hash != gate.terms_hash
            || bp.early_authority_digest != early.digest
            || bp.statement.statement_hash() != gate.bp_statement_hash
            || early.recovery_binding_hash != gate.recovery_binding_hash
            || produced.economic().bp_statement_hash() != &gate.bp_statement_hash
            || produced
                .economic()
                .policy()
                .policy()
                .bounded_availability_v23
                .is_none()
            || produced
                .economic()
                .policy()
                .policy()
                .to_bytes()
                .map_err(|_| SessionStoreError::Quarantined)?
                != gate.policy_bytes
            || encode_xmr_graph_binding_v12(graph.binding()) != gate.graph_binding_bytes
            || canonical_dom_transaction_bytes_v1(graph.funding_template())?
                != gate.funding_template
            || canonical_dom_transaction_bytes_v1(graph.claim_template())? != gate.claim_template
            || cancel != gate.cancel_session
            || compensation != gate.compensation_session
            || self.m8_funding_gate_v2_exists(gate.session_id)?
            || self.m8_funding_gate_exists(gate.session_id)?
            || self.funding_gate_exists(gate.session_id)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        let cancel_digest =
            self.audit_xmr_plain_auxiliary_round_v11(&roster, cancel, graph.cancel_bytes())?;
        let compensation_digest =
            self.audit_xmr_plain_auxiliary_round_v11(&roster, compensation, graph.punish_bytes())?;
        let mut bytes = Vec::new();
        for digest in [
            gate.chain_id,
            gate.session_id,
            gate.terms_hash,
            gate.bound_record_digest,
            gate.role.digest(),
            gate.graph_digest,
            gate.custody_id,
            cancel,
            compensation,
            cancel_digest,
            compensation_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        if tagged_hash("DOM-INTEROP/XMR-ORDINARY-RECOVERY-ROUNDS/V11\0", &bytes)
            != gate.ordinary_scope
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(produced)
    }
}
