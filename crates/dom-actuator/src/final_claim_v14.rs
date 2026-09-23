//! Universal F7 final claim using the native actuator's existing operation,
//! fencing and admission mirror. The mirror format is chain-neutral; the
//! Contracts authority remains the separate F7 profile throughout.
use super::*;
use dom_adaptor::AdaptorSecret;
use dom_scriptless_store::{
    AdmittedF7FinalClaimV14, ConsumedF7ClaimAuthorizationV12, F7FinalClaimActionV14,
    F7FinalClaimFactsV14, PreparedF7FinalClaimSubmissionV14,
};

/// One route-authorized claim adaptation. Secret bytes are borrowed privately.
pub struct DomF7FinalClaimRequestV14<'a> {
    /// Exact coordinator action for this DOM participant.
    pub scope: ScopedDomActionV1,
    /// Native consumed authority, refreshed by the selected family observer.
    pub authority: &'a ConsumedF7ClaimAuthorizationV12,
    /// Private local-origin secret or independently verified public revelation.
    pub secret: &'a AdaptorSecret,
    /// Fresh retained DOM tip used to finalize the transaction.
    pub validation_height: u64,
    /// Current time for the actuator's retained lease.
    pub now_unix_ms: u64,
}
/// Both native persistence boundaries completed before a send can occur.
pub struct DomF7FinalClaimSubmissionV14 {
    prepared: PreparedF7FinalClaimSubmissionV14,
    latched: LatchedFinalClaimSubmissionV2,
}
impl DomF7FinalClaimSubmissionV14 {
    /// Exact retained transaction, suitable for diagnostics without bytes.
    pub fn tx_hash(&self) -> [u8; 32] {
        self.prepared.tx_hash()
    }
}
/// Both native economic admission and the actuator mirror are durable.
pub struct DomF7FinalClaimAdmissionV14 {
    admitted: AdmittedF7FinalClaimV14,
}
impl DomF7FinalClaimAdmissionV14 {
    /// Exact admitted transaction identity.
    pub fn tx_hash(&self) -> [u8; 32] {
        self.admitted.tx_hash()
    }
    /// Hand the closed native admission to the Contracts 0x12 producer.
    pub fn into_transport_authority(self) -> AdmittedF7FinalClaimV14 {
        self.admitted
    }
}

impl DomContractsActuatorV1<'_> {
    /// Prepare or recover the same owner's M.8 claim operation before exposure.
    /// The V21 journal recovery verifies the prior fence and exact evidence;
    /// it does not grant another owner permission to replace a prepared claim.
    pub fn authorize_post_m8_claim_broadcast_v22(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        chain: &TrustedChainIdV1,
        authority: &ConsumedClaimSigningAuthorizationV2,
        now: u64,
    ) -> DomActuatorResult<(DomActuatorCapabilityV1, DomOperationDispositionV1)> {
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence = self.revalidate_claim_authority_v2(chain, authority)?;
        let _previous = control.f7_claim_previous_authorization_v21(lease, scope, evidence, now)?;
        control.authorize_f7_claim_action_v21(lease, scope, evidence, now)
    }

    /// Recover the post-M.8 exposure-before-mirror crash prefix. The exact
    /// native exposure is the authority; no new signature is constructed.
    pub fn resume_post_m8_claim_child_v22(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        scope: ScopedDomActionV1,
        now: u64,
    ) -> DomActuatorResult<()> {
        self.require_trusted_chain_binding(chain)?;
        if scope.binding() != self.binding || scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        match control.audit_final_claim_custody_v2(lease, self.binding, now) {
            Ok(mirror) => {
                if mirror.effect_id() != scope.effect_id() {
                    return Err(DomActuatorError::CapabilityMismatch);
                }
                // The child binding/dispatch independently compares this mirror
                // against native Contracts custody before it can submit.
                return Ok(());
            }
            Err(DomActuatorError::ReconciliationRequired) => {}
            Err(error) => return Err(error),
        }
        let authority = self.resume_consumed_final_claim_authority_v2(chain)?;
        let evidence = self.revalidate_claim_authority_v2(chain, &authority)?;
        let _previous = control
            .f7_claim_previous_authorization_v21(lease, scope, evidence, now)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        let (capability, _) = control.authorize_f7_claim_action_v21(lease, scope, evidence, now)?;
        let prepared = self
            .session_store
            .resume_operational_final_claim_broadcast_v2(*chain, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let restored_latch = self.latch_exposed_final_claim_attempt_v2(
            control,
            lease,
            &capability,
            &authority,
            &prepared,
            now,
        )?;
        if restored_latch.session_id() != prepared.session_id()
            || restored_latch.tx_hash() != prepared.tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        // This path only restores the owner-only latch after native exposure.
        // The settlement child audits custody and gates any later submission.
        Ok(())
    }

    fn require_f7_final_facts_v14(&self, facts: &F7FinalClaimFactsV14) -> DomActuatorResult<()> {
        if facts.session_id() != self.binding.session_id()
            || facts.chain_id() != self.binding.chain_id()
            || facts.terms_hash() != self.binding.terms_digest()
            || facts.sender() != self.binding.participant().participant_id()
            || facts.receiver() == facts.sender()
            || facts.minimum_confirmations() != self.binding.min_confirmations()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(())
    }

    /// Prepare the exact route action, adapt and persist under fresh F7, then
    /// latch the control-plane attempt. No network call is made while borrowed.
    pub fn prepare_and_expose_f7_final_claim_v14(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        request: DomF7FinalClaimRequestV14<'_>,
    ) -> DomActuatorResult<DomF7FinalClaimSubmissionV14> {
        self.require_trusted_chain_binding(chain)?;
        if request.scope.binding() != self.binding
            || request.scope.action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let facts = self
            .session_store
            .revalidate_f7_final_claim_authority_v14(
                request.authority,
                *chain,
                self.binding.participant().participant_id(),
            )
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        let _previous = control.f7_claim_previous_authorization_v21(
            lease,
            request.scope,
            facts.evidence_digest(),
            request.now_unix_ms,
        )?;
        let (capability, _) = control.authorize_f7_claim_action_v21(
            lease,
            request.scope,
            facts.evidence_digest(),
            request.now_unix_ms,
        )?;
        control.require_prepared_final_claim_authority_v2(
            lease,
            &capability,
            facts.evidence_digest(),
            request.now_unix_ms,
        )?;
        let action = F7FinalClaimActionV14 {
            participant_id: facts.sender(),
            action_scope_digest: claim_action_scope_digest_v2(
                request.scope,
                facts.evidence_digest(),
            ),
            validation_height: request.validation_height,
        };
        let prepared = self
            .session_store
            .finalize_and_persist_f7_claim_v14(request.authority, *chain, &action, request.secret)
            .map_err(map_f7_claim_store_error_v21)?;
        let attempt = final_attempt_facts_v14(&facts, &prepared)?;
        let latched = control.latch_final_claim_attempt_v2(
            lease,
            &capability,
            &attempt,
            request.now_unix_ms,
        )?;
        Ok(DomF7FinalClaimSubmissionV14 { prepared, latched })
    }

    /// Recover exact exposed bytes and the missing mirror/attempt. This path
    /// does not need fresh signing authority or access to the secret again.
    pub fn resume_f7_final_claim_submission_v14(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        request: SameOwnerFinalClaimRecoveryRequestV2,
    ) -> DomActuatorResult<DomF7FinalClaimSubmissionV14> {
        self.require_trusted_chain_binding(chain)?;
        if request.scope.binding() != self.binding
            || request.scope.action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let facts = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        let prepared = self
            .session_store
            .resume_f7_final_claim_submission_v14(
                *chain,
                self.binding.session_id(),
                facts.sender(),
                claim_action_scope_digest_v2(request.scope, facts.evidence_digest()),
            )
            .map_err(map_f7_claim_store_error_v21)?;
        let attempt = final_attempt_facts_v14(&facts, &prepared)?;
        let capability = match control.authorize_action(
            lease,
            request.scope,
            facts.evidence_digest(),
            None,
            request.now_unix_ms,
        ) {
            Ok((
                capability,
                DomOperationDispositionV1::Idempotent | DomOperationDispositionV1::AlreadyCompleted,
            )) => capability,
            Ok(_) => return Err(DomActuatorError::ReconciliationRequired),
            Err(DomActuatorError::ReconciliationRequired) => control
                .reauthorize_same_owner_final_claim_replay_v2(
                    lease,
                    request.scope,
                    request.previous_authorization_digest,
                    &attempt,
                    request.now_unix_ms,
                )?,
            Err(e) => return Err(e),
        };
        let latched = control.latch_final_claim_attempt_v2(
            lease,
            &capability,
            &attempt,
            request.now_unix_ms,
        )?;
        Ok(DomF7FinalClaimSubmissionV14 { prepared, latched })
    }

    /// Submit with neither an SQLite transaction nor a Contracts lock held.
    /// Missing service is retryable; malformed or substituted evidence is not.
    pub fn dispatch_f7_final_claim_v14(
        &self,
        runtime: &RealDomRpcRuntimeV1,
        submission: &DomF7FinalClaimSubmissionV14,
    ) -> DomActuatorResult<SubmissionReceiptV1> {
        self.require_dom_runtime_binding(runtime)?;
        if submission.prepared.session_id() != self.binding.session_id()
            || submission.prepared.chain_id() != self.binding.chain_id()
            || submission.latched.session_id() != self.binding.session_id()
            || submission.latched.tx_hash() != submission.prepared.tx_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        runtime
            .submit_persisted_f7_final_claim_v14(&submission.prepared)
            .map_err(|e| match e {
                RealDomError::Chain(
                    ChainAdapterError::TemporarilyUnavailable
                    | ChainAdapterError::CapabilityUnavailable,
                )
                | RealDomError::LockPoisoned => DomActuatorError::RpcAuthorityUnavailable,
                _ => DomActuatorError::CapabilityMismatch,
            })
    }

    /// Commit the native node receipt first, then its mirror. If the process
    /// stops between writes, resume repairs the mirror without sending again.
    pub fn commit_f7_final_claim_admission_v14(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        submission: DomF7FinalClaimSubmissionV14,
        receipt: SubmissionReceiptV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomF7FinalClaimAdmissionV14> {
        self.require_trusted_chain_binding(chain)?;
        if submission.prepared.session_id() != self.binding.session_id()
            || receipt.tx_hash() != submission.prepared.tx_hash()
            || !receipt.is_economically_admitted()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let admitted = self
            .session_store
            .complete_f7_final_claim_admission_v14(submission.prepared, receipt)
            .map_err(map_f7_claim_store_error_v21)?;
        self.complete_f7_admission_mirror_v14(control, lease, chain, admitted, now_unix_ms)
    }

    /// Repair or reissue the native admission and mirror without another RPC.
    pub fn resume_f7_final_claim_admission_v14(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        request: SameOwnerFinalClaimRecoveryRequestV2,
    ) -> DomActuatorResult<DomF7FinalClaimAdmissionV14> {
        self.require_trusted_chain_binding(chain)?;
        if request.scope.binding() != self.binding
            || request.scope.action() != DomActionV1::BroadcastClaim
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let admitted = self
            .session_store
            .resume_f7_final_claim_admission_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        let facts = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        match control.resume_final_claim_admission_v2(lease, self.binding, request.now_unix_ms) {
            Ok(mirror) => {
                if mirror.effect_id() != request.scope.effect_id() {
                    return Err(DomActuatorError::CapabilityMismatch);
                }
                require_matching_f7_admission_mirror_v14(&facts, &admitted, &mirror)?;
                return Ok(DomF7FinalClaimAdmissionV14 { admitted });
            }
            Err(DomActuatorError::ReconciliationRequired) => {}
            Err(error) => return Err(error),
        }
        let attempt = FinalClaimAttemptFactsV2 {
            authority_evidence_digest: facts.evidence_digest(),
            dom_claim_sender_id: facts.sender(),
            final_claim_receiver_id: facts.receiver(),
            tx_hash: admitted.tx_hash(),
            template_hash: facts.template_hash(),
            shared_output_commitment: facts.shared_commitment(),
            exposure_record_digest: admitted.exposure_digest(),
        };
        match control.authorize_action(
            lease,
            request.scope,
            facts.evidence_digest(),
            None,
            request.now_unix_ms,
        ) {
            Ok((_, DomOperationDispositionV1::AlreadyCompleted)) => {}
            Ok(_) => return Err(DomActuatorError::ReconciliationRequired),
            Err(DomActuatorError::ReconciliationRequired) => {
                // Re-fence the retained attempt only. An admission already
                // exists in Contracts: do not latch or count another send.
                control.reauthorize_same_owner_final_claim_replay_v2(
                    lease,
                    request.scope,
                    request.previous_authorization_digest,
                    &attempt,
                    request.now_unix_ms,
                )?;
            }
            Err(error) => return Err(error),
        }
        self.complete_f7_admission_mirror_v14(control, lease, chain, admitted, request.now_unix_ms)
    }
    fn complete_f7_admission_mirror_v14(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        admitted: AdmittedF7FinalClaimV14,
        now_unix_ms: u64,
    ) -> DomActuatorResult<DomF7FinalClaimAdmissionV14> {
        let facts = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        let mirror = control.persist_f7_final_claim_admission_mirror_v14(
            lease,
            self.binding,
            &FinalClaimTransportAuthorityFactsV2 {
                session_id: facts.session_id(),
                dom_claim_sender_id: facts.sender(),
                final_claim_receiver_id: facts.receiver(),
            },
            &admitted,
            now_unix_ms,
        )?;
        require_matching_f7_admission_mirror_v14(&facts, &admitted, &mirror)?;
        Ok(DomF7FinalClaimAdmissionV14 { admitted })
    }
}
fn require_matching_f7_admission_mirror_v14(
    facts: &F7FinalClaimFactsV14,
    admitted: &AdmittedF7FinalClaimV14,
    mirror: &DomFinalClaimAdmissionV2,
) -> DomActuatorResult<()> {
    if mirror.session_id() != facts.session_id()
        || mirror.dom_claim_sender_id() != facts.sender()
        || mirror.final_claim_receiver_id() != facts.receiver()
        || mirror.tx_hash() != admitted.tx_hash()
        || mirror.exposure_record_digest() != admitted.exposure_digest()
        || mirror.submission_state() != admitted.receipt_state()
        || mirror.was_relayed() != admitted.was_relayed()
        || mirror.receipt_digest() != admitted.receipt_digest()
    {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(())
}
fn final_attempt_facts_v14(
    facts: &F7FinalClaimFactsV14,
    prepared: &PreparedF7FinalClaimSubmissionV14,
) -> DomActuatorResult<FinalClaimAttemptFactsV2> {
    if prepared.session_id() != facts.session_id() || prepared.chain_id() != facts.chain_id() {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    Ok(FinalClaimAttemptFactsV2 {
        authority_evidence_digest: facts.evidence_digest(),
        dom_claim_sender_id: facts.sender(),
        final_claim_receiver_id: facts.receiver(),
        tx_hash: prepared.tx_hash(),
        template_hash: facts.template_hash(),
        shared_output_commitment: facts.shared_commitment(),
        exposure_record_digest: prepared.exposure_digest(),
    })
}

impl DomContractsActuatorV1<'_> {
    /// Observe the selected native claim profile using the sole Store opening.
    /// Verification is deferred until the completed round exists. Universal
    /// finality retains the same fenced terminal checkpoint used for recovery.
    /// `deadline` bounds the canonical walk this observation may spend. The
    /// scan keeps its authenticated prefix across calls, so running out of
    /// budget reports `FinalityPending` and the next round resumes instead of
    /// rewalking the chain from genesis. That rewalk is what used to outlast
    /// the actuator lease once the claim phase started.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_native_claim_settlement_finality_v15(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        runtime: &RealDomRpcRuntimeV1,
        chain: &TrustedChainIdV1,
        evidence: &EvidenceRefV1,
        now_unix_ms: u64,
        deadline: std::time::Instant,
    ) -> DomActuatorResult<DomFinalityObservationV1> {
        self.require_trusted_chain_binding(chain)?;
        self.require_dom_runtime_binding(runtime)?;
        if let Some(observed) = self.f7_receiver_observation_v25(chain)? {
            if evidence.chain_id.0 != observed.chain_id() || evidence.tx_id != observed.tx_hash() {
                return Err(DomActuatorError::CapabilityMismatch);
            }
            let finality = self.verified_f7_receiver_claim_v25(runtime, chain, observed.tx_hash())?;
            let observation = finality_observation(finality.tx_hash(), finality.block_height(),
                finality.block_hash(), finality.evidence_digest());
            self.persist_claim_finality(control, lease, finality, now_unix_ms)?;
            return Ok(observation);
        }
        let facts = self
            .session_store
            .f7_claim_verification_facts_v15(
                *chain,
                self.binding.session_id(),
                self.binding.participant().participant_id(),
            )
            .map_err(map_f7_claim_store_error_v21)?;
        let Some(facts) = facts else {
            if self
                .session_store
                .retained_f7_funding_gate_v19(*chain, self.binding.session_id())
                .map_err(map_f7_claim_store_error_v21)?
                .is_some()
            {
                return Err(DomActuatorError::InvalidStage);
            }
            let authority = self.resume_consumed_final_claim_authority_v2(chain)?;
            let verifier = self.build_retained_claim_verifier_v2(chain, &authority)?;
            return self.observe_final_claim_settlement_finality_v2(
                control,
                lease,
                runtime,
                &verifier,
                evidence,
                now_unix_ms,
            );
        };
        let native = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&native)?;
        let claim = control.retained_final_claim_identity_v2(lease, self.binding, now_unix_ms)?;
        if facts.minimum_confirmations() != self.binding.min_confirmations()
            || facts.template_hash() != claim.template_hash
            || facts.shared_commitment() != claim.shared_output_commitment
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let finality = runtime
            .verified_f7_claim_finality_until_v26(
                &facts,
                evidence,
                claim.tx_hash,
                self.binding.max_reorg_depth(),
                deadline,
            )
            .map_err(map_finality_error)?;
        let observation = finality_observation(
            finality.tx_hash(),
            finality.block_height(),
            finality.block_hash(),
            finality.evidence_digest(),
        );
        self.persist_claim_finality(control, lease, finality, now_unix_ms)?;
        Ok(observation)
    }
}

impl DomContractsActuatorV1<'_> {
    /// Select the native profile from authenticated custody. Only genuine gate
    /// absence selects the legacy path; corruption never becomes absence.
    pub fn f7_final_claim_progress_v21(
        &self,
        chain: &TrustedChainIdV1,
    ) -> DomActuatorResult<Option<dom_scriptless_store::F7FinalClaimProgressV14>> {
        self.require_trusted_chain_binding(chain)?;
        if self
            .session_store
            .retained_f7_funding_gate_v19(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?
            .is_none()
        {
            return Ok(None);
        }
        let _pending = self
            .session_store
            .resume_outbound_dsc1(self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.session_store
            .f7_final_claim_progress_v14(*chain, self.binding.session_id())
            .map(Some)
            .map_err(map_f7_claim_store_error_v21)
    }

    /// Reauthenticate the exact claim against both native exposure and the
    /// control mirror before issuing or accepting a coordinator locator.
    pub(crate) fn retained_f7_claim_transaction_v21(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        now: u64,
    ) -> DomActuatorResult<Option<[u8; 32]>> {
        use dom_scriptless_store::F7FinalClaimProgressV14 as Progress;
        let Some(progress) = self.f7_final_claim_progress_v21(chain)? else {
            return Ok(None);
        };
        if progress == Progress::NeedsAdaptation {
            return Err(DomActuatorError::InvalidStage);
        }
        let facts = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        let mirror = control.audit_final_claim_custody_v2(lease, self.binding, now)?;
        let scope = ScopedDomActionV1::new(
            self.binding,
            mirror.effect_id(),
            DomActionV1::BroadcastClaim,
        )?;
        let (tx, exposure) = if progress == Progress::Exposed {
            let prepared = self
                .session_store
                .resume_f7_final_claim_submission_v14(
                    *chain,
                    self.binding.session_id(),
                    facts.sender(),
                    claim_action_scope_digest_v2(scope, facts.evidence_digest()),
                )
                .map_err(map_f7_claim_store_error_v21)?;
            (prepared.tx_hash(), prepared.exposure_digest())
        } else {
            let admitted = self
                .session_store
                .resume_f7_final_claim_admission_v14(*chain, self.binding.session_id())
                .map_err(map_f7_claim_store_error_v21)?;
            (admitted.tx_hash(), admitted.exposure_digest())
        };
        if mirror.tx_hash() != tx
            || mirror.exposure_record_digest() != exposure
            || mirror.template_hash() != facts.template_hash()
            || mirror.shared_output_commitment() != facts.shared_commitment()
            || mirror.dom_claim_sender_id() != facts.sender()
            || mirror.final_claim_receiver_id() != facts.receiver()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        Ok(Some(tx))
    }

    /// Repair exposure-before-mirror without needing the original scalar or
    /// an in-memory signer. An existing complete mirror needs no new attempt.
    pub fn resume_f7_claim_child_v21(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        scope: ScopedDomActionV1,
        now: u64,
    ) -> DomActuatorResult<()> {
        use dom_scriptless_store::F7FinalClaimProgressV14 as Progress;
        let progress = self
            .f7_final_claim_progress_v21(chain)?
            .ok_or(DomActuatorError::InvalidStage)?;
        if progress == Progress::NeedsAdaptation {
            return Err(DomActuatorError::InvalidStage);
        }
        match control.audit_final_claim_custody_v2(lease, self.binding, now) {
            Ok(mirror) => {
                if scope.binding() != self.binding
                    || scope.effect_id() != mirror.effect_id()
                    || scope.action() != DomActionV1::BroadcastClaim
                {
                    return Err(DomActuatorError::CapabilityMismatch);
                }
                self.retained_f7_claim_transaction_v21(control, lease, chain, now)?;
                return Ok(());
            }
            Err(DomActuatorError::ReconciliationRequired) => {}
            Err(error) => return Err(error),
        }
        let facts = self
            .session_store
            .exposed_f7_final_claim_facts_v14(*chain, self.binding.session_id())
            .map_err(map_f7_claim_store_error_v21)?;
        self.require_f7_final_facts_v14(&facts)?;
        let previous = control
            .f7_claim_previous_authorization_v21(lease, scope, facts.evidence_digest(), now)?
            .ok_or(DomActuatorError::ReconciliationRequired)?;
        let request = SameOwnerFinalClaimRecoveryRequestV2 {
            scope,
            previous_authorization_digest: previous,
            now_unix_ms: now,
        };
        if progress == Progress::Exposed {
            let _submission =
                self.resume_f7_final_claim_submission_v14(control, lease, chain, request)?;
        } else {
            let _admission =
                self.resume_f7_final_claim_admission_v14(control, lease, chain, request)?;
        }
        Ok(())
    }
}

pub(super) fn map_f7_claim_store_error_v21(error: SessionStoreError) -> DomActuatorError {
    match error {
        SessionStoreError::Filesystem | SessionStoreError::StoreBusy => {
            DomActuatorError::ContractsAuthorityUnavailable
        }
        SessionStoreError::ClaimSigningAuthorityUnavailable => DomActuatorError::InvalidStage,
        _ => DomActuatorError::CapabilityMismatch,
    }
}

#[cfg(test)]
mod error_tests_v21 {
    use super::*;
    #[test]
    fn native_claim_corruption_is_not_a_retryable_service_failure() {
        for error in [
            SessionStoreError::Quarantined,
            SessionStoreError::InvalidTransition,
            SessionStoreError::SessionNotFound,
            SessionStoreError::Canonical,
        ] {
            assert!(matches!(
                map_f7_claim_store_error_v21(error),
                DomActuatorError::CapabilityMismatch
            ));
        }
        for error in [SessionStoreError::Filesystem, SessionStoreError::StoreBusy] {
            assert!(matches!(
                map_f7_claim_store_error_v21(error),
                DomActuatorError::ContractsAuthorityUnavailable
            ));
        }
    }
}
