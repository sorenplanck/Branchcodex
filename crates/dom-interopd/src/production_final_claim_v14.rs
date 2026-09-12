//! Native universal claim externalization under the sole Contracts owner.
//!
//! This worker consumes a completed native F7 round, persists adaptation before
//! RPC, repairs admission mirrors after restart, and stages the exact 0x12.
//! Each invocation performs at most one DOM submission. It does not create a
//! funding/claim authority, infer a secret, or initialize an unrelated chain.
use super::{ProductionContractsOutboundErrorV1, ProductionContractsV1};
use adapter_dom_real::RealDomRpcRuntimeV1;
use dom_actuator::{
    DomActuatorError, DomActuatorStoreV1, DomF7FinalClaimRequestV14, DomLeaseV1,
    DomSessionBindingV1, SameOwnerFinalClaimRecoveryRequestV2, ScopedDomActionV1,
};
use dom_adaptor::{AdaptorSecret, TrustedChainIdV1};
use dom_scriptless_store::{
    ConsumedF7ClaimAuthorizationV12, F7FinalClaimProgressV14, OutboundDsc1RecoveryV1,
    SessionStoreError,
};
use relay::TimelockSpec;
use route_transport::{F6TransportPortV1, RouteApplicationDispositionV2};

pub(crate) struct ProductionF7ClaimAdaptationV14<'a> {
    pub(crate) authority: &'a ConsumedF7ClaimAuthorizationV12,
    pub(crate) secret: &'a AdaptorSecret,
    pub(crate) validation_height: u64,
}

pub(crate) struct ProductionF7FinalClaimRequestV14<'a> {
    pub(crate) binding: DomSessionBindingV1,
    pub(crate) chain: TrustedChainIdV1,
    pub(crate) control: &'a mut DomActuatorStoreV1,
    pub(crate) lease: DomLeaseV1,
    pub(crate) rpc: &'a RealDomRpcRuntimeV1,
    pub(crate) scope: ScopedDomActionV1,
    pub(crate) previous_authorization_digest: [u8; 32],
    pub(crate) now_unix_ms: u64,
    pub(crate) expiry: TimelockSpec,
    pub(crate) adaptation: Option<ProductionF7ClaimAdaptationV14<'a>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionF7FinalClaimErrorV14 {
    #[error("universal final claim belongs to a different participant, chain or route action")]
    Scope,
    #[error("fresh F7 and a private adaptor secret are required for first adaptation")]
    AdaptationRequired,
    #[error("native universal final claim custody rejected the operation")]
    Store(#[from] SessionStoreError),
    #[error("native universal final claim actuator rejected the operation")]
    Actuator(#[from] DomActuatorError),
    #[error("native final-claim identity or Relay handoff rejected the operation")]
    Transport(#[from] ProductionContractsOutboundErrorV1),
    #[error("fresh selected-chain F7 observation rejected final adaptation")]
    Anchors(#[from] super::ProductionF7RuntimeErrorV12),
}

#[must_use]
pub(crate) enum ProductionF7FinalClaimStepV14 {
    FundingAbsent,
    AwaitingFinality,
    TemporarilyUnavailable,
    Exposed,
    Admitted,
    Staged(RouteApplicationDispositionV2),
    /// Relay handoff is complete. Confirmation/reorg observation remains a
    /// separate native chain boundary; this is never called settlement success.
    TransportReconciled,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn step_f7_final_claim_v14(
        &mut self,
        request: ProductionF7FinalClaimRequestV14<'_>,
    ) -> Result<ProductionF7FinalClaimStepV14, ProductionF7FinalClaimErrorV14> {
        self.validate_dom_binding(request.binding)?;
        if request.chain.as_bytes() != &request.binding.chain_id()
            || request.scope.binding() != request.binding
            || !super::valid_timelock(request.expiry)
        {
            return Err(ProductionF7FinalClaimErrorV14::Scope);
        }
        // Heal the native accepted-before-commit crash prefix before asking
        // the read-only progress auditor to require a committed 0x12.
        let _pending = self.store.resume_outbound_dsc1(self.session_id)?;
        let progress = self
            .store
            .f7_final_claim_progress_v14(request.chain, self.session_id)?;
        let recovery = SameOwnerFinalClaimRecoveryRequestV2 {
            scope: request.scope,
            previous_authorization_digest: request.previous_authorization_digest,
            now_unix_ms: request.now_unix_ms,
        };
        match progress {
            F7FinalClaimProgressV14::NeedsAdaptation => {
                let adaptation = request
                    .adaptation
                    .ok_or(ProductionF7FinalClaimErrorV14::AdaptationRequired)?;
                let actuator = self.bind_dom_actuator(request.binding)?;
                // Both durable exposure and the pre-RPC attempt are completed
                // by this native facade. The next invocation recovers those
                // exact bytes; no signed transaction is exported here.
                let _submission = actuator.prepare_and_expose_f7_final_claim_v14(
                    request.control,
                    request.lease,
                    &request.chain,
                    DomF7FinalClaimRequestV14 {
                        scope: request.scope,
                        authority: adaptation.authority,
                        secret: adaptation.secret,
                        validation_height: adaptation.validation_height,
                        now_unix_ms: request.now_unix_ms,
                    },
                )?;
                Ok(ProductionF7FinalClaimStepV14::Exposed)
            }
            F7FinalClaimProgressV14::Exposed => {
                let actuator = self.bind_dom_actuator(request.binding)?;
                let submission = actuator.resume_f7_final_claim_submission_v14(
                    request.control,
                    request.lease,
                    &request.chain,
                    recovery,
                )?;
                let receipt = actuator.dispatch_f7_final_claim_v14(request.rpc, &submission)?;
                actuator.commit_f7_final_claim_admission_v14(
                    request.control,
                    request.lease,
                    &request.chain,
                    submission,
                    receipt,
                    request.now_unix_ms,
                )?;
                Ok(ProductionF7FinalClaimStepV14::Admitted)
            }
            F7FinalClaimProgressV14::Admitted => {
                let admitted = self
                    .bind_dom_actuator(request.binding)?
                    .resume_f7_final_claim_admission_v14(
                        request.control,
                        request.lease,
                        &request.chain,
                        recovery,
                    )?
                    .into_transport_authority();
                match self.store.resume_outbound_dsc1(self.session_id)? {
                    OutboundDsc1RecoveryV1::SigningRequest(prepared) => {
                        if prepared.message_type() != 0x12 {
                            return Err(ProductionF7FinalClaimErrorV14::Scope);
                        }
                        let expected = self
                            .store
                            .prepare_f7_final_claim_dsc1_request_v14(&admitted)?;
                        if prepared.request_id() != expected.request_id() {
                            return Err(ProductionF7FinalClaimErrorV14::Scope);
                        }
                        self.sign_commit_and_stage(*prepared, request.expiry)
                    }
                    OutboundDsc1RecoveryV1::None => {
                        let prepared = self
                            .store
                            .prepare_f7_final_claim_dsc1_request_v14(&admitted)?;
                        self.sign_commit_and_stage(prepared, request.expiry)
                    }
                    // A pending earlier message must be reconciled by the
                    // ordinary Relay worker, not mislabeled a completed claim.
                    OutboundDsc1RecoveryV1::Committed(_) => {
                        return Err(ProductionF7FinalClaimErrorV14::Scope)
                    }
                }
                .map(ProductionF7FinalClaimStepV14::Staged)
                .map_err(Into::into)
            }
            F7FinalClaimProgressV14::TransportCommitted => {
                let OutboundDsc1RecoveryV1::Committed(outbound) =
                    self.store.resume_outbound_dsc1(self.session_id)?
                else {
                    return Err(ProductionF7FinalClaimErrorV14::Scope);
                };
                self.store
                    .revalidate_committed_f7_final_claim_transport_v14(request.chain, &outbound)?;
                let staged = self
                    .relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*outbound, request.expiry)
                    .map_err(ProductionContractsOutboundErrorV1::from)?;
                Ok(ProductionF7FinalClaimStepV14::Staged(staged))
            }
            F7FinalClaimProgressV14::TransportReconciled => {
                Ok(ProductionF7FinalClaimStepV14::TransportReconciled)
            }
        }
    }
}
