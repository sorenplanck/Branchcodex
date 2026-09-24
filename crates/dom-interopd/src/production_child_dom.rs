//! Production settlement-child authority for the DOM face.
//!
//! One instance owns the sole DOM control Store and borrows the sole
//! Scriptless Contracts Store through `DomContractsActuatorV1`. Coordinator
//! facts are frozen into an atomic cross-store binding before any action is
//! attempted, and every stable result is committed to the control Store's
//! port-call journal before it is returned.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use adapter_dom_real::{RealDomError, RealDomRpcRuntimeV1};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use dom_actuator::{
    DomActionV1, DomActuatorCapabilityV1, DomActuatorError, DomActuatorStoreV1,
    DomClaimCustodyClassificationV1, DomContractsActuatorV1, DomFinalClaimAdmissionBundleV2,
    DomFinalityObservationV1, DomFinalityRevalidationV1, DomLeaseV1, DomOperationDispositionV1,
    DomSessionBindingV1, DomSettlementChildBindingRequestV1, DomSettlementChildBindingV1,
    DomSettlementChildExposureV1, DomSettlementChildPortCallJournalStatusV1,
    DomSettlementChildPortCallKeyV1, DomSettlementChildPortCallKindV1,
    DomSettlementChildPortCallOutcomeV1, PersistedRefundTakeoverRequestV1,
    SameOwnerFinalClaimRecoveryRequestV2, ScopedDomActionV1,
};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_chain_adapter::ChainAdapterError;
use dom_scriptless_identity_store::IdentityStoreError;
use dom_scriptless_store::{
    ConsumedClaimSigningAuthorizationV2, DomTransactionValidationContextV1, SessionStoreError,
};
use f7_anchor_authority::{
    F7AnchorAuthorityError, F7AnchorValidationRequestV2, VerifiedF7RouteAnchorAuthorizationsV2,
};
use kaystra_core::state::EvidenceRefV1;
use kaystra_core::types::ChainId;
use route_composer::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
};
use route_transport::DurableRelaySenderErrorV1;
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, Digest32, SettlementActionV1,
    SettlementChildPlanV1, SettlementFaceV1, SettlementLegV1,
};

use crate::production_child_evidence::{
    externalization_evidence_v1, first_exposure_evidence_v1, observation_final_evidence_v1,
    observation_pending_evidence_v1, observation_reorg_evidence_v1,
    proven_not_externalized_evidence_v1, retryable_before_externalization_evidence_v1,
    unknown_evidence_v1, ChildEvidenceBindingV1, ChildFinalityFactsV1,
    ChildObservationEvidenceBindingV1,
};
use crate::production_child_router::{
    AuthenticatedDomChildPortV1, ProductionChildMaterializationRequestV1,
    ProductionSettlementChildPortV1, ProductionSettlementChildRouterV1,
};
use crate::production_contracts::{
    ProductionContractsOutboundErrorV1, ProductionDomChildStoreAuthorityV1,
    ProductionDomFinalClaimTransportRecoveryV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_plan_source::ProductionDomPublicSecretConsumerAuthorityV1;
use crate::relay_worker::RelayWorkerOutboundErrorV1;

const ZERO_DIGEST: Digest32 = [0; 32];
const DISPATCH_REQUEST_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/DOM-CHILD/DISPATCH-REQUEST/V1\0";
const RECONCILIATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/RECONCILIATION-REQUEST/V1\0";
const OBSERVATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/OBSERVATION-REQUEST/V1\0";
const MATERIALIZED_INTENT_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/MATERIALIZED-INTENT/V1\0";
const MATERIALIZED_CUSTODY_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/MATERIALIZED-CUSTODY/V1\0";

/// Trusted clock used for the actuator lease and durable journal timestamps.
pub(crate) trait ProductionDomChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Budget for one DOM chain validation context taken inside a route step.
///
/// The unbounded form walks from genesis to the tip with no ceiling of any
/// kind, so its cost grows with the chain and one call can outlast the actuator
/// lease the step is holding. Ten seconds is the same figure the F7 funding
/// runtime already polls this context with (`F7_FUNDING_CONTEXT_POLL_BOUND_V24`),
/// and running out is `TemporarilyUnavailable`, which every caller retries.
const DOM_CHAIN_CONTEXT_BUDGET_V26: std::time::Duration = std::time::Duration::from_secs(10);

/// Host wall-time boundary for production composition.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionDomChildClockV1;

impl ProductionDomChildClockV1 for SystemProductionDomChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Move-only proof that one exact dispatch request was crossed against both
/// DOM Stores under the live participant lease.
pub(crate) struct AuthenticatedDomDispatchCallV1 {
    binding: DomSettlementChildBindingV1,
    coordinator_attempt_id: Digest32,
    request_digest: Digest32,
    refund_context: Option<DomTransactionValidationContextV1>,
}

impl core::fmt::Debug for AuthenticatedDomDispatchCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedDomDispatchCallV1([authority redacted])")
    }
}

impl AuthenticatedDomDispatchCallV1 {
    pub(crate) const fn binding(&self) -> &DomSettlementChildBindingV1 {
        &self.binding
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn coordinator_attempt_id(&self) -> Digest32 {
        self.coordinator_attempt_id
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Authenticated live refund context, present only for a refund call.
    pub(crate) const fn refund_context(&self) -> Option<DomTransactionValidationContextV1> {
        self.refund_context
    }
}

/// Move-only proof for an exact reconciliation request.
pub(crate) struct AuthenticatedDomReconciliationCallV1 {
    binding: DomSettlementChildBindingV1,
    coordinator_attempt_id: Digest32,
    request_digest: Digest32,
    refund_context: Option<DomTransactionValidationContextV1>,
}

impl core::fmt::Debug for AuthenticatedDomReconciliationCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedDomReconciliationCallV1([authority redacted])")
    }
}

impl AuthenticatedDomReconciliationCallV1 {
    pub(crate) const fn binding(&self) -> &DomSettlementChildBindingV1 {
        &self.binding
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn coordinator_attempt_id(&self) -> Digest32 {
        self.coordinator_attempt_id
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub(crate) const fn refund_context(&self) -> Option<DomTransactionValidationContextV1> {
        self.refund_context
    }
}

/// Composition seam for the additional linear authorities needed to dispatch
/// retained DOM funding, V2 claim and refund transactions.
///
/// The implementation receives no transaction bytes, scalar or caller-shaped
/// chain fact. It can act only after consuming a move-only token minted from an
/// authenticated Contracts+control binding. The concrete composition owns the
/// action capabilities and exact broadcaster; this port owns idempotency and
/// rejects every returned classification whose evidence is not the canonical
/// request-derived value.
pub(crate) trait ProductionDomActionAuthorityV1 {
    fn externalize(
        &mut self,
        context: ProductionDomActionContextV1<'_, '_>,
        call: AuthenticatedDomDispatchCallV1,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1>;

    fn reconcile(
        &mut self,
        context: ProductionDomActionContextV1<'_, '_>,
        call: AuthenticatedDomReconciliationCallV1,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1>;
}

/// Exact borrowed authority set for one DOM child action. Keeping these
/// capabilities together prevents callers from mixing a Store lease, chain
/// identity, RPC runtime, or observation time across sessions.
pub(crate) struct ProductionDomActionContextV1<'call, 'store> {
    contracts: &'call DomContractsActuatorV1<'store>,
    control: &'call mut DomActuatorStoreV1,
    lease: DomLeaseV1,
    trusted_chain_id: &'call TrustedChainIdV1,
    runtime: &'call RealDomRpcRuntimeV1,
    now_unix_ms: u64,
    funding_limit_v23: ProductionDomFundingLimitV23,
}

#[derive(Clone, Copy)]
enum ProductionDomFundingLimitV23 {
    Legacy,
    // Independent read-only budget; it never authorizes a submission.
    Closed(std::time::Instant),
    Until(std::time::Instant),
}

/// Receipt-free result from the sole concrete DOM action authority.
///
/// Stable evidence is derived by the child port from its authenticated
/// coordinator request. The authority cannot choose an evidence digest or
/// claim `ProvenNotExternalized`.
pub(crate) enum ProductionDomActionResultV1 {
    Externalized,
    FinalClaimAdmitted(Box<DomFinalClaimAdmissionBundleV2>),
    F7ClaimAdmitted(Box<dom_actuator::DomF7FinalClaimAdmissionV14>),
    FinalClaimTransportStarted,
    Unknown,
}

enum CompletedDomCapabilityV1 {
    Current(Box<DomActuatorCapabilityV1>),
    NeedsRefence,
}

/// Exact production dispatcher over the already-open Contracts/control pair.
/// It lazily rehydrates the one process-bound claim authorization from that
/// same Contracts opening and never owns transaction bytes or a second RPC
/// client.
pub(crate) struct ConcreteProductionDomActionAuthorityV1 {
    claim_authorization: Option<ConsumedClaimSigningAuthorizationV2>,
}

impl ConcreteProductionDomActionAuthorityV1 {
    pub(crate) const fn new() -> Self {
        Self {
            claim_authorization: None,
        }
    }

    fn claim_authorization<'authorization>(
        &'authorization mut self,
        contracts: &DomContractsActuatorV1<'_>,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<&'authorization ConsumedClaimSigningAuthorizationV2, ChildAuthorityRefusalV1> {
        if self.claim_authorization.is_none() {
            self.claim_authorization = Some(
                contracts
                    .resume_consumed_final_claim_authority_v2(trusted_chain_id)
                    .map_err(map_actuator_error)?,
            );
        }
        self.claim_authorization
            .as_ref()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)
    }

    fn completed_capability(
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: &DomSettlementChildBindingV1,
        now_unix_ms: u64,
    ) -> Result<CompletedDomCapabilityV1, ChildAuthorityRefusalV1> {
        let scope = binding.request().scope();
        match control.authorize_action(
            lease,
            scope,
            binding.operation_evidence_digest(),
            None,
            now_unix_ms,
        ) {
            Ok((capability, DomOperationDispositionV1::AlreadyCompleted)) => {
                Ok(CompletedDomCapabilityV1::Current(Box::new(capability)))
            }
            Ok(_) => Err(child_conflict_at_v25(294)),
            Err(DomActuatorError::ReconciliationRequired) => {
                Ok(CompletedDomCapabilityV1::NeedsRefence)
            }
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn rpc_result(
        result: Result<dom_scriptless_chain_adapter::SubmissionReceiptV1, DomActuatorError>,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        match result {
            Ok(_) => Ok(ProductionDomActionResultV1::Externalized),
            Err(DomActuatorError::RpcAuthorityUnavailable) => {
                Ok(ProductionDomActionResultV1::Unknown)
            }
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn execute(
        &mut self,
        context: ProductionDomActionContextV1<'_, '_>,
        binding: &DomSettlementChildBindingV1,
        refund_context: Option<DomTransactionValidationContextV1>,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        let ProductionDomActionContextV1 {
            contracts,
            control,
            lease,
            trusted_chain_id,
            runtime,
            now_unix_ms,
            funding_limit_v23,
        } = context;
        let scope = binding.request().scope();
        match scope.action() {
            DomActionV1::BroadcastFunding => {
                if refund_context.is_some() {
                    return Err(child_conflict_at_v25(333));
                }
                let native = match funding_limit_v23 {
                    ProductionDomFundingLimitV23::Legacy => contracts
                        .dispatch_f7_funding_child_v20(
                            control,
                            lease,
                            binding,
                            runtime,
                            now_unix_ms,
                        ),
                    ProductionDomFundingLimitV23::Closed(_) => {
                        return Err(ChildAuthorityRefusalV1::Unavailable)
                    }
                    ProductionDomFundingLimitV23::Until(deadline) => contracts
                        .dispatch_f7_funding_child_until_v23(
                            control,
                            lease,
                            binding,
                            runtime,
                            now_unix_ms,
                            deadline,
                        ),
                };
                match native {
                    Ok(Some(_receipt)) => return Ok(ProductionDomActionResultV1::Externalized),
                    Ok(None) => {}
                    Err(DomActuatorError::RpcAuthorityUnavailable) => {
                        return Ok(ProductionDomActionResultV1::Unknown)
                    }
                    Err(error) => return Err(map_actuator_error(error)),
                }
                let broadcast =
                    match Self::completed_capability(control, lease, binding, now_unix_ms)? {
                        CompletedDomCapabilityV1::Current(capability) => contracts
                            .resume_persisted_funding_broadcast(
                                control,
                                lease,
                                *capability,
                                now_unix_ms,
                            ),
                        CompletedDomCapabilityV1::NeedsRefence => contracts
                            .adopt_persisted_funding_after_takeover(
                                control,
                                lease,
                                scope,
                                binding.operation_authorization_digest(),
                                now_unix_ms,
                            ),
                    }
                    .map_err(map_actuator_error)?;
                Self::rpc_result(match funding_limit_v23 {
                    ProductionDomFundingLimitV23::Legacy => {
                        contracts.dispatch_funding_broadcast(runtime, broadcast)
                    }
                    ProductionDomFundingLimitV23::Closed(_) => {
                        return Err(ChildAuthorityRefusalV1::Unavailable)
                    }
                    ProductionDomFundingLimitV23::Until(deadline) => {
                        contracts.dispatch_funding_broadcast_until_v23(runtime, broadcast, deadline)
                    }
                })
            }
            DomActionV1::BroadcastRefund => {
                let current_context = refund_context.ok_or_else(|| child_conflict_at_v25(397))?;
                let broadcast =
                    match Self::completed_capability(control, lease, binding, now_unix_ms)? {
                        CompletedDomCapabilityV1::Current(capability) => contracts
                            .resume_persisted_refund_broadcast(
                                control,
                                lease,
                                *capability,
                                current_context,
                                now_unix_ms,
                            ),
                        CompletedDomCapabilityV1::NeedsRefence => contracts
                            .adopt_persisted_refund_after_takeover(
                                control,
                                lease,
                                PersistedRefundTakeoverRequestV1 {
                                    scope,
                                    previous_authorization_digest: binding
                                        .operation_authorization_digest(),
                                    current_context,
                                    now_unix_ms,
                                },
                            ),
                    }
                    .map_err(map_actuator_error)?;
                Self::rpc_result(contracts.dispatch_refund_broadcast(runtime, broadcast))
            }
            DomActionV1::BroadcastClaim => {
                if refund_context.is_some() {
                    return Err(child_conflict_at_v25(426));
                }
                if crate::production_relay_stage12::step_segment_v28("claim_receiver_observation", || {
                    contracts.f7_receiver_observation_v25(trusted_chain_id)
                })
                .map_err(map_actuator_error)?
                .is_some()
                {
                    return match crate::production_relay_stage12::step_segment_v28("claim_receiver_verify", || {
                        contracts.verified_f7_receiver_claim_v25(
                            runtime, trusted_chain_id, binding.transaction_id(),
                        )
                    }) {
                        Ok(_) => Ok(ProductionDomActionResultV1::Externalized),
                        Err(DomActuatorError::FinalityPending | DomActuatorError::RpcAuthorityUnavailable)
                            => Ok(ProductionDomActionResultV1::Unknown),
                        Err(error) => Err(map_actuator_error(error)),
                    };
                }
                if let Some(progress) = contracts
                    .f7_final_claim_progress_v21(trusted_chain_id)
                    .map_err(map_actuator_error)?
                {
                    use dom_scriptless_store::F7FinalClaimProgressV14 as Progress;
                    let recovery = SameOwnerFinalClaimRecoveryRequestV2 {
                        scope,
                        previous_authorization_digest: binding.operation_authorization_digest(),
                        now_unix_ms,
                    };
                    let admitted = match progress {
                        Progress::NeedsAdaptation => {
                            return Err(ChildAuthorityRefusalV1::Unavailable)
                        }
                        Progress::Exposed => {
                            let submission = contracts
                                .resume_f7_final_claim_submission_v14(
                                    control,
                                    lease,
                                    trusted_chain_id,
                                    recovery,
                                )
                                .map_err(map_actuator_error)?;
                            let receipt = match crate::production_relay_stage12::step_segment_v28("claim_dispatch_f7_submit", || {
                                contracts.dispatch_f7_final_claim_v14(runtime, &submission)
                            }) {
                                    Ok(receipt) => receipt,
                                    Err(DomActuatorError::RpcAuthorityUnavailable) => {
                                        return Ok(ProductionDomActionResultV1::Unknown)
                                    }
                                    Err(error) => return Err(map_actuator_error(error)),
                                };
                            let after_rpc = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .and_then(|duration| u64::try_from(duration.as_millis()).ok())
                                .filter(|now| *now >= now_unix_ms)
                                .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
                            contracts
                                .commit_f7_final_claim_admission_v14(
                                    control,
                                    lease,
                                    trusted_chain_id,
                                    submission,
                                    receipt,
                                    after_rpc,
                                )
                                .map_err(map_actuator_error)?
                        }
                        Progress::Admitted
                        | Progress::TransportCommitted
                        | Progress::TransportReconciled => contracts
                            .resume_f7_final_claim_admission_v14(
                                control,
                                lease,
                                trusted_chain_id,
                                recovery,
                            )
                            .map_err(map_actuator_error)?,
                    };
                    return Ok(ProductionDomActionResultV1::F7ClaimAdmitted(Box::new(
                        admitted,
                    )));
                }
                match contracts
                    .classify_final_claim_custody_v2(control, lease, trusted_chain_id, now_unix_ms)
                    .map_err(map_actuator_error)?
                {
                    DomClaimCustodyClassificationV1::Admitted => {
                        if contracts
                            .final_claim_transport_started_v2(trusted_chain_id)
                            .map_err(map_actuator_error)?
                        {
                            return Ok(ProductionDomActionResultV1::FinalClaimTransportStarted);
                        }
                        let bundle = contracts
                            .resume_final_claim_admission_bundle_v2(
                                control,
                                lease,
                                trusted_chain_id,
                                now_unix_ms,
                            )
                            .map_err(map_actuator_error)?;
                        Ok(ProductionDomActionResultV1::FinalClaimAdmitted(Box::new(
                            bundle,
                        )))
                    }
                    DomClaimCustodyClassificationV1::PotentiallyExposed => {
                        let authorization =
                            self.claim_authorization(contracts, trusted_chain_id)?;
                        let (prepared, latched) = contracts
                            .resume_final_claim_broadcast_after_same_owner_recovery_v2(
                                control,
                                lease,
                                SameOwnerFinalClaimRecoveryRequestV2 {
                                    scope,
                                    previous_authorization_digest: binding
                                        .operation_authorization_digest(),
                                    now_unix_ms,
                                },
                                trusted_chain_id,
                                authorization,
                            )
                            .map_err(map_actuator_error)?;
                        let receipt = match contracts
                            .dispatch_final_claim_broadcast_v2(runtime, &prepared, &latched)
                        {
                            Ok(receipt) => receipt,
                            Err(DomActuatorError::RpcAuthorityUnavailable) => {
                                return Ok(ProductionDomActionResultV1::Unknown);
                            }
                            Err(error) => return Err(map_actuator_error(error)),
                        };
                        match contracts.commit_final_claim_admission_v2(
                            control,
                            lease,
                            prepared,
                            receipt,
                            now_unix_ms,
                        ) {
                            Ok(bundle) => Ok(ProductionDomActionResultV1::FinalClaimAdmitted(
                                Box::new(bundle),
                            )),
                            Err(error)
                                if map_actuator_error(error)
                                    == ChildAuthorityRefusalV1::Unavailable =>
                            {
                                Ok(ProductionDomActionResultV1::Unknown)
                            }
                            Err(error) => Err(map_actuator_error(error)),
                        }
                    }
                    DomClaimCustodyClassificationV1::Unattempted => {
                        Err(ChildAuthorityRefusalV1::Unavailable)
                    }
                }
            }
            _ => Err(child_conflict_at_v25(564)),
        }
    }
}

impl ProductionDomActionAuthorityV1 for ConcreteProductionDomActionAuthorityV1 {
    fn externalize(
        &mut self,
        context: ProductionDomActionContextV1<'_, '_>,
        call: AuthenticatedDomDispatchCallV1,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        self.execute(context, call.binding(), call.refund_context())
    }

    fn reconcile(
        &mut self,
        context: ProductionDomActionContextV1<'_, '_>,
        call: AuthenticatedDomReconciliationCallV1,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        if call.binding().request().scope().action() == DomActionV1::BroadcastFunding {
            if let ProductionDomFundingLimitV23::Closed(deadline) = context.funding_limit_v23 {
                // A durable pending intent is not proof of transmission. Resolve
                // exact canonical funding instead of replaying bytes after expiry.
                return match context.contracts.observe_funding_finality_until_v23(
                    context.control,
                    context.lease,
                    context.runtime,
                    context.trusted_chain_id,
                    &EvidenceRefV1 {
                        chain_id: ChainId(call.binding().request().scope().binding().chain_id()),
                        tx_id: call.binding().transaction_id(),
                        event_index: 0,
                        block_height: 0,
                        block_anchor: ZERO_DIGEST,
                    },
                    context.now_unix_ms,
                    deadline,
                ) {
                    Ok(observed)
                        if observed.transaction_id() == call.binding().transaction_id() =>
                    {
                        Ok(ProductionDomActionResultV1::Externalized)
                    }
                    Ok(_) => Err(child_conflict_at_v25(607)),
                    Err(
                        DomActuatorError::FinalityPending
                        | DomActuatorError::RpcAuthorityUnavailable,
                    ) => Ok(ProductionDomActionResultV1::Unknown),
                    Err(error) => Err(map_actuator_error(error)),
                };
            }
        }
        self.execute(context, call.binding(), call.refund_context())
    }
}

/// Owner-scoped bridge from coordinator calls to the exact DOM authorities.
pub(crate) struct ProductionDomChildPortV1<C, A> {
    control: DomActuatorStoreV1,
    sessions: [ProductionDomChildSessionV1<A>; 2],
    lease: DomLeaseV1,
    trusted_chain_id: TrustedChainIdV1,
    runtime: Arc<RealDomRpcRuntimeV1>,
    clock: C,
    lease_renewal_ms_v12: Option<u64>,
    funding_window_v23: Option<crate::production_timer::ProductionFundingWindowV23>,
    route_terms_digest: Digest32,
    dom_consensus_rules_digest: Digest32,
    materialization_scope: ProductionDomMaterializationScopeV1,
}

/// Fully authenticated route/composition/source commitments for both DOM
/// legs.  This is derived from admitted inputs and cannot be caller-shaped.
pub(crate) struct ProductionDomMaterializationScopeV1 {
    route_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digests: [Digest32; 2],
}

impl ProductionDomMaterializationScopeV1 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: FinalClaimSecretSourceScopeV1,
        downstream_scope: FinalClaimSecretSourceScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let composition = inputs.composition();
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope,
                downstream_scope,
            )
            .map_err(|_| child_conflict_at_v25(659))?;
        let upstream = role_plan.entry(ComposedSettlementLegV1::Upstream);
        let downstream = role_plan.entry(ComposedSettlementLegV1::Downstream);
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || upstream.secret_source_scope_digest() == ZERO_DIGEST
            || downstream.secret_source_scope_digest() == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(668));
        }
        Ok(Self {
            route_id: role_plan.route_id(),
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digests: [
                upstream.secret_source_scope_digest(),
                downstream.secret_source_scope_digest(),
            ],
        })
    }

    const fn source_scope(&self, leg: SettlementLegV1) -> Digest32 {
        match leg {
            SettlementLegV1::Upstream => self.source_scope_digests[0],
            SettlementLegV1::Downstream => self.source_scope_digests[1],
        }
    }
}

struct ProductionDomChildSessionV1<A> {
    leg: SettlementLegV1,
    settlement_id: Digest32,
    binding: DomSessionBindingV1,
    contracts: ProductionDomChildStoreAuthorityV1,
    actions: A,
    // A process-local continuation of an already durable admission. The exact
    // dispatch digest pins it across reconciliation; losing it on restart is
    // harmless because the Contracts journal rehydrates that same admission.
    pending_claim_transport_v29: Option<(Digest32, ProductionDomActionResultV1)>,
}

/// One exact DOM settlement context owned by the composed route port.
pub(crate) struct ProductionDomChildSessionBindingsV1 {
    pub(crate) leg: SettlementLegV1,
    pub(crate) settlement_id: Digest32,
    pub(crate) binding: DomSessionBindingV1,
    pub(crate) contracts: ProductionDomChildStoreAuthorityV1,
}

/// Exact route, lease and node authorities bound to both DOM settlements.
pub(crate) struct ProductionDomChildBindingsV1 {
    pub(crate) sessions: [ProductionDomChildSessionBindingsV1; 2],
    pub(crate) lease: DomLeaseV1,
    pub(crate) trusted_chain_id: TrustedChainIdV1,
    pub(crate) runtime: RealDomRpcRuntimeV1,
    pub(crate) route_terms_digest: Digest32,
    /// Raw consensus-rules digest of the admitted DOM deployment. The F6
    /// session binding commits to exactly this value, never to the
    /// adapter-profile hash that the registry derives over the whole
    /// deployment; the two are distinct commitments (the hash contains the
    /// digest) and can never be equal to each other.
    pub(crate) dom_consensus_rules_digest: Digest32,
    pub(crate) materialization_scope: ProductionDomMaterializationScopeV1,
}

/// Sole production result of composing the DOM child authorities.
///
/// Consuming `split` yields exactly one child port and exactly one public
/// consumer authority per leg.  There is no production constructor that can
/// build the child alone and strand or recreate the shared verifier runtime.
pub(crate) struct ProductionDomChildCompositionV1 {
    child: AuthenticatedDomChildPortV1,
    public_secret_consumers: [ProductionDomPublicSecretConsumerAuthorityV1; 2],
    f7_scanner: ProductionDomF7ScannerAuthorityV1,
}

/// Read-only F7 purpose handle to the exact runtime retained by the DOM child.
///
/// It owns only an `Arc` to that runtime, exposes neither the HTTP adapter nor
/// a generic scanner callback, and has no constructor outside DOM child
/// composition. Funding, observation and F7 therefore share one physical
/// authenticated node client without a clone or reopen of that client.
#[must_use = "the DOM child runtime must remain available for post-funding F7"]
pub(crate) struct ProductionDomF7ScannerAuthorityV1 {
    runtime: Arc<RealDomRpcRuntimeV1>,
}

impl core::fmt::Debug for ProductionDomF7ScannerAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomF7ScannerAuthorityV1([authority redacted])")
    }
}

/// A purpose-limited read handle; no raw RPC adapter escapes the DOM child.
pub(crate) struct ProductionDomRefundScannerV10 {
    runtime: Arc<RealDomRpcRuntimeV1>,
}

/// Recovery-only execution handle for the same native client owned by the
/// selected DOM child. It cannot accept free transaction bytes or raw shares.
pub(crate) struct ProductionDomXmrRecoveryClientV12 {
    runtime: Arc<RealDomRpcRuntimeV1>,
}

impl ProductionDomXmrRecoveryClientV12 {
    pub(crate) fn observe_bounded_v23(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        budget: std::time::Duration,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRecoveryStateV11, RealDomError> {
        self.runtime
            .observe_xmr_recovery_bounded_v23(authority, custody, budget)
    }
    /// Preserve the caller's absolute cutoff through Store/custody/scan I/O.
    pub(crate) fn observe_until_v24(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        deadline: std::time::Instant,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRecoveryStateV11, RealDomError> {
        self.runtime
            .observe_xmr_recovery_until_v24(authority, custody, deadline)
    }
    pub(crate) fn observe_refund_reorg_v23(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        checkpoint: &[u8],
        transaction: [u8; 32],
        budget: std::time::Duration,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRefundRevalidationV23, RealDomError> {
        self.runtime.verified_xmr_refund_reorg_v23(
            authority,
            custody,
            checkpoint,
            transaction,
            budget,
        )
    }
    pub(crate) fn observe(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRecoveryStateV11, RealDomError> {
        self.runtime.observe_xmr_recovery_v12(authority, custody)
    }

    pub(crate) fn advance(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        deadline: std::time::Instant,
    ) -> Result<adapter_dom_real::DomXmrRecoveryProgressV12, RealDomError> {
        self.runtime
            .advance_xmr_recovery_until_v23(authority, custody, deadline)
    }

    pub(crate) fn verify_funding_prerequisite(
        &self,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        deadline: std::time::Instant,
    ) -> Result<adapter_dom_real::VerifiedDomXmrFundingPrerequisiteV12, RealDomError> {
        self.runtime
            .verify_xmr_funding_prerequisite_until_v23(authority, custody, deadline)
    }
}
impl ProductionDomRefundScannerV10 {
    pub(crate) fn recovery_state_v11(
        &self,
        graph: &dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<adapter_dom_real::VerifiedDomXmrRecoveryStateV11, adapter_dom_real::RealDomError>
    {
        self.runtime
            .verified_xmr_recovery_state_v11(graph, minimum_confirmations, max_reorg_depth)
    }

    pub(crate) fn extract(
        &self,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        request: adapter_dom_real::DomRefundExtractionRequestV10<'_>,
    ) -> Result<adapter_dom_real::VerifiedDomRefundSecretV10, adapter_dom_real::RealDomError> {
        self.runtime
            .verified_refund_adaptor_secret_v10(store, request)
    }
}

impl ProductionDomF7ScannerAuthorityV1 {
    pub(crate) fn find_post_m8_receiver_claim_v22(
        &self,
        verifier: &adapter_dom_real::RealDomClaimVerifierV1,
        minimum: u32,
    ) -> Result<Option<dom_adaptor::VerifiedDomClaimObservationV1>, RealDomError> {
        self.runtime.find_post_m8_claim_v22(verifier, minimum)
    }

    pub(crate) fn funding_validation_context_v20(
        &self,
    ) -> Result<DomTransactionValidationContextV1, RealDomError> {
        self.runtime.current_transaction_validation_context()
    }

    pub(crate) fn funding_validation_context_bounded_v23(
        &self,
        budget: std::time::Duration,
    ) -> Result<DomTransactionValidationContextV1, RealDomError> {
        self.runtime
            .current_transaction_validation_context_bounded_v23(budget)
    }

    /// Observe a universal receiver claim using this child's sole native DOM client.
    pub(crate) fn find_f7_receiver_claim_v15(
        &self,
        facts: &dom_scriptless_store::F7ClaimObserverFactsV15,
    ) -> Result<Option<dom_adaptor::VerifiedDomClaimObservationV1>, RealDomError> {
        self.runtime.find_f7_final_claim_v15(facts)
    }

    pub(crate) fn xmr_recovery_client_v12(&self) -> ProductionDomXmrRecoveryClientV12 {
        ProductionDomXmrRecoveryClientV12 {
            runtime: Arc::clone(&self.runtime),
        }
    }

    fn from_child_runtime(runtime: &Arc<RealDomRpcRuntimeV1>) -> Self {
        Self {
            runtime: Arc::clone(runtime),
        }
    }

    /// Runs the only productive F7 V2 verifier against the child-owned
    /// runtime after both funding transactions have canonical anchors.
    pub(crate) fn verify_f7_route_anchor_authority_v2(
        &self,
        request: F7AnchorValidationRequestV2<'_>,
    ) -> Result<VerifiedF7RouteAnchorAuthorizationsV2, F7AnchorAuthorityError> {
        self.runtime.verify_f7_route_anchor_authority_v2(request)
    }

    /// Family-specific F7 verification through the same physical DOM owner.
    pub(crate) fn verify_f7_anchor_authority_v12(
        &self,
        role: &dom_final_claim_binding::FinalClaimRoleBindingV1,
        expected_dom_funding_txid: [u8; 32],
        round_start_transcript_hash: [u8; 32],
        external: f7_anchor_authority::families_v11::F7ExternalFundingV12,
    ) -> Result<
        f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12,
        f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11,
    > {
        self.runtime.verify_f7_anchor_authority_v12(
            role,
            expected_dom_funding_txid,
            round_start_transcript_hash,
            external,
        )
    }

    /// Native view-only XMR observation plus this same scanner's DOM anchors.
    pub(crate) async fn verify_f7_xmr_anchor_authority_v12(
        &self,
        request: f7_anchor_authority::families_v11::DomXmrAnchorValidationRequestV11<'_>,
        sidecar: &mut xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
        secrets: &xmr_secret_store::EncryptedSqliteSecretStore,
    ) -> Result<
        f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12,
        f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11,
    > {
        self.runtime
            .verify_f7_xmr_anchor_authority_v12(request, sidecar, secrets)
            .await
    }

    /// Native XMR F7 without a fabricated M.8 readiness/refund transaction.
    pub(crate) fn verify_f7_xmr_bounded_anchor_authority_v23(
        &self,
        request: f7_anchor_authority::families_v11::DomXmrBoundedAnchorValidationRequestV23<'_>,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<
        f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12,
        f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11,
    > {
        self.runtime
            .verify_f7_xmr_bounded_anchor_authority_v23(request, funding)
    }

    /// Derive a read-only refund scanner from this same authenticated runtime.
    /// It cannot submit a transaction or replace the configured DOM client.
    pub(crate) fn refund_scanner_v10(&self) -> ProductionDomRefundScannerV10 {
        ProductionDomRefundScannerV10 {
            runtime: Arc::clone(&self.runtime),
        }
    }

    fn shares_runtime(&self, runtime: &Arc<RealDomRpcRuntimeV1>) -> bool {
        Arc::ptr_eq(&self.runtime, runtime)
    }
}

impl core::fmt::Debug for ProductionDomChildCompositionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomChildCompositionV1([authorities redacted])")
    }
}

impl ProductionDomChildCompositionV1 {
    pub(crate) fn split(
        self,
    ) -> (
        AuthenticatedDomChildPortV1,
        [ProductionDomPublicSecretConsumerAuthorityV1; 2],
        ProductionDomF7ScannerAuthorityV1,
    ) {
        (self.child, self.public_secret_consumers, self.f7_scanner)
    }
}

/// Compose the owned concrete DOM child port from the sole retained Store
/// authorities and the registry-bound node/verifier bundle.
///
/// The returned owner is owned and `'static` without reopening either Store:
/// its Contracts authority is an `Rc` handoff from `ProductionContractsV1`,
/// so the child remains deliberately `!Send + !Sync`.  Runtime and verifier
/// objects are each constructed exactly once; only purpose-limited `Arc`
/// handles are shared between child observation, public-secret recovery and
/// post-funding F7 verification.
pub(crate) fn compose_production_dom_child_port_v1(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
) -> Result<ProductionDomChildCompositionV1, ChildAuthorityRefusalV1> {
    compose_production_dom_child_port_with_renewal_v12(control, bindings, None)
}

/// Opts the real universal runtime into finite, same-owner lease renewal.
/// An expired epoch is never reacquired here: takeover remains explicit.
#[expect(
    dead_code,
    reason = "Compatibility constructor; the universal daemon uses the mandatory V23 funding gate"
)]
pub(crate) fn compose_production_dom_child_port_v12(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
    duration_ms: u64,
) -> Result<ProductionDomChildCompositionV1, ChildAuthorityRefusalV1> {
    if duration_ms == 0 || duration_ms > 3_600_000 {
        return Err(child_conflict_at_v25(999));
    }
    compose_production_dom_child_port_with_renewal_v12(control, bindings, Some(duration_ms))
}

/// Mandatory funding-window handoff for the real universal daemon. Both DOM
/// owners receive the same revocable, default-closed route gate.
pub(crate) fn compose_production_dom_child_port_v23(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
    duration_ms: u64,
    funding_window: crate::production_timer::ProductionFundingWindowV23,
) -> Result<ProductionDomChildCompositionV1, ChildAuthorityRefusalV1> {
    if duration_ms == 0 || duration_ms > 3_600_000 {
        return Err(child_conflict_at_v25(1013));
    }
    compose_production_dom_child_port_bounded_v23(
        control,
        bindings,
        Some(duration_ms),
        Some(funding_window),
    )
}

fn compose_production_dom_child_port_with_renewal_v12(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
    renewal: Option<u64>,
) -> Result<ProductionDomChildCompositionV1, ChildAuthorityRefusalV1> {
    compose_production_dom_child_port_bounded_v23(control, bindings, renewal, None)
}

fn compose_production_dom_child_port_bounded_v23(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
    renewal: Option<u64>,
    funding_window: Option<crate::production_timer::ProductionFundingWindowV23>,
) -> Result<ProductionDomChildCompositionV1, ChildAuthorityRefusalV1> {
    let (mut port, public_secret_consumers) = ProductionDomChildPortV1::compose_shared(
        control,
        bindings,
        SystemProductionDomChildClockV1,
        [
            ConcreteProductionDomActionAuthorityV1::new(),
            ConcreteProductionDomActionAuthorityV1::new(),
        ],
    )?;
    port.lease_renewal_ms_v12 = renewal;
    port.funding_window_v23 = funding_window;
    port.renew_actuator_lease_v12()?;
    let f7_scanner = ProductionDomF7ScannerAuthorityV1::from_child_runtime(&port.runtime);
    if !f7_scanner.shares_runtime(&port.runtime) {
        return Err(child_conflict_at_v25(1051));
    }
    Ok(ProductionDomChildCompositionV1 {
        child: ProductionSettlementChildRouterV1::authenticate_dom(port),
        public_secret_consumers,
        f7_scanner,
    })
}

impl<C, A> core::fmt::Debug for ProductionDomChildPortV1<C, A> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomChildPortV1([authorities redacted])")
    }
}

impl<C, A> ProductionDomChildPortV1<C, A>
where
    C: ProductionDomChildClockV1,
    A: ProductionDomActionAuthorityV1,
{
    fn compose_shared(
        control: DomActuatorStoreV1,
        bindings: ProductionDomChildBindingsV1,
        clock: C,
        actions: [A; 2],
    ) -> Result<(Self, [ProductionDomPublicSecretConsumerAuthorityV1; 2]), ChildAuthorityRefusalV1>
    {
        let ProductionDomChildBindingsV1 {
            sessions,
            lease,
            trusted_chain_id,
            runtime,
            route_terms_digest,
            dom_consensus_rules_digest,
            materialization_scope,
        } = bindings;
        let [upstream, downstream] = sessions;
        let [upstream_actions, downstream_actions] = actions;
        let runtime = Arc::new(runtime);
        if upstream.leg != SettlementLegV1::Upstream
            || downstream.leg != SettlementLegV1::Downstream
            || upstream.settlement_id == ZERO_DIGEST
            || downstream.settlement_id == ZERO_DIGEST
            || route_terms_digest == ZERO_DIGEST
            || dom_consensus_rules_digest == ZERO_DIGEST
            || upstream.binding.profile_digest() != dom_consensus_rules_digest
            || downstream.binding.profile_digest() != dom_consensus_rules_digest
            || upstream.settlement_id == downstream.settlement_id
            || upstream.binding.session_id() == downstream.binding.session_id()
            || upstream.binding.route_id() != downstream.binding.route_id()
            || upstream.binding.participant() != downstream.binding.participant()
            || upstream.binding.chain_id() != downstream.binding.chain_id()
            || upstream.binding.profile_digest() != downstream.binding.profile_digest()
            || upstream.binding.deployment_digest() != downstream.binding.deployment_digest()
            || materialization_scope.route_id != upstream.binding.route_id()
            || materialization_scope.route_scope_digest == ZERO_DIGEST
            || materialization_scope.composition_digest == ZERO_DIGEST
            || materialization_scope.role_plan_digest == ZERO_DIGEST
            || materialization_scope
                .source_scope_digests
                .contains(&ZERO_DIGEST)
            || lease.participant_id() != upstream.binding.participant().participant_id()
            || lease.fencing_epoch() == 0
            || lease.lease_until_unix_ms() == 0
        {
            return Err(child_conflict_at_v25(1112));
        }
        for session in [&upstream, &downstream] {
            let head = session
                .contracts
                .bind()
                .and_then(|actuator| actuator.session_head())
                .map_err(map_actuator_error)?;
            let expected_identity = session
                .binding
                .expected_dom_identity()
                .map_err(map_actuator_error)?;
            if trusted_chain_id.as_bytes() != &session.binding.chain_id()
                || runtime.expected_identity() != &expected_identity
                || head.session_id() != session.binding.session_id()
                || head.terms_hash() != session.binding.terms_digest()
            {
                return Err(child_conflict_at_v25(1129));
            }
        }
        // Startup binds the existing DOM client and native Store only. The
        // post-funding verifier is reconstructed at observation/extraction,
        // after the retained signing round actually exists.
        let composition_digest = materialization_scope.composition_digest;
        let public_secret_consumers = [
            ProductionDomPublicSecretConsumerAuthorityV1::authenticate(
                composition_digest,
                upstream.leg,
                upstream.settlement_id,
                upstream.binding,
                dom_consensus_rules_digest,
                trusted_chain_id,
                Arc::clone(&runtime),
            )
            .map_err(|_| child_conflict_at_v25(1145))?,
            ProductionDomPublicSecretConsumerAuthorityV1::authenticate(
                composition_digest,
                downstream.leg,
                downstream.settlement_id,
                downstream.binding,
                dom_consensus_rules_digest,
                trusted_chain_id,
                Arc::clone(&runtime),
            )
            .map_err(|_| child_conflict_at_v25(1154))?,
        ];
        let port = Self {
            control,
            sessions: [
                ProductionDomChildSessionV1 {
                    leg: upstream.leg,
                    settlement_id: upstream.settlement_id,
                    binding: upstream.binding,
                    contracts: upstream.contracts,
                    actions: upstream_actions,
                    pending_claim_transport_v29: None,
                },
                ProductionDomChildSessionV1 {
                    leg: downstream.leg,
                    settlement_id: downstream.settlement_id,
                    binding: downstream.binding,
                    contracts: downstream.contracts,
                    actions: downstream_actions,
                    pending_claim_transport_v29: None,
                },
            ],
            lease,
            trusted_chain_id,
            runtime,
            clock,
            lease_renewal_ms_v12: None,
            funding_window_v23: None,
            route_terms_digest,
            dom_consensus_rules_digest,
            materialization_scope,
        };
        Ok((port, public_secret_consumers))
    }

    fn session_index(
        &self,
        settlement_id: Digest32,
        leg: SettlementLegV1,
    ) -> Result<usize, ChildAuthorityRefusalV1> {
        exact_dom_session_index_v1(
            &[
                (self.sessions[0].leg, self.sessions[0].settlement_id),
                (self.sessions[1].leg, self.sessions[1].settlement_id),
            ],
            settlement_id,
            leg,
        )
    }

    fn funding_limit_v23(
        &self,
        route_id: Digest32,
        now_unix_ms: u64,
        started: std::time::Instant,
    ) -> Result<ProductionDomFundingLimitV23, ChildAuthorityRefusalV1> {
        let Some(window) = &self.funding_window_v23 else {
            return Ok(ProductionDomFundingLimitV23::Legacy);
        };
        let budget = native_refund_budget_v23(self.lease, now_unix_ms)?;
        let lease_deadline = started
            .checked_add(budget)
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
        Ok(match window.deadline_for_route(route_id) {
            Some(deadline) => ProductionDomFundingLimitV23::Until(deadline.min(lease_deadline)),
            None => ProductionDomFundingLimitV23::Closed(lease_deadline),
        })
    }

    fn validate_dispatch(
        &mut self,
        request: &ChildDispatchRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        validate_dispatch_request_shape(request)?;
        self.validate_operation(
            ExpectedDomBindingsV1::from_dispatch(request),
            now_unix_ms,
            false,
        )
    }

    fn validate_observation(
        &mut self,
        request: &ChildObservationRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        validate_observation_request_shape(request)?;
        self.validate_operation(
            ExpectedDomBindingsV1::from_observation(request),
            now_unix_ms,
            true,
        )
    }

    fn validate_operation(
        &mut self,
        expected: ExpectedDomBindingsV1,
        now_unix_ms: u64,
        observation_only: bool,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        let session_index = self.session_index(expected.settlement_id, expected.leg)?;
        let session = &self.sessions[session_index];
        expected.validate_static(
            session.settlement_id,
            self.route_terms_digest,
            self.dom_consensus_rules_digest,
            session.binding,
            self.lease,
            &self.trusted_chain_id,
            &self.runtime,
        )?;
        let scope = ScopedDomActionV1::new(
            session.binding,
            expected.effect_id,
            dom_action(expected.action),
        )
        .map_err(map_actuator_error)?;
        let binding_request = DomSettlementChildBindingRequestV1::new(
            scope,
            expected.semantic_digest,
            expected.registry_digest,
            expected.intent_digest,
            expected.custody_digest,
            dom_exposure(expected.exposure),
        )
        .map_err(map_actuator_error)?;
        let native_refund_observer =
            if observation_only && expected.action == SettlementActionV1::Refund {
                session.contracts.native_xmr_refund_driver_v23()?
            } else {
                None
            };
        let native_refund = if observation_only {
            None
        } else {
            native_refund_observation_v23(
                &session.contracts,
                expected.action,
                self.lease,
                now_unix_ms,
            )?
        };
        let refund_context = if expected.action == SettlementActionV1::Refund
            && native_refund.is_none()
            && native_refund_observer.is_none()
        {
            Some(
                self.runtime
                    .current_transaction_validation_context_bounded_v23(
                        DOM_CHAIN_CONTEXT_BUDGET_V26,
                    )
                    .map_err(map_runtime_binding_error)?,
            )
        } else {
            None
        };
        let now_unix_ms = fresh_dom_time(&mut self.clock, now_unix_ms)?;
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let retained = match expected.action {
            SettlementActionV1::Funding => contracts.bind_funding_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.bind_final_claim_settlement_child_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                binding_request,
                now_unix_ms,
            ),
            SettlementActionV1::Refund if native_refund_observer.is_some() => {
                let driver = native_refund_observer
                    .as_ref()
                    .ok_or_else(|| child_conflict_at_v25(1324))?;
                contracts.retained_native_xmr_refund_settlement_child_binding_v23(
                    &mut self.control,
                    self.lease,
                    expected.custody_digest,
                    driver.refund_gate_v23(),
                    now_unix_ms,
                )
            }
            SettlementActionV1::Refund if native_refund.is_some() => {
                let native = native_refund
                    .as_ref()
                    .ok_or_else(|| child_conflict_at_v25(1336))?;
                contracts.bind_native_xmr_refund_settlement_child_v23(
                    &mut self.control,
                    self.lease,
                    binding_request,
                    native.driver.refund_gate_v23(),
                    &native.observed,
                    now_unix_ms,
                )
            }
            SettlementActionV1::Refund => contracts.bind_refund_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                refund_context.ok_or_else(|| child_conflict_at_v25(1350))?,
                now_unix_ms,
            ),
        }
        .map_err(map_actuator_error)?;
        expected.validate_retained(session.binding, self.lease, &retained)?;
        Ok(ValidatedDomOperationV1 {
            session_index,
            expected,
            binding: retained,
            refund_context,
            native_refund,
            native_refund_observer,
        })
    }

    fn externalized_receipt(
        request: &ChildDispatchRequestV1,
        evidence_digest: Digest32,
        first_exposure_evidence_digest: Option<Digest32>,
    ) -> ChildExternalizationReceiptV1 {
        ChildExternalizationReceiptV1 {
            plan_id: request.plan_id(),
            child_index: request.child_index(),
            face: request.face(),
            chain_id: request.chain_id(),
            transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            externalization_evidence_digest: evidence_digest,
            first_exposure_evidence_digest,
        }
    }

    fn exact_externalized_outcome(
        request: &ChildDispatchRequestV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        Ok(DomSettlementChildPortCallOutcomeV1::Externalized {
            evidence_digest: externalization_evidence_v1(&evidence)
                .map_err(|_| child_conflict_at_v25(1390))?,
            first_exposure_evidence_digest: first_exposure_evidence_v1(&evidence)
                .map_err(|_| child_conflict_at_v25(1392))?,
        })
    }

    fn normalize_dispatch_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        let expected = match outcome {
            DomSettlementChildPortCallOutcomeV1::Externalized { .. } => {
                Self::exact_externalized_outcome(request)?
            }
            DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization { .. } => {
                DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization {
                    evidence_digest: retryable_before_externalization_evidence_v1(&evidence)
                        .map_err(|_| child_conflict_at_v25(1408))?,
                }
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { .. } => {
                DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| child_conflict_at_v25(1414))?,
                }
            }
            _ => return Err(child_conflict_at_v25(1417)),
        };
        if outcome != expected {
            return Err(child_conflict_at_v25(1420));
        }
        Ok(expected)
    }

    fn normalize_reconciliation_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        let expected = match outcome {
            DomSettlementChildPortCallOutcomeV1::Externalized { .. } => {
                Self::exact_externalized_outcome(request)?
            }
            DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized { .. }
                if reconciliation_may_prove_not_externalized(request.action()) =>
            {
                DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&evidence)
                        .map_err(|_| child_conflict_at_v25(1439))?,
                }
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { .. } => {
                DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| child_conflict_at_v25(1445))?,
                }
            }
            _ => return Err(child_conflict_at_v25(1448)),
        };
        if outcome != expected {
            return Err(child_conflict_at_v25(1451));
        }
        Ok(expected)
    }

    fn dispatch_authority_outcome(
        request: &ChildDispatchRequestV1,
        result: ProductionDomActionResultV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        match result {
            ProductionDomActionResultV1::Externalized => Self::exact_externalized_outcome(request),
            ProductionDomActionResultV1::FinalClaimAdmitted(_)
            | ProductionDomActionResultV1::F7ClaimAdmitted(_) => {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
            ProductionDomActionResultV1::FinalClaimTransportStarted => {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
            ProductionDomActionResultV1::Unknown => {
                let evidence = ChildEvidenceBindingV1::from_dispatch(request);
                Ok(DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| child_conflict_at_v25(1473))?,
                })
            }
        }
    }

    fn dispatch_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        match Self::normalize_dispatch_outcome(request, outcome)? {
            DomSettlementChildPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => Ok(ChildExecutionOutcomeV1::Externalized(
                Self::externalized_receipt(
                    request,
                    evidence_digest,
                    first_exposure_evidence_digest,
                ),
            )),
            DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization {
                evidence_digest,
            } => Ok(ChildExecutionOutcomeV1::RetryableBeforeExternalization { evidence_digest }),
            DomSettlementChildPortCallOutcomeV1::Unknown { evidence_digest } => {
                Ok(ChildExecutionOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(child_conflict_at_v25(1500)),
        }
    }

    fn reconciliation_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        match Self::normalize_reconciliation_outcome(request, outcome)? {
            DomSettlementChildPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => Ok(ChildReconciliationOutcomeV1::Externalized(
                Self::externalized_receipt(
                    request,
                    evidence_digest,
                    first_exposure_evidence_digest,
                ),
            )),
            DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized { evidence_digest } => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { evidence_digest } => {
                Ok(ChildReconciliationOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(child_conflict_at_v25(1525)),
        }
    }

    fn pending_observation(
        request: &ChildObservationRequestV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        Ok(DomSettlementChildPortCallOutcomeV1::Pending {
            evidence_digest: observation_pending_evidence_v1(&binding)
                .map_err(|_| child_conflict_at_v25(1535))?,
        })
    }

    fn final_observation(
        request: &ChildObservationRequestV1,
        observation: DomFinalityObservationV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        if observation.transaction_id() != request.transaction_id {
            return Err(child_conflict_at_v25(1544));
        }
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        let facts = ChildFinalityFactsV1 {
            final_evidence_digest: observation.evidence_digest(),
            final_block_hash: observation.block_hash(),
            final_block_number: observation.block_height(),
        };
        Ok(DomSettlementChildPortCallOutcomeV1::Final {
            evidence_digest: observation_final_evidence_v1(&binding, &facts)
                .map_err(|_| child_conflict_at_v25(1554))?,
        })
    }

    fn revalidation_observation(
        request: &ChildObservationRequestV1,
        revalidation: DomFinalityRevalidationV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        match revalidation {
            DomFinalityRevalidationV1::StillFinal(observation) => {
                let outcome = Self::final_observation(request, observation)?;
                if let Some(prior) = request.prior_finality_evidence_digest {
                    if outcome
                        != (DomSettlementChildPortCallOutcomeV1::Final {
                            evidence_digest: prior,
                        })
                    {
                        return Err(child_conflict_at_v25(1571));
                    }
                }
                Ok(outcome)
            }
            DomFinalityRevalidationV1::Invalidated {
                transaction_id,
                prior_evidence_digest,
                prior_block_height,
                prior_block_hash,
                reorg_evidence_digest,
            } => {
                if transaction_id != request.transaction_id {
                    return Err(child_conflict_at_v25(1584));
                }
                let binding = ChildObservationEvidenceBindingV1::from_observation(request);
                let prior_facts = ChildFinalityFactsV1 {
                    final_evidence_digest: prior_evidence_digest,
                    final_block_hash: prior_block_hash,
                    final_block_number: prior_block_height,
                };
                let prior = observation_final_evidence_v1(&binding, &prior_facts)
                    .map_err(|_| child_conflict_at_v25(1593))?;
                if request.prior_finality_evidence_digest != Some(prior) {
                    return Err(child_conflict_at_v25(1595));
                }
                Ok(DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest: prior,
                    reorg_evidence_digest: observation_reorg_evidence_v1(
                        &binding,
                        prior,
                        reorg_evidence_digest,
                    )
                    .map_err(|_| child_conflict_at_v25(1604))?,
                })
            }
        }
    }

    fn evidence_ref(validated: &ValidatedDomOperationV1) -> EvidenceRefV1 {
        EvidenceRefV1 {
            chain_id: ChainId(validated.expected.chain_id),
            tx_id: validated.binding.transaction_id(),
            event_index: 0,
            block_height: 0,
            block_anchor: ZERO_DIGEST,
        }
    }

    fn observe_fresh(
        &mut self,
        request: &ChildObservationRequestV1,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = Self::evidence_ref(validated);
        // Taken before the call borrows `self.control` mutably.
        let funding_deadline = self.funding_observation_deadline_v26();
        let session = &self.sessions[validated.session_index];
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let observed = match validated.expected.action {
            // Bounded, resumable funding observation. The unbounded sibling
            // rewalks the chain from genesis on every round, so its cost grows
            // with the tip while the actuator lease stays fixed: past a few
            // hundred blocks one round outlasts the lease, `renew_actuator_
            // lease_v12` reports `Unavailable` and the composition root kills
            // the process. This variant keeps the authenticated prefix across
            // rounds and yields `TemporarilyUnavailable` when it runs out of
            // budget, which the caller already treats as "observe again".
            // A retained prefix is never evidence: each grant still re-anchors
            // and walks the full canonical chain against the rechecked tip.
            SettlementActionV1::Funding => contracts.observe_funding_finality_until_v23(
                &mut self.control,
                self.lease,
                &self.runtime,
                &self.trusted_chain_id,
                &evidence,
                now_unix_ms,
                funding_deadline,
            ),
            // Same budget as the funding sibling: the claim observation runs
            // once per round while the tip keeps growing, so an unbounded walk
            // here is what let the actuator lease lapse mid-claim.
            SettlementActionV1::Claim => contracts.observe_native_claim_settlement_finality_v15(
                &mut self.control,
                self.lease,
                &self.runtime,
                &self.trusted_chain_id,
                &evidence,
                now_unix_ms,
                funding_deadline,
            ),
            SettlementActionV1::Refund if validated.native_driver_v23().is_some() => {
                let driver = validated
                    .native_driver_v23()
                    .ok_or_else(|| child_conflict_at_v25(1649))?;
                let observation_now = fresh_dom_time(&mut self.clock, now_unix_ms)?;
                let observed = driver.observe_refund_share_bounded_v23(
                    native_refund_budget_v23(self.lease, observation_now)?,
                )?;
                let now_unix_ms = fresh_dom_time(&mut self.clock, observation_now)?;
                contracts.observe_native_xmr_refund_settlement_finality_v23(
                    &mut self.control,
                    self.lease,
                    validated.expected.custody_digest,
                    driver.refund_gate_v23(),
                    &observed,
                    now_unix_ms,
                )
            }
            SettlementActionV1::Refund => contracts.observe_refund_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                &evidence,
                now_unix_ms,
            ),
        };
        match observed {
            Ok(observation) => Self::final_observation(request, observation),
            Err(DomActuatorError::FinalityPending) => Self::pending_observation(request),
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn revalidate(
        &mut self,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomFinalityRevalidationV1, DomActuatorError> {
        let contracts = self.sessions[validated.session_index].contracts.bind()?;
        match validated.expected.action {
            SettlementActionV1::Funding => contracts.revalidate_funding_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.revalidate_final_claim_settlement_finality_v2(
                &mut self.control,
                self.lease,
                &self.runtime,
                now_unix_ms,
            ),
            SettlementActionV1::Refund if validated.native_driver_v23().is_some() => {
                let driver = validated
                    .native_driver_v23()
                    .ok_or(DomActuatorError::CapabilityMismatch)?;
                let checkpoint = contracts.native_xmr_refund_checkpoint_v23(
                    &mut self.control,
                    self.lease,
                    validated.expected.custody_digest,
                    driver.refund_gate_v23(),
                    now_unix_ms,
                )?;
                let observation_now = fresh_dom_time(&mut self.clock, now_unix_ms)
                    .map_err(|_| DomActuatorError::RpcAuthorityUnavailable)?;
                let budget_ms = self
                    .lease
                    .lease_until_unix_ms()
                    .checked_sub(observation_now)
                    .filter(|remaining| *remaining > 0)
                    .ok_or(DomActuatorError::LeaseExpired)?
                    .min(60_000);
                // The lease-derived figure bounds this call alone; the armed
                // route-step ceiling bounds the step all such calls share.
                let budget = route_step_deadline::remaining(
                    std::time::Duration::from_millis(budget_ms),
                )
                .ok_or(DomActuatorError::RpcAuthorityUnavailable)?;
                let observed = driver.observe_refund_reorg_v23(
                    &checkpoint,
                    validated.binding.transaction_id(),
                    budget,
                );
                let now_unix_ms = fresh_dom_time(&mut self.clock, observation_now)
                    .map_err(|_| DomActuatorError::RpcAuthorityUnavailable)?;
                match observed {
                    Ok(adapter_dom_real::VerifiedDomXmrRefundRevalidationV23::Invalidated(
                        proof,
                    )) => contracts.record_native_xmr_refund_reorg_v23(
                        &mut self.control,
                        self.lease,
                        validated.expected.custody_digest,
                        driver.refund_gate_v23(),
                        &proof,
                        now_unix_ms,
                    ),
                    Ok(adapter_dom_real::VerifiedDomXmrRefundRevalidationV23::StillFinal(
                        observed,
                    )) => contracts.revalidate_native_xmr_refund_settlement_finality_v23(
                        &mut self.control,
                        self.lease,
                        validated.expected.custody_digest,
                        driver.refund_gate_v23(),
                        &observed,
                        now_unix_ms,
                    ),
                    Err(RealDomError::InsufficientConfirmations) => {
                        Err(DomActuatorError::FinalityPending)
                    }
                    Err(RealDomError::ReorgBeyondPolicy) => {
                        Err(DomActuatorError::ReorgBeyondPolicy)
                    }
                    Err(
                        RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
                        | RealDomError::LockPoisoned,
                    ) => Err(DomActuatorError::RpcAuthorityUnavailable),
                    Err(_) => Err(DomActuatorError::FinalityEvidenceInvalid),
                }
            }
            SettlementActionV1::Refund => contracts.revalidate_refund_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                now_unix_ms,
            ),
        }
    }

    fn recover_invalidation(
        &mut self,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<Option<DomFinalityRevalidationV1>, DomActuatorError> {
        let contracts = self.sessions[validated.session_index].contracts.bind()?;
        match validated.expected.action {
            SettlementActionV1::Funding => contracts.recover_funding_settlement_invalidation(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.recover_final_claim_settlement_invalidation_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Refund if validated.native_driver_v23().is_some() => {
                let driver = validated
                    .native_driver_v23()
                    .ok_or(DomActuatorError::CapabilityMismatch)?;
                contracts.recover_native_xmr_refund_invalidation_v23(
                    &mut self.control,
                    self.lease,
                    validated.expected.custody_digest,
                    driver.refund_gate_v23(),
                    now_unix_ms,
                )
            }
            SettlementActionV1::Refund => contracts.recover_refund_settlement_invalidation(
                &mut self.control,
                self.lease,
                validated
                    .refund_context
                    .ok_or(DomActuatorError::CapabilityMismatch)?,
                now_unix_ms,
            ),
        }
    }

    fn observe_result(
        &mut self,
        request: &ChildObservationRequestV1,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let prior = request.prior_finality_evidence_digest;
        match self.revalidate(validated, now_unix_ms) {
            Ok(revalidation) if prior.is_some() => {
                return Self::revalidation_observation(request, revalidation);
            }
            Ok(DomFinalityRevalidationV1::StillFinal(observation)) => {
                return Self::final_observation(request, observation);
            }
            Ok(DomFinalityRevalidationV1::Invalidated { .. }) => {
                // The coordinator never received the old finality result. The
                // invalidation is durable, but this call must now prove the
                // replacement inclusion afresh or report Pending.
            }
            Err(DomActuatorError::FinalityPending) => {
                return Self::pending_observation(request);
            }
            Err(DomActuatorError::InvalidStage | DomActuatorError::ReorgEvidenceRequired) => {
                let recovered = self
                    .recover_invalidation(validated, now_unix_ms)
                    .map_err(map_actuator_error)?;
                if prior.is_some() {
                    return recovered
                        .ok_or_else(|| child_conflict_at_v25(1839))
                        .and_then(|value| Self::revalidation_observation(request, value));
                }
            }
            Err(error) => return Err(map_actuator_error(error)),
        }
        self.observe_fresh(request, validated, now_unix_ms)
    }

    fn observation_outcome(
        request: &ChildObservationRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        match outcome {
            DomSettlementChildPortCallOutcomeV1::Pending { evidence_digest } => {
                if outcome != Self::pending_observation(request)? {
                    return Err(child_conflict_at_v25(1855));
                }
                Ok(ChildObservationOutcomeV1::Pending { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::Final { evidence_digest } => {
                if request
                    .prior_finality_evidence_digest
                    .is_some_and(|prior| prior != evidence_digest)
                {
                    return Err(child_conflict_at_v25(1864));
                }
                Ok(ChildObservationOutcomeV1::Final { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest,
                reorg_evidence_digest,
            } => {
                if request.prior_finality_evidence_digest != Some(prior_finality_evidence_digest) {
                    return Err(child_conflict_at_v25(1873));
                }
                Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest,
                    reorg_evidence_digest,
                })
            }
            _ => Err(child_conflict_at_v25(1880)),
        }
    }
}

impl<C, A> ProductionDomChildPortV1<C, A> {
    /// Budget for one bounded funding observation, taken from the very lease
    /// it must not outlast. `renew_actuator_lease_v12` tops up after one
    /// eighth of the lease has been spent. This scan uses at most a quarter
    /// of the configured duration and also respects the enclosing step's
    /// deadline. Without automatic renewal, the fixed fallback still needs
    /// the same Store lease checks before its result can be committed.
    fn funding_observation_deadline_v26(&self) -> std::time::Instant {
        const DEFAULT_BUDGET_MS_V26: u64 = 15_000;
        let budget = self
            .lease_renewal_ms_v12
            .map_or(DEFAULT_BUDGET_MS_V26, |renewal| {
                (renewal / 4).clamp(1_000, DEFAULT_BUDGET_MS_V26)
            });
        adapter_dom_real::route_step_deadline_v27::clamp_v27(
            std::time::Instant::now() + std::time::Duration::from_millis(budget),
        )
    }
}

impl<C, A> ProductionSettlementChildPortV1 for ProductionDomChildPortV1<C, A>
where
    C: ProductionDomChildClockV1,
    A: ProductionDomActionAuthorityV1,
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Dom
    }


    fn renew_actuator_lease_v12(&mut self) -> Result<(), ChildAuthorityRefusalV1> {
        let Some(duration) = self.lease_renewal_ms_v12 else {
            return Ok(());
        };
        let now = self.clock.now_unix_ms()?;
        let Some(remaining) = self
            .lease
            .lease_until_unix_ms()
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
        else {
            eprintln!(
                "DOM_RENEW_SITE_V26 site=dom_lease_lapsed until={} now={now} phase={}",
                self.lease.lease_until_unix_ms(),
                crate::production_relay_stage12::lease_phase_v25()
            );
            return Err(ChildAuthorityRefusalV1::Unavailable);
        };
        // Top up as soon as an eighth of the lease has been spent. Renewing
        // only at the half-way mark silently assumes the heartbeat is sampled
        // far more often than half a lease; a single route step that outlasts
        // that assumption never produces the half-way call, and the lease
        // lapses while its owner is alive and working. Spending an eighth
        // bounds the write rate to one per eighth-lease while leaving the
        // full remaining lease as the margin against a slow step. Nothing is
        // weakened: the lease still dies if the owner stops beating for a
        // whole duration, and every operation revalidates it at the Store.
        if remaining <= duration - duration / 8 {
            self.lease = renew_dom_lease_v12(&mut self.control, self.lease, now, duration)?;
        }
        Ok(())
    }

    /// Unconditional variant for the instant before one route step. The step
    /// spends its whole wall clock against this lease without renewing, so the
    /// write-rate skip above is wrong there: skipping at a remaining lease of
    /// 106 s once cost the step that then legitimately ran 113 s. One extra
    /// single-row write per route step is the entire cost. A lapsed lease is
    /// still refused, exactly as above.
    fn renew_actuator_lease_before_step_v27(
        &mut self,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let Some(duration) = self.lease_renewal_ms_v12 else {
            return Ok(());
        };
        let now = self.clock.now_unix_ms()?;
        if self
            .lease
            .lease_until_unix_ms()
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .is_none()
        {
            eprintln!(
                "DOM_RENEW_SITE_V26 site=dom_lease_lapsed until={} now={now} phase={}",
                self.lease.lease_until_unix_ms(),
                crate::production_relay_stage12::lease_phase_v25()
            );
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        self.lease = renew_dom_lease_v12(&mut self.control, self.lease, now, duration)?;
        Ok(())
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&route_composer::RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        self.renew_actuator_lease_v12()?;
        let scalar_shape_is_valid = matches!(
            (request.action, request.exposure, public_scalar),
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
                None,
            ) | (
                SettlementActionV1::Claim,
                ChildExposureV1::FirstSecretExposure,
                None
            ) | (
                SettlementActionV1::Claim,
                ChildExposureV1::UsesPublicSecret,
                Some(_)
            )
        );
        if !scalar_shape_is_valid
            || request.route_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.settlement_id == ZERO_DIGEST
            || request.fencing_epoch == 0
            || request.semantic_digest == ZERO_DIGEST
            || request.terms_digest == ZERO_DIGEST
            || request.registry_digest == ZERO_DIGEST
            || request.profile_digest == ZERO_DIGEST
            || request.deployment_digest == ZERO_DIGEST
            || request.route_scope_digest == ZERO_DIGEST
            || request.composition_digest == ZERO_DIGEST
            || request.role_plan_digest == ZERO_DIGEST
            || request.source_scope_digest == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(1948));
        }
        let session_index = self.session_index(request.settlement_id, request.leg)?;
        let session = &self.sessions[session_index];
        // Every pin keeps its own name. One collapsed refusal over twelve
        // distinct commitments hid a real defect behind another for three
        // whole ceremony runs; the classification costs nothing and each pin
        // below remains exactly as fatal as it was.
        for (pin, refused) in [
            (
                "binding_route",
                session.binding.route_id() != request.route_id,
            ),
            (
                "session_settlement",
                session.settlement_id != request.settlement_id,
            ),
            ("terms", request.terms_digest != self.route_terms_digest),
            // The session binding carries the raw consensus-rules digest it
            // was built from; `request.profile_digest` carries the adapter
            // profile hash the registry derives over the whole deployment,
            // which contains that digest. Pin the binding against its own
            // source: the request side is already pinned to the admitted
            // deployment by the router before this call.
            (
                "binding_consensus_rules",
                session.binding.profile_digest() != self.dom_consensus_rules_digest,
            ),
            (
                "binding_deployment",
                session.binding.deployment_digest() != request.deployment_digest,
            ),
            (
                "binding_registry",
                session.binding.deployment_digest() != request.registry_digest,
            ),
            // Two independent fences, never one. `request.fencing_epoch` is
            // the route fence: the route store owns it, keyed by route, and
            // the supervisor authenticates it before this call. The actuator
            // lease carries its own fence: the DOM actuator store owns it,
            // keyed by participant, with its own duration. Neither
            // `acquire_lease` accepts an epoch from the other, so the two
            // counters cannot be aligned and coincide only while both are
            // still their initial generation. Pin each against its own
            // source, exactly as the profile digest above and as the XMR
            // child already does.
            ("route_fence", request.fencing_epoch == 0),
            ("lease_fence", self.lease.fencing_epoch() == 0),
            (
                "scope_route",
                request.route_id != self.materialization_scope.route_id,
            ),
            (
                "scope_route_scope",
                request.route_scope_digest != self.materialization_scope.route_scope_digest,
            ),
            (
                "scope_composition",
                request.composition_digest != self.materialization_scope.composition_digest,
            ),
            (
                "scope_role_plan",
                request.role_plan_digest != self.materialization_scope.role_plan_digest,
            ),
            (
                "scope_source",
                request.source_scope_digest != self.materialization_scope.source_scope(request.leg),
            ),
        ] {
            if refused {
                eprintln!("DOM_CHILD_MATERIALIZE_PIN_V25 pin={pin}");
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        let leg = [leg_tag(request.leg)];
        let action = [action_tag(request.action)];
        let fencing_epoch = request.fencing_epoch.to_be_bytes();
        let exposure = [exposure_tag(request.exposure)];
        let common = [
            request.route_id.as_slice(),
            request.effect_id.as_slice(),
            request.settlement_id.as_slice(),
            leg.as_slice(),
            action.as_slice(),
            fencing_epoch.as_slice(),
            request.semantic_digest.as_slice(),
            request.terms_digest.as_slice(),
            request.registry_digest.as_slice(),
            request.profile_digest.as_slice(),
            request.deployment_digest.as_slice(),
            request.route_scope_digest.as_slice(),
            request.composition_digest.as_slice(),
            request.role_plan_digest.as_slice(),
            request.source_scope_digest.as_slice(),
            exposure.as_slice(),
        ];
        let intent_digest = request_digest(MATERIALIZED_INTENT_DOMAIN_V1, &common)?;
        let custody_digest = request_digest(
            MATERIALIZED_CUSTODY_DOMAIN_V1,
            &[intent_digest.as_slice(), request.effect_id.as_slice()],
        )?;
        let scope = ScopedDomActionV1::new(
            session.binding,
            request.effect_id,
            dom_action(request.action),
        )
        .map_err(map_actuator_error)?;
        let binding_request = DomSettlementChildBindingRequestV1::new(
            scope,
            request.semantic_digest,
            request.registry_digest,
            intent_digest,
            custody_digest,
            dom_exposure(request.exposure),
        )
        .map_err(map_actuator_error)?;
        let pre_context_now = self.clock.now_unix_ms()?;
        let native_refund = native_refund_observation_v23(
            &session.contracts,
            request.action,
            self.lease,
            pre_context_now,
        )?;
        let refund_context =
            if request.action == SettlementActionV1::Refund && native_refund.is_none() {
                Some(
                    self.runtime
                        .current_transaction_validation_context_bounded_v23(
                            DOM_CHAIN_CONTEXT_BUDGET_V26,
                        )
                        .map_err(map_runtime_binding_error)?,
                )
            } else {
                None
            };
        let now = if request.action == SettlementActionV1::Refund {
            fresh_dom_time(&mut self.clock, pre_context_now)?
        } else {
            pre_context_now
        };
        if request.action == SettlementActionV1::Claim {
            // Full top-up right before the native claim exposure, which runs
            // a bounded XMR funding check and a DOM RPC and then re-checks
            // `now <= lease_until`. The entry renewal only tops up once half
            // the lease is gone, so entering with half a lease is not enough.
            let now = self.clock.now_unix_ms()?;
            self.lease = top_up_dom_lease_v25(
                &mut self.control,
                self.lease,
                now,
                self.lease_renewal_ms_v12,
            )?;
        }
        let native_claim = request.action == SettlementActionV1::Claim
            && session
                .contracts
                .prepare_native_claim_child_v21(
                    &mut self.control,
                    self.lease,
                    &self.trusted_chain_id,
                    scope,
                    public_scalar,
                    now,
                )
                .map_err(map_f7_claim_error_v21)?;
        let now = if native_claim {
            fresh_dom_time(&mut self.clock, now)?
        } else {
            now
        };
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let retained = match request.action {
            SettlementActionV1::Funding => contracts.bind_funding_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                now,
            ),
            SettlementActionV1::Claim => contracts.bind_final_claim_settlement_child_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                binding_request,
                now,
            ),
            SettlementActionV1::Refund if native_refund.is_some() => {
                let native = native_refund
                    .as_ref()
                    .ok_or_else(|| child_conflict_at_v25(2079))?;
                contracts.bind_native_xmr_refund_settlement_child_v23(
                    &mut self.control,
                    self.lease,
                    binding_request,
                    native.driver.refund_gate_v23(),
                    &native.observed,
                    now,
                )
            }
            SettlementActionV1::Refund => contracts.bind_refund_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                refund_context.ok_or_else(|| child_conflict_at_v25(2093))?,
                now,
            ),
        }
        .map_err(map_actuator_error)?;
        if retained.request() != binding_request
            || retained.locator().effect_id() != request.effect_id
            || retained.locator().custody_digest() != custody_digest
            || retained.transaction_id() == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(2103));
        }
        Ok(SettlementChildPlanV1 {
            face: SettlementFaceV1::Dom,
            exposure: request.exposure,
            chain_id: session.binding.chain_id(),
            expected_transaction_id: retained.transaction_id(),
            intent_digest,
            custody_digest,
        })
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.renew_actuator_lease_v12()?;
        let started = std::time::Instant::now();
        let now = self.clock.now_unix_ms()?;
        let funding_limit_v23 = self.funding_limit_v23(request.route_id(), now, started)?;
        if request.action() == SettlementActionV1::Funding
            && matches!(funding_limit_v23, ProductionDomFundingLimitV23::Closed(_))
        {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        let validated = crate::production_relay_stage12::step_segment_v28(
            "dom_validate_dispatch",
            || self.validate_dispatch(request, now),
        )?;
        self.renew_actuator_lease_v12()?;
        let now = fresh_dom_time(&mut self.clock, now)?;
        let request_digest = dispatch_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            request.attempt_id(),
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::dispatch_outcome(request, outcome);
        }
        let call = AuthenticatedDomDispatchCallV1 {
            binding: validated.binding,
            coordinator_attempt_id: request.attempt_id(),
            request_digest,
            refund_context: validated.refund_context,
        };
        let dispatch_identity = request_digest;
        let session = &mut self.sessions[validated.session_index];
        let pending = session.pending_claim_transport_v29.take();
        if pending
            .as_ref()
            .is_some_and(|(identity, _)| *identity != dispatch_identity)
        {
            session.pending_claim_transport_v29 = pending;
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        let resuming_transport = pending.is_some();
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let returned = if let Some((_, admitted)) = pending {
            admitted
        } else if let Some(native) = &validated.native_refund {
            // The completed locator is backed by a fresh canonical U token,
            // not a new send permission. Do not invoke the plain broadcaster.
            native
                .observed
                .require_recent_v23()
                .map_err(map_runtime_binding_error)?;
            ProductionDomActionResultV1::Externalized
        } else {
            crate::production_relay_stage12::step_segment_v28("dom_actions_externalize", || {
                session.actions.externalize(
                    ProductionDomActionContextV1 {
                        contracts: &contracts,
                        control: &mut self.control,
                        lease: self.lease,
                        trusted_chain_id: &self.trusted_chain_id,
                        runtime: &self.runtime,
                        now_unix_ms: now,
                        funding_limit_v23,
                    },
                    call,
                )
            })?
        };
        // Admission and transport staging are separate durable operations.
        // Do not spend both in the same leased route step. In particular, a
        // receiver's Externalized result never enters this sender continuation.
        if !resuming_transport
            && route_step_deadline::armed().is_some()
            && matches!(
                &returned,
                ProductionDomActionResultV1::F7ClaimAdmitted(_)
                    | ProductionDomActionResultV1::FinalClaimAdmitted(_)
                    | ProductionDomActionResultV1::FinalClaimTransportStarted
            )
        {
            session.pending_claim_transport_v29 = Some((dispatch_identity, returned));
            self.renew_actuator_lease_v12()?;
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        self.renew_actuator_lease_v12()?;
        let session = &mut self.sessions[validated.session_index];
        let returned = crate::production_relay_stage12::step_segment_v28(
            "dom_stage_claim_transport",
            || {
                stage_final_claim_transport_v1(
                    &mut session.contracts,
                    &self.trusted_chain_id,
                    returned,
                )
            },
        )?;
        let outcome = Self::dispatch_authority_outcome(request, returned)?;
        self.renew_actuator_lease_v12()?;
        let post_authority_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(self.lease, key, outcome, post_authority_now)
            .map_err(map_actuator_error)?;
        Self::dispatch_outcome(request, committed)
    }

    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.renew_actuator_lease_v12()?;
        let started = std::time::Instant::now();
        let now = self.clock.now_unix_ms()?;
        let funding_limit_v23 =
            self.funding_limit_v23(request.dispatch.route_id(), now, started)?;
        // Refuse a regression, not an authenticated advance. The coordinator
        // resumes a pending call under a newer owner by preserving the original
        // operation and presenting the current authority separately, so
        // demanding equality here turned a legitimate takeover into Conflict
        // after any restart with a call in flight. The XMR child already
        // compares both epochs this way, and the exact operation is still
        // authenticated below by `validate_dispatch`.
        if request.current_route_fencing_epoch < request.dispatch.route_fencing_epoch()
            || request.current_coordinator_fencing_epoch
                < request.dispatch.coordinator_fencing_epoch()
            || request.reconciliation_attempt_id == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(2204));
        }
        let validated = self.validate_dispatch(&request.dispatch, now)?;
        self.renew_actuator_lease_v12()?;
        let now = fresh_dom_time(&mut self.clock, now)?;
        let request_digest = reconciliation_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Reconciliation,
            request.reconciliation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::reconciliation_outcome(&request.dispatch, outcome);
        }
        let call = AuthenticatedDomReconciliationCallV1 {
            binding: validated.binding,
            coordinator_attempt_id: request.reconciliation_attempt_id,
            request_digest,
            refund_context: validated.refund_context,
        };
        let dispatch_identity = dispatch_request_digest(&request.dispatch)?;
        let session = &mut self.sessions[validated.session_index];
        let pending = session.pending_claim_transport_v29.take();
        if pending
            .as_ref()
            .is_some_and(|(identity, _)| *identity != dispatch_identity)
        {
            session.pending_claim_transport_v29 = pending;
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        let resuming_transport = pending.is_some();
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let returned = if let Some((_, admitted)) = pending {
            admitted
        } else if let Some(native) = &validated.native_refund {
            native
                .observed
                .require_recent_v23()
                .map_err(map_runtime_binding_error)?;
            ProductionDomActionResultV1::Externalized
        } else {
            session.actions.reconcile(
                ProductionDomActionContextV1 {
                    contracts: &contracts,
                    control: &mut self.control,
                    lease: self.lease,
                    trusted_chain_id: &self.trusted_chain_id,
                    runtime: &self.runtime,
                    now_unix_ms: now,
                    funding_limit_v23,
                },
                call,
            )?
        };
        // Admission and transport staging are separate durable operations.
        // Do not spend both in the same leased route step. In particular, a
        // receiver's Externalized result never enters this sender continuation.
        if !resuming_transport
            && route_step_deadline::armed().is_some()
            && matches!(
                &returned,
                ProductionDomActionResultV1::F7ClaimAdmitted(_)
                    | ProductionDomActionResultV1::FinalClaimAdmitted(_)
                    | ProductionDomActionResultV1::FinalClaimTransportStarted
            )
        {
            session.pending_claim_transport_v29 = Some((dispatch_identity, returned));
            self.renew_actuator_lease_v12()?;
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        self.renew_actuator_lease_v12()?;
        let session = &mut self.sessions[validated.session_index];
        let returned = stage_final_claim_transport_v1(
            &mut session.contracts,
            &self.trusted_chain_id,
            returned,
        )?;
        let outcome = Self::dispatch_authority_outcome(&request.dispatch, returned)?;
        self.renew_actuator_lease_v12()?;
        let post_authority_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(self.lease, key, outcome, post_authority_now)
            .map_err(map_actuator_error)?;
        Self::reconciliation_outcome(&request.dispatch, committed)
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.renew_actuator_lease_v12()?;
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_observation(request, now)?;
        let now = fresh_dom_time(&mut self.clock, now)?;
        let request_digest = observation_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Observation,
            request.observation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::observation_outcome(request, outcome);
        }
        let outcome = self.observe_result(request, &validated, now)?;
        self.renew_actuator_lease_v12()?;
        let post_observation_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(
                self.lease,
                key,
                outcome,
                post_observation_now,
            )
            .map_err(map_actuator_error)?;
        Self::observation_outcome(request, committed)
    }
}

#[derive(Clone, Copy)]
struct ExpectedDomBindingsV1 {
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    leg: SettlementLegV1,
    action: SettlementActionV1,
    exposure: ChildExposureV1,
    semantic_digest: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    transaction_id: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    chain_id: Digest32,
    route_fencing_epoch: u64,
    coordinator_fencing_epoch: Option<u64>,
    face: SettlementFaceV1,
}

impl ExpectedDomBindingsV1 {
    fn from_dispatch(request: &ChildDispatchRequestV1) -> Self {
        Self {
            route_id: request.route_id(),
            effect_id: request.effect_id(),
            settlement_id: request.settlement_id(),
            leg: request.leg(),
            action: request.action(),
            exposure: request.exposure(),
            semantic_digest: request.semantic_digest(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            transaction_id: request.expected_transaction_id(),
            terms_digest: request.terms_digest(),
            registry_digest: request.registry_digest(),
            profile_digest: request.profile_digest(),
            deployment_digest: request.deployment_digest(),
            chain_id: request.chain_id(),
            route_fencing_epoch: request.route_fencing_epoch(),
            coordinator_fencing_epoch: Some(request.coordinator_fencing_epoch()),
            face: request.face(),
        }
    }

    fn from_observation(request: &ChildObservationRequestV1) -> Self {
        Self {
            route_id: request.route_id,
            effect_id: request.effect_id,
            settlement_id: request.settlement_id,
            leg: request.leg,
            action: request.action,
            exposure: request.exposure,
            semantic_digest: request.semantic_digest,
            intent_digest: request.intent_digest,
            custody_digest: request.custody_digest,
            transaction_id: request.transaction_id,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            chain_id: request.chain_id,
            route_fencing_epoch: request.route_fencing_epoch,
            coordinator_fencing_epoch: None,
            face: request.face,
        }
    }

    fn validate_static(
        &self,
        settlement_id: Digest32,
        route_terms_digest: Digest32,
        dom_consensus_rules_digest: Digest32,
        binding: DomSessionBindingV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let exposure_valid = match self.action {
            SettlementActionV1::Funding | SettlementActionV1::Refund => {
                self.exposure == ChildExposureV1::NonSecret
            }
            SettlementActionV1::Claim => matches!(
                self.exposure,
                ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret
            ),
        };
        let expected_identity = binding
            .expected_dom_identity()
            .map_err(map_actuator_error)?;
        // Every pin keeps its own name. Twenty-four distinct commitments used
        // to collapse into one refusal, and a single structurally impossible
        // comparison among them could stop the whole ceremony while looking
        // exactly like any of the other twenty-three.
        for (pin, refused) in [
            ("face", self.face != SettlementFaceV1::Dom),
            ("exposure", !exposure_valid),
            (
                "zero_digest",
                [
                    self.route_id,
                    self.effect_id,
                    self.settlement_id,
                    self.semantic_digest,
                    self.intent_digest,
                    self.custody_digest,
                    self.transaction_id,
                    self.terms_digest,
                    self.registry_digest,
                    self.profile_digest,
                    self.deployment_digest,
                    self.chain_id,
                ]
                .contains(&ZERO_DIGEST),
            ),
            // Two independent fences, never one. The route fence and the
            // actuator lease fence are owned by different stores and neither
            // `acquire_lease` accepts an epoch from the other, so the two
            // counters cannot be aligned. Pin each against its own source.
            ("route_fence", self.route_fencing_epoch == 0),
            ("lease_fence", lease.fencing_epoch() == 0),
            (
                "coordinator_fence",
                self.coordinator_fencing_epoch
                    .is_some_and(|epoch| epoch == 0),
            ),
            (
                "lease_participant",
                lease.participant_id() != binding.participant().participant_id(),
            ),
            ("binding_route", binding.route_id() != self.route_id),
            ("session_settlement", settlement_id != self.settlement_id),
            ("terms", route_terms_digest != self.terms_digest),
            // The binding carries the raw consensus-rules digest of the
            // admitted deployment; the request carries the adapter-profile
            // hash derived over the whole deployment, which contains it. The
            // two are different commitments and can never be equal, so the
            // binding is pinned against its own source instead.
            (
                "binding_consensus_rules",
                binding.profile_digest() != dom_consensus_rules_digest,
            ),
            (
                "binding_deployment",
                binding.deployment_digest() != self.deployment_digest,
            ),
            (
                "binding_registry",
                binding.deployment_digest() != self.registry_digest,
            ),
            ("binding_chain", binding.chain_id() != self.chain_id),
            (
                "trusted_chain",
                trusted_chain_id.as_bytes() != &self.chain_id,
            ),
            (
                "runtime_identity",
                runtime.expected_identity() != &expected_identity,
            ),
        ] {
            if refused {
                eprintln!("DOM_CHILD_STATIC_PIN_V25 pin={pin}");
                return Err(child_conflict_at_v25(2428));
            }
        }
        Ok(())
    }

    fn validate_retained(
        &self,
        binding: DomSessionBindingV1,
        lease: DomLeaseV1,
        retained: &DomSettlementChildBindingV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let request = retained.request();
        let scope = request.scope();
        let locator = retained.locator();
        // Named pins for the same reason as `validate_static`: every term here
        // is a separate commitment, and one collapsed refusal cannot say which.
        // The operation fence and the lease fence do belong together — both are
        // counters of this one DOM actuator store — so comparing them is sound.
        for (pin, refused) in [
            ("scope_binding", scope.binding() != binding),
            ("scope_effect", scope.effect_id() != self.effect_id),
            ("scope_action", scope.action() != dom_action(self.action)),
            (
                "request_semantic",
                request.semantic_digest() != self.semantic_digest,
            ),
            (
                "request_registry",
                request.registry_digest() != self.registry_digest,
            ),
            (
                "request_intent",
                request.intent_digest() != self.intent_digest,
            ),
            (
                "request_custody",
                request.custody_digest() != self.custody_digest,
            ),
            (
                "request_exposure",
                request.exposure() != dom_exposure(self.exposure),
            ),
            (
                "transaction_id",
                retained.transaction_id() != self.transaction_id,
            ),
            ("operation_fence", retained.operation_fencing_epoch() == 0),
            (
                "operation_fence_ahead",
                retained.operation_fencing_epoch() > lease.fencing_epoch(),
            ),
            (
                "operation_evidence",
                retained.operation_evidence_digest() == ZERO_DIGEST,
            ),
            (
                "operation_authorization",
                retained.operation_authorization_digest() == ZERO_DIGEST,
            ),
            ("locator_effect", locator.effect_id() != self.effect_id),
            (
                "locator_custody",
                locator.custody_digest() != self.custody_digest,
            ),
            (
                "locator_record",
                locator.binding_record_digest() == ZERO_DIGEST,
            ),
        ] {
            if refused {
                eprintln!("DOM_CHILD_RETAINED_PIN_V25 pin={pin}");
                return Err(child_conflict_at_v25(2459));
            }
        }
        Ok(())
    }
}

struct ValidatedDomOperationV1 {
    session_index: usize,
    expected: ExpectedDomBindingsV1,
    binding: DomSettlementChildBindingV1,
    refund_context: Option<DomTransactionValidationContextV1>,
    native_refund: Option<NativeDomRefundObservationV23>,
    native_refund_observer: Option<
        std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
    >,
}

impl ValidatedDomOperationV1 {
    fn native_driver_v23(
        &self,
    ) -> Option<&crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12> {
        self.native_refund_observer
            .as_deref()
            .or_else(|| self.native_refund.as_ref().map(|v| v.driver.as_ref()))
    }
}

struct NativeDomRefundObservationV23 {
    driver: std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
    observed: adapter_dom_real::VerifiedDomRefundSecretV11,
}

fn native_refund_observation_v23(
    contracts: &ProductionDomChildStoreAuthorityV1,
    action: SettlementActionV1,
    lease: DomLeaseV1,
    now: u64,
) -> Result<Option<NativeDomRefundObservationV23>, ChildAuthorityRefusalV1> {
    let started = std::time::Instant::now();
    if action != SettlementActionV1::Refund {
        return Ok(None);
    }
    let Some(driver) = contracts.native_xmr_refund_driver_v23()? else {
        return Ok(None);
    };
    // Once the native driver is present an unavailable/nonfinal graph never
    // falls back to the incompatible plain refund lane.
    let budget = native_refund_budget_v23(lease, now)?
        .checked_sub(started.elapsed())
        .filter(|v| !v.is_zero())
        .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
    let observed = driver.observe_refund_share_bounded_v23(budget)?;
    Ok(Some(NativeDomRefundObservationV23 { driver, observed }))
}

fn native_refund_budget_v23(
    lease: DomLeaseV1,
    now: u64,
) -> Result<std::time::Duration, ChildAuthorityRefusalV1> {
    let millis = lease
        .lease_until_unix_ms()
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or(ChildAuthorityRefusalV1::Unavailable)?
        .min(60_000);
    // Narrow to the armed route-step ceiling: the lease-derived figure bounds
    // this observation alone, and per-call budgets do not compose across the
    // step. Unarmed callers keep the exact figure above.
    route_step_deadline::remaining(std::time::Duration::from_millis(millis))
        .ok_or(ChildAuthorityRefusalV1::Unavailable)
}

fn exact_dom_session_index_v1(
    sessions: &[(SettlementLegV1, Digest32); 2],
    settlement_id: Digest32,
    leg: SettlementLegV1,
) -> Result<usize, ChildAuthorityRefusalV1> {
    let mut matches = sessions
        .iter()
        .enumerate()
        .filter(|(_, session)| session.1 == settlement_id);
    let (index, (retained_leg, _)) = matches.next().ok_or_else(|| child_conflict_at_v25(2536))?;
    if matches.next().is_some() || *retained_leg != leg {
        return Err(child_conflict_at_v25(2538));
    }
    Ok(index)
}

const fn dom_action(action: SettlementActionV1) -> DomActionV1 {
    match action {
        SettlementActionV1::Funding => DomActionV1::BroadcastFunding,
        SettlementActionV1::Claim => DomActionV1::BroadcastClaim,
        SettlementActionV1::Refund => DomActionV1::BroadcastRefund,
    }
}

const fn dom_exposure(exposure: ChildExposureV1) -> DomSettlementChildExposureV1 {
    match exposure {
        ChildExposureV1::NonSecret => DomSettlementChildExposureV1::NonSecret,
        ChildExposureV1::FirstSecretExposure => DomSettlementChildExposureV1::FirstSecretExposure,
        ChildExposureV1::UsesPublicSecret => DomSettlementChildExposureV1::UsesPublicSecret,
    }
}

const fn reconciliation_may_prove_not_externalized(_action: SettlementActionV1) -> bool {
    // Every DOM action reaches this reconciliation boundary only after its
    // exact outbox artifact has been made durable.  The retained chain
    // scanner can prove canonical inclusion, but neither an absent scan nor a
    // node refusal proves that an earlier RPC attempt never reached another
    // mempool.  Claim is even stricter: its secret exposure is irreversible.
    // A ProvenNotExternalized outcome therefore requires a future move-only
    // never-started capability; no currently composed authority can mint it.
    false
}

fn stage_final_claim_transport_v1(
    contracts: &mut ProductionDomChildStoreAuthorityV1,
    trusted_chain_id: &TrustedChainIdV1,
    result: ProductionDomActionResultV1,
) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
    match result {
        ProductionDomActionResultV1::F7ClaimAdmitted(admitted) => {
            contracts
                .stage_f7_claim_admission_v21(trusted_chain_id, *admitted)
                .map_err(map_contracts_outbound_error)?;
            Ok(ProductionDomActionResultV1::Externalized)
        }
        ProductionDomActionResultV1::FinalClaimAdmitted(bundle) => {
            contracts
                .stage_final_claim_admission_bundle(*bundle)
                .map_err(map_contracts_outbound_error)?;
            Ok(ProductionDomActionResultV1::Externalized)
        }
        ProductionDomActionResultV1::FinalClaimTransportStarted => {
            match contracts
                .recover_final_claim_transport(trusted_chain_id)
                .map_err(map_contracts_outbound_error)?
            {
                ProductionDomFinalClaimTransportRecoveryV1::Staged => {
                    Ok(ProductionDomActionResultV1::Externalized)
                }
                ProductionDomFinalClaimTransportRecoveryV1::NotStarted => {
                    Err(ChildAuthorityRefusalV1::Conflict)
                }
            }
        }
        other => Ok(other),
    }
}

fn map_contracts_outbound_error(
    error: ProductionContractsOutboundErrorV1,
) -> ChildAuthorityRefusalV1 {
    match error {
        ProductionContractsOutboundErrorV1::OwnerBusy => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Identity(
            IdentityStoreError::Filesystem
            | IdentityStoreError::RandomFailure
            | IdentityStoreError::KeyDerivation
            | IdentityStoreError::StoreBusy
            | IdentityStoreError::SigningFailed
            | IdentityStoreError::TransportUnavailable,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Identity(
            IdentityStoreError::InvalidInput
            | IdentityStoreError::AuthenticationFailed
            | IdentityStoreError::InvalidKey
            | IdentityStoreError::StoreRejected,
        ) => ChildAuthorityRefusalV1::Conflict,
        ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::Filesystem
            | SessionStoreError::StoreBusy
            | SessionStoreError::CapacityExceeded
            | SessionStoreError::RandomFailure
            | SessionStoreError::NativeXmrRefundTransportPendingV23,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::Conflict
            | SessionStoreError::Canonical
            | SessionStoreError::PolicyProfile
            | SessionStoreError::Quarantined
            | SessionStoreError::InvalidDomTransaction
            | SessionStoreError::SessionNotFound
            | SessionStoreError::InvalidTransition
            | SessionStoreError::FundingAuthorityUnavailable
            | SessionStoreError::ClaimSigningAuthorityUnavailable
            | SessionStoreError::LegacyV1RecoveryOnly,
        ) => ChildAuthorityRefusalV1::Conflict,
        ProductionContractsOutboundErrorV1::Relay(
            RelayWorkerOutboundErrorV1::OwnerBusy | RelayWorkerOutboundErrorV1::EntropyUnavailable,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Relay(RelayWorkerOutboundErrorV1::Sender(
            DurableRelaySenderErrorV1::StorageUnavailable
            | DurableRelaySenderErrorV1::PendingEnvelopeExists
            | DurableRelaySenderErrorV1::FramedTransferActive
            | DurableRelaySenderErrorV1::Queue(_),
        )) => ChildAuthorityRefusalV1::Unavailable,
        // A busy or unavailable Store staged nothing; the next turn retries,
        // exactly as the sender's StorageUnavailable above already does.
        ProductionContractsOutboundErrorV1::Relay(RelayWorkerOutboundErrorV1::StoreRejected(
            dom_scriptless_store::SessionStoreError::StoreBusy
            | dom_scriptless_store::SessionStoreError::Filesystem
            | dom_scriptless_store::SessionStoreError::ClaimSigningAuthorityUnavailable,
        )) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Relay(
            RelayWorkerOutboundErrorV1::Sender(_)
            | RelayWorkerOutboundErrorV1::StoreRejected(_)
            | RelayWorkerOutboundErrorV1::InvalidDsc1
            | RelayWorkerOutboundErrorV1::WrongDsc1Scope,
        ) => ChildAuthorityRefusalV1::Conflict,
    }
}

fn validate_dispatch_request_shape(
    request: &ChildDispatchRequestV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if [
        request.plan_id(),
        request.plan_digest(),
        request.aggregate_action_id(),
        request.aggregate_custody_digest(),
        request.route_id(),
        request.effect_id(),
        request.settlement_id(),
        request.semantic_digest(),
        request.terms_digest(),
        request.registry_digest(),
        request.profile_digest(),
        request.deployment_digest(),
        request.chain_id(),
        request.expected_transaction_id(),
        request.intent_digest(),
        request.custody_digest(),
        request.attempt_id(),
    ]
    .contains(&ZERO_DIGEST)
        || request.route_fencing_epoch() == 0
        || request.coordinator_fencing_epoch() == 0
        || request.attempt() == 0
        || request.child_index() >= 2
    {
        return Err(child_conflict_at_v25(2689));
    }
    Ok(())
}

fn validate_observation_request_shape(
    request: &ChildObservationRequestV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if [
        request.plan_id,
        request.plan_digest,
        request.route_id,
        request.effect_id,
        request.settlement_id,
        request.semantic_digest,
        request.terms_digest,
        request.registry_digest,
        request.profile_digest,
        request.deployment_digest,
        request.chain_id,
        request.transaction_id,
        request.intent_digest,
        request.custody_digest,
        request.observation_attempt_id,
    ]
    .contains(&ZERO_DIGEST)
        || request.route_fencing_epoch == 0
        || request.child_index >= 2
        || request
            .prior_finality_evidence_digest
            .is_some_and(|digest| digest == ZERO_DIGEST)
    {
        return Err(child_conflict_at_v25(2721));
    }
    Ok(())
}

fn dispatch_request_digest(
    request: &ChildDispatchRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    request_digest(
        DISPATCH_REQUEST_DOMAIN_V1,
        &[
            &request.plan_id(),
            &request.plan_digest(),
            &request.aggregate_action_id(),
            &request.aggregate_custody_digest(),
            &request.route_id(),
            &request.effect_id(),
            &request.settlement_id(),
            &[leg_tag(request.leg())],
            &[action_tag(request.action())],
            &request.semantic_digest(),
            &request.terms_digest(),
            &request.registry_digest(),
            &request.profile_digest(),
            &request.deployment_digest(),
            &request.route_fencing_epoch().to_be_bytes(),
            &request.coordinator_fencing_epoch().to_be_bytes(),
            &[request.child_index()],
            &[face_tag(request.face())],
            &[exposure_tag(request.exposure())],
            &request.chain_id(),
            &request.expected_transaction_id(),
            &request.intent_digest(),
            &request.custody_digest(),
            &request.attempt().to_be_bytes(),
            &request.attempt_id(),
        ],
    )
}

fn reconciliation_request_digest(
    request: &ChildReconciliationRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let dispatch = dispatch_request_digest(&request.dispatch)?;
    request_digest(
        RECONCILIATION_REQUEST_DOMAIN_V1,
        &[
            &dispatch,
            &request.current_route_fencing_epoch.to_be_bytes(),
            &request.current_coordinator_fencing_epoch.to_be_bytes(),
            &request.reconciliation_attempt_id,
        ],
    )
}

fn observation_request_digest(
    request: &ChildObservationRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let prior_tag = [u8::from(request.prior_finality_evidence_digest.is_some())];
    let prior = request
        .prior_finality_evidence_digest
        .unwrap_or(ZERO_DIGEST);
    request_digest(
        OBSERVATION_REQUEST_DOMAIN_V1,
        &[
            &request.plan_id,
            &request.plan_digest,
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            &[leg_tag(request.leg)],
            &[action_tag(request.action)],
            &request.semantic_digest,
            &request.route_fencing_epoch.to_be_bytes(),
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &[request.child_index],
            &[face_tag(request.face)],
            &[exposure_tag(request.exposure)],
            &request.chain_id,
            &request.transaction_id,
            &request.intent_digest,
            &request.custody_digest,
            &prior_tag,
            &prior,
            &request.observation_attempt_id,
        ],
    )
}

fn request_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| child_conflict_at_v25(2817))?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    if output == ZERO_DIGEST {
        return Err(child_conflict_at_v25(2826));
    }
    Ok(output)
}

const fn face_tag(value: SettlementFaceV1) -> u8 {
    match value {
        SettlementFaceV1::Dom => 1,
        SettlementFaceV1::Evm => 2,
        SettlementFaceV1::Bitcoin => 3,
        SettlementFaceV1::Monero => 4,
        SettlementFaceV1::Solana => 5,
    }
}

const fn leg_tag(value: SettlementLegV1) -> u8 {
    match value {
        SettlementLegV1::Upstream => 1,
        SettlementLegV1::Downstream => 2,
    }
}

const fn action_tag(value: SettlementActionV1) -> u8 {
    match value {
        SettlementActionV1::Funding => 1,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }
}

const fn exposure_tag(value: ChildExposureV1) -> u8 {
    match value {
        ChildExposureV1::NonSecret => 1,
        ChildExposureV1::FirstSecretExposure => 2,
        ChildExposureV1::UsesPublicSecret => 3,
    }
}

fn map_runtime_binding_error(error: RealDomError) -> ChildAuthorityRefusalV1 {
    match error {
        RealDomError::Chain(
            ChainAdapterError::AuthenticationFailed
            | ChainAdapterError::CapabilityUnavailable
            | ChainAdapterError::TemporarilyUnavailable
            | ChainAdapterError::HttpStatus(_),
        )
        | RealDomError::Store(_)
        | RealDomError::LockPoisoned
        | RealDomError::EvidenceNotFound => ChildAuthorityRefusalV1::Unavailable,
        RealDomError::Chain(
            ChainAdapterError::InvalidConfiguration
            | ChainAdapterError::BoundsExceeded
            | ChainAdapterError::MalformedResponse
            | ChainAdapterError::IdentityMismatch
            | ChainAdapterError::ReorgDetected
            | ChainAdapterError::InvalidEvidence
            | ChainAdapterError::TransactionRejected
            | ChainAdapterError::InvalidTransaction,
        )
        | RealDomError::Leg(_)
        | RealDomError::InvalidEvidence
        | RealDomError::Observation(_)
        | RealDomError::BoundsExceeded
        | RealDomError::FinalityPolicyInvalid
        | RealDomError::InsufficientConfirmations
        | RealDomError::TransactionStillCanonical
        | RealDomError::ReorgBeyondPolicy => ChildAuthorityRefusalV1::Conflict,
    }
}

// A process heartbeat may extend a live storage lease; it never changes the
// operation, signed scope, nonce transcript or fencing generation. The native
// store also revalidates its retained physical owner and exact lease row.
/// Renews a still-live DOM actuator lease to its full duration. An expired
/// lease is never revived, and a child without a renewal duration keeps its
/// lease unchanged.
fn top_up_dom_lease_v25(
    actuator: &mut DomActuatorStoreV1,
    lease: DomLeaseV1,
    now: u64,
    duration: Option<u64>,
) -> Result<DomLeaseV1, ChildAuthorityRefusalV1> {
    let Some(duration) = duration else {
        return Ok(lease);
    };
    if now >= lease.lease_until_unix_ms() {
        return Err(ChildAuthorityRefusalV1::Unavailable);
    }
    renew_dom_lease_v12(actuator, lease, now, duration)
}

fn renew_dom_lease_v12(
    actuator: &mut DomActuatorStoreV1,
    lease: DomLeaseV1,
    now: u64,
    duration: u64,
) -> Result<DomLeaseV1, ChildAuthorityRefusalV1> {
    if duration == 0 || duration > 3_600_000 || now == 0 {
        return Err(child_conflict_at_v25(2924));
    }
    if now >= lease.lease_until_unix_ms() {
        return Err(ChildAuthorityRefusalV1::Unavailable);
    }
    actuator
        .renew_lease(lease, now, duration)
        .map_err(|error| {
            eprintln!("DOM_RENEW_SITE_V26 site=dom_store_renew error={error:?} until={} now={now}",
                lease.lease_until_unix_ms());
            map_actuator_error(error)
        })
}

fn map_actuator_error(error: DomActuatorError) -> ChildAuthorityRefusalV1 {
    match error {
        DomActuatorError::StorageUnavailable
        | DomActuatorError::ProcessLocked
        | DomActuatorError::LeaseHeld
        | DomActuatorError::LeaseExpired
        | DomActuatorError::RpcAuthorityUnavailable
        | DomActuatorError::ContractsAuthorityUnavailable
        | DomActuatorError::CryptoAuthorityUnavailable
        | DomActuatorError::WalletUnavailable
        | DomActuatorError::SharedOutputRecoveryIndeterminate => {
            ChildAuthorityRefusalV1::Unavailable
        }
        DomActuatorError::RefundNotArmed
        | DomActuatorError::ClaimNotPrepared
        | DomActuatorError::InsufficientFunds
        | DomActuatorError::ReconciliationRequired
        | DomActuatorError::ReorgEvidenceRequired
        | DomActuatorError::FinalityPending
        | DomActuatorError::TerminalStillCanonical => ChildAuthorityRefusalV1::Refused,
        DomActuatorError::LinuxRequired
        | DomActuatorError::InvalidStorageAuthority
        | DomActuatorError::DatabasePresent
        | DomActuatorError::DatabaseMissing
        | DomActuatorError::CreationIncomplete
        | DomActuatorError::UnsupportedFormat
        | DomActuatorError::InvalidBinding
        | DomActuatorError::CapabilityMismatch
        | DomActuatorError::StaleFence
        | DomActuatorError::RevisionConflict
        | DomActuatorError::IdempotencyConflict
        | DomActuatorError::InvalidStage
        | DomActuatorError::OutputReservationConflict
        | DomActuatorError::WalletChainMismatch
        | DomActuatorError::SecretReuseDetected
        | DomActuatorError::FinalityEvidenceInvalid
        | DomActuatorError::FinalityPolicyUnsupported
        | DomActuatorError::ReorgBeyondPolicy => ChildAuthorityRefusalV1::Conflict,
    }
}

fn fresh_dom_time<C: ProductionDomChildClockV1>(
    clock: &mut C,
    prior_unix_ms: u64,
) -> Result<u64, ChildAuthorityRefusalV1> {
    let fresh = clock.now_unix_ms()?;
    if fresh < prior_unix_ms {
        return Err(child_conflict_at_v25(2981));
    }
    Ok(fresh)
}

fn map_f7_claim_error_v21(
    error: crate::production_contracts::ProductionF7FinalClaimErrorV14,
) -> ChildAuthorityRefusalV1 {
    use crate::production_contracts::ProductionF7FinalClaimErrorV14 as Error;
    match error {
        Error::AdaptationRequired => ChildAuthorityRefusalV1::Unavailable,
        Error::Actuator(error) => map_actuator_error(error),
        Error::Transport(error) => map_contracts_outbound_error(error),
        Error::Store(
            dom_scriptless_store::SessionStoreError::Filesystem
            | dom_scriptless_store::SessionStoreError::StoreBusy,
        ) => ChildAuthorityRefusalV1::Unavailable,
        Error::Anchors(crate::production_contracts::ProductionF7RuntimeErrorV12::Evidence(
            f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11::WindowClosed,
        )) => ChildAuthorityRefusalV1::Unavailable,
        Error::Scope | Error::Store(_) | Error::Anchors(_) => ChildAuthorityRefusalV1::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn native_refund_scan_budget_never_exceeds_live_lease_or_sixty_seconds_v23() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = DomActuatorStoreV1::create(&root.path().join("lease.sqlite")).unwrap();
        let lease = store
            .acquire_lease([81; 32], [82; 32], 1_000, 120_000)
            .unwrap();
        assert_eq!(
            native_refund_budget_v23(lease, 1_000).unwrap(),
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            native_refund_budget_v23(lease, 120_999).unwrap(),
            std::time::Duration::from_millis(1)
        );
        assert!(native_refund_budget_v23(lease, 121_000).is_err());
        assert!(native_refund_budget_v23(lease, u64::MAX).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn v12_dom_renewal_keeps_owner_and_epoch_but_cannot_revive_expired_lease() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = DomActuatorStoreV1::create(&root.path().join("lease.sqlite")).unwrap();
        let first = store
            .acquire_lease([81; 32], [82; 32], 1_000, 1_000)
            .unwrap();
        let renewed = renew_dom_lease_v12(&mut store, first, 1_600, 1_000).unwrap();
        assert_eq!(renewed.participant_id(), first.participant_id());
        assert_eq!(renewed.owner_id(), first.owner_id());
        assert_eq!(renewed.fencing_epoch(), first.fencing_epoch());
        assert_eq!(renewed.lease_until_unix_ms(), 2_600);
        // The old copied capability no longer matches the retained deadline.
        assert!(renew_dom_lease_v12(&mut store, first, 1_700, 1_000).is_err());
        assert!(renew_dom_lease_v12(&mut store, renewed, 2_600, 1_000).is_err());
        // Only an explicit takeover, outside renewal, changes the generation.
        let takeover = store
            .acquire_lease([81; 32], [83; 32], 2_601, 1_000)
            .unwrap();
        assert_eq!(takeover.fencing_epoch(), first.fencing_epoch() + 1);
        assert!(renew_dom_lease_v12(&mut store, renewed, 2_602, 1_000).is_err());
    }

    use std::time::Duration;

    use dom_scriptless_chain_adapter::{
        BearerTokenV1, DomHttpChainAdapterV1, ExpectedDomIdentityV1,
    };
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(AuthenticatedDomDispatchCallV1: Clone, Copy);
    assert_not_impl_any!(AuthenticatedDomReconciliationCallV1: Clone, Copy);
    assert_not_impl_any!(ProductionDomChildCompositionV1: Clone, Copy);
    assert_not_impl_any!(ProductionDomF7ScannerAuthorityV1: Clone, Copy);
    assert_not_impl_any!(ProductionDomPublicSecretConsumerAuthorityV1: Clone, Copy);
    assert_not_impl_any!(ProductionDomChildStoreAuthorityV1: Clone, Send, Sync);

    const fn digest(tag: u8) -> Digest32 {
        [tag; 32]
    }

    struct OneTimeClock(Option<u64>);

    impl ProductionDomChildClockV1 for OneTimeClock {
        fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
            self.0.take().ok_or(ChildAuthorityRefusalV1::Unavailable)
        }
    }

    fn funding_observation_request() -> ChildObservationRequestV1 {
        ChildObservationRequestV1 {
            plan_id: digest(1),
            plan_digest: digest(2),
            route_id: digest(3),
            effect_id: digest(4),
            settlement_id: digest(5),
            leg: SettlementLegV1::Upstream,
            action: SettlementActionV1::Funding,
            semantic_digest: digest(6),
            route_fencing_epoch: 7,
            terms_digest: digest(8),
            registry_digest: digest(9),
            profile_digest: digest(10),
            deployment_digest: digest(11),
            child_index: 0,
            face: SettlementFaceV1::Dom,
            exposure: ChildExposureV1::NonSecret,
            chain_id: digest(12),
            transaction_id: digest(13),
            intent_digest: digest(14),
            custody_digest: digest(15),
            prior_finality_evidence_digest: None,
            observation_attempt_id: digest(16),
        }
    }

    #[test]
    fn action_and_exposure_mappings_are_closed() {
        assert_eq!(
            dom_action(SettlementActionV1::Funding),
            DomActionV1::BroadcastFunding
        );
        assert_eq!(
            dom_action(SettlementActionV1::Claim),
            DomActionV1::BroadcastClaim
        );
        assert_eq!(
            dom_action(SettlementActionV1::Refund),
            DomActionV1::BroadcastRefund
        );
        assert_eq!(
            dom_exposure(ChildExposureV1::FirstSecretExposure),
            DomSettlementChildExposureV1::FirstSecretExposure
        );
    }

    fn identity_runtime() -> RealDomRpcRuntimeV1 {
        let genesis =
            dom_core::startup_genesis_hash_for_network_magic(dom_core::NETWORK_MAGIC_REGTEST)
                .expect("compiled regtest genesis");
        let adapter = DomHttpChainAdapterV1::new(
            "http://127.0.0.1:1",
            ExpectedDomIdentityV1 {
                network: "regtest".to_owned(),
                network_magic: dom_core::NETWORK_MAGIC_REGTEST,
                chain_id: *dom_consensus::derive_chain_id(
                    dom_core::NETWORK_MAGIC_REGTEST,
                    &genesis,
                )
                .as_bytes(),
                genesis_hash: *genesis.as_bytes(),
                protocol_version: dom_core::PROTOCOL_VERSION,
                range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
            },
            BearerTokenV1::new("runtime-identity-test".to_owned()).expect("bounded bearer"),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .expect("authenticated loopback client");
        RealDomRpcRuntimeV1::new(adapter, 16).expect("bounded runtime")
    }

    #[test]
    fn child_retained_runtime_is_the_exact_f7_runtime_identity() {
        let child_runtime = Arc::new(identity_runtime());
        let scanner = ProductionDomF7ScannerAuthorityV1::from_child_runtime(&child_runtime);
        assert!(scanner.shares_runtime(&child_runtime));

        // Equal public chain identity is insufficient: another physical
        // runtime/client must never satisfy the F7 purpose handle.
        let second_runtime = Arc::new(identity_runtime());
        assert_eq!(
            child_runtime.expected_identity(),
            second_runtime.expected_identity()
        );
        assert!(!scanner.shares_runtime(&second_runtime));
    }

    #[test]
    fn action_results_retain_large_authorities_behind_owned_pointers() {
        let two_words = 2 * core::mem::size_of::<usize>();
        assert!(core::mem::size_of::<ProductionDomActionResultV1>() <= two_words);
        assert!(core::mem::size_of::<CompletedDomCapabilityV1>() <= two_words);
    }

    #[test]
    fn post_authority_time_must_not_regress() {
        assert_eq!(
            fresh_dom_time(&mut OneTimeClock(Some(99)), 100),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(fresh_dom_time(&mut OneTimeClock(Some(100)), 100), Ok(100));
    }

    #[test]
    fn actuator_error_taxonomy_never_treats_partial_creation_as_transient() {
        assert_eq!(
            map_actuator_error(DomActuatorError::CreationIncomplete),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::InvalidStorageAuthority),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::StorageUnavailable),
            ChildAuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::RefundNotArmed),
            ChildAuthorityRefusalV1::Refused
        );
    }

    #[test]
    fn request_digest_is_replay_stable_and_call_family_separated() {
        let dispatch =
            request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]]).expect("dispatch digest");
        assert_eq!(
            dispatch,
            request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]]).expect("dispatch replay")
        );
        assert_ne!(
            dispatch,
            request_digest(RECONCILIATION_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]])
                .expect("reconciliation digest")
        );
        assert_ne!(dispatch, ZERO_DIGEST);
    }

    #[test]
    fn pending_and_invalid_evidence_remain_distinct_refusals() {
        assert_eq!(
            map_actuator_error(DomActuatorError::FinalityPending),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::FinalityEvidenceInvalid),
            ChildAuthorityRefusalV1::Conflict
        );
    }

    #[test]
    fn canonical_absence_never_becomes_proven_not_externalized() {
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Funding
        ));
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Claim
        ));
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Refund
        ));
    }

    #[test]
    fn invariant_failure_never_becomes_an_ambiguous_rpc_outcome() {
        assert!(matches!(
            ConcreteProductionDomActionAuthorityV1::rpc_result(Err(
                DomActuatorError::CapabilityMismatch
            )),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
        assert!(matches!(
            ConcreteProductionDomActionAuthorityV1::rpc_result(Err(
                DomActuatorError::RpcAuthorityUnavailable
            )),
            Ok(ProductionDomActionResultV1::Unknown)
        ));
    }

    #[test]
    fn dom_route_port_selects_exactly_two_legs_and_rejects_transplants() {
        let sessions = [
            (SettlementLegV1::Upstream, digest(31)),
            (SettlementLegV1::Downstream, digest(32)),
        ];
        assert_eq!(
            exact_dom_session_index_v1(&sessions, digest(31), SettlementLegV1::Upstream),
            Ok(0)
        );
        assert_eq!(
            exact_dom_session_index_v1(&sessions, digest(32), SettlementLegV1::Downstream),
            Ok(1)
        );
        for refused in [
            exact_dom_session_index_v1(&sessions, digest(31), SettlementLegV1::Downstream),
            exact_dom_session_index_v1(&sessions, digest(32), SettlementLegV1::Upstream),
            exact_dom_session_index_v1(&sessions, digest(33), SettlementLegV1::Upstream),
            exact_dom_session_index_v1(
                &[
                    (SettlementLegV1::Upstream, digest(31)),
                    (SettlementLegV1::Downstream, digest(31)),
                ],
                digest(31),
                SettlementLegV1::Upstream,
            ),
        ] {
            assert_eq!(refused, Err(ChildAuthorityRefusalV1::Conflict));
        }
    }

    #[test]
    fn funding_reorg_recovery_is_stable_and_rejects_prior_transplant() {
        let mut request = funding_observation_request();
        let low_level_prior = digest(20);
        let prior_block_hash = digest(21);
        let low_level_reorg = digest(22);
        let facts = ChildFinalityFactsV1 {
            final_evidence_digest: low_level_prior,
            final_block_hash: prior_block_hash,
            final_block_number: 144,
        };
        let binding = ChildObservationEvidenceBindingV1::from_observation(&request);
        let coordinator_prior = observation_final_evidence_v1(&binding, &facts)
            .expect("canonical prior funding finality evidence");
        request.prior_finality_evidence_digest = Some(coordinator_prior);
        let revalidation = DomFinalityRevalidationV1::Invalidated {
            transaction_id: request.transaction_id,
            prior_evidence_digest: low_level_prior,
            prior_block_height: facts.final_block_number,
            prior_block_hash,
            reorg_evidence_digest: low_level_reorg,
        };
        let first = ProductionDomChildPortV1::<
            SystemProductionDomChildClockV1,
            ConcreteProductionDomActionAuthorityV1,
        >::revalidation_observation(&request, revalidation)
        .expect("first recovery");
        let replay = ProductionDomChildPortV1::<
            SystemProductionDomChildClockV1,
            ConcreteProductionDomActionAuthorityV1,
        >::revalidation_observation(&request, revalidation)
        .expect("byte-stable crash replay");
        assert_eq!(first, replay);
        assert!(matches!(
            first,
            DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest,
                ..
            } if prior_finality_evidence_digest == coordinator_prior
        ));

        let mut transplanted = request;
        transplanted.prior_finality_evidence_digest = Some(digest(23));
        assert!(matches!(
            ProductionDomChildPortV1::<
                SystemProductionDomChildClockV1,
                ConcreteProductionDomActionAuthorityV1,
            >::revalidation_observation(&transplanted, revalidation),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
    }
}

// DIAG(temporary): names the source line of the child refusal that fired.
fn child_conflict_at_v25(line: u32) -> ChildAuthorityRefusalV1 {
    eprintln!("DOM_CHILD_CONFLICT_V25 file=production_child_dom.rs line={line}");
    ChildAuthorityRefusalV1::Conflict
}
