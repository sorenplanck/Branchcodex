//! Production settlement-child authority for the Monero face.
//!
//! The coordinator journals every dispatch before this boundary. The port
//! owns one durable Monero actuator plus the exact-broadcast and quorum
//! observation ports; sweep construction — the only step that touches the
//! combined private spend scalar — stays behind a scoped sweep authority
//! that can build exactly this settlement's claim or refund sweep and
//! nothing else. Raw bytes never leave the actuator, and every retained
//! transaction is re-verified against its consensus hash before it is
//! trusted again.
//!
//! Legacy funding uses external custody. V12 selected funders additionally
//! retain an independently verified private candidate and submit its exact
//! bytes only after the native DOM recovery owner fsyncs the intent and checks
//! fresh collateral. The recipient observes the pinned output using its view
//! key and quorum observations; neither role needs both spend shares to fund.

use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use deployment_registry::ResolvedMoneroDeploymentV1;
use route_composer::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
    RouteScalar,
};
use route_executor::LegIdV1;
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, Digest32, SettlementActionV1,
    SettlementChildPlanV1, SettlementFaceV1,
};
use xmr_actuator::{
    DurableXmrActuatorV1, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrObservationPortV1,
    XmrOperationKindV1, XmrOperationLocatorV1, XmrOperationViewV1, XmrReconciliationKindV1,
    XmrTxStageV1,
};
use xmr_raw_tx_verify::verify_exact_raw_sweep_v10;
use xmr_setup_profile::ValidatedXmrSetup;
use xmr_spend_port::ExactBroadcastPort;

use crate::production_child_evidence::{
    externalization_evidence_v1, first_exposure_evidence_v1, observation_final_evidence_v1,
    observation_pending_evidence_v1, observation_reorg_evidence_v1,
    proven_not_externalized_evidence_v1, unknown_evidence_v1, ChildEvidenceBindingV1,
    ChildFinalityFactsV1, ChildObservationEvidenceBindingV1,
};
use crate::production_child_router::{
    ProductionChildMaterializationRequestV1, ProductionSettlementChildPortV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;

#[path = "production_xmr_funding_deadline_v24.rs"]
mod funding_deadline_v24;
#[path = "production_xmr_funding_loss_v23.rs"]
mod funding_loss_v23;
#[path = "production_xmr_funding_reconciliation_v25.rs"]
mod funding_reconciliation_v25;

const ZERO_DIGEST: Digest32 = [0; 32];
const TRANSACTION_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/TRANSACTION-ID/V1\0";
const INTENT_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/INTENT/V1\0";
const INVALIDATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/INVALIDATION/V1\0";
const FUNDING_CUSTODY_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-CUSTODY/V1\0";
const FUNDING_EVIDENCE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-EVIDENCE/V1\0";
const XMR_DEPLOYMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/XMR-CHILD/DEPLOYMENT-DIGEST/V1\0";

/// One exact signed sweep built by the scoped sweep authority.
pub(crate) struct XmrBuiltSweepV1 {
    /// Consensus transaction hash of the exact bytes.
    pub(crate) tx_hash: Digest32,
    /// The sweep's own key image, for the absence statement.
    pub(crate) key_image: Digest32,
    /// Exact signed transaction bytes.
    pub(crate) raw_transaction: Vec<u8>,
    /// Store/Relay ancestry for a remotely imported sweep. Local construction
    /// is `None`; a remote client can only obtain `Some` after full verification.
    pub(crate) remote_custody_v23: Option<xmr_actuator::XmrRemoteCustodyDigestsV23>,
}

/// Verified external funding facts from the view-key scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XmrExternalFundingFactsV1 {
    /// Exact amount found spendable, in piconero.
    pub(crate) received_amount_piconero: u64,
    /// False for an additionally timelocked or unspendable output.
    pub(crate) spendable: bool,
}

/// Scoped sweep and funding-scan authority for exactly one settlement.
///
/// Implementations own the sidecar session, the local share store and the
/// view key. They combine scalars only inside `build_claim_sweep`, and the
/// child hands the composition-verified route scalar in by borrow — it is
/// never retained here or in the child.
pub(crate) trait ScopedXmrSweepAuthorityV1 {
    /// Whether this authority requires the remote ancestry marker on every
    /// reopen and immediately before externalization.
    fn requires_remote_custody_v23(&self, _kind: XmrOperationKindV1) -> bool {
        false
    }
    /// Concrete stable RPC quorum plus the authenticated view-key sidecar.
    /// Legacy test ports cannot manufacture the native funding capability.
    fn observe_verified_funding_v22(
        &mut self,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, ChildAuthorityRefusalV1>
    {
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    /// V12 local funders own an independently checked, privately retained
    /// candidate. The concrete authority uses the retained native DOM driver
    /// immediately before exact submission; legacy mocks cannot enable it.
    fn broadcast_funding_v12(
        &mut self,
        _recovery: &crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        _broadcast: &mut dyn ExactBroadcastPort,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    /// Builds the exact claim sweep for this settlement from the revealed
    /// route scalar combined with the local share.
    fn build_claim_sweep(
        &mut self,
        request_nonce: Digest32,
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1>;

    /// V23 route-scoped form used by remote claim construction. Local
    /// authorities retain the historical method; remote authorities must
    /// override this method because effect/fence/deployment/source pins cannot
    /// be reconstructed from a nonce alone.
    fn build_claim_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.build_claim_sweep(request.effect_id, scalar)
    }

    /// Post-retention hook for a remote response producer. The default local
    /// authority has nothing to publish. Implementations must not publish
    /// before the child has durably retained these exact bytes under a live
    /// actuator fence.
    fn complete_claim_sweep_v23(
        &mut self,
        _request: &ProductionChildMaterializationRequestV1,
        _scalar: &RouteScalar,
        _retained: &XmrBuiltSweepV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Ok(())
    }

    /// Remote producers must invoke this guard AFTER their observations and
    /// immediately before publishing/reconciling the public DSC1 response.
    /// Local default hooks do not publish anything.
    fn complete_claim_sweep_guarded_v24(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        retained: &XmrBuiltSweepV1,
        before_publish: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        before_publish()?;
        self.complete_claim_sweep_v23(request, scalar, retained)
    }

    /// Builds the exact refund sweep for this settlement from the refund
    /// share revealed by the DOM refund adaptor round.
    fn build_refund_sweep(
        &mut self,
        request_nonce: Digest32,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1>;

    /// V23 route-scoped refund form. The default remains the local,
    /// DOM-observation-gated refund path.
    fn build_refund_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.build_refund_sweep(request.effect_id)
    }

    /// Verifies the pinned external funding output with the view key.
    fn verify_external_funding(
        &mut self,
        request_nonce: Digest32,
    ) -> Result<XmrExternalFundingFactsV1, ChildAuthorityRefusalV1>;
}

/// Trusted clock boundary used for actuator lease checks.
pub(crate) trait ProductionXmrChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host wall-time adapter for the production composition root.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionXmrChildClockV1;

impl ProductionXmrChildClockV1 for SystemProductionXmrChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Authenticated, non-fabricable scope used to install Monero
/// materialization; mirrors the Solana child's scope authentication.
pub(crate) struct ProductionXmrMaterializationScopeV1 {
    max_fee_piconero_v23: u64,
    route_terms_digest: Digest32,
    setup_binding_hash: Digest32,
    deployment_digest: Digest32,
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    settlement_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

impl ProductionXmrMaterializationScopeV1 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        leg: LegIdV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let composition = inputs.composition();
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope.clone(),
                downstream_scope.clone(),
            )
            .map_err(|_| child_conflict_at_v25(242))?;
        let (settlement, plan_leg, coordinator_leg) = match leg {
            LegIdV1::Upstream => (
                composition.upstream(),
                ComposedSettlementLegV1::Upstream,
                settlement_coordinator::SettlementLegV1::Upstream,
            ),
            LegIdV1::Downstream => (
                composition.downstream(),
                ComposedSettlementLegV1::Downstream,
                settlement_coordinator::SettlementLegV1::Downstream,
            ),
        };
        let entry = role_plan.entry(plan_leg);
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || inputs.monero_session(leg).is_none()
            || entry.settlement_id().0 != settlement.settlement_id.0
            || entry.session_id().0 != settlement.session_id.0
            || entry.secret_source_scope_digest() == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(264));
        }
        let max_fee_piconero_v23 = u64::try_from(settlement.fee_limit.counterparty_max)
            .ok()
            .filter(|fee| *fee != 0)
            .ok_or_else(|| child_conflict_at_v25(269))?;
        Ok(Self {
            max_fee_piconero_v23,
            route_terms_digest: inputs.admission().frozen_bindings().terms_digest,
            setup_binding_hash: inputs
                .monero_session(leg)
                .ok_or_else(|| child_conflict_at_v25(275))?
                .setup()
                .binding_hash(),
            deployment_digest: resolved_monero_deployment_digest_v1(
                inputs
                    .monero_session(leg)
                    .ok_or_else(|| child_conflict_at_v25(281))?
                    .deployment(),
            )?,
            route_id: role_plan.route_id(),
            leg: coordinator_leg,
            settlement_id: settlement.settlement_id.0,
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digest: entry.secret_source_scope_digest(),
        })
    }
}

struct ProductionXmrMaterializationAuthorityV1 {
    sweep_authority: Box<dyn ScopedXmrSweepAuthorityV1>,
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

/// A read-only face of the SAME actuator opening used by the child. It cannot
/// obtain a lease, write a stage, publish bytes, or reopen the physical Store.
pub(crate) struct ProductionXmrRetainedRefundReaderV24 {
    actuator: std::rc::Rc<DurableXmrActuatorV1>,
    setup: ValidatedXmrSetup,
    max_fee: u64,
    max_raw_bytes: usize,
}
impl ProductionXmrRetainedRefundReaderV24 {
    pub(crate) fn new(
        actuator: std::rc::Rc<DurableXmrActuatorV1>,
        setup: ValidatedXmrSetup,
        max_fee: u64,
        max_raw_bytes: usize,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if setup.settlement_id() == ZERO_DIGEST
            || max_fee == 0
            || max_fee >= setup.expected_amount_piconero()
            || max_raw_bytes == 0
            || max_raw_bytes > xmr_actuator::MAX_RAW_TX_BYTES_V1
        {
            return Err(child_conflict_at_v25(326));
        }
        Ok(Self {
            actuator,
            setup,
            max_fee,
            max_raw_bytes,
        })
    }

    pub(crate) fn retained(&self) -> Result<Option<XmrBuiltSweepV1>, ChildAuthorityRefusalV1> {
        let locator = XmrOperationLocatorV1 {
            settlement_id: self.setup.settlement_id(),
            kind: XmrOperationKindV1::Refund,
        };
        let view = match self.actuator.view(locator) {
            Ok(view) => view,
            Err(XmrActuatorErrorV1::NotFound) => return Ok(None),
            Err(error) => return Err(map_actuator_error(error)),
        };
        let raw = self
            .actuator
            .retained(locator)
            .map_err(map_actuator_error)?;
        if view.locator != locator
            || view.fencing_epoch == 0
            || view.revision == 0
            || raw.len() > self.max_raw_bytes
            || xmr_actuator::custody_digest_v1(&raw).map_err(map_actuator_error)?
                != view.custody_digest
        {
            return Err(child_conflict_at_v25(357));
        }
        let verified = xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
            &raw,
            view.tx_hash,
            self.setup.expected_amount_piconero(),
            self.max_fee,
        )
        .map_err(|_| child_conflict_at_v25(365))?;
        if verified.sweep().key_images.as_slice() != [view.key_image] {
            return Err(child_conflict_at_v25(367));
        }
        // This proves only local byte custody. Fresh chain/payout/ring proof
        // verification is still required before a remote response is signed.
        Ok(Some(XmrBuiltSweepV1 {
            tx_hash: view.tx_hash,
            key_image: view.key_image,
            raw_transaction: raw,
            remote_custody_v23: None,
        }))
    }
}

/// Owner-scoped production bridge from coordinator calls to one Monero
/// actuator over one DLEQ-authenticated shared-spend setup.
pub(crate) struct ProductionXmrChildPortV1<B, O, C> {
    actuator: std::rc::Rc<DurableXmrActuatorV1>,
    broadcast: B,
    observation: O,
    deployment: ResolvedMoneroDeploymentV1,
    setup: ValidatedXmrSetup,
    lease: XmrActuatorLeaseV1,
    funding_window_v23: Option<crate::production_timer::ProductionFundingWindowV23>,
    min_confirmations: u64,
    clock: C,
    settlement_id: Digest32,
    route_terms_digest: Option<Digest32>,
    // Present on every authenticated production materializing port.
    max_fee_piconero_v23: Option<u64>,
    materialization: Option<ProductionXmrMaterializationAuthorityV1>,
    lease_owner_v11:
        Option<crate::production_universal_actuator::ProductionUniversalActuatorLeaseOwnerV11>,
    recovery_driver_v12: Option<
        std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
    >,
    recovery_deferred_v23:
        Option<std::rc::Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>>,
}

impl<B, O, C> core::fmt::Debug for ProductionXmrChildPortV1<B, O, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionXmrChildPortV1([authorities redacted])")
    }
}

const fn operation_for_action(action: SettlementActionV1) -> Option<XmrOperationKindV1> {
    match action {
        SettlementActionV1::Funding => None,
        SettlementActionV1::Claim => Some(XmrOperationKindV1::Claim),
        SettlementActionV1::Refund => Some(XmrOperationKindV1::Refund),
    }
}

// A clock regression cannot revive an operation authorized before a long RPC.
fn fresh_materialization_time_v23(before: u64, after: u64) -> Result<u64, ChildAuthorityRefusalV1> {
    if before == 0 || after == 0 || after < before {
        return Err(child_conflict_at_v25(423));
    }
    Ok(after)
}

fn fresh_live_materialization_time_v24(
    before: u64,
    after: u64,
    original_deadline: u64,
) -> Result<u64, ChildAuthorityRefusalV1> {
    let now = fresh_materialization_time_v23(before, after)?;
    if now >= original_deadline {
        return Err(child_conflict_at_v25(435));
    }
    Ok(now)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    if output == ZERO_DIGEST {
        return Err(child_conflict_at_v25(453));
    }
    Ok(output)
}

/// Public transaction identity of one exact Monero txid.
fn transaction_id_v1(tx_hash: Digest32) -> Result<Digest32, ChildAuthorityRefusalV1> {
    digest_parts(TRANSACTION_ID_DOMAIN_V1, &[tx_hash.as_slice()])
}

/// Intent commitment derived from durable facts, recomputable at any stage.
fn intent_digest_v1(
    settlement_id: Digest32,
    action: SettlementActionV1,
    custody_digest: Digest32,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let action_tag = [match action {
        SettlementActionV1::Funding => 1u8,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }];
    digest_parts(
        INTENT_DOMAIN_V1,
        &[&settlement_id, &action_tag, &custody_digest],
    )
}

/// Deterministic commitment to the exact resolved Monero deployment.
pub(crate) fn resolved_monero_deployment_digest_v1(
    deployment: &ResolvedMoneroDeploymentV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    digest_parts(
        XMR_DEPLOYMENT_DIGEST_DOMAIN_V1,
        &[
            &deployment.registry_digest(),
            &deployment.registry_epoch().to_be_bytes(),
            &deployment.profile_digest(),
            &deployment.asset_binding_digest(),
            &deployment.profile().chain_id.0,
            &deployment.deployment().genesis_hash,
            &deployment.deployment().max_fee_piconero.to_be_bytes(),
        ],
    )
}

/// Budget for one bounded XMR observation.
///
/// It mirrors the DOM child's `funding_observation_deadline_v26`. The figure to
/// measure against is `dispatch_lease_ms` (30 s), the shortest lease a route
/// step runs under, not the 120 s actuator lease: half of the shortest one
/// leaves the other half for the rest of the step, and eight observations
/// still fit inside the actuator lease. A quorum answer fans out over several
/// daemon calls of 30 s each, so without this the sum alone reaches 180 s.
pub(crate) fn observation_deadline_v26() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(15)
}

pub(crate) fn map_actuator_error(error: XmrActuatorErrorV1) -> ChildAuthorityRefusalV1 {
    match error {
        XmrActuatorErrorV1::StorageUnavailable | XmrActuatorErrorV1::ObservationUnavailable => {
            ChildAuthorityRefusalV1::Unavailable
        }
        XmrActuatorErrorV1::NotFound | XmrActuatorErrorV1::BroadcastRejected => {
            ChildAuthorityRefusalV1::Refused
        }
        XmrActuatorErrorV1::InvalidLease
        | XmrActuatorErrorV1::LeaseExpired
        | XmrActuatorErrorV1::Corrupt
        | XmrActuatorErrorV1::Conflict
        | XmrActuatorErrorV1::InvalidInput
        | XmrActuatorErrorV1::InvalidTime => ChildAuthorityRefusalV1::Conflict,
    }
}

impl<B, O, C> ProductionXmrChildPortV1<B, O, C>
where
    B: ExactBroadcastPort,
    O: XmrObservationPortV1,
    C: ProductionXmrChildClockV1,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        actuator: impl Into<std::rc::Rc<DurableXmrActuatorV1>>,
        broadcast: B,
        observation: O,
        deployment: ResolvedMoneroDeploymentV1,
        setup: ValidatedXmrSetup,
        lease: XmrActuatorLeaseV1,
        min_confirmations: u64,
        clock: C,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let settlement_id = setup.settlement_id();
        if settlement_id == ZERO_DIGEST
            || min_confirmations == 0
            || lease.network_id() != deployment.deployment().genesis_hash
            || lease.fencing_epoch() == 0
        {
            return Err(child_conflict_at_v25(538));
        }
        Ok(Self {
            actuator: actuator.into(),
            broadcast,
            observation,
            deployment,
            setup,
            lease,
            funding_window_v23: None,
            min_confirmations,
            clock,
            settlement_id,
            materialization: None,
            route_terms_digest: None,
            max_fee_piconero_v23: None,
            lease_owner_v11: None,
            recovery_driver_v12: None,
            recovery_deferred_v23: None,
        })
    }

    /// Install only the selected physical store's finite-lease issuer. This
    /// retains local process exclusion while the daemon waits for a refund.
    pub(crate) fn with_lease_owner_v11(
        mut self,
        owner: crate::production_universal_actuator::ProductionUniversalActuatorLeaseOwnerV11,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if self.lease_owner_v11.is_some() {
            return Err(child_conflict_at_v25(567));
        }
        owner.require_scope(
            crate::production_config::ProductionChainFamilyV11::Xmr,
            self.setup.binding_hash(),
            self.deployment.deployment().genesis_hash,
            self.lease.fencing_epoch(),
        )?;
        self.lease_owner_v11 = Some(owner);
        Ok(self)
    }

    pub(crate) fn with_funding_window_v23(
        mut self,
        window: crate::production_timer::ProductionFundingWindowV23,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if self.funding_window_v23.is_some() {
            return Err(child_conflict_at_v25(584));
        }
        self.funding_window_v23 = Some(window);
        Ok(self)
    }

    fn refresh_lease_v11(&mut self, now: u64) -> Result<(), ChildAuthorityRefusalV1> {
        if let Some(owner) = &self.lease_owner_v11 {
            self.lease = owner.xmr_lease(now).inspect_err(|refusal| {
                eprintln!("DOM_RENEW_SITE_V26 site=xmr_lease refusal={refusal:?}");
            })?;
        }
        Ok(())
    }

    /// V12 selected-leg mode retains the actual DOM collateral owner. Legacy
    /// callers keep their existing constructor; the universal V12 root must
    /// always install this owner for an XMR route.
    pub(crate) fn with_recovery_driver_v12(
        mut self,
        driver: std::rc::Rc<
            crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        >,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if self.recovery_driver_v12.is_some() || self.recovery_deferred_v23.is_some() {
            return Err(child_conflict_at_v25(607));
        }
        driver.require_attachment(self.setup.terms_hash())?;
        self.recovery_driver_v12 = Some(driver);
        Ok(self)
    }

    pub(crate) fn with_deferred_recovery_v23(
        mut self,
        slot: std::rc::Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if self.recovery_driver_v12.is_some() || self.recovery_deferred_v23.is_some() {
            return Err(child_conflict_at_v25(619));
        }
        slot.require_terms(self.setup.terms_hash())?;
        self.recovery_deferred_v23 = Some(slot);
        Ok(self)
    }

    fn resolved_recovery_v23(
        &self,
    ) -> Result<
        Option<
            std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
        >,
        ChildAuthorityRefusalV1,
    > {
        match (&self.recovery_driver_v12, &self.recovery_deferred_v23) {
            (Some(_), Some(_)) => Err(child_conflict_at_v25(635)),
            (Some(driver), None) => {
                driver.require_attachment(self.setup.terms_hash())?;
                Ok(Some(std::rc::Rc::clone(driver)))
            }
            (None, Some(slot)) => slot.require_driver().map(Some),
            (None, None) => Ok(None),
        }
    }

    /// Bind recovery dispatch to the *route* terms digest used by the
    /// coordinator, keeping the per-settlement setup hash independently pinned.
    pub(crate) fn bind_route_v7(
        mut self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let session = inputs
            .monero_session(leg)
            .ok_or_else(|| child_conflict_at_v25(654))?;
        let terms = inputs.admission().frozen_bindings().terms_digest;
        if terms == ZERO_DIGEST
            || session.setup().binding_hash() != self.setup.binding_hash()
            || session.deployment() != &self.deployment
            || session.setup().settlement_id() != self.settlement_id
        {
            return Err(child_conflict_at_v25(661));
        }
        let settlement = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let maximum = u64::try_from(settlement.fee_limit.counterparty_max)
            .ok()
            .filter(|fee| *fee != 0)
            .ok_or_else(|| child_conflict_at_v25(670))?;
        if self
            .max_fee_piconero_v23
            .is_some_and(|existing| existing != maximum)
        {
            return Err(child_conflict_at_v25(675));
        }
        self.max_fee_piconero_v23 = Some(maximum);
        self.route_terms_digest = Some(terms);
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_materializing(
        actuator: impl Into<std::rc::Rc<DurableXmrActuatorV1>>,
        broadcast: B,
        observation: O,
        deployment: ResolvedMoneroDeploymentV1,
        setup: ValidatedXmrSetup,
        lease: XmrActuatorLeaseV1,
        min_confirmations: u64,
        clock: C,
        sweep_authority: Box<dyn ScopedXmrSweepAuthorityV1>,
        scope: ProductionXmrMaterializationScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if scope.settlement_id != setup.settlement_id()
            || scope.setup_binding_hash != setup.binding_hash()
            || scope.deployment_digest != resolved_monero_deployment_digest_v1(&deployment)?
            || scope.route_terms_digest == ZERO_DIGEST
        {
            return Err(child_conflict_at_v25(700));
        }
        let mut port = Self::new(
            actuator,
            broadcast,
            observation,
            deployment,
            setup,
            lease,
            min_confirmations,
            clock,
        )?;
        port.route_terms_digest = Some(scope.route_terms_digest);
        port.max_fee_piconero_v23 = Some(scope.max_fee_piconero_v23);
        port.materialization = Some(ProductionXmrMaterializationAuthorityV1 {
            sweep_authority,
            route_id: scope.route_id,
            leg: scope.leg,
            route_scope_digest: scope.route_scope_digest,
            composition_digest: scope.composition_digest,
            role_plan_digest: scope.role_plan_digest,
            source_scope_digest: scope.source_scope_digest,
        });
        Ok(port)
    }

    fn locator(&self, kind: XmrOperationKindV1) -> XmrOperationLocatorV1 {
        XmrOperationLocatorV1 {
            settlement_id: self.settlement_id,
            kind,
        }
    }

    /// Custody commitment of the external funding statement: there are no
    /// local bytes to commit to, so the commitment names the exact pinned
    /// funding facts from the DLEQ-authenticated setup.
    fn funding_custody_digest(&self) -> Result<Digest32, ChildAuthorityRefusalV1> {
        digest_parts(
            FUNDING_CUSTODY_DOMAIN_V1,
            &[
                &self.settlement_id,
                &self.setup.funding_tx_hash(),
                &self.setup.expected_amount_piconero().to_be_bytes(),
                &self.setup.combined_spend_public_key(),
            ],
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "every argument is one pinned route/settlement fact; grouping them would only rename the same ten commitments"
    )]
    fn validate_common_bindings(
        &self,
        face: SettlementFaceV1,
        action: SettlementActionV1,
        exposure: ChildExposureV1,
        settlement_id: Digest32,
        terms_digest: Digest32,
        registry_digest: Digest32,
        profile_digest: Digest32,
        deployment_digest: Digest32,
        chain_id: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        // A Monero claim sweep publishes no witness on-chain: the DOM leg
        // reveals first, and the sweep merely uses what is already public.
        let exposure_valid = match action {
            SettlementActionV1::Funding | SettlementActionV1::Refund => {
                exposure == ChildExposureV1::NonSecret
            }
            SettlementActionV1::Claim => exposure == ChildExposureV1::UsesPublicSecret,
        };
        if face != SettlementFaceV1::Monero
            || !exposure_valid
            || settlement_id != self.settlement_id
            || registry_digest != self.deployment.registry_digest()
            || profile_digest != self.deployment.profile_digest()
            || deployment_digest != resolved_monero_deployment_digest_v1(&self.deployment)?
            || chain_id != self.deployment.profile().chain_id.0
            || Some(terms_digest) != self.route_terms_digest
        {
            return Err(child_conflict_at_v25(781));
        }
        Ok(())
    }

    fn verify_retained_sweep_v23(
        &self,
        raw: &[u8],
        hash: Digest32,
        image: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if let Some(maximum) = self.max_fee_piconero_v23 {
            let verified = xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
                raw,
                hash,
                self.setup.expected_amount_piconero(),
                maximum,
            )
            .map_err(|_| child_conflict_at_v25(799))?;
            if verified.sweep().key_images.as_slice() != &[image] {
                return Err(child_conflict_at_v25(801));
            }
            Ok(())
        } else {
            // A route-bound port must never lose its authenticated economics.
            // Only unbound component callers retain the historical raw profile.
            if self.route_terms_digest.is_some() {
                return Err(child_conflict_at_v25(808));
            }
            verify_single_sweep_image_v10(raw, hash, image)
        }
    }

    /// Validates a durable sweep view against dispatch expectations and
    /// re-verifies the retained bytes' consensus hash.
    fn validated_view(
        &self,
        kind: XmrOperationKindV1,
        action: SettlementActionV1,
        expected_transaction_id: Digest32,
        expected_custody_digest: Digest32,
        expected_intent_digest: Digest32,
    ) -> Result<XmrOperationViewV1, ChildAuthorityRefusalV1> {
        let view = self
            .actuator
            .view(self.locator(kind))
            .map_err(map_actuator_error)?;
        if view.custody_digest != expected_custody_digest
            || transaction_id_v1(view.tx_hash)? != expected_transaction_id
            || intent_digest_v1(self.settlement_id, action, view.custody_digest)?
                != expected_intent_digest
        {
            return Err(child_conflict_at_v25(833));
        }
        let retained_bytes = self
            .actuator
            .retained(view.locator)
            .map_err(map_actuator_error)?;
        if xmr_actuator::custody_digest_v1(&retained_bytes).map_err(map_actuator_error)?
            != view.custody_digest
        {
            return Err(child_conflict_at_v25(842));
        }
        self.verify_retained_sweep_v23(&retained_bytes, view.tx_hash, view.key_image)?;
        Ok(view)
    }

    fn externalized_receipt(
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExternalizationReceiptV1, ChildAuthorityRefusalV1> {
        let binding = ChildEvidenceBindingV1::from_dispatch(request);
        Ok(ChildExternalizationReceiptV1 {
            plan_id: request.plan_id(),
            child_index: request.child_index(),
            face: request.face(),
            chain_id: request.chain_id(),
            transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            externalization_evidence_digest: externalization_evidence_v1(&binding)
                .map_err(|_| child_conflict_at_v25(861))?,
            first_exposure_evidence_digest: first_exposure_evidence_v1(&binding)
                .map_err(|_| child_conflict_at_v25(863))?,
        })
    }

    fn materialize_xmr_child(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
        authority: &mut ProductionXmrMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let scalar_shape = matches!(
            (request.action, request.exposure, public_scalar),
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
                None,
            ) | (
                SettlementActionV1::Claim,
                ChildExposureV1::UsesPublicSecret,
                Some(_),
            )
        );
        let evidence_shape = match (request.action, request.exposure) {
            (SettlementActionV1::Claim, ChildExposureV1::UsesPublicSecret) => {
                request.public_secret_evidence_digest != ZERO_DIGEST
            }
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
            ) => request.public_secret_evidence_digest == ZERO_DIGEST,
            _ => false,
        };
        if !scalar_shape
            || !evidence_shape
            || request.route_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.fencing_epoch == 0
            || request.semantic_digest == ZERO_DIGEST
            || request.settlement_id != self.settlement_id
            || request.route_id != authority.route_id
            || request.leg != authority.leg
            || request.route_scope_digest != authority.route_scope_digest
            || request.composition_digest != authority.composition_digest
            || request.role_plan_digest != authority.role_plan_digest
            || request.source_scope_digest != authority.source_scope_digest
        {
            return Err(child_conflict_at_v25(909));
        }
        self.validate_common_bindings(
            SettlementFaceV1::Monero,
            request.action,
            request.exposure,
            request.settlement_id,
            request.terms_digest,
            request.registry_digest,
            request.profile_digest,
            request.deployment_digest,
            self.deployment.profile().chain_id.0,
        )?;
        let action = request.action;
        let Some(kind) = operation_for_action(action) else {
            // External custody: the plan names the pinned funding facts.
            // No XMR transaction is created here. Requiring confirmed C while
            // merely making this descriptor would deadlock DOM-first funding.
            if let Some(driver) = self.resolved_recovery_v23()? {
                driver.require_attachment(self.setup.terms_hash())?;
            }
            let custody = self.funding_custody_digest()?;
            return Ok(SettlementChildPlanV1 {
                face: SettlementFaceV1::Monero,
                exposure: ChildExposureV1::NonSecret,
                chain_id: self.deployment.profile().chain_id.0,
                expected_transaction_id: transaction_id_v1(self.setup.funding_tx_hash())?,
                intent_digest: intent_digest_v1(self.settlement_id, action, custody)?,
                custody_digest: custody,
            });
        };
        let locator = self.locator(kind);
        let now = self.clock.now_unix_ms()?;
        self.refresh_lease_v11(now)?;
        let requires_remote_custody = authority.sweep_authority.requires_remote_custody_v23(kind);
        let (view, retained_sweep) = match self.actuator.view(locator) {
            Ok(view) => {
                // Idempotent reopen: re-verify the retained bytes' consensus
                // hash rather than rebuilding a sweep (the sidecar owns
                // construction and is not byte-deterministic across calls).
                let retained_bytes = self
                    .actuator
                    .retained(locator)
                    .map_err(map_actuator_error)?;
                self.verify_retained_sweep_v23(&retained_bytes, view.tx_hash, view.key_image)?;
                let remote_custody_v23 = if requires_remote_custody {
                    Some(
                        self.actuator
                            .require_remote_custody_v23(&self.lease, locator, now)
                            .map_err(map_actuator_error)?,
                    )
                } else {
                    None
                };
                let retained_sweep = XmrBuiltSweepV1 {
                    tx_hash: view.tx_hash,
                    key_image: view.key_image,
                    raw_transaction: retained_bytes,
                    remote_custody_v23,
                };
                (view, retained_sweep)
            }
            Err(XmrActuatorErrorV1::NotFound) => {
                let built = match (kind, public_scalar) {
                    (XmrOperationKindV1::Claim, Some(scalar)) => authority
                        .sweep_authority
                        .build_claim_sweep_v23(request, scalar)?,
                    (XmrOperationKindV1::Refund, None) => {
                        authority.sweep_authority.build_refund_sweep_v23(request)?
                    }
                    _ => return Err(child_conflict_at_v25(979)),
                };
                // Independent consensus-hash verification before anything is
                // retained: the sidecar's answer is never trusted bare.
                self.verify_retained_sweep_v23(
                    &built.raw_transaction,
                    built.tx_hash,
                    built.key_image,
                )?;
                // Sidecar/DOM observation can outlast the finite lease. Do
                // not extend that lease after building: retain its exact fence
                // and let the native write reject an expired deadline.
                let persist_now = fresh_materialization_time_v23(now, self.clock.now_unix_ms()?)?;
                if let Some(owner) = &self.lease_owner_v11 {
                    owner.require_scope(
                        crate::production_config::ProductionChainFamilyV11::Xmr,
                        self.setup.binding_hash(),
                        self.deployment.deployment().genesis_hash,
                        self.lease.fencing_epoch(),
                    )?;
                }
                let retained_sweep = XmrBuiltSweepV1 {
                    tx_hash: built.tx_hash,
                    key_image: built.key_image,
                    raw_transaction: built.raw_transaction.clone(),
                    remote_custody_v23: built.remote_custody_v23,
                };
                let view = match built.remote_custody_v23 {
                    Some(digests) if requires_remote_custody => {
                        self.actuator.prepare_signed_remote_v23(
                            &self.lease,
                            locator,
                            built.tx_hash,
                            built.key_image,
                            &built.raw_transaction,
                            digests,
                            persist_now,
                        )
                    }
                    None if !requires_remote_custody => self.actuator.prepare_signed(
                        &self.lease,
                        locator,
                        built.tx_hash,
                        built.key_image,
                        &built.raw_transaction,
                        persist_now,
                    ),
                    Some(_) | None => return Err(child_conflict_at_v25(1026)),
                }
                .map_err(map_actuator_error)?;
                (view, retained_sweep)
            }
            Err(error) => return Err(map_actuator_error(error)),
        };
        if view.stage == XmrTxStageV1::FinalityInvalidated {
            return Err(child_conflict_at_v25(1034));
        }
        if let (XmrOperationKindV1::Claim, Some(scalar)) = (kind, public_scalar) {
            // F7/quorum/sidecar work may have consumed the original window.
            // Recheck the exact retained row, physical owner and unchanged
            // lease at fresh time; never renew a lease merely to publish 0x1a.
            let mut last_checked_time = now;
            let mut before_publish = || {
                let completion_now =
                    fresh_materialization_time_v23(last_checked_time, self.clock.now_unix_ms()?)?;
                last_checked_time = completion_now;
                if let Some(owner) = &self.lease_owner_v11 {
                    owner.require_scope(
                        crate::production_config::ProductionChainFamilyV11::Xmr,
                        self.setup.binding_hash(),
                        self.deployment.deployment().genesis_hash,
                        self.lease.fencing_epoch(),
                    )?;
                }
                let checked = self
                    .actuator
                    .checked_view_v23(&self.lease, locator, completion_now)
                    .map_err(map_actuator_error)?;
                if checked != view {
                    return Err(child_conflict_at_v25(1058));
                }
                // checked_view can wait for its SQLite lock. Its input time
                // alone cannot prove that this same lease is still live once
                // the audited row has actually returned.
                let after_check = fresh_live_materialization_time_v24(
                    last_checked_time,
                    self.clock.now_unix_ms()?,
                    self.lease.deadline_unix_ms_v24(),
                )?;
                last_checked_time = after_check;
                Ok(())
            };
            before_publish()?;
            authority.sweep_authority.complete_claim_sweep_guarded_v24(
                request,
                scalar,
                &retained_sweep,
                &mut before_publish,
            )?;
        }
        Ok(SettlementChildPlanV1 {
            face: SettlementFaceV1::Monero,
            exposure: if action == SettlementActionV1::Claim {
                ChildExposureV1::UsesPublicSecret
            } else {
                ChildExposureV1::NonSecret
            },
            chain_id: self.deployment.profile().chain_id.0,
            expected_transaction_id: transaction_id_v1(view.tx_hash)?,
            intent_digest: intent_digest_v1(self.settlement_id, action, view.custody_digest)?,
            custody_digest: view.custody_digest,
        })
    }

    /// Funding-path observation shared by observe and reconcile: the pinned
    /// external funding transaction looked up at the quorum boundary.
    fn funding_inclusion(
        &mut self,
    ) -> Result<Option<xmr_actuator::XmrTxInclusionV1>, ChildAuthorityRefusalV1> {
        self.observation
            .transaction_inclusion(self.setup.funding_tx_hash())
            .map_err(map_actuator_error)
    }

    fn validate_funding_request(
        &self,
        expected_transaction_id: Digest32,
        expected_custody_digest: Digest32,
        expected_intent_digest: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let custody = self.funding_custody_digest()?;
        if expected_custody_digest != custody
            || expected_transaction_id != transaction_id_v1(self.setup.funding_tx_hash())?
            || expected_intent_digest
                != intent_digest_v1(self.settlement_id, SettlementActionV1::Funding, custody)?
        {
            return Err(child_conflict_at_v25(1115));
        }
        Ok(())
    }
}

impl<B, O, C> ProductionSettlementChildPortV1 for ProductionXmrChildPortV1<B, O, C>
where
    B: ExactBroadcastPort,
    O: XmrObservationPortV1,
    C: ProductionXmrChildClockV1,
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Monero
    }

    fn settlement_id(&self) -> Option<Digest32> {
        Some(self.settlement_id)
    }

    fn renew_actuator_lease_v12(&mut self) -> Result<(), ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        self.refresh_lease_v11(now)
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let mut authority = self
            .materialization
            .take()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        let result = self.materialize_xmr_child(&request, public_scalar, &mut authority);
        self.materialization = Some(authority);
        result
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.validate_common_bindings(
            request.face(),
            request.action(),
            request.exposure(),
            request.settlement_id(),
            request.terms_digest(),
            request.registry_digest(),
            request.profile_digest(),
            request.deployment_digest(),
            request.chain_id(),
        )?;
        let action = request.action();
        let Some(kind) = operation_for_action(action) else {
            // V12 local funding is privately prepared before admission and
            // submitted only after actual fresh DOM collateral is verified.
            self.validate_funding_request(
                request.expected_transaction_id(),
                request.custody_digest(),
                request.intent_digest(),
            )?;
            let recovery = self.resolved_recovery_v23()?;
            let funding_deadline = if recovery.is_some() {
                let observed_before_clock = std::time::Instant::now();
                let now = self.clock.now_unix_ms()?;
                let window = self
                    .funding_window_v23
                    .as_ref()
                    .and_then(|window| window.deadline_for_route(request.route_id()))
                    .ok_or(ChildAuthorityRefusalV1::Unavailable)
                    .inspect_err(|error| {
                        funding_reconciliation_v25::report_refusal("window", error)
                    })?;
                Some(
                    funding_deadline_v24::funding_deadline_v24(
                        window,
                        observed_before_clock,
                        now,
                        self.lease.deadline_unix_ms_v24(),
                    )
                    .ok_or(ChildAuthorityRefusalV1::Unavailable)
                    .inspect_err(|error| {
                        funding_reconciliation_v25::report_refusal("deadline", error)
                    })?,
                )
            } else {
                None
            };
            if let Some(driver) = &recovery {
                let remaining = funding_deadline
                    .ok_or(ChildAuthorityRefusalV1::Unavailable)?
                    .saturating_duration_since(std::time::Instant::now());
                let collateral = driver
                    .verify_funding_prerequisite_bounded_v23(remaining)
                    .inspect_err(|error| {
                        funding_reconciliation_v25::report_refusal("collateral", error)
                    })?;
                if collateral.collateral().finality().terms_hash() != self.setup.terms_hash() {
                    return Err(child_conflict_at_v25(1205));
                }
            }
            let mut authority = self
                .materialization
                .take()
                .ok_or(ChildAuthorityRefusalV1::Refused)?;
            let facts = (|| {
                if let Some(driver) = &recovery {
                    let mut broadcast = funding_deadline_v24::FundingDeadlineBroadcastV24::new(
                        &mut self.broadcast,
                        funding_deadline.ok_or(ChildAuthorityRefusalV1::Unavailable)?,
                    );
                    authority
                        .sweep_authority
                        .broadcast_funding_v12(driver, &mut broadcast)
                        .inspect_err(|error| {
                            funding_reconciliation_v25::report_refusal("broadcast", error)
                        })?;
                    let funding = authority
                        .sweep_authority
                        .observe_verified_funding_v22()
                        .inspect_err(|error| {
                            funding_reconciliation_v25::report_refusal("observation", error)
                        })?;
                    match driver.tick_with_funding(funding).inspect_err(|error| {
                        funding_reconciliation_v25::report_refusal("recovery", error)
                    })? {
                        adapter_dom_real::DomXmrRecoveryProgressV12::CollateralReady(_) => {}
                        _ => return Err(ChildAuthorityRefusalV1::Unavailable),
                    }
                    return Ok(XmrExternalFundingFactsV1 {
                        received_amount_piconero: self.setup.expected_amount_piconero(),
                        spendable: true,
                    });
                }
                authority
                    .sweep_authority
                    .verify_external_funding(request.attempt_id())
            })();
            self.materialization = Some(authority);
            let facts = facts?;
            if facts.spendable
                && facts.received_amount_piconero == self.setup.expected_amount_piconero()
            {
                return Ok(ChildExecutionOutcomeV1::Externalized(
                    Self::externalized_receipt(request)?,
                ));
            }
            let binding = ChildEvidenceBindingV1::from_dispatch(request);
            return Ok(ChildExecutionOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| child_conflict_at_v25(1247))?,
            });
        };
        let view = self.validated_view(
            kind,
            action,
            request.expected_transaction_id(),
            request.custody_digest(),
            request.intent_digest(),
        )?;
        if !matches!(
            view.stage,
            XmrTxStageV1::Signed | XmrTxStageV1::SendAttempted
        ) {
            return Err(child_conflict_at_v25(1261));
        }
        let now = self.clock.now_unix_ms()?;
        self.refresh_lease_v11(now)?;
        if self
            .materialization
            .as_ref()
            .is_some_and(|authority| authority.sweep_authority.requires_remote_custody_v23(kind))
        {
            self.actuator
                .require_remote_custody_v23(&self.lease, self.locator(kind), now)
                .map_err(map_actuator_error)?;
        }
        let outcome = self
            .actuator
            .broadcast_current(
                &self.lease,
                self.locator(kind),
                request.attempt_id(),
                &mut self.broadcast,
                now,
            )
            .map_err(map_actuator_error)?;
        if outcome.accepted {
            Ok(ChildExecutionOutcomeV1::Externalized(
                Self::externalized_receipt(request)?,
            ))
        } else {
            let binding = ChildEvidenceBindingV1::from_dispatch(request);
            Ok(ChildExecutionOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| child_conflict_at_v25(1292))?,
            })
        }
    }

    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let dispatch = &request.dispatch;
        if request.current_route_fencing_epoch < dispatch.route_fencing_epoch()
            || request.current_coordinator_fencing_epoch < dispatch.coordinator_fencing_epoch()
        {
            return Err(child_conflict_at_v25(1305));
        }
        self.validate_common_bindings(
            dispatch.face(),
            dispatch.action(),
            dispatch.exposure(),
            dispatch.settlement_id(),
            dispatch.terms_digest(),
            dispatch.registry_digest(),
            dispatch.profile_digest(),
            dispatch.deployment_digest(),
            dispatch.chain_id(),
        )?;
        // Same bound as `observe`, for the same reason: reconciliation reads
        // the chain through the very same quorum port, and its funding branch
        // also returns before any later statement could set one.
        self.observation
            .set_observation_deadline_v26(observation_deadline_v26())
            .map_err(map_actuator_error)?;
        let action = dispatch.action();
        let binding = ChildEvidenceBindingV1::from_dispatch(dispatch);
        let Some(kind) = operation_for_action(action) else {
            // Inclusion settles either funding mode. An absent local funding
            // must also resume its retained exact-byte submission: a failed
            // prerequisite can leave CallPending before any send occurred.
            // External funding has no local transmission authority.
            self.validate_funding_request(
                dispatch.expected_transaction_id(),
                dispatch.custody_digest(),
                dispatch.intent_digest(),
            )?;
            let min_confirmations = self.min_confirmations;
            let inclusion = self.funding_inclusion()?;
            let local = inclusion.is_none() && self.resolved_recovery_v23()?.is_some();
            return funding_reconciliation_v25::reconcile(
                inclusion.map(|value| value.confirmations),
                min_confirmations,
                Self::externalized_receipt(dispatch)?,
                unknown_evidence_v1(&binding).map_err(|_| child_conflict_at_v25(1337))?,
                local.then_some(|| self.externalize(dispatch)),
            );
        };
        let view = self.validated_view(
            kind,
            action,
            dispatch.expected_transaction_id(),
            dispatch.custody_digest(),
            dispatch.intent_digest(),
        )?;
        // Bytes retained but never offered to any daemon cannot have crossed
        // the boundary: the stage moves to SendAttempted before first send.
        if view.stage == XmrTxStageV1::Signed {
            return Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                evidence_digest: proven_not_externalized_evidence_v1(&binding)
                    .map_err(|_| child_conflict_at_v25(1353))?,
            });
        }
        let now = self.clock.now_unix_ms()?;
        self.refresh_lease_v11(now)?;
        let locator = self.locator(kind);
        let clock = &mut self.clock;
        let mut after_observation = || {
            clock
                .now_unix_ms()
                .map_err(|_| XmrActuatorErrorV1::ObservationUnavailable)
        };
        let outcome = self
            .actuator
            .reconcile_takeover_with_clock_v23(
                &self.lease,
                locator,
                request.reconciliation_attempt_id,
                &mut self.observation,
                self.min_confirmations,
                now,
                &mut after_observation,
            )
            .map_err(map_actuator_error)?;
        match outcome.kind {
            // Txid absent with the sweep's own key image unspent: the
            // adjudicated Monero absence statement (CHILD_SOCKETS_DESIGN §5).
            // Point-in-time — the coordinator treats it exactly as it treats
            // the Bitcoin child's not-externalized proof.
            XmrReconciliationKindV1::KeyImageUnspentAbsent => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&binding)
                        .map_err(|_| child_conflict_at_v25(1385))?,
                })
            }
            XmrReconciliationKindV1::Observed | XmrReconciliationKindV1::Final => Ok(
                ChildReconciliationOutcomeV1::Externalized(Self::externalized_receipt(dispatch)?),
            ),
            XmrReconciliationKindV1::Unknown => Ok(ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| child_conflict_at_v25(1393))?,
            }),
        }
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.validate_common_bindings(
            request.face,
            request.action,
            request.exposure,
            request.settlement_id,
            request.terms_digest,
            request.registry_digest,
            request.profile_digest,
            request.deployment_digest,
            request.chain_id,
        )?;
        // Bound the whole observation before any branch takes its own exit.
        // A quorum answer fans out over several daemon calls, each with its
        // own transport timeout, so the unbounded form lasts their sum — long
        // enough for the DOM actuator lease held by the surrounding route step
        // to lapse mid-step. The funding branch below returns without reaching
        // the claim path, so the bound has to be set here, not beside the one
        // call that happens to be furthest down. A timed-out observation is
        // `Unavailable`, which the driver retries on the next round; it never
        // becomes a wrong answer.
        self.observation
            .set_observation_deadline_v26(observation_deadline_v26())
            .map_err(map_actuator_error)?;
        let action = request.action;
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        let Some(kind) = operation_for_action(action) else {
            self.validate_funding_request(
                request.transaction_id,
                request.custody_digest,
                request.intent_digest,
            )?;
            let min_confirmations = self.min_confirmations;
            let funding_tx_hash = self.setup.funding_tx_hash();
            return match self.funding_inclusion()? {
                Some(inclusion) if inclusion.confirmations >= min_confirmations => {
                    let facts = ChildFinalityFactsV1 {
                        final_evidence_digest: digest_parts(
                            FUNDING_EVIDENCE_DOMAIN_V1,
                            &[
                                funding_tx_hash.as_slice(),
                                &inclusion.height.to_be_bytes(),
                                inclusion.block_hash.as_slice(),
                                &inclusion.confirmations.to_be_bytes(),
                            ],
                        )?,
                        final_block_hash: inclusion.block_hash,
                        final_block_number: inclusion.height,
                    };
                    Ok(ChildObservationOutcomeV1::Final {
                        evidence_digest: observation_final_evidence_v1(&binding, &facts)
                            .map_err(|_| child_conflict_at_v25(1440))?,
                    })
                }
                observed => funding_loss_v23::pending_or_invalidated(
                    &binding,
                    request.prior_finality_evidence_digest,
                    funding_tx_hash,
                    min_confirmations,
                    observed,
                ),
            };
        };
        let view = self.validated_view(
            kind,
            action,
            request.transaction_id,
            request.custody_digest,
            request.intent_digest,
        )?;
        if !matches!(
            view.stage,
            XmrTxStageV1::SendAttempted
                | XmrTxStageV1::Observed
                | XmrTxStageV1::Final
                | XmrTxStageV1::FinalityInvalidated
        ) {
            return Err(child_conflict_at_v25(1466));
        }
        let now = self.clock.now_unix_ms()?;
        self.refresh_lease_v11(now)?;
        let locator = self.locator(kind);
        let clock = &mut self.clock;
        let mut after_observation = || {
            clock
                .now_unix_ms()
                .map_err(|_| XmrActuatorErrorV1::ObservationUnavailable)
        };
        let view = self
            .actuator
            .observe_current_with_clock_v23(
                &self.lease,
                locator,
                request.observation_attempt_id,
                &mut self.observation,
                self.min_confirmations,
                now,
                &mut after_observation,
            )
            .map_err(map_actuator_error)?;
        match view.stage {
            XmrTxStageV1::SendAttempted | XmrTxStageV1::Observed => {
                Ok(ChildObservationOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| child_conflict_at_v25(1493))?,
                })
            }
            XmrTxStageV1::Final => {
                let finality = view.finality.ok_or_else(|| child_conflict_at_v25(1497))?;
                let facts = ChildFinalityFactsV1 {
                    final_evidence_digest: finality.final_evidence_digest,
                    final_block_hash: finality.final_block_hash,
                    final_block_number: finality.final_height,
                };
                Ok(ChildObservationOutcomeV1::Final {
                    evidence_digest: observation_final_evidence_v1(&binding, &facts)
                        .map_err(|_| child_conflict_at_v25(1505))?,
                })
            }
            XmrTxStageV1::FinalityInvalidated => {
                let Some(prior) = request.prior_finality_evidence_digest else {
                    return Ok(ChildObservationOutcomeV1::Pending {
                        evidence_digest: observation_pending_evidence_v1(&binding)
                            .map_err(|_| child_conflict_at_v25(1512))?,
                    });
                };
                let invalidation = digest_parts(
                    INVALIDATION_DOMAIN_V1,
                    &[view.tx_hash.as_slice(), &view.revision.to_be_bytes()],
                )?;
                Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest: prior,
                    reorg_evidence_digest: observation_reorg_evidence_v1(
                        &binding,
                        prior,
                        invalidation,
                    )
                    .map_err(|_| child_conflict_at_v25(1526))?,
                })
            }
            _ => Err(child_conflict_at_v25(1529)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_guard_accounts_for_time_waiting_on_actuator_sql() {
        assert_eq!(
            fresh_live_materialization_time_v24(1000, 1099, 1100),
            Ok(1099)
        );
        for after_sql in [1100, 1101, u64::MAX] {
            assert_eq!(
                fresh_live_materialization_time_v24(1000, after_sql, 1100),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
        }
        assert_eq!(
            fresh_live_materialization_time_v24(1099, 1098, 1100),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn post_build_clock_rejects_regression_and_preserves_exact_boundary() {
        assert_eq!(
            fresh_materialization_time_v23(100, 99),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(
            fresh_materialization_time_v23(0, 100),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(
            fresh_materialization_time_v23(100, 0),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(fresh_materialization_time_v23(100, 100), Ok(100));
        assert_eq!(fresh_materialization_time_v23(100, 101), Ok(101));
        assert_eq!(
            fresh_materialization_time_v23(u64::MAX, u64::MAX),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn elapsed_sidecar_time_does_not_revive_or_publish_under_expired_lease(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let actuator = DurableXmrActuatorV1::new(xmr_actuator::XmrOperationStoreV1::open(
            directory.path().join("expired-build.sqlite"),
        )?);
        let lease = XmrActuatorLeaseV1::new([1; 32], [2; 32], [3; 32], 1, 1100)?;
        let original = lease;
        let locator = XmrOperationLocatorV1 {
            settlement_id: [4; 32],
            kind: XmrOperationKindV1::Claim,
        };
        // Deliberately invalid transaction input: the lease refusal must occur
        // before any byte can become custody; this does not fake a signed sweep.
        for after in [1100, 1101, u64::MAX] {
            let now = fresh_materialization_time_v23(1000, after)
                .map_err(|_| "unexpected clock refusal")?;
            assert!(matches!(
                actuator.prepare_signed(&lease, locator, [5; 32], [6; 32], &[], now),
                Err(XmrActuatorErrorV1::LeaseExpired)
            ));
            assert_eq!(lease, original);
            assert!(matches!(
                actuator.view(locator),
                Err(XmrActuatorErrorV1::NotFound)
            ));
        }
        Ok(())
    }

    #[test]
    fn funding_has_no_actuator_row_and_sweeps_map_one_to_one() {
        assert_eq!(operation_for_action(SettlementActionV1::Funding), None);
        assert_eq!(
            operation_for_action(SettlementActionV1::Claim),
            Some(XmrOperationKindV1::Claim)
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Refund),
            Some(XmrOperationKindV1::Refund)
        );
    }

    #[test]
    fn transaction_and_intent_identities_are_domain_separated_and_stable() {
        let first = transaction_id_v1([7; 32]).expect("transaction id");
        assert_eq!(first, transaction_id_v1([7; 32]).expect("replay"));
        assert_ne!(first, ZERO_DIGEST);
        assert_ne!(first, transaction_id_v1([8; 32]).expect("other"));
        let intent = intent_digest_v1([1; 32], SettlementActionV1::Claim, [2; 32]).expect("intent");
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Refund, [2; 32]).expect("other action")
        );
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Funding, [2; 32]).expect("funding")
        );
    }

    #[test]
    fn actuator_error_taxonomy_fails_closed() {
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::BroadcastRejected),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::ObservationUnavailable),
            ChildAuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::NotFound),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::Corrupt),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::LeaseExpired),
            ChildAuthorityRefusalV1::Conflict
        );
    }
}

// The current actuator's absence statement names one input key image. Never
// accept a sidecar-supplied image that does not come from those exact bytes,
// and never silently discard additional sweep inputs.
fn verify_single_sweep_image_v10(
    raw: &[u8],
    hash: Digest32,
    image: Digest32,
) -> Result<(), ChildAuthorityRefusalV1> {
    let verified =
        verify_exact_raw_sweep_v10(raw, hash).map_err(|_| child_conflict_at_v25(1673))?;
    if verified.key_images.as_slice() != &[image] {
        return Err(child_conflict_at_v25(1675));
    }
    Ok(())
}

// DIAG(temporary): names the source line of the child refusal that fired.
fn child_conflict_at_v25(line: u32) -> ChildAuthorityRefusalV1 {
    eprintln!("DOM_CHILD_CONFLICT_V25 file=production_child_xmr.rs line={line}");
    ChildAuthorityRefusalV1::Conflict
}
