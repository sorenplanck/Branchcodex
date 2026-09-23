//! Complete verification boundary for remotely constructed XMR sweeps.
//!
//! Canonical Relay framing never becomes signing or broadcast authority. The
//! exact response is released as an actuator-ready sweep only after the pinned
//! Mainnet funding bytes, input link, destination payout, amount commitments,
//! Bulletproof+, balance, CLSAG and all sixteen independently resolved ring
//! members have been checked.

use dom_scriptless_store::{AcceptedXmrRemoteSweepRequestV23, PreparedXmrRemoteSweepImportV23};
use route_composer::RouteScalar;
use settlement_coordinator::ChildAuthorityRefusalV1;
use xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar;
use xmr_raw_tx_verify::{
    destination_digest_v23, verify_exact_raw_sweep_bounded_v23, verify_sweep_payout_v23,
    InputSpendActionV23, InputSpendContextV23, InputSpendProofV23, TxKeyDerivationProofV23,
};
use xmr_remote_sweep_wire::{
    RemoteRingMemberV23, RemoteSweepActionV23, RemoteSweepLegV23, RemoteSweepRequestV23,
    RemoteSweepResponseInputV23, RemoteSweepResponseV23, RemoteTxKeyDerivationProofV23,
};
use xmr_setup_profile::ValidatedXmrSetup;

use crate::production_child_router::ProductionChildMaterializationRequestV1;
use crate::production_child_xmr::{
    ScopedXmrSweepAuthorityV1, XmrBuiltSweepV1, XmrExternalFundingFactsV1,
};
use crate::production_children::QuorumXmrObservationPortV1;

#[path = "production_xmr_remote_refund_v23.rs"]
mod remote_refund_v23;
pub(crate) use remote_refund_v23::{
    verify_local_refund_response_v24, AuthorizedLocalXmrRefundV24, ProductionXmrRefundResponderV24,
    ProductionXmrRemoteRefundClientV23, ProductionXmrRemoteRefundPinsV23,
    ProductionXmrRemoteRefundSourceV23, RefundPublicationProgressV24,
};

/// Wires disjoint Claim/Refund roles while preserving the one shared sweep
/// owner, the one physical actuator opening and local recovery independence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_native_xmr_action_faces_v24(
    sweep: crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
    pins: ProductionXmrRemoteClaimPinsV23,
    setup: ValidatedXmrSetup,
    source: ProductionXmrRemoteRefundSourceV23,
    actuator: std::rc::Rc<xmr_actuator::DurableXmrActuatorV1>,
    requester: Box<dyn ProductionXmrRemoteSweepTransportV23>,
    responder: Box<dyn ProductionXmrRemoteSweepResponderTransportV23>,
    quorum: QuorumXmrObservationPortV1,
    claim_receiver: bool,
) -> Result<
    (
        Box<dyn ScopedXmrSweepAuthorityV1>,
        Option<ProductionXmrRefundResponderV24>,
    ),
    ChildAuthorityRefusalV1,
> {
    let refund_pins = sweep.remote_refund_pins_v23(pins.clone())?;
    if claim_receiver {
        let refund = ProductionXmrRemoteRefundClientV23::new(
            refund_pins,
            setup.clone(),
            source,
            requester,
            quorum.clone(),
        )?;
        let claim = RemoteServingXmrSweepAuthorityV23::new(sweep, pins, setup, responder, quorum)?
            .with_remote_refund_v24(refund)?;
        Ok((Box::new(claim), None))
    } else {
        sweep.enable_local_refund_v24(pins.clone(), source.clone(), quorum.clone())?;
        let reader = crate::production_child_xmr::ProductionXmrRetainedRefundReaderV24::new(
            actuator,
            setup.clone(),
            pins.max_fee_piconero,
            (pins.adapter_max_raw_transaction_bytes as usize)
                .min(xmr_actuator::MAX_RAW_TX_BYTES_V1),
        )?;
        let refund = ProductionXmrRefundResponderV24::new(
            refund_pins,
            setup.clone(),
            source,
            reader,
            responder,
            quorum.clone(),
        )?;
        let claim = ProductionXmrRemoteClaimClientV23::new(pins, setup, requester, quorum)?;
        Ok((
            Box::new(RemoteClaimingXmrSweepAuthorityV23::new(
                Box::new(sweep),
                claim,
            )),
            Some(refund),
        ))
    }
}

/// Ratified Monero Mainnet genesis hash, in canonical RPC byte order.
pub(crate) const MONERO_MAINNET_GENESIS_V23: [u8; 32] = [
    0x41, 0x80, 0x15, 0xbb, 0x9a, 0xe9, 0x82, 0xa1, 0x97, 0x5d, 0xa7, 0xd7, 0x92, 0x77, 0xc2, 0x70,
    0x57, 0x27, 0xa5, 0x68, 0x94, 0xba, 0x0f, 0xb2, 0x46, 0xad, 0xaa, 0xbb, 0x1f, 0x46, 0x32, 0xe3,
];

/// Dedicated XMR request/response transport. An EVM payload or custody token
/// cannot implement this protocol accidentally.
pub(crate) trait ProductionXmrRemoteSweepTransportV23 {
    /// Resume an already durably accepted response or exchange one request.
    /// The implementation must use the request's exact canonical bytes as the
    /// authenticated Relay payload and retain request+response before return.
    fn exchange_or_resume_v23(
        &mut self,
        request: &[u8],
        request_wire_digest: [u8; 32],
    ) -> Result<PreparedXmrRemoteSweepImportV23, ChildAuthorityRefusalV1>;
}

/// Signer-side Store/Relay face. The accepted request is move-only and came
/// from the authenticated DSC1 transcript; this face still has no XMR key.
pub(crate) trait ProductionXmrRemoteSweepResponderTransportV23 {
    /// Resume an already staged response, or return the unique unanswered
    /// authenticated request addressed to this Store's local signer.
    fn poll_request_v23(
        &mut self,
    ) -> Result<ProductionXmrRemoteResponderPollV23, ChildAuthorityRefusalV1>;

    /// Persist, sign and stage the exact response only after the XMR actuator
    /// has durably retained the same transaction under its live fence.
    fn publish_response_v23(
        &mut self,
        accepted: &AcceptedXmrRemoteSweepRequestV23,
        response: &[u8],
    ) -> Result<(), ChildAuthorityRefusalV1>;

    /// Re-stage a response already present in the durable Store journal,
    /// requiring byte identity with the response retained by the actuator.
    fn reconcile_response_v23(&mut self, response: &[u8]) -> Result<(), ChildAuthorityRefusalV1>;

    /// Claim-only publication requires the real actuator's live-custody veto
    /// to reach the Store/Relay persistence boundaries, not only this caller.
    fn publish_claim_response_guarded_v24(
        &mut self,
        _accepted: &AcceptedXmrRemoteSweepRequestV23,
        _response: &[u8],
        _before_publication: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    /// Reconcile the same retained Claim bytes under the same final veto.
    fn reconcile_claim_response_guarded_v24(
        &mut self,
        _response: &[u8],
        _before_publication: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Conflict)
    }
}

/// Restart-safe responder discovery. `RetainedResponse` is Store-authenticated
/// public wire data and still carries no signing or broadcast authority.
pub(crate) enum ProductionXmrRemoteResponderPollV23 {
    NoRequest,
    Request(AcceptedXmrRemoteSweepRequestV23),
    RetainedResponse { request: Vec<u8>, response: Vec<u8> },
}

/// Require two request instances to describe the same durable economic event.
/// Only the F7 evidence digest may differ because it commits to observation
/// time/tip; all funding identity, inclusion and route facts remain exact.
pub(crate) fn require_stable_xmr_remote_request_retry_v23(
    retained: &RemoteSweepRequestV23,
    fresh: &RemoteSweepRequestV23,
) -> Result<(), ChildAuthorityRefusalV1> {
    if retained.funding_evidence_digest == [0; 32] || fresh.funding_evidence_digest == [0; 32] {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let mut normalized = fresh.clone();
    normalized.funding_evidence_digest = retained.funding_evidence_digest;
    if &normalized != retained {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

/// Pins obtained from the authenticated route, setup and public DOM evidence.
/// The remote peer cannot select any of these fields.
#[derive(Clone)]
pub(crate) struct ProductionXmrRemoteClaimPinsV23 {
    pub(crate) network_genesis: [u8; 32],
    pub(crate) route_id: [u8; 32],
    pub(crate) session_id: [u8; 32],
    /// Route-wide frozen bindings digest carried by materialization.
    pub(crate) route_terms_digest: [u8; 32],
    /// Exact native settlement terms hash bound by XMR setup/F7/proofs.
    pub(crate) terms_digest: [u8; 32],
    pub(crate) registry_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) deployment_digest: [u8; 32],
    pub(crate) route_scope_digest: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
    pub(crate) role_plan_digest: [u8; 32],
    pub(crate) source_scope_digest: [u8; 32],
    pub(crate) max_fee_piconero: u64,
    pub(crate) adapter_max_raw_transaction_bytes: u32,
    pub(crate) leg: settlement_coordinator::SettlementLegV1,
}

impl ProductionXmrRemoteClaimPinsV23 {
    fn validate(&self, setup: &ValidatedXmrSetup) -> Result<(), ChildAuthorityRefusalV1> {
        if self.network_genesis != MONERO_MAINNET_GENESIS_V23
            || [
                self.route_id,
                self.session_id,
                self.route_terms_digest,
                self.terms_digest,
                self.registry_digest,
                self.profile_digest,
                self.deployment_digest,
                self.route_scope_digest,
                self.composition_digest,
                self.role_plan_digest,
                self.source_scope_digest,
                setup.settlement_id(),
                setup.funding_tx_hash(),
            ]
            .contains(&[0; 32])
            || self.max_fee_piconero == 0
            || self.max_fee_piconero >= setup.expected_amount_piconero()
            || self.terms_digest != setup.terms_hash()
            || self.adapter_max_raw_transaction_bytes == 0
            || usize::try_from(self.adapter_max_raw_transaction_bytes)
                .map_or(true, |maximum| maximum > 512 * 1024)
            || !setup.destination().starts_with('4')
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn require_materialization(
        &self,
        setup: &ValidatedXmrSetup,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if request.action != settlement_coordinator::SettlementActionV1::Claim
            || request.exposure != settlement_coordinator::ChildExposureV1::UsesPublicSecret
            || request.public_secret_evidence_digest == [0; 32]
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.require_common_materialization(setup, request)
    }

    fn require_common_materialization(
        &self,
        setup: &ValidatedXmrSetup,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.validate(setup)?;
        if request.route_id != self.route_id
            || request.settlement_id != setup.settlement_id()
            || request.terms_digest != self.route_terms_digest
            || request.registry_digest != self.registry_digest
            || request.profile_digest != self.profile_digest
            || request.deployment_digest != self.deployment_digest
            || request.route_scope_digest != self.route_scope_digest
            || request.composition_digest != self.composition_digest
            || request.role_plan_digest != self.role_plan_digest
            || request.source_scope_digest != self.source_scope_digest
            || request.leg != self.leg
            || request.effect_id == [0; 32]
            || request.semantic_digest == [0; 32]
            || request.fencing_epoch == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

/// Build the local economic projection only from authenticated route material
/// and opaque, independently verified funding. Local effect identities never
/// replace the requester identities in the accepted request or sidecar cache.
fn local_claim_request_v24(
    pins: &ProductionXmrRemoteClaimPinsV23,
    setup: &ValidatedXmrSetup,
    materialization: &ProductionChildMaterializationRequestV1,
    scalar: &RouteScalar,
    funding: &f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
) -> Result<RemoteSweepRequestV23, ChildAuthorityRefusalV1> {
    pins.require_materialization(setup, materialization)?;
    let f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(funding_tx_hash) =
        *funding.funding_id()
    else {
        return Err(ChildAuthorityRefusalV1::Conflict);
    };
    if funding_tx_hash != setup.funding_tx_hash()
        || funding.setup_binding_hash() != &setup.binding_hash()
        || funding.facts().settlement_id() != &setup.settlement_id()
        || funding.facts().terms_hash() != &setup.terms_hash()
        || funding.evidence_digest() == &[0; 32]
        || funding.block_height() == 0
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let public_spend_share = revealed_dom_secret_to_xmr_scalar(*scalar.expose(), &setup.claim())
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let request = RemoteSweepRequestV23 {
        network_genesis: pins.network_genesis,
        route_id: pins.route_id,
        session_id: pins.session_id,
        settlement_id: setup.settlement_id(),
        terms_digest: pins.terms_digest,
        registry_digest: pins.registry_digest,
        profile_digest: pins.profile_digest,
        deployment_digest: pins.deployment_digest,
        route_scope_digest: pins.route_scope_digest,
        composition_digest: pins.composition_digest,
        role_plan_digest: pins.role_plan_digest,
        source_scope_digest: pins.source_scope_digest,
        effect_id: materialization.effect_id,
        semantic_digest: materialization.semantic_digest,
        public_secret_evidence_digest: materialization.public_secret_evidence_digest,
        funding_tx_hash,
        funding_evidence_digest: *funding.evidence_digest(),
        funding_output_index: u64::from(funding.output_index()),
        funding_block_height: funding.block_height(),
        funded_amount_piconero: setup.expected_amount_piconero(),
        max_fee_piconero: pins.max_fee_piconero,
        adapter_max_raw_transaction_bytes: pins.adapter_max_raw_transaction_bytes,
        max_raw_transaction_bytes: pins.adapter_max_raw_transaction_bytes.min(
            u32::try_from(xmr_remote_sweep_wire::MAX_RAW_SWEEP_BYTES_V23)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        ),
        fencing_epoch: materialization.fencing_epoch,
        action: RemoteSweepActionV23::Claim,
        leg: match materialization.leg {
            settlement_coordinator::SettlementLegV1::Upstream => RemoteSweepLegV23::Upstream,
            settlement_coordinator::SettlementLegV1::Downstream => RemoteSweepLegV23::Downstream,
        },
        public_spend_share,
        destination: setup.destination().to_owned(),
    };
    Ok(request)
}

/// Distinct actors have distinct journal effects and fencing epochs. This is
/// a cross-actor Claim check, NOT the strict same-actor retry/cache check.
/// All economics and public-secret bindings remain exact; the historical F7
/// evidence may differ only because the independently observed tip advanced.
fn require_shared_claim_economics_v24(
    requester: &RemoteSweepRequestV23,
    local: &RemoteSweepRequestV23,
) -> Result<(), ChildAuthorityRefusalV1> {
    if requester.action != RemoteSweepActionV23::Claim
        || local.action != RemoteSweepActionV23::Claim
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    requester
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    local
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let mut projected = local.clone();
    projected.effect_id = requester.effect_id;
    projected.fencing_epoch = requester.fencing_epoch;
    projected.semantic_digest = requester.semantic_digest;
    require_stable_xmr_remote_request_retry_v23(requester, &projected)
}

/// Move-only signer authorization assembled from an accepted DSC1 request,
/// the locally observed route scalar and a fresh signer-side F7 observation.
/// No constructor accepts request bytes without the Store token.
pub(crate) struct AuthenticatedRemoteSweepBuildV23<'scalar> {
    accepted: AcceptedXmrRemoteSweepRequestV23,
    request: RemoteSweepRequestV23,
    request_message_digest: [u8; 32],
    claim_scalar: &'scalar RouteScalar,
    funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
}

impl<'scalar> AuthenticatedRemoteSweepBuildV23<'scalar> {
    fn authenticate(
        accepted: AcceptedXmrRemoteSweepRequestV23,
        pins: &ProductionXmrRemoteClaimPinsV23,
        setup: &ValidatedXmrSetup,
        materialization: &ProductionChildMaterializationRequestV1,
        claim_scalar: &'scalar RouteScalar,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.require_materialization(setup, materialization)?;
        let request = RemoteSweepRequestV23::decode_exact(accepted.payload())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let canonical = request
            .encode()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let request_message_digest = *accepted.message_digest();
        if accepted.session_id() != &pins.session_id
            || accepted.payload() != canonical
            || request_message_digest == [0; 32]
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let local = local_claim_request_v24(pins, setup, materialization, claim_scalar, &funding)?;
        require_shared_claim_economics_v24(&request, &local)?;
        Ok(Self {
            accepted,
            request,
            request_message_digest,
            claim_scalar,
            funding,
        })
    }

    pub(crate) const fn request(&self) -> &RemoteSweepRequestV23 {
        &self.request
    }

    pub(crate) const fn request_message_digest(&self) -> [u8; 32] {
        self.request_message_digest
    }

    pub(crate) const fn claim_scalar(&self) -> Option<&RouteScalar> {
        Some(self.claim_scalar)
    }

    pub(crate) const fn funding(
        &self,
    ) -> &f7_anchor_authority::families_v11::VerifiedXmrFundingV11 {
        &self.funding
    }

    fn into_accepted(self) -> AcceptedXmrRemoteSweepRequestV23 {
        self.accepted
    }
}

/// Remote claim-only client. Refund, funding and observation remain on the
/// original locally scoped authority and are never widened by this wrapper.
pub(crate) struct ProductionXmrRemoteClaimClientV23 {
    pins: ProductionXmrRemoteClaimPinsV23,
    setup: ValidatedXmrSetup,
    transport: Box<dyn ProductionXmrRemoteSweepTransportV23>,
    quorum: QuorumXmrObservationPortV1,
}

impl ProductionXmrRemoteClaimClientV23 {
    pub(crate) fn new(
        pins: ProductionXmrRemoteClaimPinsV23,
        setup: ValidatedXmrSetup,
        transport: Box<dyn ProductionXmrRemoteSweepTransportV23>,
        quorum: QuorumXmrObservationPortV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.validate(&setup)?;
        Ok(Self {
            pins,
            setup,
            transport,
            quorum,
        })
    }

    fn build_claim(
        &mut self,
        materialization: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        let request =
            local_claim_request_v24(&self.pins, &self.setup, materialization, scalar, &funding)?;
        let request_bytes = request
            .encode()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let request_digest = request
            .digest()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let envelope = self
            .transport
            .exchange_or_resume_v23(&request_bytes, request_digest)?;
        let retained_request = RemoteSweepRequestV23::decode_exact(envelope.request_payload())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        require_stable_xmr_remote_request_retry_v23(&retained_request, &request)?;
        verify_remote_xmr_sweep_v23(&retained_request, envelope, &self.quorum)
            .map(VerifiedRemoteXmrSweepV23::into_built_sweep)
    }
}

/// Adds one remote claim path without changing the original local authority's
/// refund/funding/observation capabilities.
pub(crate) struct RemoteClaimingXmrSweepAuthorityV23 {
    local: Box<dyn ScopedXmrSweepAuthorityV1>,
    remote_claim: ProductionXmrRemoteClaimClientV23,
}

const fn requires_remote_claim_custody_v23(kind: xmr_actuator::XmrOperationKindV1) -> bool {
    matches!(kind, xmr_actuator::XmrOperationKindV1::Claim)
}

fn finish_remote_publish_v23<T>(
    pending: &mut Option<T>,
    result: Result<(), ChildAuthorityRefusalV1>,
) -> Result<(), ChildAuthorityRefusalV1> {
    result?;
    *pending = None;
    Ok(())
}

impl RemoteClaimingXmrSweepAuthorityV23 {
    pub(crate) fn new(
        local: Box<dyn ScopedXmrSweepAuthorityV1>,
        remote_claim: ProductionXmrRemoteClaimClientV23,
    ) -> Self {
        Self {
            local,
            remote_claim,
        }
    }
}

impl ScopedXmrSweepAuthorityV1 for RemoteClaimingXmrSweepAuthorityV23 {
    fn requires_remote_custody_v23(&self, kind: xmr_actuator::XmrOperationKindV1) -> bool {
        requires_remote_claim_custody_v23(kind)
    }

    fn observe_verified_funding_v22(
        &mut self,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, ChildAuthorityRefusalV1>
    {
        self.local.observe_verified_funding_v22()
    }

    fn broadcast_funding_v12(
        &mut self,
        recovery: &crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.local.broadcast_funding_v12(recovery, broadcast)
    }

    fn build_claim_sweep(
        &mut self,
        _request_nonce: [u8; 32],
        _scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        // A nonce-only call cannot authenticate route/deployment/fence/source.
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    fn build_claim_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        let funding = self.local.observe_verified_funding_v22()?;
        self.remote_claim.build_claim(request, scalar, funding)
    }

    fn build_refund_sweep(
        &mut self,
        request_nonce: [u8; 32],
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.local.build_refund_sweep(request_nonce)
    }

    fn build_refund_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.local.build_refund_sweep_v23(request)
    }

    fn verify_external_funding(
        &mut self,
        request_nonce: [u8; 32],
    ) -> Result<XmrExternalFundingFactsV1, ChildAuthorityRefusalV1> {
        self.local.verify_external_funding(request_nonce)
    }

    fn complete_claim_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        retained: &XmrBuiltSweepV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.local
            .complete_claim_sweep_v23(request, scalar, retained)
    }
}

struct PreparedRemoteSweepPublicationV23 {
    accepted: AcceptedXmrRemoteSweepRequestV23,
    response: Vec<u8>,
    built: XmrBuiltSweepV1,
    materialization: ProductionChildMaterializationRequestV1,
    public_spend_share: [u8; 32],
}

/// Claim-receiver side of the remote protocol. Construction can happen only
/// while the local materializer supplies the independently observed DOM
/// scalar; publication is deferred until the child has retained those exact
/// bytes under its finite actuator lease.
pub(crate) struct RemoteServingXmrSweepAuthorityV23 {
    local: crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
    pins: ProductionXmrRemoteClaimPinsV23,
    setup: ValidatedXmrSetup,
    transport: Box<dyn ProductionXmrRemoteSweepResponderTransportV23>,
    quorum: QuorumXmrObservationPortV1,
    pending: Option<PreparedRemoteSweepPublicationV23>,
    remote_refund_v24: Option<ProductionXmrRemoteRefundClientV23>,
}

impl RemoteServingXmrSweepAuthorityV23 {
    pub(crate) fn new(
        local: crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
        pins: ProductionXmrRemoteClaimPinsV23,
        setup: ValidatedXmrSetup,
        transport: Box<dyn ProductionXmrRemoteSweepResponderTransportV23>,
        quorum: QuorumXmrObservationPortV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.validate(&setup)?;
        Ok(Self {
            local,
            pins,
            setup,
            transport,
            quorum,
            pending: None,
            remote_refund_v24: None,
        })
    }

    pub(crate) fn with_remote_refund_v24(
        mut self,
        refund: ProductionXmrRemoteRefundClientV23,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if self.remote_refund_v24.is_some() {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.remote_refund_v24 = Some(refund);
        Ok(self)
    }

    fn clone_built(built: &XmrBuiltSweepV1) -> XmrBuiltSweepV1 {
        XmrBuiltSweepV1 {
            tx_hash: built.tx_hash,
            key_image: built.key_image,
            raw_transaction: built.raw_transaction.clone(),
            remote_custody_v23: built.remote_custody_v23,
        }
    }

    fn require_pending_retry(
        &self,
        pending: &PreparedRemoteSweepPublicationV23,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.pins.require_materialization(&self.setup, request)?;
        let public_spend_share =
            revealed_dom_secret_to_xmr_scalar(*scalar.expose(), &self.setup.claim())
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if pending.materialization != *request || pending.public_spend_share != public_spend_share {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
    ) -> Result<Option<XmrBuiltSweepV1>, ChildAuthorityRefusalV1> {
        if let Some(pending) = self.pending.as_ref() {
            self.require_pending_retry(pending, request, scalar)?;
            return Ok(Some(Self::clone_built(&pending.built)));
        }
        let accepted = match self.transport.poll_request_v23()? {
            ProductionXmrRemoteResponderPollV23::NoRequest => return Ok(None),
            ProductionXmrRemoteResponderPollV23::Request(accepted) => accepted,
            ProductionXmrRemoteResponderPollV23::RetainedResponse {
                request: _,
                response: _,
            } => return Err(ChildAuthorityRefusalV1::Conflict),
        };
        self.prepare_accepted(request, scalar, accepted).map(Some)
    }

    fn prepare_accepted(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        accepted: AcceptedXmrRemoteSweepRequestV23,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        // The funding token is minted from this signer's own scanner/quorum;
        // the request's height/evidence are only claims until this comparison.
        let funding = self.local.observe_verified_funding_v22()?;
        let authorized = AuthenticatedRemoteSweepBuildV23::authenticate(
            accepted,
            &self.pins,
            &self.setup,
            request,
            scalar,
            funding,
        )?;
        let built_response = self
            .local
            .build_authenticated_remote_sweep_v23(&authorized)?;
        let signer_funding_evidence_digest = *authorized.funding().evidence_digest();
        let (response, built) = response_from_sidecar_v23(
            authorized.request(),
            authorized.request_message_digest(),
            signer_funding_evidence_digest,
            built_response,
            &self.quorum,
        )?;
        let returned = Self::clone_built(&built);
        let public_spend_share = authorized.request().public_spend_share;
        self.pending = Some(PreparedRemoteSweepPublicationV23 {
            accepted: authorized.into_accepted(),
            response,
            built,
            materialization: *request,
            public_spend_share,
        });
        Ok(returned)
    }

    fn reconcile_retained_response(
        &mut self,
        materialization: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        request_bytes: &[u8],
        response_bytes: &[u8],
        retained: &XmrBuiltSweepV1,
        before_publish: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.pins
            .require_materialization(&self.setup, materialization)?;
        let request = RemoteSweepRequestV23::decode_exact(request_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let funding = self.local.observe_verified_funding_v22()?;
        let local =
            local_claim_request_v24(&self.pins, &self.setup, materialization, scalar, &funding)?;
        require_shared_claim_economics_v24(&request, &local)?;
        let response = RemoteSweepResponseV23::decode_exact(response_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        response
            .validate_for_authenticated_request(&request, response.request_message_digest())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if response.transaction_hash() != retained.tx_hash
            || response.key_image() != retained.key_image
            || response.raw_transaction() != retained.raw_transaction.as_slice()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        with_claim_publication_guard_v24(before_publish, || Ok(()))?;
        self.transport
            .reconcile_claim_response_guarded_v24(response_bytes, before_publish)
    }
}

impl ScopedXmrSweepAuthorityV1 for RemoteServingXmrSweepAuthorityV23 {
    fn requires_remote_custody_v23(&self, kind: xmr_actuator::XmrOperationKindV1) -> bool {
        kind == xmr_actuator::XmrOperationKindV1::Refund && self.remote_refund_v24.is_some()
    }
    fn observe_verified_funding_v22(
        &mut self,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, ChildAuthorityRefusalV1>
    {
        self.local.observe_verified_funding_v22()
    }

    fn broadcast_funding_v12(
        &mut self,
        recovery: &crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.local.broadcast_funding_v12(recovery, broadcast)
    }

    fn build_claim_sweep(
        &mut self,
        _request_nonce: [u8; 32],
        _scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    fn build_claim_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.prepare(request, scalar)?
            .ok_or(ChildAuthorityRefusalV1::Unavailable)
    }

    fn build_refund_sweep(
        &mut self,
        request_nonce: [u8; 32],
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        self.local.build_refund_sweep(request_nonce)
    }

    fn build_refund_sweep_v23(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        if let Some(refund) = self.remote_refund_v24.as_mut() {
            let funding = self.local.observe_verified_funding_v22()?;
            return refund.build_refund(request, funding);
        }
        self.local.build_refund_sweep_v23(request)
    }

    fn verify_external_funding(
        &mut self,
        request_nonce: [u8; 32],
    ) -> Result<XmrExternalFundingFactsV1, ChildAuthorityRefusalV1> {
        self.local.verify_external_funding(request_nonce)
    }

    fn complete_claim_sweep_v23(
        &mut self,
        _request: &ProductionChildMaterializationRequestV1,
        _scalar: &RouteScalar,
        _retained: &XmrBuiltSweepV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        // A caller without the real actuator's post-observation guard cannot
        // publish, including after restart with an already signed response.
        Err(ChildAuthorityRefusalV1::Conflict)
    }

    fn complete_claim_sweep_guarded_v24(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &RouteScalar,
        retained: &XmrBuiltSweepV1,
        before_publish: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.pins.require_materialization(&self.setup, request)?;
        if self.pending.is_none() {
            match self.transport.poll_request_v23()? {
                ProductionXmrRemoteResponderPollV23::NoRequest => {
                    return Err(ChildAuthorityRefusalV1::Unavailable)
                }
                ProductionXmrRemoteResponderPollV23::Request(accepted) => {
                    let _ = self.prepare_accepted(request, scalar, accepted)?;
                }
                ProductionXmrRemoteResponderPollV23::RetainedResponse {
                    request: retained_request,
                    response,
                } => {
                    return self.reconcile_retained_response(
                        request,
                        scalar,
                        &retained_request,
                        &response,
                        retained,
                        before_publish,
                    )
                }
            }
        }
        let fresh_funding = self.local.observe_verified_funding_v22()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(ChildAuthorityRefusalV1::Conflict)?;
        self.require_pending_retry(pending, request, scalar)?;
        let retained_request = RemoteSweepRequestV23::decode_exact(pending.accepted.payload())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(funding_tx_hash) =
            *fresh_funding.funding_id()
        else {
            return Err(ChildAuthorityRefusalV1::Conflict);
        };
        if pending.built.tx_hash != retained.tx_hash
            || pending.built.key_image != retained.key_image
            || pending.built.raw_transaction != retained.raw_transaction
            || funding_tx_hash != retained_request.funding_tx_hash
            || fresh_funding.output_index()
                != u32::try_from(retained_request.funding_output_index)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
            || fresh_funding.block_height() != retained_request.funding_block_height
            || fresh_funding.setup_binding_hash() != &self.setup.binding_hash()
            || fresh_funding.facts().settlement_id() != &self.setup.settlement_id()
            || fresh_funding.facts().terms_hash() != &self.setup.terms_hash()
            || fresh_funding.evidence_digest() == &[0; 32]
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        // Store re-reads the live session phase here. The child invokes this
        // hook only after fresh-time lease validation and durable retention.
        with_claim_publication_guard_v24(before_publish, || Ok(()))?;
        let publish_result = self.transport.publish_claim_response_guarded_v24(
            &pending.accepted,
            &pending.response,
            before_publish,
        );
        finish_remote_publish_v23(&mut self.pending, publish_result)
    }
}

fn with_claim_publication_guard_v24<T>(
    before_publish: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    publish: impl FnOnce() -> Result<T, ChildAuthorityRefusalV1>,
) -> Result<T, ChildAuthorityRefusalV1> {
    before_publish()?;
    publish()
}

fn response_from_sidecar_v23(
    request: &RemoteSweepRequestV23,
    request_message_digest: [u8; 32],
    signer_funding_evidence_digest: [u8; 32],
    response: xmr_live_sidecar_api::BuildSweepResponseV23<
        xmr_live_sidecar_api::BuildSweepResponseV2,
    >,
    quorum: &QuorumXmrObservationPortV1,
) -> Result<(Vec<u8>, XmrBuiltSweepV1), ChildAuthorityRefusalV1> {
    let context = response
        .validate_framing()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    if signer_funding_evidence_digest == [0; 32]
        || response.authorization_digest
            != request
                .digest()
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
        || response.request_message_digest != request_message_digest
        || context.network_genesis != request.network_genesis
        || context.route != request.route_id
        || context.session != request.session_id
        || context.terms != request.terms_digest
        || context.funding_tx != request.funding_tx_hash
        || context.output_index != request.funding_output_index
        || context.sweep_tx != response.sweep.tx_hash
        || context.destination != destination_digest_v23(&request.destination)
        || context.funded_amount != request.funded_amount_piconero
        || context.fee == 0
        || context.fee > request.max_fee_piconero
        || context.action != InputSpendActionV23::Claim
        || response.sweep.request_nonce != request.effect_id
        || response.sweep.raw_tx.len()
            > usize::try_from(request.max_raw_transaction_bytes)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let verified_raw = verify_exact_raw_sweep_bounded_v23(
        &response.sweep.raw_tx,
        response.sweep.tx_hash,
        request.funded_amount_piconero,
        request.max_fee_piconero,
    )
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let [key_image] = verified_raw.sweep().key_images.as_slice() else {
        return Err(ChildAuthorityRefusalV1::Conflict);
    };
    let input_spend_proof: [u8; 96] = response
        .input_proof
        .as_slice()
        .try_into()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let payout_proofs = response
        .tx_key_proofs
        .iter()
        .map(|proof| RemoteTxKeyDerivationProofV23::decode(proof))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let ring_members = response
        .ring_members
        .iter()
        .map(|member| RemoteRingMemberV23 {
            global_index: member.global_index,
            key: member.key,
            commitment: member.commitment,
        })
        .collect();
    let wire = RemoteSweepResponseV23::new(RemoteSweepResponseInputV23 {
        request_digest: response.authorization_digest,
        request_message_digest,
        signer_funding_evidence_digest,
        network_genesis: request.network_genesis,
        route_id: request.route_id,
        session_id: request.session_id,
        settlement_id: request.settlement_id,
        terms_digest: request.terms_digest,
        registry_digest: request.registry_digest,
        profile_digest: request.profile_digest,
        deployment_digest: request.deployment_digest,
        effect_id: request.effect_id,
        semantic_digest: request.semantic_digest,
        transaction_hash: response.sweep.tx_hash,
        key_image: *key_image,
        funded_amount_piconero: request.funded_amount_piconero,
        fee_piconero: context.fee,
        fencing_epoch: request.fencing_epoch,
        action: request.action,
        leg: request.leg,
        raw_transaction: response.sweep.raw_tx,
        input_spend_proof,
        payout_proofs,
        ring_members,
    })
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    wire.validate_for_authenticated_request(request, request_message_digest)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let (verified_tx_hash, verified_key_image, verified_raw) =
        verify_remote_response_cryptography_v23(request, &wire, quorum)?;
    if verified_tx_hash != response.sweep.tx_hash || verified_key_image != *key_image {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let built = XmrBuiltSweepV1 {
        tx_hash: verified_tx_hash,
        key_image: verified_key_image,
        raw_transaction: verified_raw,
        remote_custody_v23: None,
    };
    let encoded = wire
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    Ok((encoded, built))
}

/// Move-only output of the complete remote verification boundary.
pub(crate) struct VerifiedRemoteXmrSweepV23 {
    request_wire_digest: [u8; 32],
    response_wire_digest: [u8; 32],
    request_message_digest: [u8; 32],
    response_message_digest: [u8; 32],
    tx_hash: [u8; 32],
    key_image: [u8; 32],
    raw_transaction: Vec<u8>,
    custody: xmr_actuator::XmrRemoteCustodyDigestsV23,
}

impl core::fmt::Debug for VerifiedRemoteXmrSweepV23 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedRemoteXmrSweepV23")
            .field("request_wire_digest", &self.request_wire_digest)
            .field("response_wire_digest", &self.response_wire_digest)
            .field("tx_hash", &self.tx_hash)
            .field("key_image", &self.key_image)
            .field("raw_transaction", &"[verified exact bytes]")
            .finish()
    }
}

impl VerifiedRemoteXmrSweepV23 {
    pub(crate) fn into_built_sweep(self) -> XmrBuiltSweepV1 {
        XmrBuiltSweepV1 {
            tx_hash: self.tx_hash,
            key_image: self.key_image,
            raw_transaction: self.raw_transaction,
            remote_custody_v23: Some(self.custody),
        }
    }

    pub(crate) const fn custody_digests(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        (
            self.request_wire_digest,
            self.response_wire_digest,
            self.request_message_digest,
            self.response_message_digest,
        )
    }
}

/// Verify the complete Monero transaction and its independently authenticated
/// inputs. This shared boundary is used by both the requester import and the
/// signer before it is allowed to retain/publish its own sidecar result.
fn verify_remote_response_cryptography_v23(
    request: &RemoteSweepRequestV23,
    response: &RemoteSweepResponseV23,
    quorum: &QuorumXmrObservationPortV1,
) -> Result<([u8; 32], [u8; 32], Vec<u8>), ChildAuthorityRefusalV1> {
    // One aggregate ceiling for both quorum reads: sixteen ring members and
    // the funding bytes are several daemon round-trips each, and their sum is
    // what has to stay inside the lease the route step is holding.
    let deadline = super::production_child_xmr::observation_deadline_v26();
    let funding_raw = quorum
        .authenticated_funding_raw_with_deadline_v24(request.funding_tx_hash, deadline)
        .map_err(super::production_child_xmr::map_actuator_error)?;
    let ring_members = quorum
        .authenticate_remote_ring_with_deadline_v24(response.ring_members(), deadline)
        .map_err(super::production_child_xmr::map_actuator_error)?;
    let input_proof = InputSpendProofV23::decode(response.input_spend_proof())
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let tx_key_proofs = response
        .payout_proofs()
        .iter()
        .map(|proof| TxKeyDerivationProofV23::decode(proof.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let context = InputSpendContextV23 {
        network_genesis: request.network_genesis,
        route: request.route_id,
        session: request.session_id,
        terms: request.terms_digest,
        funding_tx: request.funding_tx_hash,
        output_index: request.funding_output_index,
        sweep_tx: response.transaction_hash(),
        destination: destination_digest_v23(&request.destination),
        funded_amount: request.funded_amount_piconero,
        fee: response.fee_piconero(),
        action: match request.action {
            RemoteSweepActionV23::Claim => InputSpendActionV23::Claim,
            RemoteSweepActionV23::Refund => InputSpendActionV23::Refund,
        },
    };
    let mut rng = rand::rngs::OsRng;
    let verified = verify_sweep_payout_v23(
        &context,
        &funding_raw,
        response.raw_transaction(),
        &request.destination,
        request.max_fee_piconero,
        &input_proof,
        &tx_key_proofs,
        &ring_members,
        &mut rng,
    )
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let expected_amount = request
        .funded_amount_piconero
        .checked_sub(response.fee_piconero())
        .ok_or(ChildAuthorityRefusalV1::Conflict)?;
    if verified.input().context() != &context
        || verified.input().key_image() != response.key_image()
        || verified.amount() != expected_amount
        || verified.ring_members() != ring_members.as_slice()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok((
        response.transaction_hash(),
        response.key_image(),
        response.raw_transaction().to_vec(),
    ))
}

/// Authenticate and verify one remote response completely before moving raw
/// bytes into a value that the XMR actuator can retain.
pub(crate) fn verify_remote_xmr_sweep_v23(
    request: &RemoteSweepRequestV23,
    prepared: PreparedXmrRemoteSweepImportV23,
    quorum: &QuorumXmrObservationPortV1,
) -> Result<VerifiedRemoteXmrSweepV23, ChildAuthorityRefusalV1> {
    if request.network_genesis != MONERO_MAINNET_GENESIS_V23 {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let request_wire_digest = request
        .digest()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let canonical_request = request
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let request_message_digest = *prepared.request_message_digest();
    let response_message_digest = *prepared.response_message_digest();
    let retained_response_wire_digest = *prepared.response_wire_digest();
    let retained_transaction_hash = *prepared.transaction_hash();
    let retained_key_image = *prepared.key_image();
    if prepared.session_id() != &request.session_id
        || prepared.request_payload() != canonical_request
        || request_message_digest == [0; 32]
        || response_message_digest == [0; 32]
        || request_message_digest == response_message_digest
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let (retained_request, response_bytes) = prepared.into_payloads();
    if retained_request != canonical_request {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let response = RemoteSweepResponseV23::decode_exact(&response_bytes)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    response
        .validate_for_authenticated_request(request, request_message_digest)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    if response
        .digest()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
        != retained_response_wire_digest
        || response.transaction_hash() != retained_transaction_hash
        || response.key_image() != retained_key_image
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }

    let (verified_tx_hash, verified_key_image, raw_transaction) =
        verify_remote_response_cryptography_v23(request, &response, quorum)?;
    let response_wire_digest = retained_response_wire_digest;
    let tx_hash = response.transaction_hash();
    let key_image = response.key_image();
    if verified_tx_hash != tx_hash || verified_key_image != key_image {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let custody = xmr_actuator::XmrRemoteCustodyDigestsV23::new(
        request_wire_digest,
        response_wire_digest,
        request_message_digest,
        response_message_digest,
    )
    .map_err(super::production_child_xmr::map_actuator_error)?;
    Ok(VerifiedRemoteXmrSweepV23 {
        request_wire_digest,
        response_wire_digest,
        request_message_digest,
        response_message_digest,
        tx_hash,
        key_image,
        raw_transaction,
        custody,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn request() -> RemoteSweepRequestV23 {
        RemoteSweepRequestV23 {
            network_genesis: [1; 32],
            route_id: [2; 32],
            session_id: [3; 32],
            settlement_id: [4; 32],
            terms_digest: [5; 32],
            registry_digest: [6; 32],
            profile_digest: [7; 32],
            deployment_digest: [8; 32],
            route_scope_digest: [9; 32],
            composition_digest: [10; 32],
            role_plan_digest: [11; 32],
            source_scope_digest: [12; 32],
            effect_id: [13; 32],
            semantic_digest: [14; 32],
            public_secret_evidence_digest: [15; 32],
            funding_tx_hash: [16; 32],
            funding_evidence_digest: [17; 32],
            funding_output_index: 1,
            funding_block_height: 2,
            funded_amount_piconero: 10_000,
            max_fee_piconero: 100,
            adapter_max_raw_transaction_bytes: 512 * 1024,
            max_raw_transaction_bytes: 128 * 1024,
            fencing_epoch: 3,
            action: RemoteSweepActionV23::Claim,
            leg: RemoteSweepLegV23::Downstream,
            public_spend_share: [18; 32],
            destination: "48productionMainnetDestination".to_owned(),
        }
    }

    #[test]
    fn local_refund_cache_keeps_original_effect_but_not_observation_tip_v24() {
        use super::remote_refund_v23::local_refund_authorization_digest_v24 as digest;
        let mut original = request();
        original.action = RemoteSweepActionV23::Refund;
        let expected = digest(&original, [40; 32], [41; 32]).unwrap();
        let mut refreshed = original.clone();
        refreshed.funding_evidence_digest = [42; 32];
        assert_eq!(expected, digest(&refreshed, [40; 32], [41; 32]).unwrap());
        // A new lease cannot select the old signature cache after reopening.
        for field in 0..10 {
            let mut changed = refreshed.clone();
            match field {
                0 => changed.effect_id[0] ^= 1,
                1 => changed.fencing_epoch += 1,
                2 => changed.semantic_digest[0] ^= 1,
                3 => changed.funding_block_height += 1,
                4 => changed.funding_output_index += 1,
                5 => changed.destination.push('1'),
                6 => changed.max_fee_piconero += 1,
                7 => changed.funded_amount_piconero += 1,
                8 => changed.public_secret_evidence_digest[0] ^= 1,
                9 => changed.source_scope_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_ne!(expected, digest(&changed, [40; 32], [41; 32]).unwrap());
        }
        assert_ne!(expected, digest(&refreshed, [43; 32], [41; 32]).unwrap());
        assert_ne!(expected, digest(&refreshed, [40; 32], [43; 32]).unwrap());
        refreshed.action = RemoteSweepActionV23::Claim;
        assert_eq!(
            digest(&refreshed, [40; 32], [41; 32]),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        refreshed.action = RemoteSweepActionV23::Refund;
        refreshed.funding_evidence_digest = [0; 32];
        assert!(digest(&refreshed, [40; 32], [41; 32]).is_err());
    }

    #[test]
    fn claim_cross_actor_identity_differs_without_changing_request_or_local_retry() {
        let requester = request();
        let requester_bytes = requester.encode().unwrap();
        for field in 0..4 {
            let mut local = requester.clone();
            if field == 0 || field == 3 {
                local.effect_id = [41; 32];
            }
            if field == 1 || field == 3 {
                local.fencing_epoch += 1;
            }
            if field == 2 || field == 3 {
                local.semantic_digest = [42; 32];
            }
            local.funding_evidence_digest = [43; 32];
            let original_local = local.encode().unwrap();
            assert_eq!(
                require_shared_claim_economics_v24(&requester, &local),
                Ok(())
            );
            // The accepted requester/cache identity is never rewritten. Nor
            // can this cross-actor projection authorize a same-actor retry.
            assert_eq!(requester.encode().unwrap(), requester_bytes);
            assert_eq!(local.encode().unwrap(), original_local);
            assert_eq!(
                require_stable_xmr_remote_request_retry_v23(&requester, &local),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
        }
    }

    #[test]
    fn claim_cross_actor_projection_rejects_each_changed_economic_binding() {
        let requester = request();
        for field in 0..24 {
            let mut local = requester.clone();
            local.effect_id = [41; 32];
            local.fencing_epoch += 1;
            local.semantic_digest = [42; 32];
            local.funding_evidence_digest = [43; 32];
            match field {
                0 => local.network_genesis[0] ^= 1,
                1 => local.route_id[0] ^= 1,
                2 => local.session_id[0] ^= 1,
                3 => local.settlement_id[0] ^= 1,
                4 => local.terms_digest[0] ^= 1,
                5 => local.registry_digest[0] ^= 1,
                6 => local.profile_digest[0] ^= 1,
                7 => local.deployment_digest[0] ^= 1,
                8 => local.route_scope_digest[0] ^= 1,
                9 => local.composition_digest[0] ^= 1,
                10 => local.role_plan_digest[0] ^= 1,
                11 => local.source_scope_digest[0] ^= 1,
                12 => local.public_secret_evidence_digest[0] ^= 1,
                13 => local.funding_tx_hash[0] ^= 1,
                14 => local.funding_output_index += 1,
                15 => local.funding_block_height += 1,
                16 => local.funded_amount_piconero += 1,
                17 => local.max_fee_piconero += 1,
                18 => local.adapter_max_raw_transaction_bytes -= 1,
                19 => local.max_raw_transaction_bytes -= 1,
                20 => local.action = RemoteSweepActionV23::Refund,
                21 => local.leg = RemoteSweepLegV23::Upstream,
                22 => local.public_spend_share[0] ^= 1,
                23 => local.destination.push('x'),
                _ => unreachable!(),
            }
            assert_eq!(
                require_shared_claim_economics_v24(&requester, &local),
                Err(ChildAuthorityRefusalV1::Conflict),
                "economic field {field}"
            );
        }
    }

    #[test]
    fn claim_projection_requires_canonical_identities_and_never_admits_refund() {
        let request = request();
        for field in 0..4 {
            let mut malformed = request.clone();
            match field {
                0 => malformed.effect_id = [0; 32],
                1 => malformed.semantic_digest = [0; 32],
                2 => malformed.fencing_epoch = 0,
                3 => malformed.funding_evidence_digest = [0; 32],
                _ => unreachable!(),
            }
            assert!(require_shared_claim_economics_v24(&request, &malformed).is_err());
            assert!(require_shared_claim_economics_v24(&malformed, &request).is_err());
        }
        let mut refund = request;
        refund.action = RemoteSweepActionV23::Refund;
        assert!(require_shared_claim_economics_v24(&refund, &refund).is_err());
    }

    #[test]
    fn claim_observation_expiring_real_lease_never_publishes_or_reconciles(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::cell::Cell;
        use xmr_actuator::{
            DurableXmrActuatorV1, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrOperationKindV1,
            XmrOperationLocatorV1, XmrOperationStoreV1,
        };
        let directory = tempfile::tempdir()?;
        let actuator = DurableXmrActuatorV1::new(XmrOperationStoreV1::open(
            directory.path().join("claim-publication-lease.sqlite"),
        )?);
        let lease = XmrActuatorLeaseV1::new([1; 32], [2; 32], [3; 32], 1, 1100)?;
        let locator = XmrOperationLocatorV1 {
            settlement_id: [4; 32],
            kind: XmrOperationKindV1::Claim,
        };
        // A Store/lease boundary fixture, not a cryptographic sweep fixture:
        // these bytes never reach a signer, peer or broadcast port.
        let retained = actuator.prepare_signed(&lease, locator, [5; 32], [6; 32], &[7, 8], 1000)?;
        let now = Cell::new(1000);
        let publications = Cell::new(0);
        let mut guard = || {
            let view = actuator
                .checked_view_v23(&lease, locator, now.get())
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
            if view != retained {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
            Ok(())
        };
        assert_eq!(guard(), Ok(()));
        // The observation starts with a live lease and ends EXACTLY at its
        // boundary. Both fresh publish and retained reconcile use this gate.
        now.set(1100);
        assert!(matches!(
            actuator.checked_view_v23(&lease, locator, now.get()),
            Err(XmrActuatorErrorV1::LeaseExpired)
        ));
        let mut pending = Some(vec![9, 10]);
        for _ in 0..2 {
            let result = with_claim_publication_guard_v24(&mut guard, || {
                publications.set(publications.get() + 1);
                Ok(())
            });
            assert_eq!(
                finish_remote_publish_v23(&mut pending, result),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
            assert_eq!(pending, Some(vec![9, 10]));
            assert_eq!(publications.get(), 0);
            assert_eq!(actuator.view(locator)?, retained);
        }
        Ok(())
    }

    #[test]
    fn claim_publication_guard_runs_before_handoff_and_propagates_owner_refusal() {
        use std::cell::Cell;
        let guarded = Cell::new(false);
        assert_eq!(
            with_claim_publication_guard_v24(
                &mut || {
                    guarded.set(true);
                    Ok(())
                },
                || {
                    assert!(guarded.get());
                    Ok(())
                }
            ),
            Ok(())
        );
        for error in [
            ChildAuthorityRefusalV1::Conflict,
            ChildAuthorityRefusalV1::Unavailable,
        ] {
            assert_eq!(
                with_claim_publication_guard_v24(&mut || Err(error), || {
                    panic!("failed fence/owner check must not hand off a response")
                }),
                Err::<(), _>(error)
            );
        }
    }

    #[test]
    fn requester_restart_reuses_request_when_only_temporal_f7_digest_changes() {
        let retained = request();
        let mut fresh = retained.clone();
        fresh.funding_evidence_digest = [19; 32];
        assert_eq!(
            require_stable_xmr_remote_request_retry_v23(&retained, &fresh),
            Ok(())
        );
        fresh.funding_block_height += 1;
        assert_eq!(
            require_stable_xmr_remote_request_retry_v23(&retained, &fresh),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn retry_never_accepts_zero_or_changed_economic_request() {
        let retained = request();
        let mut fresh = retained.clone();
        fresh.funding_evidence_digest = [0; 32];
        assert_eq!(
            require_stable_xmr_remote_request_retry_v23(&retained, &fresh),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        fresh.funding_evidence_digest = [19; 32];
        fresh.destination.push('x');
        assert_eq!(
            require_stable_xmr_remote_request_retry_v23(&retained, &fresh),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn local_refund_never_requires_a_remote_claim_marker() {
        assert!(requires_remote_claim_custody_v23(
            xmr_actuator::XmrOperationKindV1::Claim
        ));
        assert!(!requires_remote_claim_custody_v23(
            xmr_actuator::XmrOperationKindV1::Refund
        ));
    }

    #[test]
    fn transient_publish_error_keeps_the_exact_pending_response() {
        let mut pending = Some(vec![1_u8, 2, 3]);
        assert_eq!(
            finish_remote_publish_v23(&mut pending, Err(ChildAuthorityRefusalV1::Unavailable)),
            Err(ChildAuthorityRefusalV1::Unavailable)
        );
        assert_eq!(pending.as_deref(), Some([1_u8, 2, 3].as_slice()));
        assert_eq!(finish_remote_publish_v23(&mut pending, Ok(())), Ok(()));
        assert!(pending.is_none());
    }

    #[test]
    fn retry_between_build_and_retain_reissues_identical_sweep_bytes() {
        let built = XmrBuiltSweepV1 {
            tx_hash: [21; 32],
            key_image: [22; 32],
            raw_transaction: vec![1, 3, 3, 7],
            remote_custody_v23: None,
        };
        let retried = RemoteServingXmrSweepAuthorityV23::clone_built(&built);
        assert_eq!(retried.tx_hash, built.tx_hash);
        assert_eq!(retried.key_image, built.key_image);
        assert_eq!(retried.raw_transaction, built.raw_transaction);
        assert!(retried.remote_custody_v23.is_none());
    }
}
