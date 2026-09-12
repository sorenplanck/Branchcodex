//! Remote refund is a separate capability from remote Claim. Discovery is an
//! authenticated, durably paired DSC1 response, NOT a key-image spent flag.
//! Losing the proof envelope before retention cannot be repaired by a chain
//! scan alone: ring anonymity and hidden payout amounts make that unsound.
use super::*;
use crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12;
use crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23;
use adapter_dom_real::VerifiedDomRefundSecretV11;
use std::{
    rc::Rc,
    time::{Duration, Instant},
};
use xmr_dleq_sigma::CrossCurvePublicClaim;

/// Read-only pins projected from the already authenticated local SweepBinding.
/// No value here is a secret or a constructor for a chain/signing permission.
#[derive(Clone)]
pub(crate) struct ProductionXmrRemoteRefundPinsV23 {
    pub(crate) common: ProductionXmrRemoteClaimPinsV23,
    pub(crate) dom_chain: [u8; 32],
    pub(crate) refund_template: [u8; 32],
    pub(crate) refund_claim: CrossCurvePublicClaim,
    pub(crate) refund_destination: String,
    pub(crate) funding_min_confirmations: u64,
}
impl ProductionXmrRemoteRefundPinsV23 {
    fn require_materialization(
        &self,
        setup: &ValidatedXmrSetup,
        request: &ProductionChildMaterializationRequestV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        self.common.require_common_materialization(setup, request)?;
        if request.action != settlement_coordinator::SettlementActionV1::Refund
            || request.exposure != settlement_coordinator::ChildExposureV1::NonSecret
            || request.public_secret_evidence_digest != [0; 32]
            || self.dom_chain == [0; 32]
            || self.refund_template == [0; 32]
            || self.refund_destination.is_empty()
            || self.funding_min_confirmations == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn require_observation(
        &self,
        observed: &VerifiedDomRefundSecretV11,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        observed
            .require_recent_v23()
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        if observed.session_id() != self.common.session_id
            || observed.chain_id() != self.dom_chain
            || observed.template_hash() != self.refund_template
            || observed.refund_point() != self.refund_claim.secp_compressed
            || observed.finality().terms_hash() != self.common.terms_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

/// Both roles may observe public U through their own same-Store driver. This
/// does not give the ClaimReceiver the absent participant's T or spend key.
#[derive(Clone)]
pub(crate) enum ProductionXmrRemoteRefundSourceV23 {
    Attached(Rc<ProductionXmrRecoveryDriverV12>),
    Deferred(Rc<ProductionXmrDeferredRecoveryV23>),
}
impl ProductionXmrRemoteRefundSourceV23 {
    pub(super) fn driver(
        &self,
    ) -> Result<Rc<ProductionXmrRecoveryDriverV12>, ChildAuthorityRefusalV1> {
        match self {
            Self::Attached(driver) => Ok(Rc::clone(driver)),
            Self::Deferred(slot) => slot.require_driver(),
        }
    }

    fn observe(
        &self,
        pins: &ProductionXmrRemoteRefundPinsV23,
    ) -> Result<(VerifiedDomRefundSecretV11, [u8; 32]), ChildAuthorityRefusalV1> {
        let event = self.driver()?.observe_remote_refund_event_v23()?;
        pins.require_observation(&event.0)?;
        Ok(event)
    }

    fn observe_bounded_v24(
        &self,
        pins: &ProductionXmrRemoteRefundPinsV23,
        deadline: Instant,
    ) -> Result<(VerifiedDomRefundSecretV11, [u8; 32]), ChildAuthorityRefusalV1> {
        let event = self
            .driver()?
            .observe_remote_refund_event_until_v24(deadline)?;
        public_refund_remaining_v24(deadline)?;
        pins.require_observation(&event.0)?;
        Ok(event)
    }
}

fn refund_request(
    pins: &ProductionXmrRemoteRefundPinsV23,
    setup: &ValidatedXmrSetup,
    materialization: &ProductionChildMaterializationRequestV1,
    observed: &VerifiedDomRefundSecretV11,
    public_event: [u8; 32],
    funding: &f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
) -> Result<RemoteSweepRequestV23, ChildAuthorityRefusalV1> {
    pins.require_materialization(setup, materialization)?;
    pins.require_observation(observed)?;
    if funding.facts().age() > Duration::from_secs(60) {
        return Err(ChildAuthorityRefusalV1::Unavailable);
    }
    if funding.funding_id()
        != &f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(setup.funding_tx_hash())
        || funding.setup_binding_hash() != &setup.binding_hash()
        || funding.facts().settlement_id() != &setup.settlement_id()
        || funding.facts().terms_hash() != &setup.terms_hash()
        || funding.evidence_digest() == &[0; 32]
        || funding.block_height() == 0
        || public_event == [0; 32]
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    refund_request_from_facts_v24(
        pins,
        setup,
        materialization,
        observed,
        public_event,
        *funding.evidence_digest(),
        u64::from(funding.output_index()),
        funding.block_height(),
    )
}

#[allow(clippy::too_many_arguments)]
fn refund_request_from_facts_v24(
    pins: &ProductionXmrRemoteRefundPinsV23,
    setup: &ValidatedXmrSetup,
    materialization: &ProductionChildMaterializationRequestV1,
    observed: &VerifiedDomRefundSecretV11,
    public_event: [u8; 32],
    funding_evidence_digest: [u8; 32],
    output_index: u64,
    funding_height: u64,
) -> Result<RemoteSweepRequestV23, ChildAuthorityRefusalV1> {
    pins.require_materialization(setup, materialization)?;
    pins.require_observation(observed)?;
    if public_event == [0; 32] || funding_evidence_digest == [0; 32] || funding_height == 0 {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let public_spend_share = observed
        .expose(|bytes| revealed_dom_secret_to_xmr_scalar(*bytes, &pins.refund_claim))
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let p = &pins.common;
    Ok(RemoteSweepRequestV23 {
        network_genesis: p.network_genesis,
        route_id: p.route_id,
        session_id: p.session_id,
        settlement_id: setup.settlement_id(),
        terms_digest: p.terms_digest,
        registry_digest: p.registry_digest,
        profile_digest: p.profile_digest,
        deployment_digest: p.deployment_digest,
        route_scope_digest: p.route_scope_digest,
        composition_digest: p.composition_digest,
        role_plan_digest: p.role_plan_digest,
        source_scope_digest: p.source_scope_digest,
        effect_id: materialization.effect_id,
        semantic_digest: materialization.semantic_digest,
        public_secret_evidence_digest: public_event,
        funding_tx_hash: setup.funding_tx_hash(),
        funding_evidence_digest,
        funding_output_index: output_index,
        funding_block_height: funding_height,
        funded_amount_piconero: setup.expected_amount_piconero(),
        max_fee_piconero: p.max_fee_piconero,
        adapter_max_raw_transaction_bytes: p.adapter_max_raw_transaction_bytes,
        max_raw_transaction_bytes: p.adapter_max_raw_transaction_bytes.min(
            u32::try_from(xmr_remote_sweep_wire::MAX_RAW_SWEEP_BYTES_V23)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        ),
        fencing_epoch: materialization.fencing_epoch,
        action: RemoteSweepActionV23::Refund,
        leg: match materialization.leg {
            settlement_coordinator::SettlementLegV1::Upstream => RemoteSweepLegV23::Upstream,
            settlement_coordinator::SettlementLegV1::Downstream => RemoteSweepLegV23::Downstream,
        },
        public_spend_share,
        destination: pins.refund_destination.clone(),
    })
}

/// A local effect authorized by independently observed public U and funding.
/// Unlike AcceptedRemote, this capability needs no peer message and cannot be
/// constructed from a transport digest. Its private fields retain both clocks.
pub(crate) struct AuthorizedLocalXmrRefundV24 {
    request: RemoteSweepRequestV23,
    observed: VerifiedDomRefundSecretV11,
    funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    authorization_digest: [u8; 32],
}
impl AuthorizedLocalXmrRefundV24 {
    pub(crate) fn observe(
        pins: &ProductionXmrRemoteRefundPinsV23,
        setup: &ValidatedXmrSetup,
        materialization: &ProductionChildMaterializationRequestV1,
        source: &ProductionXmrRemoteRefundSourceV23,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let (observed, event) = source.observe(pins)?;
        let request = refund_request(pins, setup, materialization, &observed, event, &funding)?;
        let authorization_digest = local_refund_authorization_digest_v24(
            &request,
            observed.finality().transaction_hash(),
            observed.finality().graph_digest(),
        )?;
        Ok(Self {
            request,
            observed,
            funding,
            authorization_digest,
        })
    }

    pub(crate) fn request(&self) -> &RemoteSweepRequestV23 {
        &self.request
    }
    pub(crate) fn observed(&self) -> &VerifiedDomRefundSecretV11 {
        &self.observed
    }
    pub(crate) fn funding(&self) -> &f7_anchor_authority::families_v11::VerifiedXmrFundingV11 {
        &self.funding
    }
    pub(crate) fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    pub(crate) fn require_recent(&self) -> Result<(), ChildAuthorityRefusalV1> {
        self.observed
            .require_recent_v23()
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        if self.funding.facts().age() > Duration::from_secs(60) {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        Ok(())
    }
}

pub(super) fn local_refund_authorization_digest_v24(
    request: &RemoteSweepRequestV23,
    dom_refund_tx: [u8; 32],
    graph: [u8; 32],
) -> Result<[u8; 32], ChildAuthorityRefusalV1> {
    if request.action != RemoteSweepActionV23::Refund
        || dom_refund_tx == [0; 32]
        || graph == [0; 32]
        || request.funding_evidence_digest == [0; 32]
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    // The cache represents one effect/economic event, not its observation tip.
    // Fresh tokens are still required on every build/load; no timestamp is reset.
    let mut stable = request.clone();
    stable.funding_evidence_digest = [1; 32];
    let mut bytes = b"DOM-INTEROP/XMR-LOCAL-REFUND-AUTHORIZATION/V24\0".to_vec();
    bytes.extend_from_slice(&dom_refund_tx);
    bytes.extend_from_slice(&graph);
    bytes.extend_from_slice(
        &stable
            .encode()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
    );
    Ok(*dom_crypto::blake2b_256(&bytes).as_bytes())
}

/// Independently authenticate the local result without manufacturing a remote
/// envelope or treating the private UDS HMAC as proof of a valid Monero spend.
pub(crate) fn verify_local_refund_response_v24(
    authorized: &AuthorizedLocalXmrRefundV24,
    response: &xmr_live_sidecar_api::LocalRefundBuildResponseV24<
        xmr_live_sidecar_api::BuildSweepResponseV2,
    >,
    quorum: &QuorumXmrObservationPortV1,
) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
    authorized.require_recent()?;
    let built = verify_refund_response_artifacts_v24(
        authorized.request(),
        authorized.authorization_digest(),
        authorized.observed().finality().transaction_hash(),
        authorized.observed().finality().graph_digest(),
        response,
        quorum,
        None,
    )?;
    authorized.require_recent()?;
    Ok(built)
}

fn verify_refund_response_artifacts_v24(
    request: &RemoteSweepRequestV23,
    local_authorization_digest: [u8; 32],
    dom_refund_tx_hash: [u8; 32],
    graph_digest: [u8; 32],
    response: &xmr_live_sidecar_api::LocalRefundBuildResponseV24<
        xmr_live_sidecar_api::BuildSweepResponseV2,
    >,
    quorum: &QuorumXmrObservationPortV1,
    deadline: Option<Instant>,
) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
    let check = || {
        deadline
            .map(public_refund_remaining_v24)
            .transpose()
            .map(|_| ())
    };
    check()?;
    let context = response
        .validate_framing()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let expected = InputSpendContextV23 {
        network_genesis: request.network_genesis,
        route: request.route_id,
        session: request.session_id,
        terms: request.terms_digest,
        funding_tx: request.funding_tx_hash,
        output_index: request.funding_output_index,
        sweep_tx: response.sweep.tx_hash,
        destination: destination_digest_v23(&request.destination),
        funded_amount: request.funded_amount_piconero,
        fee: context.fee,
        action: InputSpendActionV23::Refund,
    };
    if context != expected
        || response.local_authorization_digest != local_authorization_digest
        || response.effect_id != request.effect_id
        || response.fencing_epoch != request.fencing_epoch
        || response.semantic_digest != request.semantic_digest
        || response.dom_refund_tx_hash != dom_refund_tx_hash
        || response.graph_digest != graph_digest
        || response.sweep.request_nonce != request.effect_id
        || context.fee == 0
        || context.fee > request.max_fee_piconero
        || response.sweep.raw_tx.len() > request.max_raw_transaction_bytes as usize
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let raw = verify_exact_raw_sweep_bounded_v23(
        &response.sweep.raw_tx,
        response.sweep.tx_hash,
        request.funded_amount_piconero,
        request.max_fee_piconero,
    )
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    check()?;
    let [key_image] = raw.sweep().key_images.as_slice() else {
        return Err(ChildAuthorityRefusalV1::Conflict);
    };
    let members = response
        .ring_members
        .iter()
        .map(|m| RemoteRingMemberV23 {
            global_index: m.global_index,
            key: m.key,
            commitment: m.commitment,
        })
        .collect::<Vec<_>>();
    let rings = match deadline {
        Some(deadline) => quorum.authenticate_remote_ring_with_deadline_v24(&members, deadline),
        None => quorum.authenticate_remote_ring_v23(&members),
    }
    .map_err(crate::production_child_xmr::map_actuator_error)?;
    check()?;
    let funding_raw = match deadline {
        Some(deadline) => {
            quorum.authenticated_funding_raw_with_deadline_v24(request.funding_tx_hash, deadline)
        }
        None => quorum.authenticated_funding_raw_v23(request.funding_tx_hash),
    }
    .map_err(crate::production_child_xmr::map_actuator_error)?;
    check()?;
    let input = InputSpendProofV23::decode(&response.input_proof)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let payouts = response
        .tx_key_proofs
        .iter()
        .map(|p| TxKeyDerivationProofV23::decode(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let verified = verify_sweep_payout_v23(
        &expected,
        &funding_raw,
        &response.sweep.raw_tx,
        &request.destination,
        request.max_fee_piconero,
        &input,
        &payouts,
        &rings,
        &mut rand::rngs::OsRng,
    )
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    check()?;
    if verified.input().context() != &expected
        || verified.input().key_image() != *key_image
        || verified.amount()
            != request
                .funded_amount_piconero
                .checked_sub(context.fee)
                .ok_or(ChildAuthorityRefusalV1::Conflict)?
        || verified.ring_members() != rings.as_slice()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(XmrBuiltSweepV1 {
        tx_hash: response.sweep.tx_hash,
        key_image: *key_image,
        raw_transaction: response.sweep.raw_tx.clone(),
        remote_custody_v23: None,
    })
}

/// The signer checks the request against its OWN canonical U and funding
/// observations. The accepted transport handle cannot select a destination.
fn require_shared_refund_economics_v24(
    requester: &RemoteSweepRequestV23,
    local: &RemoteSweepRequestV23,
) -> Result<(), ChildAuthorityRefusalV1> {
    if requester.action != RemoteSweepActionV23::Refund
        || local.action != RemoteSweepActionV23::Refund
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    requester
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    local
        .encode()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    // Each actor's journal derives its effect from its own event and lease.
    // Neither identity is replaced in its durable record or signed envelope.
    // Only this cross-actor, publication-only comparison projects them out.
    let mut normalized = local.clone();
    normalized.effect_id = requester.effect_id;
    normalized.fencing_epoch = requester.fencing_epoch;
    normalized.semantic_digest = requester.semantic_digest;
    require_stable_xmr_remote_request_retry_v23(requester, &normalized)
}

pub(crate) struct AuthenticatedRemoteRefundBuildV23<'local> {
    pub(super) accepted: AcceptedXmrRemoteSweepRequestV23,
    pub(super) request: RemoteSweepRequestV23,
    local: &'local VerifiedRetainedRefundPublicationV24,
}
impl<'local> AuthenticatedRemoteRefundBuildV23<'local> {
    pub(super) fn authenticate(
        accepted: AcceptedXmrRemoteSweepRequestV23,
        local: &'local VerifiedRetainedRefundPublicationV24,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        local.require_recent()?;
        let request = RemoteSweepRequestV23::decode_exact(accepted.payload())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        require_shared_refund_economics_v24(&request, local.request())?;
        if accepted.session_id() != &local.request().session_id
            || accepted.message_digest() == &[0; 32]
            || request
                .encode()
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                .as_slice()
                != accepted.payload()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            accepted,
            request,
            local,
        })
    }
}

/// Wrap already-built local proofs ONLY after a genuine authenticated request
/// exists. No signature, transaction key or accepted-message identity is made
/// here. The independent local-byte reader must agree before publication.
fn envelope_from_local_refund_v24(
    authorized: &AuthenticatedRemoteRefundBuildV23<'_>,
    retained: &XmrBuiltSweepV1,
) -> Result<Vec<u8>, ChildAuthorityRefusalV1> {
    authorized.local.require_recent()?;
    let built = &authorized.local.built;
    let response = &authorized.local.response;
    require_retained_refund_v24(retained, built)?;
    let request = &authorized.request;
    let context = response
        .validate_framing()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let wire = RemoteSweepResponseV23::new(RemoteSweepResponseInputV23 {
        request_digest: request
            .digest()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        request_message_digest: *authorized.accepted.message_digest(),
        signer_funding_evidence_digest: authorized.local.request.funding_evidence_digest,
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
        transaction_hash: built.tx_hash,
        key_image: built.key_image,
        funded_amount_piconero: request.funded_amount_piconero,
        fee_piconero: context.fee,
        fencing_epoch: request.fencing_epoch,
        action: RemoteSweepActionV23::Refund,
        leg: request.leg,
        raw_transaction: built.raw_transaction.clone(),
        input_spend_proof: response
            .input_proof
            .as_slice()
            .try_into()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        payout_proofs: response
            .tx_key_proofs
            .iter()
            .map(|p| RemoteTxKeyDerivationProofV23::decode(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        ring_members: response
            .ring_members
            .iter()
            .map(|m| RemoteRingMemberV23 {
                global_index: m.global_index,
                key: m.key,
                commitment: m.commitment,
            })
            .collect(),
    })
    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    wire.validate_for_authenticated_request(request, *authorized.accepted.message_digest())
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    authorized.local.require_recent()?;
    wire.encode().map_err(|_| ChildAuthorityRefusalV1::Conflict)
}

/// Publication/observation only, never a funding or signing grant. Its proof
/// starts from exact bytes already retained by the native actuator after the
/// original typed funding/U build. Ready MAC merely locates those artifacts;
/// canonical inclusion, input linkage, payout and rings are rechecked here.
struct VerifiedRetainedRefundPublicationV24 {
    request: RemoteSweepRequestV23,
    observed: VerifiedDomRefundSecretV11,
    response: xmr_live_sidecar_api::LocalRefundBuildResponseV24<
        xmr_live_sidecar_api::BuildSweepResponseV2,
    >,
    built: XmrBuiltSweepV1,
    verified_at: std::time::Instant,
}
impl VerifiedRetainedRefundPublicationV24 {
    fn request(&self) -> &RemoteSweepRequestV23 {
        &self.request
    }
    fn observed(&self) -> &VerifiedDomRefundSecretV11 {
        &self.observed
    }
    fn require_recent(&self) -> Result<(), ChildAuthorityRefusalV1> {
        self.observed
            .require_recent_v23()
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        require_public_refund_age_v24(self.verified_at.elapsed())
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_retained(
        pins: &ProductionXmrRemoteRefundPinsV23,
        setup: &ValidatedXmrSetup,
        materialization: &ProductionChildMaterializationRequestV1,
        source: &ProductionXmrRemoteRefundSourceV23,
        sweep: &crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
        quorum: &mut QuorumXmrObservationPortV1,
        retained: &XmrBuiltSweepV1,
        deadline: Instant,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.require_materialization(setup, materialization)?;
        let started = std::time::Instant::now();
        public_refund_remaining_v24(deadline)?;
        let (observed, event) = source.observe_bounded_v24(pins, deadline)?;
        let p = &pins.common;
        let load = xmr_live_sidecar_api::LocalRefundLoadRequestV24 {
            api_version: 24,
            request_nonce: materialization.effect_id,
            network_genesis: p.network_genesis,
            route: p.route_id,
            session: p.session_id,
            terms: p.terms_digest,
            effect_id: materialization.effect_id,
            fencing_epoch: materialization.fencing_epoch,
            semantic_digest: materialization.semantic_digest,
            dom_refund_tx_hash: observed.finality().transaction_hash(),
            graph_digest: observed.finality().graph_digest(),
            settlement_id: setup.settlement_id(),
            funding_tx_hash: setup.funding_tx_hash(),
            funded_amount: setup.expected_amount_piconero(),
            destination: pins.refund_destination.clone(),
            expected_spend_public_key: setup.combined_spend_public_key(),
            max_fee: p.max_fee_piconero,
            auth_tag: [0; 32],
        };
        // Public HMAC/Ready lookup never loads an XMR share or a private view key.
        let response = sweep.load_local_refund_with_deadline_v24(load.clone(), deadline)?;
        public_refund_remaining_v24(deadline)?;
        if response.public_scope.request != load || response.cache_request_hash == [0; 32] {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let inclusion = quorum
            .transaction_inclusion_with_deadline_v24(setup.funding_tx_hash(), deadline)
            .map_err(crate::production_child_xmr::map_actuator_error)?
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
        public_refund_remaining_v24(deadline)?;
        if inclusion.height != response.public_scope.funding_height
            || inclusion.height == 0
            || inclusion.block_hash == [0; 32]
            || inclusion.confirmations < pins.funding_min_confirmations
        {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        let mut evidence = b"DOM-INTEROP/XMR-REFUND-PUBLIC-FUNDING-OBSERVATION/V24\0".to_vec();
        for digest in [
            p.network_genesis,
            setup.funding_tx_hash(),
            inclusion.block_hash,
            response.cache_request_hash,
        ] {
            evidence.extend_from_slice(&digest);
        }
        evidence.extend_from_slice(&inclusion.height.to_be_bytes());
        evidence.extend_from_slice(&inclusion.confirmations.to_be_bytes());
        let request = refund_request_from_facts_v24(
            pins,
            setup,
            materialization,
            &observed,
            event,
            *dom_crypto::blake2b_256(&evidence).as_bytes(),
            response.public_scope.output_index,
            inclusion.height,
        )?;
        let local_digest = local_refund_authorization_digest_v24(
            &request,
            load.dom_refund_tx_hash,
            load.graph_digest,
        )?;
        if local_digest != response.public_scope.local_authorization_digest {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let built = verify_refund_response_artifacts_v24(
            &request,
            local_digest,
            load.dom_refund_tx_hash,
            load.graph_digest,
            &response,
            quorum,
            Some(deadline),
        )?;
        require_retained_refund_v24(retained, &built)?;
        let after = quorum
            .transaction_inclusion_with_deadline_v24(setup.funding_tx_hash(), deadline)
            .map_err(crate::production_child_xmr::map_actuator_error)?;
        public_refund_remaining_v24(deadline)?;
        require_stable_public_funding_v24(inclusion, after, pins.funding_min_confirmations)?;
        let verified = Self {
            request,
            observed,
            response,
            built,
            verified_at: started,
        };
        verified.require_recent()?;
        Ok(verified)
    }
}

fn require_stable_public_funding_v24(
    before: xmr_actuator::XmrTxInclusionV1,
    after: Option<xmr_actuator::XmrTxInclusionV1>,
    minimum: u64,
) -> Result<(), ChildAuthorityRefusalV1> {
    let after = after.ok_or(ChildAuthorityRefusalV1::Unavailable)?;
    // New canonical descendants may add confirmations while proofs are being
    // verified. Preserve the original inclusion, never relocate it or accept
    // a disappearing/less-confirmed funding transaction under this capability.
    if before.height == 0
        || before.block_hash == [0; 32]
        || before.confirmations == 0
        || before.confirmations < minimum
        || after.height != before.height
        || after.block_hash != before.block_hash
        || after.confirmations < before.confirmations
    {
        return Err(ChildAuthorityRefusalV1::Unavailable);
    }
    Ok(())
}

fn require_public_refund_age_v24(age: Duration) -> Result<(), ChildAuthorityRefusalV1> {
    if age > Duration::from_secs(60) {
        Err(ChildAuthorityRefusalV1::Unavailable)
    } else {
        Ok(())
    }
}

fn require_retained_refund_v24(
    retained: &XmrBuiltSweepV1,
    built: &XmrBuiltSweepV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if retained.tx_hash != built.tx_hash
        || retained.key_image != built.key_image
        || retained.raw_transaction != built.raw_transaction
        || retained.remote_custody_v23.is_some()
        || built.remote_custody_v23.is_some()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

/// Background publication is independent of local refund dispatch/finality.
/// It can LOAD an existing local proof cache, never construct or broadcast.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefundPublicationProgressV24 {
    /// No retained local capability or no accepted request yet.
    Waiting,
    /// Response was durably staged; Relay still has to flush/acknowledge it.
    Staged,
    /// Existing authenticated response reconciled; NOT a remote delivery ACK.
    Complete,
}

fn public_refund_remaining_v24(deadline: Instant) -> Result<Duration, ChildAuthorityRefusalV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ChildAuthorityRefusalV1::Unavailable)
}

fn require_verified_public_response_v24(
    local: &VerifiedRetainedRefundPublicationV24,
    wire: &RemoteSweepResponseV23,
) -> Result<(), ChildAuthorityRefusalV1> {
    local.require_recent()?;
    // signer_funding_evidence_digest is the ORIGINAL tip-sensitive observation
    // signed into this exact DSC1 response. The authenticated Store supplies
    // these immutable bytes; canonical wire framing already rejects zero.
    // Comparing it with today's confirmations digest would prevent legitimate
    // restart. Fresh inclusion/proofs here independently revalidate economics,
    // without changing the historical envelope or minting a fresh F7 grant.
    let context = local
        .response
        .validate_framing()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    if wire.action() != RemoteSweepActionV23::Refund
        || wire.transaction_hash() != local.built.tx_hash
        || wire.key_image() != local.built.key_image
        || wire.raw_transaction() != local.built.raw_transaction
        || wire.fee_piconero() != context.fee
        || wire.input_spend_proof().as_slice() != local.response.input_proof
        || wire.payout_proofs().len() != local.response.tx_key_proofs.len()
        || wire
            .payout_proofs()
            .iter()
            .zip(&local.response.tx_key_proofs)
            .any(|(a, b)| a.as_bytes().as_slice() != b)
        || wire.ring_members().len() != local.response.ring_members.len()
        || wire
            .ring_members()
            .iter()
            .zip(&local.response.ring_members)
            .any(|(a, b)| {
                a.global_index != b.global_index || a.key != b.key || a.commitment != b.commitment
            })
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

pub(crate) struct ProductionXmrRefundResponderV24 {
    pins: ProductionXmrRemoteRefundPinsV23,
    setup: ValidatedXmrSetup,
    source: ProductionXmrRemoteRefundSourceV23,
    reader: crate::production_child_xmr::ProductionXmrRetainedRefundReaderV24,
    transport: Box<dyn ProductionXmrRemoteSweepResponderTransportV23>,
    quorum: QuorumXmrObservationPortV1,
    // Optimization only: reset on every process open, never a signing/funding
    // authority and never used to publish without fresh public verification.
    scope_retained_v24: bool,
}
impl ProductionXmrRefundResponderV24 {
    pub(crate) fn new(
        pins: ProductionXmrRemoteRefundPinsV23,
        setup: ValidatedXmrSetup,
        source: ProductionXmrRemoteRefundSourceV23,
        reader: crate::production_child_xmr::ProductionXmrRetainedRefundReaderV24,
        transport: Box<dyn ProductionXmrRemoteSweepResponderTransportV23>,
        quorum: QuorumXmrObservationPortV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.common.validate(&setup)?;
        Ok(Self {
            pins,
            setup,
            source,
            reader,
            transport,
            quorum,
            scope_retained_v24: false,
        })
    }

    pub(crate) fn tick(
        &mut self,
        snapshot: &route_executor::RouteSnapshotV1,
        sweep: &mut crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(60))
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
        self.tick_bounded_v24(snapshot, sweep, deadline).map(|_| ())
    }

    /// One absolute cutoff across the public publication attempt. DOM reads
    /// inherit its remaining budget, as do the public LOAD and quorum APIs.
    /// Synchronous CPU/disk work is checked on return; this is not preemption
    /// of those operations. No subsequent step may start after cutoff.
    pub(crate) fn tick_bounded_v24(
        &mut self,
        snapshot: &route_executor::RouteSnapshotV1,
        sweep: &mut crate::production_xmr_recovery_pump_v22::SharedXmrSweepV22,
        deadline: Instant,
    ) -> Result<RefundPublicationProgressV24, ChildAuthorityRefusalV1> {
        public_refund_remaining_v24(deadline)?;
        let Some(materialization) = self.materialization(snapshot)? else {
            return Ok(RefundPublicationProgressV24::Waiting);
        };
        let pending = if self.scope_retained_v24 {
            let pending = self.transport.poll_request_v23()?;
            public_refund_remaining_v24(deadline)?;
            if matches!(pending, ProductionXmrRemoteResponderPollV23::NoRequest) {
                return Ok(RefundPublicationProgressV24::Waiting);
            }
            Some(pending)
        } else {
            None
        };
        let Some(retained) = self.reader.retained()? else {
            return Ok(RefundPublicationProgressV24::Waiting);
        };
        let local = VerifiedRetainedRefundPublicationV24::observe_retained(
            &self.pins,
            &self.setup,
            &materialization,
            &self.source,
            sweep,
            &mut self.quorum,
            &retained,
            deadline,
        )?;
        public_refund_remaining_v24(deadline)?;
        let encoded = local
            .request()
            .encode()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        self.source
            .driver()?
            .retain_remote_refund_transport_v23(&encoded, local.observed())?;
        self.scope_retained_v24 = true;
        public_refund_remaining_v24(deadline)?;
        let pending = match pending {
            Some(pending) => pending,
            None => self.transport.poll_request_v23()?,
        };
        match pending {
            ProductionXmrRemoteResponderPollV23::NoRequest => {
                public_refund_remaining_v24(deadline)?;
                Ok(RefundPublicationProgressV24::Waiting)
            }
            ProductionXmrRemoteResponderPollV23::Request(accepted) => {
                public_refund_remaining_v24(deadline)?;
                let authorized = AuthenticatedRemoteRefundBuildV23::authenticate(accepted, &local)?;
                let bytes = envelope_from_local_refund_v24(&authorized, &retained)?;
                let current = self
                    .reader
                    .retained()?
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?;
                require_retained_refund_v24(&retained, &current)?;
                local.require_recent()?;
                public_refund_remaining_v24(deadline)?;
                self.transport
                    .publish_response_v23(&authorized.accepted, &bytes)?;
                public_refund_remaining_v24(deadline)?;
                Ok(RefundPublicationProgressV24::Staged)
            }
            ProductionXmrRemoteResponderPollV23::RetainedResponse { request, response } => {
                public_refund_remaining_v24(deadline)?;
                let request = RemoteSweepRequestV23::decode_exact(&request)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                require_shared_refund_economics_v24(&request, local.request())?;
                let wire = RemoteSweepResponseV23::decode_exact(&response)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                wire.validate_for_authenticated_request(&request, wire.request_message_digest())
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                // Reuse only this call's freshly verified public proof bundle.
                // Do not repeat quorum RPC or treat an old Ready as a token.
                require_verified_public_response_v24(&local, &wire)?;
                local.require_recent()?;
                public_refund_remaining_v24(deadline)?;
                self.transport.reconcile_response_v23(&response)?;
                public_refund_remaining_v24(deadline)?;
                Ok(RefundPublicationProgressV24::Complete)
            }
        }
    }

    fn materialization(
        &self,
        snapshot: &route_executor::RouteSnapshotV1,
    ) -> Result<Option<ProductionChildMaterializationRequestV1>, ChildAuthorityRefusalV1> {
        let p = &self.pins.common;
        let Some(effect) =
            original_refund_effect_v24(snapshot, p.route_id, p.route_terms_digest, p.leg)?
        else {
            return Ok(None);
        };
        let request = ProductionChildMaterializationRequestV1 {
            route_id: p.route_id,
            effect_id: effect.effect_id,
            settlement_id: self.setup.settlement_id(),
            leg: p.leg,
            action: settlement_coordinator::SettlementActionV1::Refund,
            // The original effect epoch, NEVER today's renewed actuator lease.
            fencing_epoch: effect.fencing_epoch,
            semantic_digest: effect.semantic_digest,
            terms_digest: p.route_terms_digest,
            registry_digest: p.registry_digest,
            profile_digest: p.profile_digest,
            deployment_digest: p.deployment_digest,
            route_scope_digest: p.route_scope_digest,
            composition_digest: p.composition_digest,
            role_plan_digest: p.role_plan_digest,
            source_scope_digest: p.source_scope_digest,
            public_secret_evidence_digest: [0; 32],
            exposure: settlement_coordinator::ChildExposureV1::NonSecret,
        };
        self.pins.require_materialization(&self.setup, &request)?;
        Ok(Some(request))
    }
}

/// Public projection only; the caller obtains `snapshot` from the sole native
/// RouteRuntime replay and independently obtains current U/funding authorities.
fn original_refund_effect_v24(
    snapshot: &route_executor::RouteSnapshotV1,
    route: [u8; 32],
    terms: [u8; 32],
    leg: settlement_coordinator::SettlementLegV1,
) -> Result<Option<&route_executor::EffectReferenceV1>, ChildAuthorityRefusalV1> {
    if snapshot.route_id != route
        || snapshot.bindings.as_ref().map(|b| b.terms_digest) != Some(terms)
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let state = match leg {
        settlement_coordinator::SettlementLegV1::Upstream => &snapshot.upstream.refund,
        settlement_coordinator::SettlementLegV1::Downstream => &snapshot.downstream.refund,
    };
    if let Some(effect) = state.effect() {
        if effect.contains_route_secret
            || effect.effect_id == [0; 32]
            || effect.semantic_digest == [0; 32]
            || effect.fencing_epoch == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
    }
    Ok(state.effect())
}

#[cfg(test)]
mod local_custody_tests_v24 {
    use super::*;

    #[test]
    fn independent_actor_effects_share_refund_economics_but_never_requester_replay() {
        let mut requester = super::super::tests::request();
        requester.action = RemoteSweepActionV23::Refund;
        let mut local = requester.clone();
        local.effect_id = [61; 32];
        local.fencing_epoch += 4;
        local.semantic_digest = [62; 32];
        local.funding_evidence_digest = [63; 32];
        let requester_bytes = requester.encode().unwrap();
        let local_bytes = local.encode().unwrap();
        require_shared_refund_economics_v24(&requester, &local).unwrap();
        assert!(require_stable_xmr_remote_request_retry_v23(&requester, &local).is_err());
        assert_eq!(requester.encode().unwrap(), requester_bytes);
        assert_eq!(local.encode().unwrap(), local_bytes);
        let mutate: &[fn(&mut RemoteSweepRequestV23)] = &[
            |r| r.network_genesis[0] ^= 1,
            |r| r.route_id[0] ^= 1,
            |r| r.session_id[0] ^= 1,
            |r| r.settlement_id[0] ^= 1,
            |r| r.terms_digest[0] ^= 1,
            |r| r.registry_digest[0] ^= 1,
            |r| r.profile_digest[0] ^= 1,
            |r| r.deployment_digest[0] ^= 1,
            |r| r.route_scope_digest[0] ^= 1,
            |r| r.composition_digest[0] ^= 1,
            |r| r.role_plan_digest[0] ^= 1,
            |r| r.source_scope_digest[0] ^= 1,
            |r| r.public_secret_evidence_digest[0] ^= 1,
            |r| r.funding_tx_hash[0] ^= 1,
            |r| r.funding_output_index += 1,
            |r| r.funding_block_height += 1,
            |r| r.funded_amount_piconero += 1,
            |r| r.max_fee_piconero += 1,
            |r| r.adapter_max_raw_transaction_bytes -= 1,
            |r| r.max_raw_transaction_bytes -= 1,
            |r| r.action = RemoteSweepActionV23::Claim,
            |r| r.leg = RemoteSweepLegV23::Upstream,
            |r| r.public_spend_share[0] ^= 1,
            |r| r.destination.push('1'),
        ];
        assert_eq!(mutate.len(), 24);
        for change in mutate {
            let mut different = local.clone();
            change(&mut different);
            assert!(require_shared_refund_economics_v24(&requester, &different).is_err());
        }
        for field in 0..3 {
            let mut malformed = local.clone();
            match field {
                0 => malformed.effect_id = [0; 32],
                1 => malformed.fencing_epoch = 0,
                _ => malformed.semantic_digest = [0; 32],
            }
            assert!(require_shared_refund_economics_v24(&requester, &malformed).is_err());
        }
        requester.action = RemoteSweepActionV23::Claim;
        local.action = RemoteSweepActionV23::Claim;
        assert!(require_shared_refund_economics_v24(&requester, &local).is_err());
        assert!(require_stable_xmr_remote_request_retry_v23(&requester, &local).is_err());
    }

    #[test]
    fn public_funding_recheck_accepts_descendants_but_not_relocation_or_rollback() {
        let original = xmr_actuator::XmrTxInclusionV1 {
            height: 100,
            block_hash: [7; 32],
            confirmations: 10,
        };
        for confirmations in [10, 11, 100] {
            let after = xmr_actuator::XmrTxInclusionV1 {
                confirmations,
                ..original
            };
            assert_eq!(
                require_stable_public_funding_v24(original, Some(after), 10),
                Ok(())
            );
        }
        for after in [
            None,
            Some(xmr_actuator::XmrTxInclusionV1 {
                height: 101,
                ..original
            }),
            Some(xmr_actuator::XmrTxInclusionV1 {
                block_hash: [8; 32],
                ..original
            }),
            Some(xmr_actuator::XmrTxInclusionV1 {
                confirmations: 9,
                ..original
            }),
        ] {
            assert_eq!(
                require_stable_public_funding_v24(original, after, 10),
                Err(ChildAuthorityRefusalV1::Unavailable)
            );
        }
        assert_eq!(
            require_stable_public_funding_v24(original, Some(original), 11),
            Err(ChildAuthorityRefusalV1::Unavailable)
        );
        for invalid in [
            xmr_actuator::XmrTxInclusionV1 {
                height: 0,
                ..original
            },
            xmr_actuator::XmrTxInclusionV1 {
                block_hash: [0; 32],
                ..original
            },
            xmr_actuator::XmrTxInclusionV1 {
                confirmations: 0,
                ..original
            },
        ] {
            assert_eq!(
                require_stable_public_funding_v24(invalid, Some(invalid), 0),
                Err(ChildAuthorityRefusalV1::Unavailable)
            );
        }
    }

    #[test]
    fn read_only_publication_does_not_refresh_an_expired_observation() {
        assert_eq!(
            require_public_refund_age_v24(Duration::from_secs(60)),
            Ok(())
        );
        for age in [
            Duration::from_secs(60) + Duration::from_nanos(1),
            Duration::from_secs(3600),
        ] {
            assert_eq!(
                require_public_refund_age_v24(age),
                Err(ChildAuthorityRefusalV1::Unavailable)
            );
        }
    }

    #[test]
    fn reopened_refund_projection_retains_original_nonce_epoch_and_semantics() {
        let mut snapshot = route_executor::RouteSnapshotV1::new([1; 32]).unwrap();
        snapshot.bindings = Some(route_executor::FrozenBindingsV1 {
            terms_digest: [2; 32],
            profile_bundle_digest: [3; 32],
            deployment_bundle_digest: [4; 32],
        });
        let original = route_executor::EffectReferenceV1 {
            effect_id: [5; 32],
            fencing_epoch: 7,
            semantic_digest: [6; 32],
            contains_route_secret: false,
            expected_transaction_id: Some([8; 32]),
        };
        snapshot.upstream.refund = route_executor::ActionStateV1::Externalized {
            effect: original.clone(),
            transaction_id: [9; 32],
        };
        // Later journal mutations do not substitute today's lease generation.
        snapshot.revision += 99;
        let reopened = snapshot.clone();
        assert_eq!(
            original_refund_effect_v24(
                &reopened,
                [1; 32],
                [2; 32],
                settlement_coordinator::SettlementLegV1::Upstream
            )
            .unwrap(),
            Some(&original)
        );
        assert!(original_refund_effect_v24(
            &reopened,
            [1; 32],
            [2; 32],
            settlement_coordinator::SettlementLegV1::Downstream
        )
        .unwrap()
        .is_none());
        assert!(original_refund_effect_v24(
            &reopened,
            [10; 32],
            [2; 32],
            settlement_coordinator::SettlementLegV1::Upstream
        )
        .is_err());
        assert!(original_refund_effect_v24(
            &reopened,
            [1; 32],
            [10; 32],
            settlement_coordinator::SettlementLegV1::Upstream
        )
        .is_err());
        let mut invalid = original;
        invalid.contains_route_secret = true;
        snapshot.upstream.refund = route_executor::ActionStateV1::Committed(invalid);
        assert!(original_refund_effect_v24(
            &snapshot,
            [1; 32],
            [2; 32],
            settlement_coordinator::SettlementLegV1::Upstream
        )
        .is_err());
    }

    #[test]
    fn publication_requires_exact_locally_retained_refund_bytes() {
        let retained = XmrBuiltSweepV1 {
            tx_hash: [1; 32],
            key_image: [2; 32],
            raw_transaction: vec![3],
            remote_custody_v23: None,
        };
        let mut replay = XmrBuiltSweepV1 {
            tx_hash: [1; 32],
            key_image: [2; 32],
            raw_transaction: vec![3],
            remote_custody_v23: None,
        };
        assert_eq!(require_retained_refund_v24(&retained, &replay), Ok(()));
        replay.raw_transaction.push(4);
        assert!(require_retained_refund_v24(&retained, &replay).is_err());
        replay.raw_transaction.pop();
        replay.tx_hash = [4; 32];
        assert!(require_retained_refund_v24(&retained, &replay).is_err());
        replay.tx_hash = retained.tx_hash;
        replay.key_image = [4; 32];
        assert!(require_retained_refund_v24(&retained, &replay).is_err());
    }

    #[test]
    fn publication_deadline_is_not_rebased_between_steps() {
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            public_refund_remaining_v24(expired),
            Err(ChildAuthorityRefusalV1::Unavailable)
        );
        let deadline = Instant::now().checked_add(Duration::from_secs(60)).unwrap();
        let first = public_refund_remaining_v24(deadline).unwrap();
        let second = public_refund_remaining_v24(deadline).unwrap();
        assert!(second <= first && first <= Duration::from_secs(60));
        assert_eq!(
            public_refund_remaining_v24(expired),
            Err(ChildAuthorityRefusalV1::Unavailable)
        );
    }

    #[test]
    fn historical_funding_digest_survives_confirmation_growth_but_not_unsigned_rewrite(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1, UnsignedMessageV1};
        // Wire/signature boundary only: these framing fixtures are NOT native
        // XMR proof tokens. Real proof/import coverage uses the daemon round.
        let mut request = super::super::tests::request();
        request.action = RemoteSweepActionV23::Refund;
        let historical = [0xe7; 32];
        let before = xmr_actuator::XmrTxInclusionV1 {
            height: 7,
            block_hash: [0xa1; 32],
            confirmations: 10,
        };
        let after = xmr_actuator::XmrTxInclusionV1 {
            confirmations: 11,
            ..before
        };
        require_stable_public_funding_v24(before, Some(after), 10)?;
        let mut fresh = request.clone();
        fresh.funding_evidence_digest = [0xe8; 32];
        require_shared_refund_economics_v24(&request, &fresh)?;
        let input = |evidence| RemoteSweepResponseInputV23 {
            request_digest: request.digest().unwrap(),
            request_message_digest: [0x23; 32],
            signer_funding_evidence_digest: evidence,
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
            transaction_hash: [0x21; 32],
            key_image: [0x22; 32],
            funded_amount_piconero: request.funded_amount_piconero,
            fee_piconero: request.max_fee_piconero - 1,
            fencing_epoch: request.fencing_epoch,
            action: request.action,
            leg: request.leg,
            raw_transaction: vec![0x7a; 64],
            input_spend_proof: [0x31; xmr_remote_sweep_wire::INPUT_SPEND_PROOF_BYTES_V23],
            payout_proofs: vec![RemoteTxKeyDerivationProofV23::decode(
                &[0x41; xmr_remote_sweep_wire::TX_KEY_DERIVATION_PROOF_BYTES_V23],
            )
            .unwrap()],
            ring_members: (0..16)
                .map(|i| RemoteRingMemberV23 {
                    global_index: i + 1,
                    key: [i as u8 + 1; 32],
                    commitment: [i as u8 + 33; 32],
                })
                .collect(),
        };
        let wire = RemoteSweepResponseV23::new(input(historical))?;
        let bytes = wire.encode()?;
        wire.validate_for_authenticated_request(&request, [0x23; 32])?;
        assert_ne!(
            wire.signer_funding_evidence_digest(),
            fresh.funding_evidence_digest
        );
        assert_eq!(
            RemoteSweepResponseV23::decode_exact(&bytes)?.encode()?,
            bytes
        );
        assert!(RemoteSweepResponseV23::new(input([0; 32])).is_err());
        let mut key = [0; 32];
        key[31] = 37;
        let key = dom_crypto::SecretKey::from_bytes(&key)?;
        let signed = SignedMessageV1::sign(
            UnsignedMessageV1::new(
                MessageTypeV1::XmrRemoteSweepResponseV23,
                [0x11; 32],
                request.session_id,
                [0x12; 32],
                1,
                [0x13; 32],
                bytes.clone(),
            )?,
            &key,
        )?;
        signed.verify_identity(&key.public_key())?;
        let rewritten =
            RemoteSweepResponseV23::new(input(fresh.funding_evidence_digest))?.encode()?;
        let mut tampered = signed.as_bytes().to_vec();
        let start = tampered
            .windows(bytes.len())
            .position(|window| window == bytes)
            .ok_or("payload absent")?;
        tampered[start..start + bytes.len()].copy_from_slice(&rewritten);
        assert!(SignedMessageV1::decode_exact(&tampered)?
            .verify_identity(&key.public_key())
            .is_err());
        // Confirmation growth keeps the original signed envelope; no re-sign.
        signed.verify_identity(&key.public_key())?;
        assert_eq!(signed.unsigned().payload(), bytes);
        Ok(())
    }
}

/// Imports only a signer-authenticated proof envelope already retained by
/// Store/Relay. Its disappearance is not repaired by guessing a spending txid.
pub(crate) struct ProductionXmrRemoteRefundClientV23 {
    pins: ProductionXmrRemoteRefundPinsV23,
    setup: ValidatedXmrSetup,
    source: ProductionXmrRemoteRefundSourceV23,
    transport: Box<dyn ProductionXmrRemoteSweepTransportV23>,
    quorum: QuorumXmrObservationPortV1,
}
impl ProductionXmrRemoteRefundClientV23 {
    pub(crate) fn new(
        pins: ProductionXmrRemoteRefundPinsV23,
        setup: ValidatedXmrSetup,
        source: ProductionXmrRemoteRefundSourceV23,
        transport: Box<dyn ProductionXmrRemoteSweepTransportV23>,
        quorum: QuorumXmrObservationPortV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        pins.common.validate(&setup)?;
        Ok(Self {
            pins,
            setup,
            source,
            transport,
            quorum,
        })
    }

    pub(super) fn build_refund(
        &mut self,
        materialization: &ProductionChildMaterializationRequestV1,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1> {
        let (observed, public_event) = self.source.observe(&self.pins)?;
        let request = refund_request(
            &self.pins,
            &self.setup,
            materialization,
            &observed,
            public_event,
            &funding,
        )?;
        let bytes = request
            .encode()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let digest = request
            .digest()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        self.source
            .driver()?
            .retain_remote_refund_transport_v23(&bytes, &observed)?;
        let envelope = self.transport.exchange_or_resume_v23(&bytes, digest)?;
        let retained = RemoteSweepRequestV23::decode_exact(envelope.request_payload())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        require_stable_xmr_remote_request_retry_v23(&retained, &request)?;
        let verified = verify_remote_xmr_sweep_v23(&retained, envelope, &self.quorum)?;
        self.pins.require_observation(&observed)?;
        if funding.facts().age() > Duration::from_secs(60) {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        Ok(verified.into_built_sweep())
    }
}
