//! Operational early/BP bootstrap from the retained private share owner.
//! One bounded native message per tick; all signing goes through Contracts/DSC1.
use super::{ProductionContractsOutboundErrorV1, ProductionContractsV1};
use crate::production_contracts_bootstrap::AuthenticatedContractsLegV1;
use crate::production_dom_shared_bootstrap_v12::{
    ProductionBoundDomSharedOutputV12, ProductionDomSharedBootstrapErrorV12,
};
use crate::relay_worker::{ContractsRelayIngressErrorV1, PreparedContractsIngressV1};
use dom_actuator::DomSessionBindingV1;
use dom_adaptor::{
    BpStatementV1, CollaborativeBpNonceBindingV1, DirectionV1, EarlyShareCommitmentV1,
    EarlyShareRevealV1, PendingSharedBlindingBindingV1, Round1ContinuationV25,
    SharedBlindingBindingV1, TrustedChainIdV1,
};
use dom_crypto::{blake2b_256, PublicKey};
use dom_scriptless_store::{
    CollaborativeBpCustodyV16, OperationalBpContinuationStageV1 as Stage, OutboundDsc1RecoveryV1,
    SessionPhaseV1, SessionStoreError,
};
use dom_scriptless_transport::SignedMessageV1;
use relay::TimelockSpec;
use route_transport::F6TransportPortV1;
use zeroize::Zeroizing;

#[path = "production_bootstrap_completion_v22.rs"]
mod completion_v22;
#[path = "production_bootstrap_templates_v17.rs"]
mod templates_v17;

// Transport lifetime only. It never changes a settlement/refund deadline.
const ENVELOPE_LIFETIME_SECONDS: u64 = 3600;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionBootstrapRuntimeErrorV16 {
    #[error("bootstrap runtime scope or private custody is inconsistent")]
    Binding,
    #[error("bootstrap native cryptographic operation failed")]
    Crypto,
    #[error("bootstrap nonce vault stage is absent, consumed, or inconsistent")]
    Vault,
    #[error("bootstrap transport lifetime expired; no new funding was authorized")]
    Expired,
    #[error("bootstrap native Contracts journal refused the transition")]
    Store(#[from] SessionStoreError),
    #[error("bootstrap private journal rejected the public continuation")]
    Journal(#[from] ProductionDomSharedBootstrapErrorV12),
    #[error("bootstrap Contracts outbound operation failed")]
    Outbound(#[from] ProductionContractsOutboundErrorV1),
    #[error("bootstrap Relay ingress authority failed")]
    Ingress(#[from] ContractsRelayIngressErrorV1),
    #[error("bootstrap public offer mailbox is unavailable or inconsistent")]
    Mailbox,
    #[error("XMR requires its authenticated adaptor refund and compensation graph")]
    XmrRecoveryGraphRequired,
    /// The peer's graph candidate arrived before this side retained the
    /// surfaces it binds to (offer, setup, private bootstrap, cancelled
    /// contracts or F6 principal slots). Not a refusal of the candidate:
    /// it stays memory-only and unacknowledged, the peer re-sends it, and
    /// a later round consumes it through the full validation once the
    /// surfaces exist.
    #[error("bootstrap has not yet retained the surfaces a peer graph candidate binds to")]
    AwaitingGraphCandidateSurfacesV25,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionBootstrapStepV16 {
    AwaitingPeer,
    Staged,
    Complete,
}

pub(crate) struct ProductionBootstrapLegV16 {
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    shared: [SharedBlindingBindingV1; 2],
    statement: BpStatementV1,
    complete: bool,
    xmr_value_v22: Option<u64>,
    frozen_xmr_v22: Option<dom_scriptless_crypto::FrozenSharedOutputV1>,
    verified_xmr_v22: Option<dom_adaptor::VerifiedSharedOutputV1>,
    xmr_collateral_policy: Option<(
        xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
        kaystra_core::SettlementTermsV1,
    )>,
    templates_v17: Option<templates_v17::TemplateDriverV17>,
    // Process-local, move-only continuation of this exact BP session. It is
    // never persisted or used instead of current Store/vault authentication.
    round1_continuation_v25: Option<Round1ContinuationV25>,
}
impl ProductionBootstrapLegV16 {
    pub(crate) fn new(
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        leg: &AuthenticatedContractsLegV1,
        amount: u64,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<Self, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        let ids = [
            leg.participants()[0].participant_id().0,
            leg.participants()[1].participant_id().0,
        ];
        if binding.session_id() != *leg.session_id()
            || binding.terms_digest() != *leg.terms_hash()
            || chain.as_bytes() != &binding.chain_id()
            || amount == 0
            || material.capability.binding().participant_id()
                != &binding.participant().participant_id()
            || material.capsule.as_bytes() != leg.recovery_capsule()
        {
            return Err(Error::Binding);
        }
        let mut shared = Vec::new();
        let mut points = Vec::new();
        for (i, p) in leg.participants().iter().enumerate() {
            let point =
                PublicKey::from_compressed_bytes(p.share_point()).map_err(|_| Error::Crypto)?;
            let pending = PendingSharedBlindingBindingV1::new(
                &chain,
                binding.session_id(),
                &ids,
                p.direction(),
                i as u16,
                binding.terms_digest(),
                point.clone(),
            )
            .map_err(|_| Error::Crypto)?;
            shared.push(SharedBlindingBindingV1::bind_recovery_capsule(
                &pending,
                &material.capsule,
            ));
            points.push(point);
        }
        let shared: [SharedBlindingBindingV1; 2] = shared.try_into().map_err(|_| Error::Binding)?;
        if material.shared_bindings_v22() != &shared
            || material.capability.binding()
                != &shared[usize::from(binding.participant().protocol_index())]
        {
            return Err(Error::Binding);
        }
        let commitment = BpStatementV1::aggregate_commitment_from_shares(&points, amount)
            .map_err(|_| Error::Crypto)?;
        let statement = BpStatementV1::new(
            &chain,
            binding.session_id(),
            ids.to_vec(),
            amount,
            points,
            commitment,
            Some(*blake2b_256(material.capsule.as_bytes()).as_bytes()),
        )
        .map_err(|_| Error::Crypto)?;
        Ok(Self {
            binding,
            chain,
            shared,
            statement,
            complete: false,
            xmr_collateral_policy: None,
            templates_v17: None,
            round1_continuation_v25: None,
            xmr_value_v22: None,
            frozen_xmr_v22: None,
            verified_xmr_v22: None,
        })
    }
    /// D uses the separately authenticated native ceremony, not C's public
    /// artifact or caller-supplied share points. Its value is fixed by policy.
    pub(crate) fn for_xmr_cancelled_v22(
        parent: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        roster: crate::production_inputs::ProductionRosterLegV1,
        policy: &xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<Self, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        let scope = crate::production_dom_shared_bootstrap_v12::ProductionXmrCancelledBootstrapScopeV22::new(
            parent, roster, policy,
        )?;
        let binding = scope.binding();
        let shared = material.shared_bindings_v22().clone();
        let ids = roster.members.map(|member| member.participant_id.0);
        let local = usize::from(binding.participant().protocol_index());
        if chain.as_bytes() != &binding.chain_id()
            || material.capability.binding() != &shared[local]
        {
            return Err(Error::Binding);
        }
        for (index, public) in shared.iter().enumerate() {
            let direction = match roster.members[index].role {
                relay::SenderRoleV1::Initiator => DirectionV1::Initiator,
                relay::SenderRoleV1::Solver => DirectionV1::Responder,
                relay::SenderRoleV1::Observer => return Err(Error::Binding),
            };
            if public
                != &SharedBlindingBindingV1::bind_recovery_capsule(
                    public.pending_binding(),
                    &material.capsule,
                )
                || public.role() != direction
                || public.chain_id() != chain.as_bytes()
                || public.session_id() != &binding.session_id()
                || public.terms_hash() != &binding.terms_digest()
                || public.roster() != ids
                || public.participant_index() != index as u16
                || public.participant_id() != &ids[index]
            {
                return Err(Error::Binding);
            }
        }
        let points = shared
            .iter()
            .map(|p| p.share_point().clone())
            .collect::<Vec<_>>();
        let amount = policy.cancelled_noms();
        let commitment = BpStatementV1::aggregate_commitment_from_shares(&points, amount)
            .map_err(|_| Error::Crypto)?;
        let statement = BpStatementV1::new(
            &chain,
            binding.session_id(),
            ids.to_vec(),
            amount,
            points,
            commitment,
            Some(*blake2b_256(material.capsule.as_bytes()).as_bytes()),
        )
        .map_err(|_| Error::Crypto)?;
        Ok(Self {
            binding,
            chain,
            shared,
            statement,
            complete: false,
            xmr_collateral_policy: None,
            templates_v17: None,
            round1_continuation_v25: None,
            xmr_value_v22: Some(amount),
            frozen_xmr_v22: None,
            verified_xmr_v22: None,
        })
    }

    pub(crate) fn xmr_noise_graph_offer_v22(
        &self,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<
        Option<crate::production_noise_relay::ProductionNoiseGraphOfferV22>,
        ProductionBootstrapRuntimeErrorV16,
    > {
        let Some((policy, terms)) = &self.xmr_collateral_policy else {
            return Ok(None);
        };
        let bytes = material
            .runtime_public_record_v16(b"xmr-graph-offer-v22")?
            .ok_or(ProductionBootstrapRuntimeErrorV16::Binding)?;
        crate::production_noise_relay::ProductionNoiseGraphOfferV22::new(
            self.binding.route_id(),
            terms.clone(),
            policy.clone(),
            material.capability.binding().clone(),
            bytes,
        )
        .map(Some)
        .map_err(|_| ProductionBootstrapRuntimeErrorV16::Binding)
    }

    /// C commits the full XMR collateral, not the ordinary V17 wallet budget.
    /// A finalized range proof alone never authorizes funding this output.
    pub(crate) fn for_xmr_collateral_v22(
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        leg: &AuthenticatedContractsLegV1,
        terms: &kaystra_core::SettlementTermsV1,
        policy: &xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<Self, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        let validated = policy
            .policy()
            .validate_for(terms)
            .map_err(|_| Error::Binding)?;
        if &validated != policy
            || policy.terms_hash() != &binding.terms_digest()
            || policy.policy().session_id != binding.session_id()
            || policy.policy().dom_chain_id != binding.chain_id()
        {
            return Err(Error::Binding);
        }
        let mut driver = Self::new(binding, chain, leg, policy.collateral_noms(), material)?;
        driver.xmr_value_v22 = Some(policy.collateral_noms());
        driver.xmr_collateral_policy = Some((validated, terms.clone()));
        Ok(driver)
    }

    pub(crate) fn with_wallet_templates_v17(
        mut self,
        terms: &kaystra_core::SettlementTermsV1,
        state_dir: &std::path::Path,
        negotiated_tip: u64,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<Self, ProductionBootstrapRuntimeErrorV16> {
        if self.xmr_collateral_policy.is_some() {
            return Err(ProductionBootstrapRuntimeErrorV16::XmrRecoveryGraphRequired);
        }
        if terms.policy_version == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17 {
            self.templates_v17 = Some(templates_v17::TemplateDriverV17::new(
                self.binding,
                terms,
                state_dir,
                negotiated_tip,
                &self.statement,
            )?);
            self.templates_v17
                .as_ref()
                .ok_or(ProductionBootstrapRuntimeErrorV16::Binding)?
                .publish_local(material)?;
        }
        Ok(self)
    }
    pub(crate) const fn complete(&self) -> bool {
        self.complete
    }

    /// Native evidence retained only after the exact C/D range proof is durable.
    /// This is input to graph formation, never a funding or signing grant.
    pub(crate) fn frozen_xmr_formation_v22(
        &self,
    ) -> Option<&dom_scriptless_crypto::FrozenSharedOutputV1> {
        self.frozen_xmr_v22.as_ref()
    }

    /// Exact journal proof and capsule, revalidated by the native verifier.
    pub(crate) fn verified_xmr_output_v22(&self) -> Option<&dom_adaptor::VerifiedSharedOutputV1> {
        self.verified_xmr_v22.as_ref()
    }

    /// Recreate owned public formation evidence without consuming a share or
    /// nonce. The current Store head and exact capsule are re-audited.
    pub(crate) fn xmr_graph_output_v22<F: F6TransportPortV1>(
        &self,
        owner: &ProductionContractsV1<F>,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<
        Option<(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        )>,
        ProductionBootstrapRuntimeErrorV16,
    > {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        owner
            .validate_dom_binding(self.binding)
            .map_err(|_| Error::Binding)?;
        let local = usize::from(self.binding.participant().protocol_index());
        if material.capability.binding() != &self.shared[local] {
            return Err(Error::Binding);
        }
        let Some(verified) = self.verified_xmr_v22.as_ref() else {
            return Ok(None);
        };
        let value = self.xmr_value_v22.ok_or(Error::Binding)?;
        let frozen = owner
            .store
            .retained_shared_output_formation_v22(
                self.chain,
                self.binding.terms_digest(),
                value,
                &self.statement,
                &material.capsule,
            )?
            .ok_or(Error::Binding)?;
        if verified
            .output()
            .recovery_capsule()
            .map_err(|_| Error::Crypto)?
            .as_ref()
            .map(|capsule| capsule.as_bytes())
            != Some(material.capsule.as_bytes())
            || verified.commitment() != frozen.aggregate_commitment()
        {
            return Err(Error::Binding);
        }
        Ok(Some((frozen, verified.clone())))
    }

    pub(crate) fn step<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        material: &mut ProductionBoundDomSharedOutputV12,
        now: u64,
    ) -> Result<ProductionBootstrapStepV16, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        use ProductionBootstrapStepV16 as Step;
        owner
            .validate_dom_binding(self.binding)
            .map_err(|_| Error::Binding)?;
        let local = usize::from(self.binding.participant().protocol_index());
        if material.capability.binding() != &self.shared[local] {
            return Err(Error::Binding);
        }
        if self.complete {
            self.round1_continuation_v25 = None;
            return Ok(Step::Complete);
        }
        let head = owner.store.load_session(owner.session_id)?;
        if matches!(
            head.phase(),
            SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
        ) {
            self.round1_continuation_v25 = None;
            return Err(Error::Binding);
        }
        let early_phase = head.revision() < 6
            && matches!(
                head.phase(),
                SessionPhaseV1::Created
                    | SessionPhaseV1::TermsCommitted
                    | SessionPhaseV1::SharesCommitted
                    | SessionPhaseV1::SharesRevealed
            );
        // A restarted daemon may already be past OutputFinalized. Authenticate
        // the immutable BP terminal prefix instead of treating the current
        // claim/refund phase as if it were the next BP round.
        let completed_proof = if early_phase {
            None
        } else {
            owner.store.completed_operational_bp_proof_v16(
                self.chain,
                owner.session_id,
                self.binding.terms_digest(),
                &self.statement,
                &material.capsule,
            )?
        };
        let proof_complete = completed_proof.is_some();
        if proof_complete {
            self.round1_continuation_v25 = None;
        }
        if proof_complete && self.frozen_xmr_v22.is_none() {
            if let Some(value) = self.xmr_value_v22 {
                let frozen = owner
                    .store
                    .retained_shared_output_formation_v22(
                        self.chain,
                        self.binding.terms_digest(),
                        value,
                        &self.statement,
                        &material.capsule,
                    )?
                    .ok_or(Error::Binding)?;
                let proof = completed_proof.ok_or(Error::Binding)?.into_proof();
                let commitment = self.statement.aggregate_commitment().to_compressed_bytes();
                let output = dom_consensus::TransactionOutput::with_recovery_capsule(
                    dom_crypto::pedersen::Commitment::from_compressed_bytes(&commitment)
                        .map_err(|_| Error::Crypto)?,
                    proof.as_bytes().to_vec(),
                    &material.capsule,
                )
                .map_err(|_| Error::Crypto)?;
                let verified = dom_adaptor::VerifiedSharedOutputV1::from_retained_output_v14(
                    &output,
                    &commitment,
                )
                .map_err(|_| Error::Crypto)?;
                // Publish neither cache until both native checks succeed.
                self.frozen_xmr_v22 = Some(frozen);
                self.verified_xmr_v22 = Some(verified);
            }
        }
        // Once the final proof is durable, the V17 owner prepares template
        // ingress before retransmitting a pending BP or template message.
        if proof_complete {
            if let Some(driver) = self.templates_v17.as_mut() {
                let step = driver.step(owner, material, self.chain, &self.statement, now)?;
                self.complete = step == Step::Complete;
                return Ok(step);
            }
        }
        // Reissue ingress for the authenticated phase before replaying a
        // pending send. The peer may already have advanced while our ACK was
        // lost; retaining the previous phase's ingress would reject its reply.
        if !proof_complete {
            let ingress = if early_phase {
                PreparedContractsIngressV1::early(owner.store.prepare_early_transport_authority(
                    self.chain,
                    [&self.shared[0], &self.shared[1]],
                )?)
            } else {
                PreparedContractsIngressV1::operational_bp(
                    owner.store.prepare_operational_bp_transport_authority(
                        self.chain,
                        owner.session_id,
                        self.binding.terms_digest(),
                        &self.statement,
                        &material.capsule,
                    )?,
                )
            };
            owner.refresh_reissued_contracts_ingress_v16(ingress)?;
        }
        // First heal accepted-before-commit/outbox crash prefixes using the
        // owner's canonical request; never generate replacement payloads.
        match owner.store.resume_outbound_dsc1(owner.session_id)? {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if completion_v22::resumed_outbound_may_complete_v22(
                    request.message_type(),
                    proof_complete,
                    self.xmr_collateral_policy.is_some(),
                )? {
                    self.complete = true;
                    return Ok(Step::Complete);
                }
                if request.sender_id() != &owner.local_participant
                    || !(1..=10).contains(&request.message_type())
                {
                    return Err(Error::Binding);
                }
                let expiry = Self::expiry(material, now)?;
                owner.sign_commit_and_stage(*request, expiry)?;
                return Ok(Step::Staged);
            }
            OutboundDsc1RecoveryV1::Committed(committed) => {
                let message = SignedMessageV1::decode_exact(committed.signed_bytes())
                    .map_err(|_| Error::Binding)?;
                let kind = message.unsigned().kind() as u8;
                if completion_v22::resumed_outbound_may_complete_v22(
                    kind,
                    proof_complete,
                    self.xmr_collateral_policy.is_some(),
                )? {
                    self.complete = true;
                    return Ok(Step::Complete);
                }
                if committed.sender_id() != &owner.local_participant || !(1..=10).contains(&kind) {
                    return Err(Error::Binding);
                }
                let expiry = Self::expiry(material, now)?;
                owner
                    .relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*committed, expiry)
                    .map_err(|e| ProductionContractsOutboundErrorV1::Relay(e))?;
                return Ok(Step::Staged);
            }
            OutboundDsc1RecoveryV1::None => {}
        }
        if proof_complete {
            // C must retain the independently signed recovery graph before
            // becoming fundable. Ordinary wallet templates cannot replace it.
            if self.xmr_collateral_policy.is_some() {
                return Err(Error::XmrRecoveryGraphRequired);
            }
            self.complete = true;
            return Ok(Step::Complete);
        }
        let expiry = Self::expiry(material, now)?;
        if early_phase {
            let authority = owner.store.prepare_early_transport_authority(
                self.chain,
                [&self.shared[0], &self.shared[1]],
            )?;
            let position = usize::try_from(head.revision()).map_err(|_| Error::Binding)?;
            if position >= 6 {
                return Err(Error::Binding);
            }
            let expected = if position % 2 == 0 {
                DirectionV1::Initiator
            } else {
                DirectionV1::Responder
            };
            let payload = if position < 2 || self.shared[local].role() != expected {
                None
            } else {
                let reveal = self.reveal(material, *authority.context_commitment())?;
                Some(if position < 4 {
                    EarlyShareCommitmentV1::new(&reveal).to_bytes().to_vec()
                } else {
                    reveal.to_bytes().to_vec()
                })
            };
            let request = owner
                .store
                .prepare_next_early_dsc1_signing_request(&authority, payload.as_deref())?;
            owner.refresh_reissued_contracts_ingress_v16(PreparedContractsIngressV1::early(
                authority,
            ))?;
            if let Some(request) = request {
                owner.sign_commit_and_stage(request, expiry)?;
                return Ok(Step::Staged);
            }
            return Ok(Step::AwaitingPeer);
        }
        let authority = owner.store.prepare_operational_bp_transport_authority(
            self.chain,
            owner.session_id,
            self.binding.terms_digest(),
            &self.statement,
            &material.capsule,
        )?;
        let continuation = owner.store.resume_operational_bp_continuation(
            self.chain,
            owner.session_id,
            self.binding.terms_digest(),
            &self.statement,
            &material.capsule,
        )?;
        let stage = continuation.stage();
        let mask = continuation.accepted_participants();
        // Exactly one finalizer is scheduled, chosen from the frozen roster.
        // The native protocol still verifies the sole proof independently.
        if (stage == Stage::Finalize && local != 1)
            || (stage != Stage::Finalize && (mask[local] || (local == 1 && !mask[0])))
        {
            owner.refresh_reissued_contracts_ingress_v16(
                PreparedContractsIngressV1::operational_bp(authority),
            )?;
            return Ok(Step::AwaitingPeer);
        }
        let nonce = CollaborativeBpNonceBindingV1::from_statement(&self.statement, local as u16)
            .map_err(|_| Error::Crypto)?;
        if stage != Stage::CommonCommit
            && material
                .runtime_public_record_v16(b"bp-start-v16")?
                .as_deref()
                != Some(nonce.binding_digest_v1().as_slice())
        {
            return Err(Error::Vault);
        }
        let state = material
            .vault
            .as_mut()
            .ok_or(Error::Vault)?
            .collaborative_bp_custody_v16(&nonce)
            .map_err(|_| Error::Vault)?;
        let driver = material
            .capability
            .bind_collaborative_range_proof_v1(
                &self.statement,
                material.capsule.as_bytes().to_vec(),
            )
            .map_err(|_| Error::Crypto)?;
        let payload: Zeroizing<Vec<u8>> = match stage {
            Stage::CommonCommit | Stage::CommonReveal | Stage::RoundCommit | Stage::Round1 => {
                let (pending, commitment) = match state {
                    CollaborativeBpCustodyV16::Absent
                        if stage == Stage::CommonCommit
                            && material
                                .runtime_public_record_v16(b"bp-start-v16")?
                                .is_none() =>
                    {
                        material
                            .capability
                            .begin_collaborative_range_proof_v1(
                                &self.statement,
                                material.vault.as_mut().ok_or(Error::Vault)?,
                            )
                            .map_err(|_| Error::Vault)?
                    }
                    CollaborativeBpCustodyV16::Nonce => material
                        .capability
                        .resume_collaborative_range_proof_v16(
                            &self.statement,
                            material.vault.as_mut().ok_or(Error::Vault)?,
                        )
                        .map_err(|_| Error::Vault)?,
                    _ => return Err(Error::Vault),
                };
                material.retain_runtime_public_v16(b"bp-start-v16", &nonce.binding_digest_v1())?;
                Zeroizing::new(match stage {
                    Stage::CommonCommit => commitment.to_vec(),
                    Stage::CommonReveal => pending.reveal_bytes().to_vec(),
                    Stage::RoundCommit | Stage::Round1 => {
                        let secrets = continuation.finish_common_nonce(pending)?;
                        let round1 = driver
                            .round1_with_continuation_v25(
                                &self.statement,
                                secrets,
                                &mut self.round1_continuation_v25,
                            )
                            .map_err(|_| Error::Crypto)?;
                        if stage == Stage::RoundCommit {
                            round1.reveal_commitment().to_vec()
                        } else {
                            round1.to_bytes().to_vec()
                        }
                    }
                    _ => return Err(Error::Binding),
                })
            }
            Stage::Round2 => {
                let durable = match state {
                    CollaborativeBpCustodyV16::Nonce => {
                        let (pending, _) = material
                            .capability
                            .resume_collaborative_range_proof_v16(
                                &self.statement,
                                material.vault.as_mut().ok_or(Error::Vault)?,
                            )
                            .map_err(|_| Error::Vault)?;
                        let secrets = continuation.finish_common_nonce(pending)?;
                        driver
                            .round1_with_continuation_v25(
                                &self.statement,
                                secrets,
                                &mut self.round1_continuation_v25,
                            )
                            .map_err(|_| Error::Crypto)?;
                        let aggregate = continuation.aggregate_round1()?;
                        // The same private continuation is moved, never
                        // cloned. The original vault-backed round2 still
                        // persists/consumes custody before bytes can leave.
                        let secrets = self
                            .round1_continuation_v25
                            .take()
                            .ok_or(Error::Crypto)?
                            .into_local_for_round2_v25();
                        driver
                            .round2_vault_backed_v1(
                                &self.statement,
                                &secrets,
                                &aggregate,
                                material.vault.as_mut().ok_or(Error::Vault)?,
                            )
                            .map_err(|_| Error::Vault)?
                    }
                    CollaborativeBpCustodyV16::Round2 | CollaborativeBpCustodyV16::Proof => {
                        self.round1_continuation_v25 = None;
                        driver
                            .resume_persisted_round2_v1(
                                &self.statement,
                                local as u16,
                                material.vault.as_mut().ok_or(Error::Vault)?,
                            )
                            .map_err(|_| Error::Vault)?
                    }
                    _ => return Err(Error::Vault),
                };
                Zeroizing::new(
                    continuation
                        .require_round2_transport(local as u16, durable)?
                        .to_vec(),
                )
            }
            Stage::Finalize => {
                let (r1, r2) = continuation.into_finalize_aggregates()?;
                let proof = match state {
                    CollaborativeBpCustodyV16::Round2 => driver
                        .finalize_vault_backed_v1(
                            &self.statement,
                            local as u16,
                            &r1,
                            &r2,
                            material.vault.as_mut().ok_or(Error::Vault)?,
                        )
                        .map_err(|_| Error::Vault)?,
                    CollaborativeBpCustodyV16::Proof => driver
                        .resume_persisted_proof_v1(
                            &self.statement,
                            local as u16,
                            &r1,
                            material.vault.as_mut().ok_or(Error::Vault)?,
                        )
                        .map_err(|_| Error::Vault)?,
                    _ => return Err(Error::Vault),
                };
                Zeroizing::new(proof.into_proof().as_bytes().to_vec())
            }
            Stage::Complete => return Err(Error::Binding),
        };
        let request = owner
            .store
            .prepare_next_operational_bp_dsc1_signing_request(&authority, &payload)?;
        owner.refresh_reissued_contracts_ingress_v16(
            PreparedContractsIngressV1::operational_bp(authority),
        )?;
        if let Some(request) = request {
            owner.sign_commit_and_stage(request, expiry)?;
            Ok(Step::Staged)
        } else {
            Ok(Step::AwaitingPeer)
        }
    }
    fn reveal(
        &self,
        material: &mut ProductionBoundDomSharedOutputV12,
        context: [u8; 32],
    ) -> Result<EarlyShareRevealV1, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        if let Some(bytes) = material.runtime_public_record_v16(b"dsc1-reveal-v16")? {
            return EarlyShareRevealV1::from_bytes(
                &bytes,
                &self.chain,
                self.statement.participant_ids(),
                &context,
            )
            .map_err(|_| Error::Crypto);
        }
        let reveal = material
            .capability
            .early_transport_reveal_v16(context)
            .map_err(|_| Error::Crypto)?;
        material.retain_runtime_public_v16(b"dsc1-reveal-v16", &reveal.to_bytes())?;
        Ok(reveal)
    }
    pub(crate) fn expiry(
        material: &mut ProductionBoundDomSharedOutputV12,
        now: u64,
    ) -> Result<TimelockSpec, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        if now == 0 {
            return Err(Error::Expired);
        }
        let value = if let Some(bytes) = material.runtime_public_record_v16(b"relay-expiry-v16")? {
            u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Binding)?)
        } else {
            let value = now
                .checked_add(ENVELOPE_LIFETIME_SECONDS)
                .ok_or(Error::Binding)?;
            material.retain_runtime_public_v16(b"relay-expiry-v16", &value.to_le_bytes())?;
            value
        };
        if now > value {
            return Err(Error::Expired);
        }
        Ok(TimelockSpec::TimestampSeconds { value })
    }
}
