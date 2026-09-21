//! Stage-12 production ownership for the central Relay and both Contracts workers.
//!
//! Stage 10 hands this module the parent and optional XMR-D Contracts openings
//! and their linear early-ingress authorities. Stage 11 hands it the two real F6
//! activation authorities. This boundary derives every Relay fact again from
//! the authenticated V8 inputs, opens the seven Relay authorities in their
//! canonical order, and then embeds each Store in exactly one
//! [`ProductionContractsV1`] owner.
//!
//! Construction deliberately does not complete the provisioning journal. The
//! returned value remains opaque until both retained F6 histories have been
//! reauthenticated, the caller has durably completed Stage 12, and
//! [`ProductionRelayStage12RecoveredV1::finish`] has re-read that fact from the
//! same journal.
#[path = "production_relay_downstream_claim_v23.rs"]
mod downstream_claim_v23;

#[path = "production_relay_xmr_enrollment_v23.rs"]
mod xmr_enrollment_v23;

use std::{path::Path, rc::Rc};

#[path = "production_relay_cancelled_v22.rs"]
mod cancelled_v22;
#[path = "production_relay_xmr_graph_v23.rs"]
pub(crate) mod graph_v23;
#[path = "production_relay_xmr_auxiliary_v23.rs"]
mod xmr_auxiliary_v23;

/// Closed token naming one XMR graph lifecycle state. Never a digest, a
/// secret or a foreign error string: every arm is a fixed enum name.
pub(crate) fn graph_lifecycle_token_v25(lifecycle: &graph_v23::GraphLifecycleV23) -> &'static str {
    use graph_v23::GraphLifecycleV23 as L;
    match lifecycle {
        L::Awaiting => "awaiting",
        L::Signing(_) => "signing",
        L::Completing => "completing",
        L::Produced(_) => "produced",
        L::Custodied { .. } => "custodied",
        L::Failed => "failed",
    }
}

/// DIAG(temporary): name the funding gate that held this leg back. Every one
/// of the early exits of `step_f7_funding_v20` used to be a bare `Ok(())`,
/// so a leg could hold at the same gate for two hours without a single line
/// of output. Printed only when the gate token changes, so a stable gate
/// costs one line per leg for the whole run.
fn diag_f7_funding_gate_v25(leg: LegIdV1, gate: &str) {
    use std::cell::RefCell;
    thread_local! {
        static LAST_GATE_V25: RefCell<[String; 2]> =
            const { RefCell::new([String::new(), String::new()]) };
    }
    let index = match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    };
    LAST_GATE_V25.with(|last| {
        let mut last = last.borrow_mut();
        if last[index] != gate {
            last[index].clear();
            last[index].push_str(gate);
            eprintln!("DOM_F7_FUNDING_GATE_V25 leg={leg:?} gate={gate}");
        }
    });
}

use dom_adaptor::{SharedBlindingBindingV1, TrustedChainIdV1};
use dom_scriptless_chain_adapter::DomHttpChainAdapterV1;
use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use dom_scriptless_store::SessionTransportIdentityReferenceV1;
use kaystra_core::types::ParticipantId;
use relay::{
    production::{
        ProductionRelayCreationStateV1, ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1,
    },
    SenderRoleV1,
};
use rfq::v2::SettlementPositionV2;
use route_executor::LegIdV1;
use route_transport::{
    DurableFrameReassemblerConfigV2, DurableInboxConfigV1, DurableRelaySenderConfigV1,
    RouteWireContextV1,
};
use zeroize::Zeroizing;

use crate::{
    production_chain_signers::ProductionChainSignerAuthoritiesV1,
    production_config::{
        ProductionPathRoleV1, ProductionRelayAuthorityPinsV6, ValidatedProductionBootstrapV1,
        ValidatedProductionLayoutV1,
    },
    production_contracts::ProductionContractsV1,
    production_contracts_session_bootstrap::{
        ProductionContractsSessionBootstrapV1, ProductionContractsSessionLegBootstrapV1,
    },
    production_f6_activation::ProductionF6PairActivationAuthorityV2,
    production_f6_activation::{ProductionF6PairProvenanceV2, ProductionF6PairRuntimeReceiverV2},
    production_f6_lifecycle::{ProductionAwaitingF6PinsV2, ProductionF6LifecyclePortV2},
    production_inputs::{
        AuthenticatedProductionInputsV1, ProductionRosterLegV1, ProductionRoutePositionV1,
    },
    production_provisioning::{
        DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
        ProductionProvisioningStageV1,
    },
    relay_worker::{PreparedContractsIngressV1, RelayWorkerConfigV1, RelayWorkerPathsV1},
};

/// Stage-12 open intent supplied by the composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionRelayStage12ModeV1 {
    /// Provision or resume only a pristine journaled creation prefix.
    CreateOrResume,
    /// Reopen only the complete retained authorities.
    ReopenExisting,
}

/// Redacted Stage-12 refusal. No variant carries a path, key, roster member or
/// nested storage error into the operator-facing surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionRelayStage12ErrorV1 {
    #[error("authenticated Stage-12 Relay binding is inconsistent")]
    InvalidBinding,
    #[error("Stage-12 provisioning state is inconsistent")]
    ProvisioningRefused,
    #[error("central production Relay authority is unavailable")]
    RelayRefused,
    #[error("production Contracts/Relay owner is unavailable")]
    ContractsRefused,
    #[error("production F6 lifecycle authority is unavailable")]
    F6Refused,
}

thread_local! {
    static LEASE_PHASE_V25: std::cell::Cell<&'static str> = const { std::cell::Cell::new("start") };
}

/// Diagnostic marker of the phase currently holding the DOM actuator lease.
/// Static names only; read by the renewal hook to name an oversized gap.
pub(crate) fn mark_lease_phase_v25(phase: &'static str) {
    LEASE_PHASE_V25.with(|cell| cell.set(phase));
}

pub(crate) fn lease_phase_v25() -> &'static str {
    LEASE_PHASE_V25.with(std::cell::Cell::get)
}

/// Move-only Stage-12 construction request.
///
/// The relay signing secrets remain zeroizing owners until the exact
/// `ProductionContractsV1` constructors consume their unavoidable fixed-size
/// copies. No secret is retained in the returned owner.
pub(crate) struct ProductionRelayStage12RequestV1<'authority> {
    pub(crate) xmr_graph_vault_provisioner_v23:
        crate::production_dom_vaults_v12::ProductionXmrGraphVaultProvisionerV23,
    pub(crate) bootstrap: &'authority ValidatedProductionBootstrapV1,
    pub(crate) inputs: &'authority AuthenticatedProductionInputsV1,
    pub(crate) chain_signers: &'authority ProductionChainSignerAuthoritiesV1,
    pub(crate) contracts: ProductionContractsSessionBootstrapV1,
    pub(crate) upstream_activation: ProductionF6PairActivationAuthorityV2,
    pub(crate) downstream_activation: ProductionF6PairActivationAuthorityV2,
    pub(crate) upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) mode: ProductionRelayStage12ModeV1,
    pub(crate) stage_before_begin: ProductionProvisioningStageStateV1,
    pub(crate) stage: ProductionProvisioningStageStateV1,
}

/// One live Contracts owner and the exact public material retained beside it.
///
/// Fields remain private so later stages cannot bypass the single owner with a
/// raw Store reopen or reconstruct Noise identities from caller-shaped bytes.
pub(crate) struct ProductionRelayStage12LegOwnerV1 {
    contracts: ProductionContractsV1<ProductionF6LifecyclePortV2>,
    wire: RouteWireContextV1,
    trusted_chain_id: TrustedChainIdV1,
    shared_blinding_bindings: [SharedBlindingBindingV1; 2],
    noise_identity_references: [SessionTransportIdentityReferenceV1; 2],
    f6_pair_provenance: ProductionF6PairProvenanceV2,
}

impl ProductionRelayStage12LegOwnerV1 {
    pub(crate) const fn wire(&self) -> RouteWireContextV1 {
        self.wire
    }

    pub(crate) const fn trusted_chain_id(&self) -> TrustedChainIdV1 {
        self.trusted_chain_id
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn shared_blinding_bindings(&self) -> &[SharedBlindingBindingV1; 2] {
        &self.shared_blinding_bindings
    }

    /// Local reference first, exact remote reference second. Both values came
    /// from the retained Store after Stage-10 convergence.
    pub(crate) const fn noise_identity_references(
        &self,
    ) -> &[SessionTransportIdentityReferenceV1; 2] {
        &self.noise_identity_references
    }

    pub(crate) fn contracts_mut(
        &mut self,
    ) -> &mut ProductionContractsV1<ProductionF6LifecyclePortV2> {
        &mut self.contracts
    }
}

/// Sole live owner produced by Stage 12.
///
/// It intentionally implements neither `Clone` nor `Debug`. The central Relay,
/// both Contracts workers, the shared transport identity and the live DOM
/// adapter cannot be separated into independently reopened graphs.
pub(crate) struct ProductionRelayStage12OwnerV1 {
    xmr_auxiliary_provisioners_v23: [xmr_auxiliary_v23::XmrAuxiliaryRelayProvisionerV23; 2],
    xmr_auxiliary_relays_v23: [[Option<xmr_auxiliary_v23::XmrAuxiliaryRelayOwnerV23>; 2]; 2],
    xmr_graph_vault_provisioner_v23:
        crate::production_dom_vaults_v12::ProductionXmrGraphVaultProvisionerV23,
    xmr_recovery_signing_v23:
        [Option<crate::production_contracts::ProductionXmrRecoverySigningOwnerV23>; 2],
    xmr_graph_signing_admission_deferred_v23: [bool; 2],
    cancelled_v22: [Option<cancelled_v22::CancelledRelayOwnerV22>; 2],
    bootstrap_v16: [Option<crate::production_contracts::ProductionBootstrapLegV16>; 2],
    xmr_graph_templates_v23: [graph_v23::GraphLifecycleV23; 2],
    xmr_custody_resources_v23: [Option<graph_v23::PendingXmrCustodyV23>; 2],
    xmr_f7_resources_v23: [Option<crate::production_xmr_sweep::ProductionXmrF7ResourcesV23>; 2],
    xmr_f7_observers_v23: [Option<crate::production_contracts::ProductionSelectedF7ObserverV12>; 2],
    xmr_graph_candidates_v22:
        [Option<crate::production_noise_relay::ProductionReceivedXmrGraphCandidateV22>; 2],
    xmr_graph_public_v22:
        [Option<crate::production_noise_relay::ProductionXmrGraphPublicMaterialV22>; 2],
    xmr_graph_setup_v22:
        [Option<crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22>; 2],
    _private_bootstrap_v13:
        Option<crate::production_contracts_bootstrap::producer_v13::MountedBootstrapV13>,
    relay: ProductionRelayV1,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    dom_chain_adapter: Option<DomHttpChainAdapterV1>,
    upstream: ProductionRelayStage12LegOwnerV1,
    downstream: ProductionRelayStage12LegOwnerV1,
    initial_relay_time_floor_seconds: u64,
    /// Legs whose applied F6 history replay is waiting on the paired leg.
    /// F6 activation is a pair: an applied upstream RFQ cannot re-activate
    /// until the downstream RFQ has been re-registered, so a sequential
    /// per-leg replay would refuse a correct history. A deferred leg keeps
    /// refusing new F6 (`RecoveryRequired`) and the route cannot become ready
    /// until its exact-duplicate replay completes.
    f6_recovery_deferred_v25: [bool; 2],
}

impl ProductionRelayStage12OwnerV1 {
    /// Replays every still-deferred leg's applied F6 history. Pair
    /// activation makes the replay order-dependent, so passes repeat while
    /// they make progress: the downstream replay completes the pair and the
    /// upstream replay then re-activates as an exact duplicate. Only the
    /// pair's `Awaiting` refusal defers a leg; every other refusal — a
    /// non-duplicate, a different receipt, a poisoned or corrupt authority —
    /// stays fatal exactly as before.
    pub(crate) fn retry_deferred_f6_recovery_v25(
        &mut self,
    ) -> Result<(), ProductionRelayStage12ErrorV1> {
        use crate::production_contracts::ProductionContractsF6RecoveryErrorV2 as RecoveryError;
        use crate::production_f6_lifecycle::ProductionF6LifecycleErrorV2 as LifecycleError;
        use route_transport::F6AppliedReplayErrorV1 as ReplayError;

        loop {
            let mut progressed = false;
            for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
                .into_iter()
                .enumerate()
            {
                if !self.f6_recovery_deferred_v25[index] {
                    continue;
                }
                match self
                    .leg_mut(leg)
                    .contracts
                    .recover_production_f6_applied_history()
                {
                    Ok(_) => {
                        self.f6_recovery_deferred_v25[index] = false;
                        progressed = true;
                    }
                    Err(RecoveryError::Replay(ReplayError::F6(LifecycleError::Awaiting(_)))) => {}
                    Err(_) => return Err(ProductionRelayStage12ErrorV1::F6Refused),
                }
            }
            if !progressed || self.f6_recovery_deferred_v25 == [false; 2] {
                return Ok(());
            }
        }
    }

    /// Whether any leg's applied F6 history still awaits its paired replay.
    pub(crate) const fn f6_recovery_deferred_v25(&self) -> bool {
        self.f6_recovery_deferred_v25[0] || self.f6_recovery_deferred_v25[1]
    }
    fn pending_xmr_graph_commit_relay_envelope_v23(
        &self,
        session_id: [u8; 32],
    ) -> Result<bool, crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
        for bytes in self
            .relay
            .pending_canonical_envelopes_for_session(&session_id)
            .map_err(|_| Error::Binding)?
        {
            let envelope = relay::RelayEnvelopeV1::decode(&bytes).map_err(|_| Error::Binding)?;
            if envelope.session_id != session_id {
                return Err(Error::Binding);
            }
            let message =
                dom_scriptless_transport::SignedMessageV1::decode_exact(&envelope.payload)
                    .map_err(|_| Error::Binding)?;
            if message.unsigned().kind() as u8 == 0x18 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn step_xmr_recovery_signing_v23(
        &mut self,
        leg: LegIdV1,
        now: u64,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        self.step_xmr_recovery_signing_with_renewal_v25(leg, now, &mut || Ok(()))
    }

    /// Same recovery signing step, renewing the retained DOM actuator lease
    /// around each auxiliary edge.
    ///
    /// Opening one auxiliary Relay creates three durable stores and then runs
    /// that edge's ceremony. Doing both edges under a single renewal window is
    /// what let the lease die exactly in the round where the Cancel and
    /// Compensation owners first appear.
    fn step_xmr_recovery_signing_with_renewal_v25(
        &mut self,
        leg: LegIdV1,
        now: u64,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        let Some(graph) = self.xmr_graph_templates_v23[index].signing()? else {
            return self.step_xmr_graph_custody_v23(leg);
        };
        let setup = self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Binding)?;
        let binding = setup.binding();
        if self.xmr_recovery_signing_v23[index].is_none() {
            let head = match leg {
                LegIdV1::Upstream => self.upstream.contracts.contracts_session_status()?,
                LegIdV1::Downstream => self.downstream.contracts.contracts_session_status()?,
            };
            if head.revision >= 19
                && head.phase == dom_scriptless_store::SessionPhaseV1::TemplatesCommitted
            {
                if self.pending_xmr_graph_commit_relay_envelope_v23(binding.session_id())? {
                    // A local Relay ACK only proves the final graph commit was
                    // enqueued. Recovery signing may emit 0x0c only after the
                    // central queue no longer retains this session's 0x18.
                    return Ok(());
                }
                if !self.xmr_graph_signing_admission_deferred_v23[index] {
                    self.xmr_graph_signing_admission_deferred_v23[index] = true;
                    return Ok(());
                }
            }
        }
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(Error::Binding)?
            ._shares[index];
        let expiry = crate::production_contracts::ProductionBootstrapLegV16::expiry(material, now)?;
        let owner = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        mark_lease_phase_v25("recovery_contracts_step");
        owner.contracts.step_xmr_recovery_signing_v23(
            &mut self.xmr_recovery_signing_v23[index],
            &self.xmr_graph_vault_provisioner_v23,
            material,
            binding,
            owner.trusted_chain_id,
            &graph.templates,
            &graph.keys,
            expiry,
            renew_actuator_lease,
        )?;
        let Some(signing) = self.xmr_recovery_signing_v23[index].as_mut() else {
            return Ok(());
        };
        self.xmr_graph_signing_admission_deferred_v23[index] = true;
        use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23 as Edge;
        for (slot, edge) in [Edge::Cancel, Edge::Compensation].into_iter().enumerate() {
            renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25)?;
            mark_lease_phase_v25(if slot == 0 {
                "recovery_edge_cancel"
            } else {
                "recovery_edge_compensation"
            });
            if self.xmr_auxiliary_relays_v23[index][slot].is_none() {
                let binding = signing.auxiliary_binding_v23(edge).ok_or(Error::Binding)?;
                self.xmr_auxiliary_relays_v23[index][slot] =
                    Some(self.xmr_auxiliary_provisioners_v23[index].open(owner, binding, edge)?);
                renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25)?;
            }
            self.xmr_auxiliary_relays_v23[index][slot]
                .as_mut()
                .ok_or(Error::Binding)?
                .contracts
                .step_xmr_auxiliary_signing_v23(
                    signing,
                    edge,
                    binding,
                    owner.trusted_chain_id,
                    &graph.templates,
                    &graph.keys,
                    expiry,
                )?;
            renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25)?;
        }
        if setup.claim_context_v23().is_none() {
            // Composition is installed after F6 admission; do not fabricate a role.
            return Ok(());
        }
        // The equations are owned only after reauditing all three native
        // journals. No template is consumed while a round is incomplete.
        let completed = owner.contracts.prepare_xmr_graph_completion_v23(
            signing,
            &graph.templates,
            &graph.keys,
        )?;
        // Renew between reauditing the three journals and consuming the
        // templates, and never after the lifecycle has left Signing: a failed
        // renewal must not strand the graph in Completing.
        renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25)?;
        if let Some(completed) = completed {
            let role = owner.contracts.bind_xmr_graph_custody_role_v23(
                setup,
                owner.trusted_chain_id,
                &graph.templates,
                &graph.keys,
            )?;
            use graph_v23::GraphLifecycleV23 as State;
            let state =
                std::mem::replace(&mut self.xmr_graph_templates_v23[index], State::Completing);
            let State::Signing(prepared) = state else {
                self.xmr_graph_templates_v23[index] = State::Failed;
                return Err(Error::Binding);
            };
            match completed.complete(prepared.templates) {
                Ok(produced) => {
                    self.xmr_graph_templates_v23[index] =
                        State::Produced(graph_v23::SignedXmrGraphV23 { produced, role })
                }
                Err(error) => {
                    self.xmr_graph_templates_v23[index] = State::Failed;
                    return Err(error);
                }
            }
            // Keep the signer vaults and auxiliary Relays alive for final ACK
            // recovery. Produced is not durable custody or funding readiness.
        }
        // Mounting custody may write the encrypted archive for the first time.
        renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25)?;
        self.step_xmr_graph_custody_v23(leg)
    }

    pub(crate) fn xmr_noise_graph_offer_v22(
        &self,
        leg: LegIdV1,
    ) -> Result<
        Option<crate::production_noise_relay::ProductionNoiseGraphOfferV22>,
        crate::production_contracts::ProductionBootstrapRuntimeErrorV16,
    > {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        let Some(driver) = &self.bootstrap_v16[index] else {
            return Ok(None);
        };
        let material = &self
            ._private_bootstrap_v13
            .as_ref()
            .ok_or(Error::Binding)?
            ._shares[index];
        driver.xmr_noise_graph_offer_v22(material)
    }

    /// Graph candidate with separate F6 principal retention. Retaining this
    /// authenticated public proof is not an economic/funding acknowledgement.
    pub(crate) fn receive_xmr_graph_candidate_v22(
        &mut self,
        leg: LegIdV1,
        candidate: crate::production_noise_relay::ProductionReceivedXmrGraphCandidateV22,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::GraphCandidateSurfaceV25 as Surface;
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
        // Each of these surfaces is established when this owner is
        // constructed, so an absence is a composition fault, not a race a
        // later round repairs. Name the surface instead of collapsing all
        // five into one opaque Binding refusal; every check against the
        // candidate's own content stays Binding as before.
        let missing = Error::GraphCandidateSurfaceMissingV25;
        let context = self
            .xmr_noise_graph_offer_v22(leg)?
            .ok_or(missing(Surface::NoiseOffer))?;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        let setup = self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(missing(Surface::GraphSetup))?;
        context
            .require_graph_setup_v22(setup)
            .map_err(|_| Error::Binding)?;
        let public = context
            .assemble_peer_material_v22(candidate.bytes())
            .map_err(|_| Error::Binding)?;
        if self.xmr_graph_candidates_v22[index]
            .as_ref()
            .is_some_and(|old| old != &candidate)
        {
            return Err(Error::Binding);
        }
        // The cancelled-contracts owner this candidate binds to is moved out of
        // `_private_bootstrap_v13._cancelled_contracts` into the prepared
        // `cancelled_v22` relay owner at Stage-12 construction (see the
        // `.take()` there). Read the surviving prepared owner here; the emptied
        // bootstrap slot would otherwise always report the surface as absent.
        let xmr_funder = self.cancelled_v22[index]
            .as_ref()
            .ok_or(missing(Surface::CancelledContracts))?
            .policy
            .policy()
            .xmr_funder;
        let private = self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(missing(Surface::PrivateBootstrap))?;
        let material = &mut private._shares[index];
        if material.capability.binding().participant_id() != &xmr_funder {
            // The publish target must exist before anything is retained, so
            // an awaiting round leaves no partial state behind.
            let publisher = private._f6_native_principals_v25[index]
                .as_ref()
                .ok_or(missing(Surface::F6PrincipalSlot))?;
            // Only the received beneficiary packet may populate this slot.
            // Persist and read it back before the factory can bind any RFQ.
            let principal = material
                .retain_peer_f6_principal_v25(&context, &candidate)
                .map_err(|_| Error::Binding)?;
            publisher.publish(principal).map_err(|_| Error::Binding)?;
        }
        self.xmr_graph_public_v22[index] = Some(public);
        self.xmr_graph_candidates_v22[index] = Some(candidate);
        self.prepare_xmr_graph_templates_v23(leg)
    }

    pub(crate) fn cancelled_noise_scope_v22(
        &self,
        leg: LegIdV1,
    ) -> Option<(
        TrustedChainIdV1,
        RouteWireContextV1,
        [SessionTransportIdentityReferenceV1; 2],
        [u8; 32],
    )> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        self.cancelled_v22[index].as_ref().map(|owner| {
            (
                owner.chain,
                owner.wire,
                owner.references.clone(),
                owner.parent_terms,
            )
        })
    }

    pub(crate) fn cancelled_and_relay_mut_v22(
        &mut self,
        leg: LegIdV1,
    ) -> Option<(
        &mut ProductionContractsV1<crate::relay_worker::UnavailableF6AuthorityV1>,
        &mut ProductionRelayV1,
    )> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        self.cancelled_v22[index]
            .as_mut()
            .map(|owner| (&mut owner.contracts, &mut self.relay))
    }

    pub(crate) fn reopen_xmr_recovery_v22(
        &mut self,
        leg: LegIdV1,
        parent: cap_std::fs::Dir,
        directory: &str,
        key: dom_scriptless_crypto::XmrRecoverySealKeyV11,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
    ) -> Result<
        Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
        settlement_coordinator::ChildAuthorityRefusalV1,
    > {
        let selected = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        selected.contracts.reopen_xmr_recovery_v22(
            selected.trusted_chain_id,
            parent,
            directory,
            key,
            scanner.xmr_recovery_client_v12(),
        )
    }

    /// Drive the selected post-M.8 DOM signer with that leg's private bootstrap.
    pub(crate) fn step_post_m8_claim_v22(
        &mut self,
        leg: LegIdV1,
        binding: dom_actuator::DomSessionBindingV1,
        pending: &mut Option<crate::production_contracts::ProductionContractsConsumedPostAnchorV2>,
        scanner: Rc<crate::production_child_dom::ProductionDomF7ScannerAuthorityV1>,
        bitcoin: Rc<adapter_btc_live::BitcoinCoreRpcClientV1>,
        now: u64,
    ) -> Result<bool, crate::production_contracts::ProductionPostM8ErrorV22> {
        use crate::production_contracts::ProductionPostM8ErrorV22 as Error;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.bootstrap_v16[index]
            .as_ref()
            .is_some_and(|driver| !driver.complete())
        {
            return Ok(false);
        }
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(Error::Scope)?
            ._shares[index];
        let selected = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        selected.contracts.step_post_m8_claim_v22(
            material,
            binding,
            selected.trusted_chain_id,
            pending,
            scanner,
            bitcoin,
            now,
        )
    }

    /// Progress the native universal claim round with the exact selected child
    /// identity and the bootstrap's sole claim share and nonce-vault owner.
    pub(crate) fn step_f7_claim_v20(
        &mut self,
        leg: LegIdV1,
        binding: dom_actuator::DomSessionBindingV1,
        scanner: std::rc::Rc<crate::production_child_dom::ProductionDomF7ScannerAuthorityV1>,
        observer: &mut Option<crate::production_contracts::ProductionF7ObserverPlanV20>,
        funding: crate::production_child_router::ProductionRetainedFundingIdV20,
        now: u64,
    ) -> Result<(), crate::production_contracts::ProductionF7RuntimeErrorV12> {
        use crate::production_contracts::ProductionF7RuntimeErrorV12 as Error;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        let Some(driver) = self.bootstrap_v16[index].as_ref() else {
            return Ok(());
        };
        if !driver.complete() {
            return Ok(());
        }
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(Error::Scope)?
            ._shares[index];
        let selected = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        selected.contracts.step_bootstrapped_f7_claim_v20(
            material,
            binding,
            selected.trusted_chain_id,
            scanner,
            observer,
            funding,
            now,
        )
    }

    /// Select native encrypted-custody readiness only for an admitted XMR graph;
    /// other families retain their existing refund transport face.
    pub(crate) fn dom_refund_face_for_selected_v23(
        &self,
        leg: LegIdV1,
        scope: crate::production_refund_arming::ProductionDomRefundFaceScopeV1<'_>,
        binding: dom_actuator::DomSessionBindingV1,
    ) -> Result<
        crate::production_refund_arming::ProductionDomRefundFaceV1,
        crate::production_refund_arming::ProductionRefundArmingOpenErrorV1,
    > {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        let selected = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        if self.xmr_graph_setup_v22[index].is_some() {
            selected
                .contracts
                .dom_refund_face_native_xmr_v23(scope, binding)
        } else {
            selected.contracts.dom_refund_face(scope, binding)
        }
    }

    /// Native XMR uses its admitted setup and custody-bound observer, not an
    /// EVM/Solana child identity or the legacy bootstrap/M.8 readiness path.
    pub(crate) fn step_native_xmr_f7_claim_v23(
        &mut self,
        leg: LegIdV1,
        binding: dom_actuator::DomSessionBindingV1,
        scanner: std::rc::Rc<crate::production_child_dom::ProductionDomF7ScannerAuthorityV1>,
        now: u64,
    ) -> Result<(), crate::production_contracts::ProductionF7RuntimeErrorV12> {
        use crate::production_contracts::ProductionF7RuntimeErrorV12 as Error;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.xmr_graph_setup_v22[index].is_none() {
            return Ok(());
        }
        let graph_session_id = self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Scope)?
            .binding()
            .session_id();
        if self
            .pending_xmr_graph_commit_relay_envelope_v23(graph_session_id)
            .map_err(|_| Error::Scope)?
        {
            return Ok(());
        }
        if !self.observe_upstream_dom_revelation_v23(leg, scanner.as_ref())? {
            return Ok(());
        }
        let selected = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        let custody = match &self.xmr_graph_templates_v23[index] {
            graph_v23::GraphLifecycleV23::Custodied { custody, .. } => custody,
            graph_v23::GraphLifecycleV23::Failed | graph_v23::GraphLifecycleV23::Completing => {
                return Err(Error::Custody)
            }
            _ => return Ok(()),
        };
        if self.xmr_f7_observers_v23[index].is_none() && self.xmr_f7_resources_v23[index].is_some()
        {
            self.xmr_f7_observers_v23[index] = custody.prepare_f7_observer_v23(
                selected.trusted_chain_id,
                &mut self.xmr_f7_resources_v23[index],
            )?;
        }
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(Error::Scope)?
            ._shares[index];
        selected.contracts.step_native_xmr_claim_v23(
            material,
            binding,
            selected.trusted_chain_id,
            scanner,
            &mut self.xmr_f7_observers_v23[index],
            &self.xmr_graph_vault_provisioner_v23,
            now,
        )
    }

    pub(crate) fn step_f7_funding_v20(
        &mut self,
        leg: LegIdV1,
        binding: dom_actuator::DomSessionBindingV1,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
        funding_window: &crate::production_timer::ProductionFundingWindowV23,
        now: u64,
    ) -> Result<(), crate::production_contracts::ProductionFundingErrorV20> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        // DIAG(temporary): prove the pump is entered at all on this peer.
        // Reasoning from the absence of the later tokens once led to the wrong
        // conclusion; this one fires on entry, before any branch can skip it.
        diag_f7_funding_gate_v25(
            leg,
            if self.xmr_graph_setup_v22[index].is_some() {
                "enter_with_setup"
            } else {
                "enter_no_setup"
            },
        );
        if let Some(setup) = self.xmr_graph_setup_v22[index].as_ref() {
            if self
                .pending_xmr_graph_commit_relay_envelope_v23(setup.binding().session_id())
                .map_err(|_| crate::production_contracts::ProductionFundingErrorV20::Binding)?
            {
                diag_f7_funding_gate_v25(leg, "pending_0x18");
                return Ok(());
            }
            match &mut self.xmr_graph_templates_v23[index] {
                graph_v23::GraphLifecycleV23::Custodied { custody, recovery } => {
                    let chain = match leg {
                        LegIdV1::Upstream => self.upstream.trusted_chain_id,
                        LegIdV1::Downstream => self.downstream.trusted_chain_id,
                    };
                    custody
                        .activate_recovery_v23(chain, setup.setup(), scanner, recovery)
                        .inspect_err(|error| {
                            eprintln!(
                                "DOM_F7_ACTIVATE_RECOVERY_V25 leg={leg:?} retryable={} error={error}",
                                error.retryable(),
                            );
                        })?;
                    diag_f7_funding_gate_v25(leg, "custodied");
                }
                graph_v23::GraphLifecycleV23::Failed | graph_v23::GraphLifecycleV23::Completing => {
                    return Err(crate::production_contracts::ProductionFundingErrorV20::Binding);
                }
                other => {
                    diag_f7_funding_gate_v25(leg, graph_lifecycle_token_v25(other));
                    return Ok(());
                }
            }
        } else {
            let Some(driver) = self.bootstrap_v16[index].as_ref() else {
                diag_f7_funding_gate_v25(leg, "no_bootstrap_driver");
                return Ok(());
            };
            if !driver.complete() {
                diag_f7_funding_gate_v25(leg, "bootstrap_incomplete");
                return Ok(());
            }
        }
        // Recovery activation above remains independent of funding freshness.
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(crate::production_contracts::ProductionFundingErrorV20::Binding)?
            ._shares[index];
        let selected = match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        };
        let step = selected.contracts.step_f7_funding_v20(
            material,
            binding,
            selected.trusted_chain_id,
            scanner,
            funding_window,
            &self.xmr_graph_vault_provisioner_v23,
            now,
        )?;
        eprintln!(
            "DOM_NATIVE_F7_FUNDING_V24 leg={leg:?} session={} step={step:?}",
            hex::encode(binding.session_id()),
        );
        Ok(())
    }

    pub(crate) fn bootstrap_ready_v16(&self) -> bool {
        // F6 activation is not funding readiness. XMR needs F6's final role
        // context to complete custody, so it cannot wait for that completion here.
        (0..2).all(|index| {
            if let Some(setup) = self.xmr_graph_setup_v22[index].as_ref() {
                // Native enrollment needs its exact, bilateral 0x18 origin
                // before Stage 13 can build refund faces and private owners.
                // This is not custody readiness: the run loop mounts it later.
                !setup.needs_refund_binding_v23()
                    && match &self.xmr_graph_templates_v23[index] {
                        graph_v23::GraphLifecycleV23::Signing(_) => false,
                        graph_v23::GraphLifecycleV23::Produced(_)
                        | graph_v23::GraphLifecycleV23::Custodied { .. } => true,
                        _ => false,
                    }
            } else {
                self.bootstrap_v16[index]
                    .as_ref()
                    .is_none_or(|leg| leg.complete())
            }
        })
    }

    /// One line of closed tokens describing why activation has not become
    /// ready, printed only by the activation liveness watchdog on its fatal
    /// exit. No secret, digest, free text or foreign error string is emitted:
    /// every token below is a fixed enum name or boolean.
    pub(crate) fn activation_stall_report_v25(&self) -> String {
        let mut out = String::new();
        for (index, name) in [(0_usize, "up"), (1, "down")] {
            let lifecycle = graph_lifecycle_token_v25(&self.xmr_graph_templates_v23[index]);
            let (refund, aux) = self.xmr_recovery_signing_v23[index]
                .as_ref()
                .map(|owner| owner.stall_tokens_v25())
                .unwrap_or((false, [false, false]));
            let contracts = match index {
                0 => &self.upstream.contracts,
                _ => &self.downstream.contracts,
            };
            let revisions = self.xmr_recovery_signing_v23[index]
                .as_ref()
                .map(|owner| contracts.stall_revisions_v25(owner.signing_session_ids_v25()))
                .unwrap_or([0; 4]);
            let (setup, bound, context) = match &self.xmr_graph_setup_v22[index] {
                Some(setup) => (
                    true,
                    !setup.needs_refund_binding_v23(),
                    setup.claim_context_v23().is_some(),
                ),
                None => (false, false, false),
            };
            // Parent transcript plus every retained auxiliary and cancelled
            // relay of this leg: bootstrap runs on those before the parent
            // flow carries any DSC1, and each advance is durable progress.
            let mut transcript = contracts.stall_transcript_v25();
            let auxiliary = self.xmr_auxiliary_relays_v23[index]
                .iter()
                .flatten()
                .map(|owner| owner.contracts.stall_transcript_v25());
            let cancelled = self.cancelled_v22[index]
                .iter()
                .map(|owner| owner.contracts.stall_transcript_v25());
            for extra in auxiliary.chain(cancelled) {
                for (total, value) in transcript.iter_mut().zip(extra) {
                    *total = total.saturating_add(value);
                }
            }
            // DIAG(temporary): rendezvous outcome counters for this leg.
            let rv = crate::production_relay_network_runtime::exchange_diag_v25(index);
            out.push_str(&format!(
                "{name}:lifecycle={lifecycle},setup={setup},refund_bound={bound},claim_context={context},refund_complete={refund},aux_complete={}/{},rev={}/{}/{}/{},parent={},sent={},delivered={},rv=call{}/cok{}/cfail{}/aok{}/adl{}/sib{}/serr{} ",
                aux[0], aux[1], revisions[0], revisions[1], revisions[2], revisions[3],
                transcript[0], transcript[1], transcript[2],
                rv[0], rv[1], rv[2], rv[3], rv[4], rv[5], rv[6]
            ));
        }
        out
    }

    pub(crate) fn step_bootstrap_v16(
        &mut self,
        leg: LegIdV1,
        now: u64,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        self.step_bootstrap_with_renewal_v25(leg, now, &mut || Ok(()))
    }

    /// Same bootstrap step, renewing the retained DOM actuator lease between
    /// its phases.
    ///
    /// The composite loop can only renew around this call, but the recovery
    /// signing phase inside it opens the auxiliary Cancel/Compensation Relays
    /// and runs their ceremony, which is bounded by no socket deadline. A
    /// lease whose renewal cadence is coarser than the work it protects will
    /// expire mid-phase no matter how long the lease is, so the hook has to
    /// reach the phase boundaries themselves.
    pub(crate) fn step_bootstrap_with_renewal_v25(
        &mut self,
        leg: LegIdV1,
        now: u64,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as StepError;
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        // Diagnostic only: names any phase that held the actuator lease for
        // more than 30 s without renewal. It prints static phase names and a
        // duration; no identifiers, amounts or key material.
        let mut last_renewal = std::time::Instant::now();
        let mut keep = |renew: &mut dyn FnMut() -> Result<(), ()>, phase: &'static str| {
            let held = last_renewal.elapsed();
            if held > std::time::Duration::from_secs(30) {
                eprintln!(
                    "DOM_PHASE_SLOW_V25 leg={index} phase={phase} held_ms={}",
                    held.as_millis()
                );
            }
            mark_lease_phase_v25(phase);
            let renewed = renew().map_err(|()| StepError::ActuatorLeaseRenewalV25);
            last_renewal = std::time::Instant::now();
            renewed
        };
        self.resume_ready_graph_for_activation_v23(leg)?;
        keep(renew_actuator_lease, "resume_ready_graph")?;
        // After native C/D formation the graph owner, not the ordinary
        // bootstrap signer, owns the outgoing 0x18 requests and their replay.
        if self.xmr_graph_templates_v23[index].has_handoff() {
            self.step_xmr_graph_agreement_v23(leg, now)?;
            keep(renew_actuator_lease, "handoff_graph_agreement")?;
            let signed =
                self.step_xmr_recovery_signing_with_renewal_v25(leg, now, renew_actuator_lease);
            keep(renew_actuator_lease, "handoff_recovery_signing")?;
            return signed;
        }
        if let Some(cancelled) = self.cancelled_v22[index].as_mut() {
            let material = self
                ._private_bootstrap_v13
                .as_mut()
                .and_then(|private| private._cancelled_shares[index].as_mut())
                .ok_or(crate::production_contracts::ProductionBootstrapRuntimeErrorV16::Binding)?;
            cancelled.step(material, now)?;
            if !cancelled.driver.complete() {
                return Ok(());
            }
        }
        let Some(driver) = self.bootstrap_v16[index].as_mut() else {
            return Ok(());
        };
        let material = &mut self
            ._private_bootstrap_v13
            .as_mut()
            .ok_or(crate::production_contracts::ProductionBootstrapRuntimeErrorV16::Binding)?
            ._shares[index];
        let contracts = match leg {
            LegIdV1::Upstream => &mut self.upstream.contracts,
            LegIdV1::Downstream => &mut self.downstream.contracts,
        };
        let step = driver.step(contracts, material, now);
        keep(renew_actuator_lease, "bootstrap_driver")?;
        // Form only unsigned V23 templates when the bilateral material and
        // native C/D proofs exist. Recovery readiness remains a separate gate.
        self.prepare_xmr_graph_templates_v23(leg)?;
        keep(renew_actuator_lease, "graph_templates")?;
        self.step_xmr_graph_agreement_v23(leg, now)?;
        keep(renew_actuator_lease, "graph_agreement")?;
        self.step_xmr_recovery_signing_with_renewal_v25(leg, now, renew_actuator_lease)?;
        keep(renew_actuator_lease, "recovery_signing")?;
        match step {
            Err(crate::production_contracts::ProductionBootstrapRuntimeErrorV16::XmrRecoveryGraphRequired)
                if self.xmr_graph_setup_v22[index].is_some() => {
                    // Explicit handoff, not bootstrap completion. Readiness
                    // remains false until the recovery graph signer completes.
                }
            other => {
                other?;
            }
        }
        Ok(())
    }

    /// Proves that the retained pair receiver was minted by the exact split
    /// whose two activation handles were installed into these two legs.
    pub(crate) fn matches_f6_pair_receiver(
        &self,
        receiver: &ProductionF6PairRuntimeReceiverV2,
    ) -> bool {
        receiver.matches_provenance(&self.upstream.f6_pair_provenance)
            && receiver.matches_provenance(&self.downstream.f6_pair_provenance)
            && self
                .upstream
                .f6_pair_provenance
                .matches(&self.downstream.f6_pair_provenance)
    }

    /// Durable rollback floor from the authenticated composition anchor and
    /// both retained Relay inbox journals.
    pub(crate) fn retained_relay_timestamp_floor(
        &self,
    ) -> Result<u64, ProductionRelayStage12ErrorV1> {
        let upstream = self
            .upstream
            .contracts
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
        let downstream = self
            .downstream
            .contracts
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
        let mut floor = self
            .initial_relay_time_floor_seconds
            .max(upstream.unwrap_or(0))
            .max(downstream.unwrap_or(0));
        for cancelled in self.cancelled_v22.iter().flatten() {
            let retained = cancelled
                .contracts
                .retained_relay_timestamp_floor()
                .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
            floor = floor.max(retained.unwrap_or(0));
        }
        for auxiliary in self.xmr_auxiliary_relays_v23.iter().flatten().flatten() {
            let retained = auxiliary
                .contracts
                .retained_relay_timestamp_floor()
                .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
            floor = floor.max(retained.unwrap_or(0));
        }
        Ok(floor)
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn identity(&self) -> &ContractsTransportIdentityStoreV1 {
        self.identity.as_ref()
    }

    pub(crate) const fn leg(&self, leg: LegIdV1) -> &ProductionRelayStage12LegOwnerV1 {
        match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        }
    }

    pub(crate) fn leg_mut(&mut self, leg: LegIdV1) -> &mut ProductionRelayStage12LegOwnerV1 {
        match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        }
    }

    pub(crate) const fn relay(&self) -> &ProductionRelayV1 {
        &self.relay
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn relay_mut(&mut self) -> &mut ProductionRelayV1 {
        &mut self.relay
    }

    /// Joint borrow used by one authenticated Noise exchange. Keeping this
    /// operation on the sole Stage-12 owner prevents callers from reopening
    /// either authority merely to satisfy Rust's borrowing rules.
    pub(crate) fn identity_and_relay_mut(
        &mut self,
    ) -> (&ContractsTransportIdentityStoreV1, &mut ProductionRelayV1) {
        (self.identity.as_ref(), &mut self.relay)
    }

    /// Joint borrow used by one bounded upstream poll without splitting the
    /// central Relay from the Contracts owner that consumes its mailbox.
    pub(crate) fn upstream_and_relay_mut(
        &mut self,
    ) -> (
        &mut ProductionContractsV1<ProductionF6LifecyclePortV2>,
        &mut ProductionRelayV1,
    ) {
        (&mut self.upstream.contracts, &mut self.relay)
    }

    /// Joint borrow used by one bounded downstream poll without splitting the
    /// central Relay from the Contracts owner that consumes its mailbox.
    pub(crate) fn downstream_and_relay_mut(
        &mut self,
    ) -> (
        &mut ProductionContractsV1<ProductionF6LifecyclePortV2>,
        &mut ProductionRelayV1,
    ) {
        (&mut self.downstream.contracts, &mut self.relay)
    }

    /// Transfers the sole live adapter into the later child/runtime graph.
    /// A second request fails closed rather than fabricating another observer.
    pub(crate) fn take_dom_chain_adapter(
        &mut self,
    ) -> Result<DomHttpChainAdapterV1, ProductionRelayStage12ErrorV1> {
        self.dom_chain_adapter
            .take()
            .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)
    }
}

/// Fully constructed but not yet journal-authorized Stage-12 graph.
///
/// There is intentionally no owner accessor. The composition root must first
/// durably complete `RelayAuthorities`, then call `finish` with that same
/// retained journal.
pub(crate) struct ProductionRelayStage12ConstructedV1 {
    owner: ProductionRelayStage12OwnerV1,
}

impl ProductionRelayStage12ConstructedV1 {
    /// Reauthenticate both retained F6 applied histories before the caller is
    /// allowed to complete the Stage-12 journal.
    ///
    /// This consumes the constructed typestate. A failure therefore exposes
    /// neither inbound polling nor the finished owner, while a retry must
    /// reopen/resume the same physical authorities through the journaled
    /// Stage-12 path.
    pub(crate) fn recover_production_f6_applied_history(
        mut self,
    ) -> Result<ProductionRelayStage12RecoveredV1, ProductionRelayStage12ErrorV1> {
        self.owner.f6_recovery_deferred_v25 = [true; 2];
        self.owner.retry_deferred_f6_recovery_v25()?;
        Ok(ProductionRelayStage12RecoveredV1 { owner: self.owner })
    }
}

/// Stage-12 graph whose two F6 histories were reauthenticated on the exact
/// retained Contracts/Relay owners.
///
/// Only this typestate can consume a completed provisioning journal into the
/// live owner, making recovery-before-completion mandatory at the API level.
pub(crate) struct ProductionRelayStage12RecoveredV1 {
    owner: ProductionRelayStage12OwnerV1,
}

impl ProductionRelayStage12RecoveredV1 {
    pub(crate) fn finish(
        self,
        journal: &DurableProductionProvisioningJournalV1,
    ) -> Result<ProductionRelayStage12OwnerV1, ProductionRelayStage12ErrorV1> {
        if journal
            .stage_state(ProductionProvisioningStageV1::RelayAuthorities)
            .map_err(|_| ProductionRelayStage12ErrorV1::ProvisioningRefused)?
            != ProductionProvisioningStageStateV1::Complete
        {
            return Err(ProductionRelayStage12ErrorV1::ProvisioningRefused);
        }
        Ok(self.owner)
    }
}

struct PreparedStage12LegV1 {
    bootstrap: ProductionContractsSessionLegBootstrapV1,
    paths: RelayWorkerPathsV1,
    config: RelayWorkerConfigV1,
    rosters: relay::auth::RosterRegistryV1,
    lifecycle: ProductionF6LifecyclePortV2,
    wire: RouteWireContextV1,
    noise_identity_references: [SessionTransportIdentityReferenceV1; 2],
    f6_pair_provenance: ProductionF6PairProvenanceV2,
}

#[derive(Clone, Copy)]
enum AuthorityOpenModeV1 {
    Create,
    ResumeCreate,
    OpenExisting,
}

/// Construct the central Relay and the two Store-sharing Contracts owners.
///
/// Every pure binding check is completed before the Relay queue is touched.
/// Durable effects occur in this order: central Relay, optional D workers,
/// then upstream/downstream parent sender/inbox/frames and early ingress.
pub(crate) fn construct_production_relay_stage12_v1(
    request: ProductionRelayStage12RequestV1<'_>,
) -> Result<ProductionRelayStage12ConstructedV1, ProductionRelayStage12ErrorV1> {
    let ProductionRelayStage12RequestV1 {
        xmr_graph_vault_provisioner_v23,
        bootstrap,
        inputs,
        chain_signers,
        contracts,
        upstream_activation,
        downstream_activation,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        mode,
        stage_before_begin,
        stage,
    } = request;
    let open_mode = authority_open_mode(mode, stage_before_begin, stage)?;
    let relay_pins = bootstrap
        .config()
        .relay_authority_pins_v6()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let roster_bundle = inputs.roster_bundle();
    if roster_bundle.network_id() != bootstrap.config().pins().network_id
        || roster_bundle.route_id() != bootstrap.config().pins().route_id
        || chain_signers.participant_id().0 == [0; 32]
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let ProductionContractsSessionBootstrapV1 {
        mut private_bootstrap_v13,
        dom_chain_adapter,
        identity,
        upstream,
        downstream,
    } = contracts;
    let upstream = prepare_leg(
        LegIdV1::Upstream,
        &roster_bundle.legs()[0],
        bootstrap.layout(),
        relay_pins,
        inputs,
        chain_signers,
        upstream,
        upstream_activation,
    )?;
    let downstream = prepare_leg(
        LegIdV1::Downstream,
        &roster_bundle.legs()[1],
        bootstrap.layout(),
        relay_pins,
        inputs,
        chain_signers,
        downstream,
        downstream_activation,
    )?;
    if upstream.wire.network_id != downstream.wire.network_id
        || upstream.wire.route_id != downstream.wire.route_id
        || upstream.wire.session_id == downstream.wire.session_id
        || upstream.wire.roster_snapshot == downstream.wire.roster_snapshot
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let mut cancelled_prepared = [None, None];
    if let Some(private) = private_bootstrap_v13.as_mut() {
        for (index, leg, chain) in [
            (0, LegIdV1::Upstream, upstream.bootstrap.trusted_chain_id),
            (
                1,
                LegIdV1::Downstream,
                downstream.bootstrap.trusted_chain_id,
            ),
        ] {
            match (
                private._cancelled_contracts[index].take(),
                private._cancelled_shares[index].as_ref(),
            ) {
                (Some(mounted), Some(material)) => {
                    cancelled_prepared[index] = Some(cancelled_v22::prepare(
                        leg,
                        mounted,
                        material,
                        chain_signers.dom_binding(leg),
                        chain,
                        inputs,
                        relay_pins,
                    )?);
                }
                (None, None) => {}
                _ => return Err(ProductionRelayStage12ErrorV1::InvalidBinding),
            }
        }
    }
    let relay_config = relay_database_config(relay_pins)?;
    let relay = open_central_relay(
        open_mode,
        bootstrap.layout().path(ProductionPathRoleV1::RelayQueue),
        relay_config,
    )?;
    let [cancelled_upstream, cancelled_downstream] = cancelled_prepared;
    let cancelled = [
        cancelled_upstream
            .map(|prepared| {
                prepared.open(
                    open_mode,
                    Rc::clone(&identity),
                    &upstream_relay_signing_secret,
                )
            })
            .transpose()?,
        cancelled_downstream
            .map(|prepared| {
                prepared.open(
                    open_mode,
                    Rc::clone(&identity),
                    &downstream_relay_signing_secret,
                )
            })
            .transpose()?,
    ];
    // Retain independent zeroizing owners before the parent open consumes the
    // two Relay credentials. These copies never leave their exact leg scopes.
    let auxiliary_relay_secrets_v23 = [
        upstream_relay_signing_secret.clone(),
        downstream_relay_signing_secret.clone(),
    ];
    let upstream = open_leg(
        open_mode,
        Rc::clone(&identity),
        upstream,
        upstream_relay_signing_secret,
    )?;
    let downstream = open_leg(
        open_mode,
        Rc::clone(&identity),
        downstream,
        downstream_relay_signing_secret,
    )?;

    let [aux_upstream_secret, aux_downstream_secret] = auxiliary_relay_secrets_v23;
    let xmr_auxiliary_provisioners_v23 = [
        xmr_auxiliary_v23::XmrAuxiliaryRelayProvisionerV23::new(
            bootstrap.layout().state_dir(),
            LegIdV1::Upstream,
            upstream.wire,
            roster_bundle.legs()[0],
            inputs.roster_registry().clone(),
            relay_pins,
            aux_upstream_secret,
            mode,
        ),
        xmr_auxiliary_v23::XmrAuxiliaryRelayProvisionerV23::new(
            bootstrap.layout().state_dir(),
            LegIdV1::Downstream,
            downstream.wire,
            roster_bundle.legs()[1],
            inputs.roster_registry().clone(),
            relay_pins,
            aux_downstream_secret,
            mode,
        ),
    ];

    let bootstrap_v16 = if let Some(private) = private_bootstrap_v13.as_ref() {
        let public = inputs
            .contracts_bootstrap()
            .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
        // The admission layer already authenticated these exact signed time
        // bytes. Use its DOM checkpoint as the negotiated construction tip;
        // this is not a replacement for live pre-funding time revalidation.
        let time = route_time_anchor::RouteTimeEvidenceV2::decode(
            inputs.signed_time_evidence().evidence_bytes(),
        )
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
        let make = |index: usize, leg: LegIdV1, chain, terms: &kaystra_core::SettlementTermsV1| {
            if terms.counterparty_leg.mechanism
                == kaystra_core::types::LockMechanism::CrossCurveSharedSpend
            {
                let cancelled_owner = cancelled[index]
                    .as_ref()
                    .ok_or(ProductionRelayStage12ErrorV1::ContractsRefused)?;
                return crate::production_contracts::ProductionBootstrapLegV16::for_xmr_collateral_v22(
                    chain_signers.dom_binding(leg),
                    chain,
                    &public.legs()[index],
                    terms,
                    &cancelled_owner.policy,
                    &private._shares[index],
                )
                .map(Some)
                .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused);
            }
            let amount = if terms.policy_version == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17 {
                dom_adaptor::DomBootstrapBudgetV17::new(
                    terms.dom_leg.amount,
                    terms.fee_limit.dom_max,
                )
                .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?
                .shared_value()
            } else {
                u64::try_from(terms.dom_leg.amount)
                    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?
            };
            let mut tips = time
                .checkpoints()
                .iter()
                .filter(|c| c.chain_id == terms.dom_leg.chain_id);
            let tip = tips
                .next()
                .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?
                .canonical_tip_height;
            if tips.next().is_some() {
                return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
            }
            crate::production_contracts::ProductionBootstrapLegV16::new(
                chain_signers.dom_binding(leg),
                chain,
                &public.legs()[index],
                amount,
                &private._shares[index],
            )
            .and_then(|driver| {
                driver.with_wallet_templates_v17(
                    terms,
                    bootstrap.layout().state_dir(),
                    tip,
                    &private._shares[index],
                )
            })
            .map(Some)
            .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)
        };
        [
            make(
                0,
                LegIdV1::Upstream,
                upstream.trusted_chain_id(),
                inputs.composition().upstream(),
            )?,
            make(
                1,
                LegIdV1::Downstream,
                downstream.trusted_chain_id(),
                inputs.composition().downstream(),
            )?,
        ]
    } else {
        [None, None]
    };

    let graph_setup = |leg| {
        let Some(session) = inputs.monero_session(leg) else {
            // DIAG(temporary): a leg without a Monero session gets no XMR graph
            // setup, and every downstream consequence of that is silent. Print
            // it once per leg at construction, on both peers.
            eprintln!("DOM_GRAPH_SETUP_V25 leg={leg:?} monero_session=absent");
            return Ok(None);
        };
        eprintln!("DOM_GRAPH_SETUP_V25 leg={leg:?} monero_session=present");
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let time = route_time_anchor::RouteTimeEvidenceV2::decode(
            inputs.signed_time_evidence().evidence_bytes(),
        )
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
        let mut checkpoints = time
            .checkpoints()
            .iter()
            .filter(|checkpoint| checkpoint.chain_id == terms.dom_leg.chain_id);
        let tip = checkpoints
            .next()
            .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?
            .canonical_tip_height;
        if checkpoints.next().is_some() {
            return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
        }
        crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22::from_admission(
            session,
            terms,
            chain_signers.dom_binding(leg),
            tip,
        )
        .map(Some)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)
    };
    let xmr_graph_setup_v22 = [
        graph_setup(LegIdV1::Upstream)?,
        graph_setup(LegIdV1::Downstream)?,
    ];

    Ok(ProductionRelayStage12ConstructedV1 {
        owner: ProductionRelayStage12OwnerV1 {
            xmr_auxiliary_provisioners_v23,
            xmr_auxiliary_relays_v23: [[None, None], [None, None]],
            xmr_graph_vault_provisioner_v23,
            xmr_recovery_signing_v23: [None, None],
            xmr_graph_signing_admission_deferred_v23: [false, false],
            cancelled_v22: cancelled,
            bootstrap_v16,
            xmr_graph_templates_v23: [
                graph_v23::GraphLifecycleV23::Awaiting,
                graph_v23::GraphLifecycleV23::Awaiting,
            ],
            xmr_custody_resources_v23: [None, None],
            xmr_f7_resources_v23: [None, None],
            xmr_f7_observers_v23: [None, None],
            xmr_graph_candidates_v22: [None, None],
            xmr_graph_public_v22: [None, None],
            xmr_graph_setup_v22,
            _private_bootstrap_v13: private_bootstrap_v13,
            relay,
            identity,
            dom_chain_adapter: Some(dom_chain_adapter),
            upstream,
            downstream,
            initial_relay_time_floor_seconds: inputs
                .composition()
                .time_proof_validated_at_seconds(),
            f6_recovery_deferred_v25: [false; 2],
        },
    })
}

fn authority_open_mode(
    mode: ProductionRelayStage12ModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
) -> Result<AuthorityOpenModeV1, ProductionRelayStage12ErrorV1> {
    match (mode, stage_before_begin, stage) {
        (
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
        ) => Ok(AuthorityOpenModeV1::Create),
        (
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Started,
        ) => Ok(AuthorityOpenModeV1::ResumeCreate),
        (
            ProductionRelayStage12ModeV1::CreateOrResume
            | ProductionRelayStage12ModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
        ) => Ok(AuthorityOpenModeV1::OpenExisting),
        _ => Err(ProductionRelayStage12ErrorV1::ProvisioningRefused),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
fn prepare_leg(
    leg: LegIdV1,
    roster_leg: &ProductionRosterLegV1,
    layout: &ValidatedProductionLayoutV1,
    relay_pins: ProductionRelayAuthorityPinsV6,
    inputs: &AuthenticatedProductionInputsV1,
    chain_signers: &ProductionChainSignerAuthoritiesV1,
    bootstrap: ProductionContractsSessionLegBootstrapV1,
    activation: ProductionF6PairActivationAuthorityV2,
) -> Result<PreparedStage12LegV1, ProductionRelayStage12ErrorV1> {
    let expected_position = match leg {
        LegIdV1::Upstream => ProductionRoutePositionV1::Upstream,
        LegIdV1::Downstream => ProductionRoutePositionV1::Downstream,
    };
    if roster_leg.position != expected_position {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    let local = chain_signers.participant_id();
    let mut local_member = None;
    let mut remote_member = None;
    for member in roster_leg.members {
        if member.participant_id == local {
            if local_member.replace(member).is_some() {
                return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
            }
        } else if remote_member.replace(member).is_some() {
            return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
        }
    }
    let local_member = local_member.ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let remote_member = remote_member.ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let roles_are_exact = matches!(
        (local_member.role, remote_member.role),
        (SenderRoleV1::Initiator, SenderRoleV1::Solver)
            | (SenderRoleV1::Solver, SenderRoleV1::Initiator)
    );
    if !roles_are_exact
        || local_member.role != chain_signers.relay_role()
        || local_member.xonly_key != chain_signers.relay_xonly_key(leg)
        || local_member.xonly_key == remote_member.xonly_key
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let wire = RouteWireContextV1 {
        network_id: inputs.roster_bundle().network_id(),
        session_id: roster_leg.session_id,
        route_id: inputs.roster_bundle().route_id(),
        roster_snapshot: roster_leg.roster_snapshot,
        policy_version: roster_leg.policy_version,
    };
    let (sender_store_id, inbox_id, reassembler_id, sender_path, inbox_path, frames_path) =
        leg_relay_facts(leg, layout, relay_pins);
    let sender = DurableRelaySenderConfigV1::new(
        sender_store_id,
        wire,
        local,
        remote_member.participant_id,
        local_member.role,
        local_member.xonly_key,
        relay_pins.sender_max_envelopes,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let inbox = DurableInboxConfigV1::new(
        inbox_id,
        relay_pins.relay_database_id,
        wire,
        local,
        relay_pins.inbox_max_entries,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let frames = DurableFrameReassemblerConfigV2::new(
        reassembler_id,
        wire,
        local,
        relay_pins.frame_max_messages,
        relay_pins.frame_max_active_bytes,
        relay_pins.frame_max_active_chunks,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let config = RelayWorkerConfigV1::new_production_v6(sender, inbox, frames, relay_pins, leg)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let initiator = if local_member.role == SenderRoleV1::Initiator {
        local
    } else {
        remote_member.participant_id
    };
    let position = match leg {
        LegIdV1::Upstream => SettlementPositionV2::Upstream,
        LegIdV1::Downstream => SettlementPositionV2::Downstream,
    };
    let pins = ProductionAwaitingF6PinsV2::new(wire, position, initiator)
        .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;
    let f6_pair_provenance = activation.provenance();
    let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins);
    lifecycle
        .install_activation_authority(activation)
        .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;

    let references = bootstrap
        .store
        .transport_identity_references(wire.session_id)
        .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    let noise_identity_references =
        order_identity_references(references, local, remote_member.participant_id)?;
    Ok(PreparedStage12LegV1 {
        bootstrap,
        paths: RelayWorkerPathsV1::new(sender_path, inbox_path, frames_path),
        config,
        rosters: inputs.roster_registry().clone(),
        lifecycle,
        wire,
        noise_identity_references,
        f6_pair_provenance,
    })
}

fn leg_relay_facts(
    leg: LegIdV1,
    layout: &ValidatedProductionLayoutV1,
    pins: ProductionRelayAuthorityPinsV6,
) -> ([u8; 32], [u8; 32], [u8; 32], &Path, &Path, &Path) {
    match leg {
        LegIdV1::Upstream => (
            pins.upstream_sender_store_id,
            pins.upstream_inbox_id,
            pins.upstream_reassembler_id,
            layout.path(ProductionPathRoleV1::UpstreamRelaySender),
            layout.path(ProductionPathRoleV1::UpstreamRelayInbox),
            layout.path(ProductionPathRoleV1::UpstreamRelayFrames),
        ),
        LegIdV1::Downstream => (
            pins.downstream_sender_store_id,
            pins.downstream_inbox_id,
            pins.downstream_reassembler_id,
            layout.path(ProductionPathRoleV1::DownstreamRelaySender),
            layout.path(ProductionPathRoleV1::DownstreamRelayInbox),
            layout.path(ProductionPathRoleV1::DownstreamRelayFrames),
        ),
    }
}

fn order_identity_references(
    references: [SessionTransportIdentityReferenceV1; 2],
    local: ParticipantId,
    remote: ParticipantId,
) -> Result<[SessionTransportIdentityReferenceV1; 2], ProductionRelayStage12ErrorV1> {
    if local == remote
        || references
            .iter()
            .filter(|reference| reference.participant_id() == &local.0)
            .count()
            != 1
        || references
            .iter()
            .filter(|reference| reference.participant_id() == &remote.0)
            .count()
            != 1
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    let local_reference = references
        .iter()
        .find(|reference| reference.participant_id() == &local.0)
        .cloned()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let remote_reference = references
        .iter()
        .find(|reference| reference.participant_id() == &remote.0)
        .cloned()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    if local_reference.key_reference() == remote_reference.key_reference()
        || local_reference.noise_public_key() == remote_reference.noise_public_key()
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    Ok([local_reference, remote_reference])
}

fn relay_database_config(
    pins: ProductionRelayAuthorityPinsV6,
) -> Result<RelayDatabaseConfigV1, ProductionRelayStage12ErrorV1> {
    let id = RelayDatabaseIdV1::new(pins.relay_database_id)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    RelayDatabaseConfigV1::new(id, pins.relay_max_envelopes)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)
}

fn open_central_relay(
    mode: AuthorityOpenModeV1,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<ProductionRelayV1, ProductionRelayStage12ErrorV1> {
    let relay = match mode {
        AuthorityOpenModeV1::Create => ProductionRelayV1::create(root, config),
        AuthorityOpenModeV1::ResumeCreate => {
            match ProductionRelayV1::production_creation_state(root, config)
                .map_err(|_| ProductionRelayStage12ErrorV1::RelayRefused)?
            {
                ProductionRelayCreationStateV1::Missing => ProductionRelayV1::create(root, config),
                ProductionRelayCreationStateV1::Incomplete
                | ProductionRelayCreationStateV1::InitializedPristine => {
                    ProductionRelayV1::resume_create_production(root, config)
                }
            }
        }
        AuthorityOpenModeV1::OpenExisting => ProductionRelayV1::open(root, config),
    };
    relay.map_err(|_| ProductionRelayStage12ErrorV1::RelayRefused)
}

fn open_leg(
    mode: AuthorityOpenModeV1,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    prepared: PreparedStage12LegV1,
    signing_secret: Zeroizing<[u8; 32]>,
) -> Result<ProductionRelayStage12LegOwnerV1, ProductionRelayStage12ErrorV1> {
    let PreparedStage12LegV1 {
        bootstrap,
        paths,
        config,
        rosters,
        lifecycle,
        wire,
        noise_identity_references,
        f6_pair_provenance,
    } = prepared;
    let ProductionContractsSessionLegBootstrapV1 {
        store,
        trusted_chain_id,
        shared_blinding_bindings,
        early_transport_authority,
    } = bootstrap;
    let mut contracts = match mode {
        AuthorityOpenModeV1::Create => ProductionContractsV1::create(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
        AuthorityOpenModeV1::ResumeCreate => ProductionContractsV1::resume_create_production(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
        AuthorityOpenModeV1::OpenExisting => ProductionContractsV1::open_existing(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
    }
    .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    contracts
        .install_contracts_ingress(PreparedContractsIngressV1::early(early_transport_authority))
        .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    Ok(ProductionRelayStage12LegOwnerV1 {
        contracts,
        wire,
        trusted_chain_id,
        shared_blinding_bindings,
        noise_identity_references,
        f6_pair_provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::SecretKey;

    #[test]
    fn authority_open_mode_accepts_only_journal_consistent_transitions() {
        let modes = [
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionRelayStage12ModeV1::ReopenExisting,
        ];
        let states = [
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Complete,
        ];
        for mode in modes {
            for before in states {
                for current in states {
                    let accepted = matches!(
                        (mode, before, current),
                        (
                            ProductionRelayStage12ModeV1::CreateOrResume,
                            ProductionProvisioningStageStateV1::Absent,
                            ProductionProvisioningStageStateV1::Started,
                        ) | (
                            ProductionRelayStage12ModeV1::CreateOrResume,
                            ProductionProvisioningStageStateV1::Started,
                            ProductionProvisioningStageStateV1::Started,
                        ) | (
                            ProductionRelayStage12ModeV1::CreateOrResume
                                | ProductionRelayStage12ModeV1::ReopenExisting,
                            ProductionProvisioningStageStateV1::Complete,
                            ProductionProvisioningStageStateV1::Complete,
                        )
                    );
                    assert_eq!(
                        authority_open_mode(mode, before, current).is_ok(),
                        accepted,
                        "unexpected Stage-12 journal transition acceptance"
                    );
                }
            }
        }
    }

    #[test]
    fn identity_references_are_local_first_and_refuse_transplants() {
        let local = ParticipantId([0x41; 32]);
        let remote = ParticipantId([0x42; 32]);
        let foreign = ParticipantId([0x43; 32]);
        let local_reference = identity_reference(local, 0x51, 0x61, 1);
        let remote_reference = identity_reference(remote, 0x52, 0x62, 2);
        let ordered = order_identity_references(
            [remote_reference.clone(), local_reference.clone()],
            local,
            remote,
        )
        .expect("authenticated references must be reordered local-first");
        assert_eq!(ordered[0].participant_id(), &local.0);
        assert_eq!(ordered[1].participant_id(), &remote.0);

        let participant_transplant = identity_reference(foreign, 0x53, 0x63, 3);
        assert_eq!(
            order_identity_references(
                [local_reference.clone(), participant_transplant],
                local,
                remote,
            )
            .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let duplicate_local = identity_reference(local, 0x54, 0x64, 4);
        assert_eq!(
            order_identity_references([local_reference.clone(), duplicate_local], local, remote,)
                .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let key_reference_transplant = SessionTransportIdentityReferenceV1::new(
            remote.0,
            *local_reference.key_reference(),
            [0x65; 32],
            SecretKey::from_bytes(&[5; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference");
        assert_eq!(
            order_identity_references(
                [local_reference.clone(), key_reference_transplant],
                local,
                remote,
            )
            .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let noise_key_transplant = SessionTransportIdentityReferenceV1::new(
            remote.0,
            [0x55; 32],
            *local_reference.noise_public_key(),
            SecretKey::from_bytes(&[6; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference");
        assert_eq!(
            order_identity_references([local_reference, noise_key_transplant], local, remote).err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );
    }

    #[test]
    fn constructed_owner_requires_f6_recovery_typestate_before_finish() {
        let _recover: fn(
            ProductionRelayStage12ConstructedV1,
        ) -> Result<
            ProductionRelayStage12RecoveredV1,
            ProductionRelayStage12ErrorV1,
        > = ProductionRelayStage12ConstructedV1::recover_production_f6_applied_history;
        let _finish: fn(
            ProductionRelayStage12RecoveredV1,
            &DurableProductionProvisioningJournalV1,
        )
            -> Result<ProductionRelayStage12OwnerV1, ProductionRelayStage12ErrorV1> =
            ProductionRelayStage12RecoveredV1::finish;
    }

    fn identity_reference(
        participant: ParticipantId,
        key_reference: u8,
        noise_public_key: u8,
        secret: u8,
    ) -> SessionTransportIdentityReferenceV1 {
        SessionTransportIdentityReferenceV1::new(
            participant.0,
            [key_reference; 32],
            [noise_public_key; 32],
            SecretKey::from_bytes(&[secret; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference")
    }
}
