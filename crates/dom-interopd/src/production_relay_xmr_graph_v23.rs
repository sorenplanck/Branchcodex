//! Form the unsigned graph from the live C/D owners and bilateral public offers.
//! Templates remain in memory; their local proposal pin is immutable on disk.
//! Neither is bilateral agreement, signing authority, or funding permission.
use super::*;
use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
use xmr_refund_policy::{
    graph_builder::{ProducedXmrRecoveryGraphV12, XmrRecoveryGraphTemplatesV12},
    graph_signing_keys_v22::XmrGraphSigningKeysV22,
};

pub(crate) struct SignedXmrGraphV23 {
    pub(crate) produced: ProducedXmrRecoveryGraphV12,
    pub(crate) role: dom_final_claim_binding::FinalClaimRoleBindingV1,
}

pub(crate) struct PreparedXmrGraphV23 {
    pub(crate) templates: XmrRecoveryGraphTemplatesV12,
    pub(crate) keys: XmrGraphSigningKeysV22,
}

/// Move-only graph lifecycle. Consumed templates must never look like missing
/// peer material: an interrupted/failed completion cannot mint a fresh owner.
pub(crate) enum GraphLifecycleV23 {
    Awaiting,
    Signing(PreparedXmrGraphV23),
    Completing,
    Produced(SignedXmrGraphV23),
    Custodied {
        custody: crate::production_contracts::ProductionXmrGraphCustodyV23,
        recovery: Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>,
    },
    Failed,
}

pub(crate) struct PendingXmrCustodyV23 {
    resources: crate::production_contracts::ProductionXmrGraphCustodyResourcesV23,
    private_owner: Option<crate::production_xmr_sweep::ProductionXmrPrivateRefundOwnerV23>,
    recovery: Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>,
}

impl GraphLifecycleV23 {
    pub(crate) fn signing(&self) -> Result<Option<&PreparedXmrGraphV23>, Error> {
        match self {
            Self::Signing(graph) => Ok(Some(graph)),
            Self::Awaiting | Self::Produced(_) | Self::Custodied { .. } => Ok(None),
            Self::Completing | Self::Failed => Err(Error::Binding),
        }
    }

    /// Failure is still a graph handoff, never permission to resume bootstrap.
    pub(crate) fn has_handoff(&self) -> bool {
        !matches!(self, Self::Awaiting)
    }
}

impl ProductionRelayStage12OwnerV1 {
    pub(super) fn resume_ready_graph_for_activation_v23(
        &mut self,
        leg: LegIdV1,
    ) -> Result<(), Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.xmr_graph_setup_v22[index].is_none()
            || !matches!(
                self.xmr_graph_templates_v23[index],
                GraphLifecycleV23::Awaiting
            )
        {
            return Ok(());
        }
        // A ready graph record is written exclusively by this process's own
        // custody mount, which only runs after the lifecycle has left
        // `Awaiting`. After one authenticated probe found nothing, re-probing
        // on every tick pays a full transport audit to re-learn the same
        // absence for the entire bootstrap phase. Reopen starts a new process
        // and probes afresh; mounting retained custody clears the flag.
        if self.ready_graph_probe_done_v25[index] {
            return Ok(());
        }
        let owner = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        if let Some((produced, role)) = owner
            .contracts
            .retained_xmr_graph_ready_for_activation_v23(owner.trusted_chain_id)
            .map_err(|error| match error {
                crate::production_contracts::ProductionXmrGraphCustodyErrorV23::Store(
                    store,
                ) => Error::Store(store),
                _ => Error::Binding,
            })?
        {
            if self.xmr_graph_setup_v22[index]
                .as_ref()
                .ok_or(Error::Binding)?
                .needs_refund_binding_v23()
            {
                let authority = owner
                    .contracts
                    .resume_xmr_refund_template_binding_v23(owner.trusted_chain_id)
                    .map_err(|_| Error::Binding)?;
                owner
                    .contracts
                    .revalidate_xmr_refund_template_binding_v23(&authority)
                    .map_err(|_| Error::Binding)?;
                self.xmr_graph_setup_v22[index]
                    .as_mut()
                    .ok_or(Error::Binding)?
                    .bind_native_refund_v23(authority)?;
            }
            let setup = self.xmr_custody_setup_v23(leg)?;
            if role.terms() != setup.terms()
                || produced.graph().binding().session_id != setup.binding().session_id()
                || produced.graph().binding().chain_id != setup.binding().chain_id()
            {
                return Err(Error::Binding);
            }
            // This historical public owner grants neither funding nor recovery.
            // Resource mounting must still match the configured custody ID and F6 role.
            self.xmr_graph_templates_v23[index] =
                GraphLifecycleV23::Produced(SignedXmrGraphV23 { produced, role });
        }
        self.ready_graph_probe_done_v25[index] = true;
        Ok(())
    }

    /// A retained gate alone cannot enable readiness during early restart:
    /// the same-process recovery executor must already own the exact archive.
    pub(crate) fn recovery_mounted_for_readiness_v23(&self, leg: LegIdV1) -> Result<bool, Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.xmr_graph_setup_v22[index].is_none() {
            return Ok(true);
        }
        match &self.xmr_graph_templates_v23[index] {
            GraphLifecycleV23::Custodied { recovery, .. } => match recovery.require_driver() {
                Ok(_) => Ok(true),
                Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => Ok(false),
                Err(_) => Err(Error::Binding),
            },
            GraphLifecycleV23::Failed | GraphLifecycleV23::Completing => Err(Error::Binding),
            _ => Ok(false),
        }
    }

    pub(crate) fn xmr_custody_setup_v23(
        &self,
        leg: LegIdV1,
    ) -> Result<&crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22, Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Binding)
    }

    pub(crate) fn mount_xmr_custody_resources_v23(
        &mut self,
        leg: LegIdV1,
        resources: crate::production_contracts::ProductionXmrGraphCustodyResourcesV23,
        nullifiers: Rc<xmr_dleq_nullifier_store::DleqNullifierStore>,
        sweep: &crate::production_xmr_sweep::ProductionXmrSweepAuthorityV10,
        recovery: Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>,
    ) -> Result<(), Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.xmr_custody_resources_v23[index].is_some()
            || matches!(
                self.xmr_graph_templates_v23[index],
                GraphLifecycleV23::Custodied { .. }
                    | GraphLifecycleV23::Completing
                    | GraphLifecycleV23::Failed
            )
        {
            return Err(Error::Binding);
        }
        self.ready_graph_probe_done_v25[index] = false;
        let setup = self.xmr_custody_setup_v23(leg)?;
        recovery.require_sweep(sweep).map_err(|_| Error::Binding)?;
        if self.xmr_f7_resources_v23[index].is_some() || self.xmr_f7_observers_v23[index].is_some()
        {
            return Err(Error::Binding);
        }
        let f7_resources = sweep
            .retain_f7_resources_v23(setup)
            .map_err(|_| Error::Binding)?;
        // Retain the same private resources for both fresh and reopened custody.
        self.xmr_f7_resources_v23[index] = Some(f7_resources);
        let setup = self.xmr_custody_setup_v23(leg)?;
        let owner = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        sweep
            .install_native_claim_origin_v23(setup, owner.trusted_chain_id, &owner.contracts)
            .map_err(|_| Error::Binding)?;
        if let Some((produced, role)) = owner
            .contracts
            .retained_xmr_graph_custody_v23(owner.trusted_chain_id, resources.custody_id)
            .map_err(|_| Error::Binding)?
        {
            let (plan, source, _) = setup.claim_context_v23().ok_or(Error::Binding)?;
            if role.terms() != setup.terms()
                || role.composed_role_plan_digest() != plan.digest()
                || role.secret_source_scope_digest() != source.digest()
            {
                return Err(Error::Binding);
            }
            let custody = owner
                .contracts
                .reopen_ready_xmr_graph_custody_v23(produced, &role, resources)
                .map_err(|_| Error::Binding)?;
            self.xmr_graph_templates_v23[index] =
                GraphLifecycleV23::Custodied { custody, recovery };
            return Ok(());
        }
        let private_owner = if setup.binding().participant().participant_id()
            == setup.terms().dom_leg.refund_to.0
        {
            Some(
                sweep
                    .retain_private_refund_owner_v23(setup, &nullifiers)
                    .map_err(|_| Error::Binding)?,
            )
        } else {
            None
        };
        self.xmr_custody_resources_v23[index] = Some(PendingXmrCustodyV23 {
            resources,
            private_owner,
            recovery,
        });
        Ok(())
    }

    pub(super) fn step_xmr_graph_custody_v23(&mut self, leg: LegIdV1) -> Result<(), Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if let GraphLifecycleV23::Custodied { custody, .. } = &self.xmr_graph_templates_v23[index] {
            // Revalidating here rebuilds the whole recovery graph and re-audits
            // both ordinary rounds. Measured on RUN26: 658 calls, 5.8 s median,
            // 76 min of a 124 min run — 61% of the ceremony spent re-auditing a
            // lifecycle that is terminal and a custody object that cannot change
            // while it holds. This is a polling tick with nothing left to do,
            // not a use: every consumer revalidates at its own point of use
            // (`ProductionXmrGraphCustodyV23::activate_recovery_v23` opens with
            // `self.revalidate()?`), so no use loses its guard. Audit once per
            // entry into `Custodied`, then let the use sites carry it.
            if self.xmr_custody_revalidated_v25[index] {
                return Ok(());
            }
            custody.revalidate().map_err(|error| match error {
                crate::production_contracts::ProductionXmrGraphCustodyErrorV23::Store(
                    store,
                ) => Error::Store(store),
                _ => Error::Binding,
            })?;
            self.xmr_custody_revalidated_v25[index] = true;
            return Ok(());
        }
        if !matches!(
            self.xmr_graph_templates_v23[index],
            GraphLifecycleV23::Produced(_)
        ) || self.xmr_custody_resources_v23[index].is_none()
        {
            return Ok(());
        }
        let pending = self.xmr_custody_resources_v23[index]
            .take()
            .ok_or(Error::Binding)?;
        let state = std::mem::replace(
            &mut self.xmr_graph_templates_v23[index],
            GraphLifecycleV23::Completing,
        );
        let GraphLifecycleV23::Produced(signed) = state else {
            self.xmr_graph_templates_v23[index] = GraphLifecycleV23::Failed;
            return Err(Error::Binding);
        };
        let owner = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        match owner.contracts.mount_xmr_graph_custody_v23(
            signed.produced,
            &signed.role,
            pending.resources,
            pending.private_owner.as_ref(),
        ) {
            Ok(custody) => {
                self.xmr_custody_revalidated_v25[index] = false;
                self.xmr_graph_templates_v23[index] = GraphLifecycleV23::Custodied {
                    custody,
                    recovery: pending.recovery,
                };
                Ok(())
            }
            Err(_) => {
                self.xmr_graph_templates_v23[index] = GraphLifecycleV23::Failed;
                Err(Error::Binding)
            }
        }
    }

    pub(crate) fn install_xmr_claim_context_v23(
        &mut self,
        plan: &dom_final_claim_binding::ComposedFinalClaimRolePlanV1,
        upstream: &dom_final_claim_binding::FinalClaimSecretSourceScopeV1,
        downstream: &dom_final_claim_binding::FinalClaimSecretSourceScopeV1,
    ) -> Result<(), Error> {
        use dom_final_claim_binding::ComposedSettlementLegV1 as Leg;
        for (index, source, leg) in [
            (0, upstream, Leg::Upstream),
            (1, downstream, Leg::Downstream),
        ] {
            if let Some(setup) = self.xmr_graph_setup_v22[index].as_mut() {
                setup.install_claim_context_v23(plan, source, leg)?;
            }
        }
        Ok(())
    }

    pub(super) fn step_xmr_graph_agreement_v23(
        &mut self,
        leg: LegIdV1,
        now: u64,
    ) -> Result<(), Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        if self.xmr_graph_templates_v23[index].signing()?.is_none() {
            // Produced is terminal for agreement: both 0x18 commitments were
            // authenticated before the first native recovery signing message.
            return Ok(());
        }
        let setup = self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Binding)?;
        let route = setup.binding().route_id();
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
        owner
            .contracts
            .step_xmr_graph_commit_v23(owner.trusted_chain_id, route, expiry)?;
        if self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Binding)?
            .needs_refund_binding_v23()
        {
            let polled = owner
                .contracts
                .poll_xmr_refund_template_binding_v23(owner.trusted_chain_id);
            if let Some(authority) = polled.map_err(|_| Error::Binding)? {
                owner
                    .contracts
                    .revalidate_xmr_refund_template_binding_v23(&authority)
                    .map_err(|_| Error::Binding)?;
                self.xmr_graph_setup_v22[index]
                    .as_mut()
                    .ok_or(Error::Binding)?
                    .bind_native_refund_v23(authority)?;
            }
        }
        Ok(())
    }

    /// Missing peer material or unfinished BP formation means wait. A mismatch
    /// fails closed. No completion flag, nonce, signature or funding is issued.
    pub(super) fn prepare_xmr_graph_templates_v23(&mut self, leg: LegIdV1) -> Result<(), Error> {
        let index = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        };
        match &self.xmr_graph_templates_v23[index] {
            GraphLifecycleV23::Awaiting => {}
            GraphLifecycleV23::Signing(_)
            | GraphLifecycleV23::Produced(_)
            | GraphLifecycleV23::Custodied { .. } => return Ok(()),
            GraphLifecycleV23::Completing | GraphLifecycleV23::Failed => {
                return Err(Error::Binding)
            }
        }
        let Some(public) = self.xmr_graph_public_v22[index].as_ref() else {
            return Ok(());
        };
        let setup = self.xmr_graph_setup_v22[index]
            .as_ref()
            .ok_or(Error::Binding)?;
        let parent = match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        };
        let driver = self.bootstrap_v16[index].as_ref().ok_or(Error::Binding)?;
        let cancelled = self.cancelled_v22[index].as_ref().ok_or(Error::Binding)?;
        let private = self._private_bootstrap_v13.as_ref().ok_or(Error::Binding)?;
        let d_material = private._cancelled_shares[index]
            .as_ref()
            .ok_or(Error::Binding)?;
        let Some((c, c_output)) =
            driver.xmr_graph_output_v22(&parent.contracts, &private._shares[index])?
        else {
            return Ok(());
        };
        let Some((d, d_output)) = cancelled
            .driver
            .xmr_graph_output_v22(&cancelled.contracts, d_material)?
        else {
            return Ok(());
        };
        let policy = cancelled
            .policy
            .policy()
            .validate_for(setup.terms())
            .map_err(|_| Error::Binding)?;
        if policy != cancelled.policy
            || policy.policy().bounded_availability_v23.is_none()
            || cancelled.parent_terms != setup.binding().terms_digest()
            || parent.trusted_chain_id != cancelled.chain
            || parent.trusted_chain_id.as_bytes() != &setup.binding().chain_id()
        {
            return Err(Error::Binding);
        }
        let formed = form_xmr_graph_templates_v23(
            public,
            setup.terms(),
            &policy,
            [(c, c_output), (d, d_output)],
            setup.negotiated_tip(),
            setup.refund_point(),
        )?;
        // The admitted XMR refund bundle pins this native DOM template.
        // U's DLEQ alone does not bind a transaction; check the separate pin.
        let (_, refund_hash) = dom_adaptor::canonical_template_v1(formed.templates.refund())
            .map_err(|_| Error::Binding)?;
        setup.require_refund_proposal_v23(refund_hash)?;
        formed
            .keys
            .require_route(setup.binding().route_id())
            .map_err(|_| Error::Binding)?;
        formed
            .keys
            .require_scope(
                &parent.trusted_chain_id,
                setup.binding().session_id(),
                setup.binding().terms_digest(),
                setup.terms().roster.map(|participant| participant.0),
                parent
                    .shared_blinding_bindings
                    .each_ref()
                    .map(|binding| binding.role()),
            )
            .map_err(|_| Error::Binding)?;
        parent
            .contracts
            .retain_xmr_graph_proposal_v23(
                &cancelled.contracts,
                parent.trusted_chain_id,
                setup.binding().route_id(),
                setup.terms(),
                &formed.templates,
                &formed.keys,
            )
            .map_err(|_| Error::Binding)?;
        self.xmr_graph_templates_v23[index] = GraphLifecycleV23::Signing(formed);
        Ok(())
    }
}

/// Shared production formation mapping. Caller must authenticate setup/route and
/// the admitted refund-template pin separately; this only forms unsigned material.
pub(crate) fn form_xmr_graph_templates_v23(
    public: &crate::production_noise_relay::ProductionXmrGraphPublicMaterialV22,
    terms: &kaystra_core::SettlementTermsV1,
    policy: &xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    outputs: [(
        dom_scriptless_crypto::FrozenSharedOutputV1,
        dom_adaptor::VerifiedSharedOutputV1,
    ); 2],
    negotiated_tip: u64,
    refund_point: [u8; 33],
) -> Result<PreparedXmrGraphV23, Error> {
    let (templates, keys) = public
        .form_templates_v23(terms, policy, outputs, negotiated_tip, refund_point)
        .map_err(|_| Error::Binding)?;
    Ok(PreparedXmrGraphV23 { templates, keys })
}
