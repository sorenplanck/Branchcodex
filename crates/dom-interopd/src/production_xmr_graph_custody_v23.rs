//! Bounded-profile encrypted custody and same-Store runtime integration.
//! Funding/recovery handles stay internal; the F7 observer shares the existing
//! private resources without exporting a scalar or opening another database.
//! Started/Ready gates owner export and forbids recreation after Ready.
//! Incomplete archive-root reinitialization is deliberately unsupported.
use super::*;
use dom_final_claim_binding::FinalClaimRoleBindingV1;
use dom_scriptless_crypto::{PrivateXmrRefundTransactionV11, XmrRecoverySealKeyV11};
use dom_scriptless_store::{
    VerifiedXmrOrdinaryRecoveryRoundsV11, XmrOrdinaryRecoveryRoundSessionsV11,
    XmrRecoveryCustodyErrorV11, XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyScopeV11,
    XmrRecoveryCustodyV11,
};
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionXmrGraphCustodyErrorV23 {
    #[error("bounded XMR graph custody scope or private role refused")]
    Scope,
    #[error("bounded XMR graph native Store audit refused")]
    Store(#[from] SessionStoreError),
    #[error("bounded XMR graph encrypted custody refused")]
    Custody(#[from] XmrRecoveryCustodyErrorV11),
}

/// Resources selected by the composition, with a real private seal key.
/// The caller cannot select/downgrade the participant's custody role.
pub(crate) struct ProductionXmrGraphCustodyResourcesV23 {
    pub(crate) parent: cap_std::fs::Dir,
    pub(crate) directory_name: String,
    pub(crate) custody_id: [u8; 32],
    pub(crate) key: XmrRecoverySealKeyV11,
}

/// Retains the exact native graph and the sole encrypted archive owner.
/// Deliberately no Clone, ordinary/custody getter or conversion to V12 funding.
pub(crate) struct ProductionXmrGraphCustodyV23 {
    produced: Rc<ProducedXmrRecoveryGraphV12>,
    custody: Rc<XmrRecoveryCustodyV11>,
    ordinary: VerifiedXmrOrdinaryRecoveryRoundsV11,
    store: Rc<ContractsSessionStoreV1>,
    role: FinalClaimRoleBindingV1,
    funding_gate: Option<Rc<dom_scriptless_store::PreparedF7FundingGateV12>>,
    claim_owner_v21: Rc<std::cell::RefCell<super::claim_owner_v21::ProductionClaimOwnerV21>>,
}

impl ProductionXmrGraphCustodyV23 {
    /// Install the exact same-Store executor before readiness can be signed.
    pub(crate) fn activate_recovery_v23(
        &mut self,
        chain: TrustedChainIdV1,
        setup: &xmr_setup_profile::ValidatedXmrSetup,
        scanner: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
        deferred: &crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23,
    ) -> Result<(), crate::production_contracts::ProductionFundingErrorV20> {
        use crate::production_contracts::ProductionFundingErrorV20 as Error;
        self.revalidate().map_err(|_| Error::Binding)?;
        if self.funding_gate.is_some() {
            deferred.require_driver().map_err(|_| Error::Binding)?;
            return Ok(());
        }
        let context = scanner.funding_validation_context_v20()?;
        let gate = Rc::new(self.store.prepare_or_resume_xmr_bounded_f7_gate_v23(
            chain,
            dom_scriptless_store::F7FundingGatePreparationV12 {
                role: &self.role,
                collateral: self.produced.collateral(),
                funding_template: self.produced.graph().funding_template(),
                claim_template: self.produced.graph().claim_template(),
                recovery: dom_scriptless_store::F7RecoveryPreparationV12::XmrBoundedV23 {
                    produced: &self.produced,
                    custody: &self.custody,
                    ordinary_rounds: &self.ordinary,
                    setup,
                },
                context,
            },
        )?);
        let driver = Rc::new(
            crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12::new(
                Rc::clone(&self.store),
                Rc::clone(&gate),
                Rc::clone(&self.custody),
                scanner.xmr_recovery_client_v12(),
            )
            .map_err(|_| Error::Binding)?,
        );
        let mut private_owner = self
            .claim_owner_v21
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?;
        if private_owner.xmr_refund_readiness_v23.is_some() {
            return Err(Error::Binding);
        }
        deferred
            .install(Rc::clone(&driver))
            .map_err(|_| Error::Binding)?;
        private_owner.xmr_refund_readiness_v23 = Some(driver);
        drop(private_owner);
        // Both views retain the same already-authenticated recovery driver.
        // No scalar, transaction bytes, or new funding permission is exported.
        self.funding_gate = Some(gate);
        Ok(())
    }

    /// Build the observer only after actual DOM funding has entered its
    /// native lifecycle. Resources stay retained while funding is pending.
    pub(crate) fn prepare_f7_observer_v23(
        &self,
        chain: TrustedChainIdV1,
        resources: &mut Option<crate::production_xmr_sweep::ProductionXmrF7ResourcesV23>,
    ) -> Result<
        Option<crate::production_contracts::ProductionSelectedF7ObserverV12>,
        crate::production_contracts::ProductionF7RuntimeErrorV12,
    > {
        use crate::production_contracts::ProductionF7RuntimeErrorV12 as Error;
        let head = self.store.load_session(self.role.session_id().0)?;
        if matches!(
            head.phase(),
            dom_scriptless_store::SessionPhaseV1::RefundSigning
                | dom_scriptless_store::SessionPhaseV1::FundingAuthorized
                | dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                | dom_scriptless_store::SessionPhaseV1::Refunded
                | dom_scriptless_store::SessionPhaseV1::FailedClosed
        ) || head.irreversible().adaptor_secret_exposed
        {
            return Ok(None);
        }
        self.revalidate().map_err(|_| Error::Custody)?;
        let gate = self.funding_gate.as_ref().ok_or(Error::Scope)?;
        let request = self.store.f7_anchor_request_binding_v12(gate, chain)?;
        if request.role() != &self.role {
            return Err(Error::Scope);
        }
        let observer = resources
            .take()
            .ok_or(Error::Consumed)?
            .into_observer(Rc::clone(&self.produced), Rc::clone(&self.custody))?;
        Ok(Some(observer))
    }

    pub(crate) fn revalidate(&self) -> Result<(), ProductionXmrGraphCustodyErrorV23> {
        self.custody.revalidate()?;
        let scope = self.store.require_xmr_graph_custody_ready_v23(
            &self.role,
            &self.produced,
            self.custody.scope().custody_id,
        )?;
        if scope != *self.custody.scope() {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        self.store.revalidate_xmr_ordinary_recovery_rounds_v11(
            &self.ordinary,
            &self.role,
            self.produced.graph(),
            self.produced.economic().policy(),
            &self.custody,
        )?;
        Ok(())
    }
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn retained_xmr_graph_ready_for_activation_v23(
        &self,
        chain: TrustedChainIdV1,
    ) -> Result<
        Option<(ProducedXmrRecoveryGraphV12, FinalClaimRoleBindingV1)>,
        ProductionXmrGraphCustodyErrorV23,
    > {
        self.store
            .retained_xmr_graph_ready_for_activation_v23(chain, self.session_id)
            .map_err(ProductionXmrGraphCustodyErrorV23::Store)
    }

    pub(crate) fn retained_xmr_graph_custody_v23(
        &self,
        chain: TrustedChainIdV1,
        custody_id: [u8; 32],
    ) -> Result<
        Option<(ProducedXmrRecoveryGraphV12, FinalClaimRoleBindingV1)>,
        ProductionXmrGraphCustodyErrorV23,
    > {
        self.store
            .retained_xmr_graph_custody_v23(chain, self.session_id, custody_id)
            .map_err(ProductionXmrGraphCustodyErrorV23::Store)
    }

    /// Restart selection is journal-first. Ready always opens; Started may
    /// create only if the final archive has never been published.
    pub(crate) fn mount_xmr_graph_custody_v23(
        &self,
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        resources: ProductionXmrGraphCustodyResourcesV23,
        private_owner: Option<&crate::production_xmr_sweep::ProductionXmrPrivateRefundOwnerV23>,
    ) -> Result<ProductionXmrGraphCustodyV23, ProductionXmrGraphCustodyErrorV23> {
        use dom_scriptless_store::XmrGraphCustodyProvisioningStateV23 as State;
        let scope =
            self.require_xmr_graph_custody_scope_v23(&produced, role, resources.custody_id)?;
        if private_owner.is_some()
            != matches!(scope.role, XmrRecoveryCustodyRoleV11::PrivateRefundOwner)
        {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        let permit = self.store.prepare_xmr_graph_custody_provisioning_v23(
            role,
            &produced,
            resources.custody_id,
        )?;
        if permit.scope() != scope {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        let state = permit.state();
        drop(permit);
        let published = match resources.parent.symlink_metadata(&resources.directory_name) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(ProductionXmrGraphCustodyErrorV23::Scope),
        };
        if state == State::Ready || published {
            // A corrupt, symlinked or missing Ready root is an error, not creation.
            self.reopen_xmr_graph_custody_v23(produced, role, resources)
        } else {
            let private_refund = private_owner
                .map(|owner| owner.complete(produced.graph()))
                .transpose()
                .map_err(|_| ProductionXmrGraphCustodyErrorV23::Scope)?;
            self.create_xmr_graph_custody_v23(produced, role, resources, private_refund)
        }
    }

    /// Create only an explicitly selected fresh archive. The U owner must
    /// supply a genuinely completed private refund; this function never adapts U.
    pub(crate) fn create_xmr_graph_custody_v23(
        &self,
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        resources: ProductionXmrGraphCustodyResourcesV23,
        private_refund: Option<PrivateXmrRefundTransactionV11>,
    ) -> Result<ProductionXmrGraphCustodyV23, ProductionXmrGraphCustodyErrorV23> {
        let scope =
            self.require_xmr_graph_custody_scope_v23(&produced, role, resources.custody_id)?;
        if private_refund.is_some()
            != matches!(scope.role, XmrRecoveryCustodyRoleV11::PrivateRefundOwner)
        {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        let permit = self.store.prepare_xmr_graph_custody_provisioning_v23(
            role,
            &produced,
            resources.custody_id,
        )?;
        if permit.state() != dom_scriptless_store::XmrGraphCustodyProvisioningStateV23::Started
            || permit.scope() != scope
        {
            // Explicit create must never recreate a Ready archive that disappeared.
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        // All scope/identity/role checks precede the first archive filesystem write.
        let (custody, permit) = self.store.create_xmr_graph_custody_archive_v23(
            permit,
            resources.parent,
            &resources.directory_name,
            produced.graph(),
            resources.key,
            private_refund.as_ref(),
        )?;
        let custody = Rc::new(custody);
        drop(private_refund);
        self.audit_xmr_graph_custody_owner_v23(produced, role, custody, Some(permit))
    }

    /// Post-funding restart is read-only with respect to provisioning:
    /// authenticate Ready first, then open the exact archive, never prepare/create.
    pub(crate) fn reopen_ready_xmr_graph_custody_v23(
        &self,
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        resources: ProductionXmrGraphCustodyResourcesV23,
    ) -> Result<ProductionXmrGraphCustodyV23, ProductionXmrGraphCustodyErrorV23> {
        let expected =
            self.require_xmr_graph_custody_scope_v23(&produced, role, resources.custody_id)?;
        let scope = self.store.require_xmr_graph_custody_ready_v23(
            role,
            &produced,
            resources.custody_id,
        )?;
        if scope != expected {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        let custody = Rc::new(XmrRecoveryCustodyV11::open_existing(
            resources.parent,
            &resources.directory_name,
            scope,
            resources.key,
        )?);
        self.audit_xmr_graph_custody_owner_v23(produced, role, custody, None)
    }

    /// Open existing exact custody only. Absence/corruption never falls back
    /// to creation or changes a private-refund owner into a public counterparty.
    pub(crate) fn reopen_xmr_graph_custody_v23(
        &self,
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        resources: ProductionXmrGraphCustodyResourcesV23,
    ) -> Result<ProductionXmrGraphCustodyV23, ProductionXmrGraphCustodyErrorV23> {
        let scope =
            self.require_xmr_graph_custody_scope_v23(&produced, role, resources.custody_id)?;
        let permit = self.store.prepare_xmr_graph_custody_provisioning_v23(
            role,
            &produced,
            resources.custody_id,
        )?;
        if permit.scope() != scope {
            return Err(ProductionXmrGraphCustodyErrorV23::Scope);
        }
        // Both Started and Ready require an existing complete/authenticated archive.
        let custody = Rc::new(XmrRecoveryCustodyV11::open_existing(
            resources.parent,
            &resources.directory_name,
            scope,
            resources.key,
        )?);
        self.audit_xmr_graph_custody_owner_v23(produced, role, custody, Some(permit))
    }

    fn require_xmr_graph_custody_scope_v23(
        &self,
        produced: &ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        custody_id: [u8; 32],
    ) -> Result<XmrRecoveryCustodyScopeV11, ProductionXmrGraphCustodyErrorV23> {
        use ProductionXmrGraphCustodyErrorV23::Scope;
        let graph = produced.graph();
        let binding = graph.binding();
        let terms = role.terms();
        let policy = produced.economic().policy();
        let validated = policy.policy().validate_for(terms).map_err(|_| Scope)?;
        let identities = self.store.transport_identity_references(self.session_id)?;
        let local = identities
            .iter()
            .find(|reference| {
                reference.key_reference() == self.identity.reference().key_reference()
            })
            .ok_or(Scope)?;
        if local.participant_id() != &self.local_participant
            || local.schnorr_public_key().to_compressed_bytes()
                != *self.identity.reference().schnorr_public_key()
            || local.noise_public_key() != self.identity.reference().noise_public_key()
            || custody_id == [0; 32]
            || role.route_id() != self.route_id
            || role.session_id().0 != self.session_id
            || binding.session_id != self.session_id
            || binding.chain_id != role.dom_chain_id().0
            || binding.terms_hash != role.terms_hash().map_err(|_| Scope)?
            || binding.funding_commitment != role.shared_output_commitment()
            || binding.claim_adaptor_point != role.adaptor_point_sec1()
            || produced.economic().graph_digest() != graph.graph_digest()
            || &validated != policy
            || policy.policy().bounded_availability_v23.is_none()
            || terms.dom_leg.refund_to == terms.counterparty_leg.refund_to
        {
            return Err(Scope);
        }
        for (template, expected) in [
            (graph.funding_template(), role.funding_template_hash()),
            (graph.claim_template(), role.claim_template_hash()),
            (graph.refund_template(), role.refund_template_hash()),
        ] {
            if dom_adaptor::canonical_template_v1(template)
                .map_err(|_| Scope)?
                .1
                != expected
            {
                return Err(Scope);
            }
        }
        let custody_role = if *local.participant_id() == terms.dom_leg.refund_to.0 {
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner
        } else if *local.participant_id() == terms.counterparty_leg.refund_to.0 {
            XmrRecoveryCustodyRoleV11::PublicCounterparty
        } else {
            return Err(Scope);
        };
        let head = self.store.load_session(self.session_id)?;
        // Lifecycle authorization belongs to the Store's create/Ready paths.
        // This identity/scope check also serves historical Ready reopening.
        if head.terms_hash() != binding.terms_hash {
            return Err(Scope);
        }
        Ok(XmrRecoveryCustodyScopeV11 {
            binding: *binding,
            graph_digest: *graph.graph_digest(),
            custody_id,
            role: custody_role,
        })
    }

    fn audit_xmr_graph_custody_owner_v23(
        &self,
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        custody: Rc<XmrRecoveryCustodyV11>,
        permit: Option<dom_scriptless_store::PreparedXmrGraphCustodyProvisioningV23>,
    ) -> Result<ProductionXmrGraphCustodyV23, ProductionXmrGraphCustodyErrorV23> {
        let (cancel_session, compensation_session) = produced.ordinary_sessions();
        let ordinary = self.store.audit_xmr_ordinary_recovery_rounds_v11(
            role,
            produced.graph(),
            produced.economic().policy(),
            &custody,
            XmrOrdinaryRecoveryRoundSessionsV11 {
                cancel_session,
                compensation_session,
            },
        )?;
        if let Some(permit) = permit {
            self.store
                .mark_xmr_graph_custody_ready_v23(permit, &custody)?;
        } else {
            self.store.require_xmr_graph_custody_ready_v23(
                role,
                &produced,
                custody.scope().custody_id,
            )?;
        }
        let owner = ProductionXmrGraphCustodyV23 {
            produced: Rc::new(produced),
            custody,
            ordinary,
            store: Rc::clone(&self.store),
            role: role.clone(),
            funding_gate: None,
            claim_owner_v21: Rc::clone(&self.claim_owner_v21),
        };
        owner.revalidate()?;
        Ok(owner)
    }
}
