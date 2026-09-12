//! One physical enrollment opening, transferred only after native binding.
use super::*;
use std::{cell::RefCell, rc::Rc};
use xmr_dleq_nullifier_store::DleqNullifierStore;
use xmr_session_init::{PreparedXmrShareEnrollmentV23, XmrLocalShareRoleV11};

/// No spending/broadcast trait, scalar getter, Clone, or database factory.
pub(crate) struct ProductionXmrEnrolledResourcesV23 {
    route: [u8; 32],
    local_participant: [u8; 32],
    terms: SettlementTermsV1,
    profile: XmrAdapterProfileV1,
    registry_profile: chain_profile::ChainProfileV1,
    genesis: [u8; 32],
    enrollment: PreparedXmrShareEnrollmentV23,
    constraints: crate::production_inputs::ProductionXmrEnrollmentBundleV23,
    role: XmrLocalShareRoleV11,
    secrets: Rc<EncryptedSqliteSecretStore>,
    nullifiers: Rc<DleqNullifierStore>,
    sidecar: Rc<RefCell<BlockingUdsSidecarPort>>,
}

/// The same physical resources after public template binding, not a funding
/// grant. Custody mounting, fresh F7, signing and durable actuation still apply.
pub(crate) struct ActivatedXmrResourcesV23 {
    pub(crate) sweep: ProductionXmrSweepAuthorityV10,
    pub(crate) nullifiers: Rc<DleqNullifierStore>,
    pub(crate) recovery: Rc<ProductionXmrDeferredRecoveryV23>,
}

impl ProductionXmrEnrolledResourcesV23 {
    /// Read the exact deposit before F6 reopening. This uses only authenticated
    /// enrollment and its retained view material, not a graph/F6/F7 capability.
    /// The same sidecar and encrypted Store are later moved into activation.
    pub(crate) fn observe_reopen_funding_v24(
        &self,
        deployment: &deployment_registry::ResolvedMoneroDeploymentV1,
        urls: &[String],
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, Refusal> {
        use f7_anchor_authority::families_v11::{
            verify_xmr_funding_v11, F7FamilyAuthorityErrorV11 as E, XmrFundingObservationRequestV11,
        };
        if self.genesis != deployment.deployment().genesis_hash {
            return Err(Refusal::Conflict);
        }
        let mut sidecar = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Refusal::Unavailable)?;
        executor
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    verify_xmr_funding_v11(
                        XmrFundingObservationRequestV11 {
                            terms: &self.terms,
                            setup: self.enrollment.setup(),
                            profile: &self.profile,
                            deployment,
                            daemon_urls: urls,
                        },
                        &mut sidecar,
                        self.secrets.as_ref(),
                    ),
                )
                .await
                .unwrap_or(Err(E::Unavailable))
            })
            .map_err(|error| match error {
                E::Unavailable | E::FundingAbsent | E::InsufficientFinality => Refusal::Unavailable,
                _ => Refusal::Conflict,
            })
    }

    /// Read-only authentication of existing local custody. The caller opens
    /// each database once with open_existing; this path never initializes it.
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        local_participant: [u8; 32],
        secrets: EncryptedSqliteSecretStore,
        nullifiers: DleqNullifierStore,
        sidecar: BlockingUdsSidecarPort,
    ) -> Result<Self, Refusal> {
        let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
        let constraints = session
            .native_enrollment_bundle_v23()
            .ok_or(Refusal::Conflict)?;
        let admitted = session.native_enrollment_v23().ok_or(Refusal::Conflict)?;
        if session.refund_bundle().is_some() {
            return Err(Refusal::Conflict);
        }
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        if terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
            || terms.terms_hash().map_err(|_| Refusal::Conflict)? != session.terms_digest()
            || terms.session_id.0 != session.session_id()
        {
            return Err(Refusal::Conflict);
        }
        let role = if local_participant == terms.counterparty_leg.beneficiary.0 {
            XmrLocalShareRoleV11::ClaimReceiver
        } else if local_participant == terms.counterparty_leg.refund_to.0 {
            XmrLocalShareRoleV11::RefundReceiver
        } else {
            return Err(Refusal::Conflict);
        };
        admitted
            .require_setup(session.setup(), constraints.proof())
            .map_err(|_| Refusal::Conflict)?;
        let enrollment = xmr_session_init::prepare_xmr_share_enrollment_v23(
            session.setup(),
            constraints.proof(),
        )
        .map_err(|_| Refusal::Conflict)?;
        xmr_session_init::resume_enrolled_session_for_role_v23(
            &enrollment,
            &secrets,
            &nullifiers,
            role,
        )
        .map_err(|_| Refusal::Conflict)?;
        Ok(Self {
            route: session.route_id(),
            local_participant,
            terms: terms.clone(),
            profile: session.profile().clone(),
            registry_profile: session.deployment().profile().clone(),
            genesis: session.deployment().deployment().genesis_hash,
            enrollment,
            constraints: constraints.clone(),
            role,
            secrets: Rc::new(secrets),
            nullifiers: Rc::new(nullifiers),
            sidecar: Rc::new(RefCell::new(sidecar)),
        })
    }

    /// Consumes the preparation owner exactly once. Requires a live readback
    /// of the same Contracts opening's bilateral native origin; no caller hash.
    pub(crate) fn activate<F: route_transport::F6TransportPortV1>(
        self,
        graph: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
        contracts: &crate::production_contracts::ProductionContractsV1<F>,
    ) -> Result<ActivatedXmrResourcesV23, Refusal> {
        let authority = graph
            .native_refund_binding_v23()
            .map_err(|_| Refusal::Conflict)?;
        contracts
            .revalidate_xmr_refund_template_binding_v23(authority)
            .map_err(|_| Refusal::Conflict)?;
        if graph.binding().route_id() != self.route
            || graph.binding().participant().participant_id() != self.local_participant
            || graph.terms() != &self.terms
            || graph.genesis() != self.genesis
        {
            return Err(Refusal::Conflict);
        }
        self.enrollment
            .require_setup(graph.setup(), self.constraints.proof())
            .map_err(|_| Refusal::Conflict)?;
        let refund = graph.refund_bundle_v23().map_err(|_| Refusal::Conflict)?;
        if refund.proof != *self.constraints.proof()
            || refund.template_hash != authority.refund_template_hash()
            || refund.adaptor_point_sec1 != *self.constraints.adaptor_point_sec1()
            || refund.executor_profile_hash != self.constraints.executor_profile_hash()
            || refund.deadline != self.constraints.deadline()
            || refund.refund_destination() != Some(self.constraints.refund_destination())
        {
            return Err(Refusal::Conflict);
        }
        xmr_session_init::resume_enrolled_session_for_role_v23(
            &self.enrollment,
            self.secrets.as_ref(),
            self.nullifiers.as_ref(),
            self.role,
        )
        .map_err(|_| Refusal::Conflict)?;
        let binding = SweepBinding::authenticate(
            &self.terms,
            graph.setup(),
            &self.profile,
            &self.registry_profile,
            refund,
            self.local_participant,
        )?;
        let material = self
            .secrets
            .load(&binding.setup.settlement_id(), &binding.setup.terms_hash())
            .map_err(map_secret)?;
        binding.local_keys(&material)?;
        let recovery = Rc::new(ProductionXmrDeferredRecoveryV23::from_setup(graph)?);
        let refund_source = if binding.local_role == LocalRole::RefundReceiver {
            Some(ProductionXmrRefundRevealSourceV11::RecoveryDeferredV23(
                Rc::clone(&recovery),
            ))
        } else {
            None
        };
        Ok(ActivatedXmrResourcesV23 {
            sweep: ProductionXmrSweepAuthorityV10 {
                binding,
                secrets: self.secrets,
                sidecar: self.sidecar,
                refund_source,
                private_funding_v12: None,
                funding_terms_v22: self.terms,
                funding_profile_v22: self.profile,
                funding_quorum_v22: None,
                local_refund_v24: None,
            },
            nullifiers: self.nullifiers,
            recovery,
        })
    }
}
