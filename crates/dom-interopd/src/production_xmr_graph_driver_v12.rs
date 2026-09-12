//! Native recovery graph formation -> encrypted custody -> same-Store ordinary
//! round audit. This is the concrete prefunding handoff, not a Boolean grant.
//! The separate V12 funding gate must bind both signed readiness votes before
//! permitting DOM collateral and then observe C before permitting XMR funding.

use cap_std::fs::Dir;
use dom_final_claim_binding::FinalClaimRoleBindingV1;
use dom_scriptless_crypto::{PrivateXmrRefundTransactionV11, XmrRecoverySealKeyV11};
use dom_scriptless_store::{
    ContractsSessionStoreV1, SessionStoreError, VerifiedXmrOrdinaryRecoveryRoundsV11,
    XmrOrdinaryRecoveryRoundSessionsV11, XmrRecoveryCustodyErrorV11, XmrRecoveryCustodyRoleV11,
    XmrRecoveryCustodyScopeV11, XmrRecoveryCustodyV11,
};
use std::rc::Rc;
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

/// No error substitutes an empty graph, regenerated keys or legacy FinalRefund.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionXmrGraphErrorV12 {
    #[error("XMR graph differs from the admitted native role")]
    Scope,
    #[error("V13 refuses prefunding custody for unconditional XMR compensation")]
    FundingConditionUnavailable,
    #[error("XMR graph recovery custody refused")]
    Custody(#[source] XmrRecoveryCustodyErrorV11),
    #[error("native ordinary XMR recovery signing history refused")]
    Contracts(#[source] SessionStoreError),
}

/// The root selects these resources for the XMR leg only. Keys originate in
/// private credentials, never from T, U, a terms digest or any public identity.
pub(crate) struct ProductionXmrGraphCustodyRequestV12 {
    pub(crate) parent: Dir,
    pub(crate) directory_name: String,
    pub(crate) custody_id: [u8; 32],
    pub(crate) role: XmrRecoveryCustodyRoleV11,
    pub(crate) key: XmrRecoverySealKeyV11,
}

/// Owns the graph formation result, actual encrypted custody and an audit from
/// the exact retained Contracts Store. None of these is created from a digest.
pub(crate) struct ProductionXmrGraphDriverV12 {
    produced: ProducedXmrRecoveryGraphV12,
    custody: Rc<XmrRecoveryCustodyV11>,
    ordinary: VerifiedXmrOrdinaryRecoveryRoundsV11,
    contracts: Rc<ContractsSessionStoreV1>,
}

impl ProductionXmrGraphDriverV12 {
    /// Fresh pre-funding publication. The private transaction, if present,
    /// comes from the authenticated U owner's `complete_private_dom_refund_v12`.
    /// A completed final refund never enters a public DSC1 message here.
    pub(crate) fn create(
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        contracts: Rc<ContractsSessionStoreV1>,
        request: ProductionXmrGraphCustodyRequestV12,
        private_refund: Option<PrivateXmrRefundTransactionV11>,
    ) -> Result<Self, ProductionXmrGraphErrorV12> {
        produced
            .graph()
            .require_conditional_compensation_v22()
            .map_err(|_| ProductionXmrGraphErrorV12::FundingConditionUnavailable)?;
        let scope = require_scope(&produced, role, request.custody_id, request.role)?;
        let custody = Rc::new(
            XmrRecoveryCustodyV11::create(
                request.parent,
                &request.directory_name,
                scope,
                produced.graph(),
                request.key,
                private_refund.as_ref(),
            )
            .map_err(ProductionXmrGraphErrorV12::Custody)?,
        );
        // Drop wipes the final U signature after it has entered encrypted
        // custody. It never becomes a field of the public producer result.
        drop(private_refund);
        Self::audit(produced, role, contracts, custody)
    }

    /// Resume an interrupted prefunding handoff using the same exact native
    /// graph reconstructed from retained nonce/partial histories. This never
    /// creates missing custody or replaces its private signature. Post-funding
    /// recovery instead opens the archive under the durable V12 funding gate.
    pub(crate) fn reopen_prefunding(
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        contracts: Rc<ContractsSessionStoreV1>,
        request: ProductionXmrGraphCustodyRequestV12,
    ) -> Result<Self, ProductionXmrGraphErrorV12> {
        produced
            .graph()
            .require_conditional_compensation_v22()
            .map_err(|_| ProductionXmrGraphErrorV12::FundingConditionUnavailable)?;
        let scope = require_scope(&produced, role, request.custody_id, request.role)?;
        let custody = Rc::new(
            XmrRecoveryCustodyV11::open_existing(
                request.parent,
                &request.directory_name,
                scope,
                request.key,
            )
            .map_err(ProductionXmrGraphErrorV12::Custody)?,
        );
        Self::audit(produced, role, contracts, custody)
    }

    fn audit(
        produced: ProducedXmrRecoveryGraphV12,
        role: &FinalClaimRoleBindingV1,
        contracts: Rc<ContractsSessionStoreV1>,
        custody: Rc<XmrRecoveryCustodyV11>,
    ) -> Result<Self, ProductionXmrGraphErrorV12> {
        let (cancel_session, compensation_session) = produced.ordinary_sessions();
        let ordinary = contracts
            .audit_xmr_ordinary_recovery_rounds_v11(
                role,
                produced.graph(),
                produced.economic().policy(),
                &custody,
                XmrOrdinaryRecoveryRoundSessionsV11 {
                    cancel_session,
                    compensation_session,
                },
            )
            .map_err(ProductionXmrGraphErrorV12::Contracts)?;
        Ok(Self {
            produced,
            custody,
            ordinary,
            contracts,
        })
    }

    /// Revalidate the actual retained directory and both ordinary native
    /// journals immediately before preparing the bilateral funding gate.
    pub(crate) fn revalidate_prefunding(
        &self,
        role: &FinalClaimRoleBindingV1,
    ) -> Result<(), ProductionXmrGraphErrorV12> {
        self.contracts
            .revalidate_xmr_ordinary_recovery_rounds_v11(
                &self.ordinary,
                role,
                self.produced.graph(),
                self.produced.economic().policy(),
                &self.custody,
            )
            .map_err(ProductionXmrGraphErrorV12::Contracts)
    }

    /// Native graph, exact amounts and actual C/D ownership evidence.
    pub(crate) const fn produced(&self) -> &ProducedXmrRecoveryGraphV12 {
        &self.produced
    }
    /// Share the same physical custody owner with the observer/execution driver.
    pub(crate) fn custody(&self) -> Rc<XmrRecoveryCustodyV11> {
        Rc::clone(&self.custody)
    }
    /// Closed same-Store ordinary-round proof consumed by native funding gate.
    pub(crate) const fn ordinary(&self) -> &VerifiedXmrOrdinaryRecoveryRoundsV11 {
        &self.ordinary
    }
}

fn require_scope(
    produced: &ProducedXmrRecoveryGraphV12,
    role: &FinalClaimRoleBindingV1,
    custody_id: [u8; 32],
    custody_role: XmrRecoveryCustodyRoleV11,
) -> Result<XmrRecoveryCustodyScopeV11, ProductionXmrGraphErrorV12> {
    let binding = produced.graph().binding();
    let terms = role.terms();
    if custody_id == [0; 32]
        || binding.session_id != terms.session_id.0
        || binding.chain_id != terms.dom_leg.chain_id.0
        || binding.terms_hash
            != terms
                .terms_hash()
                .map_err(|_| ProductionXmrGraphErrorV12::Scope)?
        || produced.economic().graph_digest() != produced.graph().graph_digest()
        || produced
            .economic()
            .policy()
            .policy()
            .validate_for(terms)
            .is_err()
    {
        return Err(ProductionXmrGraphErrorV12::Scope);
    }
    Ok(XmrRecoveryCustodyScopeV11 {
        binding: *binding,
        graph_digest: *produced.graph().graph_digest(),
        custody_id,
        role: custody_role,
    })
}
