//! DOM refund arming for the native bounded XMR graph, without public U bytes.
use super::*;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn dom_refund_face_native_xmr_v23(
        &self,
        scope: ProductionDomRefundFaceScopeV1<'_>,
        binding: DomSessionBindingV1,
    ) -> Result<ProductionDomRefundFaceV1, ProductionRefundArmingOpenErrorV1> {
        let terms = match scope.position() {
            LegIdV1::Upstream => scope.composition().upstream(),
            LegIdV1::Downstream => scope.composition().downstream(),
        };
        if terms.counterparty_leg.mechanism
            != kaystra_core::types::LockMechanism::CrossCurveSharedSpend
        {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        self.issue_dom_refund_face_once(|| {
            let mut authority = self.authenticate_dom_refund_scope(scope, binding)?;
            // The slot is installed only by the same native custody owner when
            // its authenticated F7 recovery driver is attached. Empty is pending.
            authority.native_xmr_refund_v23 = Some(Rc::clone(&self.claim_owner_v21));
            Ok(authority)
        })
    }
}

impl ProductionDomRefundStoreFaceV1 {
    pub(crate) fn native_xmr_refund_selected_v23(&self) -> bool {
        self.native_xmr_refund_v23.is_some()
    }

    pub(crate) fn native_xmr_refund_readiness_v23(
        &self,
    ) -> Result<Option<dom_scriptless_store::VerifiedXmrRefundReadinessV23>, SessionStoreError>
    {
        let slot = self
            .native_xmr_refund_v23
            .as_ref()
            .ok_or(SessionStoreError::InvalidTransition)?;
        let owner = slot
            .try_borrow()
            .map_err(|_| SessionStoreError::StoreBusy)?;
        let Some(driver) = owner.xmr_refund_readiness_v23.as_ref() else {
            return Ok(None);
        };
        let ready = driver.refund_readiness_v23()?;
        if ready.chain_id() != &self.binding.chain_id()
            || ready.session_id() != &self.binding.session_id()
            || ready.terms_hash() != &self.binding.terms_digest()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(Some(ready))
    }
}
