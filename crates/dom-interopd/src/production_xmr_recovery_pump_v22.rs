//! Recovery runs with the same sweep owner and Store as the selected child.
//! Each tick performs one observation stage; terminal recording needs a newly
//! verified funding capability and the runtime's sole fenced supervisor.
use crate::production_child_xmr::{
    ScopedXmrSweepAuthorityV1, XmrBuiltSweepV1, XmrExternalFundingFactsV1,
};
use crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12;
use crate::production_xmr_sweep::{
    ProductionXmrDeferredRecoveryV23, ProductionXmrSweepAuthorityV10,
};
use route_executor::LegIdV1;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::{cell::RefCell, rc::Rc};

pub(crate) struct SharedXmrSweepV22(Rc<RefCell<ProductionXmrSweepAuthorityV10>>);
impl SharedXmrSweepV22 {
    pub(crate) fn build_authenticated_remote_sweep_v23(
        &mut self,
        authorized: &crate::production_xmr_remote_sweep_v23::AuthenticatedRemoteSweepBuildV23<'_>,
    ) -> Result<
        xmr_live_sidecar_api::BuildSweepResponseV23<xmr_live_sidecar_api::BuildSweepResponseV2>,
        Refusal,
    > {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_authenticated_remote_sweep_v23(authorized)
    }
}
impl ScopedXmrSweepAuthorityV1 for SharedXmrSweepV22 {
    fn observe_verified_funding_v22(
        &mut self,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .observe_verified_funding_v22()
    }
    fn broadcast_funding_v12(
        &mut self,
        recovery: &ProductionXmrRecoveryDriverV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .broadcast_funding_v12(recovery, broadcast)
    }
    fn build_claim_sweep(
        &mut self,
        nonce: [u8; 32],
        scalar: &route_composer::RouteScalar,
    ) -> Result<XmrBuiltSweepV1, Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_claim_sweep(nonce, scalar)
    }
    fn build_refund_sweep(&mut self, nonce: [u8; 32]) -> Result<XmrBuiltSweepV1, Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_refund_sweep(nonce)
    }
    fn complete_claim_sweep_v23(
        &mut self,
        request: &crate::production_child_router::ProductionChildMaterializationRequestV1,
        scalar: &route_composer::RouteScalar,
        retained: &XmrBuiltSweepV1,
    ) -> Result<(), Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .complete_claim_sweep_v23(request, scalar, retained)
    }
    fn verify_external_funding(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<XmrExternalFundingFactsV1, Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .verify_external_funding(nonce)
    }
}

pub(crate) struct XmrCompensationReportV22 {
    pub(crate) leg: LegIdV1,
    pub(crate) driver: Rc<ProductionXmrRecoveryDriverV12>,
    pub(crate) funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    pub(crate) observed: adapter_dom_real::VerifiedDomCompensationObservationV11,
}

enum RecoveryDriverV23 {
    Attached(Rc<ProductionXmrRecoveryDriverV12>),
    Deferred(Rc<ProductionXmrDeferredRecoveryV23>),
}
impl RecoveryDriverV23 {
    fn resolve(&self) -> Result<Rc<ProductionXmrRecoveryDriverV12>, Refusal> {
        match self {
            Self::Attached(driver) => Ok(Rc::clone(driver)),
            Self::Deferred(slot) => slot.require_driver(),
        }
    }
}

pub(crate) struct ProductionXmrRecoveryPumpV22 {
    leg: LegIdV1,
    sweep: SharedXmrSweepV22,
    driver: RecoveryDriverV23,
    funding: Option<f7_anchor_authority::families_v11::VerifiedXmrFundingV11>,
    pending: Option<adapter_dom_real::VerifiedDomCompensationObservationV11>,
    execute_next: bool,
}
impl ProductionXmrRecoveryPumpV22 {
    pub(crate) fn attach(
        leg: LegIdV1,
        sweep: ProductionXmrSweepAuthorityV10,
        driver: Rc<ProductionXmrRecoveryDriverV12>,
    ) -> (Self, SharedXmrSweepV22) {
        let sweep = Rc::new(RefCell::new(sweep));
        (
            Self {
                leg,
                sweep: SharedXmrSweepV22(Rc::clone(&sweep)),
                driver: RecoveryDriverV23::Attached(driver),
                funding: None,
                pending: None,
                execute_next: false,
            },
            SharedXmrSweepV22(sweep),
        )
    }

    pub(crate) fn attach_deferred_v23(
        leg: LegIdV1,
        sweep: ProductionXmrSweepAuthorityV10,
        slot: Rc<ProductionXmrDeferredRecoveryV23>,
    ) -> Result<(Self, SharedXmrSweepV22), Refusal> {
        slot.require_sweep(&sweep)?;
        let sweep = Rc::new(RefCell::new(sweep));
        Ok((
            Self {
                leg,
                sweep: SharedXmrSweepV22(Rc::clone(&sweep)),
                driver: RecoveryDriverV23::Deferred(slot),
                funding: None,
                pending: None,
                execute_next: false,
            },
            SharedXmrSweepV22(sweep),
        ))
    }

    pub(crate) fn tick(&mut self) -> Result<Option<XmrCompensationReportV22>, Refusal> {
        // An empty slot is not authority even to start observing funding here.
        let driver = self.driver.resolve()?;
        if !self.execute_next || self.pending.is_some() {
            let funding = match self.sweep.observe_verified_funding_v22() {
                Ok(proof) => Some(proof),
                Err(Refusal::Unavailable) => None,
                Err(error) => return Err(error),
            };
            if self.pending.is_some() {
                if let Some(funding) = funding {
                    let observed = self.pending.take().ok_or(Refusal::Conflict)?;
                    return Ok(Some(XmrCompensationReportV22 {
                        leg: self.leg,
                        driver: Rc::clone(&driver),
                        funding,
                        observed,
                    }));
                }
                return Ok(None);
            }
            self.funding = funding;
            self.execute_next = true;
            return Ok(None);
        }
        self.execute_next = false;
        let progress = match self.funding.take() {
            Some(funding) => driver.tick_with_funding(funding),
            None => driver.tick(), // Can cancel/refund; cannot compensate without funding.
        };
        match progress {
            Ok(adapter_dom_real::DomXmrRecoveryProgressV12::DomCompensated(observed)) => {
                self.pending = Some(observed)
            }
            Ok(_) | Err(Refusal::Unavailable) => {}
            Err(error) => return Err(error),
        }
        Ok(None)
    }
}
