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
use f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE;
use route_executor::LegIdV1;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::{cell::RefCell, rc::Rc, time::Duration};

pub(crate) struct SharedXmrSweepV22(Rc<RefCell<ProductionXmrSweepAuthorityV10>>);
impl SharedXmrSweepV22 {
    pub(crate) fn enable_local_refund_v24(
        &self,
        common: crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteClaimPinsV23,
        source: crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteRefundSourceV23,
        quorum: crate::production_children::QuorumXmrObservationPortV1,
    ) -> Result<(), Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .enable_local_refund_v24(common, source, quorum)
    }

    pub(crate) fn load_local_refund_with_proofs_v24(
        &self,
        request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<
            xmr_live_sidecar_api::BuildSweepResponseV2,
        >,
        Refusal,
    > {
        self.0
            .try_borrow()
            .map_err(|_| Refusal::Unavailable)?
            .load_local_refund_with_proofs_v24(request)
    }

    pub(crate) fn load_local_refund_with_deadline_v24(
        &self,
        request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
        deadline: std::time::Instant,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<
            xmr_live_sidecar_api::BuildSweepResponseV2,
        >,
        Refusal,
    > {
        self.0
            .try_borrow()
            .map_err(|_| Refusal::Unavailable)?
            .load_local_refund_with_deadline_v24(request, deadline)
    }

    pub(crate) fn remote_refund_pins_v23(
        &self,
        common: crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteClaimPinsV23,
    ) -> Result<crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteRefundPinsV23, Refusal>
    {
        self.0
            .try_borrow()
            .map_err(|_| Refusal::Unavailable)?
            .remote_refund_pins_v23(common)
    }

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
    fn build_refund_sweep_v23(
        &mut self,
        request: &crate::production_child_router::ProductionChildMaterializationRequestV1,
    ) -> Result<XmrBuiltSweepV1, Refusal> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_refund_sweep_v23(request)
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
    refund_responder_v24:
        Option<crate::production_xmr_remote_sweep_v23::ProductionXmrRefundResponderV24>,
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
                refund_responder_v24: None,
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
                refund_responder_v24: None,
            },
            SharedXmrSweepV22(sweep),
        ))
    }

    pub(crate) fn with_refund_responder_v24(
        mut self,
        responder: crate::production_xmr_remote_sweep_v23::ProductionXmrRefundResponderV24,
    ) -> Result<Self, Refusal> {
        if self.refund_responder_v24.is_some() {
            return Err(Refusal::Conflict);
        }
        self.refund_responder_v24 = Some(responder);
        Ok(self)
    }

    pub(crate) fn tick_remote_refund_v24(
        &mut self,
        snapshot: &route_executor::RouteSnapshotV1,
    ) -> Result<(), Refusal> {
        match &mut self.refund_responder_v24 {
            Some(responder) => responder.tick(snapshot, &mut self.sweep),
            None => Ok(()),
        }
    }

    /// Select only an already-final refund on a fully terminal route. This
    /// public predicate cannot authorize BUILD, funding or compensation.
    pub(crate) fn terminal_refund_leg_v24(
        &self,
        snapshot: &route_executor::RouteSnapshotV1,
    ) -> Option<LegIdV1> {
        terminal_refund_selected_v24(snapshot, self.leg, self.refund_responder_v24.is_some())
            .then_some(self.leg)
    }

    pub(crate) fn tick_remote_refund_bounded_v24(
        &mut self,
        snapshot: &route_executor::RouteSnapshotV1,
        deadline: std::time::Instant,
    ) -> Result<crate::production_xmr_remote_sweep_v23::RefundPublicationProgressV24, Refusal> {
        if self.terminal_refund_leg_v24(snapshot).is_none() {
            return Err(Refusal::Conflict);
        }
        self.refund_responder_v24
            .as_mut()
            .ok_or(Refusal::Conflict)?
            .tick_bounded_v24(snapshot, &mut self.sweep, deadline)
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
        let progress = drive_recovery_step_v23(
            &mut self.funding,
            |funding| funding.facts().age(),
            |funding| driver.tick_with_funding(funding),
            || driver.tick(),
        );
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

fn terminal_refund_selected_v24(
    snapshot: &route_executor::RouteSnapshotV1,
    leg: LegIdV1,
    responder: bool,
) -> bool {
    let selected = match leg {
        LegIdV1::Upstream => &snapshot.upstream,
        LegIdV1::Downstream => &snapshot.downstream,
    };
    responder
        && snapshot.coordination == route_executor::CoordinationPhaseV1::Terminal
        && !snapshot.has_open_funds()
        && !snapshot.aborted_unfunded
        && selected.funding.progress() == route_executor::ActionProgressV1::Final
        && selected.refund.progress() == route_executor::ActionProgressV1::Final
        && selected.claim.progress() == route_executor::ActionProgressV1::NotPrepared
        && selected.dom_compensation_v12.is_none()
}

/// The daemon interleaves other chain work between observation and execution.
/// An expired cached observation cannot authorize compensation, but must not
/// suppress independent DOM cancel/refund recovery. Both driver paths still
/// reauthenticate the retained Store/custody and scan canonical DOM state.
fn drive_recovery_step_v23<F, P>(
    funding: &mut Option<F>,
    age: impl FnOnce(&F) -> Duration,
    with_funding: impl FnOnce(F) -> Result<P, Refusal>,
    without_funding: impl FnOnce() -> Result<P, Refusal>,
) -> Result<P, Refusal> {
    match funding
        .take()
        .filter(|funding| age(funding) <= MAX_V11_EXTERNAL_ANCHOR_AGE)
    {
        Some(funding) => with_funding(funding),
        None => without_funding(), // Cannot create a compensation authority.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_public_refund_requires_exact_final_funded_leg_and_responder() {
        use route_executor::{
            ActionStateV1, CoordinationPhaseV1, EffectReferenceV1, RouteSnapshotV1,
        };
        let final_action = |id| ActionStateV1::Final {
            effect: EffectReferenceV1 {
                effect_id: [id; 32],
                fencing_epoch: 1,
                semantic_digest: [id + 1; 32],
                contains_route_secret: false,
                expected_transaction_id: Some([id + 2; 32]),
            },
            transaction_id: [id + 2; 32],
            evidence_digest: [id + 3; 32],
        };
        let mut snapshot = RouteSnapshotV1::new([1; 32]).unwrap();
        snapshot.upstream.funding = final_action(10);
        snapshot.upstream.refund = final_action(20);
        assert!(!terminal_refund_selected_v24(
            &snapshot,
            LegIdV1::Upstream,
            true
        ));
        snapshot.coordination = CoordinationPhaseV1::Terminal;
        assert!(terminal_refund_selected_v24(
            &snapshot,
            LegIdV1::Upstream,
            true
        ));
        assert!(!terminal_refund_selected_v24(
            &snapshot,
            LegIdV1::Upstream,
            false
        ));
        assert!(!terminal_refund_selected_v24(
            &snapshot,
            LegIdV1::Downstream,
            true
        ));
        snapshot.upstream.claim = final_action(30);
        assert!(!terminal_refund_selected_v24(
            &snapshot,
            LegIdV1::Upstream,
            true
        ));
    }
    use std::cell::Cell;

    // Move-only stand-in for the cache entry, not a fabricated native proof.
    struct CachedFunding {
        age: Duration,
    }

    #[test]
    fn recovery_dispatch_uses_fresh_funding_once_then_runs_without_it() {
        for age in [Duration::ZERO, MAX_V11_EXTERNAL_ANCHOR_AGE] {
            let mut cached = Some(CachedFunding { age });
            let funded_calls = Cell::new(0);
            let independent_calls = Cell::new(0);
            let result = drive_recovery_step_v23(
                &mut cached,
                |funding| funding.age,
                |_| {
                    funded_calls.set(funded_calls.get() + 1);
                    Ok(1)
                },
                || {
                    independent_calls.set(independent_calls.get() + 1);
                    Ok(2)
                },
            );
            assert_eq!(result, Ok(1));
            assert!(cached.is_none());
            assert_eq!(funded_calls.get(), 1);
            assert_eq!(independent_calls.get(), 0);

            let next = drive_recovery_step_v23(
                &mut cached,
                |_| panic!("consumed funding must not be inspected again"),
                |_| panic!("consumed funding must not authorize another step"),
                || Ok(2),
            );
            assert_eq!(next, Ok(2));
        }
    }

    #[test]
    fn delayed_recovery_dispatch_discards_expired_funding_and_drives_dom_recovery() {
        for age in [
            MAX_V11_EXTERNAL_ANCHOR_AGE + Duration::from_nanos(1),
            MAX_V11_EXTERNAL_ANCHOR_AGE * 2,
        ] {
            let mut cached = Some(CachedFunding { age });
            let independent_calls = Cell::new(0);
            let result = drive_recovery_step_v23(
                &mut cached,
                |funding| funding.age,
                |_| panic!("expired funding must never reach the compensation-capable driver"),
                || {
                    independent_calls.set(independent_calls.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
            assert!(cached.is_none());
            assert_eq!(independent_calls.get(), 1);
        }
    }

    #[test]
    fn recovery_dispatch_preserves_driver_refusals_without_fallback_or_cache_reuse() {
        for refusal in [Refusal::Conflict, Refusal::Unavailable] {
            let mut cached = Some(CachedFunding {
                age: Duration::ZERO,
            });
            let result = drive_recovery_step_v23(
                &mut cached,
                |funding| funding.age,
                |_| Err::<(), _>(refusal),
                || panic!("a driver refusal must not be reinterpreted as an expired proof"),
            );
            assert_eq!(result, Err(refusal));
            assert!(cached.is_none());
        }
        let mut absent: Option<CachedFunding> = None;
        assert_eq!(
            drive_recovery_step_v23(
                &mut absent,
                |_| panic!("no proof exists"),
                |_| panic!("no proof exists"),
                || Err::<(), _>(Refusal::Conflict),
            ),
            Err(Refusal::Conflict)
        );
    }
}
