//! Read-only bridge from retained native recovery custody to the actual DOM
//! scanner. Refund U and DOM compensation remain distinct typed outcomes.

use crate::production_child_dom::ProductionDomRefundScannerV10;
use adapter_dom_real::{
    RealDomError, VerifiedDomCompensationObservationV11, VerifiedDomRefundSecretV11,
    VerifiedDomXmrRecoveryStateV11,
};
use dom_scriptless_store::{XmrRecoveryCustodyErrorV11, XmrRecoveryCustodyV11};
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::rc::Rc;

/// Same native scanner used by the selected DOM child, and exact selected-leg
/// custody. No raw RPC client, caller-provided scalar or legacy refund hash is
/// accepted. Scope must originate in the admitted versioned recovery terms.
pub(crate) struct ProductionDomXmrRecoverySourceV11 {
    custody: Rc<XmrRecoveryCustodyV11>,
    scanner: ProductionDomRefundScannerV10,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
}

impl ProductionDomXmrRecoverySourceV11 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        custody: Rc<XmrRecoveryCustodyV11>,
        scanner: ProductionDomRefundScannerV10,
        session: [u8; 32],
        chain: [u8; 32],
        terms_hash: [u8; 32],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<Self, Refusal> {
        let scope = custody.scope();
        if scope.binding.session_id != session
            || scope.binding.chain_id != chain
            || scope.binding.terms_hash != terms_hash
            || minimum_confirmations == 0
            || max_reorg_depth < minimum_confirmations
        {
            return Err(Refusal::Conflict);
        }
        custody.revalidate().map_err(map_custody)?;
        Ok(Self {
            custody,
            scanner,
            minimum_confirmations,
            max_reorg_depth,
        })
    }

    pub(crate) fn require_binding(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        template: [u8; 32],
        point: [u8; 33],
        minimum: u32,
        max_reorg: u32,
    ) -> Result<(), Refusal> {
        if minimum != self.minimum_confirmations || max_reorg != self.max_reorg_depth {
            return Err(Refusal::Conflict);
        }
        self.custody
            .with_graph(|graph| {
                let binding = graph.binding();
                let pre = graph.refund_pre_signature();
                if binding.session_id != session
                    || binding.chain_id != chain
                    || pre.template_hash() != &template
                    || pre.refund_adaptor_point() != point
                {
                    return Err(Refusal::Conflict);
                }
                Ok(())
            })
            .map_err(map_custody)?
    }

    pub(crate) fn observe_state(&self) -> Result<VerifiedDomXmrRecoveryStateV11, Refusal> {
        self.custody
            .with_graph(|graph| {
                self.scanner.recovery_state_v11(
                    graph,
                    self.minimum_confirmations,
                    self.max_reorg_depth,
                )
            })
            .map_err(map_custody)?
            .map_err(map_real)
    }

    pub(crate) fn observe(&self) -> Result<VerifiedDomRefundSecretV11, Refusal> {
        match self.observe_state()? {
            VerifiedDomXmrRecoveryStateV11::Refunded(revealed) => Ok(revealed),
            // Compensation is a canonical competing terminal result, never
            // misreported as an absent refund or an XMR-refund success.
            VerifiedDomXmrRecoveryStateV11::Compensated(_) => Err(Refusal::Conflict),
            VerifiedDomXmrRecoveryStateV11::CollateralReady(_)
            | VerifiedDomXmrRecoveryStateV11::Cancelled(_) => Err(Refusal::Unavailable),
        }
    }

    pub(crate) fn observe_compensation(
        &self,
    ) -> Result<VerifiedDomCompensationObservationV11, Refusal> {
        match self.observe_state()? {
            VerifiedDomXmrRecoveryStateV11::Compensated(compensation) => Ok(compensation),
            VerifiedDomXmrRecoveryStateV11::Refunded(_) => Err(Refusal::Conflict),
            VerifiedDomXmrRecoveryStateV11::CollateralReady(_)
            | VerifiedDomXmrRecoveryStateV11::Cancelled(_) => Err(Refusal::Unavailable),
        }
    }
}

fn map_custody(error: XmrRecoveryCustodyErrorV11) -> Refusal {
    match error {
        XmrRecoveryCustodyErrorV11::NotFound
        | XmrRecoveryCustodyErrorV11::Unavailable
        | XmrRecoveryCustodyErrorV11::Busy => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}

fn map_real(error: RealDomError) -> Refusal {
    match error {
        RealDomError::EvidenceNotFound
        | RealDomError::InsufficientConfirmations
        | RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
        ) => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}
