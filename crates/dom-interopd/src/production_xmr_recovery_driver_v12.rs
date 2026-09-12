//! Continuously drive a selected DOM/XMR recovery graph after peer loss.
//!
//! The owner comes from the same Contracts opening and DOM child client used
//! by normal execution. A fresh native Store grant and fresh canonical scan are
//! mandatory on every tick, including restart and an ambiguous submission.

use crate::production_child_dom::ProductionDomXmrRecoveryClientV12;
use adapter_dom_real::{
    DomXmrRecoveryProgressV12, RealDomError, VerifiedDomXmrFundingPrerequisiteV12,
};
use dom_scriptless_store::{
    ContractsSessionStoreV1, PreparedOperationalXmrFundingGateV12, SessionStoreError,
    XmrRecoveryCustodyV11,
};
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::rc::Rc;

pub(crate) struct ProductionXmrRecoveryDriverV12 {
    store: Rc<ContractsSessionStoreV1>,
    gate: Rc<PreparedOperationalXmrFundingGateV12>,
    custody: Rc<XmrRecoveryCustodyV11>,
    client: ProductionDomXmrRecoveryClientV12,
}

impl ProductionXmrRecoveryDriverV12 {
    pub(crate) fn new(
        store: Rc<ContractsSessionStoreV1>,
        gate: Rc<PreparedOperationalXmrFundingGateV12>,
        custody: Rc<XmrRecoveryCustodyV11>,
        client: ProductionDomXmrRecoveryClientV12,
    ) -> Result<Self, Refusal> {
        // Attachment is deliberately possible before funding. Actual execution
        // below still needs both signed ready votes and exact committed funding.
        store
            .validate_xmr_recovery_attachment_v12(&gate, &custody)
            .map_err(map_store)?;
        Ok(Self {
            store,
            gate,
            custody,
            client,
        })
    }

    /// Static recovery readiness from the same gate and actual private archive.
    /// No funding commit, final U bytes, chain observation or broadcast grant.
    pub(crate) fn refund_readiness_v23(
        &self,
    ) -> Result<dom_scriptless_store::VerifiedXmrRefundReadinessV23, SessionStoreError> {
        self.store
            .verify_xmr_refund_readiness_v23(&self.gate, &self.custody)
    }

    pub(crate) fn require_attachment(&self, terms_hash: [u8; 32]) -> Result<(), Refusal> {
        if self.custody.scope().binding.terms_hash != terms_hash {
            return Err(Refusal::Conflict);
        }
        self.store
            .validate_xmr_recovery_attachment_v12(&self.gate, &self.custody)
            .map_err(map_store)
    }

    pub(crate) fn require_refund_binding(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        template: [u8; 32],
        point: [u8; 33],
        minimum: u32,
        max_reorg: u32,
    ) -> Result<(), Refusal> {
        self.require_attachment(self.custody.scope().binding.terms_hash)?;
        if minimum == 0 || max_reorg < minimum {
            return Err(Refusal::Conflict);
        }
        self.custody
            .with_graph(|graph| {
                if graph.binding().session_id != session
                    || graph.binding().chain_id != chain
                    || graph.refund_pre_signature().template_hash() != &template
                    || graph.refund_pre_signature().refund_adaptor_point() != point
                {
                    return Err(Refusal::Conflict);
                }
                Ok(())
            })
            .map_err(|_| Refusal::Conflict)?
    }

    pub(crate) fn observe_refund_share(
        &self,
    ) -> Result<adapter_dom_real::VerifiedDomRefundSecretV11, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        match self
            .client
            .observe(&authority, &self.custody)
            .map_err(map_real)?
        {
            adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(secret) => Ok(secret),
            adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Compensated(_) => {
                Err(Refusal::Conflict)
            }
            _ => Err(Refusal::Unavailable),
        }
    }

    /// Run independently of Relay polling/peer availability. No operation here
    /// needs a new counterparty signature after collateral has been committed.
    /// U revelation and DOM compensation are deliberately different variants;
    /// only the XMR actuator can later report an actual refunded XMR sweep.
    pub(crate) fn tick(&self) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        self.client
            .advance(&authority, &self.custody)
            .map_err(map_real)
    }

    /// Compensation requires the real selected Monero observer's fresh proof.
    /// A recorded DOM collateral transaction cannot stand in for paid XMR.
    pub(crate) fn tick_with_funding(
        &self,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<DomXmrRecoveryProgressV12, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_with_funding_v12(&self.gate, &self.custody, funding)
            .map_err(map_store)?;
        self.custody
            .retain_xmr_funding_observed_v22(&authority)
            .map_err(|_| Refusal::Conflict)?;
        self.client
            .advance(&authority, &self.custody)
            .map_err(map_real)
    }

    /// Close the exact route leg through its sole fenced writer, preserving
    /// the distinction between a DOM payout and an actual XMR sweep refund.
    pub(crate) fn record_compensation_with_funding<C: crate::supervisor::Clock>(
        &self,
        supervisor: &mut crate::supervisor::RouteSupervisorV1<C>,
        leg: route_executor::LegIdV1,
        funding: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
        observed: &adapter_dom_real::VerifiedDomCompensationObservationV11,
    ) -> Result<route_executor::CommitOutcomeV1, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_with_funding_v12(&self.gate, &self.custody, funding)
            .map_err(map_store)?;
        self.custody
            .retain_xmr_funding_observed_v22(&authority)
            .map_err(|_| Refusal::Conflict)?;
        supervisor
            .record_dom_compensation_v12(leg, &authority, &self.custody, observed)
            .map_err(|error| match error {
                crate::supervisor::RouteSupervisorErrorV1::StoreAuthorityBusy
                | crate::supervisor::RouteSupervisorErrorV1::Clock(_)
                | crate::supervisor::RouteSupervisorErrorV1::Store(
                    route_executor::RouteStoreErrorV1::StorageUnavailable
                    | route_executor::RouteStoreErrorV1::LeaseExpired
                    | route_executor::RouteStoreErrorV1::RevisionConflict,
                ) => Refusal::Unavailable,
                _ => Refusal::Conflict,
            })
    }

    /// Called only with the actual locally retained and independently verified
    /// funding candidate. The durable intent precedes a second fresh DOM scan;
    /// exact broadcaster submission cannot substitute another transaction.
    pub(crate) fn broadcast_private_funding(
        &self,
        terms_hash: [u8; 32],
        setup_hash: [u8; 32],
        candidate: &xmr_rpc_broadcast_blocking::PreparedPrivateFundingV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), Refusal> {
        self.require_attachment(terms_hash)?;
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        let verified = candidate.verified().transaction();
        if setup_hash != authority.xmr_setup_binding_hash()
            || verified.tx_hash != authority.xmr_funding_tx_hash()
        {
            return Err(Refusal::Conflict);
        }
        self.custody
            .retain_xmr_funding_attempt_v12(
                &authority,
                setup_hash,
                verified.tx_hash,
                verified.raw_fingerprint,
            )
            .map_err(|_| Refusal::Conflict)?;
        let prerequisite = self.verify_funding_prerequisite()?;
        if prerequisite.collateral().finality().terms_hash() != terms_hash {
            return Err(Refusal::Conflict);
        }
        candidate
            .with_raw(|raw| broadcast.submit_exact(verified.tx_hash, raw))
            .map(|_| ())
            .map_err(|error| match error {
                xmr_spend_port::SpendPortError::Retryable => Refusal::Unavailable,
                xmr_spend_port::SpendPortError::Rejected => Refusal::Conflict,
            })
    }

    /// Call at the actual selected-XMR funding boundary, not just bootstrap.
    /// The returned opaque evidence has no persisted/raw reconstruction path.
    pub(crate) fn verify_funding_prerequisite(
        &self,
    ) -> Result<VerifiedDomXmrFundingPrerequisiteV12, Refusal> {
        let authority = self
            .store
            .authorize_xmr_recovery_execution_v12(&self.gate, &self.custody)
            .map_err(map_store)?;
        self.client
            .verify_funding_prerequisite(&authority, &self.custody)
            .map_err(map_real)
    }
}

fn map_store(error: SessionStoreError) -> Refusal {
    match error {
        SessionStoreError::Filesystem
        | SessionStoreError::StoreBusy
        | SessionStoreError::FundingAuthorityUnavailable => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}

fn map_real(error: RealDomError) -> Refusal {
    match error {
        RealDomError::EvidenceNotFound
        | RealDomError::InsufficientConfirmations
        | RealDomError::Chain(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
        )
        | RealDomError::Store(
            SessionStoreError::Filesystem
            | SessionStoreError::StoreBusy
            | SessionStoreError::FundingAuthorityUnavailable,
        ) => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}
