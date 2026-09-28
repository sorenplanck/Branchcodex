//! Retained three-edge recovery custody. Only the parent's U-adaptor round may
//! use the parent Relay; derived edges wait for dedicated auxiliary owners.
use super::*;
use crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12;
use crate::production_dom_vaults_v12::{
    ProductionDomVaultPurposeV12, ProductionXmrGraphVaultProvisionerV23,
};
use crate::production_xmr_round_runtime_v12::{
    require_xmr_recovery_signing_scope_v23, tick_xmr_recovery_round_v12,
    ProductionXmrRecoveryRoundKindV12, ProductionXmrRoundErrorV12, ProductionXmrRoundProgressV12,
};
use dom_actuator::{participant_retained_vault_signer_v12, RetainedParticipantVaultSignerV12};
use dom_adaptor::{canonical_template_v1, AcceptedSigningSessionV1};
use dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12;
use dom_scriptless_store::{ContractsNonceVaultV1, XmrGraphRecoverySigningEdgeV23};
use xmr_refund_policy::{
    graph_builder::XmrRecoveryGraphTemplatesV12, graph_signing_keys_v22::XmrGraphSigningKeysV22,
};

/// Store-derived terminal equations, not funding or durable custody authority.
pub(crate) struct ProductionXmrCompletedRoundsV23 {
    cancel: dom_scriptless_crypto::CompletedXmrOrdinaryRecoveryRoundV12,
    compensation: dom_scriptless_crypto::CompletedXmrOrdinaryRecoveryRoundV12,
    refund: crate::production_xmr_round_runtime_v12::ProductionCompletedXmrRefundRoundV12,
}

impl ProductionXmrCompletedRoundsV23 {
    pub(crate) fn complete(
        self,
        templates: XmrRecoveryGraphTemplatesV12,
    ) -> Result<
        xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12,
        ProductionBootstrapRuntimeErrorV16,
    > {
        self.refund
            .complete_graph(templates, self.cancel, self.compensation)
            .map_err(|_| ProductionBootstrapRuntimeErrorV16::Binding)
    }
}

/// No Clone, share getter or funding signer. All three distinct vaults remain
/// alive across ticks; partial progress cannot reconstruct a second nonce owner.
pub(crate) struct ProductionXmrRecoverySigningOwnerV23 {
    pub(super) bindings: [dom_actuator::DomSessionBindingV1; 3],
    pub(super) signers: [RetainedParticipantVaultSignerV12<ContractsNonceVaultV1>; 3],
    parent: [u8; 32],
    refund_complete: bool,
    auxiliary_complete: [bool; 2],
}

impl ProductionXmrRecoverySigningOwnerV23 {
    /// Closed progress tokens for the activation stall diagnostic.
    pub(crate) fn stall_tokens_v25(&self) -> (bool, [bool; 2]) {
        (self.refund_complete, self.auxiliary_complete)
    }

    /// The three signing-session ids (cancel, refund, compensation), for the
    /// stall diagnostic's revision progress tokens only.
    pub(crate) fn signing_session_ids_v25(&self) -> [[u8; 32]; 3] {
        [
            self.bindings[0].session_id(),
            self.bindings[1].session_id(),
            self.bindings[2].session_id(),
        ]
    }

    pub(crate) fn auxiliary_binding_v23(
        &self,
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Option<dom_actuator::DomSessionBindingV1> {
        match edge {
            XmrGraphRecoverySigningEdgeV23::Cancel => Some(self.bindings[0]),
            XmrGraphRecoverySigningEdgeV23::Compensation => Some(self.bindings[2]),
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor => None,
        }
    }
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// Durable revisions of the parent and the three signing sessions, for
    /// the activation stall diagnostic. Reads only; a missing session reads
    /// as revision 0.
    pub(crate) fn stall_revisions_v25(&self, signing: [[u8; 32]; 3]) -> [u64; 4] {
        let read = |id: [u8; 32]| {
            self.store
                .load_session(id)
                .map(|record| record.revision())
                .unwrap_or(0)
        };
        [
            read(self.session_id),
            read(signing[0]),
            read(signing[1]),
            read(signing[2]),
        ]
    }

    /// Phase-independent durable progress of this leg for the activation
    /// stall diagnostic: the parent session revision plus the Relay
    /// transcript's acknowledged envelopes and committed inbound deliveries.
    /// Bootstrap and graph traffic both advance at least one of them, so a
    /// long but live ceremony is never mistaken for a stall. Reads only; an
    /// unreadable or busy source reads as 0 and cannot fake progress.
    pub(crate) fn stall_transcript_v25(&self) -> [u64; 3] {
        let parent = self
            .store
            .load_session(self.session_id)
            .map(|record| record.revision())
            .unwrap_or(0);
        let (sent, delivered) = self
            .relay
            .try_borrow()
            .map(|relay| {
                (
                    relay
                        .sender_stats()
                        .map(|stats| u64::from(stats.completed))
                        .unwrap_or(0),
                    relay
                        .inbox_stats()
                        .map(|stats| stats.delivered as u64)
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));
        [parent, sent, delivered]
    }

    fn stage_or_wait_xmr_graph_commit_pending_v23(
        &mut self,
        pending: OutboundDsc1RecoveryV1,
        expiry: relay::TimelockSpec,
    ) -> Result<bool, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        match pending {
            OutboundDsc1RecoveryV1::SigningRequest(request) => Ok(request.message_type() == 0x18),
            OutboundDsc1RecoveryV1::Committed(record) => {
                let message =
                    dom_scriptless_transport::SignedMessageV1::decode_exact(record.signed_bytes())
                        .map_err(|_| Error::Binding)?;
                if message.unsigned().kind() as u8 != 0x18 {
                    return Ok(false);
                }
                if record.session_id() != &self.session_id
                    || record.sender_id() != &self.local_participant
                {
                    return Err(Error::Binding);
                }
                if self.outbound_dsc1_route_pending_v24(&record)? {
                    return Ok(true);
                }
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*record, expiry)
                    .map_err(ProductionContractsOutboundErrorV1::Relay)?;
                Ok(false)
            }
            OutboundDsc1RecoveryV1::None => Ok(false),
        }
    }

    /// Reissue and verify all three terminal equations before consuming templates.
    /// The retained signer/vault owners are deliberately not moved or dropped.
    pub(crate) fn prepare_xmr_graph_completion_v23(
        &self,
        owner: &ProductionXmrRecoverySigningOwnerV23,
        templates: &XmrRecoveryGraphTemplatesV12,
        keys: &XmrGraphSigningKeysV22,
    ) -> Result<Option<ProductionXmrCompletedRoundsV23>, ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16::Binding as Refused;
        if owner.parent != self.session_id || templates.binding().session_id != self.session_id {
            return Err(Refused);
        }
        if !owner.refund_complete || owner.auxiliary_complete != [true; 2] {
            return Ok(None);
        }
        use crate::production_xmr_round_runtime_v12::{
            produce_completed_xmr_ordinary_round_v12, ProductionCompletedXmrRefundRoundV12,
        };
        use XmrGraphRecoverySigningEdgeV23 as Edge;
        let cancel = self
            .store
            .resume_xmr_graph_signing_session_v23(owner.bindings[0].session_id(), Edge::Cancel)?;
        let refund = self.store.resume_xmr_graph_signing_session_v23(
            owner.bindings[1].session_id(),
            Edge::RefundAdaptor,
        )?;
        let compensation = self.store.resume_xmr_graph_signing_session_v23(
            owner.bindings[2].session_id(),
            Edge::Compensation,
        )?;
        Ok(Some(ProductionXmrCompletedRoundsV23 {
            cancel: produce_completed_xmr_ordinary_round_v12(
                &cancel,
                templates,
                keys,
                XmrOrdinaryRecoveryKindV12::Cancel,
            )
            .map_err(|_| Refused)?,
            compensation: produce_completed_xmr_ordinary_round_v12(
                &compensation,
                templates,
                keys,
                XmrOrdinaryRecoveryKindV12::Compensation,
            )
            .map_err(|_| Refused)?,
            refund: ProductionCompletedXmrRefundRoundV12::from_store_session(
                &refund, templates, keys,
            )
            .map_err(|_| Refused)?,
        }))
    }

    /// Caller must own a dedicated session-scoped auxiliary Relay.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn step_xmr_auxiliary_signing_v23(
        &mut self,
        owner: &mut ProductionXmrRecoverySigningOwnerV23,
        edge: XmrGraphRecoverySigningEdgeV23,
        parent_binding: dom_actuator::DomSessionBindingV1,
        chain: TrustedChainIdV1,
        templates: &XmrRecoveryGraphTemplatesV12,
        keys: &XmrGraphSigningKeysV22,
        expiry: relay::TimelockSpec,
    ) -> Result<(), ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16::Binding as Refused;
        let (index, complete, kind) = match edge {
            XmrGraphRecoverySigningEdgeV23::Cancel => {
                (0, 0, ProductionXmrRecoveryRoundKindV12::Cancel)
            }
            XmrGraphRecoverySigningEdgeV23::Compensation => {
                (2, 1, ProductionXmrRecoveryRoundKindV12::Compensation)
            }
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor => return Err(Refused),
        };
        if owner.parent != parent_binding.session_id()
            || self.session_id != owner.bindings[index].session_id()
            || self.session_id == owner.parent
        {
            return Err(Refused);
        }
        if owner.auxiliary_complete[complete] {
            return Ok(());
        }
        let mut relay = self.relay.try_borrow_mut().map_err(|_| Refused)?;
        match tick_xmr_recovery_round_v12(
            &self.store,
            &self.identity,
            &mut relay,
            chain,
            templates,
            keys,
            kind,
            parent_binding,
            &mut owner.signers[index],
            expiry,
        ) {
            Ok(ProductionXmrRoundProgressV12::Complete) => {
                owner.auxiliary_complete[complete] = true;
            }
            Ok(
                ProductionXmrRoundProgressV12::AwaitingPeer | ProductionXmrRoundProgressV12::Staged,
            ) => {}
            // The Relay may still be draining an earlier durable graph edge.
            // Keep the owner alive and retry after the worker polls it.
            Err(ProductionXmrRoundErrorV12::Transport) => {}
            Err(_) => return Err(Refused),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn step_xmr_recovery_signing_v23(
        &mut self,
        retained: &mut Option<ProductionXmrRecoverySigningOwnerV23>,
        provisioner: &ProductionXmrGraphVaultProvisionerV23,
        material: &mut ProductionBoundDomSharedOutputV12,
        parent_binding: dom_actuator::DomSessionBindingV1,
        chain: TrustedChainIdV1,
        templates: &XmrRecoveryGraphTemplatesV12,
        keys: &XmrGraphSigningKeysV22,
        expiry: relay::TimelockSpec,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), ProductionBootstrapRuntimeErrorV16> {
        use ProductionBootstrapRuntimeErrorV16 as Error;
        // Building the signing owner persists three sessions, three private
        // vaults and three shares, each with its own durable commits; measured
        // at up to 124 s in one uninterrupted block on a slow disk, longer
        // than the DOM actuator lease. Renew after every durable sub-step so
        // the retained authority is kept exactly as long as the work runs.
        let mut keep = || renew_actuator_lease().map_err(|()| Error::ActuatorLeaseRenewalV25);
        if self.session_id != parent_binding.session_id()
            || templates.binding().session_id != self.session_id
            || templates.binding().chain_id != *chain.as_bytes()
            || parent_binding.chain_id() != *chain.as_bytes()
            || parent_binding.terms_digest() != templates.binding().terms_hash
        {
            return Err(Error::Binding);
        }
        if retained.is_none() {
            let current = self
                .store
                .load_session(self.session_id)
                .map_err(|_| Error::Binding)?;
            // The owner is rebuilt in exactly the phases in which the refund
            // round below is resumed. Admitting only TemplatesCommitted here
            // meant a restart after the first local 0x0c (the parent is then
            // in RefundSigning) could never rebuild the owner, so the round
            // resume below was never reached. Vaults and signing sessions are
            // reopened from their durable state, never recreated.
            if current.revision() < 19
                || !matches!(
                    current.phase(),
                    dom_scriptless_store::SessionPhaseV1::TemplatesCommitted
                        | dom_scriptless_store::SessionPhaseV1::RefundSigning
                )
                || current.irreversible().funding_authorized
            {
                return Ok(());
            }
            let pending = self.store.resume_outbound_dsc1(self.session_id)?;
            if self.stage_or_wait_xmr_graph_commit_pending_v23(pending, expiry)? {
                return Ok(());
            }
            let cancel_hash = canonical_template_v1(templates.cancel())
                .map_err(|_| Error::Binding)?
                .1;
            let compensation_hash = canonical_template_v1(templates.compensation())
                .map_err(|_| Error::Binding)?
                .1;
            let bindings = [
                parent_binding
                    .for_xmr_ordinary_recovery_v22(
                        templates.binding(),
                        XmrOrdinaryRecoveryKindV12::Cancel,
                        cancel_hash,
                    )
                    .map_err(|_| Error::Binding)?,
                parent_binding,
                parent_binding
                    .for_xmr_compensation_v23(
                        templates.binding(),
                        templates.policy(),
                        compensation_hash,
                    )
                    .map_err(|_| Error::Binding)?,
            ];
            let edges = [
                XmrGraphRecoverySigningEdgeV23::Cancel,
                XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
                XmrGraphRecoverySigningEdgeV23::Compensation,
            ];
            let kinds = [
                ProductionXmrRecoveryRoundKindV12::Cancel,
                ProductionXmrRecoveryRoundKindV12::RefundAdaptor,
                ProductionXmrRecoveryRoundKindV12::Compensation,
            ];
            for index in 0..3 {
                match self.store.prepare_xmr_graph_signing_session_v23(
                    bindings[index].session_id(),
                    edges[index],
                ) {
                    Ok(_) => {}
                    Err(dom_scriptless_store::SessionStoreError::SessionNotFound) => return Ok(()),
                    Err(_) => return Err(Error::Binding),
                }
                let accepted = match self.store.resume_xmr_graph_signing_session_v23(
                    bindings[index].session_id(),
                    edges[index],
                ) {
                    Ok(accepted) => accepted,
                    Err(dom_scriptless_store::SessionStoreError::SessionNotFound) => return Ok(()),
                    Err(_) => return Err(Error::Binding),
                };
                require_xmr_recovery_signing_scope_v23(
                    keys,
                    templates,
                    &chain,
                    accepted.roster(),
                    kinds[index],
                )
                .map_err(|_| Error::Binding)?;
                self.store
                    .bind_local_transport_signer(
                        bindings[index].session_id(),
                        *self.identity.reference().key_reference(),
                    )
                    .map_err(|_| Error::Binding)?;
                keep()?;
            }
            // Open all private vaults before taking any wallet share. These are
            // distinct roots, never the bootstrap BP or parent Funding vault.
            let purposes = [
                ProductionDomVaultPurposeV12::XmrCancel,
                ProductionDomVaultPurposeV12::XmrRefundU,
                ProductionDomVaultPurposeV12::XmrCompensation,
            ];
            let mut vaults = Vec::with_capacity(3);
            for index in 0..3 {
                vaults.push(
                    provisioner
                        .provision(&self.store, bindings[index], purposes[index])
                        .map_err(|_| Error::Binding)?,
                );
                keep()?;
            }
            let shares = material
                .xmr_graph_shares_v22
                .as_mut()
                .ok_or(Error::Binding)?;
            let cancel = shares
                .take_ordinary_share_v22(
                    &self.store,
                    templates.binding(),
                    XmrOrdinaryRecoveryKindV12::Cancel,
                    cancel_hash,
                )
                .map_err(|_| Error::Binding)?;
            keep()?;
            let refund = shares
                .take_refund_adaptor_share_v23(&self.store, templates)
                .map_err(|_| Error::Binding)?;
            keep()?;
            let compensation = shares
                .take_compensation_share_v23(&self.store, templates)
                .map_err(|_| Error::Binding)?;
            keep()?;
            let mut signers = Vec::with_capacity(3);
            for (index, (vault, share)) in vaults
                .into_iter()
                .zip([cancel, refund, compensation])
                .enumerate()
            {
                signers.push(
                    participant_retained_vault_signer_v12(
                        vault,
                        Rc::clone(&self.store),
                        bindings[index],
                        chain,
                        share,
                    )
                    .map_err(|_| Error::Binding)?,
                );
                keep()?;
            }
            *retained = Some(ProductionXmrRecoverySigningOwnerV23 {
                bindings,
                signers: signers.try_into().map_err(|_| Error::Binding)?,
                parent: self.session_id,
                refund_complete: false,
                auxiliary_complete: [false; 2],
            });
        }
        let owner = retained.as_mut().ok_or(Error::Binding)?;
        if owner.parent != self.session_id || owner.bindings[1] != parent_binding {
            return Err(Error::Binding);
        }
        let parent_head = self.store.load_session(self.session_id)?;
        // Resume the authenticated refund round in its signing phase too.
        // Keep the existing revision floor and prefunding restriction.
        if parent_head.revision() < 19
            || !matches!(
                parent_head.phase(),
                dom_scriptless_store::SessionPhaseV1::TemplatesCommitted
                    | dom_scriptless_store::SessionPhaseV1::RefundSigning
            )
            || parent_head.irreversible().funding_authorized
        {
            return Ok(());
        }
        let pending = self.store.resume_outbound_dsc1(self.session_id)?;
        if self.stage_or_wait_xmr_graph_commit_pending_v23(pending, expiry)? {
            return Ok(());
        }
        if owner.refund_complete {
            // The refund round is terminal: no further refund-edge message can
            // arrive that this ingress would admit, and a byte-identical late
            // redelivery is answered by the generic derived duplicate path
            // without one. Re-minting the ingress here costs a full transport
            // audit — roster inventory plus signature re-verification of every
            // durable message of every session — per tick, to reinstall an
            // authority nothing will consume. Pending outbound bytes were
            // already re-staged above.
            return Ok(());
        }
        let ingress = self.store.prepare_xmr_graph_signing_ingress_v23(
            self.session_id,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        self.refresh_reissued_contracts_ingress_v16(
            PreparedContractsIngressV1::xmr_graph_signing_v23(ingress),
        )?;
        keep()?;
        // The auxiliary signers at indices 0 and 2 remain held. Sending them
        // through this parent's session-scoped Relay is forbidden.
        let mut relay = self.relay.try_borrow_mut().map_err(|_| Error::Binding)?;
        match tick_xmr_recovery_round_v12(
            &self.store,
            &self.identity,
            &mut relay,
            chain,
            templates,
            keys,
            ProductionXmrRecoveryRoundKindV12::RefundAdaptor,
            parent_binding,
            &mut owner.signers[1],
            expiry,
        ) {
            Ok(ProductionXmrRoundProgressV12::Complete) => {
                owner.refund_complete = true;
            }
            Ok(
                ProductionXmrRoundProgressV12::AwaitingPeer | ProductionXmrRoundProgressV12::Staged,
            ) => {}
            // The parent Relay can still hold the graph-agreement 0x18 edge;
            // retry recovery signing after that durable transport clears.
            Err(ProductionXmrRoundErrorV12::Transport) => {}
            Err(_) => return Err(Error::Binding),
        }
        Ok(())
    }
}
