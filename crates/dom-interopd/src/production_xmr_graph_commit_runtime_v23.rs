//! Productive graph agreement scheduler using the existing durable Relay owner.
use super::*;
use dom_scriptless_transport::SignedMessageV1;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn step_xmr_graph_commit_v23(
        &mut self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        expiry: TimelockSpec,
    ) -> Result<(), ProductionBootstrapRuntimeErrorV16> {
        type Error = ProductionBootstrapRuntimeErrorV16;
        if route != self.route_id {
            return Err(Error::Binding);
        }
        // Heal the last BP outbox first: the peer needs that proof before it
        // can reconstruct the graph. Never discard or reinterpret that request.
        let pending = self.store.resume_outbound_dsc1(self.session_id)?;
        let pending_kind = match &pending {
            OutboundDsc1RecoveryV1::SigningRequest(request) => Some(request.message_type()),
            OutboundDsc1RecoveryV1::Committed(record) => Some(
                SignedMessageV1::decode_exact(record.signed_bytes())
                    .map_err(|_| Error::Binding)?
                    .unsigned()
                    .kind() as u8,
            ),
            OutboundDsc1RecoveryV1::None => None,
        };
        if pending_kind.is_some_and(|kind| (1..=0x0a).contains(&kind)) {
            self.resume_and_stage(expiry)?;
            return Ok(());
        }
        let head = self.store.load_session(self.session_id)?;
        if head.revision() >= 19 {
            // Agreement is historical now. Never replace GraphSigning ingress
            // or claim its pending 0x0c..0x0e identity/Relay handoff as a commit.
            if self
                .store
                .prepare_xmr_graph_commit_dsc1_signing_request_v23(chain, route, self.session_id)?
                .is_some()
            {
                return Err(Error::Binding);
            }
            // The second agreement may have committed immediately before a
            // crash, with no Relay staging yet. Heal only that exact old edge.
            if pending_kind == Some(0x18) {
                self.resume_and_stage(expiry)?;
            }
            use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23 as Edge;
            for edge in [Edge::Cancel, Edge::RefundAdaptor, Edge::Compensation] {
                self.store.retain_xmr_graph_signing_origin_v23(
                    chain,
                    route,
                    self.session_id,
                    edge,
                )?;
            }
            // Native generic ingress authenticates old exact 0x18 replays
            // before delegating unseen messages to the installed signing scope.
            return Ok(());
        }
        if head.revision() == 17 {
            self.store
                .freeze_xmr_graph_commit_context_v23(chain, route, self.session_id)?;
        }
        let ingress =
            self.store
                .prepare_xmr_graph_commit_ingress_v23(chain, route, self.session_id)?;
        self.refresh_reissued_contracts_ingress_v16(
            PreparedContractsIngressV1::xmr_graph_commit_v23(ingress),
        )?;
        match self.store.resume_outbound_dsc1(self.session_id)? {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if request.message_type() != 0x18 {
                    return Err(Error::Binding);
                }
                self.sign_commit_and_stage(*request, expiry)?;
            }
            OutboundDsc1RecoveryV1::Committed(record) => {
                let message = SignedMessageV1::decode_exact(record.signed_bytes())
                    .map_err(|_| Error::Binding)?;
                if message.unsigned().kind() as u8 != 0x18
                    || record.sender_id() != &self.local_participant
                {
                    return Err(Error::Binding);
                }
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*record, expiry)
                    .map_err(ProductionContractsOutboundErrorV1::Relay)?;
            }
            OutboundDsc1RecoveryV1::None => {
                if let Some(request) = self
                    .store
                    .prepare_xmr_graph_commit_dsc1_signing_request_v23(
                        chain,
                        route,
                        self.session_id,
                    )?
                {
                    self.sign_commit_and_stage(request, expiry)?;
                }
            }
        }
        // Freeze all three signing origins while the parent still has the
        // bilateral agreement head. Starting the adaptor round later must not
        // make a sibling origin depend on a mutable parent phase.
        let head = self.store.load_session(self.session_id)?;
        if head.revision() == 19
            && head.phase() == dom_scriptless_store::SessionPhaseV1::TemplatesCommitted
            && !head.irreversible().funding_authorized
        {
            use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23 as Edge;
            for edge in [Edge::Cancel, Edge::RefundAdaptor, Edge::Compensation] {
                self.store.retain_xmr_graph_signing_origin_v23(
                    chain,
                    route,
                    self.session_id,
                    edge,
                )?;
            }
        }
        Ok(())
    }
}
