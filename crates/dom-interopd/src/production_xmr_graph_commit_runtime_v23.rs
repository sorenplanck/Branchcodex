//! Productive graph agreement scheduler using the existing durable Relay owner.
use super::*;
use dom_scriptless_transport::SignedMessageV1;

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    fn retain_terminal_xmr_graph_signing_origins_after_commit_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
    ) -> Result<(), ProductionBootstrapRuntimeErrorV16> {
        let head = self.store.load_session(self.session_id)?;
        if head.revision() >= 19
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
        let pre_graph_head = self.store.load_session(self.session_id)?;
        if pre_graph_head.revision() >= 18 {
            // Heal any graph-commit message that was durably retained before
            // its session successor made it to disk. Rev17 is deliberately
            // excluded: that is where the graph context is first frozen below.
            self.store.heal_retained_xmr_graph_commit_successor_v23(
                chain,
                route,
                self.session_id,
            )?;
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
        let head = self.store.load_session(self.session_id)?;
        if head.revision() < 19 && pending_kind.is_some_and(|kind| (1..=0x0a).contains(&kind)) {
            self.resume_and_stage(expiry)?;
            return Ok(());
        }
        if head.revision() >= 19 {
            // The final graph-agreement edge may already be committed locally
            // while its route frame is still pending. Keep replaying that exact
            // edge as needed before asking whether a new commit request exists;
            // otherwise a retained 0x18 can be misclassified as a binding fault.
            // Do not withhold the signing origins: recovery signing is scoped by
            // the Store and can coexist with the old ACK.
            if pending_kind == Some(0x18) {
                match &pending {
                    OutboundDsc1RecoveryV1::Committed(record)
                        if self.outbound_dsc1_route_pending_v24(record)? => {}
                    _ => {
                        self.resume_and_stage(expiry)?;
                    }
                }
            }
            // Agreement is historical now. This terminal branch must not call
            // the commit request issuer as a predicate: at revision 19 the issuer
            // is allowed to reject the live transition even though the two-message
            // prefix is already durable. Recovery signing is admitted by the
            // retained origins below, while any still-pending 0x18 replay is
            // handled above.
            use dom_scriptless_store::XmrGraphRecoverySigningEdgeV23 as Edge;
            for edge in [Edge::Cancel, Edge::RefundAdaptor, Edge::Compensation] {
                self.store.retain_xmr_graph_signing_origin_v23(
                    chain,
                    route,
                    self.session_id,
                    edge,
                )?;
            }
            // Old bootstrap messages may still need byte-identical Relay replay,
            // but at revision 19 they must not starve the graph signing origins.
            if pending_kind.is_some_and(|kind| (1..=0x0a).contains(&kind)) {
                self.resume_and_stage(expiry)?;
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
                self.retain_terminal_xmr_graph_signing_origins_after_commit_v23(chain, route)?;
                return Ok(());
            }
            OutboundDsc1RecoveryV1::Committed(record) => {
                let message = SignedMessageV1::decode_exact(record.signed_bytes())
                    .map_err(|_| Error::Binding)?;
                if message.unsigned().kind() as u8 != 0x18
                    || record.sender_id() != &self.local_participant
                {
                    return Err(Error::Binding);
                }
                let route_pending = self.outbound_dsc1_route_pending_v24(&record)?;
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*record, expiry)
                    .map_err(ProductionContractsOutboundErrorV1::Relay)?;
                if route_pending {
                    return Ok(());
                }
                // The local 0x18 is already durably committed and no longer
                // pending on the route. Keep its byte-identical replay staged,
                // but continue below so any accepted peer successor can advance
                // this leg to the terminal graph agreement and retain the
                // recovery-signing origins.
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
                    self.retain_terminal_xmr_graph_signing_origins_after_commit_v23(chain, route)?;
                    return Ok(());
                }
            }
        }
        // Freeze all three signing origins only after the two-message graph
        // agreement is durable. A revision-18 peer turn is still pending;
        // reporting readiness there can start recovery signing against a
        // sibling graph that has not authenticated the final 0x18 edge.
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
            return Ok(());
        }
        Ok(())
    }
}
