//! Authenticated public graph candidates, separate from Relay durability.
use super::*;
#[path = "production_noise_graph_material_v22.rs"]
mod material_v22;
pub(crate) use material_v22::ProductionXmrGraphPublicMaterialV22;
#[path = "production_noise_xmr_f6_principal_v25.rs"]
mod f6_principal_v25;
pub(crate) use f6_principal_v25::ProductionAuthenticatedXmrClaimPrincipalV25;
#[cfg(all(test, target_os = "linux"))]
#[path = "production_noise_native_graph_v22_tests.rs"]
mod native_graph_tests;
use dom_adaptor::SharedBlindingBindingV1;
use kaystra_core::SettlementTermsV1;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use native_graph_tests::SignedNativeGraphFixtureV23;
use xmr_refund_policy::{
    compensation::ValidatedXmrCompensationPolicyV11,
    graph_offer_v22::{XmrGraphOfferScopeV22, XmrGraphOfferV22},
};

/// Public, verified construction candidate. Not a signing or funding token.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProductionReceivedXmrGraphCandidateV22 {
    bytes: Vec<u8>,
}
impl core::fmt::Debug for ProductionReceivedXmrGraphCandidateV22 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProductionReceivedXmrGraphCandidateV22([payload redacted])")
    }
}
impl ProductionReceivedXmrGraphCandidateV22 {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Immutable local public packet and exact native validation scope.
pub(crate) struct ProductionNoiseGraphOfferV22 {
    route_id: [u8; 32],
    terms: SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    native: SharedBlindingBindingV1,
    local: Vec<u8>,
}
impl ProductionNoiseGraphOfferV22 {
    pub(crate) fn new(
        route_id: [u8; 32],
        terms: SettlementTermsV1,
        policy: ValidatedXmrCompensationPolicyV11,
        native: SharedBlindingBindingV1,
        local: Vec<u8>,
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        if native.session_id() != &terms.session_id.0
            || native.chain_id() != &terms.dom_leg.chain_id.0
            || native.terms_hash()
                != &terms
                    .terms_hash()
                    .map_err(|_| ProductionNoiseRelayErrorV1::InvalidConfiguration)?
            || native.roster() != terms.roster.map(|p| p.0).as_slice()
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        let this = Self {
            route_id,
            terms,
            policy,
            native,
            local,
        };
        this.verify_packet(&this.local, false)?;
        Ok(this)
    }

    pub(crate) fn require_graph_setup_v22(
        &self,
        setup: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let binding = setup.binding();
        if self.route_id != binding.route_id()
            || *self.native.chain_id() != binding.chain_id()
            || *self.native.session_id() != binding.session_id()
            || *self.native.terms_hash() != binding.terms_digest()
            || self.native.participant_id() != &binding.participant().participant_id()
            || usize::from(self.native.participant_index())
                != usize::from(binding.participant().protocol_index())
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    fn verify_packet(&self, bytes: &[u8], peer: bool) -> Result<(), ProductionNoiseRelayErrorV1> {
        self.decode_packet(bytes, peer).map(|_| ())
    }

    fn decode_packet(
        &self,
        bytes: &[u8],
        peer: bool,
    ) -> Result<XmrGraphOfferV22, ProductionNoiseRelayErrorV1> {
        let local = usize::from(self.native.participant_index());
        let index = if peer {
            1usize.checked_sub(local)
        } else {
            Some(local)
        }
        .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
        let participant = self
            .terms
            .roster
            .get(index)
            .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?
            .0;
        let direction = if peer {
            match self.native.role() {
                dom_adaptor::DirectionV1::Initiator => dom_adaptor::DirectionV1::Responder,
                dom_adaptor::DirectionV1::Responder => dom_adaptor::DirectionV1::Initiator,
            }
        } else {
            self.native.role()
        };
        XmrGraphOfferV22::from_bytes(
            bytes,
            &self.terms,
            &self.policy,
            &XmrGraphOfferScopeV22 {
                chain: self.native.trusted_chain_id(),
                route_id: self.route_id,
                participant,
                direction,
            },
        )
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)
    }
}

impl ProductionNoiseRelaySessionV1 {
    pub(crate) fn with_xmr_graph_offer_v22(
        mut self,
        graph: ProductionNoiseGraphOfferV22,
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        let local = usize::from(graph.native.participant_index());
        let remote = 1usize
            .checked_sub(local)
            .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
        if self.cancelled_v22.is_none()
            || self.graph_v22.is_some()
            || self.chain_id != *graph.native.chain_id()
            || self.route_id != graph.route_id
            || self.session_id != *graph.native.session_id()
            || self.local_reference.participant_id() != graph.native.participant_id()
            || self.remote_reference.participant_id() != &graph.terms.roster[remote].0
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        self.graph_v22 = Some(graph);
        Ok(self)
    }

    pub(super) fn exchange_graph_offer_v22(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        graph: &ProductionNoiseGraphOfferV22,
    ) -> Result<ProductionReceivedXmrGraphCandidateV22, ProductionNoiseRelayErrorV1> {
        // Every connection resends exact immutable local bytes. There is no
        // durability acknowledgement before the owner has checked the graph.
        let receive = |transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>| {
            let bytes = self.receive_frame_bytes(transport)?;
            let frame = self.decode_remote_frame(&bytes)?;
            if frame.kind == FrameKindV1::Refused {
                return Err(ProductionNoiseRelayErrorV1::PeerRefused);
            }
            if frame.kind != FrameKindV1::GraphOfferV22
                || frame.body.len() > XmrGraphOfferV22::MAX_BYTES
            {
                return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
            }
            graph.verify_packet(frame.body, true)?;
            Ok(ProductionReceivedXmrGraphCandidateV22 {
                bytes: frame.body.to_vec(),
            })
        };
        // Keep fallible branches inside this closure so every local failure
        // reaches the refusal path below, including responder validation.
        let result = (|| match self.role {
            NoiseRoleV1::Initiator => {
                self.send_frame(transport, FrameKindV1::GraphOfferV22, &graph.local)?;
                receive(transport)
            }
            NoiseRoleV1::Responder => {
                let candidate = receive(transport)?;
                self.send_frame(transport, FrameKindV1::GraphOfferV22, &graph.local)?;
                Ok(candidate)
            }
        })();
        if result.is_err() {
            self.send_refusal(transport);
        }
        result
    }
}
