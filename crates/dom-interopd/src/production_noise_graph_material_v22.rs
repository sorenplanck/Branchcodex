//! Public inputs assembled only from both packets under the native Noise scope.
use super::*;
pub(crate) use xmr_refund_policy::graph_public_material_v23::XmrGraphPublicMaterialV23 as ProductionXmrGraphPublicMaterialV22;

impl ProductionNoiseGraphOfferV22 {
    pub(crate) fn assemble_peer_material_v22(
        &self,
        peer: &[u8],
    ) -> Result<ProductionXmrGraphPublicMaterialV22, ProductionNoiseRelayErrorV1> {
        let local = self.decode_packet(&self.local, false)?;
        let peer = self.decode_packet(peer, true)?;
        let offers = if self.native.participant_index() == 0 {
            [local, peer]
        } else {
            [peer, local]
        };
        let opposite = match self.native.role() {
            dom_adaptor::DirectionV1::Initiator => dom_adaptor::DirectionV1::Responder,
            dom_adaptor::DirectionV1::Responder => dom_adaptor::DirectionV1::Initiator,
        };
        let scopes: [_; 2] = std::array::from_fn(|index| XmrGraphOfferScopeV22 {
            chain: self.native.trusted_chain_id(),
            route_id: self.route_id,
            participant: self.terms.roster[index].0,
            direction: if index == usize::from(self.native.participant_index()) {
                self.native.role()
            } else {
                opposite
            },
        });
        ProductionXmrGraphPublicMaterialV22::from_offers(
            &self.terms,
            &self.policy,
            [&scopes[0], &scopes[1]],
            [&offers[0], &offers[1]],
        )
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)
    }
}
