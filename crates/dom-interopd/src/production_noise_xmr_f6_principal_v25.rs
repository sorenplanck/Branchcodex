//! Public principal ownership reached through the original local custody and
//! authenticated graph exchange, never through an arbitrary public byte input.
use super::*;
use crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12;
use dom_adaptor::{DirectionV1, TrustedChainIdV1};
use xmr_refund_policy::payout_offer_v22::{XmrGraphPayoutKindV22, XmrPolicyPayoutOfferV22};

#[cfg(all(test, target_os = "linux"))]
#[path = "production_noise_xmr_f6_principal_v25_tests.rs"]
mod tests;

/// Construction evidence only. This is not a wallet, signing, funding, finality
/// or time authority. Only the exact principal beneficiary can supply its proof.
pub(crate) struct ProductionAuthenticatedXmrClaimPrincipalV25 {
    route_id: [u8; 32],
    terms: SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    chain: TrustedChainIdV1,
    beneficiary: [u8; 32],
    participant_index: u16,
    direction: DirectionV1,
    offer: XmrPolicyPayoutOfferV22,
}

impl ProductionAuthenticatedXmrClaimPrincipalV25 {
    pub(crate) fn route_id(&self) -> [u8; 32] {
        self.route_id
    }
    pub(crate) fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }
    pub(crate) fn policy(&self) -> &ValidatedXmrCompensationPolicyV11 {
        &self.policy
    }
    pub(crate) fn chain(&self) -> &TrustedChainIdV1 {
        &self.chain
    }
    pub(crate) fn beneficiary(&self) -> [u8; 32] {
        self.beneficiary
    }
    pub(crate) fn participant_index(&self) -> u16 {
        self.participant_index
    }
    pub(crate) fn direction(&self) -> DirectionV1 {
        self.direction
    }
    pub(crate) fn offer(&self) -> &XmrPolicyPayoutOfferV22 {
        &self.offer
    }
}

impl ProductionNoiseGraphOfferV22 {
    fn require_original_material_v25(
        &self,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        if material.capability.binding() != &self.native
            || material
                .runtime_public_record_v16(b"xmr-graph-offer-v22")
                .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?
                .as_deref()
                != Some(self.local.as_slice())
        {
            return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
        }
        Ok(())
    }

    /// Validate a peer candidate before retention, without releasing an owner.
    /// Only reopening the exact retained original journal below emits a token.
    pub(crate) fn verify_f6_peer_principal_v25(
        &self,
        material: &ProductionBoundDomSharedOutputV12,
        candidate: &ProductionReceivedXmrGraphCandidateV22,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        self.require_original_material_v25(material)?;
        self.principal_from_packet_v25(candidate.bytes(), true)
            .map(|_| ())
    }

    /// Read only from the original scope-bound journal. No API accepts raw
    /// retained peer bytes and promotes them into this identity-bearing token.
    pub(crate) fn reopen_f6_principal_v25(
        &self,
        material: &ProductionBoundDomSharedOutputV12,
    ) -> Result<Option<ProductionAuthenticatedXmrClaimPrincipalV25>, ProductionNoiseRelayErrorV1>
    {
        self.require_original_material_v25(material)?;
        if self.native.participant_id() == &self.policy.policy().xmr_funder {
            return self.principal_from_packet_v25(&self.local, false).map(Some);
        }
        let retained = material
            .runtime_public_record_v16(b"xmr-peer-graph-offer-v25")
            .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
        retained
            .map(|bytes| self.principal_from_packet_v25(&bytes, true))
            .transpose()
    }

    fn principal_from_packet_v25(
        &self,
        bytes: &[u8],
        peer: bool,
    ) -> Result<ProductionAuthenticatedXmrClaimPrincipalV25, ProductionNoiseRelayErrorV1> {
        let refused = ProductionNoiseRelayErrorV1::ProtocolRefused;
        let local = usize::from(self.native.participant_index());
        let index = if peer {
            1usize.checked_sub(local)
        } else {
            Some(local)
        }
        .ok_or(refused)?;
        let beneficiary = self.terms.roster.get(index).ok_or(refused)?.0;
        if beneficiary != self.policy.policy().xmr_funder
            || beneficiary != self.terms.dom_leg.beneficiary.0
        {
            return Err(refused);
        }
        let graph = self.decode_packet(bytes, peer)?;
        let principal = graph
            .payouts()
            .iter()
            .find(|payout| payout.kind() == XmrGraphPayoutKindV22::ClaimPrincipal)
            .ok_or(refused)?;
        let direction = if peer {
            match self.native.role() {
                DirectionV1::Initiator => DirectionV1::Responder,
                DirectionV1::Responder => DirectionV1::Initiator,
            }
        } else {
            self.native.role()
        };
        let chain = self.native.trusted_chain_id();
        let offer = XmrPolicyPayoutOfferV22::from_bytes(
            &principal.to_bytes().map_err(|_| refused)?,
            &self.terms,
            &self.policy,
            chain,
            direction,
        )
        .map_err(|_| refused)?;
        Ok(ProductionAuthenticatedXmrClaimPrincipalV25 {
            route_id: self.route_id,
            terms: self.terms.clone(),
            policy: self.policy.clone(),
            chain: *chain,
            beneficiary,
            participant_index: u16::try_from(index).map_err(|_| refused)?,
            direction,
            offer,
        })
    }
}
