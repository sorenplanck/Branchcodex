//! Bounded public contribution packet for the bilateral native XMR graph.
//! A valid packet proves construction/knowledge, not funding readiness.
use crate::{
    compensation::{ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11 as Error},
    funding_offer_v22::XmrFundingOfferV22,
    graph_contribution_digest_v22::{XmrGraphContributionDigestV22, XmrGraphFundingDigestV22},
    graph_key_proofs_v22::XmrGraphKeyProofScopeV22,
    payout_offer_v22::{XmrGraphPayoutKindV22 as Kind, XmrPolicyPayoutOfferV22},
};
use dom_adaptor::{DirectionV1, TrustedChainIdV1};
use dom_crypto::PublicKey;
use kaystra_core::SettlementTermsV1;

#[path = "graph_offer_verification_cache_v24.rs"]
mod verification_cache_v24;

/// Context authenticated outside the packet, including the Noise sender.
pub struct XmrGraphOfferScopeV22<'a> {
    /// Locally trusted DOM chain identity.
    pub chain: &'a TrustedChainIdV1,
    /// Exact admitted route identity.
    pub route_id: [u8; 32],
    /// Expected participant, not a packet-asserted transport identity.
    pub participant: [u8; 32],
    /// Expected native participant direction.
    pub direction: DirectionV1,
}

/// One participant's complete public construction contribution. Private
/// fields prevent bypassing verification by mutating an accepted packet.
pub struct XmrGraphOfferV22 {
    route_id: [u8; 32],
    keys: [PublicKey; 5],
    offsets: [[u8; 32]; 5],
    funding: XmrFundingOfferV22,
    payouts: [XmrPolicyPayoutOfferV22; 2],
    proofs: [u8; XmrGraphKeyProofScopeV22::ENCODED_LEN],
}

impl XmrGraphOfferV22 {
    /// Fixed packet bound, checked before decoding any nested payload.
    pub const MAX_BYTES: usize = 32_768;

    /// Verify all components and their common authenticated context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scope: &XmrGraphOfferScopeV22<'_>,
        keys: [PublicKey; 5],
        offsets: [[u8; 32]; 5],
        funding: XmrFundingOfferV22,
        payouts: [XmrPolicyPayoutOfferV22; 2],
        proofs: [u8; XmrGraphKeyProofScopeV22::ENCODED_LEN],
    ) -> Result<Self, Error> {
        let offer = Self {
            route_id: scope.route_id,
            keys,
            offsets,
            funding,
            payouts,
            proofs,
        };
        offer.verify(terms, policy, scope)?;
        offer.to_bytes()?;
        Ok(offer)
    }

    /// Recheck the policy, both exact local payouts and all five native PoPs.
    /// The complete graph must still verify balance, C/D ancestry and signing
    /// history before any funding authorization can be produced.
    pub fn verify(
        &self,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scope: &XmrGraphOfferScopeV22<'_>,
    ) -> Result<(), Error> {
        verification_cache_v24::verify(self, terms, policy, scope)
    }

    // The original, pure construction verifier. Cache misses and every cache
    // failure execute this unchanged path; it grants no time/state authority.
    fn verify_uncached_v24(
        &self,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scope: &XmrGraphOfferScopeV22<'_>,
    ) -> Result<(), Error> {
        if scope.route_id == [0; 32]
            || self.route_id != scope.route_id
            || scope.chain.as_bytes() != &policy.policy().dom_chain_id
        {
            return Err(Error::GraphMismatch);
        }
        self.funding.verify(terms, policy, scope.participant)?;
        let kinds = if scope.participant == policy.policy().dom_funder {
            [Kind::ClaimChange, Kind::Refund]
        } else {
            [Kind::ClaimPrincipal, Kind::Compensation]
        };
        for (payout, kind) in self.payouts.iter().zip(kinds) {
            if payout.kind() != kind {
                return Err(Error::GraphMismatch);
            }
            payout.verify(terms, policy, scope.chain, scope.direction)?;
        }
        for offset in self.offsets {
            dom_adaptor::aggregate_transaction_offset_contributions_v1(&[offset])
                .map_err(|_| Error::GraphMismatch)?;
        }
        let roster = terms.roster.map(|p| p.0);
        let index = roster
            .iter()
            .position(|id| id == &scope.participant)
            .ok_or(Error::GraphMismatch)?;
        XmrGraphKeyProofScopeV22 {
            chain: scope.chain,
            session_id: policy.policy().session_id,
            roster: &roster,
            direction: scope.direction,
            participant_index: index as u16,
            terms_hash: *policy.terms_hash(),
            keys: &self.keys,
            public_commitment: self.public_commitment(policy, scope),
        }
        .verify(&self.proofs)
    }

    /// Reconstruct the commitment using only public packet and route fields.
    /// Call verify before treating the components as authenticated evidence.
    pub fn public_commitment(
        &self,
        policy: &ValidatedXmrCompensationPolicyV11,
        scope: &XmrGraphOfferScopeV22<'_>,
    ) -> [u8; 32] {
        let inputs: Vec<_> = self
            .funding
            .inputs()
            .iter()
            .map(|i| *i.commitment.as_bytes())
            .collect();
        XmrGraphContributionDigestV22 {
            scope: [
                policy.policy().dom_chain_id,
                scope.route_id,
                policy.policy().session_id,
                *policy.terms_hash(),
                scope.participant,
            ],
            keys: &self.keys,
            offsets: &self.offsets,
            funding: (scope.participant == policy.policy().dom_funder).then_some(
                XmrGraphFundingDigestV22 {
                    inputs: &inputs,
                    change: self.funding.change().map(|o| *o.commitment.as_bytes()),
                    fee: self.funding.fee(),
                },
            ),
        }
        .digest()
    }

    /// Canonical complete packet, to be retained before transport publication.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"DXGO22\0\x01".to_vec();
        bytes.extend_from_slice(&self.route_id);
        for key in &self.keys {
            bytes.extend_from_slice(&key.to_compressed_bytes());
        }
        for offset in self.offsets {
            bytes.extend_from_slice(&offset);
        }
        bytes.extend_from_slice(&self.proofs);
        for payload in [
            self.funding.to_bytes()?,
            self.payouts[0].to_bytes()?,
            self.payouts[1].to_bytes()?,
        ] {
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&payload);
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        Ok(bytes)
    }

    /// Strict decode using authenticated expected context, never packet IDs.
    pub fn from_bytes(
        bytes: &[u8],
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scope: &XmrGraphOfferScopeV22<'_>,
    ) -> Result<Self, Error> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(8)? != b"DXGO22\0\x01" {
            return Err(Error::NonCanonical);
        }
        let route_id = reader.array()?;
        if route_id != scope.route_id {
            return Err(Error::GraphMismatch);
        }
        let mut keys = Vec::with_capacity(5);
        for _ in 0..5 {
            keys.push(
                PublicKey::from_compressed_bytes(reader.take(33)?)
                    .map_err(|_| Error::NonCanonical)?,
            );
        }
        let keys = keys.try_into().map_err(|_| Error::NonCanonical)?;
        let offsets = [
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
        ];
        let proofs = reader.array()?;
        let funding = XmrFundingOfferV22::from_bytes(
            reader.payload(XmrFundingOfferV22::MAX_BYTES)?,
            terms,
            policy,
            scope.participant,
        )?;
        let mut payouts = Vec::with_capacity(2);
        for _ in 0..2 {
            payouts.push(XmrPolicyPayoutOfferV22::from_bytes(
                reader.payload(XmrPolicyPayoutOfferV22::MAX_BYTES)?,
                terms,
                policy,
                scope.chain,
                scope.direction,
            )?);
        }
        if reader.position != bytes.len() {
            return Err(Error::NonCanonical);
        }
        let offer = Self {
            route_id,
            keys,
            offsets,
            funding,
            payouts: payouts.try_into().map_err(|_| Error::NonCanonical)?,
            proofs,
        };
        offer.verify(terms, policy, scope)?;
        if offer.to_bytes()? != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(offer)
    }

    /// Verified public funding construction material.
    pub const fn funding(&self) -> &XmrFundingOfferV22 {
        &self.funding
    }
    /// The two local payments, in success/recovery order.
    pub const fn payouts(&self) -> &[XmrPolicyPayoutOfferV22; 2] {
        &self.payouts
    }
    /// Five public excess contributions, in native stage order.
    pub const fn keys(&self) -> &[PublicKey; 5] {
        &self.keys
    }
    /// Five public offset contributions in the same order.
    pub const fn offsets(&self) -> &[[u8; 32]; 5] {
        &self.offsets
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::NonCanonical)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::NonCanonical)?;
        self.position = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::NonCanonical)
    }
    fn payload(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let size =
            usize::try_from(u32::from_le_bytes(self.array()?)).map_err(|_| Error::NonCanonical)?;
        if size > limit {
            return Err(Error::NonCanonical);
        }
        self.take(size)
    }
}
