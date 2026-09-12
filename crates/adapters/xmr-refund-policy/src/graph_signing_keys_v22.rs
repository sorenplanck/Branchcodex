//! Public key ancestry for all five graph edges. These construction bindings
//! are not an identity-signed agreement, Store signing authority, or funding gate.
use crate::{
    compensation::{ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11 as Error},
    graph_builder::{XmrGraphKernelContributionV12, XmrRecoveryGraphTemplatesV12},
    graph_offer_v22::{XmrGraphOfferScopeV22, XmrGraphOfferV22},
};
use dom_adaptor::{canonical_template_v1, DirectionV1};
use dom_consensus::Transaction;
use dom_crypto::PublicKey;
use kaystra_core::SettlementTermsV1;

#[path = "graph_proposal_v22.rs"]
mod proposal_v22;
pub use proposal_v22::XmrGraphProposalV22;

#[cfg(test)]
#[path = "graph_signing_keys_v22_tests.rs"]
mod tests;

/// Native graph order, distinct even where two edges use plain Refund signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum XmrGraphSigningStageV22 {
    /// Wallet inputs -> collateral C.
    Funding = 0,
    /// C -> principal and change, with witness T.
    Claim = 1,
    /// C -> cancelled output D.
    Cancel = 2,
    /// D -> DOM funder, with witness U.
    Refund = 3,
    /// D -> XMR funder, subject to the funding condition.
    Compensation = 4,
}

impl XmrGraphSigningStageV22 {
    /// Canonical order used by native wallet offers and graph construction.
    pub const ALL: [Self; 5] = [
        Self::Funding,
        Self::Claim,
        Self::Cancel,
        Self::Refund,
        Self::Compensation,
    ];
}

/// Both verified offers in signed-terms roster order. Transport authentication
/// must come from the caller; PoPs alone do not authenticate a participant.
#[derive(Clone)]
pub struct XmrGraphKeyMaterialV22 {
    chain: [u8; 32],
    route: [u8; 32],
    policy_hash: [u8; 32],
    directions: [DirectionV1; 2],
    session: [u8; 32],
    terms: [u8; 32],
    participants: [[u8; 32]; 2],
    keys: [[PublicKey; 5]; 2],
    aggregates: [PublicKey; 5],
    offsets: [[u8; 32]; 5],
    packets: [Vec<u8>; 2],
}

impl XmrGraphKeyMaterialV22 {
    /// Reverify exact route, roster positions, complementary directions, payouts,
    /// funding contribution and five PoPs before retaining either contributor.
    pub fn from_offers(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scopes: [&XmrGraphOfferScopeV22<'_>; 2],
        offers: [&XmrGraphOfferV22; 2],
    ) -> Result<Self, Error> {
        if scopes[0].chain != scopes[1].chain
            || scopes[0].route_id != scopes[1].route_id
            || scopes[0].participant != terms.roster[0].0
            || scopes[1].participant != terms.roster[1].0
            || !matches!(
                (scopes[0].direction, scopes[1].direction),
                (DirectionV1::Initiator, DirectionV1::Responder)
                    | (DirectionV1::Responder, DirectionV1::Initiator)
            )
        {
            return Err(Error::GraphMismatch);
        }
        for index in 0..2 {
            offers[index].verify(terms, policy, scopes[index])?;
        }
        let mut aggregates = Vec::with_capacity(5);
        let mut offsets = Vec::with_capacity(5);
        for index in 0..5 {
            aggregates.push(
                dom_adaptor::aggregate_public_nonces_v1(&[
                    offers[0].keys()[index].clone(),
                    offers[1].keys()[index].clone(),
                ])
                .map_err(|_| Error::GraphMismatch)?,
            );
            offsets.push(
                dom_adaptor::aggregate_transaction_offset_contributions_v1(&[
                    offers[0].offsets()[index],
                    offers[1].offsets()[index],
                ])
                .map_err(|_| Error::GraphMismatch)?,
            );
        }
        Ok(Self {
            chain: *scopes[0].chain.as_bytes(),
            route: scopes[0].route_id,
            policy_hash: policy.policy().policy_hash()?,
            directions: [scopes[0].direction, scopes[1].direction],
            session: policy.policy().session_id,
            terms: *policy.terms_hash(),
            participants: terms.roster.map(|id| id.0),
            keys: [offers[0].keys().clone(), offers[1].keys().clone()],
            aggregates: aggregates.try_into().map_err(|_| Error::GraphMismatch)?,
            offsets: offsets.try_into().map_err(|_| Error::GraphMismatch)?,
            packets: [offers[0].to_bytes()?, offers[1].to_bytes()?],
        })
    }

    /// Public native kernel contribution, without any private share or nonce.
    pub fn contribution(&self, stage: XmrGraphSigningStageV22) -> XmrGraphKernelContributionV12 {
        XmrGraphKernelContributionV12 {
            excess: self.aggregates[stage as usize].clone(),
            offset: self.offsets[stage as usize],
        }
    }

    /// Keep original canonical proof packets available for durable revalidation.
    pub fn packets(&self) -> [&[u8]; 2] {
        [&self.packets[0], &self.packets[1]]
    }

    /// Bind every contributor to the exact unsigned graph, never just its key sum.
    /// The graph constructor remains responsible for balance and C/D proof checks.
    pub fn bind_templates(
        &self,
        templates: &XmrRecoveryGraphTemplatesV12,
    ) -> Result<XmrGraphSigningKeysV22, Error> {
        let binding = templates.binding();
        if binding.chain_id != self.chain
            || binding.session_id != self.session
            || binding.terms_hash != self.terms
        {
            return Err(Error::GraphMismatch);
        }
        let hashes = self.transaction_hashes([
            templates.funding(),
            templates.claim(),
            templates.cancel(),
            templates.refund(),
            templates.compensation(),
        ])?;
        Ok(XmrGraphSigningKeysV22 {
            material: self.clone(),
            templates: hashes,
            binding: *binding,
        })
    }

    fn transaction_hashes(&self, transactions: [&Transaction; 5]) -> Result<[[u8; 32]; 5], Error> {
        let mut hashes = [[0; 32]; 5];
        for (index, transaction) in transactions.into_iter().enumerate() {
            if transaction.kernels.len() != 1
                || transaction.kernels[0].excess.as_bytes()
                    != &self.aggregates[index].to_compressed_bytes()
                || transaction.kernels[0].excess_signature != [0; 65]
                || transaction.offset != self.offsets[index]
            {
                return Err(Error::GraphMismatch);
            }
            hashes[index] = canonical_template_v1(transaction)
                .map_err(|_| Error::GraphMismatch)?
                .1;
            if hashes[index] == [0; 32] || hashes[..index].contains(&hashes[index]) {
                return Err(Error::GraphMismatch);
            }
        }
        Ok(hashes)
    }
}

/// Exact public construction ancestry. A native identity-signed graph agreement
/// and the Store's phase/provenance checks are still required before signing.
pub struct XmrGraphSigningKeysV22 {
    material: XmrGraphKeyMaterialV22,
    templates: [[u8; 32]; 5],
    binding: dom_scriptless_crypto::XmrRecoveryGraphBindingV11,
}

impl XmrGraphSigningKeysV22 {
    /// The composition owner must pin the route independently of Store scope.
    pub fn require_route(&self, route: [u8; 32]) -> Result<(), Error> {
        if route != self.material.route {
            return Err(Error::GraphMismatch);
        }
        Ok(())
    }

    /// Match the native Store's actual chain, session, terms and roster roles.
    /// Route admission remains the composition root's separate responsibility.
    pub fn require_scope(
        &self,
        chain: &dom_adaptor::TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        participants: [[u8; 32]; 2],
        directions: [DirectionV1; 2],
    ) -> Result<(), Error> {
        if &self.material.chain != chain.as_bytes()
            || self.material.session != session
            || self.material.terms != terms
            || self.material.participants != participants
            || self.material.directions != directions
        {
            return Err(Error::GraphMismatch);
        }
        Ok(())
    }

    /// Refuse a different native graph, including adaptor points omitted from
    /// transaction-template hashes. This is construction equality, not a grant.
    pub fn require_graph(&self, graph: &XmrRecoveryGraphTemplatesV12) -> Result<(), Error> {
        if self.binding != *graph.binding()
            || self.templates
                != self.material.transaction_hashes([
                    graph.funding(),
                    graph.claim(),
                    graph.cancel(),
                    graph.refund(),
                    graph.compensation(),
                ])?
        {
            return Err(Error::GraphMismatch);
        }
        Ok(())
    }

    /// Select one participant's key only for the matching edge and template.
    pub fn key(
        &self,
        stage: XmrGraphSigningStageV22,
        participant: [u8; 32],
        template: [u8; 32],
    ) -> Result<&PublicKey, Error> {
        if self.templates[stage as usize] != template {
            return Err(Error::GraphMismatch);
        }
        let index = self
            .material
            .participants
            .iter()
            .position(|id| id == &participant)
            .ok_or(Error::GraphMismatch)?;
        Ok(&self.material.keys[index][stage as usize])
    }

    /// Canonical hash for this exact graph edge, not a caller-provided digest.
    pub const fn template_hash(&self, stage: XmrGraphSigningStageV22) -> [u8; 32] {
        self.templates[stage as usize]
    }

    /// Original public contribution proofs in canonical roster order.
    pub fn packets(&self) -> [&[u8]; 2] {
        self.material.packets()
    }
}
