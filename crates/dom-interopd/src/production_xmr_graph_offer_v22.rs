//! Assemble only retained native wallet material; no peer or funding grant.
use crate::production_dom_shared_bootstrap_v12::{
    ProductionBoundDomSharedOutputV12, ProductionDomSharedBootstrapErrorV12 as Error,
};
use dom_actuator::{DomSessionBindingV1, DomXmrGraphSigningSharesV22};
use kaystra_core::SettlementTermsV1;
use xmr_refund_policy::{
    compensation::ValidatedXmrCompensationPolicyV11,
    funding_offer_v22::XmrFundingOfferV22,
    graph_offer_v22::{XmrGraphOfferScopeV22, XmrGraphOfferV22},
    payout_offer_v22::XmrPolicyPayoutOfferV22,
};

pub(crate) fn retain_local_graph_offer_v22(
    material: &mut ProductionBoundDomSharedOutputV12,
    shares: &DomXmrGraphSigningSharesV22,
    binding: DomSessionBindingV1,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
) -> Result<Vec<u8>, Error> {
    let native = material.capability.binding();
    if native.chain_id() != &binding.chain_id()
        || native.session_id() != &binding.session_id()
        || native.terms_hash() != &binding.terms_digest()
        || native.participant_id() != &binding.participant().participant_id()
        || native.participant_index() != u16::from(binding.participant().protocol_index())
        || native.roster() != terms.roster.map(|p| p.0).as_slice()
    {
        return Err(Error::Binding);
    }
    let scope = XmrGraphOfferScopeV22 {
        chain: native.trusted_chain_id(),
        route_id: binding.route_id(),
        participant: binding.participant().participant_id(),
        direction: native.role(),
    };
    let read = |key: &[u8]| {
        material
            .runtime_public_record_v16(key)?
            .ok_or(Error::Journal)
    };
    let funding = XmrFundingOfferV22::from_bytes(
        &read(b"xmr-funding-offer-v22")?,
        terms,
        policy,
        scope.participant,
    )
    .map_err(|_| Error::Binding)?;
    let keys: [&[u8]; 2] = if scope.participant == policy.policy().dom_funder {
        [b"xmr-payout-change-v22", b"xmr-payout-refund-v22"]
    } else {
        [b"xmr-payout-principal-v22", b"xmr-payout-compensation-v22"]
    };
    let mut payouts = Vec::with_capacity(2);
    for key in keys {
        payouts.push(
            XmrPolicyPayoutOfferV22::from_bytes(
                &read(key)?,
                terms,
                policy,
                scope.chain,
                scope.direction,
            )
            .map_err(|_| Error::Binding)?,
        );
    }
    let proofs = read(b"xmr-graph-proofs-v22")?
        .try_into()
        .map_err(|_| Error::Binding)?;
    let offer = XmrGraphOfferV22::new(
        terms,
        policy,
        &scope,
        shares.public_keys().clone(),
        *shares.offsets(),
        funding,
        payouts.try_into().map_err(|_| Error::Binding)?,
        proofs,
    )
    .map_err(|_| Error::Binding)?;
    if offer.public_commitment(policy, &scope) != shares.public_commitment_v22() {
        return Err(Error::Binding);
    }
    let bytes = offer.to_bytes().map_err(|_| Error::Binding)?;
    material.retain_runtime_public_v16(b"xmr-graph-offer-v22", &bytes)?;
    Ok(bytes)
}
