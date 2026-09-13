//! Native F6 terms PROPOSAL, not signed consent or an executable F6 grant.
//!
//! Owns real adapter faces and a real frozen composition. This module does not
//! implement ProductionF6TermsAuthorityV2, create AuthenticatedF6TermsV2, accept
//! a Relay delivery, reserve inventory, or change the legacy intent/RFQ rule.
//! The future consumer MUST authenticate the original outer NativeAcceptanceV25
//! envelope and compare its exact terms/record against this opaque proposal,
//! along with the real quote, reservation/status and current time authorities.

use super::{
    digest, AdapterAuthenticatedRefundFaceV2, ProductionAdapterF6TermsAuthorityV2,
    ProductionF6ErrorV2, ProductionSolverF6BindingV2, TermsIntentCheckV25,
};
use crate::production_f6::native_reconfirmation_v25::PreparedNativeReconfirmationRecordV25;
use rfq::v2::{QuoteV2, RfqV2, SettlementPositionV2, TermsBindingV2};
use route_composer::ComposedBindingV2;
use std::rc::Rc;

const PROPOSAL_DOMAIN: &[u8] = b"DOM-INTEROP/F6/NATIVE-TERMS-PROPOSAL-EVIDENCE/V25\0";
type Result<T> = core::result::Result<T, ProductionF6ErrorV2>;

/// One-shot owner for explicit native reconfirmation preparation. No decoder,
/// raw-field constructor, Clone or conversion to the legacy terms authority.
pub(crate) struct ProductionNativeF6TermsProposalOwnerV25 {
    composition: Rc<ComposedBindingV2>,
    original: Option<ProductionAdapterF6TermsAuthorityV2>,
}

/// Move-only provenance-bearing PROPOSAL. Only its public data can be read.
/// Holding this object is not proof of either participant's acceptance.
pub(crate) struct PreparedNativeF6TermsProposalV25 {
    terms: TermsBindingV2,
    record: PreparedNativeReconfirmationRecordV25,
    evidence_digest: [u8; 32],
    evidence_revision: u64,
    // Keep the actual opaque face owners and original composition alive. A
    // receipt decoder cannot reconstruct them from public commitment fields.
    original: ProductionAdapterF6TermsAuthorityV2,
    composition: Rc<ComposedBindingV2>,
}

impl ProductionNativeF6TermsProposalOwnerV25 {
    /// Captures both authentic adapter faces through the unchanged legacy
    /// constructor's composition, settlement, deployment and scope checks.
    pub(crate) fn new(
        binding: ProductionSolverF6BindingV2,
        composition: Rc<ComposedBindingV2>,
        dom: AdapterAuthenticatedRefundFaceV2,
        counterparty: AdapterAuthenticatedRefundFaceV2,
    ) -> Result<Self> {
        let original =
            ProductionAdapterF6TermsAuthorityV2::new(binding, &composition, dom, counterparty)?;
        Ok(Self {
            composition,
            original: Some(original),
        })
    }

    /// Returns only a proposal. Failures retain both original face owners;
    /// successful preparation consumes them exactly once into the proposal.
    pub(crate) fn prepare(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<PreparedNativeF6TermsProposalV25> {
        let original = self
            .original
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        let record = PreparedNativeReconfirmationRecordV25::prepare(
            &self.composition,
            binding.wire,
            binding.position,
            rfq,
            quote,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        original.validate_cross_objects_with_intent(
            binding,
            rfq,
            quote,
            TermsIntentCheckV25::NativeReconfirmation {
                composition: &self.composition,
                record: &record,
            },
        )?;
        let dom = original
            .dom
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        let counterparty = original
            .counterparty
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        let (first, second) = if rfq.route.legs[0].chain_id == binding.dom_chain_id {
            (dom, counterparty)
        } else {
            (counterparty, dom)
        };
        let terms = TermsBindingV2::from_parts(rfq, quote, [first.face, second.face])
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let evidence_revision = first
            .evidence_revision
            .checked_add(second.evidence_revision)
            .and_then(|revision| revision.checked_add(original.time_evidence_sequence))
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
        let evidence_digest = digest(
            PROPOSAL_DOMAIN,
            &[
                &binding.authority_digest(PROPOSAL_DOMAIN)?,
                &record.digest(),
                &terms
                    .canonical_bytes()
                    .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?,
                &first.evidence_digest,
                &first.evidence_revision.to_be_bytes(),
                &second.evidence_digest,
                &second.evidence_revision.to_be_bytes(),
                &evidence_revision.to_be_bytes(),
            ],
        )?;
        let original = self
            .original
            .take()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        Ok(PreparedNativeF6TermsProposalV25 {
            terms,
            record,
            evidence_digest,
            evidence_revision,
            original,
            composition: Rc::clone(&self.composition),
        })
    }
}

impl PreparedNativeF6TermsProposalV25 {
    pub(crate) const fn terms(&self) -> &TermsBindingV2 {
        &self.terms
    }
    pub(in crate::production_f6) const fn record(&self) -> &PreparedNativeReconfirmationRecordV25 {
        &self.record
    }
    /// Exact public record bytes, without exposing a constructor or capability.
    pub(crate) fn record_bytes(&self) -> &[u8] {
        self.record.canonical_bytes()
    }
    pub(crate) const fn record_digest(&self) -> [u8; 32] {
        self.record.digest()
    }
    /// Audit evidence only; NOT committed by legacy TermsBindingV2::terms_hash.
    /// The signed outer NativeAcceptanceV25 must name record().digest() too.
    pub(crate) const fn proposal_evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }
    pub(crate) const fn proposal_evidence_revision(&self) -> u64 {
        self.evidence_revision
    }
    pub(crate) const fn binding(&self) -> ProductionSolverF6BindingV2 {
        self.original.binding
    }
    pub(crate) fn composition(&self) -> &ComposedBindingV2 {
        &self.composition
    }
}

/// Native intention matching rederives the entire record rather than treating
/// a nonzero digest or an enrollment flag as authority. The common validator
/// still checks every legacy cross-object and adapter guard independently.
pub(super) fn matches_original_record(
    owner: &ProductionAdapterF6TermsAuthorityV2,
    binding: &ProductionSolverF6BindingV2,
    composition: &ComposedBindingV2,
    record: &PreparedNativeReconfirmationRecordV25,
    rfq: &RfqV2,
    quote: &QuoteV2,
) -> bool {
    let selected = match binding.position {
        SettlementPositionV2::Upstream => composition.upstream(),
        SettlementPositionV2::Downstream => composition.downstream(),
    };
    if owner.settlement != *selected
        || owner.composition_binding_digest != composition.binding_digest()
        || owner.route_scope_digest != composition.route_scope_digest()
        || owner.time_policy_digest != composition.time_policy_digest()
        || owner.time_evidence_digest != composition.time_evidence_digest()
        || owner.time_proof_digest != composition.time_proof_digest()
        || owner.time_evidence_sequence != composition.evidence_sequence()
    {
        return false;
    }
    PreparedNativeReconfirmationRecordV25::prepare(
        composition,
        binding.wire,
        binding.position,
        rfq,
        quote,
    )
    .is_ok_and(|expected| {
        expected.canonical_bytes() == record.canonical_bytes()
            && expected.digest() == record.digest()
    })
}

#[cfg(test)]
#[path = "native_reconfirmation_terms_v25_tests.rs"]
pub(super) mod tests;
