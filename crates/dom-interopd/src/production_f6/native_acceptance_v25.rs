//! Explicit native proposal/consent boundary. Never turns public receipt bytes
//! into adapter authority and never fabricates a delivery for the V2 inner
//! acceptance. The original authenticated Relay payload is checked intact.

use super::native_reconfirmation_v25::PreparedNativeReconfirmationRecordV25;
use super::terms::{PreparedNativeF6TermsProposalV25, ProductionNativeF6TermsProposalOwnerV25};
use super::*;
use rfq::native_reconfirmation_v25::NativeAcceptanceV25;

const PROPOSAL_NAMESPACE: &[u8] = b"interopd-f6-native-proposal-v25";
const PROPOSAL_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-NATIVE-PROPOSAL-RECEIPT/V25\0";
const MAX_PROPOSAL_BYTES: usize = 18_432;
pub(super) const NATIVE_SOLVER_LOG_DOMAIN_V25: &[u8] =
    b"DOM-INTEROP/INTEROPD/F6-NATIVE-SOLVER-LOG/V25\0";
pub(super) const NATIVE_SOLVER_RECEIPTS_DOMAIN_V25: &[u8] =
    b"DOM-INTEROP/INTEROPD/F6-NATIVE-SOLVER-RECEIPTS/V25\0";
pub(super) const NATIVE_INITIATOR_LOG_DOMAIN_V25: &[u8] =
    b"DOM-INTEROP/INTEROPD/F6-NATIVE-INITIATOR-LOG/V25\0";
pub(super) const NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25: &[u8] =
    b"DOM-INTEROP/INTEROPD/F6-NATIVE-INITIATOR-RECEIPTS/V25\0";

/// Closed choice of real adapter sources, not a public mode flag or callback
/// capable of returning manufactured native terms. Native preparation is
/// session-local; a fresh process must reacquire the actual opaque owners.
pub(crate) enum ProductionF6TermsSourceV25 {
    Legacy(Box<dyn ProductionF6TermsAuthorityV2>),
    Native {
        owner: ProductionNativeF6TermsProposalOwnerV25,
        prepared: Option<PreparedNativeF6TermsProposalV25>,
    },
}

impl ProductionF6TermsSourceV25 {
    pub(crate) fn legacy(owner: Box<dyn ProductionF6TermsAuthorityV2>) -> Self {
        Self::Legacy(owner)
    }

    pub(crate) fn native(owner: ProductionNativeF6TermsProposalOwnerV25) -> Self {
        Self::Native {
            owner,
            prepared: None,
        }
    }

    pub(crate) fn is_native(&self) -> bool {
        matches!(self, Self::Native { .. })
    }

    /// A fresh process cannot change this profile by changing its in-memory
    /// source. Both physical stores are opened under profile-specific bindings,
    /// including pristine and interrupted Stage-11 promotion prefixes.
    pub(super) fn store_domains(
        &self,
        legacy_log: &'static [u8],
        legacy_receipts: &'static [u8],
        native_log: &'static [u8],
        native_receipts: &'static [u8],
    ) -> (&'static [u8], &'static [u8]) {
        if self.is_native() {
            (native_log, native_receipts)
        } else {
            (legacy_log, legacy_receipts)
        }
    }

    pub(crate) fn require_legacy(&self) -> Result<(), ProductionF6ErrorV2> {
        if self.is_native() {
            Err(ProductionF6ErrorV2::InvalidTerms)
        } else {
            Ok(())
        }
    }

    pub(super) fn authenticate_terms(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<AuthenticatedF6TermsV2, ProductionF6ErrorV2> {
        match self {
            Self::Legacy(owner) => owner.authenticate_terms(binding, rfq, quote),
            Self::Native { .. } => Err(ProductionF6ErrorV2::InvalidTerms),
        }
    }

    fn prepare_native(
        &mut self,
        binding: ProductionSolverF6BindingV2,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<&PreparedNativeF6TermsProposalV25, ProductionF6ErrorV2> {
        let Self::Native { owner, prepared } = self else {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        };
        if prepared.is_none() {
            *prepared = Some(owner.prepare(&binding, rfq, quote)?);
        }
        let proposal = prepared
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        if proposal.binding() != binding {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        // Exact full-object comparison on every access. This is not a cached
        // time, candidate, inventory or acceptance verdict. Those authorities
        // remain mandatory in each receiver operation before this call.
        let expected = PreparedNativeReconfirmationRecordV25::prepare(
            proposal.composition(),
            binding.wire,
            binding.position,
            rfq,
            quote,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let terms = TermsBindingV2::from_parts(rfq, quote, proposal.terms().faces)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        if expected.canonical_bytes() != proposal.record_bytes()
            || expected.digest() != proposal.record_digest()
            || terms != *proposal.terms()
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        Ok(proposal)
    }
}

/// Public preparation bytes only. No decoder exists: every process first
/// prepares with real owners and then compares this complete immutable record.
fn proposal_receipt(
    binding: ProductionSolverF6BindingV2,
    proposal: &PreparedNativeF6TermsProposalV25,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let terms = proposal
        .terms()
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let record = proposal.record_bytes();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DOMF6P25");
    bytes.extend_from_slice(&binding.authority_digest(PROPOSAL_DOMAIN)?);
    bytes.extend_from_slice(&proposal.record_digest());
    bytes.extend_from_slice(
        &u32::try_from(record.len())
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(record);
    bytes.extend_from_slice(
        &u32::try_from(terms.len())
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&terms);
    if bytes.len() > MAX_PROPOSAL_BYTES {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    Ok(bytes)
}

/// Produces unsigned OUTER data. This neither applies Bound nor commits
/// inventory. Caller must already have validated the still-current selection.
pub(super) fn prepare_native_acceptance_v25(
    binding: ProductionSolverF6BindingV2,
    source: &mut ProductionF6TermsSourceV25,
    receipts: &mut Store,
    rfq: &RfqV2,
    quote: &QuoteV2,
) -> Result<NativeAcceptanceV25, ProductionF6ErrorV2> {
    let proposal = source.prepare_native(binding, rfq, quote)?;
    let solver =
        ProductionStoreBindingV1::new(binding.authority_digest(NATIVE_SOLVER_RECEIPTS_DOMAIN_V25)?)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    let initiator = ProductionStoreBindingV1::new(
        binding.authority_digest(NATIVE_INITIATOR_RECEIPTS_DOMAIN_V25)?,
    )
    .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    // Both receivers share the public proposal format, but neither may write
    // it into an unbound, legacy, different-role-generation or foreign store.
    if receipts.require_production_binding(solver).is_err()
        && receipts.require_production_binding(initiator).is_err()
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    let record = proposal_receipt(binding, proposal)?;
    retain_proposal(receipts, binding.rfq_id, &record)?;
    NativeAcceptanceV25::new(
        proposal.terms(),
        proposal.record_digest(),
        binding.initiator,
    )
    .map_err(|_| ProductionF6ErrorV2::InvalidTerms)
}

fn retain_proposal(
    receipts: &mut Store,
    key: Digest32,
    record: &[u8],
) -> Result<(), ProductionF6ErrorV2> {
    receipts
        .put_opaque_if_absent(PROPOSAL_NAMESPACE, &key, record)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    if receipts
        .opaque(PROPOSAL_NAMESPACE, &key)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
        .as_deref()
        != Some(record)
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    Ok(())
}

/// The only native acceptance projection consumed by the existing Bound and
/// real inventory-commit transitions. The input remains the ORIGINAL complete
/// authenticated payload; the public inner object is never a new delivery.
pub(super) fn validate_original_native_acceptance_v25(
    binding: ProductionSolverF6BindingV2,
    source: &mut ProductionF6TermsSourceV25,
    receipts: &mut Store,
    rfq: &RfqV2,
    quote: &QuoteV2,
    delivery: &F6PayloadDeliveryV1<'_>,
) -> Result<AcceptanceV2, ProductionF6ErrorV2> {
    if delivery.sender_id() != binding.initiator {
        return Err(ProductionF6ErrorV2::WrongRole);
    }
    if delivery.message_type() != relay::auth::message_type::ACCEPTANCE
        || *delivery.envelope_digest() == ZERO_DIGEST
    {
        return Err(ProductionF6ErrorV2::InvalidPayload);
    }
    let received = NativeAcceptanceV25::decode(delivery.payload())
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    let expected = prepare_native_acceptance_v25(binding, source, receipts, rfq, quote)?;
    received
        .validate_against(
            expected.terms(),
            expected.prepared_record_digest(),
            binding.initiator,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    Ok(*received.inner_acceptance())
}

#[cfg(test)]
#[path = "native_acceptance_v25_tests.rs"]
mod tests;
