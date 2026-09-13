//! Explicit post-enrollment acceptance payload. Everything here is PUBLIC DATA.
//!
//! Decoding this payload proves canonical consistency, NOT sender identity,
//! consent, signature validity, reservation, current time or funding authority.
//! A runtime must authenticate the ORIGINAL complete Relay ACCEPTANCE envelope
//! and its initiator role, then validate this outer payload against its exact
//! prepared reconfirmation record and adapter-authenticated terms. It must not
//! strip this wrapper and invent an authenticated delivery for the inner V2
//! acceptance. Legacy V2 encoding and interpretation remain unchanged.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;

use crate::{
    v2::{AcceptanceV2, F6V2Refusal, RouteV2, SettlementPositionV2, TermsBindingV2},
    ParticipantId,
};

/// Closed public V25 acceptance discriminator, distinct from legacy V1/V2.
pub const NATIVE_ACCEPTANCE_MAGIC_V25: &[u8; 8] = b"DOMIAC25";
/// Closed framing/profile version; this does not change the inner V2 codec.
pub const NATIVE_ACCEPTANCE_VERSION_V25: u16 = 25;
/// Explicit profile included literally in canonical bytes and digest domain.
pub const NATIVE_ACCEPTANCE_DOMAIN_V25: &[u8] = b"DOM-INTEROP/F6/POST-ENROLLMENT-ACCEPTANCE/V25\0";
/// Entire payload bound checked before decoding or allocating inner objects.
pub const MAX_NATIVE_ACCEPTANCE_BYTES_V25: usize = 2048;
const MAX_TERMS_BYTES: usize = 1024;
const INNER_ACCEPTANCE_BYTES: usize = 171;
const HEADER_BYTES: usize = 8 + 2 + 2 + 2 + NATIVE_ACCEPTANCE_DOMAIN_V25.len() + 4;
const FIXED_BYTES: usize = HEADER_BYTES + 32 + 32 + 4 + 4;
type Result<T> = core::result::Result<T, F6V2Refusal>;

/// Canonical public acceptance proposal, never an authenticated capability.
/// All fields are private so cross-object invariants hold after construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAcceptanceV25 {
    terms: TermsBindingV2,
    prepared_record_digest: Digest32,
    acceptance: AcceptanceV2,
}

impl NativeAcceptanceV25 {
    /// Constructs data to be signed in a complete Relay ACCEPTANCE envelope.
    /// A nonzero record digest is an identifier, not proof of its provenance.
    pub fn new(
        terms: &TermsBindingV2,
        prepared_record_digest: Digest32,
        accepted_by: ParticipantId,
    ) -> Result<Self> {
        terms.validate()?;
        if prepared_record_digest == [0; 32]
            || accepted_by.0 == [0; 32]
            || accepted_by == terms.solver_id
        {
            return Err(F6V2Refusal::InvalidField);
        }
        let acceptance = AcceptanceV2::from_terms(terms, accepted_by)?;
        Ok(Self {
            terms: *terms,
            prepared_record_digest,
            acceptance,
        })
    }

    /// Exact original F6 terms; no evidence or payout field is rewritten.
    pub const fn terms(&self) -> &TermsBindingV2 {
        &self.terms
    }

    /// Digest of the complete prepared PUBLIC reconfirmation record.
    pub const fn prepared_record_digest(&self) -> Digest32 {
        self.prepared_record_digest
    }

    /// Inner public object for cross-checking only, not a standalone delivery.
    pub const fn inner_acceptance(&self) -> &AcceptanceV2 {
        &self.acceptance
    }

    /// Claimed initiator; must match the authenticated outer envelope sender.
    pub const fn accepted_by(&self) -> ParticipantId {
        self.acceptance.accepted_by
    }

    /// Complete route claimed by this public payload.
    pub const fn route(&self) -> RouteV2 {
        self.terms.route
    }

    /// Claimed Relay session; compare with the original authenticated envelope.
    pub const fn session_id(&self) -> Digest32 {
        self.terms.session_id
    }

    /// Exact content-addressed request identifier.
    pub const fn rfq_id(&self) -> Digest32 {
        self.terms.rfq_id
    }

    /// Exact content-addressed quote identifier.
    pub const fn quote_id(&self) -> Digest32 {
        self.terms.quote_id
    }

    /// Complete original composition identifier, not a pre-negotiation hint.
    pub const fn composition_id(&self) -> Digest32 {
        self.terms.route.composition_id
    }

    /// Ordered settlement position in the linked composition.
    pub const fn position(&self) -> SettlementPositionV2 {
        self.terms.route.position
    }

    /// Validates exact expected public sources. The caller remains responsible
    /// for authenticating those sources and the complete signed envelope.
    pub fn validate_against(
        &self,
        expected_terms: &TermsBindingV2,
        expected_record_digest: Digest32,
        expected_initiator: ParticipantId,
    ) -> Result<()> {
        let expected = Self::new(expected_terms, expected_record_digest, expected_initiator)?;
        if self != &expected {
            return Err(F6V2Refusal::BindingMismatch);
        }
        self.acceptance.validate_against(&self.terms)
    }

    /// Complete canonical bytes to retain and sign as the outer payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.acceptance.validate_against(&self.terms)?;
        let terms = self.terms.canonical_bytes()?;
        let acceptance = self.acceptance.canonical_bytes()?;
        if terms.len() > MAX_TERMS_BYTES || acceptance.len() != INNER_ACCEPTANCE_BYTES {
            return Err(F6V2Refusal::BoundExceeded);
        }
        let total = FIXED_BYTES
            .checked_add(terms.len())
            .and_then(|len| len.checked_add(acceptance.len()))
            .ok_or(F6V2Refusal::Overflow)?;
        if total > MAX_NATIVE_ACCEPTANCE_BYTES_V25 {
            return Err(F6V2Refusal::BoundExceeded);
        }
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(NATIVE_ACCEPTANCE_MAGIC_V25);
        output.extend_from_slice(&NATIVE_ACCEPTANCE_VERSION_V25.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        put_u16_length(&mut output, NATIVE_ACCEPTANCE_DOMAIN_V25.len())?;
        output.extend_from_slice(NATIVE_ACCEPTANCE_DOMAIN_V25);
        put_u32_length(&mut output, total)?;
        output.extend_from_slice(&self.prepared_record_digest);
        output.extend_from_slice(&self.acceptance.accepted_by.0);
        put_u32_length(&mut output, terms.len())?;
        output.extend_from_slice(&terms);
        put_u32_length(&mut output, acceptance.len())?;
        output.extend_from_slice(&acceptance);
        Ok(output)
    }

    /// Strict, bounded data-only decode with full canonical reread. Unknown
    /// profile/version, inconsistent inner acceptance and suffixes fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NATIVE_ACCEPTANCE_BYTES_V25 {
            return Err(F6V2Refusal::BoundExceeded);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(8)? != NATIVE_ACCEPTANCE_MAGIC_V25
            || reader.u16()? != NATIVE_ACCEPTANCE_VERSION_V25
            || reader.u16()? != 0
            || usize::from(reader.u16()?) != NATIVE_ACCEPTANCE_DOMAIN_V25.len()
            || reader.take(NATIVE_ACCEPTANCE_DOMAIN_V25.len())? != NATIVE_ACCEPTANCE_DOMAIN_V25
        {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        if reader.length()? != bytes.len() {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        let record = reader.array()?;
        let accepted_by = ParticipantId(reader.array()?);
        let terms_len = reader.length()?;
        if terms_len == 0 || terms_len > MAX_TERMS_BYTES {
            return Err(F6V2Refusal::BoundExceeded);
        }
        let terms = TermsBindingV2::decode(reader.take(terms_len)?)?;
        if reader.length()? != INNER_ACCEPTANCE_BYTES {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        let inner = AcceptanceV2::decode(reader.take(INNER_ACCEPTANCE_BYTES)?)?;
        if reader.position != bytes.len() {
            return Err(F6V2Refusal::TrailingBytes);
        }
        let value = Self::new(&terms, record, accepted_by)?;
        if inner != value.acceptance {
            return Err(F6V2Refusal::BindingMismatch);
        }
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }

    /// Domain-separated identity of the complete outer public message. This
    /// unkeyed digest is neither a signature nor an authentication token.
    pub fn message_digest(&self) -> Result<Digest32> {
        let mut digest = Blake2bVar::new(32).map_err(|_| F6V2Refusal::Digest)?;
        digest.update(NATIVE_ACCEPTANCE_DOMAIN_V25);
        digest.update(&self.canonical_bytes()?);
        let mut result = [0; 32];
        digest
            .finalize_variable(&mut result)
            .map_err(|_| F6V2Refusal::Digest)?;
        Ok(result)
    }
}

fn put_u16_length(output: &mut Vec<u8>, length: usize) -> Result<()> {
    let value = u16::try_from(length).map_err(|_| F6V2Refusal::BoundExceeded)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_u32_length(output: &mut Vec<u8>, length: usize) -> Result<()> {
    let value = u32::try_from(length).map_err(|_| F6V2Refusal::BoundExceeded)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(F6V2Refusal::Overflow)?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(F6V2Refusal::Truncated)?;
        self.position = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| F6V2Refusal::Truncated)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn length(&mut self) -> Result<usize> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| F6V2Refusal::BoundExceeded)
    }
}

#[cfg(test)]
#[path = "native_reconfirmation_v25_tests.rs"]
mod tests;
