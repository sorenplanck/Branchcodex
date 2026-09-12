//! V23 proof-only request over an already cached V2 sweep, never a build command.
use super::{InputSpendContextV23, InputSpendEnvelopeV23, InputSpendProofErrorV23};
use serde::{Deserialize, Serialize};

/// Authentication domain is distinct from V2 signing and connection challenges.
pub const INPUT_PROOF_AUTH_DOMAIN_V23: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-INPUT-PROOF/V23\0";

/// `B` is the existing V2 authenticated build request, retaining its secret
/// redaction/drop behavior. No Debug/Clone is derived for this wrapper.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedInputProofRequestV23<B> {
    /// Must be 23, never inferred from a V2 request.
    pub api_version: u16,
    /// Prior request; the server must find its exact cached transaction.
    pub build: B,
    /// Exact canonical 249-byte public scope.
    pub context: Vec<u8>,
    /// Hint for scanning the funding output, not a confirmation proof.
    pub funding_height: u64,
    /// Negotiated public fee ceiling.
    pub max_fee: u64,
    /// HMAC under the separate V23 proof-only domain.
    pub auth_tag: [u8; 32],
}
impl<B> CachedInputProofRequestV23<B> {
    /// Decode the explicit profile and economic bounds; this grants nothing.
    pub fn decoded_context(&self) -> Result<InputSpendContextV23, InputSpendProofErrorV23> {
        if self.api_version != 23 || self.max_fee == 0 || self.funding_height == 0 {
            return Err(InputSpendProofErrorV23::Scope);
        }
        let context = InputSpendContextV23::decode(&self.context)?;
        if context.fee > self.max_fee {
            return Err(InputSpendProofErrorV23::Scope);
        }
        Ok(context)
    }
    /// Canonical authentication preimage. The caller MUST zeroize the returned
    /// buffer, since canonical V2 build bytes contain secret spend/view scalars.
    pub fn canonical_auth_bytes(
        &self,
        build_bytes: &[u8],
    ) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        self.decoded_context()?;
        if build_bytes.is_empty() || build_bytes.len() > 4096 {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"CACHED-INPUT-PROOF-V23\0");
        bytes.extend_from_slice(&self.api_version.to_le_bytes());
        bytes.extend_from_slice(&(build_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(build_bytes);
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.funding_height.to_le_bytes());
        bytes.extend_from_slice(&self.max_fee.to_le_bytes());
        Ok(bytes)
    }
}

/// Public proof-only response. It cannot be mistaken for a V2 signed sweep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CachedInputProofResponseV23 {
    /// Must be 23.
    pub api_version: u16,
    /// Identifies the original already durable V2 sweep request.
    pub request_nonce: [u8; 32],
    /// Public canonical XMRISP23 envelope, without a witness or grant.
    pub envelope: Vec<u8>,
}
impl CachedInputProofResponseV23 {
    /// Authenticate response/request identity and framing, not proof equations.
    pub fn decode_for(
        &self,
        nonce: [u8; 32],
        expected: &InputSpendContextV23,
    ) -> Result<InputSpendEnvelopeV23, InputSpendProofErrorV23> {
        if self.api_version != 23 || self.request_nonce != nonce || nonce == [0; 32] {
            return Err(InputSpendProofErrorV23::Scope);
        }
        let decoded = InputSpendEnvelopeV23::decode(&self.envelope)?;
        if &decoded.context != expected {
            return Err(InputSpendProofErrorV23::Scope);
        }
        Ok(decoded)
    }
}
