//! Fresh V23 sweep construction, with explicit pre-transaction scope.
use super::{InputSpendActionV23, InputSpendContextV23, InputSpendProofErrorV23};
use serde::{Deserialize, Serialize};

/// Domain of a fresh-build request, separate from V2 and proof-only V23.
pub const BUILD_PROOF_AUTH_DOMAIN_V23: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-BUILD-PROOF/V23\0";

/// A real build request has no fabricated future transaction hash or fee.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSweepRequestV23<B> {
    /// Must be 23.
    pub api_version: u16,
    /// Existing secret-carrying V2 fields, authenticated again in the V23 domain.
    pub build: B,
    /// Required network identity.
    pub network_genesis: [u8; 32],
    /// Route identity.
    pub route: [u8; 32],
    /// Native signing/session identity, distinct from the nested settlement id.
    pub session: [u8; 32],
    /// Digest of the complete authenticated remote request/public-secret evidence.
    pub authorization_digest: [u8; 32],
    /// Digest of the exact authenticated DSC1 0x19 request envelope.
    pub request_message_digest: [u8; 32],
    /// Negotiated terms identity.
    pub terms: [u8; 32],
    /// Exact funding output position.
    pub output_index: u64,
    /// Funding inclusion hint; the builder rechecks the actual scanned output.
    pub funding_height: u64,
    /// Signed fee ceiling, checked before any signing.
    pub max_fee: u64,
    /// Closed wire discriminator: Claim=1 or Refund=2.
    pub action: u8,
    /// HMAC in the dedicated build-with-proof domain.
    pub auth_tag: [u8; 32],
}
impl<B> BuildSweepRequestV23<B> {
    /// Validate pre-transaction scope, never a signing grant by itself.
    pub fn validate_scope(&self) -> Result<InputSpendActionV23, InputSpendProofErrorV23> {
        if self.api_version != 23
            || self.network_genesis == [0; 32]
            || self.route == [0; 32]
            || self.session == [0; 32]
            || self.authorization_digest == [0; 32]
            || self.request_message_digest == [0; 32]
            || self.terms == [0; 32]
            || self.funding_height == 0
            || self.max_fee == 0
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        InputSpendActionV23::from_wire(self.action)
    }
    /// Preimage contains private V2 fields: callers must zeroize it after use.
    pub fn canonical_auth_bytes(
        &self,
        build_bytes: &[u8],
    ) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        self.validate_scope()?;
        if build_bytes.is_empty() || build_bytes.len() > 4096 {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        let mut out = b"BUILD-SWEEP-WITH-PROOFS-V23\0".to_vec();
        out.extend_from_slice(&(build_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(build_bytes);
        out.extend_from_slice(&self.network_genesis);
        out.extend_from_slice(&self.route);
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.request_message_digest);
        out.extend_from_slice(&self.terms);
        out.extend_from_slice(&self.output_index.to_le_bytes());
        out.extend_from_slice(&self.funding_height.to_le_bytes());
        out.extend_from_slice(&self.max_fee.to_le_bytes());
        out.push(self.action);
        Ok(out)
    }
}

/// Ring claims emitted by the builder; requester independently resolves them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltRingMemberV23 {
    /// Absolute output index, not trusted chain membership.
    pub global_index: u64,
    /// Output key used in the actual signature.
    pub key: [u8; 32],
    /// Commitment used in the actual signature.
    pub commitment: [u8; 32],
}

/// Exact signed bytes and their public proofs, published atomically in cache.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSweepResponseV23<S> {
    /// Must be 23; nested sweep preserves the existing V2 raw-byte DTO.
    pub api_version: u16,
    /// Exact authority/event digest authenticated before construction.
    pub authorization_digest: [u8; 32],
    /// Digest of the exact authenticated DSC1 0x19 request envelope.
    pub request_message_digest: [u8; 32],
    /// Exact signed sweep response.
    pub sweep: S,
    /// Canonical post-construction scope; no zero future fields.
    pub context: Vec<u8>,
    /// CP input proof, exactly 96 bytes.
    pub input_proof: Vec<u8>,
    /// Standard-address transaction-key derivation proofs, 160 bytes each.
    pub tx_key_proofs: Vec<Vec<u8>>,
    /// Exact selected ring claims; independently authenticate using chain RPC.
    pub ring_members: Vec<BuiltRingMemberV23>,
}
impl<S> BuildSweepResponseV23<S> {
    /// Strict public framing only; raw/cryptographic/economic verification remains mandatory.
    pub fn validate_framing(&self) -> Result<InputSpendContextV23, InputSpendProofErrorV23> {
        if self.api_version != 23
            || self.authorization_digest == [0; 32]
            || self.request_message_digest == [0; 32]
            || self.ring_members.len() != 16
            || self.tx_key_proofs.is_empty()
            || self.tx_key_proofs.len() > 17
        {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        super::InputSpendProofV23::decode(&self.input_proof)?;
        for proof in &self.tx_key_proofs {
            super::TxKeyDerivationProofV23::decode(proof)?;
        }
        InputSpendContextV23::decode(&self.context)
    }
}
