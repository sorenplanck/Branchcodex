//! Dependency-minimal HMAC-SHA256, matching the DOM-side domain.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{BuildSweepRequestV2, VerifyFundingRequestV2};

const AUTH_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-AUTH/V2\0";
/// Distinct domain for the connection-opening challenge, matching the DOM
/// side: a challenge proof can never double as a request tag.
const CHALLENGE_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-CHALLENGE/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid authentication key")]
    InvalidKey,
    #[error("request authentication failed")]
    AuthenticationFailed,
    #[error("request encoding failed")]
    InvalidRequest,
}

pub struct AuthKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for AuthKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthKey(<redacted>)")
    }
}

impl AuthKey {
    pub fn new(bytes: [u8; 32]) -> Result<Self, AuthError> {
        if bytes == [0; 32] {
            return Err(AuthError::InvalidKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn verify_funding(&self, request: &VerifyFundingRequestV2) -> Result<(), AuthError> {
        let bytes = request
            .canonical_auth_bytes()
            .map_err(|_| AuthError::InvalidRequest)?;
        verify_tag(&self.0, &bytes, &request.auth_tag)
    }

    pub fn verify_build(&self, request: &BuildSweepRequestV2) -> Result<(), AuthError> {
        let bytes = request
            .canonical_auth_bytes()
            .map_err(|_| AuthError::InvalidRequest)?;
        verify_tag(&self.0, &bytes, &request.auth_tag)
    }

    pub fn verify_build_proof_v23(
        &self,
        request: &xmr_key_image_proof::BuildSweepRequestV23<BuildSweepRequestV2>,
    ) -> Result<(), AuthError> {
        let build = Zeroizing::new(
            request
                .build
                .canonical_auth_bytes()
                .map_err(|_| AuthError::InvalidRequest)?,
        );
        let bytes = Zeroizing::new(
            request
                .canonical_auth_bytes(&build)
                .map_err(|_| AuthError::InvalidRequest)?,
        );
        let actual = hmac_sha256(
            &self.0,
            xmr_key_image_proof::BUILD_PROOF_AUTH_DOMAIN_V23,
            &bytes,
        );
        let difference = actual
            .iter()
            .zip(request.auth_tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if difference != 0 {
            return Err(AuthError::AuthenticationFailed);
        }
        Ok(())
    }

    // Private cache key, never returned through a sidecar response or daemon API.
    pub(crate) fn build_plan_key_v23(&self, request_hash: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hmac_sha256(
            &self.0,
            b"DOM-INTEROP/XMR-PRIVATE-BUILD-PLAN/V23\0",
            request_hash,
        ))
    }

    pub fn verify_input_proof_v23(
        &self,
        request: &xmr_key_image_proof::CachedInputProofRequestV23<BuildSweepRequestV2>,
    ) -> Result<(), AuthError> {
        let build = Zeroizing::new(
            request
                .build
                .canonical_auth_bytes()
                .map_err(|_| AuthError::InvalidRequest)?,
        );
        let bytes = Zeroizing::new(
            request
                .canonical_auth_bytes(&build)
                .map_err(|_| AuthError::InvalidRequest)?,
        );
        let actual = hmac_sha256(
            &self.0,
            xmr_key_image_proof::INPUT_PROOF_AUTH_DOMAIN_V23,
            &bytes,
        );
        let difference = actual
            .iter()
            .zip(request.auth_tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if difference != 0 {
            return Err(AuthError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Proves possession of the shared key over one client challenge nonce,
    /// before the client will transmit any scalar-carrying request.
    pub fn challenge_proof(&self, nonce: &[u8; 32]) -> Result<[u8; 32], AuthError> {
        if nonce == &[0; 32] {
            return Err(AuthError::InvalidRequest);
        }
        Ok(hmac_sha256(&self.0, CHALLENGE_DOMAIN, nonce))
    }
}

fn verify_tag(key: &[u8; 32], message: &[u8], expected: &[u8; 32]) -> Result<(), AuthError> {
    let actual = hmac_sha256(key, AUTH_DOMAIN, message);
    let mut difference = 0_u8;
    for (left, right) in actual.iter().zip(expected.iter()) {
        difference |= left ^ right;
    }
    if difference == 0 {
        Ok(())
    } else {
        Err(AuthError::AuthenticationFailed)
    }
}

fn hmac_sha256(key: &[u8; 32], domain: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for index in 0..key.len() {
        ipad[index] ^= key[index];
        opad[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(domain);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}
