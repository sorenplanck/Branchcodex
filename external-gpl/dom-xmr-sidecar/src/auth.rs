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

    pub fn verify_local_refund_build_v24(
        &self,
        request: &xmr_key_image_proof::LocalRefundBuildRequestV24<BuildSweepRequestV2>,
    ) -> Result<(), AuthError> {
        self.verify_local_refund_in_domain_v24(
            request,
            xmr_key_image_proof::LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24,
        )
    }

    pub fn verify_local_refund_load_v24(
        &self,
        request: &xmr_key_image_proof::LocalRefundLoadRequestV24,
    ) -> Result<(), AuthError> {
        let bytes = request
            .canonical_auth_bytes()
            .map_err(|_| AuthError::InvalidRequest)?;
        let actual = hmac_sha256(
            &self.0,
            xmr_key_image_proof::LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24,
            &bytes,
        );
        if actual
            .iter()
            .zip(request.auth_tag)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            != 0
        {
            return Err(AuthError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Authenticates public Ready bytes after private-key retirement. This tag
    /// is not a request tag, and covers the complete result plus original scope.
    pub(crate) fn local_refund_ready_tag_v24(
        &self,
        hash: &[u8; 32],
        scope: &[u8],
        response: &[u8],
    ) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(48 + scope.len() + response.len());
        bytes.extend_from_slice(hash);
        bytes.extend_from_slice(&(scope.len() as u64).to_le_bytes());
        bytes.extend_from_slice(scope);
        bytes.extend_from_slice(&(response.len() as u64).to_le_bytes());
        bytes.extend_from_slice(response);
        hmac_sha256(&self.0, b"DOM-INTEROP/XMR-LOCAL-REFUND-READY/V24\0", &bytes)
    }

    fn verify_local_refund_in_domain_v24(
        &self,
        request: &xmr_key_image_proof::LocalRefundBuildRequestV24<BuildSweepRequestV2>,
        domain: &[u8],
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
        let actual = hmac_sha256(&self.0, domain, &bytes);
        let difference = actual
            .iter()
            .zip(request.auth_tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if difference != 0 {
            return Err(AuthError::AuthenticationFailed);
        }
        Ok(())
    }

    pub(crate) fn local_refund_plan_key_v24(&self, request_hash: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hmac_sha256(
            &self.0,
            b"DOM-INTEROP/XMR-PRIVATE-LOCAL-REFUND-PLAN/V24\0",
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

#[cfg(test)]
mod local_refund_tests_v24 {
    use super::*;
    use xmr_key_image_proof::{BuildSweepRequestV23, LocalRefundBuildRequestV24};

    fn request() -> LocalRefundBuildRequestV24<BuildSweepRequestV2> {
        let build = serde_json::from_value(serde_json::json!({
            "api_version":2,"request_nonce":([5;32]),"settlement_id":([2;32]),
            "funding_tx_hash":([3;32]),"expected_amount_piconero":1000,
            "destination":"synthetic-auth-only-destination","spend_scalar":([4;32]),
            "expected_spend_public_key":([5;32]),"view_scalar":([6;32]),"auth_tag":([0;32])
        }))
        .unwrap();
        LocalRefundBuildRequestV24 {
            api_version: 24,
            build,
            network_genesis: [1; 32],
            route: [2; 32],
            session: [3; 32],
            terms: [4; 32],
            effect_id: [5; 32],
            fencing_epoch: 1,
            semantic_digest: [6; 32],
            local_authorization_digest: [7; 32],
            dom_refund_tx_hash: [8; 32],
            graph_digest: [9; 32],
            output_index: 0,
            funding_height: 10,
            max_fee: 11,
            auth_tag: [0; 32],
        }
    }

    fn public_request(
        r: &LocalRefundBuildRequestV24<BuildSweepRequestV2>,
    ) -> xmr_key_image_proof::LocalRefundLoadRequestV24 {
        xmr_key_image_proof::LocalRefundLoadRequestV24 {
            api_version: 24,
            request_nonce: r.build.request_nonce,
            network_genesis: r.network_genesis,
            route: r.route,
            session: r.session,
            terms: r.terms,
            effect_id: r.effect_id,
            fencing_epoch: r.fencing_epoch,
            semantic_digest: r.semantic_digest,
            dom_refund_tx_hash: r.dom_refund_tx_hash,
            graph_digest: r.graph_digest,
            settlement_id: r.build.settlement_id,
            funding_tx_hash: r.build.funding_tx_hash,
            funded_amount: r.build.expected_amount_piconero,
            destination: r.build.destination.clone(),
            expected_spend_public_key: r.build.expected_spend_public_key,
            max_fee: r.max_fee,
            auth_tag: [0; 32],
        }
    }

    #[test]
    fn local_tags_cache_keys_and_wire_origins_are_domain_separated() {
        let key = AuthKey::new([7; 32]).unwrap();
        let mut r = request();
        let build = Zeroizing::new(r.build.canonical_auth_bytes().unwrap());
        let bytes = Zeroizing::new(r.canonical_auth_bytes(&build).unwrap());
        r.auth_tag = hmac_sha256(
            &key.0,
            xmr_key_image_proof::LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24,
            &bytes,
        );
        assert!(key.verify_local_refund_build_v24(&r).is_ok());
        let mut public = public_request(&r);
        public.auth_tag = r.auth_tag;
        assert!(key.verify_local_refund_load_v24(&public).is_err());
        let value = serde_json::to_value(&r).unwrap();
        assert!(
            serde_json::from_value::<BuildSweepRequestV23<BuildSweepRequestV2>>(value.clone())
                .is_err()
        );
        let mut invented = value;
        invented["request_message_digest"] = serde_json::to_value([99; 32]).unwrap();
        assert!(
            serde_json::from_value::<LocalRefundBuildRequestV24<BuildSweepRequestV2>>(invented)
                .is_err()
        );
        let public_bytes = public.canonical_auth_bytes().unwrap();
        public.auth_tag = hmac_sha256(
            &key.0,
            xmr_key_image_proof::LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24,
            &public_bytes,
        );
        assert!(key.verify_local_refund_load_v24(&public).is_ok());
        r.auth_tag = public.auth_tag;
        assert!(key.verify_local_refund_build_v24(&r).is_err());
        public.semantic_digest[0] ^= 1;
        assert!(key.verify_local_refund_load_v24(&public).is_err());
        let public_value = serde_json::to_value(&public).unwrap();
        assert!(public_value.get("build").is_none());
        assert!(public_value.get("spend_scalar").is_none());
        assert!(public_value.get("view_scalar").is_none());
        assert!(
            serde_json::from_value::<LocalRefundBuildRequestV24<BuildSweepRequestV2>>(
                public_value.clone()
            )
            .is_err()
        );
        let mut injected = public_value;
        injected["spend_scalar"] = serde_json::to_value([4; 32]).unwrap();
        assert!(
            serde_json::from_value::<xmr_key_image_proof::LocalRefundLoadRequestV24>(injected)
                .is_err()
        );
        assert_ne!(
            *key.build_plan_key_v23(&[2; 32]),
            *key.local_refund_plan_key_v24(&[2; 32])
        );
        assert_ne!(
            *key.local_refund_plan_key_v24(&[2; 32]),
            *key.local_refund_plan_key_v24(&[3; 32])
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_read_of_incomplete_plan_cannot_enter_the_signing_builder() {
        use monero_oxide_wallet::address::{AddressType, MoneroAddress, Network};
        let directory = tempfile::tempdir().unwrap();
        let key = AuthKey::new([7; 32]).unwrap();
        let mut r = request();
        let spend = crate::parse_scalar([4; 32]).unwrap();
        let view = crate::parse_scalar([6; 32]).unwrap();
        r.build.destination = MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            monero_wallet_ng::util::public_key(&spend),
            monero_wallet_ng::util::public_key(&view),
        )
        .to_string();
        r.network_genesis = [
            0x41, 0x80, 0x15, 0xbb, 0x9a, 0xe9, 0x82, 0xa1, 0x97, 0x5d, 0xa7, 0xd7, 0x92, 0x77,
            0xc2, 0x70, 0x57, 0x27, 0xa5, 0x68, 0x94, 0xba, 0x0f, 0xb2, 0x46, 0xad, 0xaa, 0xbb,
            0x1f, 0x46, 0x32, 0xe3,
        ];
        let private = Zeroizing::new(r.build.canonical_auth_bytes().unwrap());
        let canonical = Zeroizing::new(r.canonical_auth_bytes(&private).unwrap());
        let mut public = public_request(&r);
        // The old private request is dropped before readback: there is no
        // scalar or view key left in the request, even with a missing result.
        let request_nonce = r.build.request_nonce;
        drop(r);
        let public_bytes = public.canonical_auth_bytes().unwrap();
        public.auth_tag = hmac_sha256(
            &key.0,
            xmr_key_image_proof::LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24,
            &public_bytes,
        );
        let config = crate::Config {
            listen: "127.0.0.1:1".parse().unwrap(),
            uds_path: directory.path().join("unused.sock"),
            monerod_url: "http://127.0.0.1:1".into(),
            cache: crate::SweepCache::open(directory.path()).unwrap(),
            auth: std::sync::Arc::new(key),
        };
        let request_hash = crate::SweepCache::request_hash(&canonical);
        drop(
            config
                .cache
                .begin_local_refund_build_v24(request_nonce, request_hash)
                .unwrap(),
        );
        let result = crate::build_proof_v23::load_local_refund(&config, &public).await;
        assert!(matches!(
            result,
            Err(crate::SidecarOperationError::Retryable)
        ));
        let retained = config.cache.lookup_local_refund_v24(request_nonce).unwrap();
        assert!(
            retained
                .load_public_local_ready_v24(&public_bytes, &config.auth)
                .unwrap()
                .is_none()
        );
        assert!(
            retained
                .load_plan(&config.auth.local_refund_plan_key_v24(&request_hash))
                .unwrap()
                .is_none()
        );
    }
}
