//! Local Refund construction, before any remote DSC1 request exists.
//!
//! These DTOs carry authenticated scope, not an economic grant. The caller must
//! obtain the native Store effect, public-U and funding authorities before
//! releasing a spend scalar. No remote-envelope digest can be manufactured here.
use super::{
    BuiltRingMemberV23, InputSpendActionV23, InputSpendContextV23, InputSpendProofErrorV23,
    InputSpendProofV23, TxKeyDerivationProofV23,
};
use serde::{Deserialize, Serialize};

/// Local construction cannot authenticate an accepted-remote V23 request.
pub const LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24: &[u8] =
    b"DOM-INTEROP/XMR-SIDECAR-LOCAL-REFUND-BUILD/V24\0";
/// A read-only request must never be replayable as permission to construct.
pub const LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24: &[u8] =
    b"DOM-INTEROP/XMR-SIDECAR-LOCAL-REFUND-LOAD/V24\0";

/// Real local Store effect plus already-public DOM U, with no future tx fields.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRefundBuildRequestV24<B> {
    /// Must be 24; the embedded sweep DTO remains V2.
    pub api_version: u16,
    /// Private construction inputs, released only by the native owner.
    pub build: B,
    /// Selected Monero genesis, independently rechecked by the builder.
    pub network_genesis: [u8; 32],
    /// Exact composed route identity.
    pub route: [u8; 32],
    /// Native session identity (not a manufactured DSC1 request).
    pub session: [u8; 32],
    /// Native settlement terms, not the route-wide terms digest.
    pub terms: [u8; 32],
    /// Original, durably retained local Refund effect.
    pub effect_id: [u8; 32],
    /// Epoch bound by that original effect, never refreshed for readback.
    pub fencing_epoch: u64,
    /// Exact local child materialization semantics.
    pub semantic_digest: [u8; 32],
    /// Native caller's complete local-authority binding; HMAC is not F7.
    pub local_authorization_digest: [u8; 32],
    /// DOM transaction from which canonical final public U was observed.
    pub dom_refund_tx_hash: [u8; 32],
    /// Admitted native recovery graph.
    pub graph_digest: [u8; 32],
    /// Exact funding output position, including valid position zero.
    pub output_index: u64,
    /// Inclusion hint; the native builder scans this exact block/output.
    pub funding_height: u64,
    /// Negotiated fee ceiling, checked before signing.
    pub max_fee: u64,
    /// Dedicated Build HMAC; never accepted by the public Load endpoint.
    pub auth_tag: [u8; 32],
}

impl<B> LocalRefundBuildRequestV24<B> {
    /// Framing only. HMAC and these identifiers do not establish F7 or finality.
    pub fn validate_scope(&self) -> Result<InputSpendActionV23, InputSpendProofErrorV23> {
        if self.api_version != 24
            || [
                self.network_genesis,
                self.route,
                self.session,
                self.terms,
                self.effect_id,
                self.semantic_digest,
                self.local_authorization_digest,
                self.dom_refund_tx_hash,
                self.graph_digest,
            ]
            .contains(&[0; 32])
            || self.fencing_epoch == 0
            || self.funding_height == 0
            || self.max_fee == 0
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        Ok(InputSpendActionV23::Refund)
    }

    /// Contains private V2 fields; the caller must zeroize this preimage.
    pub fn canonical_auth_bytes(
        &self,
        build_bytes: &[u8],
    ) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        self.validate_scope()?;
        if build_bytes.is_empty() || build_bytes.len() > 4096 {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        let mut out = b"LOCAL-REFUND-BUILD-WITH-PROOFS-V24\0".to_vec();
        out.extend_from_slice(&(build_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(build_bytes);
        for digest in [
            self.network_genesis,
            self.route,
            self.session,
            self.terms,
            self.effect_id,
            self.semantic_digest,
            self.local_authorization_digest,
            self.dom_refund_tx_hash,
            self.graph_digest,
        ] {
            out.extend_from_slice(&digest);
        }
        for value in [
            self.fencing_epoch,
            self.output_index,
            self.funding_height,
            self.max_fee,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.push(InputSpendActionV23::Refund as u8);
        Ok(out)
    }
}

/// Local artifacts; cannot be deserialized as an accepted-remote V23 result.
/// Proofs bind the exact economic context, so a later authenticated request can
/// consume these same bytes without generating another signature or tx key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRefundBuildResponseV24<S> {
    /// Must be 24.
    pub api_version: u16,
    /// Authenticated identity of the original private build cache, not a key.
    pub cache_request_hash: [u8; 32],
    /// Original authenticated artifact descriptors, not fresh funding authority.
    pub public_scope: LocalRefundReadyScopeV24,
    /// Exact local origin echoed from the authenticated request.
    pub local_authorization_digest: [u8; 32],
    /// Original local effect, not a later remote DSC1 digest.
    pub effect_id: [u8; 32],
    /// Original effect fencing epoch.
    pub fencing_epoch: u64,
    /// Original effect semantics.
    pub semantic_digest: [u8; 32],
    /// Canonical public-U transaction bound by the caller.
    pub dom_refund_tx_hash: [u8; 32],
    /// Exact recovery graph bound by the caller.
    pub graph_digest: [u8; 32],
    /// Actual signed bytes and transaction hash; never a private tx key.
    pub sweep: S,
    /// Canonical V23 proof context, with action fixed to Refund.
    pub context: Vec<u8>,
    /// Public input/key-image proof (96 bytes).
    pub input_proof: Vec<u8>,
    /// Public destination derivation proofs; no private outgoing key or r.
    pub tx_key_proofs: Vec<Vec<u8>>,
    /// Ring claims requiring independent chain-quorum verification.
    pub ring_members: Vec<BuiltRingMemberV23>,
}

impl<S> LocalRefundBuildResponseV24<S> {
    /// Structural checks only; raw transactions, rings and payouts still verify.
    pub fn validate_framing(&self) -> Result<InputSpendContextV23, InputSpendProofErrorV23> {
        if self.api_version != 24
            || self.cache_request_hash == [0; 32]
            || self.fencing_epoch == 0
            || [
                self.local_authorization_digest,
                self.effect_id,
                self.semantic_digest,
                self.dom_refund_tx_hash,
                self.graph_digest,
            ]
            .contains(&[0; 32])
            || self.ring_members.len() != 16
            || self.tx_key_proofs.is_empty()
            || self.tx_key_proofs.len() > 17
        {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        InputSpendProofV23::decode(&self.input_proof)?;
        for proof in &self.tx_key_proofs {
            TxKeyDerivationProofV23::decode(proof)?;
        }
        let context = InputSpendContextV23::decode(&self.context)?;
        self.public_scope.canonical_bytes()?;
        let r = &self.public_scope.request;
        if context.action != InputSpendActionV23::Refund
            || self.public_scope.local_authorization_digest != self.local_authorization_digest
            || r.effect_id != self.effect_id
            || r.fencing_epoch != self.fencing_epoch
            || r.semantic_digest != self.semantic_digest
            || r.dom_refund_tx_hash != self.dom_refund_tx_hash
            || r.graph_digest != self.graph_digest
            || context.output_index != self.public_scope.output_index
            || context.network_genesis != r.network_genesis
            || context.route != r.route
            || context.session != r.session
            || context.terms != r.terms
            || context.funding_tx != r.funding_tx_hash
            || context.funded_amount != r.funded_amount
            || context.destination != super::destination_digest_v23(&r.destination)
            || context.fee > r.max_fee
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        Ok(context)
    }
}

/// Entirely public readback of an original local effect. Lookup obtains the
/// original cache hash from an authenticated Ready record, not a reopened key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRefundLoadRequestV24 {
    /// Must be 24.
    pub api_version: u16,
    /// The original build nonce; it is not refreshed after a daemon restart.
    pub request_nonce: [u8; 32],
    pub network_genesis: [u8; 32],
    pub route: [u8; 32],
    pub session: [u8; 32],
    pub terms: [u8; 32],
    pub effect_id: [u8; 32],
    pub fencing_epoch: u64,
    pub semantic_digest: [u8; 32],
    pub dom_refund_tx_hash: [u8; 32],
    pub graph_digest: [u8; 32],
    pub settlement_id: [u8; 32],
    pub funding_tx_hash: [u8; 32],
    pub funded_amount: u64,
    pub destination: String,
    pub expected_spend_public_key: [u8; 32],
    pub max_fee: u64,
    /// Public-request HMAC in the Load-only domain.
    pub auth_tag: [u8; 32],
}

impl LocalRefundLoadRequestV24 {
    /// Framing only; the caller still verifies native effects/U/funding.
    pub fn validate_scope(&self) -> Result<(), InputSpendProofErrorV23> {
        if self.api_version != 24
            || self.request_nonce != self.effect_id
            || self.fencing_epoch == 0
            || self.funded_amount == 0
            || self.max_fee == 0
            || self.destination.is_empty()
            || self.destination.len() > 256
            || [
                self.request_nonce,
                self.network_genesis,
                self.route,
                self.session,
                self.terms,
                self.effect_id,
                self.semantic_digest,
                self.dom_refund_tx_hash,
                self.graph_digest,
                self.settlement_id,
                self.funding_tx_hash,
                self.expected_spend_public_key,
            ]
            .contains(&[0; 32])
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        Ok(())
    }

    /// Public, unambiguous origin/economic scope, excluding the tag itself.
    pub fn canonical_auth_bytes(&self) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        self.validate_scope()?;
        let mut bytes = b"LOCAL-REFUND-PUBLIC-LOAD-V24\0".to_vec();
        for digest in [
            self.request_nonce,
            self.network_genesis,
            self.route,
            self.session,
            self.terms,
            self.effect_id,
            self.semantic_digest,
            self.dom_refund_tx_hash,
            self.graph_digest,
            self.settlement_id,
            self.funding_tx_hash,
            self.expected_spend_public_key,
        ] {
            bytes.extend_from_slice(&digest);
        }
        for value in [self.fencing_epoch, self.funded_amount, self.max_fee] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.destination.len() as u16).to_le_bytes());
        bytes.extend_from_slice(self.destination.as_bytes());
        bytes.push(InputSpendActionV23::Refund as u8);
        Ok(bytes)
    }
}

/// Complete original public construction scope retained with its proof bytes.
/// Inclusion descriptors only: reading this must never mint a fresh F7 grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRefundReadyScopeV24 {
    /// All static lookup pins; no private scalars and no stored request HMAC.
    pub request: LocalRefundLoadRequestV24,
    /// Native caller's original binding, recomputed independently on readback.
    pub local_authorization_digest: [u8; 32],
    /// Original exact funding output index (zero is valid).
    pub output_index: u64,
    /// Original inclusion height, not a claim of current canonical finality.
    pub funding_height: u64,
}

impl LocalRefundReadyScopeV24 {
    /// Complete public cache scope; the Ready MAC binds these bytes and payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        if self.local_authorization_digest == [0; 32]
            || self.funding_height == 0
            || self.request.auth_tag != [0; 32]
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        let request = self.request.canonical_auth_bytes()?;
        let mut bytes = b"LOCAL-REFUND-READY-SCOPE-V24\0".to_vec();
        bytes.extend_from_slice(&(request.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(&self.local_authorization_digest);
        bytes.extend_from_slice(&self.output_index.to_le_bytes());
        bytes.extend_from_slice(&self.funding_height.to_le_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_request() -> LocalRefundLoadRequestV24 {
        LocalRefundLoadRequestV24 {
            api_version: 24,
            request_nonce: [5; 32],
            network_genesis: [1; 32],
            route: [2; 32],
            session: [3; 32],
            terms: [4; 32],
            effect_id: [5; 32],
            fencing_epoch: 1,
            semantic_digest: [6; 32],
            dom_refund_tx_hash: [7; 32],
            graph_digest: [8; 32],
            settlement_id: [9; 32],
            funding_tx_hash: [10; 32],
            funded_amount: 1000,
            destination: "public-scope-test-only".into(),
            expected_spend_public_key: [11; 32],
            max_fee: 10,
            auth_tag: [0; 32],
        }
    }

    #[test]
    fn public_load_binds_every_static_pin_and_refuses_a_refreshed_nonce() {
        let expected = public_request().canonical_auth_bytes().unwrap();
        for field in 0..15 {
            let mut r = public_request();
            match field {
                0 => r.network_genesis[0] ^= 1,
                1 => r.route[0] ^= 1,
                2 => r.session[0] ^= 1,
                3 => r.terms[0] ^= 1,
                4 => {
                    r.effect_id[0] ^= 1;
                    r.request_nonce = r.effect_id;
                }
                5 => r.fencing_epoch += 1,
                6 => r.semantic_digest[0] ^= 1,
                7 => r.dom_refund_tx_hash[0] ^= 1,
                8 => r.graph_digest[0] ^= 1,
                9 => r.settlement_id[0] ^= 1,
                10 => r.funding_tx_hash[0] ^= 1,
                11 => r.funded_amount += 1,
                12 => r.destination.push('x'),
                13 => r.expected_spend_public_key[0] ^= 1,
                14 => r.max_fee += 1,
                _ => unreachable!(),
            }
            assert_ne!(expected, r.canonical_auth_bytes().unwrap(), "{field}");
        }
        let mut r = public_request();
        r.request_nonce[0] ^= 1;
        assert!(r.canonical_auth_bytes().is_err());
        let mut r = public_request();
        r.auth_tag = [99; 32];
        assert_eq!(expected, r.canonical_auth_bytes().unwrap());
    }

    #[test]
    fn ready_scope_authenticates_original_descriptors_without_calling_them_a_grant() {
        let original = LocalRefundReadyScopeV24 {
            request: public_request(),
            local_authorization_digest: [12; 32],
            output_index: 0,
            funding_height: 100,
        };
        let expected = original.canonical_bytes().unwrap();
        for field in 0..3 {
            let mut changed = original.clone();
            match field {
                0 => changed.local_authorization_digest[0] ^= 1,
                1 => changed.output_index += 1,
                2 => changed.funding_height += 1,
                _ => unreachable!(),
            }
            assert_ne!(expected, changed.canonical_bytes().unwrap());
        }
        let mut tagged = original;
        tagged.request.auth_tag = [99; 32];
        assert!(
            tagged.canonical_bytes().is_err(),
            "Ready never stores a request tag"
        );
    }

    fn request() -> LocalRefundBuildRequestV24<()> {
        LocalRefundBuildRequestV24 {
            api_version: 24,
            build: (),
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

    #[test]
    fn every_local_effect_or_economic_field_changes_the_auth_preimage() {
        let expected = request()
            .canonical_auth_bytes(b"synthetic-private-build")
            .unwrap();
        for field in 0..13 {
            let mut r = request();
            match field {
                0 => r.network_genesis[0] ^= 1,
                1 => r.route[0] ^= 1,
                2 => r.session[0] ^= 1,
                3 => r.terms[0] ^= 1,
                4 => r.effect_id[0] ^= 1,
                5 => r.semantic_digest[0] ^= 1,
                6 => r.local_authorization_digest[0] ^= 1,
                7 => r.dom_refund_tx_hash[0] ^= 1,
                8 => r.graph_digest[0] ^= 1,
                9 => r.fencing_epoch += 1,
                10 => r.output_index += 1,
                11 => r.funding_height += 1,
                12 => r.max_fee += 1,
                _ => unreachable!(),
            }
            assert_ne!(
                expected,
                r.canonical_auth_bytes(b"synthetic-private-build").unwrap()
            );
        }
        assert_ne!(
            expected,
            request()
                .canonical_auth_bytes(b"different-private-build")
                .unwrap()
        );
        assert_eq!(
            request().validate_scope().unwrap(),
            InputSpendActionV23::Refund
        );
    }

    #[test]
    fn local_scope_cannot_encode_missing_effect_or_a_remote_version() {
        for field in 0..13 {
            let mut r = request();
            match field {
                0 => r.api_version = 23,
                1 => r.network_genesis = [0; 32],
                2 => r.route = [0; 32],
                3 => r.session = [0; 32],
                4 => r.terms = [0; 32],
                5 => r.effect_id = [0; 32],
                6 => r.fencing_epoch = 0,
                7 => r.semantic_digest = [0; 32],
                8 => r.local_authorization_digest = [0; 32],
                9 => r.dom_refund_tx_hash = [0; 32],
                10 => r.graph_digest = [0; 32],
                11 => r.funding_height = 0,
                12 => r.max_fee = 0,
                _ => unreachable!(),
            }
            assert!(r.canonical_auth_bytes(b"build").is_err());
        }
        assert!(request().canonical_auth_bytes(&[]).is_err());
        assert!(request().canonical_auth_bytes(&vec![0; 4097]).is_err());
        assert_ne!(
            LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24,
            super::super::BUILD_PROOF_AUTH_DOMAIN_V23
        );
        assert_ne!(
            LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24,
            LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24
        );
    }
}
