//! Cross-curve share routing for the consensus-bound DOM/XMR arbiter.
//!
//! The DOM owner contributes the refund share; the XMR owner contributes the
//! claim share. Claim and punish reveal the XMR owner's share, while refund
//! reveals the DOM owner's share. This module verifies the DLEQ bindings and
//! converts only an observed DOM adaptor opening into the matching XMR scalar.

use curve25519_dalek::{edwards::CompressedEdwardsY, traits::Identity};
use dom_consensus::SwapArbiterPath;
use dom_core::DomError;
use dom_crypto::PublicKey;
use xmr_dleq_sigma::{
    revealed_dom_secret_to_xmr_scalar, verify_bound, BoundCrossCurveProofV1, CrossCurvePublicClaim,
    ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use zeroize::{Zeroize, Zeroizing};

fn invalid(reason: &str) -> DomError {
    DomError::Invalid(reason.into())
}

/// Public, settlement-bound share relations for one direct DOM/XMR swap.
#[derive(Clone)]
pub struct VerifiedArbiterSharesV1 {
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    dom_owner_refund: CrossCurvePublicClaim,
    xmr_owner_claim: CrossCurvePublicClaim,
}

impl VerifiedArbiterSharesV1 {
    /// Verify distinct, role-bound DLEQ proofs before any funding.
    pub fn new(
        settlement_id: [u8; 32],
        context_hash: [u8; 32],
        dom_owner_refund: &BoundCrossCurveProofV1,
        xmr_owner_claim: &BoundCrossCurveProofV1,
    ) -> Result<Self, DomError> {
        if settlement_id == [0; 32] || context_hash == [0; 32] {
            return Err(invalid("invalid DOM/XMR arbiter share context"));
        }
        let dom_owner_refund = verify_bound(
            dom_owner_refund,
            &settlement_id,
            &context_hash,
            ROLE_XMR_REFUND_SHARE,
        )
        .map_err(|_| invalid("invalid DOM-owner refund share proof"))?;
        let xmr_owner_claim = verify_bound(
            xmr_owner_claim,
            &settlement_id,
            &context_hash,
            ROLE_XMR_SHARED_SPEND,
        )
        .map_err(|_| invalid("invalid XMR-owner claim share proof"))?;
        if dom_owner_refund == xmr_owner_claim {
            return Err(invalid("DOM/XMR arbiter shares must be distinct"));
        }
        let result = Self {
            settlement_id,
            context_hash,
            dom_owner_refund,
            xmr_owner_claim,
        };
        result.joint_xmr_spend_key()?;
        Ok(result)
    }

    /// One-shot swap identity used by both DLEQ envelopes.
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }

    /// Authenticated setup context used by both DLEQ envelopes.
    pub const fn context_hash(&self) -> &[u8; 32] {
        &self.context_hash
    }

    fn claim_for_path(&self, path: SwapArbiterPath) -> &CrossCurvePublicClaim {
        match path {
            SwapArbiterPath::Claim | SwapArbiterPath::Punish => &self.xmr_owner_claim,
            SwapArbiterPath::Refund => &self.dom_owner_refund,
        }
    }

    /// Required secp256k1 adaptor point for the selected DOM path.
    pub fn adaptor_point(&self, path: SwapArbiterPath) -> Result<PublicKey, DomError> {
        PublicKey::from_compressed_bytes(&self.claim_for_path(path).secp_compressed)
    }

    /// Verified joint Monero spend key committed by the two DLEQ proofs.
    pub fn joint_xmr_spend_key(&self) -> Result<[u8; 32], DomError> {
        let point = |claim: &CrossCurvePublicClaim| {
            CompressedEdwardsY(claim.ed_compressed)
                .decompress()
                .filter(|point| point.is_torsion_free())
                .ok_or_else(|| invalid("invalid verified XMR share point"))
        };
        let joint = point(&self.dom_owner_refund)? + point(&self.xmr_owner_claim)?;
        if joint == curve25519_dalek::EdwardsPoint::identity() {
            return Err(invalid("joint XMR spend key is identity"));
        }
        Ok(joint.compress().to_bytes())
    }

    /// Convert an extracted DOM adaptor opening into its exact XMR share.
    ///
    /// No modulo reduction is allowed. A scalar from the other path, another
    /// settlement, or another DLEQ claim is rejected.
    pub fn xmr_share_from_dom_opening(
        &self,
        path: SwapArbiterPath,
        mut dom_secret_big_endian: [u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, DomError> {
        let result =
            revealed_dom_secret_to_xmr_scalar(dom_secret_big_endian, self.claim_for_path(path))
                .map(Zeroizing::new)
                .map_err(|_| invalid("DOM adaptor opening does not match the selected XMR share"));
        dom_secret_big_endian.zeroize();
        result
    }
}
