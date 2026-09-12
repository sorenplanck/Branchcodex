//! Knowledge proofs for all five local kernel excesses, not signing permits.
use crate::compensation::XmrCompensationPolicyErrorV11 as Error;
use dom_adaptor::{
    verify_share_knowledge_v1, DirectionV1, SharePoPStatementV1, ShareProofV1, TrustedChainIdV1,
};
use dom_crypto::PublicKey;

/// Authenticated public scope supplied by the owner or peer-offer verifier.
/// The commitment must be recomputed from the complete public contribution,
/// never accepted as a substitute for validating its economic equations.
pub struct XmrGraphKeyProofScopeV22<'a> {
    /// Locally authenticated chain.
    pub chain: &'a TrustedChainIdV1,
    /// Parent session, including for the two auxiliary recovery shares.
    pub session_id: [u8; 32],
    /// Full authenticated roster in canonical order.
    pub roster: &'a [[u8; 32]],
    /// Authenticated participant direction.
    pub direction: DirectionV1,
    /// Authenticated participant position.
    pub participant_index: u16,
    /// Frozen settlement terms.
    pub terms_hash: [u8; 32],
    /// Digest of all local keys, offsets and funding contribution.
    pub public_commitment: [u8; 32],
    /// Funding/claim/cancel/refund/compensation public excesses, in this order.
    pub keys: &'a [PublicKey; 5],
}

impl XmrGraphKeyProofScopeV22<'_> {
    /// Five native proofs, with no untrusted count or variable-sized vector.
    pub const ENCODED_LEN: usize = 5 * ShareProofV1::ENCODED_LEN;

    /// Exact stage-separated statement. Reordering equal keys also changes
    /// the challenge: the stage is bound independently of the share point.
    pub fn statement(&self, stage: usize) -> Result<SharePoPStatementV1, Error> {
        let key = self.keys.get(stage).ok_or(Error::GraphMismatch)?;
        if self.public_commitment == [0; 32] {
            return Err(Error::GraphMismatch);
        }
        let mut binding = b"DOM:XMR:graph-key-knowledge:v22\0".to_vec();
        binding.extend_from_slice(&self.public_commitment);
        binding.push(stage as u8);
        SharePoPStatementV1::new(
            self.chain,
            self.session_id,
            self.roster,
            self.direction,
            self.participant_index,
            key.clone(),
            self.terms_hash,
            *dom_crypto::blake2b_256(&binding).as_bytes(),
        )
        .map_err(|_| Error::GraphMismatch)
    }

    /// Verify all five proofs against reconstructed authenticated statements.
    /// Success proves knowledge, not peer identity, balance or funding safety.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(Error::NonCanonical);
        }
        for (stage, bytes) in bytes.chunks_exact(ShareProofV1::ENCODED_LEN).enumerate() {
            let proof = ShareProofV1::from_bytes(bytes).map_err(|_| Error::GraphMismatch)?;
            if !verify_share_knowledge_v1(&self.statement(stage)?, &proof)
                .map_err(|_| Error::GraphMismatch)?
            {
                return Err(Error::GraphMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_proofs_refuse_stage_digest_and_roster_substitution(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x000d_0012,
            &dom_core::Hash256::from_bytes([81; 32]),
        );
        // Equal keys deliberately test stage separation independent of keys.
        let share = dom_adaptor::SigningShareV1::from_be_bytes([82; 32])?;
        let keys = std::array::from_fn(|_| share.public_key().clone());
        let roster = [[5; 32], [6; 32]];
        let mut scope = XmrGraphKeyProofScopeV22 {
            chain: &chain,
            session_id: [83; 32],
            roster: &roster,
            direction: DirectionV1::Responder,
            participant_index: 1,
            terms_hash: [84; 32],
            public_commitment: [85; 32],
            keys: &keys,
        };
        let mut bytes = Vec::new();
        for stage in 0..5 {
            bytes.extend_from_slice(
                &dom_adaptor::prove_share_knowledge_v1(&scope.statement(stage)?, &share)?
                    .to_bytes(),
            );
        }
        scope.verify(&bytes)?;
        assert!(scope.statement(5).is_err());
        let size = ShareProofV1::ENCODED_LEN;
        let mut reordered = bytes.clone();
        reordered[..size].copy_from_slice(&bytes[size..2 * size]);
        reordered[size..2 * size].copy_from_slice(&bytes[..size]);
        assert!(scope.verify(&reordered).is_err());
        assert!(scope.verify(&bytes[..bytes.len() - 1]).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(scope.verify(&extended).is_err());
        scope.public_commitment[0] ^= 1;
        assert!(scope.verify(&bytes).is_err());
        scope.public_commitment[0] ^= 1;
        let foreign = [[4; 32], [6; 32]];
        scope.roster = &foreign;
        assert!(scope.verify(&bytes).is_err());
        scope.roster = &roster;
        scope.verify(&bytes)?;
        Ok(())
    }
}
