//! Public proof of possession for each wallet-composed bootstrap kernel key.
//! This is construction evidence, not a nonce or transaction authorization.
use crate::{
    verify_share_knowledge_v1, AdaptorError, DirectionV1, DomBootstrapOfferV17, PurposeV1, Result,
    SharePoPStatementV1, ShareProofV1, TrustedChainIdV1,
};
use dom_crypto::blake2b_256_tagged;

/// Exact public offer plus independently domain-bound knowledge proofs for
/// its funding, claim and refund keys. Contains no private scalar.
#[derive(Clone, Debug)]
pub struct DomBootstrapProvenOfferV18 {
    offer: DomBootstrapOfferV17,
    proofs: [ShareProofV1; 3],
}

impl DomBootstrapProvenOfferV18 {
    /// Canonical maximum, including the three native 65-byte proofs.
    pub const MAX_BYTES: usize =
        DomBootstrapOfferV17::MAX_BYTES + 12 + 3 * ShareProofV1::ENCODED_LEN;
    /// Assemble public evidence. `verify` must bind it to the trusted roster.
    pub fn new(offer: DomBootstrapOfferV17, proofs: [ShareProofV1; 3]) -> Result<Self> {
        offer.to_bytes()?;
        Ok(Self { offer, proofs })
    }
    /// Exact public construction contribution.
    pub const fn offer(&self) -> &DomBootstrapOfferV17 {
        &self.offer
    }
    /// Canonical public envelope. This does not authenticate peer identity.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let offer = self.offer.to_bytes()?;
        let mut bytes = b"DWPO18\0\x01".to_vec();
        bytes.extend_from_slice(&(offer.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&offer);
        for proof in &self.proofs {
            bytes.extend_from_slice(&proof.to_bytes());
        }
        Ok(bytes)
    }
    /// Decode bounded exact bytes; reject surplus bytes and malformed proofs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 + 195 || bytes.len() > Self::MAX_BYTES || bytes[..8] != *b"DWPO18\0\x01"
        {
            return Err(invalid());
        }
        let size = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        if size > DomBootstrapOfferV17::MAX_BYTES || size.checked_add(207) != Some(bytes.len()) {
            return Err(invalid());
        }
        let end = 12 + size;
        let value = Self::new(
            DomBootstrapOfferV17::from_bytes(&bytes[12..end])?,
            [
                ShareProofV1::from_bytes(&bytes[end..end + 65])?,
                ShareProofV1::from_bytes(&bytes[end + 65..end + 130])?,
                ShareProofV1::from_bytes(&bytes[end + 130..])?,
            ],
        )?;
        if value.to_bytes()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
    /// Reconstruct all statements from trusted identities and verify native
    /// knowledge proofs. Purpose and every public wallet byte are committed.
    pub fn verify(
        &self,
        chain: &TrustedChainIdV1,
        roster: &[[u8; 32]],
        direction: DirectionV1,
        index: u16,
    ) -> Result<()> {
        self.verify_against_frozen_chain_v18(chain.as_bytes(), roster, direction, index)
    }
    /// Mathematical revalidation against a chain already frozen by a native
    /// journal. This creates no trusted-chain or signing capability.
    pub fn verify_against_frozen_chain_v18(
        &self,
        chain: &[u8; 32],
        roster: &[[u8; 32]],
        direction: DirectionV1,
        index: u16,
    ) -> Result<()> {
        for (slot, purpose) in [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
        ]
        .into_iter()
        .enumerate()
        {
            if self.offer.chain_id != *chain
                || roster.get(usize::from(index)) != Some(&self.offer.participant_id)
            {
                return Err(invalid());
            }
            let mut bytes = Vec::with_capacity(SharePoPStatementV1::ENCODED_LEN);
            bytes.extend_from_slice(b"DSPO");
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(chain);
            bytes.extend_from_slice(&self.offer.session_id);
            bytes.extend_from_slice(&self.offer.participant_id);
            bytes.push(direction.to_byte());
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes.extend_from_slice(&self.offer.signing_keys[slot].to_compressed_bytes());
            bytes.extend_from_slice(&self.offer.terms_hash);
            bytes.extend_from_slice(&proof_context(&self.offer, purpose)?);
            let statement =
                SharePoPStatementV1::from_bytes_against_frozen_chain(&bytes, chain, roster)?;
            if !verify_share_knowledge_v1(&statement, &self.proofs[slot])? {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Construct a purpose-bound native proof statement for an exact public offer.
/// The context field is explicitly domain-separated from BP share proofs.
pub fn bootstrap_key_statement_v18(
    offer: &DomBootstrapOfferV17,
    chain: &TrustedChainIdV1,
    roster: &[[u8; 32]],
    direction: DirectionV1,
    index: u16,
    purpose: PurposeV1,
) -> Result<SharePoPStatementV1> {
    let slot = match purpose {
        PurposeV1::Funding => 0,
        PurposeV1::ClaimAdaptor => 1,
        PurposeV1::Refund => 2,
        _ => return Err(invalid()),
    };
    if offer.chain_id != *chain.as_bytes()
        || roster.get(usize::from(index)) != Some(&offer.participant_id)
    {
        return Err(invalid());
    }
    SharePoPStatementV1::new(
        chain,
        offer.session_id,
        roster,
        direction,
        index,
        offer.signing_keys[slot].clone(),
        offer.terms_hash,
        proof_context(offer, purpose)?,
    )
}
fn proof_context(offer: &DomBootstrapOfferV17, purpose: PurposeV1) -> Result<[u8; 32]> {
    let mut context = vec![purpose as u8];
    context.extend_from_slice(&offer.to_bytes()?);
    Ok(*blake2b_256_tagged("DOM:bootstrap-wallet-kernel-possession:v18", &context).as_bytes())
}
fn invalid() -> AdaptorError {
    AdaptorError::InvalidContext("bootstrap kernel possession scope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prove_share_knowledge_v1, SigningShareV1};
    use dom_consensus::TransactionOutput;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[31] = value;
        bytes
    }
    fn fixture() -> Result<(TrustedChainIdV1, [[u8; 32]; 2], DomBootstrapProvenOfferV18)> {
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let roster = [[0x21; 32], [0x42; 32]];
        let keys = [
            SigningShareV1::from_be_bytes(scalar(7))?,
            SigningShareV1::from_be_bytes(scalar(9))?,
            SigningShareV1::from_be_bytes(scalar(13))?,
        ];
        let blinding = BlindingFactor::from_bytes(scalar(17))?;
        let (proof, _) = dom_crypto::range_proof_prove_bytes(1000, &blinding)?;
        let offer = DomBootstrapOfferV17 {
            chain_id: *chain.as_bytes(),
            session_id: [0x31; 32],
            terms_hash: [0x51; 32],
            participant_id: roster[0],
            payout: TransactionOutput {
                commitment: Commitment::commit(1000, &blinding),
                proof,
            },
            funding_inputs: vec![],
            funding_change: None,
            funding_fee: 0,
            signing_keys: [
                keys[0].public_key().clone(),
                keys[1].public_key().clone(),
                keys[2].public_key().clone(),
            ],
            offsets: [scalar(19), scalar(23), scalar(29)],
        };
        let mut proofs = Vec::new();
        for (slot, purpose) in [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
        ]
        .into_iter()
        .enumerate()
        {
            let statement = bootstrap_key_statement_v18(
                &offer,
                &chain,
                &roster,
                DirectionV1::Initiator,
                0,
                purpose,
            )?;
            proofs.push(prove_share_knowledge_v1(&statement, &keys[slot])?);
        }
        Ok((
            chain,
            roster,
            DomBootstrapProvenOfferV18::new(offer, proofs.try_into().map_err(|_| invalid())?)?,
        ))
    }

    #[test]
    fn v18_native_possession_roundtrip_and_frozen_replay() -> Result<()> {
        let (chain, roster, offer) = fixture()?;
        let bytes = offer.to_bytes()?;
        let decoded = DomBootstrapProvenOfferV18::from_bytes(&bytes)?;
        decoded.verify(&chain, &roster, DirectionV1::Initiator, 0)?;
        decoded.verify_against_frozen_chain_v18(
            chain.as_bytes(),
            &roster,
            DirectionV1::Initiator,
            0,
        )?;
        assert_eq!(decoded.to_bytes()?, bytes);
        Ok(())
    }
    #[test]
    fn v18_proofs_cannot_move_between_purposes() -> Result<()> {
        let (chain, roster, mut offer) = fixture()?;
        offer.proofs.swap(0, 2);
        assert!(offer
            .verify(&chain, &roster, DirectionV1::Initiator, 0)
            .is_err());
        Ok(())
    }
    #[test]
    fn v18_proofs_bind_wallet_bytes_and_terms() -> Result<()> {
        let (chain, roster, offer) = fixture()?;
        let mut changed = offer.clone();
        changed.offer.terms_hash[0] ^= 1;
        assert!(changed
            .verify(&chain, &roster, DirectionV1::Initiator, 0)
            .is_err());
        let mut changed = offer;
        changed.offer.offsets[1] = scalar(31);
        assert!(changed
            .verify(&chain, &roster, DirectionV1::Initiator, 0)
            .is_err());
        Ok(())
    }
    #[test]
    fn v18_proofs_cannot_be_relabelled_as_peer_or_other_chain() -> Result<()> {
        let (chain, roster, mut offer) = fixture()?;
        assert!(offer
            .verify(&chain, &roster, DirectionV1::Responder, 0)
            .is_err());
        assert!(offer
            .verify(
                &TrustedChainIdV1::from_signed_fixture([0x12; 32]),
                &roster,
                DirectionV1::Initiator,
                0
            )
            .is_err());
        offer.offer.participant_id = roster[1];
        assert!(offer
            .verify(&chain, &roster, DirectionV1::Responder, 1)
            .is_err());
        Ok(())
    }
    #[test]
    fn v18_codec_rejects_size_prefix_truncation_and_trailing_data() -> Result<()> {
        let (_, _, offer) = fixture()?;
        let bytes = offer.to_bytes()?;
        assert!(DomBootstrapProvenOfferV18::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(DomBootstrapProvenOfferV18::from_bytes(&extra).is_err());
        let mut forged = bytes;
        forged[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(DomBootstrapProvenOfferV18::from_bytes(&forged).is_err());
        Ok(())
    }
}
