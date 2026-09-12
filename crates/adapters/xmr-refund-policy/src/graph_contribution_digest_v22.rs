//! Recomputable public transcript for the five graph-key knowledge proofs.
use dom_crypto::PublicKey;

/// Public funding fields only. Values/openings and local reservation IDs
/// never enter the peer transcript. The funding offer must be verified first.
pub struct XmrGraphFundingDigestV22<'a> {
    /// Native input commitments; canonicalized before hashing.
    pub inputs: &'a [[u8; 33]],
    /// Optional wallet change commitment.
    pub change: Option<[u8; 33]>,
    /// Negotiated public funding fee.
    pub fee: u64,
}

/// Exact public contribution reconstructed independently by owner and peer.
/// Computing a digest grants neither authentication nor economic authority.
pub struct XmrGraphContributionDigestV22<'a> {
    /// Chain, route, parent session, terms hash, participant ID, in that order.
    pub scope: [[u8; 32]; 5],
    /// Funding, claim, cancel, refund, compensation excess points.
    pub keys: &'a [PublicKey; 5],
    /// Public offset contributions in the same stage order.
    pub offsets: &'a [[u8; 32]; 5],
    /// Absent only for the authenticated non-funder.
    pub funding: Option<XmrGraphFundingDigestV22<'a>>,
}

impl XmrGraphContributionDigestV22<'_> {
    /// Domain-separated public digest. Sorted input commitments ensure that
    /// wallet selection order is not part of the public protocol.
    /// Proof bytes are checked separately and frozen in the signed templates.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = b"DOM:XMR:public-contribution:v22\0".to_vec();
        for field in self.scope {
            bytes.extend_from_slice(&field);
        }
        for (key, offset) in self.keys.iter().zip(self.offsets) {
            bytes.extend_from_slice(&key.to_compressed_bytes());
            bytes.extend_from_slice(offset);
        }
        if let Some(funding) = &self.funding {
            bytes.push(1);
            bytes.extend_from_slice(&funding.fee.to_le_bytes());
            let mut inputs = funding.inputs.to_vec();
            inputs.sort();
            bytes.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
            for input in inputs {
                bytes.extend_from_slice(&input);
            }
            if let Some(change) = funding.change {
                bytes.push(1);
                bytes.extend_from_slice(&change);
            } else {
                bytes.push(0);
            }
        } else {
            bytes.push(0);
        }
        *dom_crypto::blake2b_256(&bytes).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_digest_binds_each_contribution_without_wallet_private_metadata() {
        let share = dom_adaptor::SigningShareV1::from_be_bytes([7; 32]).unwrap();
        let keys = std::array::from_fn(|_| share.public_key().clone());
        let offsets = [[8; 32]; 5];
        let inputs = [[9; 33], [10; 33]];
        let mut scope = XmrGraphContributionDigestV22 {
            scope: [[11; 32]; 5],
            keys: &keys,
            offsets: &offsets,
            funding: Some(XmrGraphFundingDigestV22 {
                inputs: &inputs,
                change: Some([12; 33]),
                fee: 13,
            }),
        };
        let original = scope.digest();
        let reversed = [inputs[1], inputs[0]];
        scope.funding.as_mut().unwrap().inputs = &reversed;
        assert_eq!(scope.digest(), original);
        scope.funding.as_mut().unwrap().inputs = &inputs;
        for field in 0..5 {
            scope.scope[field][0] ^= 1;
            assert_ne!(scope.digest(), original);
            scope.scope[field][0] ^= 1;
        }
        scope.funding.as_mut().unwrap().fee += 1;
        assert_ne!(scope.digest(), original);
        scope.funding.as_mut().unwrap().fee -= 1;
        scope.funding.as_mut().unwrap().change = None;
        assert_ne!(scope.digest(), original);
        scope.funding.as_mut().unwrap().change = Some([12; 33]);
        scope.funding.as_mut().unwrap().inputs = &inputs[..1];
        assert_ne!(scope.digest(), original);
        scope.funding = None;
        assert_ne!(scope.digest(), original);
    }
}
