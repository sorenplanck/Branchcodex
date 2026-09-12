use super::*;
use dom_crypto::pedersen::BlindingFactor;

#[test]
fn public_funding_offer_refuses_foreign_scope_nonpayer_inputs_and_malformed_lengths(
) -> Result<(), Box<dyn std::error::Error>> {
    let (policy, mut terms) = crate::compensation::tests::fixture();
    terms.fee_limit.dom_max = 1_000_000;
    let policy = policy.validate_for(&terms)?;
    let funder = policy.policy().dom_funder;
    let nonfunder = policy.policy().xmr_funder;
    let mut inputs: Vec<_> = [21, 22]
        .into_iter()
        .map(|tag| TransactionInput {
            commitment: Commitment::commit(1000, &BlindingFactor::from_bytes([tag; 32]).unwrap()),
        })
        .collect();
    inputs.sort_by(|a, b| a.commitment.as_bytes().cmp(b.commitment.as_bytes()));
    // This checks only construction shape, deliberately not economic balance.
    let offer = XmrFundingOfferV22::new(&terms, &policy, funder, inputs.clone(), None, 1)?;
    let bytes = offer.to_bytes()?;
    let decode = |bytes: &[u8]| XmrFundingOfferV22::from_bytes(bytes, &terms, &policy, funder);
    assert_eq!(decode(&bytes)?.to_bytes()?, bytes);
    for offset in [0, 8, 40, 72, 104] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(decode(&changed).is_err());
    }
    let mut count = bytes.clone();
    count[144..146].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(decode(&count).is_err());
    let mut size = bytes.clone();
    let last = size.len() - 4;
    size[last..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode(&size).is_err());
    for fee in [0u64, 1_000_001] {
        let mut changed = bytes.clone();
        changed[136..144].copy_from_slice(&fee.to_le_bytes());
        assert!(decode(&changed).is_err());
    }
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    assert!(decode(&vec![0; XmrFundingOfferV22::MAX_BYTES + 1]).is_err());
    assert!(XmrFundingOfferV22::from_bytes(&bytes, &terms, &policy, nonfunder).is_err());
    assert!(XmrFundingOfferV22::new(&terms, &policy, nonfunder, inputs.clone(), None, 1).is_err());
    assert!(
        XmrFundingOfferV22::new(&terms, &policy, funder, vec![inputs[0].clone(); 2], None, 1)
            .is_err()
    );
    inputs.reverse();
    assert!(XmrFundingOfferV22::new(&terms, &policy, funder, inputs, None, 1).is_err());
    let empty = XmrFundingOfferV22::new(&terms, &policy, nonfunder, Vec::new(), None, 0)?;
    let bytes = empty.to_bytes()?;
    assert_eq!(
        XmrFundingOfferV22::from_bytes(&bytes, &terms, &policy, nonfunder)?.to_bytes()?,
        bytes
    );
    Ok(())
}
