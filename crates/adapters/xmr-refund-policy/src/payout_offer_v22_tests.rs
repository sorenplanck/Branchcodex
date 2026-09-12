//! Canonical public payout offers do not authorize funds or contain openings.
use super::*;
use dom_crypto::pedersen::{BlindingFactor, Commitment};

#[test]
fn all_policy_payout_offers_roundtrip_and_refuse_scope_or_encoding_mutations(
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let (mut policy, mut terms) = crate::compensation::tests::fixture();
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        0x000d_0012,
        &dom_core::Hash256::from_bytes([91; 32]),
    );
    policy.dom_chain_id = *chain.as_bytes();
    terms.dom_leg.chain_id.0 = *chain.as_bytes();
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let amounts = policy.validate_for(&terms)?;
    let values = [
        policy.dom_principal_noms,
        amounts.successful_change_noms(),
        amounts.refund_payout_noms(),
        amounts.compensation_payout_noms(),
    ];
    let mut commitments = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let blinding = BlindingFactor::from_bytes([index as u8 + 11; 32])?;
        commitments.push(*Commitment::commit(*value, &blinding).as_bytes());
    }
    policy.claim_principal_commitment = commitments[0];
    policy.claim_change_commitment = commitments[1];
    policy.refund_recipient_commitment = commitments[2];
    policy.compensation_recipient_commitment = commitments[3];
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let policy = policy.validate_for(&terms)?;
    let kinds = [
        XmrGraphPayoutKindV22::ClaimPrincipal,
        XmrGraphPayoutKindV22::ClaimChange,
        XmrGraphPayoutKindV22::Refund,
        XmrGraphPayoutKindV22::Compensation,
    ];
    for (index, kind) in kinds.into_iter().enumerate() {
        let blinding = BlindingFactor::from_bytes([index as u8 + 11; 32])?;
        let (proof, commitment) = dom_crypto::range_proof_prove_bytes(values[index], &blinding)?;
        assert_eq!(commitment, commitments[index]);
        let output = TransactionOutput {
            commitment: Commitment::from_compressed_bytes(&commitment)?,
            proof,
        };
        let role = if kind.policy_payout(&policy).0 == policy.policy().dom_funder {
            DirectionV1::Initiator
        } else {
            DirectionV1::Responder
        };
        let ownership = if let Some(success) = kind.success_kind() {
            let share = dom_adaptor::SigningShareV1::from_be_bytes([index as u8 + 11; 32])?;
            Some(crate::economic_graph::produce_xmr_payout_value_proof_v12(
                &terms, &policy, success, role, &chain, &share,
            )?)
        } else {
            None
        };
        let offer =
            XmrPolicyPayoutOfferV22::new(&terms, &policy, kind, output, ownership, &chain, role)?;
        let bytes = offer.to_bytes()?;
        let decode = |bytes: &[u8]| {
            XmrPolicyPayoutOfferV22::from_bytes(bytes, &terms, &policy, &chain, role)
        };
        let decoded = decode(&bytes)?;
        assert_eq!(decoded.kind(), kind);
        assert_eq!(decoded.output().commitment.as_bytes(), &commitments[index]);
        assert_eq!(decoded.to_bytes()?, bytes);
        for offset in [0, 8, 9, 41, 73, 105, 137] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x80;
            assert!(
                decode(&changed).is_err(),
                "changed payout scope must be refused"
            );
        }
        let mut length = bytes.clone();
        length[145..149].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&length).is_err());
        // The native output has its own proof length after the commitment.
        // An in-bounds outer packet must not permit an oversized inner vector.
        let mut inner_length = bytes.clone();
        inner_length[182..186].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&inner_length).is_err());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        assert!(decode(&vec![0; XmrPolicyPayoutOfferV22::MAX_BYTES + 1]).is_err());
        if kind.success_kind().is_some() {
            let opposite = if role == DirectionV1::Initiator {
                DirectionV1::Responder
            } else {
                DirectionV1::Initiator
            };
            assert!(
                XmrPolicyPayoutOfferV22::from_bytes(&bytes, &terms, &policy, &chain, opposite,)
                    .is_err()
            );
        }
        let mut wrong_terms = terms.clone();
        wrong_terms.dom_leg.amount += 1;
        assert!(
            XmrPolicyPayoutOfferV22::from_bytes(&bytes, &wrong_terms, &policy, &chain, role,)
                .is_err()
        );
    }
    Ok(())
}
