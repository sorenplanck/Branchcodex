//! A genuine PoP under a foreign roster is not this settlement's payout proof.
use super::*;
use dom_adaptor::{DirectionV1, SigningShareV1, TrustedChainIdV1};

#[test]
fn payout_verifier_refuses_foreign_roster_even_when_recipient_and_value_match(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut policy, mut terms) = super::super::compensation::tests::fixture();
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        0x000d_0012,
        &dom_core::Hash256::from_bytes([81; 32]),
    );
    policy.dom_chain_id = *chain.as_bytes();
    terms.dom_leg.chain_id.0 = *chain.as_bytes();
    let share = SigningShareV1::from_be_bytes([82; 32])?;
    policy.claim_principal_commitment = BpStatementV1::aggregate_commitment_from_shares(
        &[share.public_key().clone()],
        policy.dom_principal_noms,
    )?
    .to_compressed_bytes();
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let policy = policy.validate_for(&terms)?;
    let roster = terms.roster.map(|p| p.0);
    let native = produce_xmr_payout_value_proof_v12(
        &terms,
        &policy,
        XmrPayoutKindV12::ClaimPrincipal,
        DirectionV1::Responder,
        &chain,
        &share,
    )?;
    let check = |candidate: &XmrPayoutValueProofV11| {
        require_payout(
            &policy,
            &roster,
            1,
            policy.policy().xmr_funder,
            policy.policy().dom_principal_noms,
            policy.policy().claim_principal_commitment,
            candidate,
        )
    };
    check(&native)?;

    let foreign_roster = [[4; 32], roster[1]];
    let foreign_statement = SharePoPStatementV1::new(
        &chain,
        policy.policy().session_id,
        &foreign_roster,
        DirectionV1::Responder,
        1,
        share.public_key().clone(),
        *policy.terms_hash(),
        native.statement.recovery_binding_hash(),
    )?;
    // Canonical wire fields are identical: full roster context is external.
    assert_eq!(foreign_statement.to_bytes(), native.statement.to_bytes());
    assert_ne!(foreign_statement, native.statement);
    let foreign = XmrPayoutValueProofV11 {
        proof: dom_adaptor::prove_share_knowledge_v1(&foreign_statement, &share)?,
        statement: foreign_statement,
    };
    assert!(verify_share_knowledge_v1(
        &foreign.statement,
        &foreign.proof
    )?);
    assert!(check(&foreign).is_err());
    check(&native)?;
    Ok(())
}
