//! Economic binding of the native cancel/refund/compensation graph.
//!
//! This verifier checks exact amounts without importing any payout blinding.
//! It reuses native shared-output formation and native share proofs. A result
//! is a prerequisite for custody/funding, never a broadcast or signing grant.

use super::compensation::ValidatedXmrCompensationPolicyV11;
use super::compensation::XmrCompensationPolicyErrorV11 as Refusal;
use dom_adaptor::{verify_share_knowledge_v1, BpStatementV1, SharePoPStatementV1, ShareProofV1};
use dom_crypto::blake2b_256;
use dom_scriptless_crypto::{FrozenSharedOutputV1, VerifiedXmrRecoveryGraphV11};
use kaystra_core::terms::SettlementTermsV1;

/// The two normal-success outputs committed by the compensation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrPayoutKindV12 {
    /// The negotiated trade principal, owned by the XMR funder.
    ClaimPrincipal,
    /// Unspent collateral and margin, owned by the DOM funder.
    ClaimChange,
}

/// Produce the native value/ownership proof inside an authenticated wallet.
/// The wallet must authenticate the selected payout before calling this
/// function. Only a borrowed opaque local blinding share is accepted; no
/// private scalar is returned, serialized or transferred to the daemon.
pub fn produce_xmr_payout_value_proof_v12(
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    kind: XmrPayoutKindV12,
    role: dom_adaptor::DirectionV1,
    chain: &dom_adaptor::TrustedChainIdV1,
    payout_blinding: &dom_adaptor::SigningShareV1,
) -> Result<XmrPayoutValueProofV11, Refusal> {
    let statement = xmr_payout_value_statement_v12(
        terms,
        policy,
        kind,
        role,
        chain,
        payout_blinding.public_key().clone(),
    )?;
    let proof = dom_adaptor::prove_share_knowledge_v1(&statement, payout_blinding)
        .map_err(|_| Refusal::GraphMismatch)?;
    Ok(XmrPayoutValueProofV11 { statement, proof })
}

/// Build the exact public statement that an authenticated wallet proves.
/// A wallet returning a proof must match this point to its retained payout
/// blinding; the statement alone proves no ownership or signing authority.
pub fn xmr_payout_value_statement_v12(
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    kind: XmrPayoutKindV12,
    role: dom_adaptor::DirectionV1,
    chain: &dom_adaptor::TrustedChainIdV1,
    payout_blinding_point: dom_crypto::PublicKey,
) -> Result<SharePoPStatementV1, Refusal> {
    let policy = policy.policy().validate_for(terms)?;
    if chain.as_bytes() != &policy.policy().dom_chain_id {
        return Err(Refusal::GraphMismatch);
    }
    let signed = policy.policy();
    let (tag, recipient, amount, commitment) = match kind {
        XmrPayoutKindV12::ClaimPrincipal => (
            1,
            signed.xmr_funder,
            signed.dom_principal_noms,
            signed.claim_principal_commitment,
        ),
        XmrPayoutKindV12::ClaimChange => (
            2,
            signed.dom_funder,
            policy.successful_change_noms(),
            signed.claim_change_commitment,
        ),
    };
    let roster = [terms.roster[0].0, terms.roster[1].0];
    let index = roster
        .iter()
        .position(|participant| participant == &recipient)
        .ok_or(Refusal::GraphMismatch)?;
    let actual =
        BpStatementV1::aggregate_commitment_from_shares(&[payout_blinding_point.clone()], amount)
            .map_err(|_| Refusal::GraphMismatch)?;
    if actual.to_compressed_bytes() != commitment {
        return Err(Refusal::GraphMismatch);
    }
    SharePoPStatementV1::new(
        chain,
        signed.session_id,
        &roster,
        role,
        u16::try_from(index).map_err(|_| Refusal::GraphMismatch)?,
        payout_blinding_point,
        *policy.terms_hash(),
        payout_value_binding_v11(&policy, tag, amount, commitment),
    )
    .map_err(|_| Refusal::GraphMismatch)
}

const PAYOUT_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-COMPENSATION/PAYOUT-VALUE/V11\0";

/// Public native proof of the blinding in one signed-policy payout commitment.
/// Neither the blinding nor a spend signature is serialized in this record.
pub struct XmrPayoutValueProofV11 {
    /// Exact native PoP statement of the payout blinding.
    pub statement: SharePoPStatementV1,
    /// Native proof of knowledge, containing no private blinding.
    pub proof: ShareProofV1,
}

/// Exact accepted economic graph for one authenticated route position.
/// No generic or raw constructor is exposed.
pub struct VerifiedXmrEconomicRecoveryGraphV11 {
    policy: ValidatedXmrCompensationPolicyV11,
    graph_digest: [u8; 32],
    bp_statement_hash: [u8; 32],
}

impl VerifiedXmrEconomicRecoveryGraphV11 {
    /// Verify exact native collateral formation, all signed payout commitments,
    /// fees and principal/change amounts against the frozen assurance policy.
    /// This verifies mathematical evidence, not bilateral signatures or the
    /// current chain. Store must bind this to its admitted role and graph.
    pub fn authenticate(
        terms: &SettlementTermsV1,
        policy: ValidatedXmrCompensationPolicyV11,
        graph: &VerifiedXmrRecoveryGraphV11,
        collateral: &FrozenSharedOutputV1,
        claim_principal: &XmrPayoutValueProofV11,
        claim_change: &XmrPayoutValueProofV11,
    ) -> Result<Self, Refusal> {
        let policy = policy
            .policy()
            .validate_for(terms)
            .map_err(|_| Refusal::GraphMismatch)?;
        let binding = graph.binding();
        let signed = policy.policy();
        let roster = [terms.roster[0].0, terms.roster[1].0];
        let statement = collateral.statement();
        if policy.terms_hash() != collateral.terms_hash()
            || policy.terms_hash() != &binding.terms_hash
            || binding.chain_id != signed.dom_chain_id
            || binding.session_id != signed.session_id
            || binding.claim_adaptor_point != terms.adaptor_point_sec1
            || binding.cancel_height != signed.cancel_height
            || binding.punish_height != signed.compensation_height
            || binding.reveal_safety_blocks != signed.reveal_safety_blocks
            || binding.cancel_fee != signed.cancel_fee_noms
            || binding.refund_fee != signed.refund_fee_noms
            || binding.punish_fee != signed.compensation_fee_noms
            || binding.refund_recipient_commitment != signed.refund_recipient_commitment
            || binding.punish_recipient_commitment != signed.compensation_recipient_commitment
            || collateral.value_noms() != policy.collateral_noms()
            || collateral.aggregate_commitment() != &binding.funding_commitment
            || statement.chain_id() != signed.dom_chain_id
            || statement.session_id() != signed.session_id
            || statement.participant_ids() != roster.as_slice()
        {
            return Err(Refusal::GraphMismatch);
        }
        // The shared-blinding vault fixes this field to the actual native
        // recovery capsule hash. The assurance policy is instead authenticated
        // by the full terms hash in every contribution's native share PoP.
        // Replacing the capsule hash with the policy hash makes honest native
        // wallet formation impossible and destroys the capsule binding.
        let collateral_output = graph
            .funding_template()
            .outputs
            .iter()
            .find(|output| output.commitment.as_bytes() == collateral.aggregate_commitment())
            .ok_or(Refusal::GraphMismatch)?;
        require_collateral_capsule_v12(&policy, collateral, collateral_output)?;
        let claim = graph.claim_template();
        if claim.outputs.len() != 2
            || claim.kernels.len() != 1
            || claim.kernels[0].fee.noms() != signed.claim_fee_noms
            || claim
                .outputs
                .iter()
                .filter(|output| output.commitment.as_bytes() == &signed.claim_principal_commitment)
                .count()
                != 1
            || claim
                .outputs
                .iter()
                .filter(|output| output.commitment.as_bytes() == &signed.claim_change_commitment)
                .count()
                != 1
        {
            return Err(Refusal::GraphMismatch);
        }
        require_payout(
            &policy,
            &roster,
            1,
            signed.xmr_funder,
            signed.dom_principal_noms,
            signed.claim_principal_commitment,
            claim_principal,
        )?;
        require_payout(
            &policy,
            &roster,
            2,
            signed.dom_funder,
            policy.successful_change_noms(),
            signed.claim_change_commitment,
            claim_change,
        )?;
        // Cancel, refund and compensation each have exactly one output and
        // fixed native fees. Once C's exact value is proved, unchanged native
        // balance verification fixes every recovery payout value. No amount
        // provided by the sidecar or a JSON response is used for that proof.
        Ok(Self {
            policy,
            graph_digest: *graph.graph_digest(),
            bp_statement_hash: statement.statement_hash(),
        })
    }

    /// Full validated signed-policy scope.
    pub fn policy(&self) -> &ValidatedXmrCompensationPolicyV11 {
        &self.policy
    }
    /// Digest of the exact native graph whose amounts were verified.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Native statement binding C to its exact collateral value.
    pub const fn bp_statement_hash(&self) -> &[u8; 32] {
        &self.bp_statement_hash
    }
}

fn require_collateral_capsule_v12(
    policy: &ValidatedXmrCompensationPolicyV11,
    collateral: &FrozenSharedOutputV1,
    output: &dom_consensus::TransactionOutput,
) -> Result<(), Refusal> {
    let capsule = output
        .recovery_capsule()
        .map_err(|_| Refusal::GraphMismatch)?
        .ok_or(Refusal::GraphMismatch)?;
    if collateral.terms_hash() != policy.terms_hash()
        || collateral.statement().chain_id() != policy.policy().dom_chain_id
        || collateral.statement().session_id() != policy.policy().session_id
        || collateral.value_noms() != policy.collateral_noms()
        || output.commitment.as_bytes() != collateral.aggregate_commitment()
        || collateral.statement().recovery_binding_hash()
            != blake2b_256(capsule.as_bytes()).as_bytes()
    {
        return Err(Refusal::GraphMismatch);
    }
    Ok(())
}

fn require_payout(
    policy: &ValidatedXmrCompensationPolicyV11,
    roster: &[[u8; 32]; 2],
    tag: u8,
    recipient: [u8; 32],
    value: u64,
    commitment: [u8; 33],
    input: &XmrPayoutValueProofV11,
) -> Result<(), Refusal> {
    let statement = &input.statement;
    let index = usize::from(statement.participant_index());
    statement
        .require_authenticated_roster_v22(roster)
        .map_err(|_| Refusal::GraphMismatch)?;
    if roster.get(index) != Some(&recipient)
        || statement.participant_id() != recipient
        || statement.chain_id() != policy.policy().dom_chain_id
        || statement.session_id() != policy.policy().session_id
        || statement.terms_hash() != *policy.terms_hash()
        || statement.recovery_binding_hash()
            != payout_value_binding_v11(policy, tag, value, commitment)
        || !verify_share_knowledge_v1(statement, &input.proof)
            .map_err(|_| Refusal::GraphMismatch)?
    {
        return Err(Refusal::GraphMismatch);
    }
    // This native operation supports one or more already-proven public shares;
    // it reconstructs value*H_DOM + R without revealing the payout's blind.
    let actual = BpStatementV1::aggregate_commitment_from_shares(&[statement.share_point()], value)
        .map_err(|_| Refusal::GraphMismatch)?;
    if actual.to_compressed_bytes() != commitment {
        return Err(Refusal::GraphMismatch);
    }
    Ok(())
}

/// Shared by the wallet proof producer and verifier. The kind distinguishes
/// success principal from success change even if their amounts happen to match.
pub fn payout_value_binding_v11(
    policy: &ValidatedXmrCompensationPolicyV11,
    tag: u8,
    value: u64,
    commitment: [u8; 33],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(PAYOUT_DOMAIN.len() + 74);
    bytes.extend_from_slice(PAYOUT_DOMAIN);
    bytes.extend_from_slice(policy.terms_hash());
    bytes.push(tag);
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes.extend_from_slice(&commitment);
    *blake2b_256(&bytes).as_bytes()
}

/// Verify economic graph evidence without constructing authority or exposing keys.
pub fn verify_xmr_economic_recovery_graph_v11(
    terms: &SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    graph: &VerifiedXmrRecoveryGraphV11,
    collateral: &FrozenSharedOutputV1,
    payouts: &[XmrPayoutValueProofV11; 2],
) -> Result<VerifiedXmrEconomicRecoveryGraphV11, Refusal> {
    VerifiedXmrEconomicRecoveryGraphV11::authenticate(
        terms,
        policy,
        graph,
        collateral,
        &payouts[0],
        &payouts[1],
    )
}

#[cfg(test)]
#[path = "economic_graph_payout_scope_v22_tests.rs"]
mod payout_scope_v22_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use dom_adaptor::{
        combine_decoy_capsule_v1, prove_share_knowledge_v1, DecoyContributionV1, DirectionV1,
        SessionId, SigningShareV1, TrustedChainIdV1,
    };
    use dom_crypto::{
        pedersen::{BlindingFactor, Commitment},
        range_proof_prove_bytes_with_extra_commit,
    };
    use dom_scriptless_crypto::{
        freeze_shared_output_statement_v1, SharedOutputContributionV1, SharedOutputInputsV1,
    };

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[31] = value;
        bytes
    }

    #[test]
    fn native_capsule_and_assurance_have_distinct_bindings_and_terms_cannot_be_retagged(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut policy, mut terms) = super::super::compensation::tests::fixture();
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x000d_0012,
            &dom_core::Hash256::from_bytes([61; 32]),
        );
        policy.dom_chain_id = *chain.as_bytes();
        terms.dom_leg.chain_id.0 = *chain.as_bytes();
        terms.assurance_policy_hash = Some(policy.policy_hash()?);
        let validated = policy.validate_for(&terms)?;
        let a = SigningShareV1::from_be_bytes(scalar(4))?;
        let b = SigningShareV1::from_be_bytes(scalar(6))?;
        let session = SessionId::from_bytes(policy.session_id)?;
        let left = DecoyContributionV1::derive(&a, &session);
        let right = DecoyContributionV1::derive(&b, &session);
        let right_commitment = right.commitment();
        let capsule =
            combine_decoy_capsule_v1(&left.into_reveal(), &right.into_reveal(), &right_commitment)?;
        let capsule_hash = *blake2b_256(capsule.as_bytes()).as_bytes();
        assert_ne!(capsule_hash, policy.policy_hash()?);
        let roster = [policy.dom_funder, policy.xmr_funder];
        let contributions = [&a, &b]
            .iter()
            .enumerate()
            .map(|(index, share)| {
                let role = if index == 0 {
                    DirectionV1::Initiator
                } else {
                    DirectionV1::Responder
                };
                let statement = SharePoPStatementV1::new(
                    &chain,
                    policy.session_id,
                    &roster,
                    role,
                    u16::try_from(index)?,
                    share.public_key().clone(),
                    *validated.terms_hash(),
                    capsule_hash,
                )?;
                Ok(SharedOutputContributionV1 {
                    participant_index: u16::try_from(index)?,
                    participant_id: roster[index],
                    role,
                    commitment_share: share.public_key().clone(),
                    proof: prove_share_knowledge_v1(&statement, share)?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let collateral = freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
            chain_id: chain,
            session_id: policy.session_id,
            contributions: &contributions,
            value_noms: validated.collateral_noms(),
            terms_hash: *validated.terms_hash(),
            recovery_binding_hash: capsule_hash,
        })?;
        // Test-only sum 4+6. Production never reconstructs the shared blinding.
        let blind = BlindingFactor::from_bytes(scalar(10))?;
        let (proof, commitment) = range_proof_prove_bytes_with_extra_commit(
            validated.collateral_noms(),
            &blind,
            capsule.as_bytes(),
        )?;
        let output = dom_consensus::TransactionOutput::with_recovery_capsule(
            Commitment::from_compressed_bytes(&commitment)?,
            proof,
            &capsule,
        )?;
        require_collateral_capsule_v12(&validated, &collateral, &output)?;
        policy.volatility_margin_bps += 1;
        terms.assurance_policy_hash = Some(policy.policy_hash()?);
        let substituted = policy.validate_for(&terms)?;
        assert_eq!(
            require_collateral_capsule_v12(&substituted, &collateral, &output),
            Err(Refusal::GraphMismatch)
        );
        assert!(freeze_shared_output_statement_v1(&SharedOutputInputsV1 {
            chain_id: chain,
            session_id: policy.session_id,
            contributions: &contributions,
            value_noms: substituted.collateral_noms(),
            terms_hash: *substituted.terms_hash(),
            recovery_binding_hash: capsule_hash,
        })
        .is_err());
        Ok(())
    }
}
