//! Payout and RingCT verification against explicitly supplied ring evidence.
//! Chain membership/inclusion remains an independent observer responsibility.
use crate::{
    funding_v12, parse_exact, verify_funding_input_spend_v23, FundingInputSpendErrorV23,
    FundingVerificationErrorV12, RawTxError, VerifiedFundingInputSpendV23,
};
use monero_oxide::{
    ed25519::{Commitment, Point, Scalar as MoneroScalar},
    ringct::RctPrunable,
    transaction::{Input, Transaction},
};
use rand_core::{CryptoRng, RngCore};
use xmr_key_image_proof::{
    destination_digest_v23, verify_tx_key_derivation_v23, InputSpendContextV23,
    InputSpendProofErrorV23, InputSpendProofV23, TxKeyDerivationProofV23,
};

/// Public ring member supplied by the chain observer, never implicitly trusted
/// merely because the peer sends it. Global indexes must resolve to these exact
/// keys/commitments on the selected Monero chain before remote acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingMemberEvidenceV23 {
    /// Absolute RingCT output index.
    pub global_index: u64,
    /// Canonical one-time output key.
    pub key: [u8; 32],
    /// Canonical amount commitment.
    pub commitment: [u8; 32],
}

/// Failure of the complete cryptographic sweep checks.
#[derive(Debug, thiserror::Error)]
pub enum SweepPayoutErrorV23 {
    /// Canonical raw transaction failure.
    #[error("invalid exact transaction")]
    Raw(#[from] RawTxError),
    /// Funding input link failed.
    #[error("invalid funding input link")]
    Input(#[from] FundingInputSpendErrorV23),
    /// Destination or ECDH commitment failed.
    #[error("invalid payout commitment")]
    Payout(#[from] FundingVerificationErrorV12),
    /// Transaction key proof failed.
    #[error("invalid transaction derivation proof")]
    Proof(#[from] InputSpendProofErrorV23),
    /// Unsupported/ambiguous output, derivation or ring evidence scope.
    #[error("invalid payout scope")]
    Scope,
    /// Bulletproof+, commitment conservation, or CLSAG failed.
    #[error("invalid RingCT sweep proof")]
    RingCt,
}

/// Exact payout, BP+, balance and CLSAG hold for the retained ring evidence.
///
/// This is NOT inclusion/finality or proof of chain membership of those ring
/// members. A remote protocol must authenticate `ring_members()` using its own
/// chain observer, and perform its ordinary lease/role/session authorization.
#[derive(Debug)]
pub struct VerifiedSweepPayoutV23 {
    input: VerifiedFundingInputSpendV23,
    output_index: u32,
    amount: u64,
    ring_members: Vec<RingMemberEvidenceV23>,
}
impl VerifiedSweepPayoutV23 {
    /// Verified input link and transcript scope.
    pub fn input(&self) -> &VerifiedFundingInputSpendV23 {
        &self.input
    }
    /// Unique recipient output selected by authenticated public derivations.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
    /// Exact decrypted amount, equal to funded amount minus raw fee.
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// Evidence against which the ring signature was checked; not chain trust.
    pub fn ring_members(&self) -> &[RingMemberEvidenceV23] {
        &self.ring_members
    }
}

/// Verify a standard-address sweep with 2..16 outputs, exactly one paying the
/// full principal minus fee. Additional recipient outputs are rejected, not
/// ignored. Conservation plus range proof accounts for all remaining outputs.
///
/// The RNG is used for real Bulletproof batch verification, not signing. The
/// ring evidence must be independently resolved from the selected chain before
/// treating this conditional cryptographic result as remotely admissible.
#[allow(clippy::too_many_arguments)]
pub fn verify_sweep_payout_v23<R: RngCore + CryptoRng>(
    context: &InputSpendContextV23,
    funding_raw: &[u8],
    sweep_raw: &[u8],
    destination: &str,
    max_fee: u64,
    input_proof: &InputSpendProofV23,
    tx_key_proofs: &[TxKeyDerivationProofV23],
    ring_members: &[RingMemberEvidenceV23],
    rng: &mut R,
) -> Result<VerifiedSweepPayoutV23, SweepPayoutErrorV23> {
    let input =
        verify_funding_input_spend_v23(context, funding_raw, sweep_raw, max_fee, input_proof)?;
    let address =
        monero_address::MoneroAddress::from_str(monero_address::Network::Mainnet, destination)
            .map_err(|_| SweepPayoutErrorV23::Scope)?;
    if !matches!(address.kind(), monero_address::AddressType::Legacy)
        || address.is_subaddress()
        || address.payment_id().is_some()
        || address.to_string() != destination
        || destination_digest_v23(destination) != context.destination
    {
        return Err(SweepPayoutErrorV23::Scope);
    }
    let transaction = parse_exact(sweep_raw, context.sweep_tx)?;
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &transaction
    else {
        return Err(SweepPayoutErrorV23::Scope);
    };
    let (primary, additional) = funding_v12::extra_keys(&prefix.extra, prefix.outputs.len())?;
    let mut expected_keys = std::collections::BTreeSet::from([primary]);
    if let Some(keys) = additional {
        expected_keys.extend(keys);
    }
    if tx_key_proofs.len() != expected_keys.len() || tx_key_proofs.len() > 17 {
        return Err(SweepPayoutErrorV23::Scope);
    }
    let mut derivations = std::collections::BTreeMap::new();
    for proof in tx_key_proofs {
        if !expected_keys.contains(&proof.tx_public) || derivations.contains_key(&proof.tx_public) {
            return Err(SweepPayoutErrorV23::Scope);
        }
        let d = verify_tx_key_derivation_v23(context, address.view().compress().to_bytes(), proof)?;
        derivations.insert(proof.tx_public, funding_v12::point(d)?);
    }
    let amount = context
        .funded_amount
        .checked_sub(context.fee)
        .ok_or(SweepPayoutErrorV23::Scope)?;
    let output_index = funding_v12::verify_recipient_with_derivations_v23(
        prefix,
        &proofs.base,
        address.spend().compress().to_bytes(),
        amount,
        max_fee,
        |r| {
            derivations
                .get(&r)
                .copied()
                .ok_or(FundingVerificationErrorV12::Extra)
        },
    )?;
    let RctPrunable::Clsag {
        clsags,
        pseudo_outs,
        bulletproof,
    } = &proofs.prunable
    else {
        return Err(SweepPayoutErrorV23::Scope);
    };
    let Input::ToKey {
        key_offsets,
        key_image,
        amount: None,
    } = &prefix.inputs[0]
    else {
        return Err(SweepPayoutErrorV23::Scope);
    };
    // Mainnet modern CLSAG ring size. Explicitly reject missing, duplicated,
    // reordered or additional evidence; never pad a peer-supplied ring.
    if key_offsets.len() != 16
        || ring_members.len() != 16
        || clsags.len() != 1
        || pseudo_outs.len() != 1
    {
        return Err(SweepPayoutErrorV23::Scope);
    }
    let funding = parse_exact(funding_raw, context.funding_tx)?;
    let Transaction::V2 {
        proofs: Some(funding_proofs),
        ..
    } = &funding
    else {
        return Err(SweepPayoutErrorV23::Scope);
    };
    let funding_commitment = funding_proofs
        .base
        .commitments
        .get(context.output_index as usize)
        .ok_or(SweepPayoutErrorV23::Scope)?
        .to_bytes();
    let mut ring = Vec::with_capacity(16);
    let mut index = 0u64;
    let mut actual_funding_members = 0;
    for (position, (offset, member)) in key_offsets.iter().zip(ring_members).enumerate() {
        if position != 0 && *offset == 0 {
            return Err(SweepPayoutErrorV23::Scope);
        }
        index = index
            .checked_add(*offset)
            .ok_or(SweepPayoutErrorV23::Scope)?;
        if member.global_index != index {
            return Err(SweepPayoutErrorV23::Scope);
        }
        let key = Point::from(funding_v12::point(member.key)?).compress();
        let commitment = Point::from(funding_v12::point(member.commitment)?).compress();
        if member.key == input.output() && member.commitment == funding_commitment {
            actual_funding_members += 1;
        }
        ring.push([key, commitment]);
    }
    if actual_funding_members != 1 {
        return Err(SweepPayoutErrorV23::Scope);
    }
    if !bulletproof.verify(rng, &proofs.base.commitments) {
        return Err(SweepPayoutErrorV23::RingCt);
    }
    let mut sum = curve25519_dalek::edwards::EdwardsPoint::default();
    for commitment in &proofs.base.commitments {
        sum += funding_v12::point(commitment.to_bytes())?;
    }
    let fee_commitment: curve25519_dalek::edwards::EdwardsPoint =
        Commitment::new(MoneroScalar::ZERO, context.fee)
            .commit()
            .into();
    sum += fee_commitment;
    if sum != funding_v12::point(pseudo_outs[0].to_bytes())? {
        return Err(SweepPayoutErrorV23::RingCt);
    }
    clsags[0]
        .verify(
            ring,
            key_image,
            &pseudo_outs[0],
            &transaction
                .signature_hash()
                .ok_or(SweepPayoutErrorV23::RingCt)?,
        )
        .map_err(|_| SweepPayoutErrorV23::RingCt)?;
    Ok(VerifiedSweepPayoutV23 {
        input,
        output_index,
        amount,
        ring_members: ring_members.to_vec(),
    })
}
