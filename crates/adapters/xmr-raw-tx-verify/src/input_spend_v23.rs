//! A public input link, deliberately separate from payout or economic authority.
use crate::{parse_exact, verify_exact_raw_sweep_bounded_v23, RawTxError, SweepFeeErrorV23};
use monero_oxide::transaction::Transaction;
use xmr_key_image_proof::{
    verify_input_spend_v23, InputSpendContextV23, InputSpendProofErrorV23, InputSpendProofV23,
};

/// The selected raw output cannot be linked to the exact sweep input.
#[derive(Debug, thiserror::Error)]
pub enum FundingInputSpendErrorV23 {
    /// Exact funding bytes/hash are invalid.
    #[error("invalid funding transaction bytes")]
    Funding(#[from] RawTxError),
    /// Sweep bytes/hash/profile/fee are invalid.
    #[error("invalid bounded sweep transaction")]
    Sweep(#[from] SweepFeeErrorV23),
    /// Output index, funding profile, number of inputs, or exact fee mismatch.
    #[error("funding input proof has incompatible transaction scope")]
    Scope,
    /// The public Chaum–Pedersen proof did not verify.
    #[error("invalid funding input proof")]
    Proof(#[from] InputSpendProofErrorV23),
}

/// The raw sweep's sole key image is linked to the selected raw funding output.
///
/// NOT a verified payout/amount, ring signature, inclusion, ownership role,
/// availability guarantee, signing grant, or economic receipt. No constructor
/// accepts a caller-provided output point or key image.
#[derive(Debug)]
pub struct VerifiedFundingInputSpendV23 {
    context: InputSpendContextV23,
    output: [u8; 32],
    key_image: [u8; 32],
}
impl VerifiedFundingInputSpendV23 {
    /// Proof context; destination/amount here are transcript bindings ONLY.
    pub fn context(&self) -> &InputSpendContextV23 {
        &self.context
    }
    /// Public one-time key read from exact funding bytes at the declared index.
    pub fn output(&self) -> [u8; 32] {
        self.output
    }
    /// Public key image read from exact sweep bytes.
    pub fn key_image(&self) -> [u8; 32] {
        self.key_image
    }
}

/// Verify bytes, fee cap, selected output and the sole sweep input's DLEQ.
///
/// The caller authenticates the context against its session and negotiated
/// terms. This routine never promotes those context claims into payout proof.
pub fn verify_funding_input_spend_v23(
    context: &InputSpendContextV23,
    funding_raw: &[u8],
    sweep_raw: &[u8],
    negotiated_max_fee: u64,
    proof: &InputSpendProofV23,
) -> Result<VerifiedFundingInputSpendV23, FundingInputSpendErrorV23> {
    context.canonical_bytes()?;
    let funding = parse_exact(funding_raw, context.funding_tx)?;
    let Transaction::V2 {
        prefix,
        proofs: Some(_),
    } = &funding
    else {
        return Err(FundingInputSpendErrorV23::Scope);
    };
    let index =
        usize::try_from(context.output_index).map_err(|_| FundingInputSpendErrorV23::Scope)?;
    let output = prefix
        .outputs
        .get(index)
        .ok_or(FundingInputSpendErrorV23::Scope)?
        .key
        .to_bytes();
    let sweep = verify_exact_raw_sweep_bounded_v23(
        sweep_raw,
        context.sweep_tx,
        context.funded_amount,
        negotiated_max_fee,
    )?;
    // Multiple inputs require a different proof bundle; do not silently prove
    // only one input. The raw verifier also rejects duplicate images.
    if sweep.sweep().key_images.len() != 1 || sweep.fee_piconero() != context.fee {
        return Err(FundingInputSpendErrorV23::Scope);
    }
    let key_image = sweep.sweep().key_images[0];
    verify_input_spend_v23(context, output, key_image, proof)?;
    Ok(VerifiedFundingInputSpendV23 {
        context: context.clone(),
        output,
        key_image,
    })
}
