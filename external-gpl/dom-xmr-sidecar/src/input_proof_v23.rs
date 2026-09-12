//! Proof-only use of an already cached sweep. No new spend is signed here.
use super::*;
use monero_oxide_wallet::{
    Scanner, ViewPair,
    interface::ProvidesScannableBlocks,
    ringct::RctType,
    transaction::{Input, NotPruned, Timelock, Transaction},
};
use xmr_key_image_proof::{
    CachedInputProofRequestV23, CachedInputProofResponseV23, InputSpendEnvelopeV23,
    prove_input_spend_v23,
};

fn rejected() -> SidecarOperationError {
    SidecarOperationError::Rejected("cached input proof scope mismatch".to_owned())
}

pub(super) async fn prove_cached(
    config: &Config,
    request: &CachedInputProofRequestV23<BuildSweepRequestV2>,
) -> Result<CachedInputProofResponseV23, SidecarOperationError> {
    config
        .auth
        .verify_build(&request.build)
        .map_err(|_| rejected())?;
    config
        .auth
        .verify_input_proof_v23(request)
        .map_err(|_| rejected())?;
    let context = request.decoded_context().map_err(|_| rejected())?;
    if context.funding_tx != request.build.funding_tx_hash
        || context.funded_amount != request.build.expected_amount_piconero
        || context.destination
            != xmr_key_image_proof::destination_digest_v23(&request.build.destination)
    {
        return Err(rejected());
    }
    let address = monero_address::MoneroAddress::from_str(
        monero_address::Network::Mainnet,
        &request.build.destination,
    )
    .map_err(|_| rejected())?;
    if address.to_string() != request.build.destination {
        return Err(rejected());
    }
    let canonical = Zeroizing::new(
        request
            .build
            .canonical_auth_bytes()
            .map_err(|_| rejected())?,
    );
    // Missing cache is an error, never fallback to build_sweep/signing.
    let cached = config
        .cache
        .load(
            &request.build.request_nonce,
            &SweepCache::request_hash(&canonical),
        )
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if cached.tx_hash != context.sweep_tx
        || cached.raw_tx.is_empty()
        || cached.raw_tx.len() > MAX_RAW_TX_BYTES
    {
        return Err(rejected());
    }
    let mut cursor = cached.raw_tx.as_slice();
    let transaction = Transaction::<NotPruned>::read(&mut cursor).map_err(|_| rejected())?;
    if !cursor.is_empty()
        || transaction.serialize() != cached.raw_tx
        || transaction.hash() != context.sweep_tx
    {
        return Err(rejected());
    }
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &transaction
    else {
        return Err(rejected());
    };
    if prefix.inputs.len() != 1
        || prefix.additional_timelock != Timelock::None
        || proofs.rct_type() != RctType::ClsagBulletproofPlus
        || proofs.base.fee != context.fee
    {
        return Err(rejected());
    }
    let Input::ToKey { key_image, .. } = &prefix.inputs[0] else {
        return Err(rejected());
    };
    let image = key_image.to_bytes();
    let spend = Zeroizing::new(request.build.spend_scalar.expose(|s| parse_scalar(*s))?);
    if monero_wallet_ng::util::public_key(&spend)
        .compress()
        .to_bytes()
        != request.build.expected_spend_public_key
    {
        return Err(rejected());
    }
    let view = request.build.view_scalar.expose(|s| parse_scalar(*s))?;
    let pair = ViewPair::new(
        parse_point(request.build.expected_spend_public_key)?,
        Zeroizing::new(view),
    )
    .map_err(|_| rejected())?;
    let rpc = monerod(config).await?;
    let height = usize::try_from(request.funding_height).map_err(|_| rejected())?;
    let block = ProvidesScannableBlocks::scannable_block_by_number(&rpc, height)
        .await
        .map_err(|_| SidecarOperationError::Retryable)?;
    // The native scanner verifies output derivation and encrypted commitment.
    // Block inclusion/finality is NOT exported by this input-only proof.
    let outputs = Scanner::new(pair)
        .scan(block)
        .map_err(|_| rejected())?
        .not_additionally_locked();
    let mut matches = outputs.iter().filter(|output| {
        output.transaction() == context.funding_tx
            && output.index_in_transaction() == context.output_index
    });
    let output = matches.next().ok_or_else(rejected)?;
    if matches.next().is_some() || output.commitment().amount != context.funded_amount {
        return Err(rejected());
    }
    let base = Zeroizing::<curve25519_dalek::scalar::Scalar>::new((*spend).into());
    let offset = Zeroizing::<curve25519_dalek::scalar::Scalar>::new(output.key_offset().into());
    let witness = Zeroizing::new(*base + *offset);
    let secret_bytes = Zeroizing::new(witness.to_bytes());
    let proof = prove_input_spend_v23(
        &context,
        output.key().compress().to_bytes(),
        image,
        &secret_bytes,
        &mut rand_core::OsRng,
    )
    .map_err(|_| rejected())?;
    let envelope = InputSpendEnvelopeV23 { context, proof }
        .encode()
        .map_err(|_| rejected())?;
    Ok(CachedInputProofResponseV23 {
        api_version: 23,
        request_nonce: request.build.request_nonce,
        envelope,
    })
}
