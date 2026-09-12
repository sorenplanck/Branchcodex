//! Genuine native coinbase material for an otherwise transaction-empty local
//! RPC baseline. Headers remain a simulation, not mined or admitted blocks.
use super::*;

pub(super) fn projection(chain_id: &[u8; 32], height: u64) -> Result<Value> {
    Ok(material_v23(chain_id, height, 0)?.1)
}

pub(super) fn material_v23(
    chain_id: &[u8; 32],
    height: u64,
    fees: u64,
) -> Result<(super::ledger_v23::ValidatedDomCoinbaseV23, Value)> {
    use dom_crypto::{pedersen::Commitment, BlindingFactor};
    let mut scope = chain_id.to_vec();
    scope.extend_from_slice(&height.to_be_bytes());
    let blind_hash = dom_crypto::blake2b_256_tagged("DOM/OfflineBaseline/Coinbase/V23", &scope);
    let blinding = BlindingFactor::from_bytes(*blind_hash.as_bytes())?;
    let nonce =
        *dom_crypto::blake2b_256_tagged("DOM/OfflineBaseline/ProofNonce/V23", &scope).as_bytes();
    let value = dom_core::block_reward(dom_core::BlockHeight(height))
        .noms()
        .checked_add(fees)
        .ok_or("coinbase reward overflow")?;
    let commitment = Commitment::commit(value, &blinding);
    let (proof, actual) = dom_crypto::range_proof_prove_bytes_with_nonce(value, &blinding, &nonce)?;
    if actual != *commitment.as_bytes() {
        return Err("baseline coinbase proof mismatch".into());
    }
    let mut message = vec![dom_core::KERNEL_FEAT_COINBASE];
    message.extend_from_slice(&value.to_le_bytes());
    let message = dom_crypto::blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &message);
    let secret = dom_crypto::keys::SecretKey::from_bytes(blinding.as_bytes())?;
    let signature = dom_crypto::schnorr_sign(&secret, message.as_bytes(), chain_id)?;
    let coinbase = dom_consensus::CoinbaseTransaction {
        output: dom_consensus::TransactionOutput { commitment, proof },
        kernel: dom_consensus::CoinbaseKernel {
            features: dom_core::KERNEL_FEAT_COINBASE,
            explicit_value: value,
            excess: Commitment::commit(0, &blinding),
            excess_signature: signature.to_bytes(),
        },
        offset: [0; 32],
    };
    let validated =
        super::ledger_v23::ValidatedDomCoinbaseV23::new(*chain_id, height, fees, coinbase)?;
    let coinbase = validated.coinbase();
    let projection = json!({
        "output_commitment":hex::encode(coinbase.output.commitment.as_bytes()),
        "explicit_value":coinbase.kernel.explicit_value,
        "kernel_excess":hex::encode(coinbase.kernel.excess.as_bytes()),
        "kernel_features":coinbase.kernel.features,
        "kernel_excess_signature":hex::encode(coinbase.kernel.excess_signature),
        "offset":hex::encode(coinbase.offset),
        "output_proof_envelope":hex::encode(coinbase.output.range_proof_bytes()?),
    });
    Ok((validated, projection))
}

/// Move-only wallet provenance for the exact native baseline coinbase.
/// This is synthetic test funding, never a live-chain key or an RPC grant.
pub(super) fn wallet_output_v23(
    chain_id: &[u8; 32],
    height: u64,
    block_hash: [u8; 32],
    now: u64,
) -> Result<dom_wallet2::StoredOutput> {
    if height == 0 || block_hash == [0; 32] || now == 0 {
        return Err("baseline wallet output scope".into());
    }
    let mut scope = chain_id.to_vec();
    scope.extend_from_slice(&height.to_be_bytes());
    let hash = dom_crypto::blake2b_256_tagged("DOM/OfflineBaseline/Coinbase/V23", &scope);
    let blind = dom_crypto::BlindingFactor::from_bytes(*hash.as_bytes())?;
    let value = dom_core::block_reward(dom_core::BlockHeight(height)).noms();
    let mut output = dom_wallet2::StoredOutput::new_unconfirmed(
        *dom_crypto::pedersen::Commitment::commit(value, &blind).as_bytes(),
        value,
        *blind.as_bytes(),
        dom_wallet2::OutputOrigin::Coinbase,
        true,
        None,
        now,
    );
    output.confirm(
        dom_wallet2::BlockRef {
            height,
            hash: block_hash,
        },
        now,
    )?;
    Ok(output)
}
