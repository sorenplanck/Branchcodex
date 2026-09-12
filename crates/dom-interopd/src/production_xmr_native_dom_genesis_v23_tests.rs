//! Exact existing genesis projection; subsequent snapshot blocks remain simulated.
use super::*;

pub(super) fn projection(identity: &ExpectedDomIdentityV1) -> Result<Value> {
    identity.validate()?;
    let genesis = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?;
    if genesis.hash.as_bytes() != &identity.genesis_hash {
        return Err("compiled genesis differs from authenticated deployment".into());
    }
    let header = dom_consensus::BlockHeader::from_bytes(&genesis.header_bytes)?;
    if header.to_bytes()? != genesis.header_bytes
        || header.height.0 != 0
        || header.prev_hash != dom_core::Hash256::ZERO
    {
        return Err("canonical genesis header rejected".into());
    }
    let coinbase = match genesis.block {
        None if identity.network_magic == dom_core::NETWORK_MAGIC_MAINNET => Value::Null,
        Some(block) if identity.network_magic != dom_core::NETWORK_MAGIC_MAINNET => {
            if !block.transactions.is_empty() {
                return Err("unexpected genesis transaction".into());
            }
            json!({
                "output_commitment":hex::encode(block.coinbase.output.commitment.as_bytes()),
                "explicit_value":block.coinbase.kernel.explicit_value,
                "kernel_excess":hex::encode(block.coinbase.kernel.excess.as_bytes()),
                "kernel_features":block.coinbase.kernel.features,
                "kernel_excess_signature":hex::encode(block.coinbase.kernel.excess_signature),
                "offset":hex::encode(block.coinbase.offset),
                "output_proof_envelope":hex::encode(block.coinbase.output.range_proof_bytes()?),
            })
        }
        _ => return Err("genesis economic representation mismatch".into()),
    };
    let hash = hex::encode(identity.genesis_hash);
    Ok(json!({
        "height":0,"block_hash":hash,"previous_block_hash":hex::encode([0;32]),
        "canonical_header_bytes":hex::encode(genesis.header_bytes),
        "timestamp":header.timestamp.0,"canonical_marker":hash,
        "transactions":[],"coinbase":coinbase,"total_fees_noms":0,
        "protocol_version":header.version,
        "range_proof_serialization_version":identity.range_proof_serialization_version,
    }))
}
