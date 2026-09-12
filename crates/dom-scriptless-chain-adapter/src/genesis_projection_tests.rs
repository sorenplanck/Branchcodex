//! RPC projection regressions only: these tests do not admit blocks or change genesis.

use super::*;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn expected(network: &str, magic: u32) -> TestResult<ExpectedDomIdentityV1> {
    let genesis = dom_core::startup_genesis_hash_for_network_magic(magic)?;
    Ok(ExpectedDomIdentityV1 {
        network: network.to_owned(),
        network_magic: magic,
        chain_id: *dom_consensus::derive_chain_id(magic, &genesis).as_bytes(),
        genesis_hash: *genesis.as_bytes(),
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
    })
}

fn projection(identity: &ExpectedDomIdentityV1) -> TestResult<Value> {
    let genesis = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?;
    let header = BlockHeader::from_bytes(&genesis.header_bytes)?;
    assert_eq!(genesis.hash.as_bytes(), &identity.genesis_hash);
    Ok(json!({
        "schema_version": SCRIPTLESS_SCAN_SCHEMA_V1,
        "status": "ok", "canonical": true,
        "identity": {
            "network": identity.network, "network_magic": identity.network_magic,
            "chain_id": hex::encode(identity.chain_id),
            "genesis_hash": hex::encode(identity.genesis_hash),
            "protocol_version": identity.protocol_version,
            "range_proof_serialization_version": identity.range_proof_serialization_version,
            "coinbase_maturity": 60, "tip_height": 0,
            "tip_hash": hex::encode(genesis.hash.as_bytes())
        },
        "requested_from": 0, "requested_to": 0, "served_from": 0, "served_to": 0,
        "request_anchor": null, "continuation": null,
        "blocks": [{
            "height": 0, "block_hash": hex::encode(genesis.hash.as_bytes()),
            "previous_block_hash": hex::encode(header.prev_hash.as_bytes()),
            "canonical_header_bytes": hex::encode(genesis.header_bytes),
            "timestamp": header.timestamp.0,
            "canonical_marker": hex::encode(genesis.hash.as_bytes()),
            "transactions": [], "coinbase": null, "total_fees_noms": 0,
            "protocol_version": header.version,
            "range_proof_serialization_version": identity.range_proof_serialization_version
        }]
    }))
}

fn scan(identity: &ExpectedDomIdentityV1, wire: Value) -> TestResult<ScriptlessScanPageV1> {
    // Include the actual serde boundary, not a hand-constructed authenticated DTO.
    let dto: ScanResponseDto = serde_json::from_value(wire)?;
    Ok(validate_scan_response(
        identity,
        ScriptlessScanCursorV1::genesis(),
        0,
        dto,
    )?)
}

fn legacy_coinbase(identity: &ExpectedDomIdentityV1) -> TestResult<Value> {
    let genesis = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?;
    let block = genesis
        .block
        .ok_or("legacy genesis must contain a coinbase")?;
    let coinbase = block.coinbase;
    Ok(json!({
        "output_commitment": hex::encode(coinbase.output.commitment.as_bytes()),
        "explicit_value": coinbase.kernel.explicit_value,
        "kernel_excess": hex::encode(coinbase.kernel.excess.as_bytes()),
        "kernel_features": coinbase.kernel.features,
        "kernel_excess_signature": hex::encode(coinbase.kernel.excess_signature),
        "offset": hex::encode(coinbase.offset),
        "output_proof_envelope": hex::encode(coinbase.output.range_proof_bytes()?)
    }))
}

#[test]
fn canonical_mainnet_empty_genesis_projection_is_readable() -> TestResult {
    let identity = expected("mainnet", dom_core::NETWORK_MAGIC_MAINNET)?;
    let genesis = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?;
    assert!(genesis.block.is_none());
    // Mainnet's frozen identifier is the identity envelope, not a new ordinary header hash.
    assert_ne!(
        blake2b_256(&genesis.header_bytes).as_bytes(),
        genesis.hash.as_bytes()
    );
    let page = scan(&identity, projection(&identity)?)?;
    assert_eq!(page.blocks.len(), 1);
    assert_eq!(page.blocks[0].canonical_header_bytes, genesis.header_bytes);
    assert_eq!(page.blocks[0].block_hash, identity.genesis_hash);
    assert!(page.blocks[0].transactions.is_empty());
    assert!(page.reached_snapshot_tip);
    assert_eq!(page.next_cursor.next_height, 1);
    assert_eq!(page.next_cursor.anchor_hash, Some(identity.genesis_hash));
    let mut omitted = projection(&identity)?;
    omitted["blocks"][0]
        .as_object_mut()
        .ok_or("block must be a JSON object")?
        .remove("coinbase");
    assert!(serde_json::from_value::<ScanResponseDto>(omitted).is_err());
    Ok(())
}

#[test]
fn mainnet_empty_genesis_rejects_projection_and_economic_body_mutations() -> TestResult {
    let identity = expected("mainnet", dom_core::NETWORK_MAGIC_MAINNET)?;
    let original = projection(&identity)?;
    let mut cases = Vec::new();

    let mut header = BlockHeader::from_bytes(
        &dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?
            .header_bytes,
    )?;
    header.timestamp.0 = header
        .timestamp
        .0
        .checked_add(1)
        .ok_or("timestamp overflow")?;
    let mut altered = original.clone();
    altered["blocks"][0]["canonical_header_bytes"] = json!(hex::encode(header.to_bytes()?));
    altered["blocks"][0]["timestamp"] = json!(header.timestamp.0);
    cases.push((
        "noncanonical header even with matching projected timestamp",
        altered,
    ));

    let mut altered = original.clone();
    for field in ["block_hash", "canonical_marker"] {
        altered["blocks"][0][field] = json!(hex::encode([0x51; 32]));
    }
    altered["identity"]["tip_hash"] = json!(hex::encode([0x51; 32]));
    cases.push(("substituted hash and marker", altered));

    let mut altered = original.clone();
    altered["blocks"][0]["previous_block_hash"] = json!(hex::encode([0x52; 32]));
    cases.push(("nonzero previous hash", altered));

    let mut altered = original.clone();
    altered["blocks"][0]["coinbase"] =
        legacy_coinbase(&expected("regtest", dom_core::NETWORK_MAGIC_REGTEST)?)?;
    cases.push((
        "well-formed legacy coinbase transplanted into Mainnet",
        altered,
    ));

    let mut altered = original.clone();
    altered["blocks"][0]["transactions"] = json!([{
        "block_height": 0, "block_hash": hex::encode(identity.genesis_hash),
        "transaction_index": 0, "tx_hash": hex::encode([0x53; 32]),
        "canonical_bytes": "", "inputs": [], "outputs": [], "kernels": [],
        "offset": hex::encode([0; 32])
    }]);
    cases.push(("nonempty transaction body", altered));

    let mut altered = original;
    altered["blocks"][0]["total_fees_noms"] = json!(1);
    cases.push(("nonzero fees", altered));

    for (case, wire) in cases {
        // Each mutation remains schema-valid: reject in evidence validation itself.
        let dto: ScanResponseDto = serde_json::from_value(wire)?;
        assert!(
            validate_scan_response(&identity, ScriptlessScanCursorV1::genesis(), 0, dto).is_err(),
            "{case}"
        );
    }
    Ok(())
}

#[test]
fn empty_coinbase_exception_does_not_extend_to_other_networks() -> TestResult {
    for (network, magic) in [
        ("testnet", dom_core::NETWORK_MAGIC_TESTNET),
        ("regtest", dom_core::NETWORK_MAGIC_REGTEST),
    ] {
        let identity = expected(network, magic)?;
        let wire = projection(&identity)?;
        assert!(scan(&identity, wire.clone()).is_err(), "{network}");
        // Existing legacy projection with its real coinbase remains accepted.
        let mut existing = wire;
        existing["blocks"][0]["coinbase"] = legacy_coinbase(&identity)?;
        assert!(scan(&identity, existing)?.reached_snapshot_tip);
    }
    Ok(())
}

#[test]
fn ordinary_header_projection_still_requires_coinbase() -> TestResult {
    let identity = expected("regtest", dom_core::NETWORK_MAGIC_REGTEST)?;
    let genesis = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)?;
    let mut header = BlockHeader::from_bytes(&genesis.header_bytes)?;
    header.height.0 = 1;
    header.prev_hash = genesis.hash;
    let bytes = header.to_bytes()?;
    let hash = *blake2b_256(&bytes).as_bytes();
    let mut wire = projection(&identity)?;
    for field in ["requested_from", "requested_to", "served_from", "served_to"] {
        wire[field] = json!(1);
    }
    wire["request_anchor"] = json!({"height":0,"block_hash":hex::encode(identity.genesis_hash)});
    wire["identity"]["tip_height"] = json!(1);
    wire["identity"]["tip_hash"] = json!(hex::encode(hash));
    wire["blocks"][0]["height"] = json!(1);
    wire["blocks"][0]["previous_block_hash"] = json!(hex::encode(identity.genesis_hash));
    wire["blocks"][0]["canonical_header_bytes"] = json!(hex::encode(bytes));
    for field in ["block_hash", "canonical_marker"] {
        wire["blocks"][0][field] = json!(hex::encode(hash));
    }
    let cursor = ScriptlessScanCursorV1 {
        next_height: 1,
        anchor_hash: Some(identity.genesis_hash),
    };
    let absent: ScanResponseDto = serde_json::from_value(wire.clone())?;
    assert!(validate_scan_response(&identity, cursor, 1, absent).is_err());
    // This exercises projection semantics only, not proof of work or block admission.
    wire["blocks"][0]["coinbase"] = legacy_coinbase(&identity)?;
    let present: ScanResponseDto = serde_json::from_value(wire)?;
    assert!(validate_scan_response(&identity, cursor, 1, present)?.reached_snapshot_tip);
    Ok(())
}
