use super::epee::Ledger;
use super::*;
use crate::{
    AddressType, Change, DalekScalar, Decoys, FeeRate, MoneroAddress, Network, OutputWithDecoys,
    RctType, Request, Scalar, SignableTransaction, ViewPair, Zeroizing, build, point,
};

fn ledger() -> Result<Snapshot> {
    let request = Request {
        route_peer: None,
        position: 0,
        schema: "DOM-XMR-OFFLINE-FUNDING-REQUEST-V23".into(),
        network_tag: 1,
        combined_spend_public_key: hex::encode(point(11).compress().to_bytes()),
        amount_piconero: 1_000_000,
        max_fee_piconero: 1_000_000,
        recipient_view_public_key: None,
    };
    Snapshot::new(build(&request)?.0, 1)
}

/// Sign with the real known secret of an actual synthetic miner output. This
/// is not a made-up ring: every index/key/commitment comes from this ledger.
fn candidate(ledger: &Snapshot, marker: u8) -> Result<Transaction> {
    let ring = ledger.outputs[..16]
        .iter()
        .map(|output| {
            Ok([
                monero_oxide_wallet::ed25519::CompressedPoint::from(output.key)
                    .decompress()
                    .ok_or_else(|| anyhow!("test ring key"))?,
                monero_oxide_wallet::ed25519::CompressedPoint::from(output.mask)
                    .decompress()
                    .ok_or_else(|| anyhow!("test ring mask"))?,
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let mut offsets = vec![1; 16];
    offsets[0] = 0;
    let decoys = Decoys::new(offsets, 0, ring).ok_or_else(|| anyhow!("test retained decoys"))?;
    let mut commitment = Commitment::zero();
    commitment.amount = 1_000_000_000;
    let mut input_bytes = ledger.outputs[0].key.to_vec();
    Scalar::ZERO.write(&mut input_bytes)?;
    commitment.write(&mut input_bytes)?;
    decoys.write(&mut input_bytes)?;
    let input = OutputWithDecoys::read(&mut input_bytes.as_slice())?;
    let spend = Zeroizing::new(Scalar::from(DalekScalar::from(20_008u64)));
    let address = MoneroAddress::new(Network::Mainnet, AddressType::Legacy, point(23), point(13));
    let change = ViewPair::new(
        point(20_008),
        Zeroizing::new(Scalar::from(DalekScalar::from(47u64))),
    )?;
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new([marker; 32]),
        vec![input],
        vec![(address, 100_000_000)],
        Change::new(change, None),
        vec![],
        FeeRate::new(1, 1).ok_or_else(|| anyhow!("test fee"))?,
    )?;
    Ok(signable.sign(&mut rand::rngs::OsRng, &spend)?)
}

#[test]
fn signed_local_spend_requires_opt_in_and_private_inclusion() -> Result<()> {
    let mut ledger = ledger()?;
    let tx = candidate(&ledger, 91)?;
    let raw = tx.serialize();
    assert!(ledger.submit(&raw).is_err());
    ledger.enable_mutable_scenario();
    let hash = ledger.submit(&raw)?;
    assert_eq!(hash, tx.hash());
    assert_eq!(ledger.submit(&raw)?, hash);
    assert_eq!(ledger.tip(), TIP_HEIGHT);
    assert!(ledger.transactions.get(&hash).is_none());
    let Input::ToKey { key_image, .. } = &tx.prefix().inputs[0] else {
        return Err(anyhow!("test input"));
    };
    assert_eq!(ledger.key_image_status(key_image.to_bytes()), 2);
    let response = ledger.transaction_response(&[json!(hex::encode(hash))])?;
    assert_eq!(response["txs"][0]["in_pool"], true);
    assert!(ledger.submit(&candidate(&ledger, 92)?.serialize()).is_err());
    let original_tip_hash = ledger.block(TIP_HEIGHT)?.hash();
    let timestamp = ledger.block(TIP_HEIGHT)?.header.timestamp;
    ledger.advance(TIP_HEIGHT + 12, timestamp, &[hash])?;
    assert_eq!(
        ledger.block(TIP_HEIGHT + 1)?.header.previous,
        original_tip_hash
    );
    assert_eq!(
        ledger.transactions.get(&hash).unwrap().height,
        TIP_HEIGHT + 1
    );
    assert_eq!(ledger.key_image_status(key_image.to_bytes()), 1);
    assert!(ledger.pool.is_empty());
    assert_eq!(ledger.submit(&raw)?, hash);
    let indexes = ledger.output_indexes(hash)?;
    assert!(
        ledger
            .outputs(&indexes)?
            .iter()
            .all(|output| output.unlocked)
    );
    let scanned = ledger.scannable_blocks(TIP_HEIGHT + 1, 12)?;
    assert_eq!(scanned.len(), 12);
    assert_eq!(scanned[0].transactions.len(), 1);
    assert!(
        scanned
            .iter()
            .skip(1)
            .all(|block| block.transactions.is_empty())
    );
    let counts = ledger.cumulative_distribution(TIP_HEIGHT, TIP_HEIGHT + 12)?;
    assert_eq!(counts.len(), 13);
    assert!(counts.windows(2).all(|pair| pair[0] < pair[1]));
    Ok(())
}

#[test]
fn malformed_or_foreign_ring_candidates_never_change_pool() -> Result<()> {
    let mut ledger = ledger()?;
    ledger.enable_mutable_scenario();
    let signed = candidate(&ledger, 91)?;
    let mut trailing = signed.serialize();
    trailing.push(0);
    assert!(ledger.submit(&trailing).is_err());
    let mut wrong_ring = signed.clone();
    let Transaction::V2 { prefix, .. } = &mut wrong_ring else {
        return Err(anyhow!("test tx"));
    };
    let Input::ToKey { key_offsets, .. } = &mut prefix.inputs[0] else {
        return Err(anyhow!("test input"));
    };
    key_offsets[0] += 1;
    assert!(ledger.submit(&wrong_ring.serialize()).is_err());
    let mut wrong_amount = signed.clone();
    let Transaction::V2 {
        proofs: Some(proofs),
        ..
    } = &mut wrong_amount
    else {
        return Err(anyhow!("test proofs"));
    };
    proofs.base.fee += 1;
    assert!(ledger.submit(&wrong_amount.serialize()).is_err());
    let mut wrong_proof = signed.serialize();
    let last = wrong_proof
        .last_mut()
        .ok_or_else(|| anyhow!("test bytes"))?;
    *last ^= 1;
    assert!(ledger.submit(&wrong_proof).is_err());
    assert!(ledger.pool.is_empty());
    assert_eq!(ledger.tip(), TIP_HEIGHT);
    Ok(())
}

#[test]
fn private_advance_refuses_unknown_inclusion_rollback_and_bounds() -> Result<()> {
    let mut ledger = ledger()?;
    let timestamp = ledger.block(TIP_HEIGHT)?.header.timestamp;
    assert!(ledger.advance(TIP_HEIGHT + 1, timestamp, &[]).is_err());
    ledger.enable_mutable_scenario();
    assert!(ledger.advance(TIP_HEIGHT, timestamp, &[]).is_err());
    assert!(
        ledger
            .advance(MAX_SCENARIO_HEIGHT + 1, timestamp, &[])
            .is_err()
    );
    assert!(ledger.advance(TIP_HEIGHT + 1, timestamp - 1, &[]).is_err());
    assert!(ledger.advance(TIP_HEIGHT + 1, u64::MAX, &[]).is_err());
    assert!(
        ledger
            .advance(TIP_HEIGHT + 1, timestamp, &[[99; 32]])
            .is_err()
    );
    assert_eq!(ledger.tip(), TIP_HEIGHT);
    assert_eq!(ledger.blocks.len(), TIP_HEIGHT as usize);
    Ok(())
}

#[test]
fn mutable_route_starts_with_only_source_roots_and_inventory_not_contract_funding() -> Result<()> {
    let source = Snapshot::source_roots([1_001_000_000; 3], 1)?;
    let mut transactions = Vec::new();
    for position in 0..3 {
        let request = Request {
            route_peer: None,
            position,
            schema: "DOM-XMR-OFFLINE-FUNDING-REQUEST-V23".into(),
            network_tag: 1,
            combined_spend_public_key: hex::encode(
                point(11 + u64::from(position)).compress().to_bytes(),
            ),
            amount_piconero: 1_000_000,
            max_fee_piconero: 1_000_000,
            recipient_view_public_key: None,
        };
        let tx = crate::build_with_input(&request, Some(source.source_input(position)?))?.0;
        source.validate_candidate(&tx)?;
        transactions.push(tx);
    }
    let inventory = transactions
        .pop()
        .ok_or_else(|| anyhow!("test inventory"))?;
    let inventory_hash = inventory.hash();
    let source_metadata = source.source_metadata()?;
    let mut ledger = source.with_initial_inventory(inventory)?;
    assert_eq!(ledger.source_metadata()?, source_metadata);
    assert_eq!(ledger.non_miner_heights.len(), 1);
    assert_eq!(ledger.non_miner_heights[&inventory_hash], 102);
    assert!(ledger.pool.is_empty());
    for tx in &transactions {
        let response = ledger.transaction_response(&[json!(hex::encode(tx.hash()))])?;
        assert_eq!(response["txs"], json!([]));
        assert_eq!(response["missed_tx"], json!([hex::encode(tx.hash())]));
        ledger.validate_candidate(tx)?;
    }
    // Only the runtime's later exact submission creates a pool reservation;
    // the supervisor must still separately include it before confirmations.
    let first = ledger.submit(&transactions[0].serialize())?;
    assert_eq!(ledger.pool.len(), 1);
    assert_eq!(ledger.non_miner_heights.len(), 1);
    assert!(
        ledger.transaction_response(&[json!(hex::encode(first))])?["txs"][0]["in_pool"] == true
    );
    Ok(())
}
