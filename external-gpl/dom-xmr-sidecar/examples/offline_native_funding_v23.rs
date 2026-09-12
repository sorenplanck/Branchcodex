//! Offline GPL component fixture; never a wallet or network funding tool.
//! The synthetic input/ring has no chain UTXO. The output is a complete signed
//! V2 CLSAG/Bulletproofs+ transaction scanned by the pinned wallet implementation.
//! No DOM authority or claimed network confirmation is emitted here.
use anyhow::{Context, Result, anyhow, ensure};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar as DalekScalar};
use monero_oxide_wallet::{
    OutputWithDecoys, ViewPair,
    address::{AddressType, MoneroAddress, Network},
    ed25519::{Commitment, CompressedPoint, Point, Scalar},
    interface::FeeRate,
    ringct::{RctType, clsag::Decoys},
    send::{Change, SignableTransaction},
    transaction::Transaction,
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use zeroize::Zeroizing;

#[path = "offline_native_funding_v23/route.rs"]
mod route;
#[path = "offline_native_funding_v23/rpc.rs"]
mod rpc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    route_peer: Option<route::PeerRequest>,
    #[serde(skip)]
    position: u8,
    schema: String,
    #[serde(default = "legacy_network_tag")]
    network_tag: u8,
    combined_spend_public_key: String,
    amount_piconero: u64,
    max_fee_piconero: u64,
    #[serde(default)]
    recipient_view_public_key: Option<String>,
}

#[derive(Serialize)]
struct PublicEnvelope {
    schema: &'static str,
    scope: &'static str,
    combined_spend_public_key: String,
    view_public_key: String,
    amount_piconero: u64,
    destination: String,
    funding_tx_hash: String,
    canonical_transaction: String,
    daemon_urls: Vec<String>,
}

fn legacy_network_tag() -> u8 {
    2
}

fn point(value: u64) -> Point {
    Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(value))
}

fn build(request: &Request) -> Result<(Transaction, Point, String)> {
    ensure!(
        request.schema == "DOM-XMR-OFFLINE-FUNDING-REQUEST-V23",
        "fixture schema mismatch"
    );
    ensure!(
        request.amount_piconero > 0 && request.amount_piconero <= 1_000_000_000_000_000,
        "fixture payment bound"
    );
    let input_amount = request
        .amount_piconero
        .checked_add(1_000_000_000)
        .ok_or_else(|| anyhow!("fixture amount overflow"))?;
    let spend_bytes = hex::decode(&request.combined_spend_public_key)?;
    ensure!(spend_bytes.len() == 32, "spend key length");
    let spend = CompressedPoint::read(&mut spend_bytes.as_slice())?
        .decompress()
        .ok_or_else(|| anyhow!("invalid spend point"))?;
    ensure!(
        spend.into().is_torsion_free() && spend != point(0),
        "invalid recipient subgroup"
    );
    // Route deposits use the test-only shared view key installed by native
    // custody. The separate solver-inventory account supplies its public view
    // point explicitly; no private wallet key crosses this helper boundary.
    let recipient_view = match request.recipient_view_public_key.as_deref() {
        Some(encoded) => {
            let bytes: [u8; 32] = hex::decode(encoded)?
                .try_into()
                .map_err(|_| anyhow!("view key length"))?;
            let point = CompressedPoint::read(&mut bytes.as_slice())?
                .decompress()
                .ok_or_else(|| anyhow!("invalid view point"))?;
            ensure!(
                point.into().is_torsion_free() && point != self::point(0),
                "invalid view subgroup"
            );
            point
        }
        None => point(13),
    };
    let address = MoneroAddress::new(
        match request.network_tag {
            1 => Network::Mainnet,
            2 => Network::Stagenet,
            _ => return Err(anyhow!("unsupported explicit offline network")),
        },
        AddressType::Legacy,
        spend,
        recipient_view,
    );
    let offset = u64::from(request.position) * 32;
    let sender = Zeroizing::new(Scalar::from(DalekScalar::from(41u64 + offset)));
    let mask = Scalar::from(DalekScalar::from(43u64 + offset));
    let commitment = Commitment::new(mask, input_amount);
    let mut ring = Vec::with_capacity(16);
    ring.push([point(41 + offset), commitment.commit()]);
    for index in 1..16u64 {
        ring.push([
            point(100 + offset + index),
            Commitment::new(
                Scalar::from(DalekScalar::from(200 + offset + index)),
                input_amount + index,
            )
            .commit(),
        ]);
    }
    let decoys =
        Decoys::new(vec![1; 16], 0, ring).ok_or_else(|| anyhow!("invalid offline ring"))?;
    // Public upstream serialization of OutputData followed by Decoys. This is
    // synthetic input custody for a mathematical fixture, NOT a chain output
    // observation. SignableTransaction validates and signs it with its true key.
    let mut input_bytes = Vec::new();
    input_bytes.extend_from_slice(&point(41 + offset).compress().to_bytes());
    Scalar::from(DalekScalar::ZERO).write(&mut input_bytes)?;
    commitment.write(&mut input_bytes)?;
    decoys.write(&mut input_bytes)?;
    let mut input_reader = input_bytes.as_slice();
    let input = OutputWithDecoys::read(&mut input_reader)?;
    ensure!(input_reader.is_empty(), "offline input codec trailing data");
    let change = ViewPair::new(
        point(41 + offset),
        Zeroizing::new(Scalar::from(DalekScalar::from(47u64 + offset))),
    )?;
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new([0x91 + request.position; 32]),
        vec![input],
        vec![(address.clone(), request.amount_piconero)],
        Change::new(change, None),
        vec![],
        FeeRate::new(1, 1).ok_or_else(|| anyhow!("invalid fixture fee"))?,
    )?;
    let transaction = signable.sign(&mut rand::rngs::OsRng, &sender)?;
    ensure!(transaction.version() == 2, "not a V2 transaction");
    let Transaction::V2 {
        proofs: Some(proofs),
        ..
    } = &transaction
    else {
        return Err(anyhow!("missing RingCT proofs"));
    };
    ensure!(
        request.max_fee_piconero > 0 && proofs.base.fee <= request.max_fee_piconero,
        "signed fixture fee exceeds negotiated cap"
    );
    let bytes = transaction.serialize();
    let mut read = bytes.as_slice();
    let decoded = Transaction::read(&mut read)?;
    ensure!(
        read.is_empty() && decoded.serialize() == bytes,
        "noncanonical signed transaction"
    );
    ensure!(
        decoded.hash() == transaction.hash(),
        "transaction hash changed"
    );
    Ok((transaction, spend, address.to_string()))
}

fn main() -> Result<()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    let count = input.by_ref().take(4097).read_line(&mut line)?;
    ensure!(
        count > 0 && count <= 4096 && line.ends_with('\n'),
        "bounded request required"
    );
    let mut request: Request = serde_json::from_str(&line)?;
    let (transaction, spend, destination) = build(&request)?;
    if let Some(peer) = request.route_peer.take() {
        return route::serve(request, peer, transaction, spend, destination, input);
    }
    let hash = transaction.hash();
    let bytes = transaction.serialize();
    let servers = rpc::Servers::start(transaction, request.network_tag)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(async {
            // The real concrete provider authenticates pruned bytes against hash,
            // then the real GPL scanner checks key derivation and encrypted amount.
            let provider =
                monero_simple_request_rpc::SimpleRequestTransport::new(servers.urls()[0].clone())
                    .await?;
            let received = monero_wallet_ng::verify::largest_received_utxo(
                &provider,
                hash,
                spend,
                Zeroizing::new(Scalar::from(DalekScalar::from(13u64))),
            )
            .await?;
            ensure!(
                received == Some(request.amount_piconero),
                "real scanner did not recognize native output"
            );
            let wrong_view = monero_wallet_ng::verify::largest_received_utxo(
                &provider,
                hash,
                spend,
                Zeroizing::new(Scalar::from(DalekScalar::from(14u64))),
            )
            .await?;
            ensure!(wrong_view.is_none(), "wrong view key recognized output");
            let wrong_spend = monero_wallet_ng::verify::largest_received_utxo(
                &provider,
                hash,
                point(97),
                Zeroizing::new(Scalar::from(DalekScalar::from(13u64))),
            )
            .await?;
            ensure!(wrong_spend.is_none(), "wrong spend key recognized output");
            Ok::<(), anyhow::Error>(())
        })
        .context("offline funding real-provider/real-scanner validation failed")?;
    let envelope = PublicEnvelope {
        schema: "DOM-XMR-OFFLINE-FUNDING-V23",
        scope: "local-component-only-no-chain-funding",
        combined_spend_public_key: request.combined_spend_public_key,
        view_public_key: hex::encode(point(13).compress().to_bytes()),
        amount_piconero: request.amount_piconero,
        destination,
        funding_tx_hash: hex::encode(hash),
        canonical_transaction: hex::encode(bytes),
        daemon_urls: servers.urls().to_vec(),
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &envelope)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    // Parent retains this process as the fixture's read-only RPC owner. EOF or
    // explicit STOP closes the servers; no background orphan or broadcast.
    line.clear();
    let read = input.by_ref().take(6).read_line(&mut line)?;
    ensure!(
        read == 0 || line == "STOP\n",
        "invalid fixture shutdown command"
    );
    servers.finish()?;
    Ok(())
}
