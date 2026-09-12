//! Two funding transactions on one immutable canonical RPC history.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerRequest {
    combined_spend_public_key: String,
    amount_piconero: u64,
    max_fee_piconero: u64,
    solver_inventory: SolverInventoryRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SolverInventoryRequest {
    spend_public_key: String,
    view_public_key: String,
    amount_piconero: u64,
    max_fee_piconero: u64,
}

#[derive(Serialize)]
struct RouteEnvelope {
    schema: &'static str,
    scope: &'static str,
    legs: [PublicEnvelope; 2],
    solver_inventory: PublicEnvelope,
}

pub(super) fn serve(
    request: Request,
    peer: PeerRequest,
    primary: Transaction,
    primary_spend: Point,
    primary_destination: String,
    mut input: impl Read,
) -> Result<()> {
    ensure!(
        request.network_tag == 1,
        "new offline route requires explicit Mainnet"
    );
    let secondary_request = Request {
        schema: request.schema.clone(),
        network_tag: 1,
        route_peer: None,
        position: 1,
        combined_spend_public_key: peer.combined_spend_public_key,
        amount_piconero: peer.amount_piconero,
        max_fee_piconero: peer.max_fee_piconero,
        recipient_view_public_key: None,
    };
    let inventory_request = Request {
        schema: request.schema.clone(),
        network_tag: 1,
        route_peer: None,
        position: 2,
        combined_spend_public_key: peer.solver_inventory.spend_public_key,
        amount_piconero: peer.solver_inventory.amount_piconero,
        max_fee_piconero: peer.solver_inventory.max_fee_piconero,
        recipient_view_public_key: Some(peer.solver_inventory.view_public_key),
    };
    let (secondary, secondary_spend, secondary_destination) = build(&secondary_request)?;
    let (inventory, inventory_spend, inventory_destination) = build(&inventory_request)?;
    ensure!(
        primary.hash() != secondary.hash()
            && primary.hash() != inventory.hash()
            && secondary.hash() != inventory.hash()
            && primary_spend != secondary_spend
            && primary_spend != inventory_spend
            && secondary_spend != inventory_spend,
        "route funding and solver inventory must be independent"
    );
    let hashes = [primary.hash(), secondary.hash(), inventory.hash()];
    let bytes = [
        primary.serialize(),
        secondary.serialize(),
        inventory.serialize(),
    ];
    let spends = [primary_spend, secondary_spend];
    let amounts = [request.amount_piconero, secondary_request.amount_piconero];
    let servers = rpc::Servers::start_multiple(vec![primary, secondary, inventory], 1)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let provider =
            monero_simple_request_rpc::SimpleRequestTransport::new(servers.urls()[0].clone())
                .await?;
        for position in 0..2 {
            let received = monero_wallet_ng::verify::largest_received_utxo(
                &provider,
                hashes[position],
                spends[position],
                Zeroizing::new(Scalar::from(DalekScalar::from(13u64))),
            )
            .await?;
            ensure!(
                received == Some(amounts[position]),
                "route scanner payment mismatch"
            );
            let wrong = monero_wallet_ng::verify::largest_received_utxo(
                &provider,
                hashes[position],
                spends[position],
                Zeroizing::new(Scalar::from(DalekScalar::from(14u64))),
            )
            .await?;
            ensure!(wrong.is_none(), "wrong route view key recognized payment");
        }
        Ok::<(), anyhow::Error>(())
    })?;
    let [up_bytes, down_bytes, inventory_bytes] = bytes;
    let make = |position: usize, request: Request, destination: String, bytes: Vec<u8>| {
        let view_public_key = request
            .recipient_view_public_key
            .unwrap_or_else(|| hex::encode(point(13).compress().to_bytes()));
        PublicEnvelope {
            schema: "DOM-XMR-OFFLINE-FUNDING-V23",
            scope: "local-component-only-no-chain-funding",
            combined_spend_public_key: request.combined_spend_public_key,
            view_public_key,
            amount_piconero: request.amount_piconero,
            destination,
            funding_tx_hash: hex::encode(hashes[position]),
            canonical_transaction: hex::encode(bytes),
            daemon_urls: servers.urls().to_vec(),
        }
    };
    let envelope = RouteEnvelope {
        schema: "DOM-XMR-OFFLINE-ROUTE-FUNDING-V23",
        scope: "local-route-only-no-chain-funding",
        legs: [
            make(0, request, primary_destination, up_bytes),
            make(1, secondary_request, secondary_destination, down_bytes),
        ],
        solver_inventory: make(2, inventory_request, inventory_destination, inventory_bytes),
    };
    serde_json::to_writer(std::io::stdout().lock(), &envelope)?;
    println!();
    std::io::stdout().flush()?;
    // Own the one common history until the supervisor closes the retained pipe.
    let mut drained = [0; 1024];
    while input.read(&mut drained)? != 0 {}
    drop(servers);
    Ok(())
}
