//! No chain fixture or crypto proving work is needed to check a closed bound.
use super::*;
use dom_scriptless_chain_adapter::{BearerTokenV1, ExpectedDomIdentityV1};
use std::net::{TcpListener, TcpStream};

fn unopened_runtime() -> Result<(RealDomRpcRuntimeV1, TcpListener), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let genesis =
        dom_core::startup_genesis_hash_for_network_magic(dom_core::NETWORK_MAGIC_REGTEST)?;
    let adapter = DomHttpChainAdapterV1::new(
        &format!("http://{}", listener.local_addr()?),
        ExpectedDomIdentityV1 {
            network: "regtest".to_owned(),
            network_magic: dom_core::NETWORK_MAGIC_REGTEST,
            chain_id: *dom_consensus::derive_chain_id(dom_core::NETWORK_MAGIC_REGTEST, &genesis)
                .as_bytes(),
            genesis_hash: *genesis.as_bytes(),
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        },
        BearerTokenV1::new("funding-bound-test".to_owned())?,
        Duration::from_millis(50),
        Duration::from_millis(50),
    )?;
    Ok((RealDomRpcRuntimeV1::new(adapter, 16)?, listener))
}

fn no_connection(result: std::io::Result<(TcpStream, std::net::SocketAddr)>) {
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn expired_funding_deadline_neither_scans_nor_posts_v23() -> Result<(), Box<dyn std::error::Error>>
{
    let (runtime, listener) = unopened_runtime()?;
    let deadline = Instant::now();
    assert!(matches!(
        runtime.current_transaction_validation_context_until_v23(deadline),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    let mut broadcaster = BoundedDomFundingBroadcasterV23 {
        adapter: &runtime.adapter,
        deadline,
    };
    // Even malformed bytes cannot trigger parsing/network work after expiry.
    assert!(matches!(
        broadcaster.broadcast_exact_funding(&[]),
        Err(ChainAdapterError::TemporarilyUnavailable)
    ));
    no_connection(listener.accept());
    Ok(())
}

#[test]
fn expired_funding_reconciliation_cannot_mint_from_cached_progress_v23(
) -> Result<(), Box<dyn std::error::Error>> {
    let (runtime, listener) = unopened_runtime()?;
    let evidence = EvidenceRefV1 {
        chain_id: ChainId(runtime.expected_identity().chain_id),
        tx_id: [1; 32],
        event_index: 0,
        block_height: 0,
        block_anchor: [0; 32],
    };
    assert!(matches!(
        runtime.verified_funding_finality_until_v23(
            &evidence,
            [1; 32],
            [2; 33],
            6,
            12,
            Instant::now(),
        ),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    assert!(runtime
        .funding_finality_scan_v23
        .try_lock()
        .map_err(|_| "scan cache lock")?
        .is_empty());
    no_connection(listener.accept());
    Ok(())
}
