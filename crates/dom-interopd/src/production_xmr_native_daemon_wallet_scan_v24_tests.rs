//! A real HTTP request regression, without building the expensive chain/graph.
//! The endpoint deliberately refuses: this checks the requested public range,
//! never fabricates a coinbase, accepted response, wallet or funding authority.
use super::*;
use dom_scriptless_chain_adapter::{
    BearerTokenV1, ChainAdapterError, DomHttpChainAdapterV1, ExpectedDomIdentityV1,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

#[test]
fn baseline_scan_requests_genesis_and_all_three_wallet_origins_v24() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        dom_core::NETWORK_MAGIC_MAINNET,
        &dom_crypto::Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
    let adapter = DomHttpChainAdapterV1::new(
        &endpoint,
        ExpectedDomIdentityV1 {
            network: "mainnet".to_owned(),
            network_magic: dom_core::NETWORK_MAGIC_MAINNET,
            chain_id: *chain.as_bytes(),
            genesis_hash: dom_core::GENESIS_HASH_MAINNET,
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        },
        BearerTokenV1::new("synthetic-wallet-scan-range".to_owned())?,
        Duration::from_millis(100),
        Duration::from_secs(1),
    )?;
    let server = std::thread::spawn(move || -> std::io::Result<String> {
        let until = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        stream.write_all(
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        String::from_utf8(request)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    });
    let observed = scan_baseline_wallet_inputs_v24(&adapter);
    // Join before any assertion, including unexpected refusal classifications.
    let request = server
        .join()
        .map_err(|_| "wallet scanner fixture panicked")??;
    let error = observed.expect_err("the endpoint never grants chain evidence");
    assert!(matches!(
        error.downcast_ref::<ChainAdapterError>(),
        Some(ChainAdapterError::TemporarilyUnavailable)
    ));
    assert!(request.starts_with("GET /chain/scan/scriptless/v1?from=0&to=3&"));
    assert!(request.contains(&format!(
        "expected_chain_id={}",
        hex::encode(chain.as_bytes())
    )));
    assert!(!request.contains("anchor_hash="));
    Ok(())
}
