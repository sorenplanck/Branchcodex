//! Deadline/cursor regressions. The traversal seam tests do not mint Claim
//! evidence: real transactions and adaptor proofs keep their original verifier.
use super::*;
use dom_scriptless_chain_adapter::{BearerTokenV1, ExpectedDomIdentityV1};
use std::{
    cell::Cell,
    io::{Read, Write},
    net::TcpListener,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const GENESIS: [u8; 32] = dom_core::GENESIS_HASH_REGTEST;
const MAGIC: u32 = dom_core::NETWORK_MAGIC_REGTEST;

fn identity() -> ObservedDomIdentityV1 {
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        MAGIC,
        &dom_crypto::Hash256::from_bytes(GENESIS),
    );
    ObservedDomIdentityV1 {
        network: "regtest".to_owned(),
        network_magic: MAGIC,
        chain_id: *chain.as_bytes(),
        genesis_hash: GENESIS,
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 60,
        tip_height: 0,
        tip_hash: GENESIS,
    }
}

fn runtime(listener: &TcpListener) -> Result<RealDomRpcRuntimeV1, Box<dyn std::error::Error>> {
    let observed = identity();
    let adapter = DomHttpChainAdapterV1::new(
        &format!("http://{}", listener.local_addr()?),
        ExpectedDomIdentityV1 {
            network: observed.network,
            network_magic: observed.network_magic,
            chain_id: observed.chain_id,
            genesis_hash: observed.genesis_hash,
            protocol_version: observed.protocol_version,
            range_proof_serialization_version: observed.range_proof_serialization_version,
        },
        BearerTokenV1::new("synthetic-bounded-f7-claim".to_owned())?,
        Duration::from_millis(100),
        Duration::from_secs(2),
    )?;
    Ok(RealDomRpcRuntimeV1::new(adapter, 16)?)
}

fn genesis_prefix() -> Result<F7ClaimScanProgressV24, RealDomError> {
    // The fixture seeds only the authenticated genesis, never a transaction
    // or a claimed economic event. Production always begins at genesis itself.
    let mut progress = F7ClaimScanProgressV24::new(Instant::now());
    progress.state.append(0, GENESIS, 16)?;
    Ok(progress)
}

fn empty_tip_page(cursor: ScriptlessScanCursorV1) -> ScriptlessScanPageV1 {
    ScriptlessScanPageV1 {
        identity: identity(),
        blocks: Vec::new(),
        next_cursor: cursor,
        reached_snapshot_tip: true,
    }
}

#[test]
fn expired_deadline_and_busy_progress_never_connect() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let runtime = runtime(&listener)?;
    assert!(matches!(
        runtime.scan_f7_claim_until_v24([1; 32], [2; 33], [3; 32], Instant::now()),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    let held = runtime
        .f7_claim_scan_v24
        .lock()
        .map_err(|_| RealDomError::LockPoisoned)?;
    assert!(matches!(
        runtime.scan_f7_claim_until_v24(
            [1; 32],
            [2; 33],
            [3; 32],
            Instant::now() + Duration::from_secs(1)
        ),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    assert!(held.is_empty());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn one_original_deadline_reaches_page_and_tip_recheck() -> TestResult {
    let mut progress = genesis_prefix()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let requests = Cell::new(0);
    let observed = scan_pages_until(
        &mut progress,
        [2; 33],
        [3; 32],
        16,
        deadline,
        |cursor, maximum, until| {
            assert_eq!(until, deadline);
            assert_eq!(cursor.next_height, 1);
            assert_eq!(cursor.anchor_hash, Some(GENESIS));
            assert_eq!(
                maximum,
                if requests.get() == 0 {
                    MAX_SCRIPTLESS_SCAN_BLOCKS_V1
                } else {
                    1
                }
            );
            requests.set(requests.get() + 1);
            Ok(empty_tip_page(cursor))
        },
    )?;
    assert_eq!(requests.get(), 2);
    assert_eq!(observed, identity());
    assert!(progress.candidate.is_none());
    Ok(())
}

#[test]
fn no_progress_and_changed_tip_cannot_be_reported_as_claim_absence() -> TestResult {
    for changed_tip in [false, true] {
        let mut progress = genesis_prefix()?;
        let requests = Cell::new(0);
        let result = scan_pages_until(
            &mut progress,
            [2; 33],
            [3; 32],
            16,
            Instant::now() + Duration::from_secs(1),
            |cursor, _, _| {
                let mut page = empty_tip_page(cursor);
                requests.set(requests.get() + 1);
                if changed_tip && requests.get() == 2 {
                    page.identity.tip_height += 1;
                    page.identity.tip_hash = [9; 32];
                } else if !changed_tip {
                    page.reached_snapshot_tip = false;
                }
                Ok(page)
            },
        );
        assert!(matches!(
            result,
            Err(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable
            ))
        ));
        assert_eq!(requests.get(), if changed_tip { 2 } else { 1 });
        assert_eq!(progress.state.next_height, 1);
    }
    Ok(())
}

#[test]
fn late_or_inconsistent_page_never_advances_prefix_or_reports_absence() -> TestResult {
    for late in [false, true] {
        let mut progress = genesis_prefix()?;
        let original = progress.state.clone();
        let calls = Cell::new(0);
        let deadline = Instant::now() + Duration::from_millis(20);
        let result = scan_pages_until(
            &mut progress,
            [2; 33],
            [3; 32],
            16,
            deadline,
            |cursor, _, _| {
                calls.set(calls.get() + 1);
                let mut page = empty_tip_page(cursor);
                if late {
                    std::thread::sleep(Duration::from_millis(40));
                } else {
                    page.next_cursor.next_height += 1;
                }
                Ok(page)
            },
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(progress.state, original);
        assert!(progress.candidate.is_none());
        if late {
            assert!(matches!(
                result,
                Err(RealDomError::Chain(
                    ChainAdapterError::TemporarilyUnavailable
                ))
            ));
        } else {
            assert!(matches!(result, Err(RealDomError::InvalidEvidence)));
        }
    }
    Ok(())
}

#[test]
fn scope_retention_is_bounded_and_an_existing_scope_does_not_evict_others() {
    let mut cache = BTreeMap::new();
    let now = Instant::now();
    for key in 1..=4 {
        reserve_scope(
            &mut cache,
            [key; 32],
            now + Duration::from_millis(u64::from(key)),
        );
    }
    reserve_scope(&mut cache, [1; 32], now + Duration::from_secs(1));
    assert_eq!(cache.len(), 4);
    reserve_scope(&mut cache, [5; 32], now + Duration::from_secs(2));
    assert_eq!(cache.len(), 4);
    assert!(cache.contains_key(&[1; 32]));
    assert!(!cache.contains_key(&[2; 32]));
    assert!(cache.contains_key(&[5; 32]));
}

fn read_request(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 8192 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn accept_until(listener: &TcpListener, deadline: Instant) -> std::io::Result<std::net::TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn real_rpc_reorg_and_authentication_refusal_discard_cached_prefix() -> TestResult {
    for status in [409, 401] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let runtime = runtime(&listener)?;
        runtime
            .f7_claim_scan_v24
            .lock()
            .map_err(|_| RealDomError::LockPoisoned)?
            .insert([1; 32], genesis_prefix()?);
        let server = std::thread::spawn(move || -> std::io::Result<String> {
            let mut stream = accept_until(&listener, Instant::now() + Duration::from_secs(2))?;
            let request = read_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )?;
            Ok(request)
        });
        let observed = runtime.scan_f7_claim_until_v24(
            [1; 32],
            [2; 33],
            [3; 32],
            Instant::now() + Duration::from_secs(1),
        );
        let request = server.join().map_err(|_| "F7 scanner fixture panicked")??;
        assert!(request.contains("from=1&to=64"));
        assert!(request.contains(&format!("anchor_hash={}", hex::encode(GENESIS))));
        assert!(runtime
            .f7_claim_scan_v24
            .lock()
            .map_err(|_| RealDomError::LockPoisoned)?
            .is_empty());
        if status == 409 {
            assert!(matches!(
                observed,
                Err(RealDomError::Chain(
                    ChainAdapterError::TemporarilyUnavailable
                ))
            ));
        } else {
            assert!(matches!(
                observed,
                Err(RealDomError::Chain(ChainAdapterError::AuthenticationFailed))
            ));
        }
    }
    Ok(())
}

#[test]
fn real_rpc_rechecks_authenticated_prefix_before_completing_empty_snapshot() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let runtime = runtime(&listener)?;
    runtime
        .f7_claim_scan_v24
        .lock()
        .map_err(|_| RealDomError::LockPoisoned)?
        .insert([1; 32], genesis_prefix()?);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        for maximum in [MAX_SCRIPTLESS_SCAN_BLOCKS_V1, 1] {
            let mut stream = accept_until(&listener, Instant::now() + Duration::from_secs(2))?;
            let request = read_request(&mut stream)?;
            if !request.contains(&format!("from=1&to={maximum}"))
                || !request.contains(&format!("anchor_hash={}", hex::encode(GENESIS)))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incorrect F7 cursor",
                ));
            }
            let observed = identity();
            let response = serde_json::json!({
                "schema_version": 1, "status": "ok", "canonical": true,
                "identity": {
                    "network": observed.network, "network_magic": MAGIC,
                    "chain_id": hex::encode(observed.chain_id),
                    "genesis_hash": hex::encode(GENESIS),
                    "protocol_version": observed.protocol_version,
                    "range_proof_serialization_version": observed.range_proof_serialization_version,
                    "coinbase_maturity": observed.coinbase_maturity,
                    "tip_height": 0, "tip_hash": hex::encode(GENESIS)
                },
                "requested_from": 1, "requested_to": maximum, "served_from": 1, "served_to": null,
                "request_anchor": { "height": 0, "block_hash": hex::encode(GENESIS) },
                "blocks": [], "continuation": null
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )?;
        }
        Ok(())
    });
    let observed = runtime.scan_f7_claim_until_v24(
        [1; 32],
        [2; 33],
        [3; 32],
        Instant::now() + Duration::from_secs(2),
    );
    server
        .join()
        .map_err(|_| "F7 empty-snapshot fixture panicked")??;
    let (candidate, observed) = observed?;
    assert!(candidate.is_none());
    assert_eq!(observed, identity());
    assert_eq!(
        runtime
            .f7_claim_scan_v24
            .lock()
            .map_err(|_| RealDomError::LockPoisoned)?
            .get(&[1; 32])
            .ok_or("F7 prefix missing")?
            .state
            .next_height,
        1
    );
    Ok(())
}

#[test]
fn trickling_http_body_cannot_rebase_original_read_deadline() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let runtime = runtime(&listener)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = accept_until(&listener, Instant::now() + Duration::from_secs(2))?;
        let _request = read_request(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")?;
        for _ in 0..8 {
            if stream.write_all(b" ").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        Ok(())
    });
    let started = Instant::now();
    let observed = runtime.scan_f7_claim_until_v24(
        [1; 32],
        [2; 33],
        [3; 32],
        started + Duration::from_millis(100),
    );
    let elapsed = started.elapsed();
    // Always reap even when an assertion below fails. This test creates no
    // timeout worker on the client and never detaches its fixture server.
    server
        .join()
        .map_err(|_| "F7 trickling fixture panicked")??;
    assert!(matches!(
        observed,
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    assert!(
        elapsed < Duration::from_secs(1),
        "read exceeded the original budget: {elapsed:?}"
    );
    Ok(())
}
