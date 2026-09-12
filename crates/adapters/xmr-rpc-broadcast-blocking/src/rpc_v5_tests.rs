//! Real local HTTP transport with deterministic daemon responses.
use super::*;
use std::{
    io::Write,
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

fn http(body: serde_json::Value) -> String {
    let body = body.to_string();
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}
fn server(responses: Vec<String>) -> (String, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    listener.set_nonblocking(true).expect("nonblocking accept");
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut count = 0;
        for response in responses {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "expected RPC was not called");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("local accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read bound");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("write bound");
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 2048];
                let read = stream.read(&mut buffer).expect("HTTP request");
                assert!(read > 0 && request.len() + read <= 16_384);
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            stream
                .write_all(response.as_bytes())
                .expect("HTTP response");
            count += 1;
        }
        count
    });
    (endpoint, worker)
}
fn tx_response(hash: [u8; 32]) -> serde_json::Value {
    serde_json::json!({"status":"OK","untrusted":false,"missed_tx":[],
        "txs":[{"tx_hash":hex_lower(&hash),"in_pool":false,"block_height":100}]})
}
fn block(height: u64, hash: [u8; 32]) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":"0","result":{"status":"OK","untrusted":false,
        "block_header":{"height":height,"hash":hex_lower(&hash),"orphan_status":false},
        "tx_hashes":[hex_lower(&[7;32])]}})
}

#[test]
fn url_v5_rejects_credentials_disguised_hosts_paths_and_queries() {
    for input in [
        "http://127.0.0.1:80@evil.example",
        "http://localhost:80@evil.example",
        "http://user@127.0.0.1:18081",
        "http://127.0.0.1.evil.example:18081",
        "http://127.0.0.1:18081/rpc",
        "http://127.0.0.1:18081/?x=1",
        "http://127.0.0.1:18081/#fragment",
        "https://127.0.0.1:18081",
        "http://127.0.0.1:0",
    ] {
        assert!(BlockingMoneroDaemonReaderV1::new(input).is_err(), "{input}");
        assert!(BlockingMoneroBroadcaster::new(input).is_err(), "{input}");
    }
    assert_eq!(
        normalize_loopback_v5("http://localhost:18081/").expect("normalize"),
        normalize_loopback_v5("http://127.0.0.1:18081").expect("canonical")
    );
    assert!(normalize_loopback_v5("http://[::1]:18081").is_ok());
}

#[test]
fn exact_reconciliation_v5_never_accepts_an_unrelated_or_contradictory_tx() {
    for body in [
        tx_response([8; 32]),
        serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[]}),
        serde_json::json!({"status":"OK","untrusted":false,"txs":tx_response([7;32])["txs"],"missed_tx":[hex_lower(&[7;32])]}),
        serde_json::json!({"status":"BUSY","untrusted":false,"txs":tx_response([7;32])["txs"]}),
        serde_json::json!({"status":"OK","untrusted":true,"txs":tx_response([7;32])["txs"]}),
    ] {
        let (url, worker) = server(vec![http(body)]);
        let client = BlockingMoneroBroadcaster::new(url).expect("client");
        assert!(client.transaction_is_known([7; 32]).is_err());
        assert_eq!(worker.join().expect("HTTP worker"), 1);
    }
    for (body, expected) in [
        (tx_response([7; 32]), true),
        (
            serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[hex_lower(&[7;32])]}),
            false,
        ),
    ] {
        let (url, worker) = server(vec![http(body)]);
        assert_eq!(
            BlockingMoneroBroadcaster::new(url)
                .expect("client")
                .transaction_is_known([7; 32])
                .expect("exact response"),
            expected
        );
        worker.join().expect("HTTP worker");
    }
}

#[test]
fn exact_absence_permanent_mismatch_and_transient_failure_have_distinct_results() {
    let absent = serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[hex_lower(&[7;32])]});
    let wrong_miss = serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[hex_lower(&[8;32])]});
    let empty = serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[]});
    let mut busy = tx_response([7; 32]);
    busy["status"] = serde_json::json!("BUSY");
    for (body, expected) in [
        (absent, Ok(false)),
        (tx_response([7; 32]), Ok(true)),
        (tx_response([8; 32]), Err(SpendPortError::Rejected)),
        (wrong_miss, Err(SpendPortError::Rejected)),
        (empty, Err(SpendPortError::Rejected)),
        (busy, Err(SpendPortError::Retryable)),
    ] {
        let (url, worker) = server(vec![http(body)]);
        assert_eq!(
            BlockingMoneroBroadcaster::new(url)
                .expect("client")
                .transaction_is_known([7; 32]),
            expected
        );
        assert_eq!(worker.join().expect("HTTP worker"), 1);
    }
}

#[test]
fn full_observation_v5_checks_genesis_tx_membership_and_canonical_header() {
    let responses = vec![
        block(0, [1; 32]),
        tx_response([7; 32]),
        block(100, [2; 32]),
        serde_json::json!({"status":"OK","untrusted":false,"height":101}),
        block(100, [2; 32]),
        block(0, [1; 32]),
    ];
    let (url, worker) = server(responses.into_iter().map(http).collect());
    let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
    assert_eq!(
        reader
            .transaction_observation_v5([7; 32], [1; 32])
            .expect("corroborated"),
        MoneroTransactionObservationV5::Included {
            height: 100,
            block_hash: [2; 32],
            chain_length: 101
        }
    );
    assert_eq!(worker.join().expect("HTTP worker"), 6);
}

#[test]
fn wrong_genesis_v5_stops_before_transaction_lookup() {
    let (url, worker) = server(vec![http(block(0, [9; 32]))]);
    let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
    assert!(matches!(
        reader.transaction_observation_v5([7; 32], [1; 32]),
        Err(SpendPortError::Rejected)
    ));
    assert_eq!(worker.join().expect("worker"), 1);
}

#[test]
fn inclusion_v5_refuses_metadata_without_exact_transaction_in_block() {
    let valid = block(100, [2; 32]);
    for mutation in 0..7 {
        let mut value = valid.clone();
        match mutation {
            0 => value["result"]["tx_hashes"] = serde_json::json!([hex_lower(&[8; 32])]),
            1 => {
                value["result"]["tx_hashes"] =
                    serde_json::json!([hex_lower(&[7; 32]), hex_lower(&[7; 32])])
            }
            2 => value["result"]["block_header"]["height"] = serde_json::json!(101),
            3 => value["result"]["block_header"]["orphan_status"] = serde_json::json!(true),
            4 => value["result"]["untrusted"] = serde_json::json!(true),
            5 => value["result"]["block_header"]["hash"] = serde_json::json!(hex_lower(&[0; 32])),
            _ => value["error"] = serde_json::json!({"code":-1}),
        }
        assert!(inclusion_block_v5(&value, 100, [7; 32]).is_err());
    }
}

#[test]
fn redirect_v5_is_not_followed_and_oversized_json_is_refused() {
    let target = TcpListener::bind("127.0.0.1:0").expect("redirect target");
    target.set_nonblocking(true).expect("nonblocking");
    let response = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/get_height\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        target.local_addr().expect("target"));
    let (url, worker) = server(vec![response]);
    assert!(BlockingMoneroDaemonReaderV1::new(url)
        .expect("reader")
        .daemon_height()
        .is_err());
    worker.join().expect("worker");
    assert_eq!(
        target.accept().expect_err("no redirect connection").kind(),
        std::io::ErrorKind::WouldBlock
    );
    let (url, worker) = server(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_RPC_RESPONSE_BYTES_V5 + 1
    )]);
    assert!(BlockingMoneroDaemonReaderV1::new(url)
        .expect("reader")
        .daemon_height()
        .is_err());
    worker.join().expect("worker");
}

#[test]
fn v8_genesis_change_after_absence_is_a_hard_rejection() {
    let absent = serde_json::json!({"status":"OK","untrusted":false,"txs":[],"missed_tx":[hex_lower(&[7;32])]});
    let (url, worker) = server(vec![
        http(block(0, [1; 32])),
        http(absent),
        http(block(0, [9; 32])),
    ]);
    let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
    assert!(matches!(
        reader.transaction_observation_v5([7; 32], [1; 32]),
        Err(SpendPortError::Rejected)
    ));
    assert_eq!(worker.join().expect("worker"), 3);
}

#[test]
fn v8_genesis_substitution_cannot_produce_an_unspent_answer() {
    let (url, worker) = server(vec![http(block(0, [9; 32]))]);
    let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
    assert!(matches!(
        reader.key_image_spent_on_chain_v5([7; 32], [1; 32]),
        Err(SpendPortError::Rejected)
    ));
    assert_eq!(worker.join().expect("worker"), 1);
}

#[test]
fn v8_key_image_reply_requires_exactly_one_recognized_status() {
    for (statuses, expected) in [
        (vec![0], Ok(false)),
        (vec![1], Ok(true)),
        (vec![2], Ok(true)),
        (vec![], Err(SpendPortError::Rejected)),
        (vec![3], Err(SpendPortError::Rejected)),
        (vec![0, 0], Err(SpendPortError::Rejected)),
    ] {
        let (url, worker) = server(vec![http(serde_json::json!({
            "status":"OK", "untrusted":false, "spent_status":statuses
        }))]);
        let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
        assert_eq!(reader.key_image_spent([7; 32]), expected);
        assert_eq!(worker.join().expect("worker"), 1);
    }
}

#[test]
fn v8_malformed_complete_body_is_rejected_but_http_unavailability_is_retryable() {
    for (response, expected) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{".to_owned(),
            SpendPortError::Rejected,
        ),
        (
            "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
            SpendPortError::Retryable,
        ),
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_RPC_RESPONSE_BYTES_V5 + 1
            ),
            SpendPortError::Rejected,
        ),
    ] {
        let (url, worker) = server(vec![response]);
        let reader = BlockingMoneroDaemonReaderV1::new(url).expect("reader");
        assert_eq!(reader.transaction_location([7; 32]), Err(expected));
        assert_eq!(worker.join().expect("worker"), 1);
    }
}
