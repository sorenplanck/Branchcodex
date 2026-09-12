//! Exercise the actual HTTP readers and production quorum, not only its vote helper.
use crate::production_children::QuorumXmrObservationPortV1;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};
use xmr_actuator::{XmrActuatorErrorV1, XmrObservationPortV1};
use xmr_rpc_broadcast_blocking::BlockingMoneroDaemonReaderV1;

fn node(
    responses: Vec<serde_json::Value>,
) -> (BlockingMoneroDaemonReaderV1, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut calls = 0;
        for body in responses {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "expected RPC was never called");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 2048];
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0 && request.len() + count <= 16_384);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let body = body.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            calls += 1;
        }
        calls
    });
    (BlockingMoneroDaemonReaderV1::new(endpoint).unwrap(), worker)
}

fn genesis(byte: u8) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":"0","result":{
        "status":"OK","untrusted":false,"block_header":{
            "height":0,"hash":format!("{byte:02x}").repeat(32),"orphan_status":false}}})
}
fn missing(byte: u8) -> serde_json::Value {
    serde_json::json!({"status":"OK","untrusted":false,"txs":[],
        "missed_tx":[format!("{byte:02x}").repeat(32)]})
}
fn quorum(
    responses: [Vec<serde_json::Value>; 3],
) -> (QuorumXmrObservationPortV1, Vec<thread::JoinHandle<usize>>) {
    let (readers, workers) = responses.into_iter().map(node).unzip();
    (
        QuorumXmrObservationPortV1::new(readers, 2, [1; 32]).unwrap(),
        workers,
    )
}
fn join(workers: Vec<thread::JoinHandle<usize>>, expected: [usize; 3]) {
    for (worker, count) in workers.into_iter().zip(expected) {
        assert_eq!(worker.join().unwrap(), count);
    }
}

#[test]
fn v8_live_quorum_preserves_wrong_txid_over_two_explicit_misses() {
    let correct = vec![genesis(1), missing(7), genesis(1)];
    let (mut port, workers) = quorum([correct.clone(), vec![genesis(1), missing(8)], correct]);
    assert!(matches!(
        port.transaction_inclusion([7; 32]),
        Err(XmrActuatorErrorV1::Conflict)
    ));
    join(workers, [3, 2, 3]);
}

#[test]
fn v8_live_quorum_distinguishes_busy_from_a_contradictory_reply() {
    let correct = vec![genesis(1), missing(7), genesis(1)];
    let busy = vec![
        genesis(1),
        serde_json::json!({"status":"BUSY","untrusted":false}),
    ];
    let (mut port, workers) = quorum([correct.clone(), busy, correct]);
    assert!(matches!(port.transaction_inclusion([7; 32]), Ok(None)));
    join(workers, [3, 2, 3]);
}

#[test]
fn v8_live_quorum_preserves_genesis_substitution_over_absence_majority() {
    let correct = vec![genesis(1), missing(7), genesis(1)];
    let (mut port, workers) = quorum([correct.clone(), vec![genesis(9)], correct]);
    assert!(matches!(
        port.transaction_inclusion([7; 32]),
        Err(XmrActuatorErrorV1::Conflict)
    ));
    join(workers, [3, 1, 3]);
}

#[test]
fn v8_live_quorum_does_not_hide_a_malformed_key_image_answer() {
    let answer = |statuses: Vec<u8>| serde_json::json!({"status":"OK","untrusted":false,"spent_status":statuses});
    let correct = vec![genesis(1), answer(vec![0]), genesis(1)];
    let (mut port, workers) = quorum([
        correct.clone(),
        vec![genesis(1), answer(vec![0, 0])],
        correct,
    ]);
    assert!(matches!(
        port.key_image_spent([7; 32]),
        Err(XmrActuatorErrorV1::Conflict)
    ));
    join(workers, [3, 2, 3]);
}
