//! Local transport capture after durable exposure. Always HTTP 503: no node
//! acceptance, relay receipt, admission journal, or economic terminal is minted.
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};
type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn capture(
    store: &dom_scriptless_store::ContractsSessionStoreV1,
    binding: dom_actuator::DomSessionBindingV1,
    submission: &dom_actuator::DomF7FinalClaimSubmissionV14,
) -> Result<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let adapter = dom_scriptless_chain_adapter::DomHttpChainAdapterV1::new(
        &endpoint,
        binding.expected_dom_identity()?,
        dom_scriptless_chain_adapter::BearerTokenV1::new("offline-claim-capture-v23".into())?,
        Duration::from_secs(2),
        Duration::from_secs(5),
    )?;
    let runtime = adapter_dom_real::RealDomRpcRuntimeV1::new(adapter, 64)?;
    let expected = submission.tx_hash();
    let worker = thread::spawn(move || -> core::result::Result<Vec<u8>, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, peer) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        if !peer.ip().is_loopback() {
            return Err("nonlocal capture peer".into());
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        let end = loop {
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                break end + 4;
            }
            if bytes.len() >= 8192 {
                return Err("capture header bound".into());
            }
            let mut buf = [0; 1024];
            let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("capture truncated header".into());
            }
            bytes.extend_from_slice(&buf[..n]);
        };
        let header = std::str::from_utf8(&bytes[..end]).map_err(|e| e.to_string())?;
        if header.lines().next() != Some("POST /tx/submit HTTP/1.1")
            || !header
                .lines()
                .any(|l| l.eq_ignore_ascii_case("authorization: Bearer offline-claim-capture-v23"))
        {
            return Err("capture request scope".into());
        }
        let mut length = None;
        for line in header.lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("capture transfer encoding".into());
            }
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err("capture duplicate length".into());
                }
                length = Some(value.trim().parse::<usize>().map_err(|e| e.to_string())?);
            }
        }
        let length = length
            .filter(|n| *n > 0 && *n <= 4 * 1024 * 1024)
            .ok_or("capture body bound")?;
        while bytes.len() < end + length {
            let mut buf = [0; 4096];
            let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("capture truncated body".into());
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        if bytes.len() != end + length {
            return Err("capture trailing bytes".into());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            tx_hex: String,
        }
        let body: Body = serde_json::from_slice(&bytes[end..]).map_err(|e| e.to_string())?;
        let transaction = hex::decode(body.tx_hex).map_err(|e| e.to_string())?;
        if dom_scriptless_chain_adapter::canonical_transaction_hash_v1(&transaction)
            .map_err(|e| e.to_string())?
            != expected
        {
            return Err("capture exact transaction hash mismatch".into());
        }
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .map_err(|e|e.to_string())?;
        Ok(transaction)
    });
    // No early return between spawn and join: even refusal cannot orphan a worker.
    let result = dom_actuator::DomContractsActuatorV1::bind(store, binding)
        .and_then(|actuator| actuator.dispatch_f7_final_claim_v14(&runtime, submission));
    let bytes = worker
        .join()
        .map_err(|_| "capture worker panic")?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    if !matches!(
        result,
        Err(dom_actuator::DomActuatorError::RpcAuthorityUnavailable)
    ) {
        return Err("capture must refuse submission without an economic receipt".into());
    }
    Ok(bytes)
}
