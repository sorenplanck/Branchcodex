//! Default read-only local Monero RPC snapshot backed by signed fixture bytes.
//! Chain location is simulated; output ownership/amount is NOT an echo and must
//! be checked by the real sidecar scanner. Explicit route opt-in permits only
//! a cryptographically checked LOCAL pool; confirmed history changes by pipe.
use anyhow::{Result, anyhow, ensure};
use monero_oxide_wallet::transaction::Transaction;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_REQUEST: usize = 270_336;
const MAX_CONNECTIONS_PER_VOTER: usize = 16;
#[path = "epee.rs"]
mod epee;
#[path = "ledger.rs"]
mod ledger;
use ledger::Snapshot;

pub(super) struct Servers {
    urls: Vec<String>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<Result<(), String>>>,
    snapshot: Arc<Mutex<Snapshot>>,
}

/// Unpublished source history; route candidates are not inserted here.
pub(super) struct Sources {
    snapshot: Snapshot,
}
impl Sources {
    pub(super) fn new(amounts: [u64; 3], network_tag: u8) -> Result<Self> {
        ensure!(
            network_tag == 1,
            "mutable route requires explicit mainnet profile"
        );
        Ok(Self {
            snapshot: Snapshot::source_roots(amounts, network_tag)?,
        })
    }
    pub(super) fn input(&self, position: u8) -> Result<monero_oxide_wallet::OutputWithDecoys> {
        self.snapshot.source_input(position)
    }
    pub(super) fn metadata(&self) -> Result<Value> {
        self.snapshot.source_metadata()
    }
    pub(super) fn validate_candidate(&self, tx: &Transaction) -> Result<()> {
        self.snapshot.validate_candidate(tx)
    }
    pub(super) fn start(self, inventory: Transaction) -> Result<Servers> {
        Servers::start_snapshot(self.snapshot.with_initial_inventory(inventory)?)
    }
}

impl Servers {
    pub(super) fn start(transaction: Transaction, network_tag: u8) -> Result<Self> {
        Self::start_multiple(vec![transaction], network_tag)
    }
    pub(super) fn start_multiple(transactions: Vec<Transaction>, network_tag: u8) -> Result<Self> {
        Self::start_snapshot(Snapshot::new_multiple(transactions, network_tag)?)
    }
    fn start_snapshot(ledger: Snapshot) -> Result<Self> {
        let snapshot = Arc::new(Mutex::new(ledger));
        let mut servers = Self {
            urls: vec![],
            stop: Arc::new(AtomicBool::new(false)),
            workers: vec![],
            snapshot: Arc::clone(&snapshot),
        };
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            servers
                .urls
                .push(format!("http://{}", listener.local_addr()?));
            let stop = Arc::clone(&servers.stop);
            let snapshot = Arc::clone(&snapshot);
            servers.workers.push(thread::spawn(move || {
                serve_connections(listener, stop, snapshot)
            }));
        }
        Ok(servers)
    }
    pub(super) fn urls(&self) -> &[String] {
        &self.urls
    }
    pub(super) fn scenario_status(&self) -> Result<Value> {
        let snapshot = self
            .snapshot
            .lock()
            .map_err(|_| anyhow!("scenario ledger poisoned"))?;
        ensure!(snapshot.mutable_scenario(), "read-only snapshot");
        snapshot.scenario_status()
    }
    pub(super) fn advance(
        &self,
        height: u64,
        timestamp: u64,
        hashes: &[[u8; 32]],
    ) -> Result<Value> {
        let mut snapshot = self
            .snapshot
            .lock()
            .map_err(|_| anyhow!("scenario ledger poisoned"))?;
        snapshot.advance(height, timestamp, hashes)?;
        snapshot.scenario_status()
    }
    pub(super) fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        let mut failure = None;
        for worker in self.workers.drain(..) {
            match worker.join() {
                Ok(Ok(())) => (),
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert("fixture RPC worker panicked".into());
                }
            }
        }
        match failure {
            Some(error) => Err(anyhow!(error)),
            None => Ok(()),
        }
    }
}

fn serve_connections(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    snapshot: Arc<Mutex<Snapshot>>,
) -> Result<(), String> {
    let mut connections: Vec<JoinHandle<()>> = Vec::new();
    let mut failure = None;
    while !stop.load(Ordering::Acquire) {
        let mut index = 0;
        while index < connections.len() {
            if connections[index].is_finished() {
                if connections.swap_remove(index).join().is_err() {
                    failure = Some("fixture RPC connection panicked".into());
                    stop.store(true, Ordering::Release);
                }
            } else {
                index += 1;
            }
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                // A pooled/idle wallet connection consumes one bounded slot,
                // not the entire voter. Excess sockets are closed for retry.
                if !peer.ip().is_loopback() || connections.len() >= MAX_CONNECTIONS_PER_VOTER {
                    continue;
                }
                let stop = Arc::clone(&stop);
                let snapshot = Arc::clone(&snapshot);
                match thread::Builder::new().spawn(move || {
                    if stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .is_err()
                        || stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .is_err()
                    {
                        return;
                    }
                    while !stop.load(Ordering::Acquire) && serve(&mut stream, &snapshot).is_ok() {}
                }) {
                    Ok(connection) => connections.push(connection),
                    Err(error) => {
                        failure = Some(error.to_string());
                        // The shared stop also bounds every already-owned
                        // connection and the other voter on resource failure.
                        break;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        }
    }
    stop.store(true, Ordering::Release);
    for connection in connections {
        if connection.join().is_err() {
            failure.get_or_insert("fixture RPC connection panicked".into());
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
impl Drop for Servers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn json_rpc(request: &Value, snapshot: &Snapshot) -> Result<Value> {
    if let Some(batch) = request.as_array() {
        ensure!(batch.len() <= 16, "RPC batch bound");
        return Ok(Value::Array(
            batch
                .iter()
                .map(|entry| json_rpc(entry, snapshot))
                .collect::<Result<Vec<_>>>()?,
        ));
    }
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("RPC method absent"))?;
    let params = request.get("params").unwrap_or(&Value::Null);
    let result = if method == "get_fee_estimate" {
        json!({"status":"OK","untrusted":false,"fee":1,"fees":[1,1,1,1],"quantization_mask":1})
    } else {
        let height = if method == "on_get_block_hash" {
            params
                .get(0)
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("RPC height absent"))?
        } else if let Some(height) = params.get("height").and_then(Value::as_u64) {
            height
        } else if method == "get_block" {
            snapshot.height_for_hash(
                params
                    .get("hash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("RPC block hash absent"))?,
            )?
        } else {
            return Err(anyhow!("RPC height absent"));
        };
        ensure!(height <= snapshot.tip(), "height outside retained snapshot");
        match method {
            "on_get_block_hash" => Value::String(snapshot.block_hash(height)?),
            "get_block_header_by_height" | "get_block" => {
                let mut response = json!({"status":"OK","untrusted":false,"block_header":{
                    "height":height,"hash":snapshot.block_hash(height)?,"orphan_status":false}});
                if height > 0 {
                    let block = snapshot.block(height)?;
                    response["block_header"]["prev_hash"] =
                        json!(hex::encode(block.header.previous));
                    response["block_header"]["timestamp"] = json!(block.header.timestamp);
                }
                if method == "get_block" {
                    let block = snapshot.block(height)?;
                    response["blob"] = json!(hex::encode(block.serialize()));
                    response["tx_hashes"] = json!(
                        block
                            .transactions
                            .iter()
                            .map(hex::encode)
                            .collect::<Vec<_>>()
                    );
                }
                response
            }
            _ => return Err(anyhow!("unsupported fixture RPC method")),
        }
    };
    Ok(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn serve(stream: &mut TcpStream, ledger: &Arc<Mutex<Snapshot>>) -> Result<()> {
    let mut bytes = Vec::new();
    let (header_end, content_length) = loop {
        let mut buffer = [0; 2048];
        let count = stream.read(&mut buffer)?;
        // HTTP clients may open and immediately abandon a pooled/preflight
        // connection.  That is not a malformed RPC request and, critically,
        // must not tear down this listener's worker before the next client
        // connection can obtain the immutable snapshot.
        if count == 0 {
            return Err(anyhow!("fixture client closed connection"));
        }
        ensure!(
            bytes.len() + count <= MAX_REQUEST,
            "bounded HTTP request required"
        );
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end])?;
            ensure!(
                !headers.to_ascii_lowercase().contains("transfer-encoding:"),
                "chunked fixture requests unsupported"
            );
            let lengths = headers
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then_some(value.trim())
                })
                .collect::<Vec<_>>();
            ensure!(lengths.len() <= 1, "duplicate content length");
            let length = lengths
                .first()
                .map(|value| value.parse::<usize>())
                .transpose()?
                .unwrap_or(0);
            ensure!(end + 4 + length <= MAX_REQUEST, "HTTP body bound");
            if bytes.len() >= end + 4 + length {
                break (end, length);
            }
        }
    };
    ensure!(
        bytes.len() == header_end + 4 + content_length,
        "HTTP trailing request bytes"
    );
    let line = std::str::from_utf8(&bytes[..header_end])?
        .lines()
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("missing HTTP method"))?;
    let path = parts.next().ok_or_else(|| anyhow!("missing HTTP path"))?;
    let body = &bytes[header_end + 4..];
    let mut snapshot = ledger
        .lock()
        .map_err(|_| anyhow!("scenario ledger poisoned"))?;
    if method == "POST" {
        if let Some(response) = epee::dispatch(path, body, &*snapshot)? {
            drop(snapshot);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                response.len()
            )?;
            stream.write_all(&response)?;
            stream.flush()?;
            return Ok(());
        }
    }
    let response = match (method, path) {
        // monero-oxide's daemon client issues every non-JSON-RPC route as a
        // POST (its HttpTransport has no GET); real monerod answers these
        // read-only queries on both verbs. The refund sweep is the first path
        // to call latest_block_number -> POST /get_height, so a GET-only match
        // here 404s and surfaces as a retryable rpc_interface sweep failure.
        ("GET" | "POST", "/get_height") => {
            json!({"status":"OK","untrusted":false,"height":snapshot.tip() + 1})
        }
        ("GET" | "POST", "/get_info") => json!({"status":"OK","untrusted":false,"synchronized":true,
            "height":snapshot.tip() + 1,"target_height":snapshot.tip() + 1,
            "mainnet":snapshot.is_mainnet(),"testnet":false,"stagenet":!snapshot.is_mainnet(),"top_block_hash":snapshot.block_hash(snapshot.tip())?}),
        ("POST", "/json_rpc") => json_rpc(&serde_json::from_slice(body)?, &snapshot)?,
        ("POST", "/is_key_image_spent") => {
            let request: Value = serde_json::from_slice(body)?;
            let images = request
                .get("key_images")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("missing key images"))?;
            ensure!(images.len() == 1, "one key image required");
            let image: [u8; 32] = hex::decode(
                images[0]
                    .as_str()
                    .ok_or_else(|| anyhow!("key image type"))?,
            )?
            .try_into()
            .map_err(|_| anyhow!("key image length"))?;
            ensure!(image != [0; 32], "zero key image");
            json!({"status":"OK","untrusted":false,
                "spent_status":[snapshot.key_image_status(image)]})
        }
        ("POST", "/get_transactions") => {
            let request: Value = serde_json::from_slice(body)?;
            let hashes = request
                .get("txs_hashes")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("missing tx hashes"))?;
            snapshot.transaction_response(hashes)?
        }
        ("POST", "/send_raw_transaction") if snapshot.mutable_scenario() => {
            submission(body, &mut snapshot)
        }
        // The default immutable snapshot has no submission API. Administrative
        // height/inclusion control is never available over any HTTP endpoint.
        _ => {
            drop(snapshot);
            stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            )?;
            return Ok(());
        }
    };
    drop(snapshot);
    let response = serde_json::to_vec(&response)?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        response.len()
    )?;
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn submission(body: &[u8], snapshot: &mut Snapshot) -> Value {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Submit {
        tx_as_hex: String,
        #[serde(default)]
        do_not_relay: Option<bool>,
        #[serde(default)]
        do_sanity_checks: Option<bool>,
    }
    let result = (|| -> Result<[u8; 32]> {
        let request: Submit = serde_json::from_slice(body)?;
        let _ = (request.do_not_relay, request.do_sanity_checks);
        ensure!(
            !request.tx_as_hex.is_empty()
                && request.tx_as_hex.len() <= 262_144
                && request.tx_as_hex.len() % 2 == 0
                && request
                    .tx_as_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "candidate hex bound"
        );
        snapshot.submit(&hex::decode(request.tx_as_hex)?)
    })();
    let accepted = result.is_ok();
    json!({"status":if accepted {"OK"} else {"Failed"}, "untrusted":false,
        "double_spend":false,"fee_too_low":false,"invalid_input":!accepted,
        "invalid_output":false,"low_mixin":false,"not_relayed":false,
        "overspend":false,"too_big":false,"too_few_outputs":false,
        "reason":if accepted {"local-scenario-pool-only-no-network-relay"} else {"local-scenario-candidate-refused"}})
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
