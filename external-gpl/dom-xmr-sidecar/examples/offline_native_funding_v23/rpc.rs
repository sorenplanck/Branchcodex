//! Read-only local Monero RPC snapshot backed by complete signed fixture bytes.
//! Chain location is simulated; output ownership/amount is NOT an echo and must
//! be checked by the real sidecar scanner. No transaction submission endpoint.
use anyhow::{Result, anyhow, ensure};
use monero_oxide_wallet::transaction::Transaction;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_REQUEST: usize = 16_384;
#[path = "epee.rs"]
mod epee;
#[path = "ledger.rs"]
mod ledger;
use ledger::{Snapshot, TIP_HEIGHT};

pub(super) struct Servers {
    urls: Vec<String>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<Result<(), String>>>,
}

impl Servers {
    pub(super) fn start(transaction: Transaction, network_tag: u8) -> Result<Self> {
        Self::start_multiple(vec![transaction], network_tag)
    }
    pub(super) fn start_multiple(transactions: Vec<Transaction>, network_tag: u8) -> Result<Self> {
        let snapshot = Arc::new(Snapshot::new_multiple(transactions, network_tag)?);
        let mut servers = Self {
            urls: vec![],
            stop: Arc::new(AtomicBool::new(false)),
            workers: vec![],
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
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            if !peer.ip().is_loopback() {
                                return Err("non-loopback peer".into());
                            }
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .map_err(|e| e.to_string())?;
                            stream
                                .set_write_timeout(Some(Duration::from_secs(5)))
                                .map_err(|e| e.to_string())?;
                            serve(&mut stream, &snapshot).map_err(|e| e.to_string())?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(())
            }));
        }
        Ok(servers)
    }
    pub(super) fn urls(&self) -> &[String] {
        &self.urls
    }
    pub(super) fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            worker
                .join()
                .map_err(|_| anyhow!("fixture RPC worker panicked"))?
                .map_err(|error| anyhow!(error))?;
        }
        Ok(())
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
        ensure!(height <= TIP_HEIGHT, "height outside fixed snapshot");
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

fn serve(stream: &mut TcpStream, snapshot: &Snapshot) -> Result<()> {
    let mut bytes = Vec::new();
    let (header_end, content_length) = loop {
        let mut buffer = [0; 2048];
        let count = stream.read(&mut buffer)?;
        ensure!(
            count > 0 && bytes.len() + count <= MAX_REQUEST,
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
    if method == "POST" {
        if let Some(response) = epee::dispatch(path, body, snapshot)? {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )?;
            stream.write_all(&response)?;
            stream.flush()?;
            return Ok(());
        }
    }
    let response = match (method, path) {
        ("GET", "/get_height") => json!({"status":"OK","untrusted":false,"height":TIP_HEIGHT + 1}),
        ("GET", "/get_info") => json!({"status":"OK","untrusted":false,"synchronized":true,
            "height":TIP_HEIGHT + 1,"target_height":TIP_HEIGHT + 1,
            "mainnet":snapshot.is_mainnet(),"testnet":false,"stagenet":!snapshot.is_mainnet(),"top_block_hash":snapshot.block_hash(TIP_HEIGHT)?}),
        ("POST", "/json_rpc") => json_rpc(&serde_json::from_slice(body)?, snapshot)?,
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
                "spent_status":[u8::from(snapshot.key_image_spent(image))]})
        }
        ("POST", "/get_transactions") => {
            let request: Value = serde_json::from_slice(body)?;
            let hashes = request
                .get("txs_hashes")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("missing tx hashes"))?;
            snapshot.transaction_response(hashes)?
        }
        // Including send_raw_transaction: no network/payment API is available.
        _ => {
            stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            return Ok(());
        }
    };
    let response = serde_json::to_vec(&response)?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )?;
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}
