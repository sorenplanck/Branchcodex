//! Minimal Monero daemon RPC client.

use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const MAX_RPC_RESPONSE_BYTES_V11: usize = 1_048_576;

use crate::{NodeObservation, XmrNetwork, XmrObserverError, XmrTransactionStatus};

/// RPC operations required by quorum observation.
#[allow(async_fn_in_trait)]
pub trait XmrRpc: Send + Sync {
    /// Node health and canonical tip.
    async fn observe_tip(
        &self,
        expected_network: XmrNetwork,
    ) -> Result<NodeObservation, XmrObserverError>;
    /// Transaction location.
    async fn transaction_status(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<XmrTransactionStatus, XmrObserverError>;
    /// Block hash at a height.
    async fn block_hash(&self, height: u64) -> Result<[u8; 32], XmrObserverError>;
}

/// HTTP Monero daemon RPC implementation.
#[derive(Clone)]
pub struct HttpXmrRpc {
    base_url: String,
    client: Client,
}

impl core::fmt::Debug for HttpXmrRpc {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpXmrRpc")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl HttpXmrRpc {
    /// Creates a finite-timeout client.
    pub fn new(base_url: impl Into<String>) -> Result<Self, XmrObserverError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(20))
            .build()
            .map_err(|_| XmrObserverError::RpcTransport)?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
        })
    }
}

#[derive(Deserialize)]
struct GetInfoResponse {
    status: String,
    untrusted: bool,
    synchronized: bool,
    height: u64,
    target_height: u64,
    mainnet: bool,
    stagenet: bool,
    testnet: bool,
    top_block_hash: String,
}

#[derive(Serialize)]
struct GetTransactionsRequest {
    txs_hashes: Vec<String>,
    decode_as_json: bool,
}

#[derive(Deserialize)]
struct GetTransactionsResponse {
    status: String,
    untrusted: bool,
    #[serde(default)]
    missed_tx: Vec<String>,
    #[serde(default)]
    txs: Vec<TransactionInfo>,
}

#[derive(Deserialize)]
struct TransactionInfo {
    tx_hash: String,
    block_height: Option<u64>,
    in_pool: bool,
}

#[derive(Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'static str,
    params: T,
}

#[derive(Serialize)]
struct HeightParams {
    height: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: T,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BlockHeaderResult {
    status: String,
    untrusted: bool,
    block_header: BlockHeader,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
    height: u64,
    orphan_status: bool,
}

#[derive(Deserialize)]
struct BlockResult {
    status: String,
    untrusted: bool,
    block_header: BlockHeader,
    #[serde(default)]
    tx_hashes: Vec<String>,
}

impl XmrRpc for HttpXmrRpc {
    async fn observe_tip(
        &self,
        expected_network: XmrNetwork,
    ) -> Result<NodeObservation, XmrObserverError> {
        let response = self
            .client
            .get(format!("{}/get_info", self.base_url))
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let info: GetInfoResponse = read_json_bounded_v11(response).await?;
        if info.status != "OK" || info.untrusted {
            return Err(XmrObserverError::MalformedResponse);
        }
        let network = decode_network(info.mainnet, info.stagenet, info.testnet)?;
        if network != expected_network {
            return Err(XmrObserverError::WrongNetwork);
        }
        if !info.synchronized {
            return Err(XmrObserverError::NotSynchronized);
        }
        let tip_height = info
            .height
            .checked_sub(1)
            .ok_or(XmrObserverError::MalformedResponse)?;
        Ok(NodeObservation {
            node: self.base_url.clone(),
            network,
            synchronized: true,
            tip_height,
            target_height: info.target_height,
            top_hash: parse_hash(&info.top_block_hash)?,
        })
    }

    async fn transaction_status(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<XmrTransactionStatus, XmrObserverError> {
        if tx_hash == [0; 32] {
            return Err(XmrObserverError::MalformedResponse);
        }
        let encoded = hex_lower(&tx_hash);
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![encoded.clone()],
                decode_as_json: false,
            })
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let body: GetTransactionsResponse = read_json_bounded_v11(response).await?;
        let status = exact_transaction_status_v11(&body, tx_hash)?;
        if let XmrTransactionStatus::InBlock { block_height } = status {
            // A location and an unrelated header do not prove inclusion. Ask
            // this same node for the canonical block's transaction identities.
            let response = self
                .client
                .post(format!("{}/json_rpc", self.base_url))
                .json(&JsonRpcRequest {
                    jsonrpc: "2.0",
                    id: "0",
                    method: "get_block",
                    params: HeightParams {
                        height: block_height,
                    },
                })
                .send()
                .await
                .map_err(|_| XmrObserverError::RpcTransport)?;
            let block: JsonRpcResponse<BlockResult> = read_json_bounded_v11(response).await?;
            let block_hash = exact_inclusion_v11(&block, block_height, tx_hash)?;
            if self.block_hash(block_height).await? != block_hash {
                return Err(XmrObserverError::StaleTip);
            }
        }
        Ok(status)
    }

    async fn block_hash(&self, height: u64) -> Result<[u8; 32], XmrObserverError> {
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&JsonRpcRequest {
                jsonrpc: "2.0",
                id: "0",
                method: "get_block_header_by_height",
                params: HeightParams { height },
            })
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let body: JsonRpcResponse<BlockHeaderResult> = read_json_bounded_v11(response).await?;
        if body.error.is_some()
            || body.result.status != "OK"
            || body.result.untrusted
            || body.result.block_header.height != height
            || body.result.block_header.orphan_status
        {
            return Err(XmrObserverError::MalformedResponse);
        }
        parse_hash(&body.result.block_header.hash)
    }
}

fn decode_network(
    mainnet: bool,
    stagenet: bool,
    testnet: bool,
) -> Result<XmrNetwork, XmrObserverError> {
    match (mainnet, stagenet, testnet) {
        (true, false, false) => Ok(XmrNetwork::Mainnet),
        (false, true, false) => Ok(XmrNetwork::Stagenet),
        (false, false, true) => Ok(XmrNetwork::Testnet),
        _ => Err(XmrObserverError::MalformedResponse),
    }
}

fn parse_hash(encoded: &str) -> Result<[u8; 32], XmrObserverError> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 64 {
        return Err(XmrObserverError::MalformedResponse);
    }
    let digit = |value: u8| match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        // The daemon's canonical identity fields use lower-case hexadecimal.
        _ => Err(XmrObserverError::MalformedResponse),
    };
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = digit(bytes[index * 2])? << 4 | digit(bytes[index * 2 + 1])?;
    }
    if output == [0; 32] {
        return Err(XmrObserverError::MalformedResponse);
    }
    Ok(output)
}

async fn read_json_bounded_v11<T: DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, XmrObserverError> {
    if !response.status().is_success() {
        return Err(XmrObserverError::RpcTransport);
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RPC_RESPONSE_BYTES_V11 as u64)
    {
        return Err(XmrObserverError::MalformedResponse);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| XmrObserverError::RpcTransport)?
    {
        if chunk.len() > MAX_RPC_RESPONSE_BYTES_V11.saturating_sub(bytes.len()) {
            return Err(XmrObserverError::MalformedResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| XmrObserverError::MalformedResponse)
}

fn exact_transaction_status_v11(
    body: &GetTransactionsResponse,
    tx_hash: [u8; 32],
) -> Result<XmrTransactionStatus, XmrObserverError> {
    if tx_hash == [0; 32] || body.status != "OK" || body.untrusted {
        return Err(XmrObserverError::MalformedResponse);
    }
    let wanted = hex_lower(&tx_hash);
    match (body.missed_tx.as_slice(), body.txs.as_slice()) {
        ([missing], []) if missing == &wanted => Ok(XmrTransactionStatus::Unseen),
        ([], [entry]) if entry.tx_hash == wanted => {
            if entry.in_pool {
                // monerod can retain a stale block_height for a pool entry;
                // no height from an in-pool answer is used as inclusion.
                Ok(XmrTransactionStatus::InPool)
            } else {
                Ok(XmrTransactionStatus::InBlock {
                    block_height: entry
                        .block_height
                        .ok_or(XmrObserverError::MalformedResponse)?,
                })
            }
        }
        _ => Err(XmrObserverError::MalformedResponse),
    }
}

fn exact_inclusion_v11(
    body: &JsonRpcResponse<BlockResult>,
    height: u64,
    tx_hash: [u8; 32],
) -> Result<[u8; 32], XmrObserverError> {
    let block = &body.result;
    if tx_hash == [0; 32]
        || body.error.is_some()
        || block.status != "OK"
        || block.untrusted
        || block.block_header.height != height
        || block.block_header.orphan_status
    {
        return Err(XmrObserverError::MalformedResponse);
    }
    let mut identities = std::collections::BTreeSet::new();
    for value in &block.tx_hashes {
        if !identities.insert(parse_hash(value)?) {
            return Err(XmrObserverError::MalformedResponse);
        }
    }
    if !identities.contains(&tx_hash) {
        return Err(XmrObserverError::MalformedResponse);
    }
    parse_hash(&block.block_header.hash)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn wanted() -> String {
        hex_lower(&[1; 32])
    }
    fn transaction_response(missing: Value, entries: Value) -> Value {
        json!({"status":"OK", "untrusted":false, "missed_tx":missing, "txs":entries})
    }
    fn decode_status(value: Value) -> Result<XmrTransactionStatus, XmrObserverError> {
        let body =
            serde_json::from_value(value).map_err(|_| XmrObserverError::MalformedResponse)?;
        exact_transaction_status_v11(&body, [1; 32])
    }
    #[test]
    fn v11_exact_absence_is_distinct_from_substitution_and_contradiction() {
        assert_eq!(
            decode_status(transaction_response(json!([wanted()]), json!([]))),
            Ok(XmrTransactionStatus::Unseen)
        );
        let entry = json!({"tx_hash":wanted(), "in_pool":true});
        for body in [
            transaction_response(json!([hex_lower(&[2; 32])]), json!([])),
            transaction_response(
                json!([]),
                json!([{ "tx_hash":hex_lower(&[2; 32]), "in_pool":true }]),
            ),
            transaction_response(json!([wanted()]), json!([entry.clone()])),
            transaction_response(json!([wanted(), wanted()]), json!([])),
            transaction_response(json!([]), json!([entry.clone(), entry])),
            transaction_response(json!([]), json!([])),
            transaction_response(json!([]), json!([{ "in_pool":true }])),
        ] {
            assert_eq!(
                decode_status(body),
                Err(XmrObserverError::MalformedResponse)
            );
        }
    }
    #[test]
    fn v11_status_and_trust_fields_cannot_create_presence_or_absence() {
        let good = transaction_response(
            json!([]),
            json!([{ "tx_hash":wanted(), "in_pool":true, "block_height":700 }]),
        );
        assert_eq!(
            decode_status(good.clone()),
            Ok(XmrTransactionStatus::InPool)
        );
        for (key, value) in [("status", json!("BUSY")), ("untrusted", json!(true))] {
            let mut changed = good.clone();
            changed[key] = value;
            assert_eq!(
                decode_status(changed),
                Err(XmrObserverError::MalformedResponse)
            );
        }
        assert_eq!(
            decode_status(transaction_response(
                json!([]),
                json!([{ "tx_hash":wanted(), "in_pool":false }])
            )),
            Err(XmrObserverError::MalformedResponse)
        );
    }
    fn block(tx_ids: Value) -> Value {
        json!({"result": {"status":"OK", "untrusted":false, "tx_hashes":tx_ids,
            "block_header": {"height":19, "hash":hex_lower(&[3; 32]), "orphan_status":false}}})
    }
    fn inclusion(value: Value) -> Result<[u8; 32], XmrObserverError> {
        let body =
            serde_json::from_value(value).map_err(|_| XmrObserverError::MalformedResponse)?;
        exact_inclusion_v11(&body, 19, [1; 32])
    }
    #[test]
    fn v11_inclusion_requires_exact_unique_transaction_and_canonical_block() {
        assert_eq!(inclusion(block(json!([wanted()]))), Ok([3; 32]));
        for value in [
            json!([]),
            json!([hex_lower(&[2; 32])]),
            json!([wanted(), wanted()]),
            json!([wanted(), "nothex"]),
        ] {
            assert_eq!(
                inclusion(block(value)),
                Err(XmrObserverError::MalformedResponse)
            );
        }
        for (key, value) in [
            ("height", json!(20)),
            ("orphan_status", json!(true)),
            ("hash", json!(hex_lower(&[0; 32]))),
        ] {
            let mut changed = block(json!([wanted()]));
            changed["result"]["block_header"][key] = value;
            assert_eq!(inclusion(changed), Err(XmrObserverError::MalformedResponse));
        }
        let mut error = block(json!([wanted()]));
        error["error"] = json!({"code":-1});
        assert_eq!(inclusion(error), Err(XmrObserverError::MalformedResponse));
    }
    #[test]
    fn v11_hash_decoder_refuses_non_ascii_without_utf8_boundary_panics() {
        for value in [
            format!("aé{}", "b".repeat(61)),
            "é".repeat(32),
            "A".repeat(64),
            "0".repeat(64),
        ] {
            assert_eq!(parse_hash(&value), Err(XmrObserverError::MalformedResponse));
        }
        assert_eq!(parse_hash(&wanted()), Ok([1; 32]));
    }

    fn serve_once(
        body: String,
        declared_length: Option<usize>,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let endpoint = format!("http://{}", listener.local_addr().expect("fixture address"));
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fixture");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            let mut received = Vec::new();
            let mut part = [0; 1024];
            loop {
                let count = stream.read(&mut part).expect("request");
                assert!(count > 0);
                received.extend_from_slice(&part[..count]);
                if let Some(end) = received.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|value| value.trim().parse::<usize>().expect("request length"))
                        .unwrap_or(0);
                    if received.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(received.len() < 8192);
            }
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                declared_length.unwrap_or(body.len()), body);
            stream.write_all(response.as_bytes()).expect("response");
        });
        (endpoint, worker)
    }
    #[tokio::test]
    async fn v11_http_client_preserves_exact_miss_and_rejects_swapped_txid() {
        for (body, expected) in [
            (
                transaction_response(json!([wanted()]), json!([])),
                Ok(XmrTransactionStatus::Unseen),
            ),
            (
                transaction_response(
                    json!([]),
                    json!([{ "tx_hash":hex_lower(&[2; 32]), "in_pool":true }]),
                ),
                Err(XmrObserverError::MalformedResponse),
            ),
        ] {
            let (endpoint, worker) = serve_once(body.to_string(), None);
            let client = HttpXmrRpc::new(endpoint).expect("client");
            assert_eq!(client.transaction_status([1; 32]).await, expected);
            worker.join().expect("fixture complete");
        }
    }
    #[tokio::test]
    async fn v11_http_response_bound_cannot_become_transaction_absence() {
        let body = transaction_response(json!([wanted()]), json!([])).to_string();
        let (endpoint, worker) = serve_once(body, Some(MAX_RPC_RESPONSE_BYTES_V11 + 1));
        let client = HttpXmrRpc::new(endpoint).expect("client");
        assert_eq!(
            client.transaction_status([1; 32]).await,
            Err(XmrObserverError::MalformedResponse)
        );
        worker.join().expect("fixture complete");
    }
}
