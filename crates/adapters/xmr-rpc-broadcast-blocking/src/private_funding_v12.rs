//! Private construction only. This module has no `relay_tx` or broadcast method.
//! Operator wallet custody is separate from the swap's shared spend custody.
//! RPC contract: https://docs.getmonero.org/rpc-library/wallet-rpc/#transfer

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::Read;
use xmr_raw_tx_verify::{
    standard_funding_address_v12, verify_exact_raw_funding_v12, FundingVerificationErrorV12,
    VerifiedRawFundingV12, MAX_VERIFIED_RAW_TX_BYTES,
};
use zeroize::Zeroizing;

const MAX_PRIVATE_RESPONSE_BYTES: usize = 2 * MAX_VERIFIED_RAW_TX_BYTES + 65_536;

/// Failures never contain endpoint response bodies or private transaction bytes.
#[derive(Debug, thiserror::Error)]
pub enum PrivateFundingErrorV12 {
    /// Invalid endpoint, bounds or caller input.
    #[error("invalid private funding request")]
    Request,
    /// Network failure; caller must not automatically repeat wallet construction.
    #[error("private wallet response unavailable; inspect custody before retry")]
    Unavailable,
    /// Explicit wallet rejection, without reflecting potentially sensitive text.
    #[error("private wallet refused construction")]
    WalletRejected,
    /// Successful HTTP response does not answer the exact RPC request.
    #[error("private wallet response contradicts the request")]
    Response,
    /// The signed bytes do not prove the specified recipient and economics.
    #[error("private funding candidate failed independent verification")]
    Verification(#[from] FundingVerificationErrorV12),
}

/// Public construction parameters. The private view key is supplied separately.
#[derive(Clone, Debug)]
pub struct PrivateFundingRequestV12 {
    /// XmrSetupProfile network tag: mainnet 1, stagenet 2, testnet 3.
    pub network_tag: u8,
    /// Combined PUBLIC spend point; never the combined private spend scalar.
    pub combined_spend_public: [u8; 32],
    /// Principal to lock at the shared address, in atomic units.
    pub amount_piconero: u64,
    /// Maximum acceptable independently decoded fee.
    pub max_fee_piconero: u64,
    /// Operator funding wallet's account, separate from shared swap custody.
    pub account_index: u32,
    /// Explicit unique source subaddresses. Empty wallet-wide selection is refused.
    pub subaddr_indices: Vec<u32>,
    /// Native wallet priority, 0 through 4.
    pub priority: u8,
}

/// Signed but unbroadcast private candidate. No serialization or unredacted Debug.
/// Publication is an effect requiring the separate fresh DOM collateral grant.
pub struct PreparedPrivateFundingV12 {
    raw: Zeroizing<Vec<u8>>,
    verified: VerifiedRawFundingV12,
}
impl core::fmt::Debug for PreparedPrivateFundingV12 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PreparedPrivateFundingV12(<private signed transaction>)")
    }
}
impl PreparedPrivateFundingV12 {
    /// Import durable private bytes and independently recheck their complete binding.
    pub fn import(
        raw: Vec<u8>,
        expected_tx_hash: [u8; 32],
        spend: [u8; 32],
        view: &[u8; 32],
        amount: u64,
        max_fee: u64,
    ) -> Result<Self, PrivateFundingErrorV12> {
        let signed_bytes = Zeroizing::new(raw);
        let verified = verify_exact_raw_funding_v12(
            &signed_bytes,
            expected_tx_hash,
            spend,
            view,
            amount,
            max_fee,
        )?;
        Ok(Self {
            raw: signed_bytes,
            verified,
        })
    }
    /// Verified public transaction identity and economics.
    pub fn verified(&self) -> VerifiedRawFundingV12 {
        self.verified
    }
    /// Scoped access for owner-only durable custody or grant-gated exact relay.
    pub fn with_raw<R>(&self, use_bytes: impl FnOnce(&[u8]) -> R) -> R {
        use_bytes(&self.raw)
    }
}

/// Dedicated loopback wallet RPC client. The operator must isolate this funding
/// wallet endpoint and its private spending authority from other local users.
/// HTTP redirects and environment proxies are disabled; DNS cannot redirect it.
/// This client deliberately does not retry an ambiguous transfer response.
pub struct BlockingPrivateFundingWalletV12 {
    base_url: String,
    client: Client,
}
impl BlockingPrivateFundingWalletV12 {
    /// Uses the same strict loopback URL grammar as the native Monero broadcaster.
    /// A wallet with RPC authentication must be exposed through an authenticated
    /// local operator proxy; credentials are never placed in a URL or response log.
    pub fn new(base_url: impl Into<String>) -> Result<Self, PrivateFundingErrorV12> {
        let (base_url, _) = crate::normalize_loopback_v5(&base_url.into())
            .map_err(|_| PrivateFundingErrorV12::Request)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            // 120 s was exactly the DOM actuator lease: one slow transfer could
            // spend the whole lease of the route step that issued it. Sixty
            // seconds is the external-call ceiling every other adapter obeys.
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|_| PrivateFundingErrorV12::Unavailable)?;
        Ok(Self { base_url, client })
    }

    /// Privately signs one transaction. The derived shared address, exact amount,
    /// no-timelock requirement and fee cap are checked from raw bytes locally.
    /// `get_tx_metadata` and `get_tx_key` are false: no extra spend capability is
    /// needed. This function must run before admission pins the resulting txid.
    pub fn prepare(
        &self,
        request: &PrivateFundingRequestV12,
        view: &[u8; 32],
    ) -> Result<PreparedPrivateFundingV12, PrivateFundingErrorV12> {
        let params = transfer_params(request, view)?;
        let body = WalletRequest {
            jsonrpc: "2.0",
            id: "dom-private-funding-v12",
            method: "transfer",
            params,
        };
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&body)
            .send()
            .map_err(|_| PrivateFundingErrorV12::Unavailable)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(PrivateFundingErrorV12::WalletRejected);
        }
        if !response.status().is_success() {
            return Err(PrivateFundingErrorV12::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_PRIVATE_RESPONSE_BYTES as u64)
        {
            return Err(PrivateFundingErrorV12::Response);
        }
        let bytes = read_private_response(response)?;
        let response = parse_wallet_response(&bytes)?;
        accept_response(response, request, view)
    }
}

#[derive(Serialize)]
struct WalletRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: TransferParams<'a>,
}
#[derive(Serialize)]
struct TransferParams<'a> {
    destinations: [Destination; 1],
    account_index: u32,
    subaddr_indices: &'a [u32],
    priority: u8,
    unlock_time: u64,
    do_not_relay: bool,
    get_tx_hex: bool,
    get_tx_metadata: bool,
    get_tx_key: bool,
}
#[derive(Serialize)]
struct Destination {
    amount: u64,
    address: String,
}
fn transfer_params<'a>(
    request: &'a PrivateFundingRequestV12,
    view: &[u8; 32],
) -> Result<TransferParams<'a>, PrivateFundingErrorV12> {
    if request.amount_piconero == 0
        || request.max_fee_piconero == 0
        || request.priority > 4
        || request.subaddr_indices.is_empty()
        || request.subaddr_indices.len() > 256
    {
        return Err(PrivateFundingErrorV12::Request);
    }
    let unique: std::collections::BTreeSet<_> = request.subaddr_indices.iter().collect();
    if unique.len() != request.subaddr_indices.len() {
        return Err(PrivateFundingErrorV12::Request);
    }
    let address =
        standard_funding_address_v12(request.network_tag, request.combined_spend_public, view)?;
    Ok(TransferParams {
        destinations: [Destination {
            amount: request.amount_piconero,
            address,
        }],
        account_index: request.account_index,
        subaddr_indices: &request.subaddr_indices,
        priority: request.priority,
        unlock_time: 0,
        do_not_relay: true,
        get_tx_hex: true,
        get_tx_metadata: false,
        get_tx_key: false,
    })
}
#[derive(Deserialize)]
struct WalletEnvelope<'a> {
    #[serde(borrow)]
    jsonrpc: &'a str,
    #[serde(borrow)]
    id: &'a str,
    #[serde(borrow)]
    result: Option<TransferResult<'a>>,
    error: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct TransferResult<'a> {
    #[serde(borrow)]
    tx_hash: &'a str,
    #[serde(borrow)]
    tx_blob: &'a str,
    amount: u64,
    fee: u64,
    #[serde(default, borrow)]
    unsigned_txset: &'a str,
    #[serde(default, borrow)]
    multisig_txset: &'a str,
    #[serde(default, borrow)]
    tx_metadata: &'a str,
    #[serde(default, borrow)]
    tx_key: &'a str,
}
fn read_private_response(
    mut input: impl Read,
) -> Result<Zeroizing<Vec<u8>>, PrivateFundingErrorV12> {
    // Never grow a buffer containing signed raw bytes: keep one fixed backing
    // allocation across short reads, interruption, parse failure and success.
    let mut bytes = Zeroizing::new(vec![0u8; MAX_PRIVATE_RESPONSE_BYTES + 1]);
    let mut length = 0;
    while length < bytes.len() {
        match input.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PrivateFundingErrorV12::Unavailable),
        }
    }
    if length > MAX_PRIVATE_RESPONSE_BYTES {
        return Err(PrivateFundingErrorV12::Response);
    }
    bytes.truncate(length);
    Ok(bytes)
}
fn parse_wallet_response(bytes: &[u8]) -> Result<WalletEnvelope<'_>, PrivateFundingErrorV12> {
    // Native transfer hex/identifiers need no escapes. Refuse escaped strings
    // before serde can create an unzeroized temporary decoding buffer.
    if bytes.contains(&b'\\') {
        return Err(PrivateFundingErrorV12::Response);
    }
    serde_json::from_slice(bytes).map_err(|_| PrivateFundingErrorV12::Response)
}
fn accept_response(
    response: WalletEnvelope<'_>,
    request: &PrivateFundingRequestV12,
    view: &[u8; 32],
) -> Result<PreparedPrivateFundingV12, PrivateFundingErrorV12> {
    if response.jsonrpc != "2.0" || response.id != "dom-private-funding-v12" {
        return Err(PrivateFundingErrorV12::Response);
    }
    if response.error.is_some() {
        return Err(if response.result.is_some() {
            PrivateFundingErrorV12::Response
        } else {
            PrivateFundingErrorV12::WalletRejected
        });
    }
    let result = response.result.ok_or(PrivateFundingErrorV12::Response)?;
    if result.amount != request.amount_piconero
        || result.fee == 0
        || result.fee > request.max_fee_piconero
        || !result.unsigned_txset.is_empty()
        || !result.multisig_txset.is_empty()
        || !result.tx_metadata.is_empty()
        || !result.tx_key.is_empty()
    {
        return Err(PrivateFundingErrorV12::Response);
    }
    let hash = crate::decode_hex_32(result.tx_hash)
        .filter(|h| *h != [0; 32])
        .ok_or(PrivateFundingErrorV12::Response)?;
    let raw = decode_candidate(result.tx_blob)?;
    let candidate = PreparedPrivateFundingV12::import(
        raw,
        hash,
        request.combined_spend_public,
        view,
        request.amount_piconero,
        request.max_fee_piconero,
    )?;
    if candidate.verified().fee_piconero() != result.fee {
        return Err(PrivateFundingErrorV12::Response);
    }
    Ok(candidate)
}
fn decode_candidate(hex: &str) -> Result<Vec<u8>, PrivateFundingErrorV12> {
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > MAX_VERIFIED_RAW_TX_BYTES * 2 {
        return Err(PrivateFundingErrorV12::Response);
    }
    fn nibble(b: u8) -> Result<u8, PrivateFundingErrorV12> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(PrivateFundingErrorV12::Response),
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    for pair in hex.as_bytes().chunks_exact(2) {
        bytes.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(std::mem::take(&mut *bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> (PrivateFundingRequestV12, [u8; 32]) {
        let mut g = [0x66; 32];
        g[0] = 0x58;
        let mut view = [0; 32];
        view[0] = 1;
        (
            PrivateFundingRequestV12 {
                network_tag: 2,
                combined_spend_public: g,
                amount_piconero: 100,
                max_fee_piconero: 10,
                account_index: 3,
                subaddr_indices: vec![0, 1],
                priority: 0,
            },
            view,
        )
    }
    #[test]
    fn private_transfer_cannot_accidentally_enable_relay_or_request_spend_material() {
        let (r, view) = request();
        let p = transfer_params(&r, &view).unwrap();
        let value = serde_json::to_value(p).unwrap();
        assert_eq!(value["do_not_relay"], true);
        assert_eq!(value["get_tx_hex"], true);
        assert_eq!(value["get_tx_metadata"], false);
        assert_eq!(value["get_tx_key"], false);
        assert_eq!(value["unlock_time"], 0);
        assert_eq!(value["destinations"].as_array().unwrap().len(), 1);
        assert_eq!(value["destinations"][0]["amount"], 100);
        assert_eq!(
            value["destinations"][0]["address"].as_str().unwrap().len(),
            95
        );
    }
    #[test]
    fn mismatched_id_null_success_and_dual_error_result_are_hard_failures() {
        let (request, view) = request();
        for raw in [
            r#"{"jsonrpc":"2.0","id":"another","result":null}"#,
            r#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":null}"#,
        ] {
            let response = serde_json::from_str(raw).unwrap();
            assert!(matches!(
                accept_response(response, &request, &view),
                Err(PrivateFundingErrorV12::Response)
            ));
        }
        let raw = r#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","error":{"code":-1},"result":{"tx_hash":"","tx_blob":"","amount":100,"fee":10}}"#;
        assert!(matches!(
            accept_response(serde_json::from_str(raw).unwrap(), &request, &view),
            Err(PrivateFundingErrorV12::Response)
        ));
        let explicit = r#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","error":{"code":-1}}"#;
        assert!(matches!(
            accept_response(serde_json::from_str(explicit).unwrap(), &request, &view),
            Err(PrivateFundingErrorV12::WalletRejected)
        ));
    }
    #[test]
    fn endpoint_or_candidate_encoding_cannot_escape_its_narrow_scope() {
        for endpoint in [
            "http://example.com:18083/",
            "https://127.0.0.1:18083/",
            "http://user:secret@127.0.0.1:18083/",
            "http://127.0.0.1:18083/redirect",
            "http://127.0.0.1:18083/?target=outside",
        ] {
            assert!(BlockingPrivateFundingWalletV12::new(endpoint).is_err());
        }
        for raw in ["", "0", "AA", "zz", "00\n"] {
            assert!(decode_candidate(raw).is_err());
        }
        assert_eq!(decode_candidate("00ff12").unwrap(), vec![0, 255, 18]);
        let (mut r, view) = request();
        r.subaddr_indices = vec![1, 1];
        assert!(transfer_params(&r, &view).is_err());
        r.subaddr_indices.clear();
        assert!(transfer_params(&r, &view).is_err());
    }

    #[test]
    fn transfer_fields_borrow_the_retained_buffer_even_before_later_failures() {
        let response = br#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":{"tx_hash":"00","tx_blob":"0123456789abcdef","amount":100,"fee":10}}"#;
        let bytes = read_private_response(&response[..]).unwrap();
        let result = parse_wallet_response(&bytes).unwrap().result.unwrap();
        let storage = bytes.as_ptr() as usize;
        let raw_start = result.tx_blob.as_ptr() as usize;
        assert!(raw_start >= storage && raw_start + result.tx_blob.len() <= storage + bytes.len());
        assert_eq!(result.tx_blob, "0123456789abcdef");
        // A later duplicate/type/truncation failure never leaves a heap-owned
        // tx_blob String behind: that field's type is an input-buffer loan.
        for malformed in [
            br#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":{"tx_blob":"0123","tx_blob":"4567"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":{"tx_blob":"0123","fee":"wrong"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":{"tx_blob":"0123""#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"dom-private-funding-v12","result":{"tx_blob":"\u0030123"}}"#.as_slice(),
        ] { assert!(matches!(parse_wallet_response(malformed),Err(PrivateFundingErrorV12::Response))); }
    }

    #[test]
    fn fixed_private_response_read_handles_short_reads_interruption_and_bounds() {
        struct InterruptedOnce<'a> {
            bytes: &'a [u8],
            interrupted: bool,
        }
        impl Read for InterruptedOnce<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let count = self.bytes.len().min(out.len()).min(3);
                out[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes = &self.bytes[count..];
                Ok(count)
            }
        }
        let bytes = read_private_response(InterruptedOnce {
            bytes: b"private raw response",
            interrupted: false,
        })
        .unwrap();
        assert_eq!(bytes.as_slice(), b"private raw response");
        assert_eq!(bytes.capacity(), MAX_PRIVATE_RESPONSE_BYTES + 1);
        let oversized = vec![0u8; MAX_PRIVATE_RESPONSE_BYTES + 1];
        assert!(matches!(
            read_private_response(oversized.as_slice()),
            Err(PrivateFundingErrorV12::Response)
        ));
    }

    #[test]
    fn real_http_wrong_rpc_identity_is_not_absence_and_is_not_retried() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut block = [0u8; 1024];
            let request = loop {
                let count = stream.read(&mut block).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&block[..count]);
                assert!(bytes.len() < 16_384);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice::<serde_json::Value>(
                            &bytes[end + 4..end + 4 + length],
                        )
                        .unwrap();
                    }
                }
            };
            assert_eq!(request["method"], "transfer");
            assert_eq!(request["params"]["do_not_relay"], true);
            let response = r#"{"jsonrpc":"2.0","id":"substituted","result":null}"#;
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(),response).unwrap();
            stream.flush().unwrap();
            drop(stream);
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(),Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        let client = BlockingPrivateFundingWalletV12::new(format!("http://{address}/")).unwrap();
        let (request, view) = request();
        assert!(matches!(
            client.prepare(&request, &view),
            Err(PrivateFundingErrorV12::Response)
        ));
        server.join().unwrap();
    }
}
