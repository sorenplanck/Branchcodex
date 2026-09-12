//! Exact-byte monerod broadcaster with ambiguous-response reconciliation.

#![forbid(unsafe_code)]

mod time_header_v23;
pub use time_header_v23::MoneroTimeHeaderV23;
mod private_funding_v12;
pub use private_funding_v12::{
    BlockingPrivateFundingWalletV12, PreparedPrivateFundingV12, PrivateFundingErrorV12,
    PrivateFundingRequestV12,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::Read;
use xmr_raw_tx_verify::verify_exact_raw_transaction;
use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort, SpendPortError};

/// Direct loopback monerod broadcaster.
pub struct BlockingMoneroBroadcaster {
    base_url: String,
    client: Client,
    expected_genesis: Option<[u8; 32]>,
}

impl core::fmt::Debug for BlockingMoneroBroadcaster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockingMoneroBroadcaster")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BlockingMoneroBroadcaster {
    /// Creates a finite-timeout loopback client.
    pub fn new(base_url: impl Into<String>) -> Result<Self, SpendPortError> {
        let (base_url, _) = normalize_loopback_v5(&base_url.into())?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(30))
            .build()
            .map_err(|_| SpendPortError::Retryable)?;
        Ok(Self {
            base_url,
            client,
            expected_genesis: None,
        })
    }

    /// Binds production broadcast and reconciliation to an authenticated
    /// deployment genesis. The legacy constructor remains for lab callers.
    pub fn new_for_chain_v5(
        base_url: impl Into<String>,
        genesis: [u8; 32],
    ) -> Result<Self, SpendPortError> {
        if genesis == [0; 32] {
            return Err(SpendPortError::Rejected);
        }
        let mut value = Self::new(base_url)?;
        value.expected_genesis = Some(genesis);
        Ok(value)
    }

    fn require_genesis_v5(&self) -> Result<(), SpendPortError> {
        if let Some(expected) = self.expected_genesis {
            let reader = BlockingMoneroDaemonReaderV1 {
                base_url: self.base_url.clone(),
                client: self.client.clone(),
            };
            if reader.block_hash_at(0)? != expected {
                return Err(SpendPortError::Rejected);
            }
        }
        Ok(())
    }

    fn transaction_is_known(&self, tx_hash: [u8; 32]) -> Result<bool, SpendPortError> {
        self.require_genesis_v5()?;
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![hex_lower(&tx_hash)],
                decode_as_json: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: GetTransactionsLocationResponse = read_json_bounded_v5(response)?;
        let known = exact_location_v5(&body, tx_hash)?.is_some();
        self.require_genesis_v5()?;
        Ok(known)
    }
}

impl ExactBroadcastPort for BlockingMoneroBroadcaster {
    fn submit_exact(
        &mut self,
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<BroadcastAcceptance, SpendPortError> {
        if tx_hash == [0; 32] || raw_tx.is_empty() {
            return Err(SpendPortError::Rejected);
        }
        // Re-verify the exact bytes against the expected consensus hash before
        // they reach the network. The delivery journal persists bytes and the
        // broadcaster is a separate step, so this guards against a corrupt or
        // substituted record just as the sidecar check guards the response.
        verify_exact_raw_transaction(raw_tx, tx_hash).map_err(|_| SpendPortError::Rejected)?;
        self.require_genesis_v5()?;
        let result = self
            .client
            .post(format!("{}/send_raw_transaction", self.base_url))
            .json(&SendRawTransactionRequest {
                tx_as_hex: hex_lower(raw_tx),
                do_not_relay: false,
            })
            .send();
        let response = match result {
            Ok(value) => value,
            Err(_) => {
                return if self.transaction_is_known(tx_hash)? {
                    Ok(BroadcastAcceptance::AlreadyKnown)
                } else {
                    Err(SpendPortError::Retryable)
                };
            }
        };
        if !response.status().is_success() {
            return if self.transaction_is_known(tx_hash)? {
                Ok(BroadcastAcceptance::AlreadyKnown)
            } else if response.status().is_server_error() || response.status().as_u16() == 429 {
                Err(SpendPortError::Retryable)
            } else {
                Err(SpendPortError::Rejected)
            };
        }
        let body: SendRawTransactionResponse = read_json_bounded_v5(response)?;
        if body.status == "OK" && !body.permanent_rejection() {
            return Ok(BroadcastAcceptance::Accepted);
        }
        if self.transaction_is_known(tx_hash)? {
            Ok(BroadcastAcceptance::AlreadyKnown)
        } else if body.busy || body.not_relayed {
            Err(SpendPortError::Retryable)
        } else {
            Err(SpendPortError::Rejected)
        }
    }
}

/// Read-only loopback monerod reader for reconciliation and observation.
///
/// Same endpoint policy as the broadcaster: loopback only, finite timeouts.
/// Every answer is a single daemon's view; quorum assembly is the caller's
/// job, never this client's.
#[derive(Clone)]
pub struct BlockingMoneroDaemonReaderV1 {
    base_url: String,
    client: Client,
}

impl core::fmt::Debug for BlockingMoneroDaemonReaderV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockingMoneroDaemonReaderV1")
            .field("base_url", &self.base_url)
            .finish()
    }
}

/// One daemon's answer about an exact txid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoneroTransactionLocationV1 {
    /// Still in the transaction pool.
    pub in_pool: bool,
    /// Inclusion height when mined.
    pub block_height: Option<u64>,
}

/// One RingCT output resolved by absolute index from a genesis-bound daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoneroRingMemberV23 {
    /// Absolute amount-zero output index.
    pub global_index: u64,
    /// Canonical one-time output key.
    pub key: [u8; 32],
    /// Canonical amount commitment/mask.
    pub commitment: [u8; 32],
}

#[derive(Serialize)]
struct GetOutsRequestV23 {
    outputs: Vec<GetOutRequestV23>,
    get_txid: bool,
}

#[derive(Serialize)]
struct GetOutRequestV23 {
    amount: u64,
    index: u64,
}

#[derive(Deserialize)]
struct GetOutsResponseV23 {
    status: String,
    untrusted: bool,
    outs: Vec<GetOutResponseV23>,
}

#[derive(Deserialize)]
struct GetOutResponseV23 {
    key: String,
    mask: String,
    unlocked: bool,
}

/// One daemon's bounded observation, before any quorum decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoneroTransactionObservationV5 {
    /// Exact txid explicitly listed as missing by this daemon.
    Absent,
    /// Exact txid is in the pool, without canonical inclusion.
    InPool,
    /// Exact txid belongs to the returned canonical block.
    Included {
        /// Zero-based inclusion height.
        height: u64,
        /// Canonical block hash corroborated after reading its transaction list.
        block_hash: [u8; 32],
        /// Number of blocks, as returned by monerod get_height.
        chain_length: u64,
    },
}

impl BlockingMoneroDaemonReaderV1 {
    /// Fetch exact canonical bytes for a mined transaction from a daemon whose
    /// genesis is checked before and after the request. Quorum and finality are
    /// still caller responsibilities.
    pub fn transaction_raw_v23(
        &self,
        tx_hash: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<Vec<u8>, SpendPortError> {
        if tx_hash == [0; 32] || genesis == [0; 32] || self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        let wanted = hex_lower(&tx_hash);
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![wanted.clone()],
                decode_as_json: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        let body: GetTransactionsLocationResponse = read_json_bounded_v5(response)?;
        if body.status != "OK" || body.untrusted || !body.missed_tx.is_empty() {
            return Err(SpendPortError::Retryable);
        }
        let [entry] = body.txs.as_slice() else {
            return Err(SpendPortError::Rejected);
        };
        if entry.tx_hash != wanted || entry.in_pool || entry.block_height.is_none() {
            return Err(SpendPortError::Rejected);
        }
        let raw =
            decode_hex_bounded_v23(&entry.as_hex, xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES)?;
        verify_exact_raw_transaction(&raw, tx_hash).map_err(|_| SpendPortError::Rejected)?;
        if self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        Ok(raw)
    }

    /// Resolves exactly one modern 16-member RingCT ring. The genesis is read
    /// both before and after `/get_outs`; quorum assembly and comparison are a
    /// separate caller responsibility.
    pub fn ring_members_v23(
        &self,
        global_indices: &[u64],
        genesis: [u8; 32],
    ) -> Result<Vec<MoneroRingMemberV23>, SpendPortError> {
        if genesis == [0; 32]
            || global_indices.len() != 16
            || global_indices.windows(2).any(|pair| pair[0] >= pair[1])
            || self.block_hash_at(0)? != genesis
        {
            return Err(SpendPortError::Rejected);
        }
        let response = self
            .client
            .post(format!("{}/get_outs", self.base_url))
            .json(&GetOutsRequestV23 {
                outputs: global_indices
                    .iter()
                    .map(|index| GetOutRequestV23 {
                        amount: 0,
                        index: *index,
                    })
                    .collect(),
                get_txid: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: GetOutsResponseV23 = read_json_bounded_v5(response)?;
        if body.status != "OK" || body.untrusted || body.outs.len() != global_indices.len() {
            return Err(SpendPortError::Retryable);
        }
        let members = global_indices
            .iter()
            .zip(body.outs)
            .map(|(index, output)| {
                if !output.unlocked {
                    return Err(SpendPortError::Rejected);
                }
                Ok(MoneroRingMemberV23 {
                    global_index: *index,
                    key: decode_hex_32(&output.key).ok_or(SpendPortError::Rejected)?,
                    commitment: decode_hex_32(&output.mask).ok_or(SpendPortError::Rejected)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        Ok(members)
    }

    /// Corroborates location with the canonical block's actual transaction
    /// list. A location height plus an unrelated header is not inclusion.
    /// Both genesis and inclusion header are reread across the observation.
    pub fn transaction_observation_v5(
        &self,
        tx_hash: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<MoneroTransactionObservationV5, SpendPortError> {
        if genesis == [0; 32] || self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        let location = self.transaction_location(tx_hash)?;
        let observation = match location {
            None => MoneroTransactionObservationV5::Absent,
            Some(MoneroTransactionLocationV1 { in_pool: true, .. }) => {
                MoneroTransactionObservationV5::InPool
            }
            Some(MoneroTransactionLocationV1 {
                block_height: Some(height),
                ..
            }) => {
                let response = self
                    .client
                    .post(format!("{}/json_rpc", self.base_url))
                    .json(&serde_json::json!({"jsonrpc": "2.0", "id": "0",
                        "method": "get_block", "params": {"height": height}}))
                    .send()
                    .map_err(|_| SpendPortError::Retryable)?;
                let body: serde_json::Value = read_json_bounded_v5(response)?;
                let block_hash = inclusion_block_v5(&body, height, tx_hash)?;
                let chain_length = self.daemon_height()?;
                if chain_length <= height || self.block_hash_at(height)? != block_hash {
                    return Err(SpendPortError::Retryable);
                }
                MoneroTransactionObservationV5::Included {
                    height,
                    block_hash,
                    chain_length,
                }
            }
            _ => return Err(SpendPortError::Retryable),
        };
        if self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        Ok(observation)
    }

    /// A key-image answer scoped to the expected genesis before and after I/O.
    pub fn key_image_spent_on_chain_v5(
        &self,
        key_image: [u8; 32],
        genesis: [u8; 32],
    ) -> Result<bool, SpendPortError> {
        if genesis == [0; 32] || self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        let spent = self.key_image_spent(key_image)?;
        if self.block_hash_at(0)? != genesis {
            return Err(SpendPortError::Rejected);
        }
        Ok(spent)
    }
    /// Canonical loopback socket port used to reject duplicate quorum voters.
    pub fn loopback_port_v5(&self) -> Result<u16, SpendPortError> {
        normalize_loopback_v5(&self.base_url).map(|(_, port)| port)
    }

    /// Creates a finite-timeout loopback reader.
    pub fn new(base_url: impl Into<String>) -> Result<Self, SpendPortError> {
        let (base_url, _) = normalize_loopback_v5(&base_url.into())?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(30))
            .build()
            .map_err(|_| SpendPortError::Retryable)?;
        Ok(Self { base_url, client })
    }

    /// Where the daemon sees an exact txid, `None` when unknown to it.
    pub fn transaction_location(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<MoneroTransactionLocationV1>, SpendPortError> {
        let wanted = hex_lower(&tx_hash);
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![wanted.clone()],
                decode_as_json: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: GetTransactionsLocationResponse = read_json_bounded_v5(response)?;
        exact_location_v5(&body, tx_hash)
    }

    /// The daemon's current chain height.
    pub fn daemon_height(&self) -> Result<u64, SpendPortError> {
        let response = self
            .client
            .get(format!("{}/get_height", self.base_url))
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: GetHeightResponse = read_json_bounded_v5(response)?;
        if body.height == 0 || body.status != "OK" || body.untrusted {
            return Err(SpendPortError::Retryable);
        }
        Ok(body.height)
    }

    /// The canonical block hash at one height, from the daemon's chain view.
    pub fn block_hash_at(&self, height: u64) -> Result<[u8; 32], SpendPortError> {
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block_header_by_height",
                "params": { "height": height },
            }))
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: serde_json::Value = read_json_bounded_v5(response)?;
        let result = body.get("result").ok_or(SpendPortError::Retryable)?;
        let header = result
            .get("block_header")
            .ok_or(SpendPortError::Retryable)?;
        if body.get("error").is_some_and(|error| !error.is_null())
            || result.get("status").and_then(serde_json::Value::as_str) != Some("OK")
            || result.get("untrusted").and_then(serde_json::Value::as_bool) != Some(false)
            || header.get("height").and_then(serde_json::Value::as_u64) != Some(height)
            || header
                .get("orphan_status")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
        {
            return Err(SpendPortError::Retryable);
        }
        let hash = header
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .and_then(decode_hex_32)
            .filter(|hash| *hash != [0; 32])
            .ok_or(SpendPortError::Retryable)?;
        Ok(hash)
    }

    /// Whether the exact key image is spent in the daemon's view (chain or
    /// pool alike: either way the shared output is contested).
    pub fn key_image_spent(&self, key_image: [u8; 32]) -> Result<bool, SpendPortError> {
        let response = self
            .client
            .post(format!("{}/is_key_image_spent", self.base_url))
            .json(&IsKeyImageSpentRequest {
                key_images: vec![hex_lower(&key_image)],
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: IsKeyImageSpentResponse = read_json_bounded_v5(response)?;
        if body.status != "OK" || body.untrusted {
            return Err(SpendPortError::Retryable);
        }
        match body.spent_status.as_slice() {
            [0] => Ok(false),
            [1] | [2] => Ok(true),
            // One requested key image requires exactly one recognized answer.
            // A malformed successful response is not an unavailable voter.
            _ => Err(SpendPortError::Rejected),
        }
    }
}

#[derive(Serialize)]
struct IsKeyImageSpentRequest {
    key_images: Vec<String>,
}

#[derive(Deserialize)]
struct IsKeyImageSpentResponse {
    status: String,
    untrusted: bool,
    #[serde(default)]
    spent_status: Vec<u8>,
}

#[derive(Deserialize)]
struct GetHeightResponse {
    status: String,
    untrusted: bool,
    #[serde(default)]
    height: u64,
}

#[derive(Deserialize)]
struct GetTransactionsLocationResponse {
    status: String,
    untrusted: bool,
    #[serde(default)]
    missed_tx: Vec<String>,
    #[serde(default)]
    txs: Vec<TransactionLocationEntry>,
}

#[derive(Deserialize)]
struct TransactionLocationEntry {
    tx_hash: String,
    in_pool: bool,
    block_height: Option<u64>,
    #[serde(default)]
    as_hex: String,
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = (chunk[0] as char).to_digit(16)?;
        let low = (chunk[1] as char).to_digit(16)?;
        out[index] = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

fn decode_hex_bounded_v23(value: &str, maximum: usize) -> Result<Vec<u8>, SpendPortError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 || bytes.len() / 2 > maximum {
        return Err(SpendPortError::Rejected);
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(SpendPortError::Rejected)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(SpendPortError::Rejected)?;
        output.push(u8::try_from(high * 16 + low).map_err(|_| SpendPortError::Rejected)?);
    }
    Ok(output)
}

#[derive(Serialize)]
struct SendRawTransactionRequest {
    tx_as_hex: String,
    do_not_relay: bool,
}

#[derive(Deserialize)]
struct SendRawTransactionResponse {
    status: String,
    #[serde(default)]
    busy: bool,
    #[serde(default)]
    not_relayed: bool,
    #[serde(default)]
    double_spend: bool,
    #[serde(default)]
    fee_too_low: bool,
    #[serde(default)]
    invalid_input: bool,
    #[serde(default)]
    invalid_output: bool,
    #[serde(default)]
    low_mixin: bool,
    #[serde(default)]
    not_rct: bool,
    #[serde(default)]
    overspend: bool,
    #[serde(default)]
    too_big: bool,
}

impl SendRawTransactionResponse {
    fn permanent_rejection(&self) -> bool {
        self.double_spend
            || self.fee_too_low
            || self.invalid_input
            || self.invalid_output
            || self.low_mixin
            || self.not_rct
            || self.overspend
            || self.too_big
    }
}

#[derive(Serialize)]
struct GetTransactionsRequest {
    txs_hashes: Vec<String>,
    decode_as_json: bool,
}

const MAX_RPC_RESPONSE_BYTES_V5: u64 = 4 * 1024 * 1024;

fn inclusion_block_v5(
    body: &serde_json::Value,
    height: u64,
    tx_hash: [u8; 32],
) -> Result<[u8; 32], SpendPortError> {
    let result = body.get("result").ok_or(SpendPortError::Retryable)?;
    let header = result
        .get("block_header")
        .ok_or(SpendPortError::Retryable)?;
    if body.get("error").is_some_and(|error| !error.is_null())
        || result.get("status").and_then(serde_json::Value::as_str) != Some("OK")
        || result.get("untrusted").and_then(serde_json::Value::as_bool) != Some(false)
        || header.get("height").and_then(serde_json::Value::as_u64) != Some(height)
        || header
            .get("orphan_status")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(SpendPortError::Retryable);
    }
    let hashes = result
        .get("tx_hashes")
        .and_then(serde_json::Value::as_array)
        .ok_or(SpendPortError::Retryable)?;
    let mut found = 0usize;
    for hash in hashes {
        let hash = hash
            .as_str()
            .and_then(decode_hex_32)
            .ok_or(SpendPortError::Retryable)?;
        if hash == tx_hash {
            found += 1;
        }
    }
    if found != 1 {
        return Err(SpendPortError::Retryable);
    }
    header
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .and_then(decode_hex_32)
        .filter(|hash| *hash != [0; 32])
        .ok_or(SpendPortError::Retryable)
}

fn normalize_loopback_v5(input: &str) -> Result<(String, u16), SpendPortError> {
    let mut url = reqwest::Url::parse(input).map_err(|_| SpendPortError::Rejected)?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        )
    {
        return Err(SpendPortError::Rejected);
    }
    if url.host_str() == Some("localhost") {
        url.set_host(Some("127.0.0.1"))
            .map_err(|_| SpendPortError::Rejected)?;
    }
    let port = url
        .port_or_known_default()
        .filter(|port| *port > 0)
        .ok_or(SpendPortError::Rejected)?;
    Ok((url.as_str().trim_end_matches('/').to_owned(), port))
}

fn read_json_bounded_v5<T: serde::de::DeserializeOwned>(
    response: reqwest::blocking::Response,
) -> Result<T, SpendPortError> {
    if !response.status().is_success() {
        return Err(SpendPortError::Retryable);
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RPC_RESPONSE_BYTES_V5)
    {
        return Err(SpendPortError::Rejected);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RPC_RESPONSE_BYTES_V5 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SpendPortError::Retryable)?;
    if bytes.len() as u64 > MAX_RPC_RESPONSE_BYTES_V5 {
        return Err(SpendPortError::Rejected);
    }
    // Interrupted reads remain retryable above. A complete HTTP success whose
    // body cannot decode as the expected response is a protocol contradiction.
    serde_json::from_slice(&bytes).map_err(|_| SpendPortError::Rejected)
}

fn exact_location_v5(
    body: &GetTransactionsLocationResponse,
    tx_hash: [u8; 32],
) -> Result<Option<MoneroTransactionLocationV1>, SpendPortError> {
    if tx_hash == [0; 32] {
        return Err(SpendPortError::Rejected);
    }
    if body.status != "OK" || body.untrusted {
        return Err(SpendPortError::Retryable);
    }
    let wanted = hex_lower(&tx_hash);
    match (body.missed_tx.as_slice(), body.txs.as_slice()) {
        ([missing], []) if missing == &wanted => Ok(None),
        ([], [entry]) if entry.tx_hash == wanted => {
            if entry.in_pool {
                Ok(Some(MoneroTransactionLocationV1 {
                    in_pool: true,
                    block_height: None,
                }))
            } else {
                Ok(Some(MoneroTransactionLocationV1 {
                    in_pool: false,
                    block_height: Some(entry.block_height.ok_or(SpendPortError::Rejected)?),
                }))
            }
        }
        // Only an explicit miss for the requested identity is absence. A
        // substituted, duplicate, contradictory or empty successful response
        // is a permanently invalid response, never a negative observation.
        _ => Err(SpendPortError::Rejected),
    }
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

    #[test]
    fn bytes_that_do_not_match_the_expected_hash_never_reach_the_network() {
        // The base URL is unroutable, so any network attempt surfaces as
        // Retryable. A Rejected verdict therefore proves the bytes were refused
        // by the independent raw-transaction check before the broadcaster ever
        // opened a connection.
        let mut broadcaster =
            BlockingMoneroBroadcaster::new("http://127.0.0.1:1").expect("construct");
        assert_eq!(
            broadcaster
                .submit_exact([0x42; 32], b"not a monero transaction")
                .unwrap_err(),
            SpendPortError::Rejected
        );
    }

    #[test]
    fn zero_hash_or_empty_bytes_are_refused() {
        let mut broadcaster =
            BlockingMoneroBroadcaster::new("http://127.0.0.1:1").expect("construct");
        assert_eq!(
            broadcaster.submit_exact([0; 32], b"x").unwrap_err(),
            SpendPortError::Rejected
        );
        assert_eq!(
            broadcaster.submit_exact([1; 32], b"").unwrap_err(),
            SpendPortError::Rejected
        );
    }
}

#[cfg(test)]
#[path = "rpc_v5_tests.rs"]
mod rpc_v5_tests;
