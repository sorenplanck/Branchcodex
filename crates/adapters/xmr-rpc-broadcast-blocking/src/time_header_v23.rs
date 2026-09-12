//! Bounded canonical-header observations for threshold-attested time evidence.
//! These are RPC statements, not independent proof-of-work validation.
use super::*;

/// Exact header facts from a trusted local Monero daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoneroTimeHeaderV23 {
    /// Native block height.
    pub height: u64,
    /// Daemon's canonical block identifier.
    pub hash: [u8; 32],
    /// Header's previous block identifier.
    pub parent: [u8; 32],
    /// Native header timestamp.
    pub timestamp: u64,
}

impl BlockingMoneroDaemonReaderV1 {
    /// Reads all checkpoint facts in one bounded response and refuses orphan,
    /// untrusted, zero-identity and incomplete projections. The caller must
    /// link the sequence to the pinned genesis and apply the selected quorum.
    pub fn time_header_at_v23(&self, height: u64) -> Result<MoneroTimeHeaderV23, SpendPortError> {
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&serde_json::json!({
                "jsonrpc":"2.0", "id":"0", "method":"get_block_header_by_height",
                "params":{"height":height}
            }))
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body: serde_json::Value = read_json_bounded_v5(response)?;
        let result = body.get("result").ok_or(SpendPortError::Rejected)?;
        let header = result.get("block_header").ok_or(SpendPortError::Rejected)?;
        if body.get("error").is_some_and(|error| !error.is_null())
            || result.get("status").and_then(serde_json::Value::as_str) != Some("OK")
            || result.get("untrusted").and_then(serde_json::Value::as_bool) != Some(false)
            || header.get("height").and_then(serde_json::Value::as_u64) != Some(height)
            || header
                .get("orphan_status")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
        {
            return Err(SpendPortError::Rejected);
        }
        let decode = |field| {
            header
                .get(field)
                .and_then(serde_json::Value::as_str)
                .and_then(decode_hex_32)
                .ok_or(SpendPortError::Rejected)
        };
        let hash = decode("hash")?;
        let parent = decode("prev_hash")?;
        let timestamp = header
            .get("timestamp")
            .and_then(serde_json::Value::as_u64)
            .ok_or(SpendPortError::Rejected)?;
        if hash == [0; 32]
            || timestamp == 0
            || (height == 0 && parent != [0; 32])
            || (height != 0 && parent == [0; 32])
        {
            return Err(SpendPortError::Rejected);
        }
        Ok(MoneroTimeHeaderV23 {
            height,
            hash,
            parent,
            timestamp,
        })
    }
}
