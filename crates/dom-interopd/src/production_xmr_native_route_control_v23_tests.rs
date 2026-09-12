//! Bounded private pipe control for the opt-in synthetic Monero history.
//! No command is sent to an external daemon, and ACKs are not mainnet proofs.
use serde::Deserialize;
use std::{io::Write, sync::mpsc::Receiver, thread::JoinHandle, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type Replies = Receiver<std::result::Result<Vec<u8>, &'static str>>;

pub(crate) struct NativeXmrHistoryTransactionV23 {
    pub tx_hash: [u8; 32],
    pub block_height: u64,
}

pub(crate) struct NativeXmrHistoryStatusV23 {
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub tip_timestamp: u64,
    pub pool_tx_hashes: Vec<[u8; 32]>,
    pub transactions: Vec<NativeXmrHistoryTransactionV23>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    schema: String,
    sequence: u64,
    accepted: bool,
    status: WireStatus,
    error: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    scope: String,
    tip_height: u64,
    tip_hash: String,
    tip_timestamp: u64,
    pool_tx_hashes: Vec<String>,
    transactions: Vec<WireTransaction>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTransaction {
    tx_hash: String,
    block_height: u64,
}

fn hash(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical local history hash".into());
    }
    let value = hex::decode(text)?
        .try_into()
        .map_err(|_| "local history hash size")?;
    if value == [0; 32] {
        return Err("zero local history hash".into());
    }
    Ok(value)
}

impl WireStatus {
    fn checked(self) -> Result<NativeXmrHistoryStatusV23> {
        if self.scope != "local-synthetic-history-not-mainnet-confirmation"
            || !(200..=1_000_000).contains(&self.tip_height)
            || self.tip_timestamp == 0
            || self.pool_tx_hashes.len() > 32
            || self.transactions.len() > 256
        {
            return Err("local history scope or size refused".into());
        }
        let mut unique = std::collections::BTreeSet::new();
        let mut transactions = Vec::with_capacity(self.transactions.len());
        for tx in self.transactions {
            let tx_hash = hash(&tx.tx_hash)?;
            if tx.block_height == 0 || tx.block_height > self.tip_height || !unique.insert(tx_hash)
            {
                return Err("local history transaction location or identity refused".into());
            }
            transactions.push(NativeXmrHistoryTransactionV23 {
                tx_hash,
                block_height: tx.block_height,
            });
        }
        let mut pool = Vec::with_capacity(self.pool_tx_hashes.len());
        for tx in self.pool_tx_hashes {
            let tx_hash = hash(&tx)?;
            if !unique.insert(tx_hash) {
                return Err("local pool duplicates retained history".into());
            }
            pool.push(tx_hash);
        }
        Ok(NativeXmrHistoryStatusV23 {
            tip_height: self.tip_height,
            tip_timestamp: self.tip_timestamp,
            tip_hash: hash(&self.tip_hash)?,
            pool_tx_hashes: pool,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn status() -> Value {
        json!({"scope":"local-synthetic-history-not-mainnet-confirmation",
            "tip_height":200,"tip_hash":hex::encode([7;32]),"tip_timestamp":1000,
            "pool_tx_hashes":[hex::encode([8;32])],
            "transactions":[{"tx_hash":hex::encode([9;32]),"block_height":100}]})
    }
    fn ack(sequence: u64, status: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({
            "schema":"DOM-XMR-OFFLINE-CONTROL-ACK-V23","sequence":sequence,
            "accepted":true,"error":null,"status":status}))
        .unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn control(replies: Vec<Vec<u8>>) -> RouteFixtureControlV23 {
        let (send, receive) = std::sync::mpsc::channel();
        for bytes in replies {
            send.send(Ok(bytes)).unwrap();
        }
        drop(send);
        RouteFixtureControlV23::new(receive, std::thread::spawn(|| {}))
    }

    #[test]
    fn local_history_ack_requires_canonical_hashes_and_disjoint_pool() {
        assert!(serde_json::from_value::<WireStatus>(status())
            .unwrap()
            .checked()
            .is_ok());
        for mutation in 0..5 {
            let mut value = status();
            match mutation {
                0 => value["scope"] = json!("mainnet"),
                1 => value["pool_tx_hashes"] = json!([hex::encode([9; 32])]),
                2 => value["tip_hash"] = json!("AA".repeat(32)),
                3 => value["transactions"][0]["block_height"] = json!(201),
                _ => value["pool_tx_hashes"] = json!([hex::encode([8; 32]), hex::encode([8; 32])]),
            }
            assert!(serde_json::from_value::<WireStatus>(value)
                .unwrap()
                .checked()
                .is_err());
        }
    }

    #[test]
    fn local_history_sequence_replay_poisoning_never_reissues_a_command() {
        let mut owner = control(vec![ack(1, status()), ack(1, status())]);
        let mut input = Vec::new();
        assert_eq!(owner.status(&mut input).unwrap().tip_height, 200);
        assert!(owner.status(&mut input).is_err());
        let written = input.len();
        assert!(owner.status(&mut input).is_err());
        assert_eq!(input.len(), written);
        let requests = input
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["sequence"], 1);
        assert_eq!(requests[1]["sequence"], 2);
    }

    #[test]
    fn local_history_advance_requires_the_exact_retained_inclusion_receipt() {
        let mut after = status();
        after["tip_height"] = json!(204);
        after["tip_hash"] = json!(hex::encode([10; 32]));
        after["pool_tx_hashes"] = json!([]);
        after["transactions"].as_array_mut().unwrap().push(json!({
            "tx_hash":hex::encode([8;32]),"block_height":201}));
        let mut input = Vec::new();
        let mut owner = control(vec![ack(1, status()), ack(2, after.clone())]);
        assert_eq!(
            owner
                .advance(&mut input, 204, 1000, &[[8; 32]])
                .unwrap()
                .tip_height,
            204
        );
        after["transactions"][1]["block_height"] = json!(202);
        let mut wrong = control(vec![ack(1, status()), ack(2, after)]);
        assert!(wrong
            .advance(&mut Vec::new(), 204, 1000, &[[8; 32]])
            .is_err());
        assert!(wrong.in_flight_or_failed);
        let mut absent = control(vec![ack(1, status())]);
        let mut bytes = Vec::new();
        assert!(absent.advance(&mut bytes, 204, 1000, &[[11; 32]]).is_err());
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn local_history_advance_cannot_rewrite_history_or_consume_unselected_pool_entries() {
        let mut before = status();
        before["pool_tx_hashes"] = json!([hex::encode([8; 32]), hex::encode([12; 32])]);
        let mut after = before.clone();
        after["tip_height"] = json!(204);
        after["tip_hash"] = json!(hex::encode([10; 32]));
        // A concurrent daemon submission may add to the pool, but cannot cause
        // an unselected transaction to be confirmed or disappear.
        after["pool_tx_hashes"] = json!([hex::encode([12; 32]), hex::encode([13; 32])]);
        after["transactions"].as_array_mut().unwrap().push(json!({
            "tx_hash":hex::encode([8;32]),"block_height":201}));
        let mut valid = control(vec![ack(1, before.clone()), ack(2, after.clone())]);
        assert!(valid
            .advance(&mut Vec::new(), 204, 1000, &[[8; 32]])
            .is_ok());
        for mutation in 0..4 {
            let mut changed = after.clone();
            match mutation {
                0 => {
                    changed["transactions"].as_array_mut().unwrap().remove(0);
                }
                1 => changed["transactions"][0]["block_height"] = json!(99),
                2 => changed["transactions"].as_array_mut().unwrap().push(json!({
                    "tx_hash":hex::encode([14;32]),"block_height":201})),
                _ => changed["pool_tx_hashes"] = json!([hex::encode([13; 32])]),
            }
            let mut owner = control(vec![ack(1, before.clone()), ack(2, changed)]);
            let mut input = Vec::new();
            assert!(owner.advance(&mut input, 204, 1000, &[[8; 32]]).is_err());
            assert!(owner.in_flight_or_failed);
            let written = input.len();
            assert!(owner.status(&mut input).is_err());
            assert_eq!(input.len(), written);
        }
    }

    #[test]
    fn status_cannot_silently_drop_retained_history_or_pool() {
        for mutation in 0..3 {
            let mut after = status();
            match mutation {
                0 => after["transactions"] = json!([]),
                1 => after["pool_tx_hashes"] = json!([]),
                _ => {
                    after["tip_height"] = json!(201);
                    after["tip_hash"] = json!(hex::encode([10; 32]));
                }
            }
            let mut owner = control(vec![ack(1, status()), ack(2, after)]);
            let mut input = Vec::new();
            assert!(owner.status(&mut input).is_ok());
            assert!(owner.status(&mut input).is_err());
            assert!(owner.in_flight_or_failed);
        }
    }
}

pub(super) struct RouteFixtureControlV23 {
    replies: Replies,
    // The process owner closes stdout on teardown. Dropping this handle must
    // not join before that owner is killed during a constructor failure.
    _reader: JoinHandle<()>,
    next_sequence: u64,
    in_flight_or_failed: bool,
    previous_tip: Option<(u64, u64, [u8; 32])>,
    previous_history: std::collections::BTreeMap<[u8; 32], u64>,
    previous_pool: std::collections::BTreeSet<[u8; 32]>,
}

impl RouteFixtureControlV23 {
    pub(super) fn new(replies: Replies, reader: JoinHandle<()>) -> Self {
        Self {
            replies,
            _reader: reader,
            next_sequence: 1,
            in_flight_or_failed: false,
            previous_tip: None,
            previous_history: Default::default(),
            previous_pool: Default::default(),
        }
    }

    fn exchange(
        &mut self,
        input: &mut impl Write,
        mut request: serde_json::Value,
        timeout: Duration,
    ) -> Result<NativeXmrHistoryStatusV23> {
        if self.in_flight_or_failed || self.next_sequence > 65_536 {
            return Err("local history control is ambiguous or exhausted; do not retry".into());
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        request["schema"] = serde_json::json!("DOM-XMR-OFFLINE-CONTROL-V23");
        request["sequence"] = serde_json::json!(sequence);
        let bytes = serde_json::to_vec(&request)?;
        if bytes.len() > 4096 {
            return Err("local history control request too large".into());
        }
        self.in_flight_or_failed = true;
        input.write_all(&bytes)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let bytes = self
            .replies
            .recv_timeout(timeout)
            .map_err(|_| "local history control ACK timeout")??;
        if bytes.len() > 65_536 || !bytes.ends_with(b"\n") {
            return Err("local history ACK framing".into());
        }
        let ack: Ack = serde_json::from_slice(&bytes)?;
        if ack.schema != "DOM-XMR-OFFLINE-CONTROL-ACK-V23"
            || ack.sequence != sequence
            || !ack.accepted
            || ack.error.is_some()
        {
            return Err("local history control was refused or ACK scope changed".into());
        }
        let status = ack.status.checked()?;
        let history: std::collections::BTreeMap<_, _> = status
            .transactions
            .iter()
            .map(|tx| (tx.tx_hash, tx.block_height))
            .collect();
        let pool: std::collections::BTreeSet<_> = status.pool_tx_hashes.iter().copied().collect();
        if let Some((height, timestamp, hash)) = self.previous_tip {
            if status.tip_height < height
                || status.tip_timestamp < timestamp
                || (request["operation"] == "status" && status.tip_height != height)
                || (status.tip_height == height
                    && (status.tip_hash != hash
                        || status.tip_timestamp != timestamp
                        || history != self.previous_history))
                || self
                    .previous_history
                    .iter()
                    .any(|(tx, at)| history.get(tx) != Some(at))
                || self
                    .previous_pool
                    .iter()
                    .any(|tx| !pool.contains(tx) && !history.contains_key(tx))
            {
                return Err("local history ACK rolled back or changed an existing tip".into());
            }
        }
        self.previous_tip = Some((status.tip_height, status.tip_timestamp, status.tip_hash));
        self.previous_history = history;
        self.previous_pool = pool;
        self.in_flight_or_failed = false;
        Ok(status)
    }

    pub(super) fn status(&mut self, input: &mut impl Write) -> Result<NativeXmrHistoryStatusV23> {
        self.exchange(
            input,
            serde_json::json!({"operation":"status"}),
            Duration::from_secs(15),
        )
    }

    pub(super) fn advance(
        &mut self,
        input: &mut impl Write,
        height: u64,
        timestamp: u64,
        include: &[[u8; 32]],
    ) -> Result<NativeXmrHistoryStatusV23> {
        if include.len() > 16
            || include.contains(&[0; 32])
            || include
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != include.len()
        {
            return Err("local history inclusion list refused".into());
        }
        let before = self.status(input)?;
        if height <= before.tip_height
            || height > 1_000_000
            || timestamp < before.tip_timestamp
            || include
                .iter()
                .any(|hash| !before.pool_tx_hashes.contains(hash))
        {
            return Err("local history advance does not match retained pool and tip".into());
        }
        let status = self.exchange(input, serde_json::json!({"operation":"advance",
            "height":height,"timestamp":timestamp,"include_tx_hashes":include.iter().map(hex::encode).collect::<Vec<_>>()
        }), Duration::from_secs(300))?;
        if status.tip_height != height
            || status.tip_timestamp != timestamp
            || status.transactions.len() != before.transactions.len() + include.len()
            || before.transactions.iter().any(|old| {
                !status
                    .transactions
                    .iter()
                    .any(|tx| tx.tx_hash == old.tx_hash && tx.block_height == old.block_height)
            })
            || before
                .pool_tx_hashes
                .iter()
                .any(|hash| !include.contains(hash) && !status.pool_tx_hashes.contains(hash))
            || include.iter().any(|hash| {
                status.pool_tx_hashes.contains(hash)
                    || !status
                        .transactions
                        .iter()
                        .any(|tx| tx.tx_hash == *hash && tx.block_height == before.tip_height + 1)
            })
        {
            self.in_flight_or_failed = true;
            return Err(
                "local history inclusion ACK does not prove the requested transition".into(),
            );
        }
        Ok(status)
    }
}
