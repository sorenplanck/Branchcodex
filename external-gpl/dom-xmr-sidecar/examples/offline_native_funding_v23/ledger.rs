//! Canonical offline history for the real wallet scanner/decoy selector.
//! This is NOT a mined chain: PoW, historical input existence and consensus
//! admission are deliberately not asserted. Default operation is immutable;
//! explicit route opt-in adds a verified local pool and private-pipe inclusion.
use anyhow::{Result, anyhow, ensure};
use monero_oxide_wallet::{
    block::{Block, BlockHeader},
    ed25519::Commitment,
    primitives::keccak256,
    transaction::{Input, Output, Timelock, Transaction, TransactionPrefix},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[path = "verify.rs"]
mod verify;

use super::epee;

pub(super) const FUNDING_HEIGHT: u64 = 100;
pub(super) const TIP_HEIGHT: u64 = 200;
pub(super) const MAX_SCENARIO_HEIGHT: u64 = 1_000_000;

struct StoredTransaction {
    transaction: Transaction,
    height: u64,
    indexes: Vec<u64>,
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;

pub(super) struct Snapshot {
    genesis: &'static str,
    network_tag: u8,
    blocks: BTreeMap<u64, Block>,
    block_heights: BTreeMap<[u8; 32], u64>,
    transactions: BTreeMap<[u8; 32], StoredTransaction>,
    non_miner_heights: BTreeMap<[u8; 32], u64>,
    outputs: Vec<epee::Output>,
    cumulative: Vec<u64>,
    unlock_heights: Vec<u64>,
    spent: BTreeSet<[u8; 32]>,
    pool: BTreeMap<[u8; 32], Transaction>,
    mutable_scenario: bool,
    tip: u64,
    source_amounts: Option<[u64; 3]>,
}

impl Snapshot {
    pub(super) fn new(funding: Transaction, network_tag: u8) -> Result<Self> {
        Self::new_multiple(vec![funding], network_tag)
    }
    pub(super) fn new_multiple(fundings: Vec<Transaction>, network_tag: u8) -> Result<Self> {
        ensure!(
            !fundings.is_empty() && fundings.len() <= 3,
            "offline funding and inventory count"
        );
        Self::new_history(fundings, network_tag, None)
    }
    pub(super) fn source_roots(amounts: [u64; 3], network_tag: u8) -> Result<Self> {
        ensure!(
            amounts
                .iter()
                .all(|amount| *amount > 1_000_000_000 && *amount <= 1_000_001_000_000_000),
            "source amount bound"
        );
        Self::new_history(vec![], network_tag, Some(amounts))
    }
    fn new_history(
        fundings: Vec<Transaction>,
        network_tag: u8,
        source_amounts: Option<[u64; 3]>,
    ) -> Result<Self> {
        let genesis = match network_tag {
            1 => "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
            2 => "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb",
            _ => return Err(anyhow!("unsupported offline snapshot network")),
        };
        ensure!(
            fundings.iter().all(|funding| matches!(
                funding,
                Transaction::V2 {
                    proofs: Some(_),
                    ..
                }
            )),
            "signed V2 funding required"
        );
        let funding_hashes = fundings.iter().map(Transaction::hash).collect::<Vec<_>>();
        ensure!(
            funding_hashes.iter().collect::<BTreeSet<_>>().len() == funding_hashes.len(),
            "duplicate funding"
        );
        let mut ledger = Self {
            genesis,
            network_tag,
            blocks: BTreeMap::new(),
            block_heights: BTreeMap::new(),
            transactions: BTreeMap::new(),
            non_miner_heights: BTreeMap::new(),
            outputs: Vec::new(),
            cumulative: vec![0],
            unlock_heights: Vec::new(),
            spent: BTreeSet::new(),
            pool: BTreeMap::new(),
            mutable_scenario: false,
            tip: TIP_HEIGHT,
            source_amounts,
        };
        let mut previous = hex::decode(genesis)?
            .try_into()
            .map_err(|_| anyhow!("genesis length"))?;
        // Freeze one coherent local observation history; never refresh timestamps
        // per RPC request. These synthetic headers are not mined mainnet history.
        let snapshot_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let first_time = snapshot_time
            .checked_sub(TIP_HEIGHT * 120)
            .ok_or_else(|| anyhow!("offline snapshot clock before history"))?;
        for height in 1..=TIP_HEIGHT {
            let mut extra = vec![1];
            extra.extend_from_slice(&super::super::point(10_000 + height).compress().to_bytes());
            let miner = Transaction::V2 {
                prefix: TransactionPrefix {
                    additional_timelock: Timelock::Block(usize::try_from(height + 60)?),
                    inputs: vec![Input::Gen(usize::try_from(height)?)],
                    outputs: (0..8)
                        .map(|index| {
                            let source = source_amounts.filter(|_| index == 0 && height <= 3);
                            let amount = source
                                .map_or(1_000_000_000, |amounts| amounts[(height - 1) as usize]);
                            let key = if source.is_some() {
                                super::super::point(41 + (height - 1) * 32)
                            } else {
                                super::super::point(20_000 + height * 8 + index)
                            };
                            Output {
                                amount: Some(amount),
                                key: key.compress(),
                                view_tag: Some(0),
                            }
                        })
                        .collect(),
                    extra,
                },
                proofs: None,
            };
            ledger.insert(miner.clone(), height, true)?;
            let funding_index = height
                .checked_sub(if source_amounts.is_some() {
                    102
                } else {
                    FUNDING_HEIGHT
                })
                .and_then(|index| usize::try_from(index).ok());
            let hashes = if let Some(index) = funding_index.filter(|index| *index < fundings.len())
            {
                ledger.insert(fundings[index].clone(), height, false)?;
                vec![funding_hashes[index]]
            } else {
                vec![]
            };
            let block = Block::new(
                BlockHeader {
                    hardfork_version: 16,
                    hardfork_signal: 16,
                    timestamp: first_time + height * 120,
                    previous,
                    nonce: 0,
                },
                miner,
                hashes,
            )
            .ok_or_else(|| anyhow!("offline block construction"))?;
            let raw = block.serialize();
            let mut reader = raw.as_slice();
            let decoded = Block::read(&mut reader)?;
            ensure!(
                reader.is_empty() && decoded == block,
                "block canonical roundtrip"
            );
            ensure!(
                block.number() == usize::try_from(height)?,
                "block height binding"
            );
            previous = block.hash();
            ledger.block_heights.insert(previous, height);
            ledger.blocks.insert(height, block);
            ledger.cumulative.push(u64::try_from(ledger.outputs.len())?);
        }
        Ok(ledger)
    }

    pub(super) fn source_input(
        &self,
        position: u8,
    ) -> Result<monero_oxide_wallet::OutputWithDecoys> {
        use monero_oxide_wallet::{
            OutputWithDecoys,
            ed25519::{CompressedPoint, Scalar},
            ringct::clsag::Decoys,
        };
        let amounts = self
            .source_amounts
            .ok_or_else(|| anyhow!("source mode required"))?;
        ensure!(position < 3, "source position bound");
        let source_index = usize::from(position) * 8;
        let first = if position == 2 { 8 } else { 0 };
        let ring = self.outputs[first..first + 16]
            .iter()
            .map(|output| {
                Ok([
                    CompressedPoint::from(output.key)
                        .decompress()
                        .ok_or_else(|| anyhow!("source ring key"))?,
                    CompressedPoint::from(output.mask)
                        .decompress()
                        .ok_or_else(|| anyhow!("source ring mask"))?,
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        let mut offsets = vec![1; 16];
        offsets[0] = first as u64;
        let decoys = Decoys::new(offsets, u8::try_from(source_index - first)?, ring)
            .ok_or_else(|| anyhow!("source decoys"))?;
        let mut commitment = Commitment::zero();
        commitment.amount = amounts[usize::from(position)];
        ensure!(
            commitment.commit().compress().to_bytes() == self.outputs[source_index].mask,
            "source commitment mismatch"
        );
        let mut bytes = self.outputs[source_index].key.to_vec();
        Scalar::ZERO.write(&mut bytes)?;
        commitment.write(&mut bytes)?;
        decoys.write(&mut bytes)?;
        let mut reader = bytes.as_slice();
        let input = OutputWithDecoys::read(&mut reader)?;
        ensure!(reader.is_empty(), "source input trailing bytes");
        Ok(input)
    }

    pub(super) fn source_metadata(&self) -> Result<Value> {
        let amounts = self
            .source_amounts
            .ok_or_else(|| anyhow!("source mode required"))?;
        Ok(Value::Array((0..3usize).map(|position| {
            let index = position * 8;
            let output = &self.outputs[index];
            json!({"position":["upstream","downstream","inventory"][position],"tx_hash":hex::encode(output.txid),
                "block_height":output.height,"global_output_index":index,"amount_piconero":amounts[position],
                "public_key":hex::encode(output.key),"commitment":hex::encode(output.mask)})
        }).collect()))
    }

    pub(super) fn validate_candidate(&self, tx: &Transaction) -> Result<()> {
        verify::candidate(tx, self)
    }

    pub(super) fn with_initial_inventory(self, inventory: Transaction) -> Result<Self> {
        verify::candidate(&inventory, &self)?;
        let mut history = Self::new_history(
            vec![inventory],
            self.network_tag,
            Some(
                self.source_amounts
                    .ok_or_else(|| anyhow!("source mode required"))?,
            ),
        )?;
        history.enable_mutable_scenario();
        Ok(history)
    }

    fn insert(&mut self, transaction: Transaction, height: u64, miner: bool) -> Result<()> {
        let hash = transaction.hash();
        ensure!(
            !self.transactions.contains_key(&hash),
            "duplicate ledger transaction"
        );
        let mut indexes = Vec::new();
        for (position, output) in transaction.prefix().outputs.iter().enumerate() {
            let mask = match &transaction {
                Transaction::V2 {
                    proofs: Some(proofs),
                    ..
                } => proofs
                    .base
                    .commitments
                    .get(position)
                    .ok_or_else(|| anyhow!("missing funding commitment"))?
                    .to_bytes(),
                Transaction::V2 { proofs: None, .. } if miner => {
                    // Monero's transparent commitment uses mask ONE, not ZERO.
                    let mut commitment = Commitment::zero();
                    commitment.amount = output
                        .amount
                        .ok_or_else(|| anyhow!("miner amount missing"))?;
                    commitment.commit().compress().to_bytes()
                }
                _ => return Err(anyhow!("unsupported ledger transaction")),
            };
            indexes.push(u64::try_from(self.outputs.len())?);
            self.outputs.push(epee::Output {
                height,
                key: output.key.to_bytes(),
                mask,
                txid: hash,
                unlocked: height + if miner { 60 } else { 10 } <= TIP_HEIGHT,
            });
            self.unlock_heights.push(
                height
                    .checked_add(if miner { 60 } else { 10 })
                    .ok_or_else(|| anyhow!("output unlock overflow"))?,
            );
        }
        for input in &transaction.prefix().inputs {
            if let Input::ToKey { key_image, .. } = input {
                ensure!(
                    self.spent.insert(key_image.to_bytes()),
                    "duplicate spent key image"
                );
            }
        }
        self.transactions.insert(
            hash,
            StoredTransaction {
                transaction,
                height,
                indexes,
            },
        );
        if !miner {
            self.non_miner_heights.insert(hash, height);
        }
        Ok(())
    }

    pub(super) fn is_mainnet(&self) -> bool {
        self.network_tag == 1
    }

    pub(super) fn block(&self, height: u64) -> Result<&Block> {
        self.blocks
            .get(&height)
            .ok_or_else(|| anyhow!("block outside offline history"))
    }

    pub(super) fn block_hash(&self, height: u64) -> Result<String> {
        if height == 0 {
            return Ok(self.genesis.to_owned());
        }
        Ok(hex::encode(self.block(height)?.hash()))
    }

    pub(super) fn height_for_hash(&self, hash: &str) -> Result<u64> {
        let hash: [u8; 32] = hex::decode(hash)?
            .try_into()
            .map_err(|_| anyhow!("block hash length"))?;
        self.block_heights
            .get(&hash)
            .copied()
            .ok_or_else(|| anyhow!("unknown offline block hash"))
    }

    /// Complete immutable-ledger lookup for one exact key image. This is not
    /// inferred from a candidate balance: every retained transaction input is
    /// inspected, including any future spend added to this snapshot.
    pub(super) fn key_image_spent(&self, key_image: [u8; 32]) -> bool {
        self.spent.contains(&key_image)
    }

    pub(super) fn key_image_status(&self, key_image: [u8; 32]) -> u8 {
        if self.key_image_spent(key_image) {
            return 1;
        }
        if self.pool.values().any(|tx| tx.prefix().inputs.iter().any(|input| matches!(input, Input::ToKey { key_image: image, .. } if image.to_bytes() == key_image))) { 2 } else { 0 }
    }

    pub(super) fn tip(&self) -> u64 {
        self.tip
    }

    pub(super) fn enable_mutable_scenario(&mut self) {
        self.mutable_scenario = true;
    }

    pub(super) fn mutable_scenario(&self) -> bool {
        self.mutable_scenario
    }

    pub(super) fn scenario_status(&self) -> Result<Value> {
        Ok(
            json!({"scope":"local-synthetic-history-not-mainnet-confirmation", "tip_height":self.tip,
            "tip_hash":self.block_hash(self.tip)?, "tip_timestamp":self.block(self.tip)?.header.timestamp,
            "pool_tx_hashes":self.pool.keys().map(hex::encode).collect::<Vec<_>>(),
            "transactions": self.non_miner_heights.iter().map(|(hash, height)| json!({"tx_hash":hex::encode(hash), "block_height":height})).collect::<Vec<_>>()}),
        )
    }

    /// Submission only reserves a verified candidate in the local pool. It
    /// never advances history or forwards bytes to another daemon.
    pub(super) fn submit(&mut self, raw: &[u8]) -> Result<[u8; 32]> {
        ensure!(self.mutable_scenario, "read-only snapshot");
        let tx = verify::decode(raw)?;
        let hash = tx.hash();
        if let Some(stored) = self.transactions.get(&hash) {
            ensure!(
                stored.transaction.serialize() == raw,
                "confirmed replay changed bytes"
            );
            return Ok(hash);
        }
        if let Some(stored) = self.pool.get(&hash) {
            ensure!(stored.serialize() == raw, "pool replay changed bytes");
            return Ok(hash);
        }
        ensure!(
            self.pool.len() < 32 && self.pool.len() + self.non_miner_heights.len() < 256,
            "local pool/history bound"
        );
        verify::candidate(&tx, self)?;
        self.pool.insert(hash, tx);
        Ok(hash)
    }

    /// Private-pipe-only transition. Every intervening block, miner output,
    /// output index and cumulative distribution row is actually constructed.
    /// Timestamps are explicitly synthetic, monotonic interpolation supplied
    /// by the supervisor, never a claim of valid PoW or mainnet confirmation.
    pub(super) fn advance(
        &mut self,
        height: u64,
        timestamp: u64,
        hashes: &[[u8; 32]],
    ) -> Result<()> {
        ensure!(
            self.mutable_scenario && height > self.tip && height <= MAX_SCENARIO_HEIGHT,
            "scenario height bound"
        );
        ensure!(hashes.len() <= 16, "scenario inclusion bound");
        let mut distinct = BTreeSet::new();
        for hash in hashes {
            ensure!(
                distinct.insert(*hash) && self.pool.contains_key(hash),
                "unknown or duplicate pool inclusion"
            );
        }
        let start = self.tip;
        let first_timestamp = self.block(start)?.header.timestamp;
        ensure!(timestamp >= first_timestamp, "scenario timestamp rollback");
        ensure!(
            timestamp
                <= std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            "scenario timestamp is in the future"
        );
        let span = height - start;
        let time_span = timestamp - first_timestamp;
        let miner_public_key = super::super::point(10_001).compress().to_bytes();
        // Canonical blocks are not consensus-validated blocks. One deterministic
        // miner output per added height keeps the 100200-refund history bounded.
        for next in start + 1..=height {
            let mut extra = vec![1];
            extra.extend_from_slice(&miner_public_key);
            let miner = Transaction::V2 {
                prefix: TransactionPrefix {
                    additional_timelock: Timelock::Block(usize::try_from(next + 60)?),
                    inputs: vec![Input::Gen(usize::try_from(next)?)],
                    outputs: vec![Output {
                        amount: Some(1_000_000_000),
                        key: super::super::point(2_000_000 + next).compress(),
                        view_tag: Some(0),
                    }],
                    extra,
                },
                proofs: None,
            };
            // Prepare the block before publishing any row for this height.
            let included = if next == start + 1 {
                hashes.to_vec()
            } else {
                vec![]
            };
            let block_time = first_timestamp
                + u64::try_from(
                    u128::from(time_span) * u128::from(next - start) / u128::from(span),
                )?;
            let previous = self.block(next - 1)?.hash();
            let block = Block::new(
                BlockHeader {
                    hardfork_version: 16,
                    hardfork_signal: 16,
                    timestamp: block_time,
                    previous,
                    nonce: 0,
                },
                miner.clone(),
                included.clone(),
            )
            .ok_or_else(|| anyhow!("scenario block construction"))?;
            ensure!(
                block.number() == usize::try_from(next)?,
                "scenario height binding"
            );
            self.insert(miner, next, true)?;
            for hash in included {
                let tx = self
                    .pool
                    .remove(&hash)
                    .ok_or_else(|| anyhow!("pool candidate disappeared"))?;
                self.insert(tx, next, false)?;
            }
            self.block_heights.insert(block.hash(), next);
            self.blocks.insert(next, block);
            self.cumulative.push(u64::try_from(self.outputs.len())?);
            self.tip = next;
        }
        Ok(())
    }

    pub(super) fn transaction_response(&self, hashes: &[Value]) -> Result<Value> {
        ensure!(
            !hashes.is_empty() && hashes.len() <= 100,
            "transaction request bound"
        );
        let mut txs = Vec::new();
        let mut missed = Vec::new();
        for value in hashes {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow!("transaction hash type"))?;
            let hash: [u8; 32] = hex::decode(text)?
                .try_into()
                .map_err(|_| anyhow!("transaction hash length"))?;
            let Some(stored) = self.transactions.get(&hash) else {
                if let Some(tx) = self.pool.get(&hash) {
                    let (pruned, _) = tx.clone().pruned_with_prunable();
                    let prunable_hash = tx
                        .prunable_hash()
                        .ok_or_else(|| anyhow!("pool prunable hash"))?;
                    txs.push(json!({"tx_hash":text,"as_hex":hex::encode(tx.serialize()),"pruned_as_hex":hex::encode(pruned.serialize()),"prunable_hash":hex::encode(prunable_hash),"in_pool":true,"block_height":0}));
                    continue;
                }
                missed.push(text.to_owned());
                continue;
            };
            let (pruned, prunable) = stored.transaction.clone().pruned_with_prunable();
            let prunable_hash = stored
                .transaction
                .prunable_hash()
                .ok_or_else(|| anyhow!("V2 prunable identity missing"))?;
            // Null RingCT (coinbase) has a ZERO prunable hash, not Keccak
            // of empty bytes. Emit the canonical identity even when a client
            // could normalize an incorrect daemon response on our behalf.
            if matches!(
                &stored.transaction,
                Transaction::V2 {
                    proofs: Some(_),
                    ..
                }
            ) {
                ensure!(
                    prunable_hash == keccak256(&prunable),
                    "prunable bytes mismatch"
                );
            }
            ensure!(
                pruned.hash_with_prunable_hash(prunable_hash) == Some(hash),
                "pruned identity mismatch"
            );
            txs.push(json!({"tx_hash":text,"as_hex":hex::encode(stored.transaction.serialize()),
                "pruned_as_hex":hex::encode(pruned.serialize()),"prunable_hash":hex::encode(prunable_hash),
                "in_pool":false,"block_height":stored.height}));
        }
        Ok(json!({"status":"OK","untrusted":false,"txs":txs,"missed_tx":missed}))
    }
}

impl epee::Ledger for Snapshot {
    fn scannable_blocks(&self, start: u64, count: u64) -> Result<Vec<epee::ScannableBlock>> {
        ensure!(
            start > 0 && count > 0 && count <= 200,
            "block request bound"
        );
        let end = start
            .checked_add(count - 1)
            .ok_or_else(|| anyhow!("block range overflow"))?;
        ensure!(end <= self.tip, "block range outside history");
        (start..=end)
            .map(|height| {
                let block = self.block(height)?;
                let mut output_indices =
                    vec![self.output_indexes(block.miner_transaction().hash())?];
                let mut transactions = Vec::new();
                for hash in &block.transactions {
                    let stored = self
                        .transactions
                        .get(hash)
                        .ok_or_else(|| anyhow!("block transaction missing"))?;
                    ensure!(stored.height == height, "transaction height mismatch");
                    let (pruned, prunable) = stored.transaction.clone().pruned_with_prunable();
                    let prunable_hash = keccak256(&prunable);
                    ensure!(
                        pruned.hash_with_prunable_hash(prunable_hash) == Some(*hash),
                        "block pruned hash mismatch"
                    );
                    transactions.push(epee::PrunedTransaction {
                        blob: pruned.serialize(),
                        prunable_hash,
                    });
                    output_indices.push(stored.indexes.clone());
                }
                Ok(epee::ScannableBlock {
                    block: block.serialize(),
                    transactions,
                    output_indices,
                })
            })
            .collect()
    }

    fn output_indexes(&self, txid: [u8; 32]) -> Result<Vec<u64>> {
        Ok(self
            .transactions
            .get(&txid)
            .ok_or_else(|| anyhow!("unknown output transaction"))?
            .indexes
            .clone())
    }
    fn cumulative_distribution(&self, from: u64, to: u64) -> Result<Vec<u64>> {
        ensure!(from <= to && to <= self.tip, "distribution outside history");
        Ok(self.cumulative[usize::try_from(from)?..=usize::try_from(to)?].to_vec())
    }
    fn outputs(&self, indexes: &[u64]) -> Result<Vec<epee::Output>> {
        indexes
            .iter()
            .map(|index| {
                let output = self
                    .outputs
                    .get(usize::try_from(*index)?)
                    .ok_or_else(|| anyhow!("output index outside history"))?;
                Ok(epee::Output {
                    height: output.height,
                    key: output.key,
                    mask: output.mask,
                    txid: output.txid,
                    unlocked: self.unlock_heights[usize::try_from(*index)?] <= self.tip,
                })
            })
            .collect()
    }
}
