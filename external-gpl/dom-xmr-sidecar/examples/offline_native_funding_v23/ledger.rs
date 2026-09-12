//! Immutable, canonical offline history for the real wallet scanner/decoy selector.
//! This is NOT a mined chain: PoW, historical input existence and consensus
//! admission are deliberately not asserted. Nothing here submits transactions.
use anyhow::{Result, anyhow, ensure};
use monero_oxide_wallet::{
    block::{Block, BlockHeader},
    ed25519::Commitment,
    primitives::keccak256,
    transaction::{Input, Output, Timelock, Transaction, TransactionPrefix},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::epee;

pub(super) const FUNDING_HEIGHT: u64 = 100;
pub(super) const TIP_HEIGHT: u64 = 200;

struct StoredTransaction {
    transaction: Transaction,
    height: u64,
    indexes: Vec<u64>,
}

pub(super) struct Snapshot {
    genesis: &'static str,
    network_tag: u8,
    blocks: BTreeMap<u64, Block>,
    transactions: BTreeMap<[u8; 32], StoredTransaction>,
    outputs: Vec<epee::Output>,
    cumulative: Vec<u64>,
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
        let genesis = match network_tag {
            1 => "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
            3 => "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb",
            _ => return Err(anyhow!("unsupported offline snapshot network")),
        };
        ensure!(
            matches!(
                fundings.first().ok_or_else(|| anyhow!("missing funding"))?,
                Transaction::V2 {
                    proofs: Some(_),
                    ..
                }
            ),
            "signed V2 funding required"
        );
        let funding_hashes = fundings.iter().map(Transaction::hash).collect::<Vec<_>>();
        ensure!(
            funding_hashes.len() == 1 || funding_hashes[0] != funding_hashes[1],
            "duplicate funding"
        );
        let mut ledger = Self {
            genesis,
            network_tag,
            blocks: BTreeMap::new(),
            transactions: BTreeMap::new(),
            outputs: Vec::new(),
            cumulative: vec![0],
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
                        .map(|index| Output {
                            amount: Some(1_000_000_000),
                            key: super::super::point(20_000 + height * 8 + index).compress(),
                            view_tag: Some(0),
                        })
                        .collect(),
                    extra,
                },
                proofs: None,
            };
            ledger.insert(miner.clone(), height, true)?;
            let funding_index = height
                .checked_sub(FUNDING_HEIGHT)
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
            ledger.blocks.insert(height, block);
            ledger.cumulative.push(u64::try_from(ledger.outputs.len())?);
        }
        Ok(ledger)
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
        }
        self.transactions.insert(
            hash,
            StoredTransaction {
                transaction,
                height,
                indexes,
            },
        );
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
        for (&height, block) in &self.blocks {
            if hex::encode(block.hash()) == hash {
                return Ok(height);
            }
        }
        Err(anyhow!("unknown offline block hash"))
    }

    /// Complete immutable-ledger lookup for one exact key image. This is not
    /// inferred from a candidate balance: every retained transaction input is
    /// inspected, including any future spend added to this snapshot.
    pub(super) fn key_image_spent(&self, key_image: [u8; 32]) -> bool {
        self.transactions.values().any(|stored| {
            stored.transaction.prefix().inputs.iter().any(|input| {
                matches!(input, Input::ToKey { key_image: value, .. }
                    if value.to_bytes() == key_image)
            })
        })
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
            start > 0 && count > 0 && count <= TIP_HEIGHT,
            "block request bound"
        );
        let end = start
            .checked_add(count - 1)
            .ok_or_else(|| anyhow!("block range overflow"))?;
        ensure!(end <= TIP_HEIGHT, "block range outside history");
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
        ensure!(
            from <= to && to <= TIP_HEIGHT,
            "distribution outside history"
        );
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
                    unlocked: output.unlocked,
                })
            })
            .collect()
    }
}
