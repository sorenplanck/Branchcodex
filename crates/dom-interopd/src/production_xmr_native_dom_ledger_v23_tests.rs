//! Transaction admission for the controlled RPC scenario, not block/PoW
//! admission and never a replacement for a mainnet node.
use dom_consensus::{Transaction, ValidationContext};
use dom_core::{BlockHeight, Timestamp};
use dom_serialization::{DomDeserialize, DomSerialize};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Constructor is the sole native coinbase validation boundary for this fixture.
pub(crate) struct ValidatedDomCoinbaseV23 {
    chain_id: [u8; 32],
    height: u64,
    fees: u64,
    coinbase: dom_consensus::CoinbaseTransaction,
}
impl ValidatedDomCoinbaseV23 {
    pub(crate) fn new(
        chain_id: [u8; 32],
        height: u64,
        fees: u64,
        coinbase: dom_consensus::CoinbaseTransaction,
    ) -> Result<Self> {
        coinbase.validate(BlockHeight(height), fees, &chain_id)?;
        Ok(Self {
            chain_id,
            height,
            fees,
            coinbase,
        })
    }
    pub(crate) fn coinbase(&self) -> &dom_consensus::CoinbaseTransaction {
        &self.coinbase
    }
}

pub(crate) struct NativeDomLedgerV23 {
    chain_id: [u8; 32],
    tip: u64,
    revision: [u8; 32],
    seen_outputs: BTreeSet<Vec<u8>>,
    outputs: BTreeMap<Vec<u8>, dom_store::utxo::UtxoEntry>,
    kernels: BTreeSet<Vec<u8>>,
    transactions: BTreeSet<[u8; 32]>,
}

/// A validated candidate cannot mutate the ledger until its containing block
/// projection is complete. The revision guard rejects stale parallel candidates.
pub(crate) struct PreparedDomTransactionV23 {
    previous_tip: u64,
    previous_revision: [u8; 32],
    transaction: Transaction,
    hash: [u8; 32],
}

impl PreparedDomTransactionV23 {
    pub(crate) fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

impl NativeDomLedgerV23 {
    pub(crate) fn new(chain_id: [u8; 32]) -> Result<Self> {
        if chain_id == [0; 32] {
            return Err("zero ledger chain identity".into());
        }
        Ok(Self {
            chain_id,
            tip: 0,
            revision: chain_id,
            seen_outputs: BTreeSet::new(),
            outputs: BTreeMap::new(),
            kernels: BTreeSet::new(),
            transactions: BTreeSet::new(),
        })
    }

    /// Seed only actual sequential coinbases whose proofs, reward and signature
    /// pass the existing native validator. Genesis is not a spendable seed.
    pub(crate) fn seed_coinbase(
        &mut self,
        height: u64,
        validated: &ValidatedDomCoinbaseV23,
    ) -> Result<()> {
        if validated.chain_id != self.chain_id || validated.height != height || validated.fees != 0
        {
            return Err("baseline coinbase capability scope".into());
        }
        let coinbase = validated.coinbase();
        if height != self.tip.checked_add(1).ok_or("ledger height overflow")? {
            return Err("baseline coinbase height is not contiguous".into());
        }
        let commitment = coinbase.output.commitment.as_bytes().to_vec();
        let kernel = coinbase.kernel.excess.as_bytes().to_vec();
        if self.seen_outputs.contains(&commitment) || self.kernels.contains(&kernel) {
            return Err("baseline coinbase commitment or kernel reused".into());
        }
        let entry = dom_store::utxo::UtxoEntry {
            block_height: height,
            is_coinbase: true,
            proof: coinbase.output.range_proof_bytes()?.to_vec(),
        };
        self.revision = *dom_crypto::blake2b_256(
            &[
                self.revision.as_slice(),
                commitment.as_slice(),
                kernel.as_slice(),
            ]
            .concat(),
        )
        .as_bytes();
        self.seen_outputs.insert(commitment.clone());
        self.outputs.insert(commitment, entry);
        self.kernels.insert(kernel);
        self.tip = height;
        Ok(())
    }

    pub(crate) fn contains_transaction(&self, hash: &[u8; 32]) -> bool {
        self.transactions.contains(hash)
    }

    pub(crate) fn prepare(&self, bytes: &[u8], now: u64) -> Result<PreparedDomTransactionV23> {
        let transaction = Transaction::from_bytes(bytes)?;
        if transaction.to_bytes()? != bytes {
            return Err("noncanonical transaction".into());
        }
        let hash = *dom_crypto::blake2b_256(bytes).as_bytes();
        if self.transactions.contains(&hash) {
            return Err("transaction already admitted".into());
        }
        let height = self.tip.checked_add(1).ok_or("ledger height overflow")?;
        dom_consensus::validate_transaction(
            &transaction,
            &ValidationContext {
                current_height: BlockHeight(height),
                chain_id: self.chain_id,
                now: Timestamp(now),
            },
        )?;
        dom_core::fee_policy::validate_minimum_fee(
            transaction.total_fee()?,
            transaction.fee_shape()?,
        )?;
        for input in &transaction.inputs {
            let entry = self
                .outputs
                .get(input.commitment.as_bytes().as_slice())
                .ok_or("transaction input absent or already spent")?;
            dom_store::utxo::UtxoSet::validate_input(entry, BlockHeight(height))?;
        }
        for output in &transaction.outputs {
            if self
                .seen_outputs
                .contains(output.commitment.as_bytes().as_slice())
            {
                return Err("transaction output already exists".into());
            }
        }
        for kernel in &transaction.kernels {
            if self.kernels.contains(kernel.excess.as_bytes().as_slice()) {
                return Err("transaction kernel already exists".into());
            }
        }
        Ok(PreparedDomTransactionV23 {
            previous_tip: self.tip,
            previous_revision: self.revision,
            transaction,
            hash,
        })
    }

    /// Call while holding the same mutex as the RPC block vector. No fallible
    /// projection work may follow this commit before publishing that vector.
    pub(crate) fn commit(
        &mut self,
        prepared: PreparedDomTransactionV23,
        validated: &ValidatedDomCoinbaseV23,
    ) -> Result<()> {
        let coinbase = validated.coinbase();
        if prepared.previous_tip != self.tip || prepared.previous_revision != self.revision {
            return Err("stale prepared transaction".into());
        }
        let height = self.tip.checked_add(1).ok_or("ledger height overflow")?;
        if validated.chain_id != self.chain_id
            || validated.height != height
            || validated.fees != prepared.transaction.total_fee()?
        {
            return Err("containing block coinbase capability scope".into());
        }
        if dom_consensus::block_weight(coinbase, std::slice::from_ref(&prepared.transaction))?
            > dom_core::MAX_BLOCK_WEIGHT
        {
            return Err("containing block exceeds native weight bound".into());
        }
        let coinbase_key = coinbase.output.commitment.as_bytes().to_vec();
        let coinbase_kernel = coinbase.kernel.excess.as_bytes().to_vec();
        if self.seen_outputs.contains(&coinbase_key)
            || self.kernels.contains(&coinbase_kernel)
            || prepared
                .transaction
                .outputs
                .iter()
                .any(|o| o.commitment == coinbase.output.commitment)
            || prepared
                .transaction
                .kernels
                .iter()
                .any(|k| k.excess == coinbase.kernel.excess)
        {
            return Err("containing block coinbase aliases transaction or history".into());
        }
        let coinbase_entry = dom_store::utxo::UtxoEntry {
            block_height: height,
            is_coinbase: true,
            proof: coinbase.output.range_proof_bytes()?.to_vec(),
        };
        let outputs = prepared
            .transaction
            .outputs
            .iter()
            .map(|output| {
                Ok((
                    output.commitment.as_bytes().to_vec(),
                    dom_store::utxo::UtxoEntry {
                        block_height: height,
                        is_coinbase: false,
                        proof: output.range_proof_bytes()?.to_vec(),
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        for input in &prepared.transaction.inputs {
            self.outputs.remove(input.commitment.as_bytes().as_slice());
        }
        self.seen_outputs
            .extend(outputs.iter().map(|(key, _)| key.clone()));
        self.seen_outputs.insert(coinbase_key.clone());
        self.outputs.extend(outputs);
        self.outputs.insert(coinbase_key, coinbase_entry);
        self.kernels.insert(coinbase_kernel);
        self.revision = *dom_crypto::blake2b_256(
            &[self.revision.as_slice(), prepared.hash.as_slice()].concat(),
        )
        .as_bytes();
        self.kernels.extend(
            prepared
                .transaction
                .kernels
                .iter()
                .map(|kernel| kernel.excess.as_bytes().to_vec()),
        );
        self.transactions.insert(prepared.hash);
        self.tip = height;
        Ok(())
    }
}
