//! Consensus-bound DOM/XMR arbitration output.
//!
//! This module defines the immutable output extension and exact spend intent.
//! Contextual UTXO validation is wired separately because a transaction alone
//! does not contain the proof envelope of the output it spends.

use dom_core::{
    Amount, BlockHeight, DomError, KERNEL_FEAT_SWAP_CLAIM, KERNEL_FEAT_SWAP_PUNISH,
    KERNEL_FEAT_SWAP_REFUND, SWAP_ARBITER_CONTRACT_SIZE, TAG_SWAP_ARBITER_INTENT,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_serialization::DomSerialize;

use crate::Transaction;

const MAGIC: &[u8; 4] = b"DXA1";

/// Immutable paths committed into a DOM output's range-proof transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapArbiterContract {
    claim_until: u64,
    refund_until: u64,
    claim_intent: [u8; 32],
    refund_intent: [u8; 32],
    punish_intent: [u8; 32],
}

/// Spend branch selected by the single kernel of an arbiter spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapArbiterPath {
    /// Recipient claim; valid through the first terminal height.
    Claim,
    /// Owner refund; valid in the strictly following bounded phase.
    Refund,
    /// Recipient punishment; valid only after the refund phase.
    Punish,
}

impl SwapArbiterContract {
    /// Construct a canonical contract. Adjacent phases never overlap.
    pub fn new(
        claim_until: u64,
        refund_until: u64,
        claim_intent: [u8; 32],
        refund_intent: [u8; 32],
        punish_intent: [u8; 32],
    ) -> Result<Self, DomError> {
        if claim_until == 0
            || refund_until <= claim_until
            || refund_until == u64::MAX
            || [claim_intent, refund_intent, punish_intent].contains(&[0; 32])
            || claim_intent == refund_intent
            || claim_intent == punish_intent
            || refund_intent == punish_intent
        {
            return Err(DomError::Invalid(
                "noncanonical DOM/XMR swap arbiter contract".into(),
            ));
        }
        Ok(Self {
            claim_until,
            refund_until,
            claim_intent,
            refund_intent,
            punish_intent,
        })
    }

    /// Parse exactly one canonical V1 contract.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != SWAP_ARBITER_CONTRACT_SIZE || &bytes[..4] != MAGIC {
            return Err(DomError::Malformed(
                "invalid DOM/XMR swap arbiter envelope".into(),
            ));
        }
        let claim_until = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let refund_until = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let claim_intent = bytes[20..52].try_into().unwrap();
        let refund_intent = bytes[52..84].try_into().unwrap();
        let punish_intent = bytes[84..116].try_into().unwrap();
        Self::new(
            claim_until,
            refund_until,
            claim_intent,
            refund_intent,
            punish_intent,
        )
    }

    /// Canonical fixed-width bytes bound into the funding range proof.
    pub fn to_bytes(&self) -> [u8; SWAP_ARBITER_CONTRACT_SIZE] {
        let mut bytes = [0u8; SWAP_ARBITER_CONTRACT_SIZE];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4..12].copy_from_slice(&self.claim_until.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.refund_until.to_le_bytes());
        bytes[20..52].copy_from_slice(&self.claim_intent);
        bytes[52..84].copy_from_slice(&self.refund_intent);
        bytes[84..116].copy_from_slice(&self.punish_intent);
        bytes
    }

    /// Last height at which the claim path is valid.
    pub const fn claim_until(&self) -> u64 {
        self.claim_until
    }

    /// Last height at which the refund path is valid.
    pub const fn refund_until(&self) -> u64 {
        self.refund_until
    }

    fn expected(&self, path: SwapArbiterPath) -> ([u8; 32], u64) {
        match path {
            SwapArbiterPath::Claim => (self.claim_intent, self.claim_until),
            SwapArbiterPath::Refund => (self.refund_intent, self.claim_until + 1),
            SwapArbiterPath::Punish => (self.punish_intent, self.refund_until + 1),
        }
    }

    /// Validate a complete spend against its committed path and block height.
    pub fn validate_spend(&self, tx: &Transaction, height: BlockHeight) -> Result<(), DomError> {
        if tx.inputs.len() != 1 || tx.kernels.len() != 1 {
            return Err(DomError::Invalid(
                "swap arbiter spend requires exactly one input and one kernel".into(),
            ));
        }
        let kernel = &tx.kernels[0];
        let path = match kernel.features {
            KERNEL_FEAT_SWAP_CLAIM => SwapArbiterPath::Claim,
            KERNEL_FEAT_SWAP_REFUND => SwapArbiterPath::Refund,
            KERNEL_FEAT_SWAP_PUNISH => SwapArbiterPath::Punish,
            _ => {
                return Err(DomError::Invalid(
                    "swap arbiter output requires a swap path kernel".into(),
                ))
            }
        };
        let (expected_intent, expected_lock) = self.expected(path);
        if kernel.lock_height != expected_lock {
            return Err(DomError::Invalid(
                "swap path kernel carries the wrong phase boundary".into(),
            ));
        }
        match path {
            SwapArbiterPath::Claim if height.0 > self.claim_until => {
                return Err(DomError::Invalid("swap claim phase expired".into()))
            }
            SwapArbiterPath::Refund if height.0 <= self.claim_until => {
                return Err(DomError::TemporarilyInvalid(
                    "swap refund phase has not started".into(),
                ))
            }
            SwapArbiterPath::Refund if height.0 > self.refund_until => {
                return Err(DomError::Invalid("swap refund phase expired".into()))
            }
            SwapArbiterPath::Punish if height.0 <= self.refund_until => {
                return Err(DomError::TemporarilyInvalid(
                    "swap punish phase has not started".into(),
                ))
            }
            _ => {}
        }
        if swap_arbiter_intent(tx)? != expected_intent {
            return Err(DomError::Invalid(
                "swap spend differs from the funding commitment".into(),
            ));
        }
        Ok(())
    }
}

/// Hash every consensus field of a spend except its final kernel signature.
///
/// The omitted signature may be completed from an adaptor after funding. The
/// kernel excess, path, fee, phase boundary, outputs and offset remain bound.
pub fn swap_arbiter_intent(tx: &Transaction) -> Result<[u8; 32], DomError> {
    if tx.inputs.len() != 1 || tx.kernels.len() != 1 {
        return Err(DomError::Invalid(
            "swap intent requires exactly one input and one kernel".into(),
        ));
    }
    let kernel = &tx.kernels[0];
    if !matches!(
        kernel.features,
        KERNEL_FEAT_SWAP_CLAIM | KERNEL_FEAT_SWAP_REFUND | KERNEL_FEAT_SWAP_PUNISH
    ) {
        return Err(DomError::Invalid(
            "ordinary kernel is not a swap intent".into(),
        ));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tx.inputs[0].commitment.as_bytes());
    bytes.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for output in &tx.outputs {
        let encoded = output.to_bytes()?;
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    bytes.push(kernel.features);
    let fee: Amount = kernel.fee;
    bytes.extend_from_slice(&fee.noms().to_le_bytes());
    bytes.extend_from_slice(&kernel.lock_height.to_le_bytes());
    bytes.extend_from_slice(kernel.excess.as_bytes());
    bytes.extend_from_slice(&tx.offset);
    Ok(*blake2b_256_tagged(TAG_SWAP_ARBITER_INTENT, &bytes).as_bytes())
}

/// Enforce arbiter outputs against the canonical proof envelopes of all inputs.
///
/// Callers obtain these envelopes from their canonical UTXO snapshot. Passing
/// transaction-supplied data here would turn the covenant into a peer claim.
pub fn validate_swap_arbiter_input_proofs(
    tx: &Transaction,
    height: BlockHeight,
    input_proofs: &[Vec<u8>],
) -> Result<(), DomError> {
    if input_proofs.len() != tx.inputs.len() {
        return Err(DomError::Internal(
            "swap arbiter validation received an incomplete UTXO snapshot".into(),
        ));
    }
    let mut contract = None;
    for proof in input_proofs {
        if proof.len() == dom_crypto::RANGE_PROOF_SIZE + SWAP_ARBITER_CONTRACT_SIZE {
            let parsed = SwapArbiterContract::from_bytes(&proof[dom_crypto::RANGE_PROOF_SIZE..])?;
            if contract.replace(parsed).is_some() {
                return Err(DomError::Invalid(
                    "one transaction cannot spend multiple swap arbiter outputs".into(),
                ));
            }
        }
    }
    let special_kernels = tx
        .kernels
        .iter()
        .filter(|kernel| {
            matches!(
                kernel.features,
                KERNEL_FEAT_SWAP_CLAIM | KERNEL_FEAT_SWAP_REFUND | KERNEL_FEAT_SWAP_PUNISH
            )
        })
        .count();
    match (contract, special_kernels) {
        (None, 0) => Ok(()),
        (None, _) => Err(DomError::Invalid(
            "swap path kernel does not spend an arbiter output".into(),
        )),
        (Some(_), 0) => Err(DomError::Invalid(
            "arbiter output cannot be spent by an ordinary kernel".into(),
        )),
        (Some(contract), 1) => contract.validate_spend(tx, height),
        (Some(_), _) => Err(DomError::Invalid(
            "arbiter spend has multiple swap path kernels".into(),
        )),
    }
}
