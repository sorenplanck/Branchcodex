//! Independent MIT Monero parser/hash check for sidecar-produced raw transactions.

#![forbid(unsafe_code)]

mod funding_v12;
mod input_spend_v23;
mod payout_v23;
pub use input_spend_v23::{
    verify_funding_input_spend_v23, FundingInputSpendErrorV23, VerifiedFundingInputSpendV23,
};
pub use payout_v23::{
    verify_sweep_payout_v23, RingMemberEvidenceV23, SweepPayoutErrorV23, VerifiedSweepPayoutV23,
};
pub use xmr_key_image_proof::TxKeyDerivationProofV23;
pub use xmr_key_image_proof::{
    destination_digest_v23, InputSpendActionV23, InputSpendContextV23, InputSpendProofV23,
};
mod sweep_fee_v23;
pub use funding_v12::{
    derive_owned_funding_key_image_v23, standard_funding_address_v12, verify_exact_raw_funding_v12,
    FundingVerificationErrorV12, VerifiedOwnedFundingKeyImageV23, VerifiedRawFundingV12,
};
pub use sweep_fee_v23::{
    verify_exact_raw_sweep_bounded_v23, SweepFeeErrorV23, VerifiedBoundedRawSweepV23,
};

use blake2::{digest::consts::U32, Blake2b, Digest};
use monero_oxide::transaction::{Input, NotPruned, Transaction};

type Blake2b256 = Blake2b<U32>;
/// Hard raw transaction bound.
pub const MAX_VERIFIED_RAW_TX_BYTES: usize = 1024 * 1024;

/// Raw transaction validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RawTxError {
    /// Empty/oversized bytes.
    #[error("raw transaction exceeds bounds")]
    BoundsExceeded,
    /// Monero parser rejected bytes.
    #[error("invalid raw Monero transaction")]
    Parse,
    /// Bytes are not the canonical serialization of the parsed transaction.
    #[error("non-canonical raw Monero transaction")]
    NonCanonical,
    /// Parsed consensus hash differs from the sidecar response.
    #[error("Monero transaction hash mismatch")]
    HashMismatch,
    /// A sweep needs exactly one nonzero key image per distinct input.
    #[error("invalid Monero sweep inputs")]
    InvalidSweepInputs,
}

/// Independently verified public result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRawTransaction {
    /// Consensus transaction hash.
    pub tx_hash: [u8; 32],
    /// Domain-separated exact-byte fingerprint.
    pub raw_fingerprint: [u8; 32],
}

/// Parse, require full consumption/canonical roundtrip, and verify consensus hash.
pub fn verify_exact_raw_transaction(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
) -> Result<VerifiedRawTransaction, RawTxError> {
    let transaction = parse_exact(raw, expected_tx_hash)?;
    Ok(fingerprint(raw, transaction.hash()))
}

fn parse_exact(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
) -> Result<Transaction<NotPruned>, RawTxError> {
    if raw.is_empty() || raw.len() > MAX_VERIFIED_RAW_TX_BYTES || expected_tx_hash == [0; 32] {
        return Err(RawTxError::BoundsExceeded);
    }
    let mut cursor = raw;
    let transaction: Transaction<NotPruned> =
        Transaction::read(&mut cursor).map_err(|_| RawTxError::Parse)?;
    if !cursor.is_empty() {
        return Err(RawTxError::NonCanonical);
    }
    let canonical = transaction.serialize();
    if canonical.as_slice() != raw {
        return Err(RawTxError::NonCanonical);
    }
    let tx_hash = transaction.hash();
    if tx_hash != expected_tx_hash {
        return Err(RawTxError::HashMismatch);
    }
    Ok(transaction)
}

fn fingerprint(raw: &[u8], tx_hash: [u8; 32]) -> VerifiedRawTransaction {
    let raw_fingerprint = Blake2b256::new()
        .chain_update(b"DOM-INTEROP/XMR-RAW-TX/V1\0")
        .chain_update(raw)
        .finalize()
        .into();
    VerifiedRawTransaction {
        tx_hash,
        raw_fingerprint,
    }
}

/// Independently derived sweep inputs. A response-provided key image is never
/// an authority for absence or reconciliation; each image comes from raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRawSweepV10 {
    /// Consensus hash and exact-byte digest.
    pub transaction: VerifiedRawTransaction,
    /// All input key images in canonical transaction order.
    pub key_images: Vec<[u8; 32]>,
}

/// Parse one complete canonical transaction, verify its exact hash and derive
/// every key image. Reject miner transactions, zero images and duplicated images.
/// This proves byte identity and input structure; it does not verify CLSAG or
/// prove the destination/amount, which remain the trusted signer's obligation.
pub fn verify_exact_raw_sweep_v10(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
) -> Result<VerifiedRawSweepV10, RawTxError> {
    let transaction = parse_exact(raw, expected_tx_hash)?;
    let mut key_images = Vec::with_capacity(transaction.prefix().inputs.len());
    for input in &transaction.prefix().inputs {
        let Input::ToKey { key_image, .. } = input else {
            return Err(RawTxError::InvalidSweepInputs);
        };
        let image = key_image.to_bytes();
        if image == [0; 32] || key_images.contains(&image) {
            return Err(RawTxError::InvalidSweepInputs);
        }
        key_images.push(image);
    }
    if key_images.is_empty() {
        return Err(RawTxError::InvalidSweepInputs);
    }
    Ok(VerifiedRawSweepV10 {
        transaction: fingerprint(raw, transaction.hash()),
        key_images,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic V1 serialization with public zero ring scalars: this is a
    // parser fixture, NOT a signed, spendable or consensus-valid transaction.
    fn fixture(images: &[[u8; 32]]) -> Vec<u8> {
        let mut raw = vec![1, 0, u8::try_from(images.len()).expect("small fixture")];
        for image in images {
            raw.extend_from_slice(&[2, 1, 1, 1]); // ToKey, amount, ring length, offset
            raw.extend_from_slice(image);
        }
        raw.extend_from_slice(&[1, 1, 2]); // one untagged output, amount 1
        raw.push(0x58);
        raw.extend_from_slice(&[0x66; 31]); // canonical G
        raw.push(0); // no extra
        raw.resize(raw.len() + 64 * images.len(), 0);
        raw
    }

    fn hash(raw: &[u8]) -> [u8; 32] {
        let mut cursor = raw;
        let tx = Transaction::<NotPruned>::read(&mut cursor).expect("canonical parser fixture");
        assert!(cursor.is_empty());
        tx.hash()
    }

    #[test]
    fn v10_images_are_derived_from_raw_and_hash_mismatch_is_hard_rejection() {
        let mut image = [0x66; 32];
        image[0] = 0x58;
        let encoded = fixture(&[image]);
        let tx_hash = hash(&encoded);
        let result = verify_exact_raw_sweep_v10(&encoded, tx_hash).expect("canonical raw inputs");
        assert_eq!(result.key_images, vec![image]);
        let mut wrong = tx_hash;
        wrong[0] ^= 1;
        assert_eq!(
            verify_exact_raw_sweep_v10(&encoded, wrong),
            Err(RawTxError::HashMismatch)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(verify_exact_raw_sweep_v10(&trailing, tx_hash).is_err());
    }

    #[test]
    fn v23_bounded_sweep_refuses_legacy_raw_without_changing_v10_parser() {
        let mut image = [0x66; 32];
        image[0] = 0x58;
        let raw = fixture(&[image]);
        let tx_hash = hash(&raw);
        assert!(verify_exact_raw_sweep_v10(&raw, tx_hash).is_ok());
        assert_eq!(
            verify_exact_raw_sweep_bounded_v23(&raw, tx_hash, 100, 10),
            Err(SweepFeeErrorV23::Profile)
        );
    }

    #[test]
    fn v10_duplicate_images_are_rejected_even_when_raw_hash_matches() {
        let mut image = [0x66; 32];
        image[0] = 0x58;
        let raw = fixture(&[image, image]);
        assert_eq!(
            verify_exact_raw_sweep_v10(&raw, hash(&raw)),
            Err(RawTxError::InvalidSweepInputs)
        );
    }

    #[test]
    fn empty_oversized_and_unbound_inputs_are_refused_before_parsing() {
        assert_eq!(
            verify_exact_raw_transaction(&[], [1; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
        let oversized = vec![0_u8; MAX_VERIFIED_RAW_TX_BYTES + 1];
        assert_eq!(
            verify_exact_raw_transaction(&oversized, [1; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
        // A zero expected hash is not a hash: accepting it would let a caller
        // opt out of the comparison entirely.
        assert_eq!(
            verify_exact_raw_transaction(&[1, 2, 3], [0; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
    }

    #[test]
    fn bytes_that_are_not_a_monero_transaction_are_refused() {
        assert_eq!(
            verify_exact_raw_transaction(b"not a monero transaction", [1; 32]).unwrap_err(),
            RawTxError::Parse
        );
    }
}
