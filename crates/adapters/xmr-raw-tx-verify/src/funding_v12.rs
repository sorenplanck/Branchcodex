//! Offline recipient/amount verification for privately prepared modern XMR funding.
//!
//! The equations are the Monero compact RingCT ECDH equations, checked independently
//! of wallet RPC and the GPL sidecar. This is not an inclusion or CLSAG verifier.
//! Reference: pinned monero-oxide c8be5d3d, wallet/src/{lib,scan}.rs.

use crate::{fingerprint, parse_exact, RawTxError, VerifiedRawTransaction};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use monero_oxide::{
    ed25519::{Commitment, Scalar as MoneroScalar},
    primitives::keccak256,
    ringct::{EncryptedAmount, RctBase, RctType},
    transaction::{Input, Timelock, Transaction, TransactionPrefix},
};
use zeroize::Zeroizing;

/// A complete response which contradicts the requested economics is a hard error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FundingVerificationErrorV12 {
    /// Exact raw encoding/hash verification failed.
    #[error("invalid exact funding transaction")]
    Raw(#[from] RawTxError),
    /// Invalid canonical private view scalar or public spend point.
    #[error("invalid funding recipient key")]
    Recipient,
    /// Transaction is outside the narrowly supported modern funding profile.
    #[error("unsupported funding transaction profile")]
    Profile,
    /// Transaction extra is ambiguous, malformed or unsupported.
    #[error("invalid funding transaction extra")]
    Extra,
    /// No unique output pays the exact bound recipient and amount.
    #[error("funding destination or amount mismatch")]
    Economics,
    /// The decrypted amount does not open the on-wire commitment.
    #[error("funding amount commitment mismatch")]
    Commitment,
}

/// Offline result. Private fields prevent treating an RPC assertion as verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedRawFundingV12 {
    transaction: VerifiedRawTransaction,
    output_index: u32,
    amount_piconero: u64,
    fee_piconero: u64,
}
impl VerifiedRawFundingV12 {
    /// Consensus hash and exact-byte fingerprint.
    pub fn transaction(&self) -> VerifiedRawTransaction {
        self.transaction
    }
    /// Unique output at the shared funding address.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
    /// Exact independently decrypted amount.
    pub fn amount_piconero(&self) -> u64 {
        self.amount_piconero
    }
    /// Fee encoded by the transaction, not the RPC's separate fee field.
    pub fn fee_piconero(&self) -> u64 {
        self.fee_piconero
    }
}

/// Verify an unbroadcast transaction using only the shared PUBLIC spend key and
/// private VIEW key. No private spend share, T+U or remote scanning is involved.
/// Requires one exact output, no additional timelock, bounded fee and modern
/// CLSAG/Bulletproof+ RingCT. It does not establish chain validity or finality.
pub fn verify_exact_raw_funding_v12(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
    combined_spend_public: [u8; 32],
    view_scalar: &[u8; 32],
    expected_amount_piconero: u64,
    max_fee_piconero: u64,
) -> Result<VerifiedRawFundingV12, FundingVerificationErrorV12> {
    let transaction = parse_exact(raw, expected_tx_hash)?;
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &transaction
    else {
        return Err(FundingVerificationErrorV12::Profile);
    };
    if proofs.rct_type() != RctType::ClsagBulletproofPlus {
        return Err(FundingVerificationErrorV12::Profile);
    }
    let output_index = verify_recipient(
        prefix,
        &proofs.base,
        combined_spend_public,
        view_scalar,
        expected_amount_piconero,
        max_fee_piconero,
    )?;
    Ok(VerifiedRawFundingV12 {
        transaction: fingerprint(raw, expected_tx_hash),
        output_index,
        amount_piconero: expected_amount_piconero,
        fee_piconero: proofs.base.fee,
    })
}

/// Public identifier for one exact owned funding output. Derivation requires
/// the private wallet keys, but the result contains only the raw-verified
/// output position/key and its Monero key image. This is not inclusion,
/// unspent, finality, availability or an economic authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedOwnedFundingKeyImageV23 {
    funding: VerifiedRawFundingV12,
    output_key: [u8; 32],
    key_image: [u8; 32],
}

impl VerifiedOwnedFundingKeyImageV23 {
    /// Exact raw funding and recipient result.
    pub fn funding(&self) -> VerifiedRawFundingV12 {
        self.funding
    }
    /// One-time key read from the uniquely matched raw output.
    pub fn output_key(&self) -> [u8; 32] {
        self.output_key
    }
    /// Key image derived from the owned one-time output secret.
    pub fn key_image(&self) -> [u8; 32] {
        self.key_image
    }
}

/// Derive the public key image for a uniquely owned funding output without
/// constructing or signing a sweep. The exact raw transaction first passes
/// all recipient/amount/fee checks; both private scalars are canonical and
/// the spend scalar is checked against the supplied public wallet key.
pub fn derive_owned_funding_key_image_v23(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
    spend_scalar: &[u8; 32],
    view_scalar: &[u8; 32],
    expected_amount_piconero: u64,
    max_fee_piconero: u64,
) -> Result<VerifiedOwnedFundingKeyImageV23, FundingVerificationErrorV12> {
    let spend = Zeroizing::new(
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*spend_scalar))
            .filter(|value| *value != Scalar::ZERO)
            .ok_or(FundingVerificationErrorV12::Recipient)?,
    );
    let view = view_key(view_scalar)?;
    let spend_public = (ED25519_BASEPOINT_POINT * *spend).compress().to_bytes();
    let funding = verify_exact_raw_funding_v12(
        raw,
        expected_tx_hash,
        spend_public,
        view_scalar,
        expected_amount_piconero,
        max_fee_piconero,
    )?;
    let transaction = parse_exact(raw, expected_tx_hash)?;
    let Transaction::V2 {
        prefix,
        proofs: Some(_),
    } = &transaction
    else {
        return Err(FundingVerificationErrorV12::Profile);
    };
    let index =
        usize::try_from(funding.output_index).map_err(|_| FundingVerificationErrorV12::Profile)?;
    let output_key = prefix
        .outputs
        .get(index)
        .ok_or(FundingVerificationErrorV12::Economics)?
        .key
        .to_bytes();
    let (primary, additional) = extra_keys(&prefix.extra, prefix.outputs.len())?;
    let mut candidates = vec![primary];
    if let Some(keys) = additional {
        let key = *keys.get(index).ok_or(FundingVerificationErrorV12::Extra)?;
        if key != primary {
            candidates.push(key);
        }
    }
    let mut owned_secret = None;
    for tx_key in candidates {
        let derivation = Zeroizing::new((point(tx_key)? * *view).mul_by_cofactor());
        let mut bytes = Zeroizing::new(Vec::with_capacity(42));
        bytes.extend_from_slice(&derivation.compress().to_bytes());
        put_varint(index as u64, &mut bytes);
        let shared = hash_scalar(&bytes)?;
        let candidate = Zeroizing::new(*spend + *shared);
        if (ED25519_BASEPOINT_POINT * *candidate).compress().to_bytes() == output_key {
            if owned_secret.replace(candidate).is_some() {
                return Err(FundingVerificationErrorV12::Economics);
            }
        }
    }
    let owned_secret = owned_secret.ok_or(FundingVerificationErrorV12::Economics)?;
    let hash_point: EdwardsPoint = monero_ed25519::Point::biased_hash(output_key).into();
    let key_image = (hash_point * *owned_secret).compress().to_bytes();
    point(key_image)?;
    Ok(VerifiedOwnedFundingKeyImageV23 {
        funding,
        output_key,
        key_image,
    })
}

pub(super) fn point(bytes: [u8; 32]) -> Result<EdwardsPoint, FundingVerificationErrorV12> {
    CompressedEdwardsY(bytes)
        .decompress()
        .filter(|p| {
            p.is_torsion_free() && *p != EdwardsPoint::default() && p.compress().to_bytes() == bytes
        })
        .ok_or(FundingVerificationErrorV12::Recipient)
}
fn view_key(bytes: &[u8; 32]) -> Result<Zeroizing<Scalar>, FundingVerificationErrorV12> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .filter(|s| *s != Scalar::ZERO)
        .map(Zeroizing::new)
        .ok_or(FundingVerificationErrorV12::Recipient)
}
fn hash_scalar(bytes: &[u8]) -> Result<Zeroizing<Scalar>, FundingVerificationErrorV12> {
    let hash = Zeroizing::new(keccak256(bytes));
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*hash));
    if *scalar == Scalar::ZERO {
        return Err(FundingVerificationErrorV12::Recipient);
    }
    Ok(scalar)
}

fn verify_recipient(
    prefix: &TransactionPrefix,
    base: &RctBase,
    spend: [u8; 32],
    view: &[u8; 32],
    amount: u64,
    max_fee: u64,
) -> Result<u32, FundingVerificationErrorV12> {
    let view = view_key(view)?;
    verify_recipient_with_derivations_v23(prefix, base, spend, amount, max_fee, |tx_key| {
        Ok(point(tx_key)? * *view)
    })
}

/// Internal common ECDH verifier. The public proof caller authenticates every
/// derivation against raw R and destination A before entering this helper.
pub(super) fn verify_recipient_with_derivations_v23(
    prefix: &TransactionPrefix,
    base: &RctBase,
    spend: [u8; 32],
    amount: u64,
    max_fee: u64,
    mut derive: impl FnMut([u8; 32]) -> Result<EdwardsPoint, FundingVerificationErrorV12>,
) -> Result<u32, FundingVerificationErrorV12> {
    let outputs = &prefix.outputs;
    if amount == 0
        || max_fee == 0
        || base.fee == 0
        || base.fee > max_fee
        || prefix.additional_timelock != Timelock::None
        || !(2..=16).contains(&outputs.len())
        || outputs.len() != base.encrypted_amounts.len()
        || outputs.len() != base.commitments.len()
        || !base.pseudo_outs.is_empty()
        || prefix.inputs.is_empty()
    {
        return Err(FundingVerificationErrorV12::Profile);
    }
    let mut images = std::collections::BTreeSet::new();
    for input in &prefix.inputs {
        let Input::ToKey { key_image, .. } = input else {
            return Err(FundingVerificationErrorV12::Profile);
        };
        let image = key_image.to_bytes();
        if point(image).is_err() || !images.insert(image) {
            return Err(FundingVerificationErrorV12::Profile);
        }
    }
    let spend = point(spend)?;
    let (primary, additional) = extra_keys(&prefix.extra, outputs.len())?;
    let mut match_index = None;
    for (index, output) in outputs.iter().enumerate() {
        if output.amount.is_some() || output.view_tag.is_none() {
            return Err(FundingVerificationErrorV12::Profile);
        }
        point(output.key.to_bytes())?;
        let EncryptedAmount::Compact { amount: encrypted } = &base.encrypted_amounts[index] else {
            return Err(FundingVerificationErrorV12::Profile);
        };
        let mut candidates = vec![primary];
        if let Some(keys) = &additional {
            if keys[index] != primary {
                candidates.push(keys[index]);
            }
        }
        let mut output_matched = false;
        for tx_key in candidates {
            let derivation = Zeroizing::new(derive(tx_key)?.mul_by_cofactor());
            let mut bytes = Zeroizing::new(Vec::with_capacity(32 + 10));
            bytes.extend_from_slice(&derivation.compress().to_bytes());
            put_varint(index as u64, &mut bytes);
            let mut tagged = Zeroizing::new(Vec::with_capacity(b"view_tag".len() + bytes.len()));
            tagged.extend_from_slice(b"view_tag");
            tagged.extend_from_slice(&bytes);
            if output.view_tag != Some(keccak256(&tagged)[0]) {
                continue;
            }
            let shared = hash_scalar(&bytes)?;
            if (spend + ED25519_BASEPOINT_POINT * *shared)
                .compress()
                .to_bytes()
                != output.key.to_bytes()
            {
                continue;
            }
            let mut masked = Zeroizing::new(Vec::with_capacity(b"amount".len() + 32));
            masked.extend_from_slice(b"amount");
            masked.extend_from_slice(&shared.to_bytes());
            let mask = Zeroizing::new(keccak256(&masked));
            let mut short_mask = Zeroizing::new([0u8; 8]);
            short_mask.copy_from_slice(&mask[..8]);
            let received = u64::from_le_bytes(*encrypted) ^ u64::from_le_bytes(*short_mask);
            let mut commitment_mask =
                Zeroizing::new(Vec::with_capacity(b"commitment_mask".len() + 32));
            commitment_mask.extend_from_slice(b"commitment_mask");
            commitment_mask.extend_from_slice(&shared.to_bytes());
            let opening = Commitment::new(
                MoneroScalar::from(*hash_scalar(&commitment_mask)?),
                received,
            );
            if opening.commit().compress().to_bytes() != base.commitments[index].to_bytes() {
                return Err(FundingVerificationErrorV12::Commitment);
            }
            if received != amount {
                return Err(FundingVerificationErrorV12::Economics);
            }
            if output_matched {
                return Err(FundingVerificationErrorV12::Economics);
            }
            output_matched = true;
        }
        if output_matched {
            if match_index.replace(index as u32).is_some() {
                return Err(FundingVerificationErrorV12::Economics);
            }
        }
    }
    match_index.ok_or(FundingVerificationErrorV12::Economics)
}

// Strict narrow extra profile: one primary key, optional one additional-key
// vector matching output count, optional one bounded nonce, trailing zero padding.
// Never silently stop parsing on unknown data as wallet scanners often do.
pub(super) fn extra_keys(
    extra: &[u8],
    outputs: usize,
) -> Result<([u8; 32], Option<Vec<[u8; 32]>>), FundingVerificationErrorV12> {
    if extra.is_empty() || extra.len() > 4096 {
        return Err(FundingVerificationErrorV12::Extra);
    }
    let mut input = extra;
    let mut primary = None;
    let mut additional = None;
    let mut nonce = false;
    while !input.is_empty() {
        let tag = take(&mut input, 1)?[0];
        match tag {
            0 => {
                if input.len() >= 255 || input.iter().any(|b| *b != 0) {
                    return Err(FundingVerificationErrorV12::Extra);
                }
                input = &[];
            }
            1 if primary.is_none() => {
                let key: [u8; 32] = take(&mut input, 32)?
                    .try_into()
                    .map_err(|_| FundingVerificationErrorV12::Extra)?;
                point(key)?;
                primary = Some(key);
            }
            2 if !nonce => {
                let len = varint(&mut input)?;
                if len > 255 {
                    return Err(FundingVerificationErrorV12::Extra);
                }
                take(&mut input, len)?;
                nonce = true;
            }
            4 if additional.is_none() => {
                if varint(&mut input)? != outputs {
                    return Err(FundingVerificationErrorV12::Extra);
                }
                let mut keys = Vec::with_capacity(outputs);
                for _ in 0..outputs {
                    let key: [u8; 32] = take(&mut input, 32)?
                        .try_into()
                        .map_err(|_| FundingVerificationErrorV12::Extra)?;
                    point(key)?;
                    keys.push(key);
                }
                additional = Some(keys);
            }
            _ => return Err(FundingVerificationErrorV12::Extra),
        }
    }
    Ok((
        primary.ok_or(FundingVerificationErrorV12::Extra)?,
        additional,
    ))
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], FundingVerificationErrorV12> {
    if input.len() < count {
        return Err(FundingVerificationErrorV12::Extra);
    }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}
fn varint(input: &mut &[u8]) -> Result<usize, FundingVerificationErrorV12> {
    let mut value = 0usize;
    for shift in (0..28).step_by(7) {
        let b = take(input, 1)?[0];
        value |= usize::from(b & 127) << shift;
        if b < 128 {
            if shift != 0 && b == 0 {
                return Err(FundingVerificationErrorV12::Extra);
            }
            return Ok(value);
        }
    }
    Err(FundingVerificationErrorV12::Extra)
}
fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Encode the standard shared FUNDING address (not the final sweep destination).
/// Network tags follow XmrSetupProfile: 1 mainnet, 2 stagenet, 3 testnet.
pub fn standard_funding_address_v12(
    network_tag: u8,
    spend: [u8; 32],
    view: &[u8; 32],
) -> Result<String, FundingVerificationErrorV12> {
    point(spend)?;
    let view = view_key(view)?;
    let prefix = match network_tag {
        1 => 18,
        2 => 24,
        3 => 53,
        _ => return Err(FundingVerificationErrorV12::Profile),
    };
    Ok(encode_standard_address(
        prefix,
        spend,
        (ED25519_BASEPOINT_POINT * *view).compress().to_bytes(),
    ))
}
fn encode_standard_address(prefix: u8, spend: [u8; 32], view_public: [u8; 32]) -> String {
    let mut bytes = vec![prefix];
    bytes.extend_from_slice(&spend);
    bytes.extend_from_slice(&view_public);
    let checksum = keccak256(&bytes);
    bytes.extend_from_slice(&checksum[..4]);
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const LENGTHS: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    let mut result = String::with_capacity(95);
    for chunk in bytes.chunks(8) {
        let mut block = [0u8; 8];
        block[8 - chunk.len()..].copy_from_slice(chunk);
        let mut value = u64::from_be_bytes(block);
        let mut encoded = vec![b'1'; LENGTHS[chunk.len()]];
        for position in (0..encoded.len()).rev() {
            encoded[position] = ALPHABET[(value % 58) as usize];
            value /= 58;
        }
        for byte in encoded {
            result.push(char::from(byte));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_oxide::{ed25519::CompressedPoint, transaction::Output};

    // Deterministic ECDH/commitment fixture, not a CLSAG or consensus-valid tx.
    // Recipient construction is the sender equation r*(aG), whereas verification
    // uses the receiver equation a*(rG).
    fn fixture() -> (TransactionPrefix, RctBase, [u8; 32], [u8; 32]) {
        let spend_scalar = Scalar::from(7u64);
        let view = Scalar::from(11u64);
        let r = Scalar::from(19u64);
        let spend = ED25519_BASEPOINT_POINT * spend_scalar;
        let primary = (ED25519_BASEPOINT_POINT * r).compress().to_bytes();
        let mut prefix = TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::ToKey {
                amount: None,
                key_offsets: vec![1; 16],
                key_image: CompressedPoint::from(
                    (ED25519_BASEPOINT_POINT * Scalar::from(29u64))
                        .compress()
                        .to_bytes(),
                ),
            }],
            outputs: vec![],
            extra: vec![1],
        };
        prefix.extra.extend_from_slice(&primary);
        let mut base = RctBase {
            fee: 10,
            pseudo_outs: vec![],
            encrypted_amounts: vec![],
            commitments: vec![],
        };
        for (index, receiver) in [spend, ED25519_BASEPOINT_POINT * Scalar::from(31u64)]
            .into_iter()
            .enumerate()
        {
            let ecdh = ((ED25519_BASEPOINT_POINT * view) * r).mul_by_cofactor();
            let mut d = ecdh.compress().to_bytes().to_vec();
            put_varint(index as u64, &mut d);
            let shared = Scalar::from_bytes_mod_order(keccak256(&d));
            let tag = keccak256([b"view_tag".as_slice(), &d].concat())[0];
            let amount = if index == 0 { 100 } else { 9 };
            let mask_hash =
                keccak256([b"amount".as_slice(), shared.to_bytes().as_slice()].concat());
            let mut mask = [0u8; 8];
            mask.copy_from_slice(&mask_hash[..8]);
            let encrypted = (amount ^ u64::from_le_bytes(mask)).to_le_bytes();
            let cm = Scalar::from_bytes_mod_order(keccak256(
                [b"commitment_mask".as_slice(), shared.to_bytes().as_slice()].concat(),
            ));
            prefix.outputs.push(Output {
                amount: None,
                key: CompressedPoint::from(
                    (receiver + ED25519_BASEPOINT_POINT * shared)
                        .compress()
                        .to_bytes(),
                ),
                view_tag: Some(tag),
            });
            base.encrypted_amounts
                .push(EncryptedAmount::Compact { amount: encrypted });
            base.commitments.push(
                Commitment::new(MoneroScalar::from(cm), amount)
                    .commit()
                    .compress(),
            );
        }
        (prefix, base, spend.compress().to_bytes(), view.to_bytes())
    }
    #[test]
    fn sender_ecdh_matches_receiver_exact_economics_without_spend_shares() {
        let (prefix, base, spend, view) = fixture();
        assert_eq!(
            verify_recipient(&prefix, &base, spend, &view, 100, 10),
            Ok(0)
        );
        assert_eq!(
            verify_recipient(&prefix, &base, spend, &view, 101, 10),
            Err(FundingVerificationErrorV12::Economics)
        );
        let wrong_spend = (ED25519_BASEPOINT_POINT * Scalar::from(5u64))
            .compress()
            .to_bytes();
        assert_eq!(
            verify_recipient(&prefix, &base, wrong_spend, &view, 100, 10),
            Err(FundingVerificationErrorV12::Economics)
        );
        assert_eq!(
            verify_recipient(
                &prefix,
                &base,
                spend,
                &Scalar::from(5u64).to_bytes(),
                100,
                10
            ),
            Err(FundingVerificationErrorV12::Economics)
        );
    }
    #[test]
    fn amount_ciphertext_commitment_fee_and_timelock_cannot_be_relabelled() {
        let (prefix, base, spend, view) = fixture();
        let mut changed = base.clone();
        let EncryptedAmount::Compact { amount } = &mut changed.encrypted_amounts[0] else {
            panic!("fixture");
        };
        amount[0] ^= 1;
        assert_eq!(
            verify_recipient(&prefix, &changed, spend, &view, 100, 10),
            Err(FundingVerificationErrorV12::Commitment)
        );
        changed = base.clone();
        changed.commitments.swap(0, 1);
        assert_eq!(
            verify_recipient(&prefix, &changed, spend, &view, 100, 10),
            Err(FundingVerificationErrorV12::Commitment)
        );
        assert_eq!(
            verify_recipient(&prefix, &base, spend, &view, 100, 9),
            Err(FundingVerificationErrorV12::Profile)
        );
        let mut locked = prefix.clone();
        locked.additional_timelock = Timelock::Block(1);
        assert_eq!(
            verify_recipient(&locked, &base, spend, &view, 100, 10),
            Err(FundingVerificationErrorV12::Profile)
        );
    }
    #[test]
    fn ambiguous_or_partial_extra_never_becomes_absence() {
        let (prefix, _, _, _) = fixture();
        assert!(extra_keys(&prefix.extra, 2).is_ok());
        let mut duplicate = prefix.extra.clone();
        duplicate.extend_from_slice(&prefix.extra);
        assert!(extra_keys(&duplicate, 2).is_err());
        let mut unknown = prefix.extra.clone();
        unknown.push(3);
        assert!(extra_keys(&unknown, 2).is_err());
        assert!(extra_keys(&prefix.extra[..32], 2).is_err());
        let mut overlong = prefix.extra.clone();
        overlong.extend_from_slice(&[2, 0x80, 0]);
        assert!(extra_keys(&overlong, 2).is_err());
        let mut wrong_count = prefix.extra;
        wrong_count.extend_from_slice(&[4, 1]);
        assert!(extra_keys(&wrong_count, 2).is_err());
    }
    #[test]
    fn address_network_keys_and_secret_encodings_are_bound() {
        let (_, _, spend, view) = fixture();
        let main = standard_funding_address_v12(1, spend, &view).unwrap();
        assert_eq!(main.len(), 95);
        assert!(main.starts_with('4'));
        assert_ne!(main, standard_funding_address_v12(2, spend, &view).unwrap());
        assert_ne!(main, standard_funding_address_v12(3, spend, &view).unwrap());
        assert!(standard_funding_address_v12(0, spend, &view).is_err());
        assert!(standard_funding_address_v12(1, spend, &[0; 32]).is_err());
        assert!(standard_funding_address_v12(1, spend, &[255; 32]).is_err());
        assert!(standard_funding_address_v12(1, [0; 32], &view).is_err());
    }
    #[test]
    fn base58_and_checksum_match_the_independent_upstream_address_vector() {
        // monero-oxide c8be5d3d wallet/address/src/tests.rs STANDARD/SPEND/VIEW.
        fn bytes(hex: &str) -> [u8; 32] {
            std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        }
        let spend = bytes("f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7");
        let view = bytes("4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce");
        assert_eq!(encode_standard_address(18,spend,view),
            "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey");
    }
}
