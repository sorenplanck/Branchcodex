//! Cryptographic admission for the explicitly enabled local scenario pool.
//! This is deliberately not Monero consensus admission or mainnet validity.
use anyhow::{Result, anyhow, ensure};
use curve25519_dalek::{edwards::EdwardsPoint, traits::Identity};
use monero_oxide_wallet::{
    ed25519::{Commitment, CompressedPoint, Scalar},
    ringct::{RctPrunable, RctType},
    transaction::{Input, Timelock, Transaction},
};

use super::Snapshot;

pub(super) const MAX_RAW_BYTES: usize = 131_072;

pub(super) fn decode(raw: &[u8]) -> Result<Transaction> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_RAW_BYTES,
        "candidate raw byte bound"
    );
    let mut reader = raw;
    let tx = Transaction::read(&mut reader)?;
    ensure!(
        reader.is_empty() && tx.serialize() == raw,
        "candidate canonical encoding"
    );
    Ok(tx)
}

fn point(encoded: CompressedPoint) -> Result<EdwardsPoint> {
    let point: EdwardsPoint = encoded
        .decompress()
        .ok_or_else(|| anyhow!("candidate compressed point"))?
        .into();
    ensure!(point.is_torsion_free(), "candidate torsion point");
    Ok(point)
}

pub(super) fn candidate(tx: &Transaction, ledger: &Snapshot) -> Result<()> {
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = tx
    else {
        return Err(anyhow!("candidate must carry V2 RingCT proofs"));
    };
    ensure!(
        prefix.additional_timelock == Timelock::None,
        "candidate additional timelock unsupported"
    );
    ensure!(
        !prefix.inputs.is_empty()
            && prefix.inputs.len() <= 16
            && (2..=16).contains(&prefix.outputs.len()),
        "candidate cardinality bound"
    );
    ensure!(
        proofs.rct_type() == RctType::ClsagBulletproofPlus,
        "candidate hardfork profile"
    );
    ensure!(
        proofs.base.fee > 0 && proofs.base.fee <= 1_000_000_000,
        "candidate fee bound"
    );
    ensure!(
        proofs.base.commitments.len() == prefix.outputs.len()
            && proofs.base.encrypted_amounts.len() == prefix.outputs.len(),
        "candidate output proof cardinality"
    );
    let RctPrunable::Clsag {
        bulletproof,
        clsags,
        pseudo_outs,
    } = &proofs.prunable
    else {
        return Err(anyhow!("candidate CLSAG proof required"));
    };
    ensure!(
        clsags.len() == prefix.inputs.len() && pseudo_outs.len() == prefix.inputs.len(),
        "candidate input proof cardinality"
    );
    let signature_hash = tx
        .signature_hash()
        .ok_or_else(|| anyhow!("candidate signature hash"))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut input_sum = EdwardsPoint::identity();
    for (index, input) in prefix.inputs.iter().enumerate() {
        let Input::ToKey {
            amount,
            key_offsets,
            key_image,
        } = input
        else {
            return Err(anyhow!("candidate coinbase input refused"));
        };
        ensure!(
            amount.unwrap_or(0) == 0 && key_offsets.len() == 16,
            "candidate RingCT ring shape"
        );
        ensure!(
            seen.insert(key_image.to_bytes()) && ledger.key_image_status(key_image.to_bytes()) == 0,
            "candidate duplicate or spent key image"
        );
        let mut absolute = 0u64;
        let mut ring = Vec::with_capacity(16);
        for (member, offset) in key_offsets.iter().enumerate() {
            ensure!(member == 0 || *offset > 0, "candidate duplicate ring index");
            absolute = absolute
                .checked_add(*offset)
                .ok_or_else(|| anyhow!("candidate ring offset overflow"))?;
            let at = usize::try_from(absolute)?;
            let output = ledger
                .outputs
                .get(at)
                .ok_or_else(|| anyhow!("candidate ring member outside history"))?;
            ensure!(
                ledger.unlock_heights[at] <= ledger.tip,
                "candidate immature ring member"
            );
            ring.push([
                CompressedPoint::from(output.key),
                CompressedPoint::from(output.mask),
            ]);
        }
        clsags[index]
            .verify(ring, key_image, &pseudo_outs[index], &signature_hash)
            .map_err(|_| anyhow!("candidate CLSAG verification failed"))?;
        input_sum += point(pseudo_outs[index])?;
    }
    let mut output_sum: EdwardsPoint = Commitment::new(Scalar::ZERO, proofs.base.fee)
        .commit()
        .into();
    for (output, commitment) in prefix.outputs.iter().zip(&proofs.base.commitments) {
        ensure!(
            output.amount.is_none() && output.view_tag.is_some(),
            "candidate output profile"
        );
        ensure!(
            point(output.key)? != EdwardsPoint::identity(),
            "candidate identity output key"
        );
        output_sum += point(*commitment)?;
    }
    ensure!(
        input_sum == output_sum,
        "candidate commitment amount conservation"
    );
    ensure!(
        bulletproof.verify(&mut rand::rngs::OsRng, &proofs.base.commitments),
        "candidate Bulletproofs+ verification failed"
    );
    Ok(())
}
