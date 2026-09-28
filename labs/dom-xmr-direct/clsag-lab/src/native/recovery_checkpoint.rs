//! Private unsigned recovery intent. Contains commitment openings, not spend
//! shares or signing nonces. Loading is not chain observation or send authority.
//! An independently pinned digest and trusted participant storage are required.

use super::*;
use monero_clsag::{Clsag, Decoys};

const MAGIC: &[u8] = b"DXP1/unsigned-xmr-recovery/v1\0";

fn placeholder() -> Clsag {
    // Native wire encoding requires a fixed-size CLSAG, even for an unsigned
    // intent. This marker is never accepted as a signature or pre-signature.
    Clsag {
        D: Point::from(G).compress(),
        s: vec![MoneroScalar::from(Scalar::ZERO); RING_SIZE],
        c1: MoneroScalar::from(Scalar::ZERO),
    }
}

impl PreparedClaim {
    /// Frozen unsigned body and original input openings. The caller stores
    /// this privately/durably before discarding preparation. No signature is
    /// produced here, and no spend key or signing nonce is serialized.
    pub fn to_recovery_bytes(&self) -> Result<Zeroizing<Vec<u8>>, NativeError> {
        let context = self.context();
        context.validate()?;
        let mut bytes = Zeroizing::new(MAGIC.to_vec());
        bytes.extend(context.route_binding);
        bytes.push(context.real as u8);
        for pair in context.ring {
            for point in pair {
                bytes.extend(point.compress().to_bytes());
            }
        }
        bytes.extend(context.image.compress().to_bytes());
        bytes.extend(context.pseudo_out.compress().to_bytes());
        bytes.extend(context.message);
        self.opening
            .commitment
            .write(&mut *bytes)
            .map_err(|_| NativeError::ResumeEncoding)?;
        let mask = Zeroizing::new(self.opening.pseudo_mask.to_bytes());
        bytes.extend_from_slice(&*mask);
        let mut transaction = self.body.transaction.clone();
        let Transaction::V2 {
            proofs: Some(proofs),
            ..
        } = &mut transaction
        else {
            return Err(NativeError::Proofs);
        };
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } = &mut proofs.prunable
        else {
            return Err(NativeError::Proofs);
        };
        *clsags = vec![placeholder()];
        *pseudo_outs = vec![Point::from(context.pseudo_out).compress()];
        let raw = transaction.serialize();
        bytes.extend(
            u32::try_from(raw.len())
                .map_err(|_| NativeError::ResumeEncoding)?
                .to_le_bytes(),
        );
        bytes.extend(raw);
        if bytes.len() > claim_resume::MAX_RECORD_BYTES {
            return Err(NativeError::ResumeEncoding);
        }
        Ok(bytes)
    }

    /// Restore the EXACT approved unsigned intent, retaining its input opening
    /// and output bytes. No new outputs, fee, transaction key or deadline.
    /// This verifies internal cryptographic consistency, not funding/maturity,
    /// input unspentness, destinations' authorization or original timing policy.
    /// `expected` uses claim_resume::digest (domain + length + body), not a
    /// plain SHA-256 of the body.
    pub fn from_recovery_bytes(
        bytes: &[u8],
        expected: [u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, NativeError> {
        let error = || NativeError::ResumeEncoding;
        let mut input = claim_resume::checked(bytes, expected, MAGIC).ok_or_else(error)?;
        let route_binding = claim_resume::take(&mut input).ok_or_else(error)?;
        let real = claim_resume::take::<1>(&mut input).ok_or_else(error)?[0] as usize;
        fn point(input: &mut &[u8]) -> Result<EdwardsPoint, NativeError> {
            let raw = claim_resume::take(input).ok_or(NativeError::ResumeEncoding)?;
            let point = CompressedEdwardsY(raw)
                .decompress()
                .ok_or(NativeError::ResumeEncoding)?;
            if point.compress().to_bytes() != raw {
                return Err(NativeError::ResumeEncoding);
            }
            Ok(point)
        }
        let mut ring = [[G; 2]; RING_SIZE];
        for pair in &mut ring {
            for value in pair {
                *value = point(&mut input)?;
            }
        }
        let context = Context {
            ring,
            real,
            image: point(&mut input)?,
            pseudo_out: point(&mut input)?,
            message: claim_resume::take(&mut input).ok_or_else(error)?,
            route_binding,
        };
        context.validate()?;
        let commitment = Commitment::read(&mut input).map_err(|_| NativeError::ResumeEncoding)?;
        let raw_mask = Zeroizing::new(claim_resume::take(&mut input).ok_or_else(error)?);
        let pseudo_mask = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(*raw_mask)).ok_or_else(error)?,
        );
        if commitment.commit().into() != context.ring[real][1]
            || Commitment::new(MoneroScalar::from(*pseudo_mask), commitment.amount)
                .commit()
                .into()
                != context.pseudo_out
        {
            return Err(NativeError::Input);
        }
        let length = u32::from_le_bytes(claim_resume::take(&mut input).ok_or_else(error)?) as usize;
        if input.len() != length {
            return Err(error());
        }
        let transaction = Transaction::read(&mut input).map_err(|_| NativeError::ResumeEncoding)?;
        if !input.is_empty()
            || transaction.prefix().additional_timelock != Timelock::None
            || transaction.prefix().outputs.len() != 2
        {
            return Err(error());
        }
        let offsets = match transaction.prefix().inputs.as_slice() {
            [Input::ToKey {
                amount: None,
                key_offsets,
                key_image,
            }] if key_offsets.len() == RING_SIZE
                && key_image.to_bytes() == context.image.compress().to_bytes() =>
            {
                key_offsets.clone()
            }
            _ => return Err(NativeError::Input),
        };
        Decoys::new(
            offsets.clone(),
            real as u8,
            ring.iter().map(|pair| pair.map(Point::from)).collect(),
        )
        .ok_or(NativeError::Input)?;
        let proof = proofs(&transaction)?;
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } = &proof.prunable
        else {
            return Err(NativeError::Proofs);
        };
        if clsags.as_slice() != [placeholder()]
            || pseudo_outs.as_slice() != [Point::from(context.pseudo_out).compress()]
            || proof.base.commitments.len() != 2
            || proof.base.encrypted_amounts.len() != 2
            || transaction.signature_hash() != Some(context.message)
        {
            return Err(NativeError::Proofs);
        }
        check_range_and_balance(proof, context.pseudo_out, rng)?;
        let result = Self {
            body: ClaimBody {
                transaction,
                context,
            },
            opening: InputOpening {
                commitment,
                pseudo_mask,
            },
            offsets,
        };
        if result.to_recovery_bytes()?.as_slice() != bytes {
            return Err(error());
        }
        // Fail closed even if the wire marker were somehow a valid native
        // signature for this intent. This record must remain unsigned.
        if result.verify_final(&result.body.transaction, rng).is_ok() {
            return Err(NativeError::Proofs);
        }
        Ok(result)
    }
}
