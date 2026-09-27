//! Native transaction experiment: one RingCT input, standard recipient and change.
//!
//! Uses the upstream wallet builder and Bulletproofs+ verifier, then attaches a
//! jointly produced adaptor CLSAG. No chain membership, maturity, unspentness,
//! fee freshness, transport authentication or recovery is established here.
//! The caller must validate those before any funding or signature exchange.

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use monero_wallet::{
    address::{AddressType, MoneroAddress},
    ed25519::{Commitment, CompressedPoint, Point, Scalar as MoneroScalar},
    interface::FeeRate,
    io::VarInt,
    primitives::keccak256,
    ringct::{EncryptedAmount, RctProofs, RctPrunable, RctType},
    send::{Change, SignableTransaction, TransactionKeys},
    transaction::{Input, Timelock, Transaction},
    OutputWithDecoys, ViewPair,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    claim_resume, joint::InputOpening, Context, Error, PreSignature, Statement, G, RING_SIZE,
};

mod recovery_checkpoint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeError {
    ResumeEncoding,
    Terms,
    Input,
    Builder,
    Outputs,
    Proofs,
    DifferentTransaction,
    Crypto(Error),
}

impl From<Error> for NativeError {
    fn from(error: Error) -> Self {
        Self::Crypto(error)
    }
}

/// A locally approved payment; amounts and fee limits are in atomic XMR units.
pub struct ClaimTerms {
    pub recipient: MoneroAddress,
    pub amount: u64,
    pub change: ViewPair,
    pub fee_rate: FeeRate,
    pub max_fee: u64,
}

/// Frozen unsigned transaction and its signing context. Does not own spend keys.
pub struct PreparedClaim {
    body: ClaimBody,
    opening: InputOpening,
    offsets: Vec<u64>,
}

struct ClaimBody {
    transaction: Transaction,
    context: Context,
}

impl PreparedClaim {
    /// `outgoing_view_key` must be fresh for each incompatible transaction.
    /// It is a secret shared between these two signers, not a spend key.
    pub fn new(
        input: OutputWithDecoys,
        image: EdwardsPoint,
        terms: ClaimTerms,
        outgoing_view_key: Zeroizing<[u8; 32]>,
        route_binding: [u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, NativeError> {
        let change = terms.change.legacy_address(terms.recipient.network());
        if terms.recipient.kind() != &AddressType::Legacy
            || terms.recipient == change
            || terms.amount == 0
            || terms.max_fee == 0
            || *outgoing_view_key == [0; 32]
            || route_binding == [0; 32]
            || [terms.recipient, change].iter().any(|addr| {
                !crate::valid_point(&addr.spend().into())
                    || !crate::valid_point(&addr.view().into())
            })
        {
            return Err(NativeError::Terms);
        }
        // The upstream fee calculator deliberately panics on overflow. Reject
        // unrepresentable local policies before invoking the wallet builder.
        let fee_encoding = terms.fee_rate.serialize();
        let mask = u64::from_le_bytes(fee_encoding[8..16].try_into().expect("native fee format"));
        let max_weight = u64::try_from(Transaction::NON_MINER_SIZE_UPPER_BOUND.0)
            .map_err(|_| NativeError::Terms)?;
        if terms
            .fee_rate
            .per_weight()
            .checked_mul(max_weight)
            .and_then(|fee| fee.checked_add(mask))
            .is_none()
        {
            return Err(NativeError::Terms);
        }
        if input.decoys().len() != RING_SIZE {
            return Err(NativeError::Input);
        }
        let real = usize::from(input.decoys().signer_index());
        let ring = input
            .decoys()
            .ring()
            .iter()
            .map(|pair| pair.map(Point::into))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| NativeError::Input)?;
        let mut context = Context {
            ring,
            real,
            image,
            pseudo_out: input.commitment().commit().into(),
            message: [0; 32],
            route_binding,
        };
        context.validate()?;
        if context.ring[real] != [input.key().into(), input.commitment().commit().into()] {
            return Err(NativeError::Input);
        }
        let commitment = input.commitment().clone();
        let offsets = input.decoys().offsets().to_vec();
        let tx_key =
            TransactionKeys::new(&outgoing_view_key, vec![(input.key(), commitment.commit())])
                .next()
                .ok_or(NativeError::Builder)?;
        let intent = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            outgoing_view_key,
            vec![input],
            vec![(terms.recipient, terms.amount)],
            Change::new(terms.change, None),
            vec![],
            terms.fee_rate,
        )
        .map_err(|_| NativeError::Builder)?;
        let fee = intent.necessary_fee();
        if fee > terms.max_fee {
            return Err(NativeError::Terms);
        }
        let change_amount = commitment
            .amount
            .checked_sub(terms.amount)
            .and_then(|remainder| remainder.checked_sub(fee))
            .filter(|amount| *amount > 0)
            .ok_or(NativeError::Terms)?;
        let transaction = intent
            .unsigned_transaction(vec![Point::from(image).compress()])
            .ok_or(NativeError::Builder)?;
        let proofs = proofs(&transaction)?;
        if proofs.base.fee != fee
            || transaction.prefix().outputs.len() != 2
            || proofs.base.commitments.len() != 2
            || proofs.base.encrypted_amounts.len() != 2
        {
            return Err(NativeError::Outputs);
        }

        // Recover the sender's output openings using only the ephemeral TX key
        // and the approved public addresses. Account for the native shuffle.
        let expected = [(terms.recipient, terms.amount), (change, change_amount)];
        let mut used = [false; 2];
        let mut mask_sum = Zeroizing::new(Scalar::ZERO);
        for (index, output) in transaction.prefix().outputs.iter().enumerate() {
            let mut matched = None;
            for (which, (address, amount)) in expected.iter().enumerate() {
                if used[which] {
                    continue;
                }
                let (key, tag, mask, encrypted) = output_opening(&tx_key, address, index, *amount);
                if output.key == key {
                    if output.amount.is_some()
                        || output.view_tag != Some(tag)
                        || proofs.base.commitments[index]
                            != Commitment::new(MoneroScalar::from(*mask), *amount)
                                .commit()
                                .compress()
                        || proofs.base.encrypted_amounts[index] != encrypted
                    {
                        return Err(NativeError::Outputs);
                    }
                    matched = Some((which, mask));
                    break;
                }
            }
            let (which, mask) = matched.ok_or(NativeError::Outputs)?;
            used[which] = true;
            *mask_sum += *mask;
        }
        context.pseudo_out = Commitment::new(MoneroScalar::from(*mask_sum), commitment.amount)
            .commit()
            .into();
        context.message = transaction.signature_hash().ok_or(NativeError::Builder)?;
        context.validate()?;
        check_range_and_balance(proofs, context.pseudo_out, rng)?;
        Ok(Self {
            body: ClaimBody {
                transaction,
                context,
            },
            offsets,
            opening: InputOpening {
                commitment,
                pseudo_mask: mask_sum,
            },
        })
    }

    pub fn context(&self) -> &Context {
        &self.body.context
    }
    pub fn offsets(&self) -> &[u64] {
        &self.offsets
    }
    pub fn input_opening(&self) -> InputOpening {
        InputOpening {
            commitment: self.opening.commitment.clone(),
            pseudo_mask: self.opening.pseudo_mask.clone(),
        }
    }
    pub fn fee(&self) -> u64 {
        self.body.fee()
    }

    /// Consumes signing preparation, dropping private input openings. The
    /// resulting artifact can only adapt/extract this already signed intent.
    pub fn into_claim_envelope(self, pre: PreSignature) -> Result<XmrClaimEnvelope, NativeError> {
        pre.verify(&self.body.context)?;
        Ok(XmrClaimEnvelope {
            body: self.body,
            pre,
        })
    }

    pub fn complete(
        &self,
        pre: &PreSignature,
        witness: &Zeroizing<Scalar>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction, NativeError> {
        self.body.complete(pre, witness, rng)
    }

    pub fn verify_final(
        &self,
        transaction: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), NativeError> {
        self.body.verify_final(transaction, rng)
    }

    pub fn extract(
        &self,
        pre: &PreSignature,
        transaction: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Zeroizing<Scalar>, NativeError> {
        self.body.extract(pre, transaction, rng)
    }
}

impl ClaimBody {
    fn fee(&self) -> u64 {
        proofs(&self.transaction)
            .expect("validated transaction")
            .base
            .fee
    }

    /// Fill only the CLSAG and pseudo-output fields, then verify the whole intent.
    pub fn complete(
        &self,
        pre: &PreSignature,
        witness: &Zeroizing<Scalar>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction, NativeError> {
        let signature = pre.complete(&self.context, witness)?;
        let mut transaction = self.transaction.clone();
        let Transaction::V2 {
            proofs: Some(proofs),
            ..
        } = &mut transaction
        else {
            return Err(NativeError::Builder);
        };
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } = &mut proofs.prunable
        else {
            return Err(NativeError::Builder);
        };
        *clsags = vec![signature];
        *pseudo_outs = vec![Point::from(self.context.pseudo_out).compress()];
        self.verify_final(&transaction, rng)?;
        Ok(transaction)
    }

    /// Verify correspondence to this exact payment, plus native CLSAG, range
    /// proof and commitment balance. Chain checks remain the caller's duty.
    pub fn verify_final(
        &self,
        transaction: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), NativeError> {
        let expected = proofs(&self.transaction)?;
        let candidate = proofs(transaction)?;
        if transaction.prefix() != self.transaction.prefix() || candidate.base != expected.base {
            return Err(NativeError::DifferentTransaction);
        }
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            bulletproof,
        } = &candidate.prunable
        else {
            return Err(NativeError::Proofs);
        };
        let RctPrunable::Clsag {
            bulletproof: expected_bp,
            ..
        } = &expected.prunable
        else {
            return Err(NativeError::Proofs);
        };
        if clsags.len() != 1
            || pseudo_outs.as_slice() != [Point::from(self.context.pseudo_out).compress()]
            || bulletproof != expected_bp
            || transaction.signature_hash() != Some(self.context.message)
        {
            return Err(NativeError::DifferentTransaction);
        }
        check_range_and_balance(candidate, self.context.pseudo_out, rng)?;
        self.context.verify_native(&clsags[0])?;
        Ok(())
    }

    pub fn extract(
        &self,
        pre: &PreSignature,
        transaction: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Zeroizing<Scalar>, NativeError> {
        self.verify_final(transaction, rng)?;
        let RctPrunable::Clsag { clsags, .. } = &proofs(transaction)?.prunable else {
            return Err(NativeError::Proofs);
        };
        Ok(pre.extract(&self.context, &clsags[0])?)
    }
}

/// Frozen claim plus validated adaptor. No InputOpening, spend share, nonce,
/// outgoing view key or original adaptor witness survives conversion.
/// Context contains real ring position: this is participant-private metadata.
pub struct XmrClaimEnvelope {
    body: ClaimBody,
    pre: PreSignature,
}

const RESUME_MAGIC: &[u8] = b"DXP1/XMR-claim-resume/v1\0";

impl XmrClaimEnvelope {
    pub fn context(&self) -> &Context {
        &self.body.context
    }
    pub fn fee(&self) -> u64 {
        self.body.fee()
    }
    pub fn complete(
        &self,
        witness: &Zeroizing<Scalar>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transaction, NativeError> {
        self.body.complete(&self.pre, witness, rng)
    }
    pub fn verify_final(
        &self,
        tx: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), NativeError> {
        self.body.verify_final(tx, rng)
    }
    pub fn extract(
        &self,
        tx: &Transaction,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Zeroizing<Scalar>, NativeError> {
        self.body.extract(&self.pre, tx, rng)
    }

    pub fn to_resume_bytes(&self) -> Result<Vec<u8>, NativeError> {
        self.pre.verify(self.context())?;
        let mut bytes = RESUME_MAGIC.to_vec();
        bytes.extend(self.context().route_binding);
        bytes.push(self.context().real as u8);
        for pair in self.context().ring {
            for point in pair {
                bytes.extend(point.compress().to_bytes());
            }
        }
        bytes.extend(self.context().image.compress().to_bytes());
        bytes.extend(self.context().pseudo_out.compress().to_bytes());
        bytes.extend(self.context().message);
        for point in [
            self.pre.statement.t_g,
            self.pre.statement.t_h,
            self.pre.statement.r_g,
            self.pre.statement.r_h,
        ] {
            bytes.extend(point.compress().to_bytes());
        }
        bytes.extend(self.pre.statement.response.to_bytes());
        // A complete native wire shape carrying the PRE-signature, which is
        // not a valid spend until adapted. Unsigned upstream placeholders do
        // not have a round-trippable transaction encoding by themselves.
        let mut tx = self.body.transaction.clone();
        let Transaction::V2 {
            proofs: Some(proofs),
            ..
        } = &mut tx
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
        *clsags = vec![self.pre.signature.clone()];
        *pseudo_outs = vec![Point::from(self.context().pseudo_out).compress()];
        let raw = tx.serialize();
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

    /// Expected digest must be pinned BEFORE exposure/failure. This validates
    /// canonical encoding, adaptor, range proof and intent consistency, not
    /// chain membership, destinations' approval or any timing assumption.
    pub fn from_resume_bytes(
        bytes: &[u8],
        expected: [u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, NativeError> {
        let mut input = claim_resume::checked(bytes, expected, RESUME_MAGIC)
            .ok_or(NativeError::ResumeEncoding)?;
        let route_binding = claim_resume::take(&mut input).ok_or(NativeError::ResumeEncoding)?;
        let real =
            claim_resume::take::<1>(&mut input).ok_or(NativeError::ResumeEncoding)?[0] as usize;
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
            message: claim_resume::take(&mut input).ok_or(NativeError::ResumeEncoding)?,
            route_binding,
        };
        context.validate()?;
        let statement = Statement {
            t_g: point(&mut input)?,
            t_h: point(&mut input)?,
            r_g: point(&mut input)?,
            r_h: point(&mut input)?,
            response: Option::<Scalar>::from(Scalar::from_canonical_bytes(
                claim_resume::take(&mut input).ok_or(NativeError::ResumeEncoding)?,
            ))
            .ok_or(NativeError::ResumeEncoding)?,
        };
        let len =
            u32::from_le_bytes(claim_resume::take(&mut input).ok_or(NativeError::ResumeEncoding)?)
                as usize;
        if input.len() != len {
            return Err(NativeError::ResumeEncoding);
        }
        let transaction = Transaction::read(&mut input).map_err(|_| NativeError::ResumeEncoding)?;
        if !input.is_empty()
            || transaction.prefix().additional_timelock != Timelock::None
            || transaction.prefix().outputs.len() != 2
        {
            return Err(NativeError::ResumeEncoding);
        }
        match transaction.prefix().inputs.as_slice() {
            [Input::ToKey {
                amount: None,
                key_offsets,
                key_image,
            }] if key_offsets.len() == RING_SIZE
                && key_image.to_bytes() == context.image.compress().to_bytes() => {}
            _ => return Err(NativeError::Input),
        }
        let proofs = proofs(&transaction)?;
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } = &proofs.prunable
        else {
            return Err(NativeError::Proofs);
        };
        if clsags.len() != 1
            || pseudo_outs.as_slice() != [Point::from(context.pseudo_out).compress()]
            || transaction.signature_hash() != Some(context.message)
            || proofs.base.commitments.len() != 2
            || proofs.base.encrypted_amounts.len() != 2
        {
            return Err(NativeError::Proofs);
        }
        check_range_and_balance(proofs, context.pseudo_out, rng)?;
        let pre = PreSignature {
            signature: clsags[0].clone(),
            statement,
        };
        pre.verify(&context)?;
        let result = Self {
            body: ClaimBody {
                transaction,
                context,
            },
            pre,
        };
        if result.to_resume_bytes()? != bytes {
            return Err(NativeError::ResumeEncoding);
        }
        Ok(result)
    }
}

fn proofs(transaction: &Transaction) -> Result<&RctProofs, NativeError> {
    match transaction {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => Ok(proofs),
        _ => Err(NativeError::Proofs),
    }
}

fn check_range_and_balance(
    proofs: &RctProofs,
    pseudo_out: EdwardsPoint,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), NativeError> {
    let RctPrunable::Clsag { bulletproof, .. } = &proofs.prunable else {
        return Err(NativeError::Proofs);
    };
    if !bulletproof.verify(rng, &proofs.base.commitments) {
        return Err(NativeError::Proofs);
    }
    let mut balance: EdwardsPoint =
        Commitment::new(MoneroScalar::from(Scalar::ZERO), proofs.base.fee)
            .commit()
            .into();
    for commitment in &proofs.base.commitments {
        balance += commitment.decompress().ok_or(NativeError::Proofs)?.into();
    }
    if balance != pseudo_out {
        return Err(NativeError::Proofs);
    }
    Ok(())
}

// Standard-address derivations follow the pinned native wallet. See NOTICE.md.
fn output_opening(
    tx_key: &Zeroizing<MoneroScalar>,
    address: &MoneroAddress,
    index: usize,
    amount: u64,
) -> (CompressedPoint, u8, Zeroizing<Scalar>, EncryptedAmount) {
    let tx_scalar = Zeroizing::new((**tx_key).into());
    let secret = Zeroizing::new(*tx_scalar * address.view().into());
    let mut derivation = Zeroizing::new(secret.mul_by_cofactor().compress().to_bytes().to_vec());
    VarInt::write(&index, &mut *derivation).expect("Vec write cannot fail");
    let tag = keccak256(Zeroizing::new(
        [b"view_tag".as_slice(), &derivation].concat(),
    ))[0];
    let shared = Zeroizing::new(MoneroScalar::hash(&derivation));
    let mask = Zeroizing::new(
        MoneroScalar::hash(Zeroizing::new(
            [b"commitment_mask".as_slice(), &<[u8; 32]>::from(*shared)].concat(),
        ))
        .into(),
    );
    let amount_mask = Zeroizing::new(keccak256(Zeroizing::new(
        [b"amount".as_slice(), &<[u8; 32]>::from(*shared)].concat(),
    )));
    let encrypted =
        (amount ^ u64::from_le_bytes(amount_mask[..8].try_into().expect("8 bytes"))).to_le_bytes();
    let shared_scalar = Zeroizing::new((*shared).into());
    (
        Point::from(*shared_scalar * G + address.spend().into()).compress(),
        tag,
        mask,
        EncryptedAmount::Compact { amount: encrypted },
    )
}
