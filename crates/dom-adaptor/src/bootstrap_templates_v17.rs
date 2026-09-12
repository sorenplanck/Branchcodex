//! Unsigned bootstrap transactions with an explicit, signed fee-reserve policy.
//!
//! Public construction data never authorizes a signature or broadcast. The
//! resulting templates still enter the native Contracts transport and gates.

use crate::{
    aggregate_public_nonces_v1, aggregate_transaction_offset_contributions_v1, AdaptorError,
    BpStatementV1, Result, ScriptlessTransactionTemplateV1, VerifiedSharedOutputV1,
};
use dom_consensus::{TransactionInput, TransactionKernel, TransactionOutput};
use dom_core::{
    fee_policy::{fee_breakdown, TransactionShape},
    Amount, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN, MAX_INPUTS_PER_TX,
};
use dom_crypto::{pedersen::Commitment, PublicKey, MAX_PROVABLE_VALUE};
use dom_serialization::{DomDeserialize, DomSerialize};

/// Signed terms policy for principal-preserving native bootstrap transactions.
/// Legacy signed terms retain their original interpretation.
pub const DOM_NATIVE_BOOTSTRAP_POLICY_V17: u32 = 17;

/// A funding fee plus exactly one mutually exclusive claim/refund fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomBootstrapBudgetV17 {
    principal: u64,
    shared_value: u64,
    exit_fee: u64,
    funding_fee_ceiling: u64,
}

impl DomBootstrapBudgetV17 {
    /// Reserve the native recommended one-input, one-output exit fee inside
    /// the shared output. `fee_ceiling` covers funding and either exit, never
    /// both mutually exclusive exits. All arithmetic is checked.
    pub fn new(principal: u128, fee_ceiling: u128) -> Result<Self> {
        let principal = u64::try_from(principal)
            .map_err(|_| AdaptorError::InvalidContext("bootstrap principal overflow"))?;
        let fee_ceiling = u64::try_from(fee_ceiling)
            .map_err(|_| AdaptorError::InvalidContext("bootstrap fee ceiling overflow"))?;
        let exit_fee = fee_breakdown(TransactionShape::from_counts(1, 1, 1)?)?.recommended_fee_noms;
        let shared_value = principal
            .checked_add(exit_fee)
            .ok_or(AdaptorError::InvalidContext(
                "bootstrap shared value overflow",
            ))?;
        let funding_fee_ceiling =
            fee_ceiling
                .checked_sub(exit_fee)
                .ok_or(AdaptorError::InvalidContext(
                    "fee ceiling cannot cover recovery",
                ))?;
        if principal == 0 || shared_value > MAX_PROVABLE_VALUE || funding_fee_ceiling < exit_fee {
            return Err(AdaptorError::InvalidContext(
                "bootstrap principal or fee budget",
            ));
        }
        Ok(Self {
            principal,
            shared_value,
            exit_fee,
            funding_fee_ceiling,
        })
    }
    /// Exact value delivered to the claim or refund recipient.
    pub const fn principal(&self) -> u64 {
        self.principal
    }
    /// Principal plus one reserved exit fee, locked by the collaborative BP.
    pub const fn shared_value(&self) -> u64 {
        self.shared_value
    }
    /// Fee consumed by either claim or refund.
    pub const fn exit_fee(&self) -> u64 {
        self.exit_fee
    }
    /// Remaining signed fee allowance for the funding transaction.
    pub const fn funding_fee_ceiling(&self) -> u64 {
        self.funding_fee_ceiling
    }
}

/// One participant's public wallet contribution. This type contains no
/// blinding, signing share, nonce secret, or authority to release a signature.
#[derive(Clone, Debug)]
pub struct DomBootstrapOfferV17 {
    /// Authenticated DOM chain identifier.
    pub chain_id: [u8; 32],
    /// Native Contracts session identifier.
    pub session_id: [u8; 32],
    /// Exact signed settlement-terms hash.
    pub terms_hash: [u8; 32],
    /// Identity in the sorted two-participant roster.
    pub participant_id: [u8; 32],
    /// Local recipient output: refund for the funder, claim for the other party.
    pub payout: TransactionOutput,
    /// Only the DOM funder contributes transaction inputs.
    pub funding_inputs: Vec<TransactionInput>,
    /// Optional change returned to that same funder's wallet.
    pub funding_change: Option<TransactionOutput>,
    /// Funding fee; zero for the participant who supplies no inputs.
    pub funding_fee: u64,
    /// Public signing keys ordered as funding, claim, refund.
    pub signing_keys: [PublicKey; 3],
    /// Purpose-separated offset contributions in the same order.
    pub offsets: [[u8; 32]; 3],
}

impl DomBootstrapOfferV17 {
    /// Maximum canonical public offer size; checked before parsing any vector.
    pub const MAX_BYTES: usize = 16_384;

    /// Canonical bounded public bytes suitable for an authenticated envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut out = b"DWO17\0\0\x01".to_vec();
        for value in [
            self.chain_id,
            self.session_id,
            self.terms_hash,
            self.participant_id,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.funding_fee.to_le_bytes());
        for key in &self.signing_keys {
            out.extend_from_slice(&key.to_compressed_bytes());
        }
        for offset in &self.offsets {
            out.extend_from_slice(offset);
        }
        put_output(&mut out, &self.payout)?;
        out.extend_from_slice(&(self.funding_inputs.len() as u16).to_le_bytes());
        for input in &self.funding_inputs {
            out.extend_from_slice(input.commitment.as_bytes());
        }
        out.push(u8::from(self.funding_change.is_some()));
        if let Some(change) = &self.funding_change {
            put_output(&mut out, change)?;
        }
        if out.len() > Self::MAX_BYTES {
            return Err(invalid_offer());
        }
        Ok(out)
    }

    /// Decode exact canonical bytes. Successful decoding is not peer identity
    /// authentication; the caller must verify the enclosing signed transport.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(invalid_offer());
        }
        let mut reader = OfferReader { bytes, position: 0 };
        if reader.take(8)? != b"DWO17\0\0\x01" {
            return Err(invalid_offer());
        }
        let chain_id = reader.array()?;
        let session_id = reader.array()?;
        let terms_hash = reader.array()?;
        let participant_id = reader.array()?;
        let funding_fee = u64::from_le_bytes(reader.array()?);
        let signing_keys = [reader.key()?, reader.key()?, reader.key()?];
        let offsets = [reader.array()?, reader.array()?, reader.array()?];
        let payout = reader.output()?;
        let count = usize::from(u16::from_le_bytes(reader.array()?));
        if count > MAX_INPUTS_PER_TX || count.checked_mul(33).is_none_or(|n| n > reader.remaining())
        {
            return Err(invalid_offer());
        }
        let mut funding_inputs = Vec::with_capacity(count);
        for _ in 0..count {
            funding_inputs.push(TransactionInput {
                commitment: Commitment::from_compressed_bytes(reader.take(33)?)?,
            });
        }
        let funding_change = match reader.take(1)?[0] {
            0 => None,
            1 => Some(reader.output()?),
            _ => return Err(invalid_offer()),
        };
        if reader.remaining() != 0 {
            return Err(invalid_offer());
        }
        let offer = Self {
            chain_id,
            session_id,
            terms_hash,
            participant_id,
            payout,
            funding_inputs,
            funding_change,
            funding_fee,
            signing_keys,
            offsets,
        };
        if offer.to_bytes()? != bytes {
            return Err(invalid_offer());
        }
        Ok(offer)
    }

    fn validate_shape(&self) -> Result<()> {
        if [
            self.chain_id,
            self.session_id,
            self.terms_hash,
            self.participant_id,
        ]
        .contains(&[0; 32])
            || self.funding_inputs.len() > MAX_INPUTS_PER_TX
            || self
                .funding_inputs
                .windows(2)
                .any(|pair| pair[0].commitment.as_bytes() >= pair[1].commitment.as_bytes())
            || (self.funding_inputs.is_empty()
                && (self.funding_fee != 0 || self.funding_change.is_some()))
            || (!self.funding_inputs.is_empty() && self.funding_fee == 0)
        {
            return Err(invalid_offer());
        }
        for offset in &self.offsets {
            aggregate_transaction_offset_contributions_v1(&[*offset])?;
        }
        verify_output(&self.payout)?;
        if let Some(change) = &self.funding_change {
            verify_output(change)?;
        }
        Ok(())
    }
}

/// All three balanced, proof-verified, unsigned native transaction templates.
/// The normal refund-before-funding and post-anchor claim authorities remain
/// mandatory when signatures are requested from these templates.
#[derive(Debug)]
pub struct DomBootstrapTemplatesV17 {
    /// Creates the shared output and returns actual funding change.
    pub funding: ScriptlessTransactionTemplateV1,
    /// Pays the full principal and consumes its reserved exit fee.
    pub claim: ScriptlessTransactionTemplateV1,
    /// Pays the full principal after the agreed absolute DOM height.
    pub refund: ScriptlessTransactionTemplateV1,
}

impl DomBootstrapTemplatesV17 {
    /// Assemble from both authenticated participant offers in roster order.
    /// `dom_funder` is taken from `refund_to` in the signed terms by the caller.
    /// The collaborative statement, all offer scopes, fee totals, proofs,
    /// offsets and balance equations are checked before returning anything.
    pub fn assemble(
        budget: DomBootstrapBudgetV17,
        statement: &BpStatementV1,
        shared: &VerifiedSharedOutputV1,
        terms_hash: [u8; 32],
        offers: &[DomBootstrapOfferV17; 2],
        dom_funder: usize,
        refund_height: u64,
        funding_tip: u64,
    ) -> Result<Self> {
        if dom_funder > 1
            || statement.participant_ids().len() != 2
            || terms_hash == [0; 32]
            || statement.value_noms() != budget.shared_value
            || shared.commitment() != &statement.aggregate_commitment().to_compressed_bytes()
            || refund_height <= funding_tip
        {
            return Err(invalid_offer());
        }
        for (i, offer) in offers.iter().enumerate() {
            offer.validate_shape()?;
            if offer.chain_id != statement.chain_id()
                || offer.session_id != statement.session_id()
                || offer.terms_hash != terms_hash
                || offer.participant_id != statement.participant_ids()[i]
            {
                return Err(invalid_offer());
            }
        }
        let funder = &offers[dom_funder];
        let receiver = &offers[1 - dom_funder];
        let shape = TransactionShape::from_counts(
            funder.funding_inputs.len(),
            1 + usize::from(funder.funding_change.is_some()),
            1,
        )?;
        if funder.funding_inputs.is_empty()
            || !receiver.funding_inputs.is_empty()
            || receiver.funding_fee != 0
            || receiver.funding_change.is_some()
            || funder.funding_fee > budget.funding_fee_ceiling
            || funder.funding_fee < fee_breakdown(shape)?.recommended_fee_noms
        {
            return Err(invalid_offer());
        }
        let kernel = |index: usize, fee: u64, lock_height: u64| -> Result<TransactionKernel> {
            let excess = aggregate_public_nonces_v1(&[
                offers[0].signing_keys[index].clone(),
                offers[1].signing_keys[index].clone(),
            ])?;
            Ok(TransactionKernel {
                features: if lock_height == 0 {
                    KERNEL_FEAT_PLAIN
                } else {
                    KERNEL_FEAT_HEIGHT_LOCKED
                },
                fee: Amount::from_noms(fee)?,
                lock_height,
                excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes())?,
                excess_signature: [0; 65],
            })
        };
        let offset = |i: usize| {
            aggregate_transaction_offset_contributions_v1(&[
                offers[0].offsets[i],
                offers[1].offsets[i],
            ])
        };
        let changes: Vec<_> = funder.funding_change.iter().cloned().collect();
        // Canonical transaction constructors validate structure, proofs and
        // the complete balance equation; summing public keys is insufficient.
        let funding = ScriptlessTransactionTemplateV1::funding(
            shared,
            funder.funding_inputs.clone(),
            changes,
            0,
            kernel(0, funder.funding_fee, 0)?,
            offset(0)?,
        )?;
        let claim = ScriptlessTransactionTemplateV1::claim(
            shared,
            vec![receiver.payout.clone()],
            kernel(1, budget.exit_fee, 0)?,
            offset(1)?,
        )?;
        let refund = ScriptlessTransactionTemplateV1::refund(
            shared,
            vec![funder.payout.clone()],
            kernel(2, budget.exit_fee, refund_height)?,
            offset(2)?,
            funding_tip,
        )?;
        Ok(Self {
            funding,
            claim,
            refund,
        })
    }
}

fn invalid_offer() -> AdaptorError {
    AdaptorError::InvalidContext("bootstrap wallet offer binding or shape")
}
fn verify_output(output: &TransactionOutput) -> Result<()> {
    VerifiedSharedOutputV1::from_retained_output_v14(output, output.commitment.as_bytes())?;
    Ok(())
}
fn put_output(out: &mut Vec<u8>, output: &TransactionOutput) -> Result<()> {
    let bytes = output.to_bytes()?;
    let len = u16::try_from(bytes.len()).map_err(|_| invalid_offer())?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}
struct OfferReader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> OfferReader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(size).ok_or_else(invalid_offer)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(invalid_offer)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| invalid_offer())
    }
    fn key(&mut self) -> Result<PublicKey> {
        Ok(PublicKey::from_compressed_bytes(self.take(33)?)?)
    }
    fn output(&mut self) -> Result<TransactionOutput> {
        let size = usize::from(u16::from_le_bytes(self.array()?));
        let bytes = self.take(size)?;
        let output = TransactionOutput::from_bytes(bytes)?;
        if output.to_bytes()? != bytes {
            return Err(invalid_offer());
        }
        Ok(output)
    }
}
