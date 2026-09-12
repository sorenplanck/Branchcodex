//! Public funding inputs and change, without wallet openings or spend authority.
use crate::compensation::{
    ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11 as Error,
};
use dom_adaptor::VerifiedSharedOutputV1;
use dom_consensus::{TransactionInput, TransactionOutput};
use dom_crypto::pedersen::Commitment;
use dom_serialization::{DomDeserialize, DomSerialize};
use kaystra_core::SettlementTermsV1;

#[cfg(test)]
#[path = "funding_offer_v22_tests.rs"]
mod tests;

/// Canonical public funding contribution from one authenticated participant.
/// Shape and range proofs are checked here; input ownership, chain presence
/// and full economic balance remain obligations of the wallet/graph/gate.
pub struct XmrFundingOfferV22 {
    scope: [[u8; 32]; 4],
    inputs: Vec<TransactionInput>,
    change: Option<TransactionOutput>,
    fee: u64,
}

impl XmrFundingOfferV22 {
    /// Bound checked before parsing any variable-sized field.
    pub const MAX_BYTES: usize = 16_384;

    /// Validate construction material under the exact frozen economic policy.
    pub fn new(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        participant: [u8; 32],
        inputs: Vec<TransactionInput>,
        change: Option<TransactionOutput>,
        fee: u64,
    ) -> Result<Self, Error> {
        let offer = Self {
            scope: [
                policy.policy().dom_chain_id,
                policy.policy().session_id,
                *policy.terms_hash(),
                participant,
            ],
            inputs,
            change,
            fee,
        };
        offer.verify(terms, policy, participant)?;
        offer.to_bytes()?;
        Ok(offer)
    }

    /// Revalidate against the transport-authenticated participant, not merely
    /// an identity asserted by the packet. This is not a signature or gate.
    pub fn verify(
        &self,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        participant: [u8; 32],
    ) -> Result<(), Error> {
        if &policy.policy().validate_for(terms)? != policy
            || !terms.roster.iter().any(|p| p.0 == participant)
            || self.scope
                != [
                    policy.policy().dom_chain_id,
                    policy.policy().session_id,
                    *policy.terms_hash(),
                    participant,
                ]
            || self.inputs.len() > dom_core::MAX_INPUTS_PER_TX
            || self
                .inputs
                .windows(2)
                .any(|w| w[0].commitment.as_bytes() >= w[1].commitment.as_bytes())
        {
            return Err(Error::GraphMismatch);
        }
        if participant == policy.policy().dom_funder {
            if self.inputs.is_empty()
                || self.fee == 0
                || u128::from(self.fee) > terms.fee_limit.dom_max
            {
                return Err(Error::GraphMismatch);
            }
        } else if !self.inputs.is_empty() || self.change.is_some() || self.fee != 0 {
            return Err(Error::GraphMismatch);
        }
        if let Some(change) = &self.change {
            if change
                .recovery_capsule()
                .map_err(|_| Error::GraphMismatch)?
                .is_some()
                || self
                    .inputs
                    .iter()
                    .any(|input| input.commitment == change.commitment)
            {
                return Err(Error::GraphMismatch);
            }
            VerifiedSharedOutputV1::from_retained_output_v14(change, change.commitment.as_bytes())
                .map_err(|_| Error::GraphMismatch)?;
        }
        Ok(())
    }

    /// Canonical bytes retained before publication, with no input values.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"DXFO22\0\x01".to_vec();
        for field in self.scope {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        let count = u16::try_from(self.inputs.len()).map_err(|_| Error::NonCanonical)?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for input in &self.inputs {
            bytes.extend_from_slice(input.commitment.as_bytes());
        }
        let output = self
            .change
            .as_ref()
            .map(DomSerialize::to_bytes)
            .transpose()
            .map_err(|_| Error::NonCanonical)?
            .unwrap_or_default();
        if output.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        bytes.extend_from_slice(&(output.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&output);
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        Ok(bytes)
    }

    /// Bounded decode followed by exact policy, participant and proof checks.
    pub fn from_bytes(
        bytes: &[u8],
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        participant: [u8; 32],
    ) -> Result<Self, Error> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(8)? != b"DXFO22\0\x01" {
            return Err(Error::NonCanonical);
        }
        let scope = [
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
        ];
        let fee = u64::from_le_bytes(reader.array()?);
        let count = usize::from(u16::from_le_bytes(reader.array()?));
        if count > dom_core::MAX_INPUTS_PER_TX {
            return Err(Error::NonCanonical);
        }
        let packed = reader.take(count.checked_mul(33).ok_or(Error::NonCanonical)?)?;
        let mut inputs = Vec::with_capacity(count);
        for bytes in packed.chunks_exact(33) {
            inputs.push(TransactionInput {
                commitment: Commitment::from_compressed_bytes(bytes)
                    .map_err(|_| Error::NonCanonical)?,
            });
        }
        let size = usize::try_from(u32::from_le_bytes(reader.array()?))
            .map_err(|_| Error::NonCanonical)?;
        let output = reader.take(size)?;
        let change = if output.is_empty() {
            None
        } else {
            let output = TransactionOutput::from_bytes(output).map_err(|_| Error::NonCanonical)?;
            Some(output)
        };
        if reader.position != bytes.len() {
            return Err(Error::NonCanonical);
        }
        let offer = Self {
            scope,
            inputs,
            change,
            fee,
        };
        offer.verify(terms, policy, participant)?;
        if offer.to_bytes()? != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(offer)
    }

    /// Public reserved input commitments, in canonical order.
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs
    }
    /// Wallet change with native range proof, if present.
    pub const fn change(&self) -> Option<&TransactionOutput> {
        self.change.as_ref()
    }
    /// Public funding fee, zero for the non-funder.
    pub const fn fee(&self) -> u64 {
        self.fee
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::NonCanonical)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::NonCanonical)?;
        self.position = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::NonCanonical)
    }
}
