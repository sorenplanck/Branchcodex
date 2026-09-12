//! Bounded public wallet offers for the four policy-committed XMR payouts.
//! Decoding verifies construction evidence, not peer identity or funding permission.
use crate::compensation::{
    ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11 as Error,
};
use crate::economic_graph::{
    xmr_payout_value_statement_v12, XmrPayoutKindV12, XmrPayoutValueProofV11,
};
use dom_adaptor::{
    verify_share_knowledge_v1, DirectionV1, SharePoPStatementV1, ShareProofV1, TrustedChainIdV1,
    VerifiedSharedOutputV1,
};
use dom_consensus::TransactionOutput;
use dom_serialization::{DomDeserialize, DomSerialize};
use kaystra_core::SettlementTermsV1;

type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
#[path = "payout_offer_v22_tests.rs"]
mod tests;

/// Closed positions of wallet-owned outputs in the XMR graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrGraphPayoutKindV22 {
    /// Principal paid to the XMR funder on success.
    ClaimPrincipal = 1,
    /// Unused collateral returned to the DOM funder on success.
    ClaimChange = 2,
    /// Revealing refund paid to the DOM funder.
    Refund = 3,
    /// Conditional compensation paid to the XMR funder.
    Compensation = 4,
}
impl XmrGraphPayoutKindV22 {
    /// Recipient, commitment and exact policy amount, without private openings.
    pub fn policy_payout(
        self,
        policy: &ValidatedXmrCompensationPolicyV11,
    ) -> ([u8; 32], [u8; 33], u64) {
        let p = policy.policy();
        match self {
            Self::ClaimPrincipal => (
                p.xmr_funder,
                p.claim_principal_commitment,
                p.dom_principal_noms,
            ),
            Self::ClaimChange => (
                p.dom_funder,
                p.claim_change_commitment,
                policy.successful_change_noms(),
            ),
            Self::Refund => (
                p.dom_funder,
                p.refund_recipient_commitment,
                policy.refund_payout_noms(),
            ),
            Self::Compensation => (
                p.xmr_funder,
                p.compensation_recipient_commitment,
                policy.compensation_payout_noms(),
            ),
        }
    }
    /// Success outputs require separate value/ownership proofs. Recovery
    /// output values are also checked by the complete graph's native balance.
    pub const fn success_kind(self) -> Option<XmrPayoutKindV12> {
        match self {
            Self::ClaimPrincipal => Some(XmrPayoutKindV12::ClaimPrincipal),
            Self::ClaimChange => Some(XmrPayoutKindV12::ClaimChange),
            Self::Refund | Self::Compensation => None,
        }
    }
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::ClaimPrincipal),
            2 => Ok(Self::ClaimChange),
            3 => Ok(Self::Refund),
            4 => Ok(Self::Compensation),
            _ => Err(Error::NonCanonical),
        }
    }
}

/// Public range proof and, for success payouts, native value/ownership proof.
/// This carries no blinding, nonce secret, signing share or funding authority.
pub struct XmrPolicyPayoutOfferV22 {
    kind: XmrGraphPayoutKindV22,
    scope: [[u8; 32]; 4],
    value: u64,
    output: TransactionOutput,
    ownership: Option<XmrPayoutValueProofV11>,
}
impl XmrPolicyPayoutOfferV22 {
    /// Maximum public encoding, checked before decoding any variable payload.
    pub const MAX_BYTES: usize = 4096;

    /// Construct and verify public material under the exact authenticated
    /// terms, chain and participant direction supplied by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        kind: XmrGraphPayoutKindV22,
        output: TransactionOutput,
        ownership: Option<XmrPayoutValueProofV11>,
        chain: &TrustedChainIdV1,
        direction: DirectionV1,
    ) -> Result<Self> {
        let (recipient, _, value) = kind.policy_payout(policy);
        let offer = Self {
            kind,
            scope: [
                policy.policy().dom_chain_id,
                policy.policy().session_id,
                *policy.terms_hash(),
                recipient,
            ],
            value,
            output,
            ownership,
        };
        offer.verify(terms, policy, chain, direction)?;
        Ok(offer)
    }

    /// Revalidate the exact context and native public proofs. This is not a
    /// signature over an offer and does not authenticate a transport sender.
    pub fn verify(
        &self,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        chain: &TrustedChainIdV1,
        direction: DirectionV1,
    ) -> Result<()> {
        let validated = policy.policy().validate_for(terms)?;
        let (recipient, commitment, value) = self.kind.policy_payout(policy);
        if &validated != policy
            || chain.as_bytes() != &policy.policy().dom_chain_id
            || self.scope
                != [
                    policy.policy().dom_chain_id,
                    policy.policy().session_id,
                    *policy.terms_hash(),
                    recipient,
                ]
            || self.value != value
            || self.output.commitment.as_bytes() != &commitment
            || self
                .output
                .recovery_capsule()
                .map_err(|_| Error::GraphMismatch)?
                .is_some()
        {
            return Err(Error::GraphMismatch);
        }
        VerifiedSharedOutputV1::from_retained_output_v14(&self.output, &commitment)
            .map_err(|_| Error::GraphMismatch)?;
        match (self.kind.success_kind(), &self.ownership) {
            (Some(kind), Some(pop)) => {
                let expected = xmr_payout_value_statement_v12(
                    terms,
                    policy,
                    kind,
                    direction,
                    chain,
                    pop.statement.share_point(),
                )?;
                if pop.statement != expected
                    || !verify_share_knowledge_v1(&expected, &pop.proof)
                        .map_err(|_| Error::GraphMismatch)?
                {
                    return Err(Error::GraphMismatch);
                }
            }
            (None, None) => {}
            _ => return Err(Error::GraphMismatch),
        }
        Ok(())
    }

    /// Exact canonical public bytes. Retain these before any publication.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let output = self.output.to_bytes().map_err(|_| Error::NonCanonical)?;
        if output.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        let mut bytes = b"DXPO22\0\x01".to_vec();
        bytes.push(self.kind as u8);
        for field in self.scope {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&(output.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&output);
        if let Some(pop) = &self.ownership {
            bytes.extend_from_slice(&pop.statement.to_bytes());
            bytes.extend_from_slice(&pop.proof.to_bytes());
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        Ok(bytes)
    }

    /// Decode with a bounded cursor and verify against authenticated scope.
    /// Full roster context comes from terms, never from untrusted packet bytes.
    pub fn from_bytes(
        bytes: &[u8],
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        chain: &TrustedChainIdV1,
        direction: DirectionV1,
    ) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::NonCanonical);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(8)? != b"DXPO22\0\x01" {
            return Err(Error::NonCanonical);
        }
        let kind = XmrGraphPayoutKindV22::from_tag(reader.take(1)?[0])?;
        let scope = [
            reader.array()?,
            reader.array()?,
            reader.array()?,
            reader.array()?,
        ];
        let value = u64::from_le_bytes(reader.array()?);
        let size = usize::try_from(u32::from_le_bytes(reader.array()?))
            .map_err(|_| Error::NonCanonical)?;
        let output_bytes = reader.take(size)?;
        let output =
            TransactionOutput::from_bytes(output_bytes).map_err(|_| Error::NonCanonical)?;
        if output.to_bytes().map_err(|_| Error::NonCanonical)? != output_bytes {
            return Err(Error::NonCanonical);
        }
        let ownership = if kind.success_kind().is_some() {
            Some(XmrPayoutValueProofV11 {
                statement: SharePoPStatementV1::from_bytes(
                    reader.take(SharePoPStatementV1::ENCODED_LEN)?,
                    chain,
                    &terms.roster.map(|p| p.0),
                )
                .map_err(|_| Error::GraphMismatch)?,
                proof: ShareProofV1::from_bytes(reader.take(ShareProofV1::ENCODED_LEN)?)
                    .map_err(|_| Error::GraphMismatch)?,
            })
        } else {
            None
        };
        if reader.position != bytes.len() {
            return Err(Error::NonCanonical);
        }
        let offer = Self {
            kind,
            scope,
            value,
            output,
            ownership,
        };
        offer.verify(terms, policy, chain, direction)?;
        if offer.to_bytes()? != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(offer)
    }

    /// Policy output position.
    pub const fn kind(&self) -> XmrGraphPayoutKindV22 {
        self.kind
    }
    /// Native output and range proof, without private opening.
    pub const fn output(&self) -> &TransactionOutput {
        &self.output
    }
    /// Optional success value/ownership evidence.
    pub const fn ownership(&self) -> Option<&XmrPayoutValueProofV11> {
        self.ownership.as_ref()
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
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
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::NonCanonical)
    }
}
