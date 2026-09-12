//! Versioned XMR catastrophic-recovery assurance terms.
//!
//! The canonical policy digest is committed in `assurance_policy_hash` of
//! both-party authenticated settlement terms. Opaque V1 metadata is never
//! interpreted as economic authority. Validation here is arithmetic and scope
//! validation only: it cannot prove that collateral was funded or that anyone
//! owns a transaction output. Those checks belong to native Store/chain gates.
//!
//! A finite volatility margin covers the price movement assumed by the two
//! participants; it is not an oracle or a guarantee against every future price.

use kaystra_core::{
    terms::SettlementTermsV1,
    types::{LockMechanism, TimelockSpec},
};
use sha2::{Digest, Sha256};

#[path = "recovery_availability_v23.rs"]
mod recovery_availability_v23;
pub use recovery_availability_v23::XmrRecoveryAvailabilityV23;

const MAGIC_V23: &[u8; 8] = b"DOMXCM23";
const DOMAIN_V23: &[u8] = b"DOM-INTEROP/XMR-DOM-COMPENSATION/POLICY/V23\0";
/// Exact V23 length: legacy economic fields plus four availability bounds.
pub const XMR_COMPENSATION_POLICY_BYTES_V23: usize = XMR_COMPENSATION_POLICY_BYTES_V11 + 4 * 8;

const MAGIC: &[u8; 8] = b"DOMXCM11";
const DOMAIN: &[u8] = b"DOM-INTEROP/XMR-DOM-COMPENSATION/POLICY/V11\0";
/// Exact canonical encoding size. No optional or trailing fields are accepted.
pub const XMR_COMPENSATION_POLICY_BYTES_V11: usize = 8 + 6 * 32 + 4 * 33 + 12 * 8 + 2 * 4;

/// Public policy signed indirectly by the exact settlement terms digest.
/// Monetary quantities use native integer units, never floats or spot RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmrCompensationPolicyV11 {
    /// The one-shot settlement.
    pub settlement_id: [u8; 32],
    /// The signing session.
    pub session_id: [u8; 32],
    /// DOM network identifier.
    pub dom_chain_id: [u8; 32],
    /// Monero network identifier.
    pub xmr_chain_id: [u8; 32],
    /// Owner of U, funding DOM and receiving XMR in the successful swap.
    pub dom_funder: [u8; 32],
    /// Owner of T, funding XMR and receiving DOM or catastrophe compensation.
    pub xmr_funder: [u8; 32],
    /// Negotiated success payout commitment owned by the XMR funder.
    pub claim_principal_commitment: [u8; 33],
    /// Negotiated success change commitment owned by the DOM funder.
    pub claim_change_commitment: [u8; 33],
    /// Negotiated ordinary DOM refund commitment owned by the DOM funder.
    pub refund_recipient_commitment: [u8; 33],
    /// Negotiated catastrophe payout commitment owned by the XMR funder.
    pub compensation_recipient_commitment: [u8; 33],
    /// Numerator of the frozen quote in DOM noms per XMR piconero.
    pub quote_dom_numerator: u64,
    /// Positive denominator; the rational must be reduced to a unique form.
    pub quote_xmr_denominator: u64,
    /// Exact principal deposited on Monero.
    pub xmr_principal_piconero: u64,
    /// Exact principal exchanged on DOM, equal to the rounded-up frozen quote.
    pub dom_principal_noms: u64,
    /// Positive margin paid to the XMR funder only on catastrophe compensation.
    pub volatility_margin_bps: u32,
    /// Required finality of the DOM collateral before authorizing XMR funding.
    pub collateral_confirmations: u32,
    /// Earliest cancel height Hc.
    pub cancel_height: u64,
    /// Earliest compensation height Hp, strictly after the refund window.
    pub compensation_height: u64,
    /// Minimum interval reserved for the ordinary revealing refund.
    pub cooperative_window_blocks: u64,
    /// Additional strict witness-revelation inclusion/reorg budget.
    pub reveal_safety_blocks: u64,
    /// Exact success-claim fee, paid from the DOM collateral.
    pub claim_fee_noms: u64,
    /// Exact cancel fee, paid from the DOM collateral.
    pub cancel_fee_noms: u64,
    /// Exact DOM adaptor-refund fee, paid from the DOM collateral.
    pub refund_fee_noms: u64,
    /// Exact catastrophe-compensation fee, paid from the DOM collateral.
    pub compensation_fee_noms: u64,
    /// Explicit acceptance of ordinary DOM compensation under bounded honest
    /// availability, even if the original XMR remains locked. None preserves
    /// legacy V11 bytes and grants no V23 admission. Some uses a new magic and
    /// hash domain; both participants must authenticate the new terms.
    pub bounded_availability_v23: Option<XmrRecoveryAvailabilityV23>,
}

/// Failure of an immutable policy or of its binding to signed terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XmrCompensationPolicyErrorV11 {
    /// Native graph, value proof or payout commitment differs from the policy.
    #[error("XMR compensation graph does not match its economic policy")]
    GraphMismatch,
    /// Wrong size, magic, or non-canonical rational encoding.
    #[error("noncanonical XMR compensation policy")]
    NonCanonical,
    /// A mandatory field is zero, invalid or overflows native monetary units.
    #[error("invalid XMR compensation policy bounds")]
    InvalidBounds,
    /// Policy digest, identities, amounts or roles differ from frozen terms.
    #[error("XMR compensation policy does not match settlement terms")]
    TermsMismatch,
    /// The cooperative window/finality/revelation budget is insufficient.
    #[error("XMR compensation policy leaves insufficient recovery time")]
    RecoveryWindow,
    /// Compensation does not cost more than the maximum admitted refund path.
    #[error("XMR compensation fee does not preserve refund priority")]
    RefundPriority,
}

type Result<T> = core::result::Result<T, XmrCompensationPolicyErrorV11>;

/// Economically validated public scope. This grants no custody or funding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedXmrCompensationPolicyV11 {
    policy: XmrCompensationPolicyV11,
    terms_hash: [u8; 32],
    margin_noms: u64,
    collateral_noms: u64,
}

impl ValidatedXmrCompensationPolicyV11 {
    /// Exact immutable policy.
    pub const fn policy(&self) -> &XmrCompensationPolicyV11 {
        &self.policy
    }
    /// Full settlement digest, including its assurance-policy commitment.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }
    /// Minimum required amount in the jointly controlled funding output C.
    pub const fn collateral_noms(&self) -> u64 {
        self.collateral_noms
    }
    /// Volatility margin included in the compensation payout.
    pub const fn margin_noms(&self) -> u64 {
        self.margin_noms
    }
    /// Amount in D after cancel.
    pub fn cancelled_noms(&self) -> u64 {
        self.collateral_noms - self.policy.cancel_fee_noms
    }
    /// Catastrophe payout: principal plus margin, after both native fees.
    pub fn compensation_payout_noms(&self) -> u64 {
        self.collateral_noms - self.policy.cancel_fee_noms - self.policy.compensation_fee_noms
    }
    /// DOM returned to the U owner on an ordinary revealing refund.
    pub fn refund_payout_noms(&self) -> u64 {
        self.collateral_noms - self.policy.cancel_fee_noms - self.policy.refund_fee_noms
    }
    /// Margin and unused recovery fees returned to the DOM funder on success.
    /// The other claim output must pay exactly `dom_principal_noms`.
    pub fn successful_change_noms(&self) -> u64 {
        self.collateral_noms - self.policy.dom_principal_noms - self.policy.claim_fee_noms
    }
}

impl XmrCompensationPolicyV11 {
    /// Canonical public encoding, suitable for an authenticated authority bundle.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(XMR_COMPENSATION_POLICY_BYTES_V23);
        out.extend_from_slice(if self.bounded_availability_v23.is_some() {
            MAGIC_V23
        } else {
            MAGIC
        });
        for identity in [
            self.settlement_id,
            self.session_id,
            self.dom_chain_id,
            self.xmr_chain_id,
            self.dom_funder,
            self.xmr_funder,
        ] {
            out.extend_from_slice(&identity);
        }
        for commitment in [
            self.claim_principal_commitment,
            self.claim_change_commitment,
            self.refund_recipient_commitment,
            self.compensation_recipient_commitment,
        ] {
            out.extend_from_slice(&commitment);
        }
        for value in [
            self.quote_dom_numerator,
            self.quote_xmr_denominator,
            self.xmr_principal_piconero,
            self.dom_principal_noms,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.volatility_margin_bps.to_be_bytes());
        out.extend_from_slice(&self.collateral_confirmations.to_be_bytes());
        for value in [
            self.cancel_height,
            self.compensation_height,
            self.cooperative_window_blocks,
            self.reveal_safety_blocks,
            self.claim_fee_noms,
            self.cancel_fee_noms,
            self.refund_fee_noms,
            self.compensation_fee_noms,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        if let Some(availability) = self.bounded_availability_v23 {
            for value in availability.values() {
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Strict decoder: malformed, truncated, extended or equivalent-rate
    /// encodings are rejected rather than normalized during authentication.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v23 = match (bytes.get(..8), bytes.len()) {
            (Some(magic), XMR_COMPENSATION_POLICY_BYTES_V11) if magic == MAGIC => false,
            (Some(magic), XMR_COMPENSATION_POLICY_BYTES_V23) if magic == MAGIC_V23 => true,
            _ => return Err(XmrCompensationPolicyErrorV11::NonCanonical),
        };
        let mut cursor = Cursor { bytes, position: 8 };
        let result = Self {
            settlement_id: cursor.array()?,
            session_id: cursor.array()?,
            dom_chain_id: cursor.array()?,
            xmr_chain_id: cursor.array()?,
            dom_funder: cursor.array()?,
            xmr_funder: cursor.array()?,
            claim_principal_commitment: cursor.array()?,
            claim_change_commitment: cursor.array()?,
            refund_recipient_commitment: cursor.array()?,
            compensation_recipient_commitment: cursor.array()?,
            quote_dom_numerator: cursor.u64()?,
            quote_xmr_denominator: cursor.u64()?,
            xmr_principal_piconero: cursor.u64()?,
            dom_principal_noms: cursor.u64()?,
            volatility_margin_bps: u32::from_be_bytes(cursor.array()?),
            collateral_confirmations: u32::from_be_bytes(cursor.array()?),
            cancel_height: cursor.u64()?,
            compensation_height: cursor.u64()?,
            cooperative_window_blocks: cursor.u64()?,
            reveal_safety_blocks: cursor.u64()?,
            claim_fee_noms: cursor.u64()?,
            cancel_fee_noms: cursor.u64()?,
            refund_fee_noms: cursor.u64()?,
            compensation_fee_noms: cursor.u64()?,
            bounded_availability_v23: if v23 {
                Some(XmrRecoveryAvailabilityV23 {
                    maximum_unavailability_blocks: cursor.u64()?,
                    observation_delay_blocks: cursor.u64()?,
                    cancel_inclusion_blocks: cursor.u64()?,
                    refund_inclusion_blocks: cursor.u64()?,
                })
            } else {
                None
            },
        };
        result.validate_shape()?;
        Ok(result)
    }

    /// Commit this digest in `SettlementTermsV1::assurance_policy_hash` before
    /// either participant signs the terms. No historical terms are upgraded.
    pub fn policy_hash(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(if self.bounded_availability_v23.is_some() {
            DOMAIN_V23
        } else {
            DOMAIN
        });
        hash.update(self.to_bytes()?);
        Ok(hash.finalize().into())
    }

    /// Bind the versioned assurance policy to already authenticated terms.
    /// Signature verification remains with the existing bilateral admission.
    pub fn validate_for(
        &self,
        terms: &SettlementTermsV1,
    ) -> Result<ValidatedXmrCompensationPolicyV11> {
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| XmrCompensationPolicyErrorV11::TermsMismatch)?;
        if terms.assurance_policy_hash != Some(self.policy_hash()?)
            || terms.settlement_id.0 != self.settlement_id
            || terms.session_id.0 != self.session_id
            || terms.dom_leg.chain_id.0 != self.dom_chain_id
            || terms.counterparty_leg.chain_id.0 != self.xmr_chain_id
            || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
            || terms.dom_leg.amount != u128::from(self.dom_principal_noms)
            || terms.counterparty_leg.amount != u128::from(self.xmr_principal_piconero)
            || terms.dom_leg.refund_to.0 != self.dom_funder
            || terms.dom_leg.beneficiary.0 != self.xmr_funder
            || terms.counterparty_leg.refund_to.0 != self.xmr_funder
            || terms.counterparty_leg.beneficiary.0 != self.dom_funder
            || !terms.roster.iter().any(|p| p.0 == self.dom_funder)
            || !terms.roster.iter().any(|p| p.0 == self.xmr_funder)
            || terms.dom_leg.deadline
                != (TimelockSpec::BlockHeight {
                    value: self.cancel_height,
                })
            || !terms.recovery.refund_before_funding
        {
            return Err(XmrCompensationPolicyErrorV11::TermsMismatch);
        }
        if let Some(availability) = self.bounded_availability_v23 {
            let (before_refund, after_revelation) = availability.required_reserves(
                terms.dom_leg.finality.min_confirmations,
                terms.dom_leg.finality.max_reorg_depth,
            )?;
            if self.cooperative_window_blocks < before_refund
                || self.reveal_safety_blocks < after_revelation
            {
                return Err(XmrCompensationPolicyErrorV11::RecoveryWindow);
            }
        }
        let finality_budget = u64::from(terms.dom_leg.finality.min_confirmations)
            + u64::from(terms.dom_leg.finality.max_reorg_depth);
        if self.reveal_safety_blocks < finality_budget
            || self.collateral_confirmations < terms.dom_leg.finality.min_confirmations
            || self.cooperative_window_blocks < finality_budget
        {
            return Err(XmrCompensationPolicyErrorV11::RecoveryWindow);
        }
        if [
            self.claim_fee_noms,
            self.cancel_fee_noms,
            self.refund_fee_noms,
            self.compensation_fee_noms,
        ]
        .iter()
        .any(|fee| u128::from(*fee) > terms.fee_limit.dom_max)
        {
            return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
        }
        // Compare the maximum cooperative fees in the same signed unit of
        // account. This does not read a manipulable run-time exchange rate.
        let xmr_fee = u64::try_from(terms.fee_limit.counterparty_max)
            .map_err(|_| XmrCompensationPolicyErrorV11::InvalidBounds)?;
        let refund_fee_bound = ceil_ratio(
            xmr_fee,
            self.quote_dom_numerator,
            self.quote_xmr_denominator,
        )?
        .checked_add(self.refund_fee_noms)
        .ok_or(XmrCompensationPolicyErrorV11::InvalidBounds)?;
        if self.compensation_fee_noms <= refund_fee_bound {
            return Err(XmrCompensationPolicyErrorV11::RefundPriority);
        }
        let margin_noms = ceil_ratio(
            self.dom_principal_noms,
            u64::from(self.volatility_margin_bps),
            10_000,
        )?;
        let compensation_fees = self
            .cancel_fee_noms
            .checked_add(self.compensation_fee_noms)
            .ok_or(XmrCompensationPolicyErrorV11::InvalidBounds)?;
        let collateral_noms = self
            .dom_principal_noms
            .checked_add(margin_noms)
            .and_then(|value| value.checked_add(compensation_fees))
            .ok_or(XmrCompensationPolicyErrorV11::InvalidBounds)?;
        if self.claim_fee_noms
            >= margin_noms
                .checked_add(compensation_fees)
                .ok_or(XmrCompensationPolicyErrorV11::InvalidBounds)?
        {
            return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
        }
        Ok(ValidatedXmrCompensationPolicyV11 {
            policy: *self,
            terms_hash,
            margin_noms,
            collateral_noms,
        })
    }

    fn validate_shape(&self) -> Result<()> {
        if let Some(availability) = self.bounded_availability_v23 {
            availability.validate_shape()?;
        }
        let payouts = [
            self.claim_principal_commitment,
            self.claim_change_commitment,
            self.refund_recipient_commitment,
            self.compensation_recipient_commitment,
        ];
        if payouts
            .iter()
            .enumerate()
            .any(|(index, point)| !matches!(point[0], 2 | 3) || payouts[..index].contains(point))
        {
            return Err(XmrCompensationPolicyErrorV11::NonCanonical);
        }
        if [
            self.settlement_id,
            self.session_id,
            self.dom_chain_id,
            self.xmr_chain_id,
            self.dom_funder,
            self.xmr_funder,
        ]
        .contains(&[0; 32])
            || self.dom_chain_id == self.xmr_chain_id
            || self.dom_funder == self.xmr_funder
            || self.quote_dom_numerator == 0
            || self.quote_xmr_denominator == 0
            || self.xmr_principal_piconero == 0
            || self.dom_principal_noms == 0
            || self.volatility_margin_bps == 0
            || self.collateral_confirmations == 0
            || self.cancel_height == 0
            || self.cooperative_window_blocks == 0
            || self.reveal_safety_blocks == 0
        {
            return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
        }
        if gcd(self.quote_dom_numerator, self.quote_xmr_denominator) != 1 {
            return Err(XmrCompensationPolicyErrorV11::NonCanonical);
        }
        if ceil_ratio(
            self.xmr_principal_piconero,
            self.quote_dom_numerator,
            self.quote_xmr_denominator,
        )? != self.dom_principal_noms
        {
            return Err(XmrCompensationPolicyErrorV11::TermsMismatch);
        }
        if self
            .cancel_height
            .checked_add(self.cooperative_window_blocks)
            .and_then(|height| height.checked_add(self.reveal_safety_blocks))
            .filter(|height| *height < self.compensation_height)
            .is_none()
        {
            return Err(XmrCompensationPolicyErrorV11::RecoveryWindow);
        }
        Ok(())
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn ceil_ratio(amount: u64, numerator: u64, denominator: u64) -> Result<u64> {
    if denominator == 0 {
        return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
    }
    let product = u128::from(amount) * u128::from(numerator);
    let denominator = u128::from(denominator);
    u64::try_from(product / denominator + u128::from(product % denominator != 0))
        .map_err(|_| XmrCompensationPolicyErrorV11::InvalidBounds)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Cursor<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(XmrCompensationPolicyErrorV11::NonCanonical)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(XmrCompensationPolicyErrorV11::NonCanonical)?;
        let mut result = [0; N];
        result.copy_from_slice(value);
        self.position = end;
        Ok(result)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kaystra_core::types::*;

    pub(crate) fn fixture() -> (XmrCompensationPolicyV11, SettlementTermsV1) {
        let point = |byte: u8| {
            let mut result = [byte; 33];
            result[0] = 2;
            result
        };
        let policy = XmrCompensationPolicyV11 {
            settlement_id: [1; 32],
            session_id: [2; 32],
            dom_chain_id: [3; 32],
            xmr_chain_id: [4; 32],
            dom_funder: [5; 32],
            xmr_funder: [6; 32],
            claim_principal_commitment: point(7),
            claim_change_commitment: point(8),
            refund_recipient_commitment: point(9),
            compensation_recipient_commitment: point(10),
            quote_dom_numerator: 3,
            quote_xmr_denominator: 2,
            xmr_principal_piconero: 101,
            dom_principal_noms: 152,
            volatility_margin_bps: 2500,
            collateral_confirmations: 6,
            cancel_height: 100,
            compensation_height: 121,
            cooperative_window_blocks: 10,
            reveal_safety_blocks: 10,
            claim_fee_noms: 2,
            cancel_fee_noms: 3,
            refund_fee_noms: 2,
            compensation_fee_noms: 8,
            bounded_availability_v23: None,
        };
        let dom_funder = ParticipantId(policy.dom_funder);
        let xmr_funder = ParticipantId(policy.xmr_funder);
        let finality = FinalityPolicyV1 {
            min_confirmations: 3,
            max_reorg_depth: 6,
        };
        let terms = SettlementTermsV1 {
            settlement_id: SettlementId(policy.settlement_id),
            session_id: SessionId(policy.session_id),
            intent_hash: IntentHash([11; 32]),
            solver_id: SolverId([12; 32]),
            roster: [dom_funder, xmr_funder],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId(policy.dom_chain_id),
                asset_id: AssetId([13; 32]),
                amount: u128::from(policy.dom_principal_noms),
                beneficiary: xmr_funder,
                refund_to: dom_funder,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 100 },
                finality,
                adapter_profile_hash: [14; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId(policy.xmr_chain_id),
                asset_id: AssetId([15; 32]),
                amount: 101,
                beneficiary: dom_funder,
                refund_to: xmr_funder,
                mechanism: LockMechanism::CrossCurveSharedSpend,
                deadline: TimelockSpec::TimestampSeconds {
                    value: 1_900_000_000,
                },
                finality,
                adapter_profile_hash: [16; 32],
            },
            adaptor_point_sec1: point(17),
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 3,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: Some(policy.policy_hash().expect("canonical policy")),
            policy_version: 1,
            metadata: vec![],
        };
        (policy, terms)
    }

    #[test]
    fn exact_quote_margin_fees_and_success_change_conserve_collateral() {
        let (policy, terms) = fixture();
        let admitted = policy.validate_for(&terms).expect("valid policy");
        assert_eq!(admitted.margin_noms(), 38);
        assert_eq!(admitted.collateral_noms(), 201);
        assert_eq!(admitted.compensation_payout_noms(), 190);
        assert_eq!(admitted.refund_payout_noms(), 196);
        assert_eq!(admitted.successful_change_noms(), 47);
        assert_eq!(152 + 47 + 2, admitted.collateral_noms());
        assert_eq!(190 + 3 + 8, admitted.collateral_noms());
        let bytes = policy.to_bytes().expect("encode");
        assert_eq!(bytes.len(), XMR_COMPENSATION_POLICY_BYTES_V11);
        assert_eq!(XmrCompensationPolicyV11::from_bytes(&bytes), Ok(policy));
        for length in 0..bytes.len() {
            assert!(XmrCompensationPolicyV11::from_bytes(&bytes[..length]).is_err());
        }
        let mut appended = bytes;
        appended.push(0);
        assert_eq!(
            XmrCompensationPolicyV11::from_bytes(&appended),
            Err(XmrCompensationPolicyErrorV11::NonCanonical)
        );
    }

    #[test]
    fn assurance_commitment_cannot_be_replaced_by_opaque_metadata_or_other_policy() {
        let (policy, mut terms) = fixture();
        terms.assurance_policy_hash = None;
        terms.metadata = policy.to_bytes().expect("encode");
        assert_eq!(
            policy.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::TermsMismatch)
        );
        let (mut policy, terms) = fixture();
        policy.volatility_margin_bps += 1;
        assert_eq!(
            policy.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::TermsMismatch)
        );
    }

    #[test]
    fn disappearance_cannot_bypass_refund_window_or_the_agreed_margin() {
        let (mut policy, mut terms) = fixture();
        policy.compensation_height = 120;
        assert_eq!(
            policy.to_bytes(),
            Err(XmrCompensationPolicyErrorV11::RecoveryWindow)
        );
        policy.compensation_height = 121;
        policy.volatility_margin_bps = 0;
        assert_eq!(
            policy.to_bytes(),
            Err(XmrCompensationPolicyErrorV11::InvalidBounds)
        );
        policy.volatility_margin_bps = 2500;
        policy.collateral_confirmations = 2;
        terms.assurance_policy_hash = Some(policy.policy_hash().expect("encode"));
        assert_eq!(
            policy.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::RecoveryWindow)
        );
    }

    #[test]
    fn catastrophe_fee_must_exceed_the_full_cooperative_refund_fee_bound() {
        let (mut policy, mut terms) = fixture();
        // ceil(3 piconero * 3/2) + 2 native refund fee = 7.
        policy.compensation_fee_noms = 7;
        terms.assurance_policy_hash = Some(policy.policy_hash().expect("encode"));
        assert_eq!(
            policy.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::RefundPriority)
        );
        policy.compensation_fee_noms = 8;
        terms.assurance_policy_hash = Some(policy.policy_hash().expect("encode"));
        assert!(policy.validate_for(&terms).is_ok());
        terms.recovery.refund_before_funding = false;
        assert_eq!(
            policy.validate_for(&terms),
            Err(XmrCompensationPolicyErrorV11::TermsMismatch)
        );
    }

    #[test]
    fn quote_and_margin_arithmetic_never_round_down_or_wrap() {
        assert_eq!(ceil_ratio(u64::MAX, 1, 1), Ok(u64::MAX));
        assert_eq!(ceil_ratio(u64::MAX, u64::MAX, u64::MAX), Ok(u64::MAX));
        assert_eq!(
            ceil_ratio(u64::MAX, u64::MAX, 1),
            Err(XmrCompensationPolicyErrorV11::InvalidBounds)
        );
        assert_eq!(ceil_ratio(1, 1, 10_000), Ok(1));
        let (mut policy, _) = fixture();
        policy.quote_dom_numerator *= 2;
        policy.quote_xmr_denominator *= 2;
        assert_eq!(
            policy.to_bytes(),
            Err(XmrCompensationPolicyErrorV11::NonCanonical)
        );
    }
}

#[cfg(test)]
#[path = "compensation_availability_v23_tests.rs"]
mod availability_tests;
