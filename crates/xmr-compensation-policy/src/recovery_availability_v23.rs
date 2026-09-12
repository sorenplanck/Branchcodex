//! Explicit bounded-availability assumptions for ordinary DOM compensation.
//! These are negotiated environmental bounds, not chain facts or permission
//! to sign/fund. XMR may remain locked after economic compensation in DOM.

use super::{Result, XmrCompensationPolicyErrorV11};

/// Availability envelope committed by the V23 assurance-policy encoding.
/// Every duration is measured in DOM blocks. Inclusion bounds assume the
/// exact negotiated transaction fees suffice; no oracle can guarantee them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmrRecoveryAvailabilityV23 {
    /// Total honest unavailability across the entire cancel/refund episode,
    /// including all crashes, restarts and local signing/storage delays.
    /// This is an aggregate allowance, not a fresh allowance per restart.
    pub maximum_unavailability_blocks: u64,
    /// Maximum online observation/dispatch delay at each of the two dependent
    /// boundaries: cancellation height and final cancelled-output observation.
    pub observation_delay_blocks: u64,
    /// Maximum inclusion delay of cancel at its negotiated exact fee.
    pub cancel_inclusion_blocks: u64,
    /// Maximum inclusion delay of refund at its negotiated exact fee.
    pub refund_inclusion_blocks: u64,
}

impl XmrRecoveryAvailabilityV23 {
    pub(super) fn values(self) -> [u64; 4] {
        [
            self.maximum_unavailability_blocks,
            self.observation_delay_blocks,
            self.cancel_inclusion_blocks,
            self.refund_inclusion_blocks,
        ]
    }

    pub(super) fn validate_shape(self) -> Result<()> {
        if self.values().contains(&0) {
            return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
        }
        Ok(())
    }

    /// Required pre-refund and post-revelation reserves respectively.
    /// Finality reserve is the signed minimum depth plus accepted reorg depth.
    /// Reserving the full depth (rather than depth minus one) is conservative.
    /// Checked arithmetic never turns an excessive requirement into a grant.
    pub fn required_reserves(
        self,
        minimum_confirmations: u32,
        maximum_reorg_depth: u32,
    ) -> Result<(u64, u64)> {
        self.validate_shape()?;
        if minimum_confirmations == 0 {
            return Err(XmrCompensationPolicyErrorV11::InvalidBounds);
        }
        let finality = u64::from(minimum_confirmations) + u64::from(maximum_reorg_depth);
        let before = self
            .observation_delay_blocks
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.maximum_unavailability_blocks))
            .and_then(|value| value.checked_add(self.cancel_inclusion_blocks))
            .and_then(|value| value.checked_add(finality))
            .ok_or(XmrCompensationPolicyErrorV11::RecoveryWindow)?;
        let after = self
            .refund_inclusion_blocks
            .checked_add(finality)
            .ok_or(XmrCompensationPolicyErrorV11::RecoveryWindow)?;
        Ok((before, after))
    }
}
