//! Family-specific concrete funding authentication without synthetic Bitcoin facts.
//!
//! These observations are prerequisites, not signing authority. Public RPC
//! responses and caller-defined verifier implementations cannot construct them.
//! The only productive constructors perform the real, exact family checks.

mod authorization_v12;
mod dom_xmr;
mod evm;
mod solana;
mod xmr;
pub use authorization_v12::*;

pub use dom_xmr::{
    verify_dom_xmr_anchor_evidence_v11, DomXmrAnchorValidationRequestV11,
    VerifiedDomXmrAnchorEvidenceV11, MAX_V11_EXTERNAL_ANCHOR_AGE,
};
pub use evm::*;
pub use solana::*;
pub use xmr::{verify_xmr_funding_v11, VerifiedXmrFundingV11, XmrFundingObservationRequestV11};

use std::time::Instant;

/// External family selected by a concrete funding verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum F7ExternalFamilyV11 {
    /// ConditionLock on an EVM chain.
    Evm = 1,
    /// Native Bitcoin funding; the historical M.8 authority remains separate.
    Bitcoin = 2,
    /// Native SOL or supported legacy SPL escrow.
    Solana = 3,
    /// Shared-spend Monero output verified with its view key.
    Monero = 4,
}

/// Exact native transaction identity. Solana signatures are never truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum F7FundingIdV11 {
    /// Native 32-byte transaction hash.
    Hash32([u8; 32]),
    /// Complete 64-byte Solana transaction signature.
    SolanaSignature([u8; 64]),
}

/// Closed family observation failures. Legitimate absence has its own result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum F7FamilyAuthorityErrorV11 {
    /// Immutable terms, setup, role, network or exact transaction disagree.
    #[error("F7 family binding mismatch")]
    Binding,
    /// A configured service or required local custody record is unavailable.
    #[error("F7 family observation unavailable")]
    Unavailable,
    /// Successful response contains an invalid or substituted identity or fact.
    #[error("F7 family evidence rejected")]
    InvalidEvidence,
    /// The exact transaction is legitimately unknown or not yet in a block.
    #[error("F7 exact funding transaction is not yet included")]
    FundingAbsent,
    /// The exact funding location has insufficient canonical confirmation depth.
    #[error("F7 family funding is not final")]
    InsufficientFinality,
    /// Observation is stale or the authenticated reveal interval has closed.
    #[error("F7 family reveal window closed")]
    WindowClosed,
    /// A configured limit or checked arithmetic boundary was exceeded.
    #[error("F7 family observation bound exceeded")]
    Bounds,
}

/// Read-only facts authenticated by a concrete native funding verifier.
/// No public constructor, codec or Clone; this is not signing authority.
pub struct ExternalFundingEvidenceV11 {
    pub(super) family: F7ExternalFamilyV11,
    pub(super) settlement_id: [u8; 32],
    pub(super) terms_hash: [u8; 32],
    pub(super) chain_registry_id: [u8; 32],
    pub(super) funding_id: F7FundingIdV11,
    pub(super) block_hash: [u8; 32],
    pub(super) position: u64,
    pub(super) observed_tip_hash: [u8; 32],
    pub(super) observed_tip_position: u64,
    pub(super) confirmations: u32,
    pub(super) evidence_digest: [u8; 32],
    pub(super) observed_at: Instant,
}

impl ExternalFundingEvidenceV11 {
    /// The concrete verifier's external chain family.
    pub const fn family(&self) -> F7ExternalFamilyV11 {
        self.family
    }
    /// Exact one-shot settlement identifier.
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }
    /// Digest of the full immutable settlement terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }
    /// Chain identifier bound by the authenticated registry.
    pub const fn chain_registry_id(&self) -> &[u8; 32] {
        &self.chain_registry_id
    }
    /// Exact native transaction identifier without truncation or relabelling.
    pub const fn funding_id(&self) -> &F7FundingIdV11 {
        &self.funding_id
    }
    /// Canonical native block containing the funding transaction.
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }
    /// Native height or slot of the funding transaction.
    pub const fn position(&self) -> u64 {
        self.position
    }
    /// Canonical snapshot tip hash used for the confirmation calculation.
    pub const fn observed_tip_hash(&self) -> &[u8; 32] {
        &self.observed_tip_hash
    }
    /// Canonical snapshot tip height or slot.
    pub const fn observed_tip_position(&self) -> u64 {
        self.observed_tip_position
    }
    /// Confirmations counted from the native canonical snapshot.
    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }
    /// Commitment to immutable scope and exact native evidence.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Process-local age; never a substitute for canonical chain revalidation.
    pub fn age(&self) -> std::time::Duration {
        self.observed_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    assert_not_impl_any!(ExternalFundingEvidenceV11: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(VerifiedEvmFundingV11: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(VerifiedSolanaFundingV11: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(VerifiedXmrFundingV11: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(VerifiedDomXmrAnchorEvidenceV11: Clone, Copy, core::fmt::Debug);
}
