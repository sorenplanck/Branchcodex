//! Family-tagged F7 authorization inputs. Native snapshots retain complete IDs.
//!
//! This boundary validates the real DOM funding together with a concrete EVM,
//! Solana or XMR verifier. The resulting linear value is consumed by the native
//! Store's separate V12 journal; it can never be converted to a Bitcoin V2 token.

#[path = "xmr_bounded_v23.rs"]
mod xmr_bounded_v23;
pub use xmr_bounded_v23::{
    verify_f7_xmr_bounded_anchor_authorization_v23, DomXmrBoundedAnchorValidationRequestV23,
};

use super::{
    ExternalFundingEvidenceV11, F7ExternalFamilyV11, F7FamilyAuthorityErrorV11 as Error,
    F7FundingIdV11, VerifiedDomXmrAnchorEvidenceV11, VerifiedEvmFundingV11,
    VerifiedSolanaFundingV11,
};
use crate::verify_dom_funding_evidence_inner;
use dom_final_claim_binding::FinalClaimRoleBindingV1;
use dom_scriptless_chain_adapter::DomHttpChainAdapterV1;
use kaystra_core::types::{LockMechanism, TimelockSpec};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Concrete native funding verifiers accepted by the V12 Store profile.
/// XMR additionally requires its complete DOM collateral/recovery validation.
pub enum F7ExternalFundingV12 {
    /// Native condition-lock receipt, live state and finalized ancestry.
    Evm(VerifiedEvmFundingV11),
    /// Complete signature, immutable escrow and stable native quorum.
    Solana(VerifiedSolanaFundingV11),
}

/// Fresh complete family-tagged anchors for exactly one DOM-centered leg.
/// No raw constructor, deserialization, Clone or Copy exists.
pub struct VerifiedF7AnchorAuthorizationV12 {
    role: FinalClaimRoleBindingV1,
    family: F7ExternalFamilyV11,
    funding_id: F7FundingIdV11,
    dom_funding_txid: [u8; 32],
    dom_block_hash: [u8; 32],
    dom_height: u64,
    dom_tip_hash: [u8; 32],
    dom_tip_height: u64,
    graph_digest: Option<[u8; 32]>,
    xmr_setup_binding_hash: Option<[u8; 32]>,
    round_start_transcript_hash: [u8; 32],
    evidence_digest: [u8; 32],
    observed_at: Instant,
}
impl VerifiedF7AnchorAuthorizationV12 {
    /// Immutable operational role verified against both native chains.
    pub const fn role(&self) -> &FinalClaimRoleBindingV1 {
        &self.role
    }
    /// The actual external family; no synthetic BTC role is introduced.
    pub const fn family(&self) -> F7ExternalFamilyV11 {
        self.family
    }
    /// Complete external transaction ID, including all 64 Solana bytes.
    pub const fn funding_id(&self) -> F7FundingIdV11 {
        self.funding_id
    }
    /// Exact confirmed DOM funding transaction.
    pub const fn dom_funding_txid(&self) -> &[u8; 32] {
        &self.dom_funding_txid
    }
    /// Native block containing that exact DOM transaction.
    pub const fn dom_block_hash(&self) -> &[u8; 32] {
        &self.dom_block_hash
    }
    /// Native inclusion height.
    pub const fn dom_height(&self) -> u64 {
        self.dom_height
    }
    /// Canonical tip where the funded output remained unspent.
    pub const fn dom_tip_hash(&self) -> &[u8; 32] {
        &self.dom_tip_hash
    }
    /// Height of the complete canonical snapshot.
    pub const fn dom_tip_height(&self) -> u64 {
        self.dom_tip_height
    }
    /// XMR's exact recovery graph, absent for unrelated families.
    pub const fn graph_digest(&self) -> Option<[u8; 32]> {
        self.graph_digest
    }
    /// Complete native setup identity for XMR, absent for other families.
    pub const fn xmr_setup_binding_hash(&self) -> Option<[u8; 32]> {
        self.xmr_setup_binding_hash
    }
    /// Exact retained transcript preceding the intended claim round.
    pub const fn round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.round_start_transcript_hash
    }
    /// Commitment to both exact native snapshots and the full economic scope.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Require immediate consumption; a restart must query both chains again.
    pub fn require_recent(&self) -> Result<(), Error> {
        if self.observed_at.elapsed() > Duration::from_secs(60) {
            Err(Error::WindowClosed)
        } else {
            Ok(())
        }
    }
    /// Promote complete native DOM/XMR evidence without weakening its checks.
    pub fn from_dom_xmr(value: VerifiedDomXmrAnchorEvidenceV11) -> Result<Self, Error> {
        value.require_recent()?;
        Ok(Self {
            role: value.role().clone(),
            family: F7ExternalFamilyV11::Monero,
            funding_id: *value.xmr().funding_id(),
            dom_funding_txid: *value.dom_funding_txid(),
            dom_block_hash: *value.dom_funding_block_hash(),
            dom_height: value.dom_funding_height(),
            dom_tip_hash: *value.dom_tip_hash(),
            dom_tip_height: value.dom_tip_height(),
            graph_digest: Some(*value.graph_digest()),
            xmr_setup_binding_hash: Some(*value.xmr().setup_binding_hash()),
            round_start_transcript_hash: *value.claim_round_start_transcript_hash(),
            evidence_digest: *value.evidence_digest(),
            observed_at: Instant::now(),
        })
    }
}

/// Verify the selected live EVM/Solana funding with the actual DOM scanner.
/// Caller hashes cannot mint the external observation or its native finality.
pub fn verify_f7_anchor_authorization_v12(
    dom: &DomHttpChainAdapterV1,
    role: &FinalClaimRoleBindingV1,
    expected_dom_funding_txid: [u8; 32],
    round_start_transcript_hash: [u8; 32],
    external: F7ExternalFundingV12,
) -> Result<VerifiedF7AnchorAuthorizationV12, Error> {
    let facts: &ExternalFundingEvidenceV11 = match &external {
        F7ExternalFundingV12::Evm(value) => value.facts(),
        F7ExternalFundingV12::Solana(value) => value.facts(),
    };
    let terms = role.terms();
    let family_ok = matches!(
        (&external, terms.counterparty_leg.mechanism),
        (F7ExternalFundingV12::Evm(_), LockMechanism::ConditionLock)
            | (
                F7ExternalFundingV12::Solana(_),
                LockMechanism::CrossCurveConditionLock
            )
    );
    if !family_ok
        || expected_dom_funding_txid == [0; 32]
        || round_start_transcript_hash == [0; 32]
        || facts.settlement_id() != &terms.settlement_id.0
        || facts.terms_hash() != &terms.terms_hash().map_err(|_| Error::Binding)?
        || facts.chain_registry_id() != &terms.counterparty_leg.chain_id.0
        || facts.confirmations() < terms.counterparty_leg.finality.min_confirmations
        || facts.age() > Duration::from_secs(60)
    {
        return Err(Error::Binding);
    }
    let snapshot = verify_dom_funding_evidence_inner(
        dom,
        expected_dom_funding_txid,
        role.shared_output_commitment(),
        role.funding_template_hash(),
        terms.dom_leg.finality.min_confirmations,
        true,
    )
    .map_err(map_dom_v12)?;
    let deadline = match terms.dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => return Err(Error::Binding),
    };
    let safety = u64::from(terms.dom_leg.finality.min_confirmations)
        .checked_add(u64::from(terms.dom_leg.finality.max_reorg_depth))
        .ok_or(Error::Bounds)?;
    if snapshot.chain_id != terms.dom_leg.chain_id.0
        || snapshot
            .observed_tip_height
            .checked_add(safety)
            .ok_or(Error::Bounds)?
            >= deadline
        || facts.age() > Duration::from_secs(60)
    {
        return Err(Error::WindowClosed);
    }
    let mut digest = Sha256::new();
    digest.update(b"DOM-INTEROP/F7-FAMILY-AUTHORIZATION/V12\0");
    for hash in [
        role.digest().map_err(|_| Error::Binding)?,
        expected_dom_funding_txid,
        snapshot.block_hash,
        snapshot.observed_tip_hash,
        *facts.evidence_digest(),
        round_start_transcript_hash,
    ] {
        digest.update(hash);
    }
    digest.update(snapshot.height.to_be_bytes());
    digest.update(snapshot.observed_tip_height.to_be_bytes());
    Ok(VerifiedF7AnchorAuthorizationV12 {
        role: role.clone(),
        family: facts.family(),
        funding_id: *facts.funding_id(),
        dom_funding_txid: expected_dom_funding_txid,
        dom_block_hash: snapshot.block_hash,
        dom_height: snapshot.height,
        dom_tip_hash: snapshot.observed_tip_hash,
        dom_tip_height: snapshot.observed_tip_height,
        graph_digest: None,
        xmr_setup_binding_hash: None,
        round_start_transcript_hash,
        evidence_digest: digest.finalize().into(),
        observed_at: Instant::now(),
    })
}

fn map_dom_v12(error: crate::F7AnchorAuthorityError) -> Error {
    use crate::F7AnchorAuthorityError as DomError;
    match error {
        DomError::DomFundingAbsent => Error::FundingAbsent,
        DomError::Dom(dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable) => {
            Error::Unavailable
        }
        DomError::InsufficientFinality => Error::InsufficientFinality,
        DomError::BoundsExceeded => Error::Bounds,
        _ => Error::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_dom_absence_does_not_hide_substituted_or_invalid_funding() {
        use crate::F7AnchorAuthorityError as DomError;
        assert_eq!(
            map_dom_v12(DomError::DomFundingAbsent),
            Error::FundingAbsent
        );
        assert_eq!(
            map_dom_v12(DomError::InsufficientFinality),
            Error::InsufficientFinality
        );
        assert_eq!(
            map_dom_v12(DomError::DomFundingMismatch),
            Error::InvalidEvidence
        );
        assert_eq!(
            map_dom_v12(DomError::RouteBindingMismatch),
            Error::InvalidEvidence
        );
        assert_eq!(
            map_dom_v12(DomError::Dom(
                dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
            )),
            Error::Unavailable
        );
    }
}
