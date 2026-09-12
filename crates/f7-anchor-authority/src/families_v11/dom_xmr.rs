//! Native DOM/XMR post-funding evidence with an explicit compensation policy.
//!
//! This is deliberately a separate V11 boundary. It cannot be converted into
//! Bitcoin V2 authority, does not mint Bitcoin nonce permissions, and does not
//! claim that confidential collateral or public recovery bytes alone authorize
//! signing. A same-Store consumer must additionally authenticate both readiness
//! signatures, ordinary cancel/punish round provenance and payout ownership.

use super::{
    verify_xmr_funding_v11, F7FamilyAuthorityErrorV11 as Error, VerifiedXmrFundingV11,
    XmrFundingObservationRequestV11,
};
use crate::{
    verify_dom_funding_evidence_inner, F7AnchorAuthorityError, VerifiedDomFundingEvidenceV1,
};
use dom_final_claim_binding::{FinalClaimRoleBindingV1, OperationalM8ReadyBindingV2};
use dom_scriptless_chain_adapter::DomHttpChainAdapterV1;
use dom_scriptless_crypto::{FrozenSharedOutputV1, VerifiedXmrRecoveryGraphV11};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use xmr_dleq_sigma::{verify_bound, BoundCrossCurveProofV1, ROLE_XMR_REFUND_SHARE};
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;
use xmr_secret_store::EncryptedSqliteSecretStore;

/// Maximum age of the external snapshot at completion of the DOM scan.
/// A Store must still revalidate the live claim window immediately before use.
pub const MAX_V11_EXTERNAL_ANCHOR_AGE: Duration = Duration::from_secs(60);

/// Exact V11 DOM/XMR evidence request. The native graph and output formation
/// are closed verified types; config amounts cannot substitute for either.
pub struct DomXmrAnchorValidationRequestV11<'a> {
    /// Operational role binding decoded under the real native chain authority.
    pub role: &'a FinalClaimRoleBindingV1,
    /// Complete canonical readiness object. Its signatures remain Store-owned.
    /// In the V11 gate its policy field binds the assurance policy below; a
    /// historical V2 Bitcoin gate never accepts this policy substitution.
    pub ready: &'a OperationalM8ReadyBindingV2,
    /// Canonical policy whose hash is signed through assurance_policy_hash.
    pub compensation_policy: &'a XmrCompensationPolicyV11,
    /// Native verified cancel/refund/compensation transaction graph.
    pub recovery_graph: &'a VerifiedXmrRecoveryGraphV11,
    /// Native two-share proof-of-possession formation of exact collateral C.
    pub collateral: &'a FrozenSharedOutputV1,
    /// Role-2 DLEQ proof connecting the exact DOM refund U to the funded XMR
    /// shared-spend key. A valid claim-T proof alone cannot establish this.
    pub refund_share_proof: &'a BoundCrossCurveProofV1,
    /// Exact funding transaction committed by the same Contracts Store.
    pub expected_dom_funding_txid: [u8; 32],
    /// Exact predecessor transcript retained for this post-anchor claim round.
    pub claim_round_start_transcript_hash: [u8; 32],
    /// Concrete exact XMR observation inputs.
    pub xmr: XmrFundingObservationRequestV11<'a>,
}

/// Fresh, linear DOM/XMR anchor evidence, not a Store signing permission.
/// This type has no public constructor, Clone, Debug or deserialization.
pub struct VerifiedDomXmrAnchorEvidenceV11 {
    role: FinalClaimRoleBindingV1,
    ready: OperationalM8ReadyBindingV2,
    policy_bytes: Vec<u8>,
    policy_hash: [u8; 32],
    graph_digest: [u8; 32],
    dom: VerifiedDomFundingEvidenceV1,
    xmr: VerifiedXmrFundingV11,
    claim_round_start_transcript_hash: [u8; 32],
    evidence_digest: [u8; 32],
    observed_at: Instant,
}

impl VerifiedDomXmrAnchorEvidenceV11 {
    /// Complete operational role binding reauthenticated by this boundary.
    pub const fn role(&self) -> &FinalClaimRoleBindingV1 {
        &self.role
    }
    /// Exact canonical readiness whose signed Store record must be consumed.
    pub const fn ready(&self) -> &OperationalM8ReadyBindingV2 {
        &self.ready
    }
    /// Canonical V11 assurance policy. Historical M.8 policy decoding refuses it.
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }
    /// Policy digest already committed in the complete settlement terms.
    pub const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }
    /// Exact native recovery graph digest to match against durable custody.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Exact post-anchor predecessor transcript, never inferred from a revision.
    pub const fn claim_round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.claim_round_start_transcript_hash
    }
    /// Native DOM funding transaction proven to create the unspent C.
    pub const fn dom_funding_txid(&self) -> &[u8; 32] {
        &self.dom.funding_txid
    }
    /// Native DOM funding block.
    pub const fn dom_funding_block_hash(&self) -> &[u8; 32] {
        &self.dom.block_hash
    }
    /// Height containing native DOM funding.
    pub const fn dom_funding_height(&self) -> u64 {
        self.dom.height
    }
    /// Full DOM snapshot tip hash.
    pub const fn dom_tip_hash(&self) -> &[u8; 32] {
        &self.dom.observed_tip_hash
    }
    /// Full DOM snapshot tip height at which C remained unspent.
    pub const fn dom_tip_height(&self) -> u64 {
        self.dom.observed_tip_height
    }
    /// Native canonical funding confirmation depth.
    pub const fn dom_confirmation_depth(&self) -> u32 {
        self.dom.confirmation_depth
    }
    /// Exact native XMR funding evidence; it has no raw constructor.
    pub const fn xmr(&self) -> &VerifiedXmrFundingV11 {
        &self.xmr
    }
    /// Digest of complete immutable scope and both exact chain snapshots.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Reject stale retained process-local observations. This never substitutes
    /// for the Store's fresh chain projection and linear signing consumption.
    pub fn require_recent(&self) -> Result<(), Error> {
        if self.observed_at.elapsed() > MAX_V11_EXTERNAL_ANCHOR_AGE
            || self.xmr.evidence.observed_at.elapsed() > MAX_V11_EXTERNAL_ANCHOR_AGE
        {
            Err(Error::WindowClosed)
        } else {
            Ok(())
        }
    }
}

/// Drive native DOM, exact XMR view verification and canonical quorum checks.
/// No BTC client, BTC policy or BTC signer is created or required.
pub async fn verify_dom_xmr_anchor_evidence_v11(
    dom: &DomHttpChainAdapterV1,
    request: DomXmrAnchorValidationRequestV11<'_>,
    sidecar: &mut BlockingUdsSidecarPort,
    secrets: &EncryptedSqliteSecretStore,
) -> Result<VerifiedDomXmrAnchorEvidenceV11, Error> {
    validate_scope(&request)?;
    let role = request.role;
    let ready = request.ready;
    let terms = role.terms();
    let policy = request.compensation_policy;
    let xmr = verify_xmr_funding_v11(request.xmr, sidecar, secrets).await?;
    let dom_evidence = verify_dom_funding_evidence_inner(
        dom,
        request.expected_dom_funding_txid,
        ready.shared_output_commitment(),
        ready.funding_template_hash(),
        policy.collateral_confirmations,
        true,
    )
    .map_err(map_dom)?;
    if dom_evidence.chain_id != terms.dom_leg.chain_id.0
        || dom_evidence.observed_tip_hash == [0; 32]
    {
        return Err(Error::Binding);
    }
    if xmr.evidence.observed_at.elapsed() > MAX_V11_EXTERNAL_ANCHOR_AGE {
        return Err(Error::WindowClosed);
    }
    request
        .recovery_graph
        .require_claim_window(dom_evidence.observed_tip_height)
        .map_err(|_| Error::WindowClosed)?;
    let policy_hash = policy.policy_hash().map_err(|_| Error::Binding)?;
    let graph_digest = *request.recovery_graph.graph_digest();
    let mut digest = Sha256::new();
    digest.update(b"DOM-INTEROP/F7-DOM-XMR-ANCHORS/V11\0");
    for hash in [
        terms.terms_hash().map_err(|_| Error::Binding)?,
        role.digest().map_err(|_| Error::Binding)?,
        ready.digest(),
        policy_hash,
        graph_digest,
        request.claim_round_start_transcript_hash,
        dom_evidence.chain_id,
        dom_evidence.funding_txid,
        dom_evidence.block_hash,
        dom_evidence.observed_tip_hash,
        *xmr.evidence_digest(),
    ] {
        digest.update(hash);
    }
    for position in [
        dom_evidence.height,
        dom_evidence.block_time_seconds,
        dom_evidence.observed_tip_height,
    ] {
        digest.update(position.to_be_bytes());
    }
    digest.update(dom_evidence.confirmation_depth.to_be_bytes());
    Ok(VerifiedDomXmrAnchorEvidenceV11 {
        role: role.clone(),
        ready: ready.clone(),
        policy_bytes: policy.to_bytes().map_err(|_| Error::Binding)?,
        policy_hash,
        graph_digest,
        dom: dom_evidence,
        xmr,
        claim_round_start_transcript_hash: request.claim_round_start_transcript_hash,
        evidence_digest: digest.finalize().into(),
        observed_at: Instant::now(),
    })
}

fn validate_scope(request: &DomXmrAnchorValidationRequestV11<'_>) -> Result<(), Error> {
    let role = request.role;
    let terms = role.terms();
    let ready = request.ready;
    let policy = request.compensation_policy;
    let admitted = policy.validate_for(terms).map_err(|_| Error::Binding)?;
    let graph = request.recovery_graph.binding();
    let collateral = request.collateral;
    let statement = collateral.statement();
    let expected_roster = [terms.roster[0].0, terms.roster[1].0];
    let refund_share = verify_bound(
        request.refund_share_proof,
        &terms.settlement_id.0,
        request.xmr.setup.proof_context_hash(),
        ROLE_XMR_REFUND_SHARE,
    )
    .map_err(|_| Error::Binding)?;
    let combined = xmr_crypto::combine_public_shares(
        request.xmr.setup.claim().ed_compressed,
        refund_share.ed_compressed,
    )
    .map_err(|_| Error::Binding)?;
    let rebound = OperationalM8ReadyBindingV2::decode_canonical(role, &ready.canonical_bytes())
        .map_err(|_| Error::Binding)?;
    let graph_funding_hash =
        dom_adaptor::canonical_template_v1(request.recovery_graph.funding_template())
            .map_err(|_| Error::Binding)?
            .1;
    let graph_claim_hash =
        dom_adaptor::canonical_template_v1(request.recovery_graph.claim_template())
            .map_err(|_| Error::Binding)?
            .1;
    let graph_refund_hash =
        dom_adaptor::canonical_template_v1(request.recovery_graph.refund_template())
            .map_err(|_| Error::Binding)?
            .1;
    if rebound != *ready
        || role
            .canonical_bytes()
            .map_err(|_| Error::Binding)?
            .is_empty()
        || terms.terms_hash().map_err(|_| Error::Binding)?
            != request.xmr.terms.terms_hash().map_err(|_| Error::Binding)?
        || graph.chain_id != terms.dom_leg.chain_id.0
        || graph.session_id != terms.session_id.0
        || graph.terms_hash != *admitted.terms_hash()
        || graph.funding_commitment != ready.shared_output_commitment()
        || graph.claim_adaptor_point != terms.adaptor_point_sec1
        || graph.refund_adaptor_point != refund_share.secp_compressed
        || combined != request.xmr.setup.combined_spend_public_key()
        || refund_share.ed_compressed == request.xmr.setup.claim().ed_compressed
        || graph.cancel_height != policy.cancel_height
        || graph.punish_height != policy.compensation_height
        || graph.reveal_safety_blocks != policy.reveal_safety_blocks
        || graph.cancel_fee != policy.cancel_fee_noms
        || graph.refund_fee != policy.refund_fee_noms
        || graph.punish_fee != policy.compensation_fee_noms
        || graph_funding_hash != ready.funding_template_hash()
        || graph_claim_hash != ready.claim_template_hash()
        || graph_refund_hash != ready.refund_template_hash()
        || collateral.terms_hash() != admitted.terms_hash()
        || collateral.value_noms() != admitted.collateral_noms()
        || collateral.aggregate_commitment() != &graph.funding_commitment
        || statement.chain_id() != terms.dom_leg.chain_id.0
        || statement.session_id() != terms.session_id.0
        || statement.participant_ids() != expected_roster.as_slice()
        || statement.statement_hash() != ready.bp_statement_hash()
        || statement.recovery_binding_hash() != &ready.recovery_binding_hash()
        || ready.m8_policy_digest() != policy.policy_hash().map_err(|_| Error::Binding)?
        || ready.refund_unlock_height() != policy.cancel_height
        || ready.claim_kernel_index() != 0
        || request.expected_dom_funding_txid == [0; 32]
        || request.claim_round_start_transcript_hash == [0; 32]
    {
        return Err(Error::Binding);
    }
    Ok(())
}

fn map_dom(error: F7AnchorAuthorityError) -> Error {
    match error {
        F7AnchorAuthorityError::DomFundingAbsent => Error::FundingAbsent,
        F7AnchorAuthorityError::Dom(
            dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable,
        ) => Error::Unavailable,
        F7AnchorAuthorityError::InsufficientFinality => Error::InsufficientFinality,
        F7AnchorAuthorityError::BoundsExceeded => Error::Bounds,
        _ => Error::InvalidEvidence,
    }
}
