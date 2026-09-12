//! Native bounded-availability DOM/XMR anchors, without a synthetic M.8 Ready.
//! The native Store separately authenticates custody, votes and consumed F7.
use super::*;
use crate::families_v11::{VerifiedXmrFundingV11, XmrFundingObservationRequestV11};
use xmr_dleq_sigma::{verify_bound, BoundCrossCurveProofV1, ROLE_XMR_REFUND_SHARE};
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

/// Public verified graph inputs plus the exact native observation request.
/// This request alone grants no signing, funding, adaptation or transmission.
pub struct DomXmrBoundedAnchorValidationRequestV23<'a> {
    /// Exact operational leg role retained by the caller's native F7 gate.
    pub role: &'a FinalClaimRoleBindingV1,
    /// Verified economic graph completed from native Cancel/U/Compensation.
    pub produced: &'a ProducedXmrRecoveryGraphV12,
    /// Admitted role-2 proof for U, distinct from the claim point T.
    pub refund_share_proof: &'a BoundCrossCurveProofV1,
    /// Hash of the exact signed DOM funding committed by the native Store.
    pub expected_dom_funding_txid: [u8; 32],
    /// Immutable transcript preceding the claim round, including on restart.
    pub claim_round_start_transcript_hash: [u8; 32],
    /// The selected Monero setup, deployment and concrete observation clients.
    pub xmr: XmrFundingObservationRequestV11<'a>,
}

/// Promote a fresh opaque XMR observation using this exact DOM client.
/// Call outside an async runtime: the DOM adapter performs blocking HTTP.
/// No raw constructor can substitute for the concrete XMR observation.
pub fn verify_f7_xmr_bounded_anchor_authorization_v23(
    dom: &DomHttpChainAdapterV1,
    request: DomXmrBoundedAnchorValidationRequestV23<'_>,
    xmr: VerifiedXmrFundingV11,
) -> Result<VerifiedF7AnchorAuthorizationV12, Error> {
    super::super::xmr::require_funding_request_v23(&request.xmr, &xmr)?;
    let role = request.role;
    let terms = role.terms();
    let produced = request.produced;
    let graph = produced.graph();
    let scope = graph.binding();
    let policy = produced.economic().policy().policy();
    let admitted = policy.validate_for(terms).map_err(|_| Error::Binding)?;
    let collateral = produced.collateral();
    let statement = collateral.statement();
    let refund = verify_bound(
        request.refund_share_proof,
        &terms.settlement_id.0,
        request.xmr.setup.proof_context_hash(),
        ROLE_XMR_REFUND_SHARE,
    )
    .map_err(|_| Error::Binding)?;
    let combined = xmr_crypto::combine_public_shares(
        request.xmr.setup.claim().ed_compressed,
        refund.ed_compressed,
    )
    .map_err(|_| Error::Binding)?;
    let funding_hash = dom_adaptor::canonical_template_v1(graph.funding_template())
        .map_err(|_| Error::Binding)?
        .1;
    let claim_hash = dom_adaptor::canonical_template_v1(graph.claim_template())
        .map_err(|_| Error::Binding)?
        .1;
    let refund_hash = dom_adaptor::canonical_template_v1(graph.refund_template())
        .map_err(|_| Error::Binding)?
        .1;
    let terms_hash = terms.terms_hash().map_err(|_| Error::Binding)?;
    if policy.bounded_availability_v23.is_none()
        || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
        || request.xmr.terms.terms_hash().map_err(|_| Error::Binding)? != terms_hash
        || scope.chain_id != terms.dom_leg.chain_id.0
        || scope.session_id != terms.session_id.0
        || scope.terms_hash != terms_hash
        || produced.economic().policy().terms_hash() != &terms_hash
        || scope.funding_commitment != role.shared_output_commitment()
        || funding_hash != role.funding_template_hash()
        || claim_hash != role.claim_template_hash()
        || refund_hash != role.refund_template_hash()
        || scope.claim_adaptor_point != terms.adaptor_point_sec1
        || request.xmr.setup.claim().secp_compressed != terms.adaptor_point_sec1
        || scope.refund_adaptor_point != refund.secp_compressed
        || refund.ed_compressed == request.xmr.setup.claim().ed_compressed
        || combined != request.xmr.setup.combined_spend_public_key()
        || scope.cancel_height != policy.cancel_height
        || scope.punish_height != policy.compensation_height
        || scope.reveal_safety_blocks != policy.reveal_safety_blocks
        || scope.cancel_fee != policy.cancel_fee_noms
        || scope.refund_fee != policy.refund_fee_noms
        || scope.punish_fee != policy.compensation_fee_noms
        || collateral.terms_hash() != admitted.terms_hash()
        || collateral.value_noms() != admitted.collateral_noms()
        || collateral.aggregate_commitment() != &scope.funding_commitment
        || statement.chain_id() != terms.dom_leg.chain_id.0
        || statement.session_id() != terms.session_id.0
        || statement.participant_ids() != [terms.roster[0].0, terms.roster[1].0].as_slice()
        || produced.economic().bp_statement_hash() != &statement.statement_hash()
        || request.expected_dom_funding_txid == [0; 32]
        || request.claim_round_start_transcript_hash == [0; 32]
    {
        return Err(Error::Binding);
    }
    let external_deadline = xmr
        .facts()
        .observed_at
        .checked_add(Duration::from_secs(60))
        .ok_or(Error::Bounds)?;
    let snapshot = crate::verify_dom_funding_evidence_until_v23(
        dom,
        request.expected_dom_funding_txid,
        scope.funding_commitment,
        funding_hash,
        policy
            .collateral_confirmations
            .max(terms.dom_leg.finality.min_confirmations),
        true,
        Some(external_deadline),
    )
    .map_err(map_dom_v12)?;
    require_native_dom_identity_v23(
        terms.dom_leg.chain_id.0,
        snapshot.chain_id,
        snapshot.observed_tip_hash,
    )?;
    if xmr.facts().age() > Duration::from_secs(60) {
        return Err(Error::WindowClosed);
    }
    graph
        .require_claim_window(snapshot.observed_tip_height)
        .map_err(|_| Error::WindowClosed)?;
    let TimelockSpec::BlockHeight { value: deadline } = terms.dom_leg.deadline else {
        return Err(Error::Binding);
    };
    let reserve = u64::from(terms.dom_leg.finality.min_confirmations)
        + u64::from(terms.dom_leg.finality.max_reorg_depth);
    if snapshot
        .observed_tip_height
        .checked_add(reserve)
        .is_none_or(|height| height >= deadline)
    {
        return Err(Error::WindowClosed);
    }
    let mut digest = Sha256::new();
    digest.update(b"DOM-INTEROP/F7-DOM-XMR-BOUNDED-ANCHORS/V23\0");
    for hash in [
        terms_hash,
        role.digest().map_err(|_| Error::Binding)?,
        policy.policy_hash().map_err(|_| Error::Binding)?,
        *graph.graph_digest(),
        statement.statement_hash(),
        *statement.recovery_binding_hash(),
        request.claim_round_start_transcript_hash,
        snapshot.chain_id,
        snapshot.funding_txid,
        snapshot.block_hash,
        snapshot.observed_tip_hash,
        *xmr.evidence_digest(),
        *xmr.setup_binding_hash(),
    ] {
        digest.update(hash);
    }
    for position in [
        snapshot.height,
        snapshot.block_time_seconds,
        snapshot.observed_tip_height,
    ] {
        digest.update(position.to_be_bytes());
    }
    digest.update(snapshot.confirmation_depth.to_be_bytes());
    Ok(VerifiedF7AnchorAuthorizationV12 {
        role: role.clone(),
        family: F7ExternalFamilyV11::Monero,
        funding_id: *xmr.funding_id(),
        dom_funding_txid: snapshot.funding_txid,
        dom_block_hash: snapshot.block_hash,
        dom_height: snapshot.height,
        dom_tip_hash: snapshot.observed_tip_hash,
        dom_tip_height: snapshot.observed_tip_height,
        graph_digest: Some(*graph.graph_digest()),
        xmr_setup_binding_hash: Some(*xmr.setup_binding_hash()),
        round_start_transcript_hash: request.claim_round_start_transcript_hash,
        evidence_digest: digest.finalize().into(),
        // Do not renew the external snapshot's age during promotion.
        observed_at: xmr.facts().observed_at,
    })
}

// Invalid identity is a hard refusal, never a recoverable closed signing window.
fn require_native_dom_identity_v23(
    expected_chain: [u8; 32],
    observed_chain: [u8; 32],
    tip_hash: [u8; 32],
) -> Result<(), Error> {
    if expected_chain != observed_chain || tip_hash == [0; 32] {
        return Err(Error::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_dom_identity_mismatch_is_not_a_window_wait() {
        assert_eq!(
            require_native_dom_identity_v23([1; 32], [2; 32], [3; 32]),
            Err(Error::Binding)
        );
        assert_eq!(
            require_native_dom_identity_v23([1; 32], [1; 32], [0; 32]),
            Err(Error::Binding)
        );
        assert_eq!(
            require_native_dom_identity_v23([1; 32], [1; 32], [3; 32]),
            Ok(())
        );
    }
}
