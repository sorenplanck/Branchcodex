//! Bounded one-participant DOM claim signing over the retained native stores.
//!
//! The root obtains the accepted session from a consumed V2 or V12 post-anchor
//! authority. This module cannot create that authority, pick a template, sign
//! for the peer, or reconstruct a signing share from public bytes. It consumes
//! one retained wallet-owned signer and the exact purpose-separated native vault.

use dom_actuator::{DomSessionBindingV1, RetainedParticipantVaultSignerV12};
use dom_adaptor::{
    AcceptedSigningSessionV1, NonceVaultV1, PurposeV1, ResentArtifactV1,
    RestartArtifactRecoveryVaultV1, RestartedReservationV1, TrustedChainIdV1,
};
use dom_scriptless_store::{
    AcceptedContractsSigningSessionV1, ContractsSessionStoreV1, PreparedDsc1SigningRequestV1,
    PreparedOperationalSigningTransportAuthorityV1, XmrGraphRecoverySigningEdgeV23,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionDomClaimDriverErrorV12 {
    #[error("DOM claim participant, scope or canonical signing prefix mismatch")]
    Binding,
    #[error("retained DOM wallet/nonce signing authority refused the claim")]
    Signer,
    #[error("retained Contracts authority refused the next DOM claim edge")]
    Contracts,
}

/// No raw signing payload escapes the driver: a public edge is returned only
/// after Contracts has checked and durably issued its exact DSC1 request.
#[must_use]
pub(crate) enum ProductionDomClaimProgressV12 {
    AwaitingPeer,
    Prepared(PreparedDsc1SigningRequestV1),
    /// Both native partial signatures are authenticated in the retained Store.
    /// The root must still reconstruct and transport the canonical pre-signature
    /// through the matching V2/V12 post-anchor authority before adaptation.
    SigningComplete,
}

/// Advance a bounded claim tick using the same retained one-participant
/// signer. Its native custody classifies fresh versus restart; the caller
/// cannot select either branch or supply a replacement reservation lookup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_next_dom_claim_edge_with_signer_v12<Vault>(
    store: &ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
    trusted_chain: TrustedChainIdV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    accepted: AcceptedContractsSigningSessionV1,
    transport: &PreparedOperationalSigningTransportAuthorityV1,
) -> Result<ProductionDomClaimProgressV12, ProductionDomClaimDriverErrorV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    prepare_next_dom_signing_edge_v12(
        store,
        binding,
        trusted_chain,
        signer,
        accepted,
        SigningTransportV23::Legacy(transport),
        PurposeV1::ClaimAdaptor,
    )
}

/// Native prefunding gate is retained before this signer can spend a nonce.
pub(crate) fn prepare_next_dom_funding_edge_v20<Vault>(
    store: &ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    accepted: AcceptedContractsSigningSessionV1,
    transport: &PreparedOperationalSigningTransportAuthorityV1,
) -> Result<ProductionDomClaimProgressV12, ProductionDomClaimDriverErrorV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    prepare_next_dom_signing_edge_v12(
        store,
        binding,
        chain,
        signer,
        accepted,
        SigningTransportV23::Legacy(transport),
        PurposeV1::Funding,
    )
}

/// Native recovery rounds use the same nonce lifecycle while remaining a
/// separate entry. The recovery runtime must first bind the exact auxiliary
/// graph transaction through its consumed native graph/Store authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_next_dom_recovery_edge_with_signer_v12<Vault>(
    store: &ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
    trusted_chain: TrustedChainIdV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    accepted: AcceptedContractsSigningSessionV1,
    transport: &PreparedOperationalSigningTransportAuthorityV1,
) -> Result<ProductionDomClaimProgressV12, ProductionDomClaimDriverErrorV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    let purpose = accepted.purpose();
    if !matches!(purpose, PurposeV1::Refund | PurposeV1::RefundAdaptor) {
        return Err(ProductionDomClaimDriverErrorV12::Binding);
    }
    prepare_next_dom_signing_edge_v12(
        store,
        binding,
        trusted_chain,
        signer,
        accepted,
        SigningTransportV23::Legacy(transport),
        purpose,
    )
}

/// Explicit GraphV23 transport profile; the nonce lifecycle remains identical.
/// The accepted handle is issued only by the graph-native Store dispatcher.
pub(crate) fn prepare_next_xmr_graph_recovery_edge_v23<Vault>(
    store: &ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
    trusted_chain: TrustedChainIdV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    accepted: AcceptedContractsSigningSessionV1,
    edge: XmrGraphRecoverySigningEdgeV23,
) -> Result<ProductionDomClaimProgressV12, ProductionDomClaimDriverErrorV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    let purpose = match edge {
        XmrGraphRecoverySigningEdgeV23::RefundAdaptor => PurposeV1::RefundAdaptor,
        XmrGraphRecoverySigningEdgeV23::Cancel | XmrGraphRecoverySigningEdgeV23::Compensation => {
            PurposeV1::Refund
        }
    };
    prepare_next_dom_signing_edge_v12(
        store,
        binding,
        trusted_chain,
        signer,
        accepted,
        SigningTransportV23::Graph(edge),
        purpose,
    )
}

#[derive(Clone, Copy)]
enum SigningTransportV23<'a> {
    Legacy(&'a PreparedOperationalSigningTransportAuthorityV1),
    Graph(XmrGraphRecoverySigningEdgeV23),
}

#[allow(clippy::too_many_arguments)]
fn prepare_next_dom_signing_edge_v12<Vault>(
    store: &ContractsSessionStoreV1,
    binding: DomSessionBindingV1,
    trusted_chain: TrustedChainIdV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    accepted: AcceptedContractsSigningSessionV1,
    transport: SigningTransportV23<'_>,
    expected_purpose: PurposeV1,
) -> Result<ProductionDomClaimProgressV12, ProductionDomClaimDriverErrorV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    use ProductionDomClaimDriverErrorV12 as Error;
    if accepted.purpose() != expected_purpose
        || accepted.session_id() != &binding.session_id()
        || accepted.trusted_chain_id() != &trusted_chain
        || trusted_chain.as_bytes() != &binding.chain_id()
        || accepted.roster().entries().len() != 2
    {
        return Err(Error::Binding);
    }
    let local_index = accepted
        .roster()
        .entries()
        .iter()
        .position(|entry| entry.participant_id() == &binding.participant().participant_id())
        .ok_or(Error::Binding)?;
    if local_index != usize::from(binding.participant().protocol_index()) {
        return Err(Error::Binding);
    }
    let prefix = accepted.accepted_signing_messages().count();
    if prefix > 6 {
        return Err(Error::Binding);
    }
    if prefix == 6 {
        return Ok(ProductionDomClaimProgressV12::SigningComplete);
    }
    let local_turn = prefix % 2 == local_index;
    // A fresh participant precomputes and durably retains its commitment even
    // when the first sender is the peer. Subsequent waiting ticks need no nonce
    // access, and can never initialize or mutate a second reservation.
    if !local_turn && prefix > local_index {
        return Ok(ProductionDomClaimProgressV12::AwaitingPeer);
    }
    let mut round = match transport {
        SigningTransportV23::Graph(XmrGraphRecoverySigningEdgeV23::RefundAdaptor) => {
            signer.begin_graph_refund_signing_round_v23(accepted)
        }
        _ => signer.begin_operational_signing_round(accepted),
    }
    .map_err(|_| Error::Signer)?;
    let state = signer
        .open_local_reservation_v12(&mut round)
        .map_err(|_| Error::Signer)?;
    let stage = prefix / 2;
    let payload = match state {
        RestartedReservationV1::PreDerivation(reserved) if stage == 0 => {
            let (_retained, commitment) = signer
                .derive_and_export_commitment(reserved)
                .map_err(|_| Error::Signer)?;
            commitment.to_bytes().to_vec()
        }
        RestartedReservationV1::AfterCommitment(state) if stage == 0 => {
            match signer
                .resend_commitment_from_restarted(&state, &mut round)
                .map_err(|_| Error::Signer)?
            {
                ResentArtifactV1::NonceCommitment(commitment) => commitment.to_bytes().to_vec(),
                _ => return Err(Error::Signer),
            }
        }
        RestartedReservationV1::AfterCommitment(state) if stage == 1 => {
            let authority = round.take_commitment_round().map_err(|_| Error::Signer)?;
            let (_retained, reveal) = signer
                .export_reveal(state, authority)
                .map_err(|_| Error::Signer)?;
            reveal.to_bytes().to_vec()
        }
        RestartedReservationV1::AfterReveal(state) if stage == 1 => {
            match signer
                .resend_reveal_from_restarted(&state, &mut round)
                .map_err(|_| Error::Signer)?
            {
                ResentArtifactV1::NonceReveal(reveal) => reveal.to_bytes().to_vec(),
                _ => return Err(Error::Signer),
            }
        }
        RestartedReservationV1::AfterReveal(state) if stage == 2 => {
            let authority = round.take_reveal_round().map_err(|_| Error::Signer)?;
            let (_terminal, partial) = signer
                .sign_and_export_partial(state, authority)
                .map_err(|_| Error::Signer)?;
            partial.to_bytes().to_vec()
        }
        RestartedReservationV1::PartialAuthorized(state) if stage == 2 => {
            match signer
                .resend_partial_from_restarted(&state, &mut round)
                .map_err(|_| Error::Signer)?
            {
                ResentArtifactV1::PartialSignature(partial) => partial.to_bytes().to_vec(),
                _ => return Err(Error::Signer),
            }
        }
        _ => return Err(Error::Signer),
    };
    if !local_turn {
        return Ok(ProductionDomClaimProgressV12::AwaitingPeer);
    }
    let request = match transport {
        SigningTransportV23::Legacy(authority) => {
            store.prepare_next_operational_signing_dsc1_signing_request(authority, &payload)
        }
        SigningTransportV23::Graph(edge) => {
            store.prepare_xmr_graph_signing_dsc1_request_v23(binding.session_id(), edge, &payload)
        }
    }
    .map_err(|_| Error::Contracts)?
    .ok_or(Error::Binding)?;
    Ok(ProductionDomClaimProgressV12::Prepared(request))
}
