//! Per-participant native recovery signing and actual Contracts/Relay staging.
//! Every V23 round starts from a retained graph origin and bilateral agreement.
//! This file cannot fabricate early/BP journals, relabel shares or sign for a peer.

use crate::production_dom_claim_driver_v12::{
    prepare_next_xmr_graph_recovery_edge_v23, ProductionDomClaimProgressV12,
};
use crate::relay_worker::DurableRelayWorkerV1;
use dom_actuator::{DomSessionBindingV1, RetainedParticipantVaultSignerV12};
use dom_adaptor::{
    advance_transcript_hash_v1, canonical_template_v1, nonce_commitment_hash_v1,
    AcceptedOperationalSigningSessionV1, AcceptedSigningSessionV1, BindingContextV1,
    ContractKindV1, NonceCommitmentV1, NonceRevealV1, NonceVaultV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, ParticipantRosterV1, PurposeV1, RestartArtifactRecoveryVaultV1,
    SigningPhaseV1, TrustedChainIdV1,
};
use dom_crypto::PublicKey;
use dom_scriptless_crypto::{
    begin_refund_adaptor_round_v1, xmr_ordinary_recovery_session_v12,
    CompletedXmrOrdinaryRecoveryRoundV12, RefundAdaptorRoundInputsV1, RefundAdaptorRoundV1,
    XmrOrdinaryRecoveryKindV12, XmrOrdinaryRecoveryRoundV12,
};
use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use dom_scriptless_store::{
    AcceptedContractsSigningSessionV1, ContractsSessionStoreV1, DurableTransportOutcomeV1,
    PreparedDsc1SigningRequestV1, PreparedXmrGraphSigningIngressV23,
    XmrGraphRecoverySigningEdgeV23,
};
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1};
use relay::TimelockSpec;
use route_transport::F6TransportPortV1;
use xmr_refund_policy::graph_builder::{ProducedXmrRecoveryGraphV12, XmrRecoveryGraphTemplatesV12};
use xmr_refund_policy::graph_signing_keys_v22::{XmrGraphSigningKeysV22, XmrGraphSigningStageV22};

#[path = "production_xmr_signing_scope_v23.rs"]
mod signing_scope_v23;
pub(crate) use signing_scope_v23::require_roster as require_xmr_recovery_signing_scope_v23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductionXmrRecoveryRoundKindV12 {
    Cancel,
    RefundAdaptor,
    Compensation,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionXmrRoundErrorV12 {
    #[error("native XMR recovery signing scope mismatch")]
    Scope,
    #[error("unconditional XMR compensation cannot be signed or transmitted by V13")]
    FundingConditionUnavailable,
    #[error("native retained XMR recovery signing authority refused")]
    Contracts,
    #[error("native XMR recovery vault refused nonce/signature operation")]
    Signer,
    #[error("native XMR recovery identity/Relay staging failed")]
    Transport,
}
type Result<T> = core::result::Result<T, ProductionXmrRoundErrorV12>;

/// Native custody classifies fresh versus resumed nonce state without a
/// caller-provided flag or missing-reservation fallback.
pub(crate) enum ProductionXmrRoundProgressV12 {
    AwaitingPeer,
    Staged,
    Complete,
}

/// Initialize the native graph session and bind its exact recovery edge.
/// Missing origins or bilateral graph agreement are refused by the Store.
pub(crate) fn bind_xmr_recovery_round_v12(
    store: &ContractsSessionStoreV1,
    trusted: TrustedChainIdV1,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    kind: ProductionXmrRecoveryRoundKindV12,
    roster: ParticipantRosterV1,
) -> Result<()> {
    require_xmr_recovery_signing_scope_v23(keys, templates, &trusted, &roster, kind)?;
    let scope = scope(templates, kind)?;
    if trusted.as_bytes() != &templates.binding().chain_id {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    store
        .prepare_xmr_graph_signing_session_v23(scope.session, graph_edge(kind))
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    require_retained_terms(store, &scope, templates)?;
    let accepted = store
        .resume_xmr_graph_signing_session_v23(scope.session, graph_edge(kind))
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    if accepted.roster() != &roster {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    require_accepted(&accepted, &scope, &trusted)
}

/// Drive one participant's next public edge and durably stage it through the
/// real identity signer and Relay owner. Vault derivation and partial signing
/// are native consume-before-export operations, including on crash replay.
/// `binding` is the parent graph binding. Ordinary rounds derive their own
/// auxiliary binding; their signer must already own the corresponding share.
/// The U-adaptor refund retains the parent binding and its separate purpose.
#[allow(clippy::too_many_arguments)]
pub(crate) fn tick_xmr_recovery_round_v12<Vault, F>(
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    relay: &mut DurableRelayWorkerV1<F>,
    trusted: TrustedChainIdV1,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    kind: ProductionXmrRecoveryRoundKindV12,
    binding: DomSessionBindingV1,
    signer: &mut RetainedParticipantVaultSignerV12<Vault>,
    expiry: TimelockSpec,
) -> Result<ProductionXmrRoundProgressV12>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
    F: F6TransportPortV1,
{
    let scope = scope(templates, kind)?;
    require_retained_terms(store, &scope, templates)?;
    if binding.session_id() != templates.binding().session_id
        || binding.terms_digest() != templates.binding().terms_hash
        || binding.chain_id() != templates.binding().chain_id
    {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    let binding = match kind {
        ProductionXmrRecoveryRoundKindV12::RefundAdaptor => binding,
        ProductionXmrRecoveryRoundKindV12::Cancel => {
            let (_, hash) = canonical_template_v1(scope.template)
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
            binding
                .for_xmr_ordinary_recovery_v22(
                    templates.binding(),
                    XmrOrdinaryRecoveryKindV12::Cancel,
                    hash,
                )
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?
        }
        ProductionXmrRecoveryRoundKindV12::Compensation => {
            let (_, hash) = canonical_template_v1(scope.template)
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
            binding
                .for_xmr_compensation_v23(templates.binding(), templates.policy(), hash)
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?
        }
    };
    if binding.session_id() != scope.session || binding.chain_id() != templates.binding().chain_id {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    let accepted = store
        .resume_xmr_graph_signing_session_v23(scope.session, graph_edge(kind))
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    require_accepted(&accepted, &scope, &trusted)?;
    require_xmr_recovery_signing_scope_v23(keys, templates, &trusted, accepted.roster(), kind)?;
    store
        .bind_local_transport_signer(scope.session, *identity.reference().key_reference())
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    // Restore the exact Store-to-Relay handoff before deciding whose turn is
    // next. A committed local message already advanced the signing prefix,
    // even when a crash prevented its initial Relay staging.
    match store
        .resume_outbound_dsc1(scope.session)
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?
    {
        dom_scriptless_store::OutboundDsc1RecoveryV1::None => {}
        dom_scriptless_store::OutboundDsc1RecoveryV1::SigningRequest(request) => {
            if request.session_id() != &scope.session
                || request.chain_id() != trusted.as_bytes()
                || !matches!(request.message_type(), 0x0c..=0x0e)
            {
                return Err(ProductionXmrRoundErrorV12::Scope);
            }
            stage(store, identity, relay, scope.session, *request, expiry)?;
            return Ok(ProductionXmrRoundProgressV12::Staged);
        }
        dom_scriptless_store::OutboundDsc1RecoveryV1::Committed(message) => {
            let parsed = SignedMessageV1::decode_exact(message.signed_bytes())
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
            if message.session_id() != &scope.session
                || !matches!(
                    parsed.unsigned().kind(),
                    MessageTypeV1::SigNonceCommit
                        | MessageTypeV1::SigNonceReveal
                        | MessageTypeV1::PartialSignature
                )
            {
                return Err(ProductionXmrRoundErrorV12::Scope);
            }
            relay
                .stage_store_outbound_dsc1(*message, expiry)
                .map_err(|_| ProductionXmrRoundErrorV12::Transport)?;
            return Ok(ProductionXmrRoundProgressV12::Staged);
        }
    }
    let progress = prepare_next_xmr_graph_recovery_edge_v23(
        store,
        binding,
        trusted,
        signer,
        accepted,
        graph_edge(kind),
    )
    .map_err(|_| ProductionXmrRoundErrorV12::Signer)?;
    match progress {
        ProductionDomClaimProgressV12::AwaitingPeer => {
            Ok(ProductionXmrRoundProgressV12::AwaitingPeer)
        }
        ProductionDomClaimProgressV12::Prepared(request) => {
            stage(store, identity, relay, scope.session, request, expiry)?;
            Ok(ProductionXmrRoundProgressV12::Staged)
        }
        ProductionDomClaimProgressV12::SigningComplete => {
            // Six authenticated messages complete the public equation. GraphV23
            // does not borrow the legacy 0x10 final-refund transport authority.
            Ok(ProductionXmrRoundProgressV12::Complete)
        }
    }
}

fn graph_edge(kind: ProductionXmrRecoveryRoundKindV12) -> XmrGraphRecoverySigningEdgeV23 {
    match kind {
        ProductionXmrRecoveryRoundKindV12::Cancel => XmrGraphRecoverySigningEdgeV23::Cancel,
        ProductionXmrRecoveryRoundKindV12::RefundAdaptor => {
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor
        }
        ProductionXmrRecoveryRoundKindV12::Compensation => {
            XmrGraphRecoverySigningEdgeV23::Compensation
        }
    }
}

/// Prepare the exact incoming route scope without exposing a caller-shaped phase.
pub(crate) fn prepare_xmr_recovery_ingress_v23(
    store: &ContractsSessionStoreV1,
    trusted: TrustedChainIdV1,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    kind: ProductionXmrRecoveryRoundKindV12,
) -> Result<PreparedXmrGraphSigningIngressV23> {
    let scope = scope(templates, kind)?;
    let accepted = store
        .resume_xmr_graph_signing_session_v23(scope.session, graph_edge(kind))
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    require_accepted(&accepted, &scope, &trusted)?;
    require_xmr_recovery_signing_scope_v23(keys, templates, &trusted, accepted.roster(), kind)?;
    store
        .prepare_xmr_graph_signing_ingress_v23(scope.session, graph_edge(kind))
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)
}

pub(crate) fn accept_xmr_recovery_ingress_v23(
    store: &ContractsSessionStoreV1,
    prepared: &PreparedXmrGraphSigningIngressV23,
    signed_bytes: &[u8],
) -> Result<DurableTransportOutcomeV1> {
    store
        .accept_xmr_graph_signing_ingress_v23(prepared, signed_bytes)
        .map_err(|_| ProductionXmrRoundErrorV12::Transport)
}

fn stage<F: F6TransportPortV1>(
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    relay: &mut DurableRelayWorkerV1<F>,
    session: [u8; 32],
    request: PreparedDsc1SigningRequestV1,
    expiry: TimelockSpec,
) -> Result<()> {
    if request.session_id() != &session {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    let message = identity
        .sign_and_commit_store_prepared_dsc1(store, request)
        .map_err(|_| ProductionXmrRoundErrorV12::Transport)?;
    relay
        .stage_store_outbound_dsc1(message, expiry)
        .map_err(|_| ProductionXmrRoundErrorV12::Transport)?;
    Ok(())
}

/// Recover the completed ordinary equation from six native authenticated
/// envelopes. This function accepts only a concrete Store-issued session.
pub(crate) fn produce_completed_xmr_ordinary_round_v12(
    accepted: &AcceptedContractsSigningSessionV1,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    kind: XmrOrdinaryRecoveryKindV12,
) -> Result<CompletedXmrOrdinaryRecoveryRoundV12> {
    let scope = scope(
        templates,
        match kind {
            XmrOrdinaryRecoveryKindV12::Cancel => ProductionXmrRecoveryRoundKindV12::Cancel,
            XmrOrdinaryRecoveryKindV12::Compensation => {
                ProductionXmrRecoveryRoundKindV12::Compensation
            }
        },
    )?;
    require_accepted(accepted, &scope, accepted.trusted_chain_id())?;
    require_xmr_recovery_signing_scope_v23(
        keys,
        templates,
        accepted.trusted_chain_id(),
        accepted.roster(),
        match kind {
            XmrOrdinaryRecoveryKindV12::Cancel => ProductionXmrRecoveryRoundKindV12::Cancel,
            XmrOrdinaryRecoveryKindV12::Compensation => {
                ProductionXmrRecoveryRoundKindV12::Compensation
            }
        },
    )?;
    let public = rederive_public_round(accepted)?;
    let round = match kind {
        XmrOrdinaryRecoveryKindV12::Cancel => XmrOrdinaryRecoveryRoundV12::begin(
            *templates.binding(),
            kind,
            scope.template,
            &public.nonces,
        )
        .map_err(|_| ProductionXmrRoundErrorV12::Scope)?,
        XmrOrdinaryRecoveryKindV12::Compensation => templates
            .begin_compensation_round_v23(&public.nonces)
            .map_err(|_| ProductionXmrRoundErrorV12::Scope)?,
    };
    round
        .complete(&public.partials)
        .map_err(|_| ProductionXmrRoundErrorV12::Signer)
}

/// Retired V22 compatibility entry. A local funding witness cannot authorize
/// compensation; only cancellation remains available through this entry.
pub(crate) fn produce_completed_xmr_ordinary_round_with_funding_v22(
    accepted: &AcceptedContractsSigningSessionV1,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    kind: XmrOrdinaryRecoveryKindV12,
    _funding_witness: Option<&dom_scriptless_crypto::XmrCompensationFundingWitnessV22>,
) -> Result<CompletedXmrOrdinaryRecoveryRoundV12> {
    if kind == XmrOrdinaryRecoveryKindV12::Compensation {
        return Err(ProductionXmrRoundErrorV12::FundingConditionUnavailable);
    }
    produce_completed_xmr_ordinary_round_v12(accepted, templates, keys, kind)
}

/// Parent U-adaptor round produced from actual retained transcript, never from
/// a caller's purported final signature or a secret sent by the other party.
pub(crate) struct ProductionCompletedXmrRefundRoundV12 {
    round: RefundAdaptorRoundV1,
    partials: Vec<PartialSignatureV1>,
}
impl ProductionCompletedXmrRefundRoundV12 {
    pub(crate) fn from_store_session(
        accepted: &AcceptedContractsSigningSessionV1,
        templates: &XmrRecoveryGraphTemplatesV12,
        keys: &XmrGraphSigningKeysV22,
    ) -> Result<Self> {
        let scope = scope(templates, ProductionXmrRecoveryRoundKindV12::RefundAdaptor)?;
        require_accepted(accepted, &scope, accepted.trusted_chain_id())?;
        require_xmr_recovery_signing_scope_v23(
            keys,
            templates,
            accepted.trusted_chain_id(),
            accepted.roster(),
            ProductionXmrRecoveryRoundKindV12::RefundAdaptor,
        )?;
        let public = rederive_public_round(accepted)?;
        let (_, template_hash) =
            canonical_template_v1(scope.template).map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
        let kernel = &scope.template.kernels[0];
        let round = begin_refund_adaptor_round_v1(&RefundAdaptorRoundInputsV1 {
            binding_context: BindingContextV1 {
                chain_id: *accepted.trusted_chain_id().as_bytes(),
                session_id: scope.session,
                purpose: PurposeV1::RefundAdaptor,
                template_hash,
            },
            participants: &public.nonces,
            refund_adaptor_point: scope.adaptor.ok_or(ProductionXmrRoundErrorV12::Scope)?,
            aggregate_signing_key: PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?,
            transcript_hash: public.reveal_transcript,
            kernel_message_digest: *dom_scriptless_consensus::scriptless_kernel_message_digest_v1(
                kernel,
            )
            .as_bytes(),
        })
        .map_err(|_| ProductionXmrRoundErrorV12::Signer)?;
        round
            .aggregate_pre_signature_v1(&public.partials)
            .map_err(|_| ProductionXmrRoundErrorV12::Signer)?;
        Ok(Self {
            round,
            partials: public.partials,
        })
    }

    pub(crate) fn complete_graph(
        self,
        templates: XmrRecoveryGraphTemplatesV12,
        cancel: CompletedXmrOrdinaryRecoveryRoundV12,
        compensation: CompletedXmrOrdinaryRecoveryRoundV12,
    ) -> Result<ProducedXmrRecoveryGraphV12> {
        templates
            .complete(cancel, compensation, &self.round, &self.partials)
            .map_err(|_| ProductionXmrRoundErrorV12::Scope)
    }
}

struct Scope<'a> {
    chain: [u8; 32],
    session: [u8; 32],
    purpose: PurposeV1,
    template: &'a dom_consensus::Transaction,
    adaptor: Option<PublicKey>,
}
fn scope(
    templates: &XmrRecoveryGraphTemplatesV12,
    kind: ProductionXmrRecoveryRoundKindV12,
) -> Result<Scope<'_>> {
    let (template, ordinary) = match kind {
        ProductionXmrRecoveryRoundKindV12::Cancel => {
            (templates.cancel(), Some(XmrOrdinaryRecoveryKindV12::Cancel))
        }
        ProductionXmrRecoveryRoundKindV12::Compensation => (
            templates.compensation(),
            Some(XmrOrdinaryRecoveryKindV12::Compensation),
        ),
        ProductionXmrRecoveryRoundKindV12::RefundAdaptor => (templates.refund(), None),
    };
    let (_, hash) =
        canonical_template_v1(template).map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
    let (session, purpose, adaptor) = match ordinary {
        Some(XmrOrdinaryRecoveryKindV12::Cancel) => (
            xmr_ordinary_recovery_session_v12(
                templates.binding(),
                XmrOrdinaryRecoveryKindV12::Cancel,
                hash,
            ),
            PurposeV1::Refund,
            None,
        ),
        Some(XmrOrdinaryRecoveryKindV12::Compensation) => (
            templates
                .compensation_session_v23()
                .map_err(|_| ProductionXmrRoundErrorV12::Scope)?,
            PurposeV1::Refund,
            None,
        ),
        None => (
            templates.binding().session_id,
            PurposeV1::RefundAdaptor,
            Some(
                PublicKey::from_compressed_bytes(&templates.binding().refund_adaptor_point)
                    .map_err(|_| ProductionXmrRoundErrorV12::Scope)?,
            ),
        ),
    };
    Ok(Scope {
        chain: templates.binding().chain_id,
        session,
        purpose,
        template,
        adaptor,
    })
}
fn require_retained_terms(
    store: &ContractsSessionStoreV1,
    scope: &Scope<'_>,
    templates: &XmrRecoveryGraphTemplatesV12,
) -> Result<()> {
    let record = store
        .load_session(scope.session)
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
    if record.session_id() != scope.session || record.terms_hash() != templates.binding().terms_hash
    {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    Ok(())
}

fn require_accepted(
    accepted: &AcceptedContractsSigningSessionV1,
    scope: &Scope<'_>,
    trusted: &TrustedChainIdV1,
) -> Result<()> {
    if accepted.session_id() != &scope.session
        || accepted.contract_kind() != ContractKindV1::WitnessOrTimeout
        || accepted.purpose() != scope.purpose
        || trusted.as_bytes() != &scope.chain
        || accepted.trusted_chain_id() != trusted
        || accepted.kernel_index() != 0
        || accepted.transaction_template() != scope.template
        || accepted.adaptor_point() != scope.adaptor.as_ref()
    {
        return Err(ProductionXmrRoundErrorV12::Scope);
    }
    Ok(())
}

struct PublicRound {
    nonces: Vec<ParticipantPublicNoncesV1>,
    partials: Vec<PartialSignatureV1>,
    reveal_transcript: [u8; 32],
}
fn rederive_public_round(accepted: &AcceptedContractsSigningSessionV1) -> Result<PublicRound> {
    let messages = accepted.accepted_signing_messages().collect::<Vec<_>>();
    let roster = accepted.roster();
    if messages.len() != 6 || roster.entries().len() != 2 {
        return Err(ProductionXmrRoundErrorV12::Contracts);
    }
    let mut transcript = *accepted.round_start_transcript_hash();
    let mut reveal_transcript = [0; 32];
    let mut commits = Vec::new();
    let mut reveals = Vec::new();
    let mut partials = Vec::new();
    for (position, bytes) in messages.iter().enumerate() {
        let sender = position % 2;
        let stage = position / 2;
        let participant = &roster.entries()[sender];
        let message = SignedMessageV1::decode_exact(bytes)
            .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
        message
            .verify_identity(participant.identity_public_key())
            .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
        let unsigned = message.unsigned();
        let kind = match stage {
            0 => MessageTypeV1::SigNonceCommit,
            1 => MessageTypeV1::SigNonceReveal,
            _ => MessageTypeV1::PartialSignature,
        };
        if unsigned.chain_id() != accepted.trusted_chain_id().as_bytes()
            || unsigned.session_id() != accepted.session_id()
            || unsigned.sender_id() != participant.participant_id()
            || unsigned.sequence()
                != accepted.sender_sequence_bases()[sender]
                    .checked_add(stage as u64)
                    .ok_or(ProductionXmrRoundErrorV12::Contracts)?
            || unsigned.previous_transcript_hash() != &transcript
            || unsigned.kind() != kind
        {
            return Err(ProductionXmrRoundErrorV12::Contracts);
        }
        match stage {
            0 => commits.push(
                NonceCommitmentV1::from_bytes(unsigned.payload())
                    .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?,
            ),
            1 => reveals.push(
                NonceRevealV1::from_bytes(unsigned.payload())
                    .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?,
            ),
            _ => partials.push(
                PartialSignatureV1::from_bytes(unsigned.payload())
                    .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?,
            ),
        }
        transcript = advance_transcript_hash_v1(
            &transcript,
            message.digest(),
            participant.direction(),
            match stage {
                0 => SigningPhaseV1::SigNonceCommit,
                1 => SigningPhaseV1::SigNonceReveal,
                _ => SigningPhaseV1::SigPartial,
            },
        );
        if position == 3 {
            reveal_transcript = transcript;
        }
    }
    let (_, hash) = canonical_template_v1(accepted.transaction_template())
        .map_err(|_| ProductionXmrRoundErrorV12::Scope)?;
    let mut nonces = Vec::new();
    for (index, participant) in roster.entries().iter().enumerate() {
        let signing_index = roster
            .signing_index(participant.participant_id())
            .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
        let reveal = &reveals[index];
        let commit = &commits[index];
        let partial = &partials[index];
        if reveal.purpose() != accepted.purpose()
            || commit.purpose() != accepted.purpose()
            || partial.purpose() != accepted.purpose()
            || reveal.participant_index() != signing_index
            || commit.participant_index() != signing_index
            || partial.participant_index() != signing_index
            || partial.template_hash() != &hash
        {
            return Err(ProductionXmrRoundErrorV12::Contracts);
        }
        let expected = nonce_commitment_hash_v1(
            accepted.trusted_chain_id().as_bytes(),
            accepted.session_id(),
            participant.participant_id(),
            accepted.purpose(),
            &hash,
            reveal.first(),
            reveal.second(),
            accepted.adaptor_point(),
        )
        .map_err(|_| ProductionXmrRoundErrorV12::Contracts)?;
        if commit.nonce_reveal_hash() != expected.as_bytes() {
            return Err(ProductionXmrRoundErrorV12::Contracts);
        }
        nonces.push(ParticipantPublicNoncesV1 {
            participant_index: signing_index,
            signing_key: participant.signing_public_key().clone(),
            first_nonce: reveal.first().clone(),
            second_nonce: reveal.second().clone(),
        });
    }
    nonces.sort_by_key(|participant| participant.participant_index);
    partials.sort_by_key(PartialSignatureV1::participant_index);
    Ok(PublicRound {
        nonces,
        partials,
        reveal_transcript,
    })
}
