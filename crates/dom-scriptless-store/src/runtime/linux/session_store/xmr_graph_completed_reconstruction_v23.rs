//! Rebuild a completed graph from immutable native origins and the three real
//! signing transcripts. Public nonce/partial parsing follows full Store audit.
use super::*;
use dom_adaptor::{BindingContextV1, ParticipantPublicNoncesV1};
use dom_scriptless_crypto::{
    begin_refund_adaptor_round_v1, RefundAdaptorRoundInputsV1, XmrOrdinaryRecoveryKindV12,
    XmrOrdinaryRecoveryRoundV12,
};
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

impl ContractsSessionStoreV1 {
    /// Caller holds operation lock. Historical reconstruction, no signing or
    /// creation, and no assumption that the current parent remains at revision25.
    pub(in super::super) fn reconstruct_completed_xmr_graph_v23(
        &self,
        parent: [u8; 32],
    ) -> Result<ProducedXmrRecoveryGraphV12, SessionStoreError> {
        let context = self.load_xmr_graph_commit_context_v23(parent)?;
        let chain = self.require_process_trusted_chain_v23(&context.chain)?;
        let (templates, _) =
            self.reconstruct_xmr_graph_evidence_core_v23(chain, context.route, parent, false)?;
        let cancel = dom_scriptless_crypto::xmr_ordinary_recovery_session_v12(
            templates.binding(),
            XmrOrdinaryRecoveryKindV12::Cancel,
            canonical_template_v1(templates.cancel())
                .map_err(|_| SessionStoreError::Quarantined)?
                .1,
        );
        let compensation = templates
            .compensation_session_v23()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let (cancel_nonces, cancel_partials, _) =
            self.completed_graph_public_round_v23(cancel, XmrGraphRecoverySigningEdgeV23::Cancel)?;
        let (comp_nonces, comp_partials, _) = self.completed_graph_public_round_v23(
            compensation,
            XmrGraphRecoverySigningEdgeV23::Compensation,
        )?;
        let (refund_nonces, refund_partials, reveal) = self.completed_graph_public_round_v23(
            parent,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        let cancel_round = XmrOrdinaryRecoveryRoundV12::begin(
            *templates.binding(),
            XmrOrdinaryRecoveryKindV12::Cancel,
            templates.cancel(),
            &cancel_nonces,
        )
        .and_then(|round| round.complete(&cancel_partials))
        .map_err(|_| SessionStoreError::Quarantined)?;
        let comp_round = templates
            .begin_compensation_round_v23(&comp_nonces)
            .map_err(|_| SessionStoreError::Quarantined)?
            .complete(&comp_partials)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let kernel = templates
            .refund()
            .kernels
            .first()
            .ok_or(SessionStoreError::Quarantined)?;
        let refund_round = begin_refund_adaptor_round_v1(&RefundAdaptorRoundInputsV1 {
            binding_context: BindingContextV1 {
                chain_id: context.chain,
                session_id: parent,
                purpose: PurposeV1::RefundAdaptor,
                template_hash: canonical_template_v1(templates.refund())
                    .map_err(|_| SessionStoreError::Quarantined)?
                    .1,
            },
            participants: &refund_nonces,
            refund_adaptor_point: PublicKey::from_compressed_bytes(
                &templates.binding().refund_adaptor_point,
            )
            .map_err(|_| SessionStoreError::Quarantined)?,
            aggregate_signing_key: PublicKey::from_compressed_bytes(kernel.excess.as_bytes())
                .map_err(|_| SessionStoreError::Quarantined)?,
            transcript_hash: reveal,
            kernel_message_digest: *dom_scriptless_consensus::scriptless_kernel_message_digest_v1(
                kernel,
            )
            .as_bytes(),
        })
        .map_err(|_| SessionStoreError::Quarantined)?;
        templates
            .complete(cancel_round, comp_round, &refund_round, &refund_partials)
            .map_err(|_| SessionStoreError::Quarantined)
    }

    fn completed_graph_public_round_v23(
        &self,
        session: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<
        (
            Vec<ParticipantPublicNoncesV1>,
            Vec<PartialSignatureV1>,
            [u8; 32],
        ),
        SessionStoreError,
    > {
        let binding = self.authenticate_xmr_graph_signing_session_v23(session, edge)?;
        let terminal_revision = binding
            .start
            .revision()
            .checked_add(6)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let terminal = self.load_session_revision(session, terminal_revision)?;
        if terminal.phase() != SessionPhaseV1::RefundSigning
            || terminal.irreversible().funding_authorized
            || terminal.irreversible().adaptor_secret_exposed
            || !terminal.irreversible().any_signing_share_sent
        {
            return Err(SessionStoreError::Quarantined);
        }
        let round = self.audit_xmr_graph_signing_round_at_v23(&binding, &terminal, None)?;
        if round.accepted_messages.len() != 6 {
            return Err(SessionStoreError::Quarantined);
        }
        let mut nonces = Vec::with_capacity(2);
        let mut partials = Vec::with_capacity(2);
        for index in 0..2 {
            let reveal_message =
                ParsedTransportEnvelopeV1::parse(&round.accepted_messages[index + 2])
                    .map_err(|_| SessionStoreError::Quarantined)?;
            let reveal = NonceRevealV1::from_bytes(
                reveal_message.payload(&round.accepted_messages[index + 2])?,
            )
            .map_err(|_| SessionStoreError::Quarantined)?;
            let participant = &binding.origin.roster.entries()[index];
            nonces.push(ParticipantPublicNoncesV1 {
                participant_index: reveal.participant_index(),
                signing_key: participant.signing_public_key().clone(),
                first_nonce: reveal.first().clone(),
                second_nonce: reveal.second().clone(),
            });
            let message = ParsedTransportEnvelopeV1::parse(&round.accepted_messages[index + 4])
                .map_err(|_| SessionStoreError::Quarantined)?;
            partials.push(
                PartialSignatureV1::from_bytes(
                    message.payload(&round.accepted_messages[index + 4])?,
                )
                .map_err(|_| SessionStoreError::Quarantined)?,
            );
        }
        nonces.sort_by_key(|nonce| nonce.participant_index);
        partials.sort_by_key(PartialSignatureV1::participant_index);
        let reveal = self
            .load_session_revision(
                session,
                binding
                    .start
                    .revision()
                    .checked_add(4)
                    .ok_or(SessionStoreError::CapacityExceeded)?,
            )?
            .transcript_hash();
        Ok((nonces, partials, reveal))
    }
}
