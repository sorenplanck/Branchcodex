//! Move-only XMR remote-sweep transport face over the exact retained
//! Contracts Store and Relay opening. Extracted from the owner file: the
//! owner surface guard forbids raw payload bytes and direct SignedMessage
//! decoding there, and this face is precisely the audited place where the
//! canonical 0x19/0x1a transcripts are reconstructed from durable commits.
//! Behaviour is unchanged; only the file boundary moved.
use super::*;
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1};
/// Move-only XMR transport face over the exact retained Contracts Store and
/// Relay opening. It can stage only canonical 0x19 and import only the Store's
/// linearly paired 0x1a token; it has no Monero signing or broadcast access.
pub(crate) struct ProductionXmrRemoteContractsAuthorityV23<F>
where
    F: F6TransportPortV1,
{
    pub(super) session_id: [u8; 32],
    pub(super) route_id: [u8; 32],
    pub(super) local_participant: [u8; 32],
    pub(super) remote_participant: [u8; 32],
    pub(super) store: Rc<ContractsSessionStoreV1>,
    pub(super) identity: Rc<ContractsTransportIdentityStoreV1>,
    pub(super) relay: Rc<RefCell<DurableRelayWorkerV1<F>>>,
    pub(super) expiry: TimelockSpec,
}

impl<F> core::fmt::Debug for ProductionXmrRemoteContractsAuthorityV23<F>
where
    F: F6TransportPortV1,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionXmrRemoteContractsAuthorityV23([authority redacted])")
    }
}

impl<F> ProductionXmrRemoteContractsAuthorityV23<F>
where
    F: F6TransportPortV1,
{
    fn responder_request_and_completed_response_v23(
        &self,
        request_message_digest: [u8; 32],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), ChildAuthorityRefusalV1> {
        if let Some(accepted) = self
            .store
            .resume_pending_xmr_remote_sweep_request_for_local_signer(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?
        {
            if accepted.message_digest() != &request_message_digest {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
            return Ok((accepted.payload().to_vec(), None));
        }
        let completed = self
            .store
            .resume_completed_xmr_remote_sweep_response_for_local_signer(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?
            .ok_or(ChildAuthorityRefusalV1::Conflict)?;
        if completed.request_message_digest() != &request_message_digest {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let prepared = self
            .store
            .take_xmr_remote_sweep_for_import(completed)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?;
        Ok((
            prepared.request_payload().to_vec(),
            Some(prepared.response_payload().to_vec()),
        ))
    }
}

impl<F> crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteSweepTransportV23
    for ProductionXmrRemoteContractsAuthorityV23<F>
where
    F: F6TransportPortV1,
{
    fn exchange_or_resume_v23(
        &mut self,
        request_bytes: &[u8],
        request_wire_digest: [u8; 32],
    ) -> Result<PreparedXmrRemoteSweepImportV23, ChildAuthorityRefusalV1> {
        let request = xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(request_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if request.session_id != self.session_id
            || request.route_id != self.route_id
            || request
                .digest()
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                != request_wire_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }

        // A restart must reuse the first durable 0x19. Its F7 evidence digest
        // is observation-time sensitive, so discover by authenticated local
        // identity/session and compare every stable field before exact resume.
        let request_bytes = match self
            .store
            .resume_xmr_remote_sweep_request_for_local_requester(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })? {
            Some(retained) => {
                if retained.session_id() != &self.session_id
                    || retained.requester_id() != &self.local_participant
                    || retained.signer_id() != &self.remote_participant
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let retained_request =
                    xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(retained.payload())
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                crate::production_xmr_remote_sweep_v23::require_stable_xmr_remote_request_retry_v23(
                    &retained_request,
                    &request,
                )?;
                retained.payload().to_vec()
            }
            None => request_bytes.to_vec(),
        };

        let request_message_digest = match self.store.resume_xmr_remote_sweep_request_exact(
            self.session_id,
            self.local_participant,
            &request_bytes,
        ) {
            Ok(accepted) => {
                if accepted.session_id() != &self.session_id
                    || accepted.requester_id() != &self.local_participant
                    || accepted.signer_id() != &self.remote_participant
                    || accepted.payload() != request_bytes.as_slice()
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let digest = *accepted.message_digest();
                match self
                    .store
                    .resume_outbound_dsc1(self.session_id)
                    .map_err(|error| {
                        map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
                    })? {
                    OutboundDsc1RecoveryV1::SigningRequest(prepared)
                        if prepared.message_type() == 0x19
                            && prepared.unsigned_message_digest() == &digest
                            && prepared.payload() == request_bytes.as_slice() =>
                    {
                        sign_commit_and_stage_with_shared_relay(
                            self.session_id,
                            self.local_participant,
                            self.store.as_ref(),
                            self.identity.as_ref(),
                            &self.relay,
                            *prepared,
                            self.expiry,
                        )
                        .map_err(map_remote_transport_error)?;
                    }
                    OutboundDsc1RecoveryV1::Committed(committed)
                        if committed.message_digest() == &digest =>
                    {
                        let signed = SignedMessageV1::decode_exact(committed.signed_bytes())
                            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                        if committed.session_id() != &self.session_id
                            || committed.sender_id() != &self.local_participant
                            || signed.unsigned().kind() != MessageTypeV1::XmrRemoteSweepRequestV23
                            || signed.unsigned().session_id() != &self.session_id
                            || signed.unsigned().sender_id() != &self.local_participant
                            || signed.unsigned().payload() != request_bytes.as_slice()
                        {
                            return Err(ChildAuthorityRefusalV1::Conflict);
                        }
                        self.relay
                            .try_borrow_mut()
                            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?
                            .stage_store_outbound_dsc1(*committed, self.expiry)
                            .map_err(ProductionContractsOutboundErrorV1::from)
                            .map_err(map_remote_transport_error)?;
                    }
                    OutboundDsc1RecoveryV1::None => {}
                    OutboundDsc1RecoveryV1::SigningRequest(_)
                    | OutboundDsc1RecoveryV1::Committed(_) => {
                        return Err(ChildAuthorityRefusalV1::Unavailable)
                    }
                }
                digest
            }
            Err(SessionStoreError::SessionNotFound) => {
                let prepared = self
                    .store
                    .prepare_xmr_remote_sweep_request_dsc1_signing_request(
                        self.session_id,
                        &request_bytes,
                    )
                    .map_err(|error| {
                        map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
                    })?;
                if prepared.message_type() != 0x19
                    || prepared.session_id() != &self.session_id
                    || prepared.sender_id() != &self.local_participant
                    || prepared.payload() != request_bytes.as_slice()
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let digest = *prepared.unsigned_message_digest();
                sign_commit_and_stage_with_shared_relay(
                    self.session_id,
                    self.local_participant,
                    self.store.as_ref(),
                    self.identity.as_ref(),
                    &self.relay,
                    prepared,
                    self.expiry,
                )
                .map_err(map_remote_transport_error)?;
                digest
            }
            Err(error) => {
                return Err(map_remote_transport_error(
                    ProductionContractsOutboundErrorV1::Store(error),
                ))
            }
        };

        let accepted = match self.store.resume_xmr_remote_sweep_response_for_request(
            self.session_id,
            self.remote_participant,
            request_message_digest,
        ) {
            Ok(accepted) => accepted,
            Err(SessionStoreError::SessionNotFound) => {
                return Err(ChildAuthorityRefusalV1::Unavailable)
            }
            Err(error) => {
                return Err(map_remote_transport_error(
                    ProductionContractsOutboundErrorV1::Store(error),
                ))
            }
        };
        if accepted.session_id() != &self.session_id
            || accepted.request_message_digest() != &request_message_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.store
            .take_xmr_remote_sweep_for_import(accepted)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })
    }
}

impl<F> crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteSweepResponderTransportV23
    for ProductionXmrRemoteContractsAuthorityV23<F>
where
    F: F6TransportPortV1,
{
    fn poll_request_v23(
        &mut self,
    ) -> Result<
        crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23,
        ChildAuthorityRefusalV1,
    > {
        // Recover the response journal before discovery: once a peer has
        // accepted 0x1a, discovery correctly reports no unanswered 0x19, but
        // the local Relay handoff may still need byte-identical reconciliation.
        match self
            .store
            .resume_outbound_dsc1(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })? {
            OutboundDsc1RecoveryV1::SigningRequest(prepared) => {
                if prepared.message_type() != 0x1a
                    || prepared.session_id() != &self.session_id
                    || prepared.sender_id() != &self.local_participant
                {
                    return Err(ChildAuthorityRefusalV1::Unavailable);
                }
                let response =
                    xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(prepared.payload())
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                if response.request_message_digest() == [0; 32] {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let (request, completed_response) = self
                    .responder_request_and_completed_response_v23(
                        response.request_message_digest(),
                    )?;
                if let Some(completed) = completed_response {
                    if completed.as_slice() != prepared.payload() {
                        return Err(ChildAuthorityRefusalV1::Conflict);
                    }
                }
                return Ok(crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23::RetainedResponse {
                    request,
                    response: prepared.payload().to_vec(),
                });
            }
            OutboundDsc1RecoveryV1::Committed(committed) => {
                let signed = SignedMessageV1::decode_exact(committed.signed_bytes())
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                if committed.session_id() != &self.session_id
                    || committed.sender_id() != &self.local_participant
                    || signed.unsigned().kind() != MessageTypeV1::XmrRemoteSweepResponseV23
                    || signed.unsigned().session_id() != &self.session_id
                    || signed.unsigned().sender_id() != &self.local_participant
                {
                    return Err(ChildAuthorityRefusalV1::Unavailable);
                }
                let response = xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(
                    signed.unsigned().payload(),
                )
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                if response.request_message_digest() == [0; 32] {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let (request, completed_response) = self
                    .responder_request_and_completed_response_v23(
                        response.request_message_digest(),
                    )?;
                if let Some(completed) = completed_response {
                    if completed.as_slice() != signed.unsigned().payload() {
                        return Err(ChildAuthorityRefusalV1::Conflict);
                    }
                }
                return Ok(crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23::RetainedResponse {
                    request,
                    response: signed.unsigned().payload().to_vec(),
                });
            }
            OutboundDsc1RecoveryV1::None => {}
        }
        if let Some(completed) = self
            .store
            .resume_completed_xmr_remote_sweep_response_for_local_signer(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?
        {
            let prepared = self
                .store
                .take_xmr_remote_sweep_for_import(completed)
                .map_err(|error| {
                    map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
                })?;
            let (request, response) = prepared.into_payloads();
            return Ok(crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23::RetainedResponse {
                request,
                response,
            });
        }
        let Some(accepted) = self
            .store
            .resume_pending_xmr_remote_sweep_request_for_local_signer(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?
        else {
            return Ok(crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23::NoRequest);
        };
        if accepted.session_id() != &self.session_id
            || accepted.requester_id() != &self.remote_participant
            || accepted.signer_id() != &self.local_participant
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let request =
            xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(accepted.payload())
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if request.route_id != self.route_id || request.session_id != self.session_id {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(
            crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteResponderPollV23::Request(
                accepted,
            ),
        )
    }

    fn publish_response_v23(
        &mut self,
        accepted: &AcceptedXmrRemoteSweepRequestV23,
        response_bytes: &[u8],
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if accepted.session_id() != &self.session_id
            || accepted.requester_id() != &self.remote_participant
            || accepted.signer_id() != &self.local_participant
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let request =
            xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(accepted.payload())
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let response = xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(response_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        response
            .validate_for_authenticated_request(&request, *accepted.message_digest())
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let prepared = self
            .store
            .prepare_xmr_remote_sweep_response_dsc1_signing_request(accepted, response_bytes)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })?
            .ok_or(ChildAuthorityRefusalV1::Conflict)?;
        if prepared.message_type() != 0x1a
            || prepared.session_id() != &self.session_id
            || prepared.sender_id() != &self.local_participant
            || prepared.payload() != response_bytes
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        sign_commit_and_stage_with_shared_relay(
            self.session_id,
            self.local_participant,
            self.store.as_ref(),
            self.identity.as_ref(),
            &self.relay,
            prepared,
            self.expiry,
        )
        .map_err(map_remote_transport_error)?;
        Ok(())
    }

    fn reconcile_response_v23(
        &mut self,
        response_bytes: &[u8],
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let response = xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(response_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if response.request_message_digest() == [0; 32] {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        match self
            .store
            .resume_outbound_dsc1(self.session_id)
            .map_err(|error| {
                map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
            })? {
            OutboundDsc1RecoveryV1::SigningRequest(prepared) => {
                if prepared.message_type() != 0x1a
                    || prepared.session_id() != &self.session_id
                    || prepared.sender_id() != &self.local_participant
                    || prepared.payload() != response_bytes
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                sign_commit_and_stage_with_shared_relay(
                    self.session_id,
                    self.local_participant,
                    self.store.as_ref(),
                    self.identity.as_ref(),
                    &self.relay,
                    *prepared,
                    self.expiry,
                )
                .map_err(map_remote_transport_error)?;
                Ok(())
            }
            OutboundDsc1RecoveryV1::Committed(committed) => {
                let signed = SignedMessageV1::decode_exact(committed.signed_bytes())
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                if committed.session_id() != &self.session_id
                    || committed.sender_id() != &self.local_participant
                    || signed.unsigned().kind() != MessageTypeV1::XmrRemoteSweepResponseV23
                    || signed.unsigned().session_id() != &self.session_id
                    || signed.unsigned().sender_id() != &self.local_participant
                    || signed.unsigned().payload() != response_bytes
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?
                    .stage_store_outbound_dsc1(*committed, self.expiry)
                    .map_err(ProductionContractsOutboundErrorV1::from)
                    .map_err(map_remote_transport_error)?;
                Ok(())
            }
            OutboundDsc1RecoveryV1::None => {
                let completed = self
                    .store
                    .resume_completed_xmr_remote_sweep_response_for_local_signer(self.session_id)
                    .map_err(|error| {
                        map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
                    })?
                    .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
                let prepared = self
                    .store
                    .take_xmr_remote_sweep_for_import(completed)
                    .map_err(|error| {
                        map_remote_transport_error(ProductionContractsOutboundErrorV1::Store(error))
                    })?;
                if prepared.response_payload() != response_bytes {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(())
            }
        }
    }
}
