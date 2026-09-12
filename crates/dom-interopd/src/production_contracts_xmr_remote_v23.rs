//! Move-only XMR remote-sweep transport face over the exact retained
//! Contracts Store and Relay opening. Extracted from the owner file: the
//! owner surface guard forbids raw payload bytes and direct SignedMessage
//! decoding there, and this face is precisely the audited place where the
//! canonical 0x19/0x1a transcripts are reconstructed from durable commits.
//! Claim response publication additionally carries the live actuator veto
//! through signing, Store commit and durable Relay staging.
use super::*;
fn with_xmr_claim_publication_veto_v24<T>(
    guard: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    operation: impl FnOnce(&mut dyn FnMut() -> bool) -> Result<T, ChildAuthorityRefusalV1>,
) -> Result<T, ChildAuthorityRefusalV1> {
    let mut refused = None;
    let mut veto = || {
        if refused.is_some() {
            return false;
        }
        match guard() {
            Ok(()) => true,
            Err(error) => {
                refused = Some(error);
                false
            }
        }
    };
    let result = operation(&mut veto);
    match refused {
        Some(error) => Err(error),
        None => result,
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_commit_and_stage_xmr_response_v24<F: F6TransportPortV1>(
    session_id: [u8; 32],
    local_participant: [u8; 32],
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    relay: &Rc<RefCell<DurableRelayWorkerV1<F>>>,
    request: PreparedDsc1SigningRequestV1,
    expiry: TimelockSpec,
    guard: &mut Option<&mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>>,
) -> Result<RouteApplicationDispositionV2, ChildAuthorityRefusalV1> {
    if request.session_id() != &session_id
        || request.sender_id() != &local_participant
        || request.message_type() != 0x1a
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let outbound = match guard.as_mut() {
        Some(guard) => with_xmr_claim_publication_veto_v24(*guard, |veto| {
            identity
                .sign_and_commit_xmr_claim_response_guarded_v24(store, request, veto)
                .map_err(ProductionContractsOutboundErrorV1::from)
                .map_err(map_remote_transport_error)
        })?,
        None => identity
            .sign_and_commit_store_prepared_dsc1(store, request)
            .map_err(ProductionContractsOutboundErrorV1::from)
            .map_err(map_remote_transport_error)?,
    };
    stage_xmr_response_v24(relay, outbound, expiry, guard)
}

fn stage_xmr_response_v24<F: F6TransportPortV1>(
    relay: &Rc<RefCell<DurableRelayWorkerV1<F>>>,
    outbound: dom_scriptless_store::CommittedOutboundDsc1V1,
    expiry: TimelockSpec,
    guard: &mut Option<&mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>>,
) -> Result<RouteApplicationDispositionV2, ChildAuthorityRefusalV1> {
    let mut relay = relay
        .try_borrow_mut()
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    match guard.as_mut() {
        Some(guard) => with_xmr_claim_publication_veto_v24(*guard, |veto| {
            relay
                .stage_xmr_claim_response_guarded_v24(outbound, expiry, veto)
                .map_err(ProductionContractsOutboundErrorV1::from)
                .map_err(map_remote_transport_error)
        }),
        None => relay
            .stage_store_outbound_dsc1(outbound, expiry)
            .map_err(ProductionContractsOutboundErrorV1::from)
            .map_err(map_remote_transport_error),
    }
}
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
    pub(super) last_transport_time_v24: Cell<u64>,
    pub(super) action_v24: xmr_remote_sweep_wire::RemoteSweepActionV23,
}

// Relay time is Unix time, never the economic Monero block-height deadline.
// Same one-hour operational TTL as the bootstrap/F7 transport. Existing
// application rows retain their first expiry in DurableRelaySenderV1; this
// value is used only when creating an application, never to rewrite a replay.
fn xmr_transport_expiry_v24(
    now: u64,
    floor: Option<u64>,
    last: u64,
) -> Result<TimelockSpec, ChildAuthorityRefusalV1> {
    if now == 0 || now < last || floor.is_some_and(|floor| now < floor) {
        return Err(ChildAuthorityRefusalV1::Unavailable);
    }
    Ok(TimelockSpec::TimestampSeconds {
        value: now
            .checked_add(3600)
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?,
    })
}

#[cfg(test)]
mod transport_clock_tests_v24 {
    use super::*;

    #[test]
    fn claim_commit_veto_uses_post_signing_time_and_retains_original_error() {
        use std::cell::Cell;
        let now = Cell::new(1099);
        let writes = Cell::new(0);
        let mut guard = || {
            if now.get() < 1100 {
                Ok(())
            } else {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
        };
        assert_eq!(guard(), Ok(()));
        let result = with_xmr_claim_publication_veto_v24(&mut guard, |veto| {
            // Simulate the time consumed by identity signing and SQL/Store
            // authentication. The producer must consult the guard HERE.
            now.set(1100);
            if !veto() {
                return Err(ChildAuthorityRefusalV1::Unavailable);
            }
            writes.set(writes.get() + 1);
            Ok(())
        });
        assert_eq!(result, Err(ChildAuthorityRefusalV1::Conflict));
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn a_failed_publication_veto_cannot_be_revived_inside_one_commit() {
        let mut checks = 0;
        let mut guard = || {
            checks += 1;
            if checks == 1 {
                Err(ChildAuthorityRefusalV1::Unavailable)
            } else {
                Ok(())
            }
        };
        assert_eq!(
            with_xmr_claim_publication_veto_v24(&mut guard, |veto| {
                assert!(!veto());
                assert!(!veto());
                Ok(())
            }),
            Err(ChildAuthorityRefusalV1::Unavailable)
        );
        assert_eq!(checks, 1);
    }

    #[test]
    fn xmr_envelope_ttl_uses_relay_timestamp_not_chain_height() {
        assert_eq!(
            xmr_transport_expiry_v24(1_900_000_000, Some(1_899_999_999), 1_900_000_000),
            Ok(TimelockSpec::TimestampSeconds {
                value: 1_900_003_600
            })
        );
    }

    #[test]
    fn xmr_envelope_clock_refuses_zero_backwards_and_overflow() {
        for (now, floor, last) in [
            (0, None, 0),
            (9, Some(10), 0),
            (9, None, 10),
            (u64::MAX, None, 0),
        ] {
            assert_eq!(
                xmr_transport_expiry_v24(now, floor, last),
                Err(ChildAuthorityRefusalV1::Unavailable)
            );
        }
    }
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
    fn require_action_v24(&self, bytes: &[u8]) -> Result<(), ChildAuthorityRefusalV1> {
        let request = xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if request.action != self.action_v24
            || request.session_id != self.session_id
            || request.route_id != self.route_id
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn transport_expiry_v24(&self) -> Result<TimelockSpec, ChildAuthorityRefusalV1> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?
            .as_secs();
        let floor = self
            .relay
            .try_borrow()
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?
            .retained_timestamp_floor()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let expiry = xmr_transport_expiry_v24(now, floor, self.last_transport_time_v24.get())?;
        self.last_transport_time_v24.set(now);
        Ok(expiry)
    }

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
            self.require_action_v24(accepted.payload())?;
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
        self.require_action_v24(prepared.request_payload())?;
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
        let expiry = self.transport_expiry_v24()?;
        let request = xmr_remote_sweep_wire::RemoteSweepRequestV23::decode_exact(request_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if request.action != self.action_v24
            || request.session_id != self.session_id
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
                            expiry,
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
                            .stage_store_outbound_dsc1(*committed, expiry)
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
                    expiry,
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
            self.require_action_v24(&request)?;
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
        if request.action != self.action_v24
            || request.route_id != self.route_id
            || request.session_id != self.session_id
        {
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
        if self.action_v24 == xmr_remote_sweep_wire::RemoteSweepActionV23::Claim {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.publish_response_inner_v24(accepted, response_bytes, None)
    }
    fn reconcile_response_v23(
        &mut self,
        response_bytes: &[u8],
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if self.action_v24 == xmr_remote_sweep_wire::RemoteSweepActionV23::Claim {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.reconcile_response_inner_v24(response_bytes, None)
    }
    fn publish_claim_response_guarded_v24(
        &mut self,
        accepted: &AcceptedXmrRemoteSweepRequestV23,
        response_bytes: &[u8],
        before_publication: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if self.action_v24 != xmr_remote_sweep_wire::RemoteSweepActionV23::Claim {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.publish_response_inner_v24(accepted, response_bytes, Some(before_publication))
    }
    fn reconcile_claim_response_guarded_v24(
        &mut self,
        response_bytes: &[u8],
        before_publication: &mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if self.action_v24 != xmr_remote_sweep_wire::RemoteSweepActionV23::Claim {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.reconcile_response_inner_v24(response_bytes, Some(before_publication))
    }
}

impl<F: F6TransportPortV1> ProductionXmrRemoteContractsAuthorityV23<F> {
    fn publish_response_inner_v24(
        &mut self,
        accepted: &AcceptedXmrRemoteSweepRequestV23,
        response_bytes: &[u8],
        mut before_publication: Option<&mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let expiry = self.transport_expiry_v24()?;
        self.require_action_v24(accepted.payload())?;
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
        // This immutable SigningRequest is LOCAL preparation only. A later
        // live-custody veto may leave it for byte-exact retry; it must not
        // create a signed DSC1 transcript edge or Relay frame. The caller has
        // already bound these public proof bytes to its retained XMR sweep.
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
        sign_commit_and_stage_xmr_response_v24(
            self.session_id,
            self.local_participant,
            self.store.as_ref(),
            self.identity.as_ref(),
            &self.relay,
            prepared,
            expiry,
            &mut before_publication,
        )?;
        Ok(())
    }

    fn reconcile_response_inner_v24(
        &mut self,
        response_bytes: &[u8],
        mut before_publication: Option<&mut dyn FnMut() -> Result<(), ChildAuthorityRefusalV1>>,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let expiry = self.transport_expiry_v24()?;
        let response = xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(response_bytes)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if response.request_message_digest() == [0; 32] {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.responder_request_and_completed_response_v23(response.request_message_digest())?;
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
                sign_commit_and_stage_xmr_response_v24(
                    self.session_id,
                    self.local_participant,
                    self.store.as_ref(),
                    self.identity.as_ref(),
                    &self.relay,
                    *prepared,
                    expiry,
                    &mut before_publication,
                )?;
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
                stage_xmr_response_v24(&self.relay, *committed, expiry, &mut before_publication)?;
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
                if let Some(guard) = before_publication.as_mut() {
                    guard()?;
                }
                Ok(())
            }
        }
    }
}
