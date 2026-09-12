//! Authenticated network face for the durable production Relay.
//!
//! The application protocol in this module deliberately adds no cryptographic
//! primitive.  It runs inside the existing Contracts-keystore-owned Noise XX
//! channel and composes the Relay's session-scoped V3 delivery pages with its durable
//! idempotent submission API.  A source delivery cursor advances only after
//! the peer reports that every exact envelope in the page was accepted by its
//! own durable [`ProductionRelayV1`].

#[path = "production_noise_hello_v22.rs"]
mod hello_v22;
#[path = "production_noise_recovery_v23.rs"]
mod recovery_v23;

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use dom_scriptless_store::SessionTransportIdentityReferenceV1;
use dom_scriptless_transport::{EncryptedTransportV1, NoiseRoleV1, MAX_MESSAGE_LEN_V1};
use relay::{
    production::{
        DeliveryCursorV3, DeliveryPageLimitsV3, DeliveryPageV3, DeliveryScopeV3, ProductionRelayV1,
        RelayDatabaseIdV1, DELIVERY_CURSOR_V3_LEN,
    },
    server::IdempotencyKeyV1,
    ParticipantId, RelayEnvelopeV1,
};

const WIRE_MAGIC_V1: &[u8; 8] = b"DOMNRLY1";
const WIRE_VERSION_V1: u16 = 1;
const WIRE_HEADER_LEN_V1: usize = 8 + 2 + 1 + 1 + (32 * 7);
const HELLO_BODY_LEN_V1: usize = 2 + 4 + 2;
const RECEIPT_BODY_LEN_V1: usize = DELIVERY_CURSOR_V3_LEN + 2;
const DONE_BODY_LEN_V1: usize = 1 + 2;
const PAGE_LENGTH_PREFIX_V1: usize = 4;

const NETWORK_PAGE_MAX_ITEMS_V1: u16 = 32;
const NETWORK_PAGE_MAX_BYTES_V1: u32 = 512 * 1024;
const NETWORK_MAX_PAGES_PER_DIRECTION_V1: u16 = 8;
const NETWORK_MAX_PAGE_WIRE_BYTES_V1: usize = 8
    + 2
    + (DELIVERY_CURSOR_V3_LEN * 2)
    + 1
    + 2
    + 4
    + (NETWORK_PAGE_MAX_ITEMS_V1 as usize * 12)
    + NETWORK_PAGE_MAX_BYTES_V1 as usize;
const NETWORK_MAX_FRAME_BYTES_V1: usize =
    WIRE_HEADER_LEN_V1 + PAGE_LENGTH_PREFIX_V1 + NETWORK_MAX_PAGE_WIRE_BYTES_V1;
const MIN_EXCHANGE_TIMEOUT_V1: Duration = Duration::from_millis(100);
const MAX_EXCHANGE_TIMEOUT_V1: Duration = Duration::from_secs(300);

const _: () = assert!(NETWORK_MAX_FRAME_BYTES_V1 <= MAX_MESSAGE_LEN_V1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKindV1 {
    Hello = 1,
    Page = 2,
    Persisted = 3,
    Done = 4,
    Refused = 5,
    GraphOfferV22 = 6,
    RecoveryScopesV23 = 7,
}

impl FrameKindV1 {
    fn decode(value: u8) -> Result<Self, ProductionNoiseRelayErrorV1> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Page),
            3 => Ok(Self::Persisted),
            4 => Ok(Self::Done),
            5 => Ok(Self::Refused),
            6 => Ok(Self::GraphOfferV22),
            7 => Ok(Self::RecoveryScopesV23),
            _ => Err(ProductionNoiseRelayErrorV1::ProtocolRefused),
        }
    }
}

/// Fail-closed, payload-redacted refusal from the production network face.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionNoiseRelayErrorV1 {
    /// Session, identity, database or timeout inputs were not exact.
    #[error("production Noise Relay configuration is invalid")]
    InvalidConfiguration,
    /// The retained Contracts identity failed revalidation or peer binding.
    #[error("production Noise Relay identity authentication failed")]
    IdentityAuthenticationFailed,
    /// The bounded TCP or Noise channel failed.
    #[error("production Noise Relay channel is unavailable")]
    ChannelUnavailable,
    /// The local durable Relay refused a read, persistence or acknowledgement.
    #[error("production Noise Relay durable storage is unavailable")]
    DurableRelayUnavailable,
    /// The peer sent a non-canonical or context-divergent application frame.
    #[error("production Noise Relay protocol was refused")]
    ProtocolRefused,
    /// The authenticated peer refused the current transfer without details.
    #[error("production Noise Relay peer refused the transfer")]
    PeerRefused,
}

/// Exact authenticated session and retained-database scope of one connection.
///
/// Both identity references are expected to come directly from
/// `ContractsSessionStoreV1::transport_identity_references`.  This type never
/// accepts or exposes either transport private key. Relay delivery state is
/// durably scoped to this exact recipient, route and session.
pub(crate) struct ProductionNoiseRelaySessionV1 {
    cancelled_v22: Option<Box<ProductionNoiseRelaySessionV1>>,
    graph_v22: Option<ProductionNoiseGraphOfferV22>,
    recovery_v23: Option<Box<[ProductionNoiseRelaySessionV1; 2]>>,
    role: NoiseRoleV1,
    chain_id: [u8; 32],
    network_id: [u8; 32],
    route_id: [u8; 32],
    session_id: [u8; 32],
    local_reference: SessionTransportIdentityReferenceV1,
    remote_reference: SessionTransportIdentityReferenceV1,
    expected_local_relay: RelayDatabaseIdV1,
    expected_remote_relay: RelayDatabaseIdV1,
    exchange_timeout: Duration,
}

/// Four immutable route identifiers already authenticated by the production
/// bootstrap and Contracts session records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionNoiseRelayRouteContextV1 {
    chain_id: [u8; 32],
    network_id: [u8; 32],
    route_id: [u8; 32],
    session_id: [u8; 32],
}

impl ProductionNoiseRelayRouteContextV1 {
    pub(crate) fn new(
        chain_id: [u8; 32],
        network_id: [u8; 32],
        route_id: [u8; 32],
        session_id: [u8; 32],
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        if chain_id == [0; 32]
            || network_id == [0; 32]
            || route_id == [0; 32]
            || session_id == [0; 32]
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            chain_id,
            network_id,
            route_id,
            session_id,
        })
    }
}

/// The two distinct retained Relay database identities pinned for one peer
/// link by production configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionNoiseRelayDatabasePairV1 {
    local: RelayDatabaseIdV1,
    remote: RelayDatabaseIdV1,
}

impl ProductionNoiseRelayDatabasePairV1 {
    pub(crate) fn new(
        local: RelayDatabaseIdV1,
        remote: RelayDatabaseIdV1,
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        if local == remote {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        Ok(Self { local, remote })
    }
}

impl core::fmt::Debug for ProductionNoiseRelaySessionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionNoiseRelaySessionV1")
            .field("role", &self.role)
            .field("context", &"[authenticated]")
            .field("identity_references", &"[authenticated public references]")
            .field("relay_databases", &"[authenticated public references]")
            .field("exchange_timeout", &self.exchange_timeout)
            .finish()
    }
}

impl ProductionNoiseRelaySessionV1 {
    /// Freezes one already-authenticated two-party connection scope.
    pub(crate) fn new(
        role: NoiseRoleV1,
        context: ProductionNoiseRelayRouteContextV1,
        identity_references: [SessionTransportIdentityReferenceV1; 2],
        relay_databases: ProductionNoiseRelayDatabasePairV1,
        exchange_timeout: Duration,
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        let [local_reference, remote_reference] = identity_references;
        if local_reference.participant_id() == remote_reference.participant_id()
            || local_reference.key_reference() == remote_reference.key_reference()
            || local_reference.noise_public_key() == remote_reference.noise_public_key()
            || !(MIN_EXCHANGE_TIMEOUT_V1..=MAX_EXCHANGE_TIMEOUT_V1).contains(&exchange_timeout)
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            cancelled_v22: None,
            graph_v22: None,
            recovery_v23: None,
            role,
            chain_id: context.chain_id,
            network_id: context.network_id,
            route_id: context.route_id,
            session_id: context.session_id,
            local_reference,
            remote_reference,
            expected_local_relay: relay_databases.local,
            expected_remote_relay: relay_databases.remote,
            exchange_timeout,
        })
    }

    /// Attach only the canonical XMR D scope with exactly the same peers and
    /// databases. Both scopes are exchanged on every connection, regardless of
    /// local protocol phase, so restart does not require a synchronized switch.
    pub(crate) fn with_xmr_cancelled_v22(
        mut self,
        cancelled: Self,
        parent_terms: [u8; 32],
    ) -> Result<Self, ProductionNoiseRelayErrorV1> {
        let expected = dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(
            &self.chain_id,
            &self.session_id,
            &parent_terms,
        );
        if parent_terms == [0; 32]
            || self.cancelled_v22.is_some()
            || cancelled.cancelled_v22.is_some()
            || cancelled.graph_v22.is_some()
            || cancelled.recovery_v23.is_some()
            || cancelled.session_id != expected
            || cancelled.session_id == self.session_id
            || cancelled.role != self.role
            || cancelled.chain_id != self.chain_id
            || cancelled.network_id != self.network_id
            || cancelled.route_id != self.route_id
            || cancelled.local_reference != self.local_reference
            || cancelled.remote_reference != self.remote_reference
            || cancelled.expected_local_relay != self.expected_local_relay
            || cancelled.expected_remote_relay != self.expected_remote_relay
            || cancelled.exchange_timeout != self.exchange_timeout
        {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        self.cancelled_v22 = Some(Box::new(cancelled));
        Ok(self)
    }

    /// Confirms that the network sidecar selected the only permitted socket
    /// operation/Noise role and the exact peer Relay database for this
    /// authenticated session. The network runtime performs this check before
    /// opening, binding, connecting or accepting any socket.
    pub(crate) fn matches_network_binding(
        &self,
        role: NoiseRoleV1,
        remote_relay: RelayDatabaseIdV1,
    ) -> bool {
        self.role == role && self.expected_remote_relay == remote_relay
    }

    /// Establishes Noise XX over an already-connected TCP socket and performs
    /// one bounded, bidirectional store-and-forward exchange.
    pub(crate) fn exchange(
        &self,
        identity: &ContractsTransportIdentityStoreV1,
        relay: &mut ProductionRelayV1,
        stream: TcpStream,
    ) -> Result<ProductionNoiseRelayExchangeReportV1, ProductionNoiseRelayErrorV1> {
        if relay.database_id() != self.expected_local_relay {
            return Err(ProductionNoiseRelayErrorV1::InvalidConfiguration);
        }
        let stream = DeadlineTcpStreamV1::new(stream, self.exchange_timeout)?;
        let mut transport = identity
            .establish_noise_for_session(
                stream,
                self.role,
                self.chain_id,
                self.session_id,
                &self.local_reference,
                &self.remote_reference,
            )
            .map_err(|_| ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed)?;

        let mut report = self.exchange_pages(&mut transport, relay)?;
        if let Some(cancelled) = self.cancelled_v22.as_ref() {
            let extra = cancelled.exchange_pages(&mut transport, relay)?;
            report.pages_sent += extra.pages_sent;
            report.envelopes_sent += extra.envelopes_sent;
            report.outbound_backlog_remains |= extra.outbound_backlog_remains;
            report.pages_received += extra.pages_received;
            report.envelopes_received += extra.envelopes_received;
            report.inbound_backlog_remains |= extra.inbound_backlog_remains;
        }
        if self.graph_v22.is_some() && self.exchange_recovery_scopes_v23(&mut transport)? {
            let children = self
                .recovery_v23
                .as_ref()
                .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
            for child in children.iter() {
                let extra = child.exchange_pages(&mut transport, relay)?;
                report.pages_sent += extra.pages_sent;
                report.envelopes_sent += extra.envelopes_sent;
                report.outbound_backlog_remains |= extra.outbound_backlog_remains;
                report.pages_received += extra.pages_received;
                report.envelopes_received += extra.envelopes_received;
                report.inbound_backlog_remains |= extra.inbound_backlog_remains;
            }
        }
        Ok(report)
    }

    fn exchange_pages(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        relay: &mut ProductionRelayV1,
    ) -> Result<ProductionNoiseRelayExchangeReportV1, ProductionNoiseRelayErrorV1> {
        if let Err(error) = self.exchange_hello(transport) {
            self.send_refusal(transport);
            return Err(error);
        }
        let graph_candidate_v22 = self
            .graph_v22
            .as_ref()
            .map(|graph| self.exchange_graph_offer_v22(transport, graph))
            .transpose()?;
        let (sent, received) = match self.role {
            NoiseRoleV1::Initiator => {
                let sent = self.send_direction(transport, relay)?;
                let received = self.receive_direction(transport, relay)?;
                (sent, received)
            }
            NoiseRoleV1::Responder => {
                let received = self.receive_direction(transport, relay)?;
                let sent = self.send_direction(transport, relay)?;
                (sent, received)
            }
        };
        Ok(ProductionNoiseRelayExchangeReportV1 {
            graph_candidate_v22,
            pages_sent: sent.pages,
            envelopes_sent: sent.envelopes,
            outbound_backlog_remains: sent.backlog_remains,
            pages_received: received.pages,
            envelopes_received: received.envelopes,
            inbound_backlog_remains: received.backlog_remains,
        })
    }

    fn exchange_hello(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        match self.role {
            NoiseRoleV1::Initiator => {
                self.send_hello(transport)?;
                self.receive_hello(transport)
            }
            NoiseRoleV1::Responder => {
                self.receive_hello(transport)?;
                self.send_hello(transport)
            }
        }
    }

    fn send_hello(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let body = hello_v22::hello_body_v22(
            self.cancelled_v22.as_ref().map(|c| &c.session_id),
            self.graph_v22.is_some(),
        )?;
        self.send_frame(transport, FrameKindV1::Hello, &body)
    }

    fn receive_hello(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let bytes = self.receive_frame_bytes(transport)?;
        let frame = self.decode_remote_frame(&bytes)?;
        if frame.kind == FrameKindV1::Refused {
            return Err(ProductionNoiseRelayErrorV1::PeerRefused);
        }
        if frame.kind != FrameKindV1::Hello {
            return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
        }
        hello_v22::verify_hello_body_v22(
            frame.body,
            self.cancelled_v22.as_ref().map(|c| &c.session_id),
            self.graph_v22.is_some(),
        )
    }

    fn send_direction(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        relay: &mut ProductionRelayV1,
    ) -> Result<DirectionReportV1, ProductionNoiseRelayErrorV1> {
        let recipient = ParticipantId(*self.remote_reference.participant_id());
        let scope = DeliveryScopeV3::new(recipient, self.route_id, self.session_id)
            .map_err(|_| ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
        let limits = network_page_limits()?;
        let mut current = relay
            .acknowledged_delivery_cursor_v3(&scope)
            .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
        let mut pages = 0_u16;
        let mut envelopes = 0_u32;
        let backlog_remains;

        loop {
            let page = relay
                .delivery_page_v3(&scope, &current, limits)
                .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            let canonical = page
                .canonical_bytes()
                .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            let item_count = u16::try_from(page.envelopes().len())
                .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            let next = *page.next_cursor();
            let has_more = page.has_more();
            let body = encode_page_body(&canonical)?;
            self.send_frame(transport, FrameKindV1::Page, &body)?;
            self.receive_persisted_receipt(transport, &next, item_count)?;

            let durable_ack = relay
                .acknowledge_delivery_page_v3(&scope, &next)
                .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            if durable_ack.cursor() != &next {
                return Err(ProductionNoiseRelayErrorV1::DurableRelayUnavailable);
            }
            pages = pages
                .checked_add(1)
                .ok_or(ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            envelopes = envelopes
                .checked_add(u32::from(item_count))
                .ok_or(ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
            current = next;
            if !has_more || pages == NETWORK_MAX_PAGES_PER_DIRECTION_V1 {
                backlog_remains = has_more;
                break;
            }
        }
        let mut done = [0_u8; DONE_BODY_LEN_V1];
        done[0] = u8::from(backlog_remains);
        done[1..].copy_from_slice(&pages.to_be_bytes());
        self.send_frame(transport, FrameKindV1::Done, &done)?;
        Ok(DirectionReportV1 {
            pages,
            envelopes,
            backlog_remains,
        })
    }

    fn receive_persisted_receipt(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        expected_cursor: &DeliveryCursorV3,
        expected_items: u16,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let bytes = self.receive_frame_bytes(transport)?;
        let frame = self.decode_remote_frame(&bytes)?;
        if frame.kind == FrameKindV1::Refused {
            return Err(ProductionNoiseRelayErrorV1::PeerRefused);
        }
        if frame.kind != FrameKindV1::Persisted || frame.body.len() != RECEIPT_BODY_LEN_V1 {
            return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
        }
        let cursor = DeliveryCursorV3::decode(&frame.body[..DELIVERY_CURSOR_V3_LEN])
            .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
        let items = take_u16(frame.body, DELIVERY_CURSOR_V3_LEN)?;
        if &cursor != expected_cursor || items != expected_items {
            return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
        }
        Ok(())
    }

    fn receive_direction(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        relay: &mut ProductionRelayV1,
    ) -> Result<DirectionReportV1, ProductionNoiseRelayErrorV1> {
        let limits = network_page_limits()?;
        let mut pages = 0_u16;
        let mut envelopes = 0_u32;
        let mut previous_next = None;
        let mut last_has_more = None;
        loop {
            let bytes = self.receive_frame_bytes(transport)?;
            let frame = self.decode_remote_frame(&bytes)?;
            match frame.kind {
                FrameKindV1::Page => {
                    if pages == NETWORK_MAX_PAGES_PER_DIRECTION_V1 || last_has_more == Some(false) {
                        self.send_refusal(transport);
                        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
                    }
                    let page = match decode_page_body(frame.body, limits) {
                        Ok(page) => page,
                        Err(error) => {
                            self.send_refusal(transport);
                            return Err(error);
                        }
                    };
                    if let Err(error) = self.validate_received_page(&page, previous_next.as_ref()) {
                        self.send_refusal(transport);
                        return Err(error);
                    }
                    for raw in page.envelopes() {
                        if let Err(error) = self.persist_received_envelope(relay, raw) {
                            self.send_refusal(transport);
                            return Err(error);
                        }
                    }
                    let item_count = u16::try_from(page.envelopes().len())
                        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
                    self.send_persisted_receipt(transport, page.next_cursor(), item_count)?;
                    pages = pages
                        .checked_add(1)
                        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?;
                    envelopes = envelopes
                        .checked_add(u32::from(item_count))
                        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?;
                    previous_next = Some(*page.next_cursor());
                    last_has_more = Some(page.has_more());
                }
                FrameKindV1::Done => {
                    let backlog_remains = match decode_done(frame.body, pages, last_has_more) {
                        Ok(value) => value,
                        Err(error) => {
                            self.send_refusal(transport);
                            return Err(error);
                        }
                    };
                    return Ok(DirectionReportV1 {
                        pages,
                        envelopes,
                        backlog_remains,
                    });
                }
                FrameKindV1::Refused => {
                    return Err(ProductionNoiseRelayErrorV1::PeerRefused);
                }
                FrameKindV1::Hello
                | FrameKindV1::Persisted
                | FrameKindV1::GraphOfferV22
                | FrameKindV1::RecoveryScopesV23 => {
                    self.send_refusal(transport);
                    return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
                }
            }
        }
    }

    fn validate_received_page(
        &self,
        page: &DeliveryPageV3,
        previous_next: Option<&DeliveryCursorV3>,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let local = ParticipantId(*self.local_reference.participant_id());
        if page.current_cursor().database_id() != self.expected_remote_relay
            || page.next_cursor().database_id() != self.expected_remote_relay
            || page.current_cursor().scope().recipient_id() != local
            || page.next_cursor().scope().recipient_id() != local
            || page.current_cursor().scope().route_id() != &self.route_id
            || page.next_cursor().scope().route_id() != &self.route_id
            || page.current_cursor().scope().session_id() != &self.session_id
            || page.next_cursor().scope().session_id() != &self.session_id
            || previous_next.is_some_and(|cursor| cursor != page.current_cursor())
        {
            return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
        }
        for raw in page.envelopes() {
            let envelope = RelayEnvelopeV1::decode(raw)
                .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
            let canonical = envelope
                .canonical_bytes()
                .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
            if envelope.network_id != self.network_id
                || envelope.route_id != self.route_id
                || envelope.session_id != self.session_id
                || envelope.sender_id.0 != *self.remote_reference.participant_id()
                || envelope.recipient_id.0 != *self.local_reference.participant_id()
                || canonical.as_slice() != raw.as_slice()
            {
                return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
            }
        }
        Ok(())
    }

    fn persist_received_envelope(
        &self,
        relay: &mut ProductionRelayV1,
        raw: &[u8],
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let envelope = RelayEnvelopeV1::decode(raw)
            .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
        let expected_key = IdempotencyKeyV1::of(&envelope);
        let expected_digest = envelope
            .envelope_digest()
            .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
        let ack = relay
            .submit(raw)
            .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
        if ack.key != expected_key || ack.digest != expected_digest {
            return Err(ProductionNoiseRelayErrorV1::DurableRelayUnavailable);
        }
        Ok(())
    }

    fn send_persisted_receipt(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        cursor: &DeliveryCursorV3,
        item_count: u16,
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let mut body = Vec::with_capacity(RECEIPT_BODY_LEN_V1);
        body.extend_from_slice(&cursor.canonical_bytes());
        body.extend_from_slice(&item_count.to_be_bytes());
        self.send_frame(transport, FrameKindV1::Persisted, &body)
    }

    fn send_refusal(&self, transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>) {
        let _refusal_delivery = self.send_frame(transport, FrameKindV1::Refused, &[]);
    }

    fn send_frame(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
        kind: FrameKindV1,
        body: &[u8],
    ) -> Result<(), ProductionNoiseRelayErrorV1> {
        let frame = encode_frame(
            kind,
            FrameContextV1 {
                chain_id: self.chain_id,
                network_id: self.network_id,
                route_id: self.route_id,
                session_id: self.session_id,
                sender: *self.local_reference.participant_id(),
                recipient: *self.remote_reference.participant_id(),
                relay_database: self.expected_local_relay,
            },
            body,
        )?;
        transport
            .send_message(&frame)
            .map_err(|_| ProductionNoiseRelayErrorV1::ChannelUnavailable)
    }

    fn receive_frame_bytes(
        &self,
        transport: &mut EncryptedTransportV1<DeadlineTcpStreamV1>,
    ) -> Result<Vec<u8>, ProductionNoiseRelayErrorV1> {
        transport
            .receive_message()
            .map_err(|_| ProductionNoiseRelayErrorV1::ChannelUnavailable)
    }

    fn decode_remote_frame<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<DecodedFrameV1<'a>, ProductionNoiseRelayErrorV1> {
        decode_frame(
            bytes,
            FrameContextV1 {
                chain_id: self.chain_id,
                network_id: self.network_id,
                route_id: self.route_id,
                session_id: self.session_id,
                sender: *self.remote_reference.participant_id(),
                recipient: *self.local_reference.participant_id(),
                relay_database: self.expected_remote_relay,
            },
        )
    }
}

#[path = "production_noise_graph_offer_v22.rs"]
mod graph_offer_v22;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use graph_offer_v22::SignedNativeGraphFixtureV23;
pub(crate) use graph_offer_v22::{
    ProductionNoiseGraphOfferV22, ProductionReceivedXmrGraphCandidateV22,
    ProductionXmrGraphPublicMaterialV22,
};

/// Bounded counters plus an optional public candidate, redacted in Debug.
/// A candidate does not acknowledge durable graph acceptance or funding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductionNoiseRelayExchangeReportV1 {
    pub(crate) graph_candidate_v22: Option<ProductionReceivedXmrGraphCandidateV22>,
    pub(crate) pages_sent: u16,
    pub(crate) envelopes_sent: u32,
    pub(crate) outbound_backlog_remains: bool,
    pub(crate) pages_received: u16,
    pub(crate) envelopes_received: u32,
    pub(crate) inbound_backlog_remains: bool,
}

#[derive(Clone, Copy)]
struct FrameContextV1 {
    chain_id: [u8; 32],
    network_id: [u8; 32],
    route_id: [u8; 32],
    session_id: [u8; 32],
    sender: [u8; 32],
    recipient: [u8; 32],
    relay_database: RelayDatabaseIdV1,
}

struct DecodedFrameV1<'a> {
    kind: FrameKindV1,
    body: &'a [u8],
}

#[derive(Clone, Copy)]
struct DirectionReportV1 {
    pages: u16,
    envelopes: u32,
    backlog_remains: bool,
}

fn encode_frame(
    kind: FrameKindV1,
    context: FrameContextV1,
    body: &[u8],
) -> Result<Vec<u8>, ProductionNoiseRelayErrorV1> {
    let total = WIRE_HEADER_LEN_V1
        .checked_add(body.len())
        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    if total > NETWORK_MAX_FRAME_BYTES_V1 || total > MAX_MESSAGE_LEN_V1 {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(WIRE_MAGIC_V1);
    out.extend_from_slice(&WIRE_VERSION_V1.to_be_bytes());
    out.push(kind as u8);
    out.push(0);
    out.extend_from_slice(&context.chain_id);
    out.extend_from_slice(&context.network_id);
    out.extend_from_slice(&context.route_id);
    out.extend_from_slice(&context.session_id);
    out.extend_from_slice(&context.sender);
    out.extend_from_slice(&context.recipient);
    out.extend_from_slice(context.relay_database.as_bytes());
    out.extend_from_slice(body);
    if out.len() != total {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    Ok(out)
}

fn decode_frame<'a>(
    bytes: &'a [u8],
    expected: FrameContextV1,
) -> Result<DecodedFrameV1<'a>, ProductionNoiseRelayErrorV1> {
    if bytes.len() < WIRE_HEADER_LEN_V1 || bytes.len() > NETWORK_MAX_FRAME_BYTES_V1 {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    if &bytes[..8] != WIRE_MAGIC_V1
        || take_u16(bytes, 8)? != WIRE_VERSION_V1
        || bytes[11] != 0
        || bytes[12..44] != expected.chain_id
        || bytes[44..76] != expected.network_id
        || bytes[76..108] != expected.route_id
        || bytes[108..140] != expected.session_id
        || bytes[140..172] != expected.sender
        || bytes[172..204] != expected.recipient
        || bytes[204..236] != *expected.relay_database.as_bytes()
    {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    let kind = FrameKindV1::decode(bytes[10])?;
    let body = &bytes[WIRE_HEADER_LEN_V1..];
    if kind == FrameKindV1::Refused && !body.is_empty() {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    Ok(DecodedFrameV1 { kind, body })
}

fn encode_page_body(page: &[u8]) -> Result<Vec<u8>, ProductionNoiseRelayErrorV1> {
    if page.is_empty() || page.len() > NETWORK_MAX_PAGE_WIRE_BYTES_V1 {
        return Err(ProductionNoiseRelayErrorV1::DurableRelayUnavailable);
    }
    let length = u32::try_from(page.len())
        .map_err(|_| ProductionNoiseRelayErrorV1::DurableRelayUnavailable)?;
    let mut out = Vec::with_capacity(PAGE_LENGTH_PREFIX_V1 + page.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(page);
    Ok(out)
}

fn decode_page_body(
    body: &[u8],
    limits: DeliveryPageLimitsV3,
) -> Result<DeliveryPageV3, ProductionNoiseRelayErrorV1> {
    if body.len() < PAGE_LENGTH_PREFIX_V1
        || body.len() > PAGE_LENGTH_PREFIX_V1 + NETWORK_MAX_PAGE_WIRE_BYTES_V1
    {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    let length = usize::try_from(take_u32(body, 0)?)
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    if length == 0
        || length > NETWORK_MAX_PAGE_WIRE_BYTES_V1
        || body.len() != PAGE_LENGTH_PREFIX_V1 + length
    {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    DeliveryPageV3::decode(&body[PAGE_LENGTH_PREFIX_V1..], limits)
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)
}

fn decode_done(
    body: &[u8],
    received_pages: u16,
    last_has_more: Option<bool>,
) -> Result<bool, ProductionNoiseRelayErrorV1> {
    if body.len() != DONE_BODY_LEN_V1 || received_pages == 0 {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    let backlog_remains = match body[0] {
        0 => false,
        1 => true,
        _ => return Err(ProductionNoiseRelayErrorV1::ProtocolRefused),
    };
    if take_u16(body, 1)? != received_pages
        || last_has_more != Some(backlog_remains)
        || (backlog_remains && received_pages != NETWORK_MAX_PAGES_PER_DIRECTION_V1)
    {
        return Err(ProductionNoiseRelayErrorV1::ProtocolRefused);
    }
    Ok(backlog_remains)
}

fn network_page_limits() -> Result<DeliveryPageLimitsV3, ProductionNoiseRelayErrorV1> {
    DeliveryPageLimitsV3::new(NETWORK_PAGE_MAX_ITEMS_V1, NETWORK_PAGE_MAX_BYTES_V1)
        .map_err(|_| ProductionNoiseRelayErrorV1::InvalidConfiguration)
}

fn take_u16(bytes: &[u8], offset: usize) -> Result<u16, ProductionNoiseRelayErrorV1> {
    let end = offset
        .checked_add(2)
        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    let exact: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?
        .try_into()
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    Ok(u16::from_be_bytes(exact))
}

fn take_u32(bytes: &[u8], offset: usize) -> Result<u32, ProductionNoiseRelayErrorV1> {
    let end = offset
        .checked_add(4)
        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    let exact: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(ProductionNoiseRelayErrorV1::ProtocolRefused)?
        .try_into()
        .map_err(|_| ProductionNoiseRelayErrorV1::ProtocolRefused)?;
    Ok(u32::from_be_bytes(exact))
}

struct DeadlineTcpStreamV1 {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineTcpStreamV1 {
    fn new(stream: TcpStream, timeout: Duration) -> Result<Self, ProductionNoiseRelayErrorV1> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ProductionNoiseRelayErrorV1::InvalidConfiguration)?;
        stream
            .set_nodelay(true)
            .map_err(|_| ProductionNoiseRelayErrorV1::ChannelUnavailable)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| ProductionNoiseRelayErrorV1::ChannelUnavailable)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| ProductionNoiseRelayErrorV1::ChannelUnavailable)?;
        Ok(Self { stream, deadline })
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "production Noise Relay exchange deadline elapsed",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for DeadlineTcpStreamV1 {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineTcpStreamV1 {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.flush()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use dom_scriptless_identity_store::{
        ContractsIdentityPassphraseV1, ContractsTransportIdentityReferenceV1,
    };
    use relay::{
        auth::message_type,
        production::{RelayDatabaseConfigV1, RelayDatabaseIdV1},
        SenderRoleV1, TimelockSpec,
    };
    use std::{
        error::Error, fs::File as AmbientFile, net::TcpListener, os::unix::fs::PermissionsExt,
        path::Path, sync::Arc, thread,
    };
    use tempfile::TempDir;

    mod negotiation_v22_tests {
        include!("production_noise_negotiation_v22_tests.rs");
    }

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    const CHAIN: [u8; 32] = [0x11; 32];
    const NETWORK: [u8; 32] = [0x12; 32];
    const ROUTE: [u8; 32] = [0x13; 32];
    const SESSION: [u8; 32] = [0x14; 32];
    const ALICE: [u8; 32] = [0x21; 32];
    const BOB: [u8; 32] = [0x22; 32];

    struct IdentityFixtureV1 {
        parent: Arc<Dir>,
        alice_identity: ContractsTransportIdentityReferenceV1,
        bob_identity: ContractsTransportIdentityReferenceV1,
        alice_session: SessionTransportIdentityReferenceV1,
        bob_session: SessionTransportIdentityReferenceV1,
    }

    fn passphrase() -> Result<ContractsIdentityPassphraseV1, Box<dyn Error + Send + Sync>> {
        Ok(ContractsIdentityPassphraseV1::new(
            b"production Noise Relay identity test passphrase".to_vec(),
        )?)
    }

    fn open_parent(path: &Path) -> Result<Arc<Dir>, Box<dyn Error + Send + Sync>> {
        Ok(Arc::new(Dir::from_std_file(AmbientFile::open(path)?)))
    }

    fn relay_config(
        marker: u8,
        capacity: u32,
    ) -> Result<RelayDatabaseConfigV1, Box<dyn Error + Send + Sync>> {
        Ok(RelayDatabaseConfigV1::new(
            RelayDatabaseIdV1::new([marker; 32])?,
            capacity,
        )?)
    }

    fn envelope(
        sender: [u8; 32],
        recipient: [u8; 32],
        sequence: u64,
        marker: u8,
    ) -> Result<(IdempotencyKeyV1, Vec<u8>), Box<dyn Error + Send + Sync>> {
        let envelope = RelayEnvelopeV1 {
            network_id: NETWORK,
            message_type: message_type::QUOTE,
            session_id: SESSION,
            route_id: ROUTE,
            sender_id: ParticipantId(sender),
            recipient_id: ParticipantId(recipient),
            sender_role: SenderRoleV1::Solver,
            sequence,
            previous_transcript_hash: [0; 32],
            payload: vec![marker; 64],
            expiry: TimelockSpec::TimestampSeconds {
                value: 1_900_000_000,
            },
            policy_version: 1,
            roster_snapshot: [0x31; 32],
            signature: [marker; 64],
        };
        let key = IdempotencyKeyV1::of(&envelope);
        Ok((key, envelope.canonical_bytes()?))
    }

    fn identity_references(
        temporary: &TempDir,
    ) -> Result<IdentityFixtureV1, Box<dyn Error + Send + Sync>> {
        let parent = open_parent(temporary.path())?;
        let alice = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "alice-identity",
            &passphrase()?,
        )?;
        let bob = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "bob-identity",
            &passphrase()?,
        )?;
        let alice_identity = *alice.reference();
        let bob_identity = *bob.reference();
        let alice_session = alice_identity.bind_session_participant(ALICE)?;
        let bob_session = bob_identity.bind_session_participant(BOB)?;
        drop(alice);
        drop(bob);
        Ok(IdentityFixtureV1 {
            parent,
            alice_identity,
            bob_identity,
            alice_session,
            bob_session,
        })
    }

    fn session(
        role: NoiseRoleV1,
        local_reference: SessionTransportIdentityReferenceV1,
        remote_reference: SessionTransportIdentityReferenceV1,
        local_relay: RelayDatabaseIdV1,
        remote_relay: RelayDatabaseIdV1,
    ) -> Result<ProductionNoiseRelaySessionV1, ProductionNoiseRelayErrorV1> {
        ProductionNoiseRelaySessionV1::new(
            role,
            ProductionNoiseRelayRouteContextV1::new(CHAIN, NETWORK, ROUTE, SESSION)?,
            [local_reference, remote_reference],
            ProductionNoiseRelayDatabasePairV1::new(local_relay, remote_relay)?,
            Duration::from_secs(30),
        )
    }

    #[test]
    fn loopback_persists_before_source_ack_and_preserves_source_on_backpressure() -> TestResult {
        let temporary = TempDir::new()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let identities = identity_references(&temporary)?;
        let parent = identities.parent;
        let alice_identity = identities.alice_identity;
        let bob_identity = identities.bob_identity;
        let alice_reference = identities.alice_session;
        let bob_reference = identities.bob_session;

        let alice_config = relay_config(0x41, 64)?;
        let bob_config = relay_config(0x42, 64)?;
        let alice_root = temporary.path().join("alice-relay");
        let bob_root = temporary.path().join("bob-relay");
        let (alice_out_key, alice_out) = envelope(ALICE, BOB, 0, 0x51)?;
        let (bob_out_key, bob_out) = envelope(BOB, ALICE, 0, 0x52)?;
        let mut alice_relay = ProductionRelayV1::create(&alice_root, alice_config)?;
        let mut bob_relay = ProductionRelayV1::create(&bob_root, bob_config)?;
        alice_relay.submit(&alice_out)?;
        bob_relay.submit(&bob_out)?;
        drop(alice_relay);
        drop(bob_relay);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let responder_parent = Arc::clone(&parent);
        let responder_alice_reference = alice_reference.clone();
        let responder_bob_reference = bob_reference.clone();
        let responder_bob_root = bob_root.clone();
        let responder = thread::spawn(move || -> TestResult {
            let identity = ContractsTransportIdentityStoreV1::open_production(
                responder_parent,
                "bob-identity",
                &passphrase()?,
            )?;
            if identity.reference() != &bob_identity {
                return Err("wrong reopened responder identity".into());
            }
            let mut relay = ProductionRelayV1::open(&responder_bob_root, bob_config)?;
            let (stream, _) = listener.accept()?;
            let report = session(
                NoiseRoleV1::Responder,
                responder_bob_reference,
                responder_alice_reference,
                bob_config.database_id(),
                alice_config.database_id(),
            )?
            .exchange(&identity, &mut relay, stream)?;
            assert_eq!(report.pages_sent, 1);
            assert_eq!(report.envelopes_sent, 1);
            assert_eq!(report.pages_received, 1);
            assert_eq!(report.envelopes_received, 1);
            assert!(!report.outbound_backlog_remains);
            assert!(!report.inbound_backlog_remains);
            assert_eq!(relay.stored_bytes(&alice_out_key)?, Some(alice_out));
            assert_eq!(relay.stored_bytes(&bob_out_key)?, None);
            Ok(())
        });

        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&parent),
            "alice-identity",
            &passphrase()?,
        )?;
        assert_eq!(identity.reference(), &alice_identity);
        let mut relay = ProductionRelayV1::open(&alice_root, alice_config)?;
        let report = session(
            NoiseRoleV1::Initiator,
            alice_reference.clone(),
            bob_reference.clone(),
            alice_config.database_id(),
            bob_config.database_id(),
        )?
        .exchange(&identity, &mut relay, TcpStream::connect(address)?)?;
        assert_eq!(report.pages_sent, 1);
        assert_eq!(report.envelopes_sent, 1);
        assert_eq!(report.pages_received, 1);
        assert_eq!(report.envelopes_received, 1);
        assert_eq!(relay.stored_bytes(&alice_out_key)?, None);
        assert_eq!(relay.stored_bytes(&bob_out_key)?, Some(bob_out));
        responder
            .join()
            .map_err(|_| io::Error::other("responder thread panicked"))??;

        let source_config = relay_config(0x43, 8)?;
        let full_config = relay_config(0x44, 1)?;
        let source_root = temporary.path().join("backpressure-source");
        let full_root = temporary.path().join("backpressure-full");
        let (blocked_key, blocked) = envelope(ALICE, BOB, 0, 0x61)?;
        let (_, occupying) = envelope([0x81; 32], [0x82; 32], 0, 0x62)?;
        let mut source = ProductionRelayV1::create(&source_root, source_config)?;
        let mut full = ProductionRelayV1::create(&full_root, full_config)?;
        source.submit(&blocked)?;
        full.submit(&occupying)?;
        drop(source);
        drop(full);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let responder_parent = Arc::clone(&parent);
        let responder = thread::spawn(move || -> TestResult {
            let identity = ContractsTransportIdentityStoreV1::open_production(
                responder_parent,
                "bob-identity",
                &passphrase()?,
            )?;
            let mut relay = ProductionRelayV1::open(&full_root, full_config)?;
            let (stream, _) = listener.accept()?;
            let error = session(
                NoiseRoleV1::Responder,
                bob_reference,
                alice_reference,
                full_config.database_id(),
                source_config.database_id(),
            )?
            .exchange(&identity, &mut relay, stream)
            .expect_err("full destination must refuse before a network receipt");
            assert_eq!(error, ProductionNoiseRelayErrorV1::DurableRelayUnavailable);
            Ok(())
        });
        let mut source = ProductionRelayV1::open(&source_root, source_config)?;
        let error = session(
            NoiseRoleV1::Initiator,
            identity.reference().bind_session_participant(ALICE)?,
            bob_identity.bind_session_participant(BOB)?,
            source_config.database_id(),
            full_config.database_id(),
        )?
        .exchange(&identity, &mut source, TcpStream::connect(address)?)
        .expect_err("source must observe the peer refusal");
        assert_eq!(error, ProductionNoiseRelayErrorV1::PeerRefused);
        assert_eq!(source.stored_bytes(&blocked_key)?, Some(blocked));
        let blocked_scope = DeliveryScopeV3::new(ParticipantId(BOB), ROUTE, SESSION)?;
        assert_eq!(
            source
                .acknowledged_delivery_cursor_v3(&blocked_scope)?
                .position(),
            0
        );
        responder
            .join()
            .map_err(|_| io::Error::other("backpressure thread panicked"))??;
        Ok(())
    }

    fn cancelled_session(
        role: NoiseRoleV1,
        local: SessionTransportIdentityReferenceV1,
        remote: SessionTransportIdentityReferenceV1,
        local_db: RelayDatabaseIdV1,
        remote_db: RelayDatabaseIdV1,
    ) -> Result<ProductionNoiseRelaySessionV1, ProductionNoiseRelayErrorV1> {
        let parent = session(role, local.clone(), remote.clone(), local_db, remote_db)?;
        let mut child = session(role, local, remote, local_db, remote_db)?;
        child.session_id = dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(
            &CHAIN,
            &SESSION,
            &[0x71; 32],
        );
        parent.with_xmr_cancelled_v22(child, [0x71; 32])
    }

    #[test]
    fn cancelled_scope_shares_one_noise_connection_and_restarts_without_cross_delivery(
    ) -> TestResult {
        let temporary = TempDir::new()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let refs = identity_references(&temporary)?;
        let alice_config = relay_config(0xa1, 32)?;
        let bob_config = relay_config(0xa2, 32)?;
        let alice_root = temporary.path().join("cancelled-alice-relay");
        let bob_root = temporary.path().join("cancelled-bob-relay");
        let d = dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(
            &CHAIN,
            &SESSION,
            &[0x71; 32],
        );
        let packets = |sender, recipient| -> Result<Vec<_>, Box<dyn Error + Send + Sync>> {
            [SESSION, d]
                .into_iter()
                .map(|scope| {
                    let (_, raw) = envelope(sender, recipient, 0, 0x73)?;
                    let mut decoded = RelayEnvelopeV1::decode(&raw)?;
                    decoded.session_id = scope;
                    Ok((IdempotencyKeyV1::of(&decoded), decoded.canonical_bytes()?))
                })
                .collect()
        };
        let alice_packets = packets(ALICE, BOB)?;
        let bob_packets = packets(BOB, ALICE)?;
        let mut alice = ProductionRelayV1::create(&alice_root, alice_config)?;
        let mut bob = ProductionRelayV1::create(&bob_root, bob_config)?;
        for (_, raw) in &alice_packets {
            alice.submit(raw)?;
        }
        for (_, raw) in &bob_packets {
            bob.submit(raw)?;
        }
        drop(alice);
        drop(bob);

        // Mismatched auxiliary scopes are refused before any socket is opened.
        let parent = session(
            NoiseRoleV1::Initiator,
            refs.alice_session.clone(),
            refs.bob_session.clone(),
            alice_config.database_id(),
            bob_config.database_id(),
        )?;
        let child = session(
            NoiseRoleV1::Initiator,
            refs.alice_session.clone(),
            refs.bob_session.clone(),
            alice_config.database_id(),
            bob_config.database_id(),
        )?;
        assert!(parent.with_xmr_cancelled_v22(child, [0x71; 32]).is_err());

        for round in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let bob_parent = Arc::clone(&refs.parent);
            let remote_alice = refs.alice_session.clone();
            let remote_bob = refs.bob_session.clone();
            let remote_root = bob_root.clone();
            let expected_received = alice_packets.clone();
            let expected_sent = bob_packets.clone();
            let responder = thread::spawn(move || -> TestResult {
                let identity = ContractsTransportIdentityStoreV1::open_production(
                    bob_parent,
                    "bob-identity",
                    &passphrase()?,
                )?;
                let mut relay = ProductionRelayV1::open(&remote_root, bob_config)?;
                let (stream, _) = listener.accept()?;
                let report = cancelled_session(
                    NoiseRoleV1::Responder,
                    remote_bob,
                    remote_alice,
                    bob_config.database_id(),
                    alice_config.database_id(),
                )?
                .exchange(&identity, &mut relay, stream)?;
                assert_eq!((report.pages_sent, report.pages_received), (2, 2));
                let count = if round == 0 { 2 } else { 0 };
                assert_eq!(
                    (report.envelopes_sent, report.envelopes_received),
                    (count, count)
                );
                for (key, bytes) in expected_received {
                    assert_eq!(relay.stored_bytes(&key)?, Some(bytes));
                }
                for (key, _) in expected_sent {
                    assert_eq!(relay.stored_bytes(&key)?, None);
                }
                Ok(())
            });
            let identity = ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&refs.parent),
                "alice-identity",
                &passphrase()?,
            )?;
            let mut relay = ProductionRelayV1::open(&alice_root, alice_config)?;
            let report = cancelled_session(
                NoiseRoleV1::Initiator,
                refs.alice_session.clone(),
                refs.bob_session.clone(),
                alice_config.database_id(),
                bob_config.database_id(),
            )?
            .exchange(&identity, &mut relay, TcpStream::connect(address)?)?;
            assert_eq!((report.pages_sent, report.pages_received), (2, 2));
            let count = if round == 0 { 2 } else { 0 };
            assert_eq!(
                (report.envelopes_sent, report.envelopes_received),
                (count, count)
            );
            for (key, bytes) in &bob_packets {
                assert_eq!(relay.stored_bytes(key)?, Some(bytes.clone()));
            }
            for (key, _) in &alice_packets {
                assert_eq!(relay.stored_bytes(key)?, None);
            }
            responder
                .join()
                .map_err(|_| io::Error::other("cancelled responder panicked"))??;
        }

        // A legacy/misconfigured peer must be rejected during Hello, before
        // even the C page is acknowledged. Pending source bytes survive.
        let (_, blocked_raw) = envelope(ALICE, BOB, 1, 0x74)?;
        let mut blocked_envelope = RelayEnvelopeV1::decode(&blocked_raw)?;
        blocked_envelope.previous_transcript_hash =
            RelayEnvelopeV1::decode(&alice_packets[0].1)?.envelope_digest()?;
        let blocked_key = IdempotencyKeyV1::of(&blocked_envelope);
        let blocked = blocked_envelope.canonical_bytes()?;
        {
            let mut relay = ProductionRelayV1::open(&alice_root, alice_config)?;
            relay.submit(&blocked)?;
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let remote_parent = Arc::clone(&refs.parent);
        let remote_alice = refs.alice_session.clone();
        let remote_bob = refs.bob_session.clone();
        let responder = thread::spawn(move || -> TestResult {
            let identity = ContractsTransportIdentityStoreV1::open_production(
                remote_parent,
                "bob-identity",
                &passphrase()?,
            )?;
            let mut relay = ProductionRelayV1::open(&bob_root, bob_config)?;
            let (stream, _) = listener.accept()?;
            let error = session(
                NoiseRoleV1::Responder,
                remote_bob,
                remote_alice,
                bob_config.database_id(),
                alice_config.database_id(),
            )?
            .exchange(&identity, &mut relay, stream)
            .expect_err("missing D negotiation must fail before pages");
            assert_eq!(error, ProductionNoiseRelayErrorV1::ProtocolRefused);
            Ok(())
        });
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&refs.parent),
            "alice-identity",
            &passphrase()?,
        )?;
        let mut relay = ProductionRelayV1::open(&alice_root, alice_config)?;
        assert!(cancelled_session(
            NoiseRoleV1::Initiator,
            refs.alice_session,
            refs.bob_session,
            alice_config.database_id(),
            bob_config.database_id(),
        )?
        .exchange(&identity, &mut relay, TcpStream::connect(address)?)
        .is_err());
        assert_eq!(relay.stored_bytes(&blocked_key)?, Some(blocked));
        responder
            .join()
            .map_err(|_| io::Error::other("legacy responder panicked"))??;
        Ok(())
    }

    #[test]
    fn canonical_frame_decoder_refuses_context_transplant_and_noncanonical_done() -> TestResult {
        let local = RelayDatabaseIdV1::new([0x71; 32])?;
        let context = FrameContextV1 {
            chain_id: CHAIN,
            network_id: NETWORK,
            route_id: ROUTE,
            session_id: SESSION,
            sender: ALICE,
            recipient: BOB,
            relay_database: local,
        };
        let frame = encode_frame(FrameKindV1::Hello, context, &[0; HELLO_BODY_LEN_V1])?;
        assert_eq!(decode_frame(&frame, context)?.kind, FrameKindV1::Hello);
        let refused_with_body = encode_frame(FrameKindV1::Refused, context, &[0x73])?;
        let refused_error = match decode_frame(&refused_with_body, context) {
            Ok(_) => return Err("non-canonical refusal body was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(refused_error, ProductionNoiseRelayErrorV1::ProtocolRefused);
        let mut transplanted = context;
        transplanted.route_id = [0x72; 32];
        let transplanted_error = match decode_frame(&frame, transplanted) {
            Ok(_) => return Err("route transplant was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            transplanted_error,
            ProductionNoiseRelayErrorV1::ProtocolRefused
        );
        assert_eq!(
            decode_done(&[0, 0, 1], 1, Some(true))
                .expect_err("done flag must equal the pinned page"),
            ProductionNoiseRelayErrorV1::ProtocolRefused
        );
        assert_eq!(
            decode_done(&[1, 0, 1], 1, Some(true)).expect_err("early truncation must fail"),
            ProductionNoiseRelayErrorV1::ProtocolRefused
        );
        Ok(())
    }
}
