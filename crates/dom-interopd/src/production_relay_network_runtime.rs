//! Bounded TCP composition root for one authenticated production Relay link.
//!
//! The owner-only network sidecar remains the sole authority for both the
//! numeric socket address and the Noise XX role. This module opens exactly one
//! TCP connection per call, then delegates authentication and application
//! exchange to [`ProductionNoiseRelaySessionV1`]. No application byte is sent
//! before that session completes its existing authenticated Noise handshake.

use std::{
    io,
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use relay::production::ProductionRelayV1;

use crate::{
    production_noise_relay::{
        ProductionNoiseRelayErrorV1, ProductionNoiseRelayExchangeReportV1,
        ProductionNoiseRelaySessionV1,
    },
    production_relay_network_config::{
        ProductionRelayEndpointModeV1, ProductionRelayNetworkLinkV1,
    },
};

const MIN_SOCKET_TIMEOUT_V1: Duration = Duration::from_millis(25);
const MAX_SOCKET_TIMEOUT_V1: Duration = Duration::from_secs(300);
const ACCEPT_POLL_INTERVAL_V1: Duration = Duration::from_millis(5);

/// Redacted refusal from the bounded production Relay socket boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionRelayNetworkRuntimeErrorV1 {
    /// Timeout bounds or the session-to-sidecar binding were not exact.
    #[error("production Relay network runtime configuration is invalid")]
    InvalidConfiguration,
    /// The outbound socket could not connect within its fixed bound.
    #[error("production Relay outbound connection is unavailable")]
    ConnectUnavailable,
    /// The configured local socket could not be bound safely.
    #[error("production Relay listener is unavailable")]
    ListenUnavailable,
    /// No inbound peer arrived before the fixed accept deadline.
    #[error("production Relay accept deadline elapsed")]
    AcceptDeadlineElapsed,
    /// Noise authentication or the bounded application exchange failed.
    #[error("production Relay authenticated exchange failed")]
    AuthenticatedExchangeFailed,
    /// The peer's static identity failed Noise verification.
    #[error("production Relay peer identity authentication was refused")]
    IdentityAuthenticationRefused,
    /// The authenticated peer sent a non-canonical or divergent frame.
    #[error("production Relay authenticated protocol was refused")]
    ProtocolRefused,
    /// The authenticated peer refused the transfer without details.
    #[error("production Relay authenticated peer refused the transfer")]
    PeerRefused,
    /// The authenticated channel could not complete within its deadline.
    #[error("production Relay authenticated channel is temporarily unavailable")]
    ChannelUnavailable,
    /// The retained local Relay could not complete one durable exchange step.
    #[error("production Relay durable exchange authority is temporarily unavailable")]
    DurableRelayUnavailable,
}

/// Independent bounds for establishing one production TCP link.
///
/// The authenticated session owns the separate end-to-end handshake/exchange
/// deadline. Keeping these values separate prevents a stalled accept or
/// connect from consuming an unbounded amount of supervisor time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionRelayNetworkBoundsV1 {
    connect_timeout: Duration,
    accept_timeout: Duration,
}

impl ProductionRelayNetworkBoundsV1 {
    pub(crate) fn new(
        connect_timeout: Duration,
        accept_timeout: Duration,
    ) -> Result<Self, ProductionRelayNetworkRuntimeErrorV1> {
        if !(MIN_SOCKET_TIMEOUT_V1..=MAX_SOCKET_TIMEOUT_V1).contains(&connect_timeout)
            || !(MIN_SOCKET_TIMEOUT_V1..=MAX_SOCKET_TIMEOUT_V1).contains(&accept_timeout)
        {
            return Err(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            connect_timeout,
            accept_timeout,
        })
    }
}

/// Stateless opener for one exact sidecar-selected Relay link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionRelayNetworkRuntimeV1 {
    bounds: ProductionRelayNetworkBoundsV1,
}

impl ProductionRelayNetworkRuntimeV1 {
    pub(crate) const fn new(bounds: ProductionRelayNetworkBoundsV1) -> Self {
        Self { bounds }
    }

    /// Opens exactly one configured TCP link and runs one authenticated,
    /// bounded bidirectional Relay exchange.
    pub(crate) fn exchange_configured_link(
        &self,
        link: &ProductionRelayNetworkLinkV1,
        session: &ProductionNoiseRelaySessionV1,
        identity: &ContractsTransportIdentityStoreV1,
        relay: &mut ProductionRelayV1,
    ) -> Result<ProductionNoiseRelayExchangeReportV1, ProductionRelayNetworkRuntimeErrorV1> {
        self.exchange_configured_link_retained_v25(link, session, identity, relay, &mut None, None)
    }

    /// Same exchange, reusing a listening socket the caller keeps across
    /// rounds.
    ///
    /// A listener bound and dropped inside one accept attempt only exists for
    /// that attempt's window. The peer then has to call `connect` inside that
    /// exact window or be refused, which makes the link a rendezvous between
    /// two independently paced loops. Both sides walk their legs on the same
    /// period, so once an asymmetric delay drifts their phases apart the
    /// windows stop overlapping and neither side ever sees the other again;
    /// both only observe a swallowed "peer unavailable" and retry forever.
    ///
    /// Keeping the listener bound removes the rendezvous: the kernel backlog
    /// holds the peer's connection until this side reaches its next accept,
    /// whenever that happens. Nothing about authentication changes, because
    /// the Noise handshake and the exact-identity checks still run on the
    /// accepted stream exactly as before.
    pub(crate) fn exchange_configured_link_retained_v25(
        &self,
        link: &ProductionRelayNetworkLinkV1,
        session: &ProductionNoiseRelaySessionV1,
        identity: &ContractsTransportIdentityStoreV1,
        relay: &mut ProductionRelayV1,
        retained_listener: &mut Option<TcpListener>,
        sibling_listener: Option<&TcpListener>,
    ) -> Result<ProductionNoiseRelayExchangeReportV1, ProductionRelayNetworkRuntimeErrorV1> {
        if !session.matches_network_binding(link.noise_role(), link.remote_relay_database_id()) {
            return Err(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration);
        }

        if link.mode() == ProductionRelayEndpointModeV1::Connect {
            let stream = self.connect_with_deadline(link.address())?;
            return session
                .exchange(identity, relay, stream)
                .map_err(map_authenticated_exchange_error);
        }

        // The listening side drains backlog corpses inside one unchanged
        // accept window. A retained listener lets the kernel complete a
        // connection while this side is still busy elsewhere; the peer then
        // writes its opening handshake, waits out its own exchange bound and
        // leaves. What stays queued is a socket that already carries bytes,
        // so no test applied *before* the handshake can tell it apart from a
        // live peer. After the handshake the difference is observable: a
        // departed peer leaves the connection at EOF or reset, while an
        // impostor is still there. Only the first is drained; the second
        // keeps its original fatal identity verdict.
        let deadline = Instant::now()
            .checked_add(self.bounds.accept_timeout)
            .ok_or(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration)?;
        loop {
            let stream = self.accept_one_until_v25(
                link.address(),
                retained_listener,
                sibling_listener,
                deadline,
            )?;
            let probe = stream.try_clone().ok();
            match session.exchange(identity, relay, stream) {
                Ok(report) => return Ok(report),
                Err(error) => {
                    let departed = matches!(
                        error,
                        ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed
                            | ProductionNoiseRelayErrorV1::ChannelUnavailable
                    ) && probe.as_ref().is_some_and(peer_has_departed_v25);
                    if departed && Instant::now() < deadline {
                        continue;
                    }
                    return Err(map_authenticated_exchange_error(error));
                }
            }
        }
    }

    fn connect_with_deadline(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        let deadline = Instant::now()
            .checked_add(self.bounds.connect_timeout)
            .ok_or(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable);
            }
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => return Ok(stream),
                Err(_) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable);
                    }
                    thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL_V1));
                }
            }
        }
    }

    fn accept_exactly_one(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        self.accept_exactly_one_retained_v25(address, &mut None)
    }

    /// Accepts exactly one peer, binding the listener only when the caller
    /// holds none yet and leaving it bound afterwards. A caller that passes
    /// `&mut None` gets the original bind-per-attempt behaviour.
    fn accept_exactly_one_retained_v25(
        &self,
        address: std::net::SocketAddr,
        retained: &mut Option<TcpListener>,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        let deadline = Instant::now()
            .checked_add(self.bounds.accept_timeout)
            .ok_or(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration)?;
        self.accept_one_until_v25(address, retained, None, deadline)
    }

    /// The accept step of `accept_exactly_one_retained_v25`, against a caller
    /// deadline so that draining several backlog corpses still consumes one
    /// single accept window.
    fn accept_one_until_v25(
        &self,
        address: std::net::SocketAddr,
        retained: &mut Option<TcpListener>,
        sibling: Option<&TcpListener>,
        deadline: Instant,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        let listener = match retained.as_ref() {
            Some(listener) => listener,
            None => {
                let listener = TcpListener::bind(address)
                    .map_err(|_| ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable)?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable)?;
                retained.insert(listener)
            }
        };

        let outcome = loop {
            match listener.accept() {
                Ok((stream, _peer)) => break Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break Err(ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed);
                    }
                    // Two daemons walk their legs in the same fixed order but
                    // on independent clocks. When the peer is already queued
                    // on the other leg's listener it is not coming to this
                    // one within this window: yield now with the ordinary
                    // "peer has not arrived" outcome instead of letting both
                    // exchange windows expire on mismatched legs (measured).
                    if sibling.is_some_and(listener_has_pending_peer_v25) {
                        break Err(ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed);
                    }
                    thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL_V1));
                }
                Err(_) => break Err(ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable),
            }
        };
        // A listener that failed for anything other than "no peer yet" is not
        // reusable: drop it so the next round rebinds instead of polling a
        // socket the kernel has already broken. An elapsed deadline keeps the
        // listener, because that is the ordinary "peer has not arrived" case
        // and rebinding it is exactly what reopened the rendezvous window.
        if matches!(
            outcome,
            Err(ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable)
        ) {
            *retained = None;
        }
        outcome
    }
}

/// Whether the peer behind an already-failed exchange has left the
/// connection.
///
/// This runs only after a failed handshake, purely to decide whether the
/// failure was a departed peer rather than a refused identity. It never
/// admits anyone: an answer of `true` only drains that socket and waits for
/// the next one inside the same accept window, and an answer of `false`
/// keeps the original refusal. A socket that is still open, or whose state
/// cannot be read, counts as present, so the fatal verdict is what survives
/// every ambiguity.
fn peer_has_departed_v25(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut discard = [0_u8; 1];
    match stream.peek(&mut discard) {
        // Orderly close: the peer wrote what it had and went away.
        Ok(0) => true,
        // Bytes still queued, or the socket would block: someone is there.
        Ok(_) => false,
        Err(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        ),
    }
}

fn map_authenticated_exchange_error(
    error: ProductionNoiseRelayErrorV1,
) -> ProductionRelayNetworkRuntimeErrorV1 {
    match error {
        ProductionNoiseRelayErrorV1::ChannelUnavailable => {
            ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable
        }
        ProductionNoiseRelayErrorV1::DurableRelayUnavailable => {
            ProductionRelayNetworkRuntimeErrorV1::DurableRelayUnavailable
        }
        // Each refusal keeps its own name. A single collapsed tag already hid
        // one real defect behind another in this loop; the classification is
        // diagnostic only and every one of these remains equally fatal.
        ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed => {
            ProductionRelayNetworkRuntimeErrorV1::IdentityAuthenticationRefused
        }
        ProductionNoiseRelayErrorV1::ProtocolRefused => {
            ProductionRelayNetworkRuntimeErrorV1::ProtocolRefused
        }
        ProductionNoiseRelayErrorV1::PeerRefused => {
            ProductionRelayNetworkRuntimeErrorV1::PeerRefused
        }
        ProductionNoiseRelayErrorV1::InvalidConfiguration => {
            ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use dom_scriptless_identity_store::{
        ContractsIdentityPassphraseV1, ContractsTransportIdentityReferenceV1,
    };
    use dom_scriptless_store::SessionTransportIdentityReferenceV1;
    use dom_scriptless_transport::NoiseRoleV1;
    use relay::production::{RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use std::{
        error::Error,
        fs::File as AmbientFile,
        net::SocketAddr,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use tempfile::TempDir;

    use crate::production_noise_relay::{
        ProductionNoiseRelayDatabasePairV1, ProductionNoiseRelayRouteContextV1,
    };

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    const CHAIN: [u8; 32] = [0x11; 32];
    const NETWORK: [u8; 32] = [0x12; 32];
    const ROUTE: [u8; 32] = [0x13; 32];
    const SESSION: [u8; 32] = [0x14; 32];
    const ALICE: [u8; 32] = [0x21; 32];
    const BOB: [u8; 32] = [0x22; 32];
    const MALLORY: [u8; 32] = [0x23; 32];

    struct IdentityFixtureV1 {
        parent: Arc<Dir>,
        alice: ContractsTransportIdentityReferenceV1,
        bob: ContractsTransportIdentityReferenceV1,
        mallory: ContractsTransportIdentityReferenceV1,
    }

    fn passphrase() -> Result<ContractsIdentityPassphraseV1, Box<dyn Error + Send + Sync>> {
        Ok(ContractsIdentityPassphraseV1::new(
            b"production Relay network runtime test passphrase".to_vec(),
        )?)
    }

    fn identities(temporary: &TempDir) -> Result<IdentityFixtureV1, Box<dyn Error + Send + Sync>> {
        let parent = Arc::new(Dir::from_std_file(AmbientFile::open(temporary.path())?));
        let alice = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-alice-identity",
            &passphrase()?,
        )?;
        let bob = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-bob-identity",
            &passphrase()?,
        )?;
        let mallory = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-mallory-identity",
            &passphrase()?,
        )?;
        Ok(IdentityFixtureV1 {
            parent,
            alice: *alice.reference(),
            bob: *bob.reference(),
            mallory: *mallory.reference(),
        })
    }

    fn database(marker: u8) -> Result<RelayDatabaseConfigV1, Box<dyn Error + Send + Sync>> {
        Ok(RelayDatabaseConfigV1::new(
            RelayDatabaseIdV1::new([marker; 32])?,
            16,
        )?)
    }

    fn session(
        role: NoiseRoleV1,
        local: SessionTransportIdentityReferenceV1,
        remote: SessionTransportIdentityReferenceV1,
        local_database: RelayDatabaseIdV1,
        remote_database: RelayDatabaseIdV1,
        timeout: Duration,
    ) -> Result<ProductionNoiseRelaySessionV1, ProductionNoiseRelayErrorV1> {
        ProductionNoiseRelaySessionV1::new(
            role,
            ProductionNoiseRelayRouteContextV1::new(CHAIN, NETWORK, ROUTE, SESSION)?,
            [local, remote],
            ProductionNoiseRelayDatabasePairV1::new(local_database, remote_database)?,
            timeout,
        )
    }

    /// Serialises every test in this module that binds a loopback port.
    ///
    /// `unused_loopback_address` asks the system for an ephemeral port and
    /// drops the listener, which returns that port to the pool; the relay
    /// binds it only afterwards. Between those two moments any concurrent
    /// binder can be handed the same port, and the relay then fails with the
    /// address already in use. That is a race by construction, and it is why
    /// these tests failed intermittently once the suite grew large enough for
    /// the window to matter — never in isolation.
    ///
    /// Holding this lock for the whole of each such test removes the other
    /// binder rather than narrowing the window. It is deliberately coarse:
    /// these tests take about twenty seconds each and run rarely, so making
    /// them sequential costs little, while a retry loop would leave the race
    /// in place and merely paper over it.
    ///
    /// Poisoning is ignored on purpose: a panic in one network test must not
    /// convert every later one into a second, misleading failure.
    static LOOPBACK_PORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serialise_loopback_tests() -> std::sync::MutexGuard<'static, ()> {
        LOOPBACK_PORTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn unused_loopback_address() -> Result<SocketAddr, io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    fn link(
        mode: ProductionRelayEndpointModeV1,
        address: SocketAddr,
        remote_database: RelayDatabaseIdV1,
    ) -> Result<ProductionRelayNetworkLinkV1, Box<dyn Error + Send + Sync>> {
        Ok(ProductionRelayNetworkLinkV1::new(
            mode,
            address,
            remote_database,
        )?)
    }

    fn relay_root(temporary: &TempDir, leaf: &str) -> PathBuf {
        temporary.path().join(leaf)
    }

    fn reopen_identity(
        parent: Arc<Dir>,
        leaf: &str,
    ) -> Result<ContractsTransportIdentityStoreV1, Box<dyn Error + Send + Sync>> {
        Ok(ContractsTransportIdentityStoreV1::open_production(
            parent,
            leaf,
            &passphrase()?,
        )?)
    }

    fn make_owner_directory(path: &Path) -> Result<(), io::Error> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }

    #[test]
    fn role_and_database_mismatch_fail_before_socket_effects() -> TestResult {
        let _ports = serialise_loopback_tests();
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x41)?;
        let bob_database = database(0x42)?;
        let alice_root = relay_root(&temporary, "role-alice-relay");
        let mut alice_relay = ProductionRelayV1::create(&alice_root, alice_database)?;
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-alice-identity")?;
        let address = unused_loopback_address()?;
        let runtime = ProductionRelayNetworkRuntimeV1::new(ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        )?);
        let initiator = session(
            NoiseRoleV1::Initiator,
            identities.alice.bind_session_participant(ALICE)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_millis(100),
        )?;

        let wrong_role = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            bob_database.database_id(),
        )?;
        assert_eq!(
            runtime
                .exchange_configured_link(&wrong_role, &initiator, &identity, &mut alice_relay,)
                .expect_err("independent role substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration
        );
        assert!(TcpListener::bind(address).is_ok());

        let wrong_database = link(
            ProductionRelayEndpointModeV1::Connect,
            address,
            RelayDatabaseIdV1::new([0x43; 32])?,
        )?;
        assert_eq!(
            runtime
                .exchange_configured_link(&wrong_database, &initiator, &identity, &mut alice_relay,)
                .expect_err("peer database substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration
        );
        Ok(())
    }

    #[test]
    fn listener_without_peer_returns_at_its_deadline() -> TestResult {
        let _ports = serialise_loopback_tests();
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x51)?;
        let bob_database = database(0x52)?;
        let bob_root = relay_root(&temporary, "timeout-bob-relay");
        let mut bob_relay = ProductionRelayV1::create(&bob_root, bob_database)?;
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-bob-identity")?;
        let address = unused_loopback_address()?;
        let runtime = ProductionRelayNetworkRuntimeV1::new(ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        )?);
        let responder = session(
            NoiseRoleV1::Responder,
            identities.bob.bind_session_participant(BOB)?,
            identities.alice.bind_session_participant(ALICE)?,
            bob_database.database_id(),
            alice_database.database_id(),
            Duration::from_millis(100),
        )?;
        let listen = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            alice_database.database_id(),
        )?;
        let started = Instant::now();
        assert_eq!(
            runtime
                .exchange_configured_link(&listen, &responder, &identity, &mut bob_relay)
                .expect_err("listener must not wait forever"),
            ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn authenticated_local_pair_succeeds_and_wrong_peer_identity_fails_closed() -> TestResult {
        let _ports = serialise_loopback_tests();
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x61)?;
        let bob_database = database(0x62)?;
        let alice_root = relay_root(&temporary, "pair-alice-relay");
        let bob_root = relay_root(&temporary, "pair-bob-relay");
        let _alice_relay = ProductionRelayV1::create(&alice_root, alice_database)?;
        let _bob_relay = ProductionRelayV1::create(&bob_root, bob_database)?;
        drop(_alice_relay);
        drop(_bob_relay);
        let address = unused_loopback_address()?;
        let bounds = ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(250),
            Duration::from_millis(250),
        )?;
        let listener_link = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            alice_database.database_id(),
        )?;
        let connector_link = link(
            ProductionRelayEndpointModeV1::Connect,
            address,
            bob_database.database_id(),
        )?;

        // Complete encrypted identity and durable database setup before either
        // socket deadline starts: this test measures transport, not KDF timing.
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-alice-identity")?;
        let mut relay = ProductionRelayV1::open(&alice_root, alice_database)?;
        let responder_identity =
            reopen_identity(Arc::clone(&identities.parent), "runtime-bob-identity")?;
        let responder_relay = ProductionRelayV1::open(&bob_root, bob_database)?;
        let responder_alice = identities.alice;
        let responder_bob = identities.bob;

        let responder =
            thread::spawn(move || -> TestResult {
                let identity = responder_identity;
                let mut relay = responder_relay;
                let session = session(
                    NoiseRoleV1::Responder,
                    responder_bob.bind_session_participant(BOB)?,
                    responder_alice.bind_session_participant(ALICE)?,
                    bob_database.database_id(),
                    alice_database.database_id(),
                    Duration::from_secs(2),
                )?;
                let report = ProductionRelayNetworkRuntimeV1::new(bounds)
                    .exchange_configured_link(&listener_link, &session, &identity, &mut relay)?;
                assert_eq!(report.pages_sent, 1);
                assert_eq!(report.pages_received, 1);
                Ok(())
            });
        thread::sleep(Duration::from_millis(20));
        let initiator = session(
            NoiseRoleV1::Initiator,
            identities.alice.bind_session_participant(ALICE)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_secs(2),
        )?;
        let report = ProductionRelayNetworkRuntimeV1::new(bounds).exchange_configured_link(
            &connector_link,
            &initiator,
            &identity,
            &mut relay,
        )?;
        assert_eq!(report.pages_sent, 1);
        assert_eq!(report.pages_received, 1);
        responder
            .join()
            .map_err(|_| io::Error::other("runtime responder panicked"))??;
        drop(relay);
        drop(identity);

        let wrong_address = unused_loopback_address()?;
        let wrong_listener = link(
            ProductionRelayEndpointModeV1::Listen,
            wrong_address,
            alice_database.database_id(),
        )?;
        let wrong_connector = link(
            ProductionRelayEndpointModeV1::Connect,
            wrong_address,
            bob_database.database_id(),
        )?;
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-mallory-identity")?;
        let mut relay = ProductionRelayV1::open(&alice_root, alice_database)?;
        let wrong_identity = reopen_identity(identities.parent, "runtime-bob-identity")?;
        let wrong_relay = ProductionRelayV1::open(&bob_root, bob_database)?;
        let wrong_alice = identities.alice;
        let wrong_bob = identities.bob;

        let wrong_responder = thread::spawn(move || -> TestResult {
            let identity = wrong_identity;
            let mut relay = wrong_relay;
            let session = session(
                NoiseRoleV1::Responder,
                wrong_bob.bind_session_participant(BOB)?,
                wrong_alice.bind_session_participant(ALICE)?,
                bob_database.database_id(),
                alice_database.database_id(),
                Duration::from_millis(500),
            )?;
            assert_eq!(
                ProductionRelayNetworkRuntimeV1::new(bounds)
                    .exchange_configured_link(&wrong_listener, &session, &identity, &mut relay)
                    .expect_err("unexpected initiator identity must fail Noise authentication"),
                ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
            );
            Ok(())
        });
        thread::sleep(Duration::from_millis(20));
        let impostor = session(
            NoiseRoleV1::Initiator,
            identities.mallory.bind_session_participant(MALLORY)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_millis(500),
        )?;
        // The rejected initiator must fail closed. Which refusal it observes
        // depends on TCP timing: it either completes enough of the handshake
        // to fail its own Noise authentication, or reads the responder's
        // slammed connection first. The security-critical exact assertion is
        // the responder-side one in `wrong_responder`.
        assert!(matches!(
            ProductionRelayNetworkRuntimeV1::new(bounds)
                .exchange_configured_link(&wrong_connector, &impostor, &identity, &mut relay)
                .expect_err("peer identity substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
                | ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable
        ));
        wrong_responder
            .join()
            .map_err(|_| io::Error::other("wrong-peer responder panicked"))??;
        Ok(())
    }
}

/// Whether a connection already waits in `listener`'s accept backlog. It
/// never accepts, so the queued peer keeps its place for the owning leg's
/// own accept, handshake and identity checks.
pub(crate) fn listener_has_pending_peer_v25(listener: &TcpListener) -> bool {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut fds = [PollFd::new(listener, PollFlags::IN)];
    let immediate = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(poll(&mut fds, Some(&immediate)), Ok(ready) if ready > 0)
}
