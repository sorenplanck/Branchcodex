//! Bounded composition of the retained Stage-12 Relay graph and route runtime.
//!
//! One owner derives both Noise sessions from the exact Stage-12 wire, chain,
//! identity and Relay database bindings. Every Relay leg step is ordered as
//! durable outbound submission, authenticated bounded network exchange, then
//! inbound polling with fresh wall time. F6 activation and the route driver are
//! interleaved without reopening a Store, Relay, identity or network client.

#[path = "production_composite_noise_recovery_v23.rs"]
mod noise_recovery_v23;
use noise_recovery_v23::attach_xmr_signing_noise_v23;

#[path = "production_composite_failure_v25.rs"]
mod failure_v25;
pub use failure_v25::ProductionCompositeFailureV25;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kaystra_core::types::TimelockSpec;
use route_executor::LegIdV1;

use crate::production_contracts::ProductionContractsPollErrorV1;
use crate::production_f6::terminal_release::ProductionRouteStoreRuntimeAuthorityV2;
use crate::production_f6_activation::ProductionF6PairRuntimeReceiverV2;
use crate::production_f6_lifecycle::{
    ProductionF6ActivationRefusalV2, ProductionF6LifecycleErrorV2,
};
use crate::production_noise_relay::{
    ProductionNoiseRelayDatabasePairV1, ProductionNoiseRelayErrorV1,
    ProductionNoiseRelayExchangeReportV1, ProductionNoiseRelayRouteContextV1,
    ProductionNoiseRelaySessionV1,
};
use crate::production_relay_network_config::{
    ProductionRelayLinkPositionV1, ProductionRelayNetworkConfigErrorV1,
    ProductionRelayNetworkConfigV1, ProductionRelayNetworkLinkV1,
};
use crate::production_relay_network_runtime::{
    ProductionRelayNetworkBoundsV1, ProductionRelayNetworkRuntimeErrorV1,
    ProductionRelayNetworkRuntimeV1,
};
use crate::production_relay_peer_scope_v23::ProductionSharedRelayPeerScopeV23;
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;
use crate::relay_worker::{
    RelayInboundPollReportV1, RelayOutboundStepV1, RelayWorkerInboundErrorV1,
    RelayWorkerOutboundErrorV1,
};
use crate::{
    ChainObservationAuthority, Clock, ExternalCustodyAuthority, ProductionRouteRuntimeV1,
    RefundArmingAuthority, RouteActionAuthority, RouteDriveDispositionV1, RouteDriveReportV1,
    RouteRunControlErrorV1, RouteRunControlV1, RouteRuntimeErrorV1, RouteSecretRetirementAuthority,
    RunnerActionAuthority, TakeoverReconciliationAuthority, TimerAuthority,
};

const MIN_SOCKET_BOUND_V1: Duration = Duration::from_millis(25);
const MIN_EXCHANGE_BOUND_V1: Duration = Duration::from_millis(100);
const MAX_COMPOSITE_BLOCKING_BOUND_V1: Duration = Duration::from_secs(30);
/// Authenticated scopes carried by one Noise connection: the parent session,
/// the cancelled session, the recovery readiness negotiation and the two
/// recovery children. Each holds one full exchange bound.
pub(crate) const EXCHANGE_SCOPES_PER_CONNECTION_V25: u32 = 5;

/// Largest per-call socket/exchange bound whose worst case (one socket wait
/// plus every scope of one authenticated connection) still fits inside the
/// caller's own blocking ceiling. The route supervisor refuses an external
/// block that could outlive its lease renewal window, so the network bounds
/// are derived from that authenticated window instead of being invented.
pub(crate) const fn call_bound_for_blocking_ceiling_v25(ceiling: Duration) -> Duration {
    Duration::from_millis(
        (ceiling.as_millis() as u64) / (EXCHANGE_SCOPES_PER_CONNECTION_V25 as u64 + 1),
    )
}
const MIN_BACKOFF_V1: Duration = Duration::from_millis(1);
const MAX_ACTIVATION_ROUNDS_V1: u64 = 1_000_000;
const MAX_INTERLEAVED_ROUNDS_V1: u64 = 1_000_000;

/// Operational drain limits, not negotiated route or Relay message expiry.
/// Time is fixed once; neither an unavailable peer nor a new frame renews it.
/// Ceiling for one whole route step, not for one call inside it.
///
/// The step runs under the DOM actuator lease of 120 s, renewed unconditionally
/// immediately before it and not again until it returns. The ceiling bounds
/// only the deadline-carrying calls inside the step; the local work between
/// them — store writes, fsync, signature verification — obeys no clock and was
/// measured at up to ~53 s across one claim step under load (90 s ceiling +
/// 53 s local work = 143 s against the 120 s lease). Sixty seconds still covers
/// the longest step measured doing real chain work on this route (59 s,
/// `Progressed`) and leaves the other sixty to the unclockable local work. A
/// step cut by the ceiling returns `TemporarilyUnavailable` and retries on the
/// next round under a fresh lease; nothing is weakened.
const ROUTE_STEP_CEILING_V27: Duration = Duration::from_secs(60);

const TERMINAL_REFUND_DRAIN_TIME_V24: Duration = Duration::from_secs(180);
const TERMINAL_REFUND_DRAIN_ROUNDS_V24: u16 = route_transport::MAX_ROUTE_FRAME_COUNT_V2 + 2;

pub(crate) struct TerminalRefundDrainBudgetV24 {
    deadline: Instant,
    rounds: u16,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct TerminalRefundDrainProgressV24 {
    staged: bool,
    complete: bool,
}

impl TerminalRefundDrainProgressV24 {
    pub(crate) fn complete(self) -> bool {
        self.complete
    }
    pub(crate) fn needs_publication(self) -> bool {
        !self.staged
    }
    pub(crate) fn publication_staged(&mut self) {
        self.staged = true;
    }
    pub(crate) fn observe_flush(&mut self, flushed: bool) {
        self.complete |= self.staged && flushed;
    }
}

impl TerminalRefundDrainBudgetV24 {
    pub(crate) fn new(started: Instant) -> Result<Self, ProductionCompositeLoopErrorV1> {
        Ok(Self {
            deadline: started
                .checked_add(TERMINAL_REFUND_DRAIN_TIME_V24)
                .ok_or(ProductionCompositeLoopErrorV1::InvalidConfiguration)?,
            rounds: 0,
        })
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn next_round(&mut self, now: Instant) -> bool {
        if now >= self.deadline || self.rounds >= TERMINAL_REFUND_DRAIN_ROUNDS_V24 {
            return false;
        }
        self.rounds += 1;
        true
    }

    pub(crate) fn permits(&self, now: Instant, blocking_bound: Duration) -> bool {
        !blocking_bound.is_zero()
            && self
                .deadline
                .checked_duration_since(now)
                .is_some_and(|remaining| remaining >= blocking_bound)
    }
}

/// Fixed blocking and retry bounds for one composite owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionCompositeLoopConfigV1 {
    network: ProductionRelayNetworkRuntimeV1,
    blocking_bound: Duration,
    exchange_timeout: Duration,
    backoff: Duration,
    activation_round_budget: u64,
}

impl ProductionCompositeLoopConfigV1 {
    pub(crate) fn new(
        connect_timeout: Duration,
        accept_timeout: Duration,
        exchange_timeout: Duration,
        backoff: Duration,
        activation_round_budget: u64,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        if !(MIN_SOCKET_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&connect_timeout)
            || !(MIN_SOCKET_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&accept_timeout)
            || !(MIN_EXCHANGE_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1)
                .contains(&exchange_timeout)
            || !(MIN_BACKOFF_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&backoff)
            || activation_round_budget == 0
            || activation_round_budget > MAX_ACTIVATION_ROUNDS_V1
        {
            return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
        }
        // The combined worst-case blocking window per leg must stay within the
        // composite bound even though the loop takes its per-call bounds from
        // the network runtime below. One authenticated connection carries a
        // fixed number of scopes (parent, cancelled, readiness negotiation and
        // two recovery children), and each scope holds the full exchange bound,
        // so the worst case is the socket bound plus that many exchanges.
        let exchanges = exchange_timeout
            .checked_mul(EXCHANGE_SCOPES_PER_CONNECTION_V25)
            .ok_or(ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        let blocking_bound = connect_timeout
            .max(accept_timeout)
            .checked_add(exchanges)
            .filter(|bound| {
                *bound
                    <= MAX_COMPOSITE_BLOCKING_BOUND_V1
                        .saturating_mul(EXCHANGE_SCOPES_PER_CONNECTION_V25)
            })
            .ok_or(ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        let bounds = ProductionRelayNetworkBoundsV1::new(connect_timeout, accept_timeout)
            .map_err(|_| ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        Ok(Self {
            network: ProductionRelayNetworkRuntimeV1::new(bounds),
            blocking_bound,
            exchange_timeout,
            backoff,
            activation_round_budget,
        })
    }
}

/// Exact composite call site, not input supplied by a peer or caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionCompositeBootstrapContextV25 {
    LocalBootstrap,
    GraphCandidate,
    PostExchangeBootstrap,
}

/// Redacted failure from composite activation or interleaved execution.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionCompositeLoopErrorV1 {
    #[error("native early/BP bootstrap could not advance")]
    Bootstrap(#[source] crate::production_contracts::ProductionBootstrapRuntimeErrorV16),
    #[error("native early/BP bootstrap could not advance at the retained composite stage")]
    BootstrapAtV25 {
        context: ProductionCompositeBootstrapContextV25,
        #[source]
        error: crate::production_contracts::ProductionBootstrapRuntimeErrorV16,
    },
    #[error("production F7 bilateral readiness failed")]
    F7Readiness(#[source] crate::production_contracts::ProductionF7ReadinessErrorV19),
    #[error("production composite loop configuration is invalid")]
    InvalidConfiguration,
    #[error("production composite wall clock is unavailable")]
    ClockUnavailable,
    #[error("production composite outbound Relay step failed")]
    Outbound(#[source] RelayWorkerOutboundErrorV1),
    #[error("production composite authenticated Relay exchange failed")]
    Network(#[source] ProductionRelayNetworkRuntimeErrorV1),
    #[error("production composite Noise setup failed")]
    Noise(#[source] ProductionNoiseRelayErrorV1),
    #[error("production composite network configuration failed")]
    NetworkConfiguration(#[source] ProductionRelayNetworkConfigErrorV1),
    #[error("production composite inbound Relay step failed")]
    Inbound(#[source] ProductionContractsPollErrorV1<ProductionF6LifecycleErrorV2>),
    #[error("production composite cancelled-output inbound Relay step failed")]
    CancelledInbound(
        #[source]
        ProductionContractsPollErrorV1<crate::relay_worker::UnavailableF6AuthorityErrorV1>,
    ),
    #[error("production composite recovery-signing inbound Relay step failed")]
    RecoverySigningInbound(
        #[source]
        ProductionContractsPollErrorV1<crate::relay_worker::UnavailableF6AuthorityErrorV1>,
    ),
    /// The auxiliary inbox refused and quarantined a peer recovery-signing
    /// envelope. Every refusal class there is permanent for that envelope, and
    /// the edge cannot complete without it, so this stops the loop with a
    /// named cause instead of waiting on an edge that will never finish.
    #[error("production composite recovery-signing envelope was refused")]
    RecoverySigningEnvelopeRefused,
    #[error("production composite F6 activation failed")]
    Activation(#[source] ProductionF6ActivationRefusalV2),
    #[error("production composite route runtime failed")]
    Route(#[source] RouteRuntimeErrorV1),
    #[error("production composite shutdown/backoff control failed")]
    Control(#[source] RouteRunControlErrorV1),
    /// Activation made no readiness progress for its whole liveness bound.
    /// The loop would otherwise retry silently forever, and the harness would
    /// kill it with no diagnostic; this names the stall and carries the
    /// closed-token state report out through the ordinary fatal exit path.
    #[error("production composite activation stalled without readiness")]
    ActivationStalled,
    /// The retained DOM actuator lease could not be renewed at a step boundary.
    /// Distinct from `InvalidConfiguration` so a lost fenced ownership is never
    /// read as a malformed configuration.
    #[error("production composite DOM actuator lease renewal failed")]
    ActuatorLeaseRenewal,
}

/// Secret-free report for one exact leg cycle.
pub(crate) struct ProductionCompositeRelayStepReportV1 {
    pub(crate) leg: LegIdV1,
    pub(crate) outbound: RelayOutboundStepV1,
    pub(crate) exchange: ProductionNoiseRelayExchangeReportV1,
    pub(crate) inbound: RelayInboundPollReportV1,
}

impl core::fmt::Debug for ProductionCompositeRelayStepReportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionCompositeRelayStepReportV1")
            .field("leg", &self.leg)
            .field("outbound", &self.outbound)
            .field("exchange", &self.exchange)
            .field("inbound", &self.inbound)
            .finish()
    }
}

/// Sole retained Stage-12 owner plus its two exact Noise sessions.
pub(crate) struct ProductionCompositeRelayLoopV1 {
    owner: ProductionRelayStage12OwnerV1,
    network_config: ProductionRelayNetworkConfigV1,
    network: ProductionRelayNetworkRuntimeV1,
    blocking_bound: Duration,
    sessions: [ProductionNoiseRelaySessionV1; 2],
    shared_peer_scope_v23: Option<ProductionSharedRelayPeerScopeV23>,
    exchange_timeout: Duration,
    backoff: Duration,
    last_relay_time_seconds: u64,
    /// One retained listening socket per relay position, for the positions
    /// configured to listen. Binding inside each accept attempt turned the
    /// link into a rendezvous between two independently paced loops; this
    /// owner outlives the rounds, so the socket stays bound and the kernel
    /// backlog holds the peer until the next accept.
    retained_listeners_v25: [Option<std::net::TcpListener>; 2],
}

impl core::fmt::Debug for ProductionCompositeRelayLoopV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionCompositeRelayLoopV1([authorities redacted])")
    }
}

impl ProductionCompositeRelayLoopV1 {
    /// Borrows the already-retained Stage-12 owner for root-only startup
    /// handoffs and the purpose-specific post-anchor claim pump. This does
    /// not reopen a Store, clone a signer, or mint a second Relay owner.
    pub(crate) fn stage12_owner_mut_v11(&mut self) -> &mut ProductionRelayStage12OwnerV1 {
        &mut self.owner
    }

    pub(crate) fn stage12_owner_ref_v25(&self) -> &ProductionRelayStage12OwnerV1 {
        &self.owner
    }

    fn compose(
        owner: ProductionRelayStage12OwnerV1,
        receiver: &ProductionF6PairRuntimeReceiverV2,
        network_config: ProductionRelayNetworkConfigV1,
        config: ProductionCompositeLoopConfigV1,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        if !owner.matches_f6_pair_receiver(receiver) {
            return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
        }
        let local_database = owner.relay().database_id();
        network_config
            .validate_local_database_id(local_database)
            .map_err(map_network_config_error)?;
        let shared_peer_scope_v23 = if network_config.shared_peer_v23() {
            Some(
                ProductionSharedRelayPeerScopeV23::authenticate(
                    &owner,
                    [
                        network_config
                            .link(ProductionRelayLinkPositionV1::Upstream)
                            .remote_relay_database_id(),
                        network_config
                            .link(ProductionRelayLinkPositionV1::Downstream)
                            .remote_relay_database_id(),
                    ],
                )
                .map_err(|_| ProductionCompositeLoopErrorV1::InvalidConfiguration)?,
            )
        } else {
            None
        };
        let upstream = derive_noise_session(
            &owner,
            LegIdV1::Upstream,
            network_config.link(ProductionRelayLinkPositionV1::Upstream),
            local_database,
            config.exchange_timeout,
        )?;
        let downstream = derive_noise_session(
            &owner,
            LegIdV1::Downstream,
            network_config.link(ProductionRelayLinkPositionV1::Downstream),
            local_database,
            config.exchange_timeout,
        )?;
        let last_relay_time_seconds = owner
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?;
        Ok(Self {
            owner,
            network_config,
            network: config.network,
            blocking_bound: config.blocking_bound,
            sessions: [upstream, downstream],
            shared_peer_scope_v23,
            exchange_timeout: config.exchange_timeout,
            backoff: config.backoff,

            last_relay_time_seconds,
            retained_listeners_v25: [None, None],
        })
    }

    /// Executes exactly one submit/exchange/poll cycle for one named leg.
    pub(crate) fn step_leg(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        self.step_leg_renewing_v25(leg, &mut || Ok(()))
    }

    /// Same cycle, renewing the retained DOM actuator lease inside it. After
    /// activation the route runtime keeps stepping these legs, and each step
    /// can re-enter the recovery signing ceremony and custody mount through
    /// both bootstraps; the lease has to be renewed there as well, not only
    /// between route rounds.
    pub(crate) fn step_leg_renewing_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        self.validate_retained_peer_scope_v23()?;
        self.step_local_bootstrap_with_renewal_v25(leg, renew_actuator_lease)?;
        self.step_exchange_and_poll_renewing_v25(leg, false, renew_actuator_lease)
    }

    /// One retained public-refund cycle after route termination. This never
    /// enters local bootstrap, F6, F7 readiness, auxiliary signing workers or
    /// graph-candidate acceptance. The negotiated Noise scopes may retransmit
    /// already-retained public graph offers/auxiliary Relay bytes; they never
    /// create or dispatch signing work. Authentication, Relay expiry and
    /// shared-stream ordering remain unchanged (no base-only downgrade).
    pub(crate) fn step_terminal_refund_v24(
        &mut self,
        leg: LegIdV1,
    ) -> Result<bool, ProductionCompositeLoopErrorV1> {
        self.validate_retained_peer_scope_v23()?;
        let now = self.fresh_relay_time()?;
        match leg {
            LegIdV1::Upstream => {
                let (contracts, relay) = self.owner.upstream_and_relay_mut();
                contracts.submit_terminal_refund_outbound_v24(relay, now)
            }
            LegIdV1::Downstream => {
                let (contracts, relay) = self.owner.downstream_and_relay_mut();
                contracts.submit_terminal_refund_outbound_v24(relay, now)
            }
        }
        .map_err(ProductionCompositeLoopErrorV1::Outbound)?;
        let position = relay_position(leg);
        let index = relay_index(leg);
        // This only reconstructs public Noise scopes from retained owners;
        // it does not call the graph producer or install new economic gates.
        self.sessions[index] = derive_noise_session(
            &self.owner,
            leg,
            self.network_config.link(position),
            self.owner.relay().database_id(),
            self.exchange_timeout,
        )?;
        let exchange = {
            let link = self.network_config.link(position);
            let session = &self.sessions[index];
            let (retained, sibling) =
                split_retained_listeners_v25(&mut self.retained_listeners_v25, index);
            crate::production_relay_network_runtime::set_exchange_diag_leg_v25(index);
            let (identity, relay) = self.owner.identity_and_relay_mut();
            self.network
                .exchange_configured_link_retained_v25(
                    link, session, identity, relay, retained, sibling,
                )
                .map_err(ProductionCompositeLoopErrorV1::Network)
        };
        let result = complete_exchange_poll_v23(exchange, |_report| {
            // Any authenticated graph candidate remains memory-only. Do not
            // consume it into Store or acknowledge economic graph acceptance;
            // ordinary bootstrap may receive it again on a later normal run.
            let now = self.fresh_relay_time()?;
            match leg {
                LegIdV1::Upstream => {
                    let (contracts, relay) = self.owner.upstream_and_relay_mut();
                    contracts.poll_terminal_refund_inbound_v24(relay, now)
                }
                LegIdV1::Downstream => {
                    let (contracts, relay) = self.owner.downstream_and_relay_mut();
                    contracts.poll_terminal_refund_inbound_v24(relay, now)
                }
            }
            .map_err(ProductionCompositeLoopErrorV1::Inbound)
        });
        match result {
            Ok((exchange, ())) => {
                let pending = self
                    .owner
                    .leg_mut(leg)
                    .contracts_mut()
                    .terminal_refund_frames_pending_v24()
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?;
                // Only a successful authenticated exchange with an exhausted
                // local frame job is flush evidence. A missing peer is not.
                Ok(!pending && !exchange.outbound_backlog_remains)
            }
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
            // The next public publisher tick may install the retained public
            // transport witness. No ACK is invented for the pending 0x19.
            Err(error) if is_terminal_refund_transport_awaiting_v24(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn terminal_refund_relay_bound_v24(&self) -> Duration {
        self.blocking_bound
    }

    pub(crate) fn step_terminal_relay_drain_v24(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<bool, ProductionCompositeLoopErrorV1> {
        self.validate_retained_peer_scope_v23()?;
        match self.step_local_bootstrap_with_renewal_v25(leg, renew_actuator_lease) {
            Ok(()) => {}
            Err(error) if is_terminal_relay_bootstrap_awaiting_v24(&error) => {}
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
        match self.step_exchange_and_poll_renewing_v25(leg, true, renew_actuator_lease) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            Err(error) if is_terminal_relay_bootstrap_awaiting_v24(&error) => Ok(false),
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn validate_retained_peer_scope_v23(&self) -> Result<(), ProductionCompositeLoopErrorV1> {
        if let Some(scope) = &self.shared_peer_scope_v23 {
            scope
                .validate_owner(
                    &self.owner,
                    [
                        self.network_config
                            .link(ProductionRelayLinkPositionV1::Upstream)
                            .remote_relay_database_id(),
                        self.network_config
                            .link(ProductionRelayLinkPositionV1::Downstream)
                            .remote_relay_database_id(),
                    ],
                )
                .map_err(|_| ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        }
        Ok(())
    }

    fn step_local_bootstrap_v23(
        &mut self,
        leg: LegIdV1,
    ) -> Result<(), ProductionCompositeLoopErrorV1> {
        self.step_local_bootstrap_with_renewal_v25(leg, &mut || Ok(()))
    }

    /// Same local bootstrap, carrying the DOM actuator lease renewal hook into
    /// the bootstrap phases. The composite loop renews around this call, but
    /// the recovery signing ceremony inside it is unbounded in wall clock.
    fn step_local_bootstrap_with_renewal_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), ProductionCompositeLoopErrorV1> {
        let TimelockSpec::TimestampSeconds { value: now } = self.fresh_relay_time()? else {
            return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
        };
        self.owner
            .step_bootstrap_with_renewal_v25(leg, now, renew_actuator_lease)
            .map_err(|error| ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                context: ProductionCompositeBootstrapContextV25::LocalBootstrap,
                error,
            })?;
        if self
            .owner
            .recovery_mounted_for_readiness_v23(leg)
            .map_err(ProductionCompositeLoopErrorV1::Bootstrap)?
        {
            let selected = self.owner.leg_mut(leg);
            let chain = selected.trusted_chain_id();
            if let Err(error) = selected.contracts_mut().step_f7_readiness_v19(chain, now) {
                if !readiness_refusal_is_retryable_v29(&error) {
                    return Err(ProductionCompositeLoopErrorV1::F7Readiness(error));
                }
            }
        }
        Ok(())
    }

    fn step_exchange_and_poll_v23(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        self.step_exchange_and_poll_with_v24(leg, false)
    }

    fn step_exchange_and_poll_with_v24(
        &mut self,
        leg: LegIdV1,
        terminal_relay_drain: bool,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        self.step_exchange_and_poll_renewing_v25(leg, terminal_relay_drain, &mut || Ok(()))
    }

    /// Same exchange-and-poll, carrying the DOM actuator lease hook into the
    /// post-exchange bootstrap. That bootstrap re-enters the recovery signing
    /// ceremony, including the first opening of the auxiliary Relays, so it
    /// is exactly as unbounded as the local bootstrap and needs the same
    /// in-phase renewals; the activation loop only renews around this call.
    fn step_exchange_and_poll_renewing_v25(
        &mut self,
        leg: LegIdV1,
        terminal_relay_drain: bool,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        if let Some((contracts, relay)) = self.owner.cancelled_and_relay_mut_v22(leg) {
            let _cancelled_outbound = contracts
                .submit_outbound_once(relay)
                .map_err(ProductionCompositeLoopErrorV1::Outbound)?;
        }
        for edge in [
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Cancel,
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Compensation,
        ] {
            if let Some((contracts, relay)) = self.owner.xmr_signing_and_relay_mut_v23(leg, edge) {
                contracts
                    .submit_outbound_once(relay)
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?;
            }
        }
        let outbound = match leg {
            LegIdV1::Upstream => {
                let (contracts, relay) = self.owner.upstream_and_relay_mut();
                contracts
                    .submit_outbound_once(relay)
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?
            }
            LegIdV1::Downstream => {
                let (contracts, relay) = self.owner.downstream_and_relay_mut();
                contracts
                    .submit_outbound_once(relay)
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?
            }
        };

        let position = relay_position(leg);
        let session_index = relay_index(leg);
        self.sessions[session_index] = derive_noise_session(
            &self.owner,
            leg,
            self.network_config.link(position),
            self.owner.relay().database_id(),
            self.exchange_timeout,
        )?;
        crate::production_relay_stage12::mark_lease_phase_v25("network_exchange");
        let exchange = {
            let link = self.network_config.link(position);
            let session = &self.sessions[session_index];
            let (retained, sibling) =
                split_retained_listeners_v25(&mut self.retained_listeners_v25, session_index);
            crate::production_relay_network_runtime::set_exchange_diag_leg_v25(session_index);
            let (identity, relay) = self.owner.identity_and_relay_mut();
            self.network
                .exchange_configured_link_retained_v25(
                    link, session, identity, relay, retained, sibling,
                )
                .map_err(ProductionCompositeLoopErrorV1::Network)
        };

        let (exchange, inbound) = complete_exchange_poll_v23(exchange, |exchange| {
            if let Some(candidate) = exchange.and_then(|report| report.graph_candidate_v22.take()) {
                self.owner
                    .receive_xmr_graph_candidate_v22(leg, candidate)
                    .map_err(|error| ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                        context: ProductionCompositeBootstrapContextV25::GraphCandidate,
                        error,
                    })?;
            }
            self.poll_retained_inbound_renewing_v25(leg, terminal_relay_drain, renew_actuator_lease)
        })?;
        // DIAG(temporary): a leg whose outbound backlog never drains looks
        // exactly like an idle leg from outside. Print one line per change of
        // the leg's exchange shape, so a scope that stops being offered is
        // visible without one line per round.
        diag_exchange_shape_v25(leg, &exchange);
        Ok(ProductionCompositeRelayStepReportV1 {
            leg,
            outbound,
            exchange,
            inbound,
        })
    }

    fn poll_retained_inbound_renewing_v25(
        &mut self,
        leg: LegIdV1,
        terminal_relay_drain: bool,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<RelayInboundPollReportV1, ProductionCompositeLoopErrorV1> {
        // Poll time is sampled only after the potentially blocking network
        // exchange; a stale timestamp can never be reused across legs.
        let now = self.fresh_relay_time()?;
        // Local acceptance can advance the native phase before an outbound
        // envelope reaches its peer. Reissue the next ingress after exchange
        // and before reading the reply (notably 0x0b -> 0x0c and 0x0e -> 0x10).
        // Pending sends replay exact Store bytes; this never skips an edge.
        let TimelockSpec::TimestampSeconds {
            value: after_exchange,
        } = now
        else {
            return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
        };
        renew_actuator_lease()
            .map_err(|()| ProductionCompositeLoopErrorV1::ActuatorLeaseRenewal)?;
        crate::production_relay_stage12::mark_lease_phase_v25("post_exchange_bootstrap");
        let post_exchange_bootstrap =
            self.owner
                .step_bootstrap_with_renewal_v25(leg, after_exchange, renew_actuator_lease);
        match post_exchange_bootstrap {
            Ok(()) => {}
            Err(error) => {
                let error = ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                    context: ProductionCompositeBootstrapContextV25::PostExchangeBootstrap,
                    error,
                };
                if !terminal_relay_drain || !is_terminal_relay_bootstrap_awaiting_v24(&error) {
                    return Err(error);
                }
            }
        }
        if self
            .owner
            .recovery_mounted_for_readiness_v23(leg)
            .map_err(ProductionCompositeLoopErrorV1::Bootstrap)?
        {
            let selected = self.owner.leg_mut(leg);
            let chain = selected.trusted_chain_id();
            if let Err(error) =
                selected.contracts_mut().step_f7_readiness_v19(chain, after_exchange)
            {
                if !readiness_refusal_is_retryable_v29(&error) {
                    return Err(ProductionCompositeLoopErrorV1::F7Readiness(error));
                }
            }
        }
        if let Some((contracts, relay)) = self.owner.cancelled_and_relay_mut_v22(leg) {
            let _cancelled_inbound = contracts
                .poll_inbound(relay, now)
                .map_err(ProductionCompositeLoopErrorV1::CancelledInbound)?;
        }
        for edge in [
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Cancel,
            dom_scriptless_store::XmrGraphRecoverySigningEdgeV23::Compensation,
        ] {
            if let Some((contracts, relay)) = self.owner.xmr_signing_and_relay_mut_v23(leg, edge) {
                let report = contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::RecoverySigningInbound)?;
                if !report.ingest.refused.is_empty() {
                    return Err(ProductionCompositeLoopErrorV1::RecoverySigningEnvelopeRefused);
                }
            }
        }
        let inbound = match leg {
            LegIdV1::Upstream => {
                let (contracts, relay) = self.owner.upstream_and_relay_mut();
                contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::Inbound)?
            }
            LegIdV1::Downstream => {
                let (contracts, relay) = self.owner.downstream_and_relay_mut();
                contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::Inbound)?
            }
        };
        Ok(inbound)
    }

    fn fresh_relay_time(&mut self) -> Result<TimelockSpec, ProductionCompositeLoopErrorV1> {
        let current = host_time_seconds()?;
        let durable_floor = self
            .owner
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?;
        let accepted =
            validate_nonregressing_time(current, durable_floor, self.last_relay_time_seconds)?;
        self.last_relay_time_seconds = accepted;
        Ok(TimelockSpec::TimestampSeconds { value: accepted })
    }
}

/// Owner of the pre-runtime Relay/F6 activation phase.
pub(crate) struct ProductionCompositeActivationV1 {
    relay: ProductionCompositeRelayLoopV1,
    receiver: ProductionF6PairRuntimeReceiverV2,
    round_budget: u64,
    /// The last activation stall report and when it last changed. The
    /// liveness watchdog in `activate_bounded_with_renewal_v25` fires only
    /// when this closed-token snapshot has been identical for its whole
    /// bound: any progress, however slow, resets the clock.
    last_stall_report_v25: Option<(String, std::time::Instant)>,
}

impl ProductionCompositeActivationV1 {
    /// The retained Stage-12 owner, reachable between bounded activation
    /// rounds. The composition root needs it to install the F6 claim context
    /// as soon as both native refund bindings exist: graph completion is
    /// gated on that context, and activation readiness is gated on graph
    /// completion. Installing it only after activation returns `Ready` makes
    /// those two gates wait on each other forever.
    pub(crate) fn stage12_owner_mut_v25(&mut self) -> &mut ProductionRelayStage12OwnerV1 {
        self.relay.stage12_owner_mut_v11()
    }
}

impl core::fmt::Debug for ProductionCompositeActivationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionCompositeActivationV1([authorities redacted])")
    }
}

/// Bounded activation outcome that never discards the retained Relay owner on
/// shutdown or budget exhaustion.
pub(crate) enum ProductionCompositeActivationExitV1 {
    Ready {
        relay: ProductionCompositeRelayLoopV1,
        route_store: ProductionRouteStoreRuntimeAuthorityV2,
    },
    #[expect(dead_code, reason = "retains the Relay owner across a non-ready exit")]
    Shutdown(ProductionCompositeActivationV1),
    RoundBudgetExhausted(ProductionCompositeActivationV1),
    Failed {
        #[expect(dead_code, reason = "retains the Relay owner across a non-ready exit")]
        activation: ProductionCompositeActivationV1,
        error: ProductionCompositeLoopErrorV1,
    },
}

impl core::fmt::Debug for ProductionCompositeActivationExitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ready { .. } => formatter.write_str("ProductionCompositeActivationExitV1::Ready"),
            Self::Shutdown(_) => {
                formatter.write_str("ProductionCompositeActivationExitV1::Shutdown")
            }
            Self::RoundBudgetExhausted(_) => {
                formatter.write_str("ProductionCompositeActivationExitV1::RoundBudgetExhausted")
            }
            Self::Failed { .. } => {
                formatter.write_str("ProductionCompositeActivationExitV1::Failed")
            }
        }
    }
}

/// Process previously authenticated durable ingress even if this exchange could
/// not obtain a peer. Never invent a successful exchange, accept unauthenticated
/// bytes, or hide a local validation/storage failure behind a socket timeout.
/// DIAG(temporary): one line per change of a leg's exchange shape. Counts are
/// cumulative totals for this round only; `out_backlog` is what matters — a leg
/// that keeps reporting a remaining outbound backlog is one whose envelopes are
/// staged but never leave.
fn diag_exchange_shape_v25(leg: LegIdV1, report: &ProductionNoiseRelayExchangeReportV1) {
    use std::cell::RefCell;
    thread_local! {
        static LAST_SHAPE_V25: RefCell<[String; 2]> =
            const { RefCell::new([String::new(), String::new()]) };
    }
    let index = match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    };
    // call/connect_ok/connect_fail/accept_ok/accept_deadline/sibling_yield/session_error
    let counters = crate::production_relay_network_runtime::exchange_diag_v25(index);
    let line = format!(
        "leg={leg:?} sent={} recv={} out_backlog={} in_backlog={} \
         calls={} conn_ok={} conn_fail={} acc_ok={} acc_deadline={} yield={} sess_err={}",
        report.envelopes_sent,
        report.envelopes_received,
        report.outbound_backlog_remains,
        report.inbound_backlog_remains,
        counters[0],
        counters[1],
        counters[2],
        counters[3],
        counters[4],
        counters[5],
        counters[6],
    );
    LAST_SHAPE_V25.with(|last| {
        let mut last = last.borrow_mut();
        if last[index] != line {
            eprintln!("DOM_EXCHANGE_SHAPE_V25 {line}");
            last[index] = line;
        }
    });
}

fn complete_exchange_poll_v23<T, U>(
    mut exchange: Result<T, ProductionCompositeLoopErrorV1>,
    poll: impl FnOnce(Option<&mut T>) -> Result<U, ProductionCompositeLoopErrorV1>,
) -> Result<(T, U), ProductionCompositeLoopErrorV1> {
    exchange = match exchange {
        Err(error) if !is_peer_temporarily_unavailable_v23(&error) => return Err(error),
        other => other,
    };
    let inbound = poll(exchange.as_mut().ok())?;
    Ok((exchange?, inbound))
}

fn is_peer_temporarily_unavailable_v23(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(
        error,
        ProductionCompositeLoopErrorV1::Network(
            ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable
                | ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed
                | ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable
        )
    )
}

trait CompositeActivationRelayV1 {
    type Error;

    fn resume_local_activation_v23(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    /// One leg of the local bootstrap resume. Exposed per leg so the caller can
    /// renew the retained DOM actuator lease between them: both legs together
    /// can outlast the lease, and a renewal only around the pair is too coarse.
    ///
    /// The hook reaches the bootstrap phases: resuming a leg re-enters the
    /// same recovery signing ceremony as the leg bootstrap, so it needs the
    /// same in-phase lease renewals.
    fn resume_local_activation_leg_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), Self::Error> {
        let _ = (leg, renew_actuator_lease);
        Ok(())
    }
    /// Returns whether the leg moved authenticated relay traffic this round;
    /// see [`CompositeRelayCycleV1::step_relay_leg`]. Used only to skip the
    /// idle backoff between actively exchanging rounds.
    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error>;
    /// The exchange half of one activation leg, split from its local bootstrap
    /// so the caller can renew the retained DOM actuator lease between them.
    /// The hook also reaches the post-exchange bootstrap inside this step,
    /// which re-enters the unbounded recovery signing ceremony.
    fn step_activation_leg_exchange_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<bool, Self::Error> {
        let _ = renew_actuator_lease;
        self.step_activation_leg(leg)
    }
    fn activation_backoff(&self) -> Duration;
    fn bootstrap_ready_v16(&self) -> bool {
        true
    }
}

impl CompositeActivationRelayV1 for ProductionCompositeRelayLoopV1 {
    type Error = ProductionCompositeLoopErrorV1;

    fn resume_local_activation_v23(&mut self) -> Result<(), Self::Error> {
        self.validate_retained_peer_scope_v23()?;
        // Stage 12 has already authenticated both retained F6 applied histories.
        // Rehydrate bootstrap from those exact owners before any socket. This
        // does not manufacture F6 readiness or grant funding/recovery authority.
        self.step_local_bootstrap_v23(LegIdV1::Upstream)?;
        self.step_local_bootstrap_v23(LegIdV1::Downstream)
    }

    fn resume_local_activation_leg_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<(), Self::Error> {
        if leg == LegIdV1::Upstream {
            self.validate_retained_peer_scope_v23()?;
        }
        self.step_local_bootstrap_with_renewal_v25(leg, renew_actuator_lease)
    }

    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
        match self.step_leg(leg) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            Err(error) if is_f6_activation_awaiting(&error) => Ok(false),
            Err(error) if is_template_construction_awaiting_v17(&error) => Ok(false),
            Err(error) if is_funding_handoff_awaiting_v25(&error) => Ok(false),
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn step_activation_leg_exchange_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<bool, Self::Error> {
        match self.step_exchange_and_poll_renewing_v25(leg, false, renew_actuator_lease) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            Err(error) if is_f6_activation_awaiting(&error) => Ok(false),
            Err(error) if is_template_construction_awaiting_v17(&error) => Ok(false),
            Err(error) if is_funding_handoff_awaiting_v25(&error) => Ok(false),
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn activation_backoff(&self) -> Duration {
        self.backoff
    }
    fn bootstrap_ready_v16(&self) -> bool {
        self.owner.bootstrap_ready_v16()
    }
}

trait CompositeActivationReceiverV1 {
    type Ready;
    type Error;

    fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error>;
}

impl CompositeActivationReceiverV1 for ProductionF6PairRuntimeReceiverV2 {
    type Ready = ProductionRouteStoreRuntimeAuthorityV2;
    type Error = ProductionF6ActivationRefusalV2;

    fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error> {
        match self.take_ready() {
            Ok(ready) => Ok(Some(ready)),
            Err(
                ProductionF6ActivationRefusalV2::Awaiting(_)
                | ProductionF6ActivationRefusalV2::Unavailable,
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

enum CompositeActivationCoreExitV1<Ready> {
    Ready(Ready),
    Shutdown,
    RoundBudgetExhausted,
}

#[derive(Debug)]
enum CompositeActivationCoreErrorV1<RelayError, ReceiverError> {
    Relay(RelayError),
    Receiver(ReceiverError),
    Control(RouteRunControlErrorV1),
    InvalidConfiguration,
    ActuatorLeaseRenewal,
}

type CompositeActivationCoreResultV1<Relay, Receiver> = Result<
    CompositeActivationCoreExitV1<<Receiver as CompositeActivationReceiverV1>::Ready>,
    CompositeActivationCoreErrorV1<
        <Relay as CompositeActivationRelayV1>::Error,
        <Receiver as CompositeActivationReceiverV1>::Error,
    >,
>;

fn run_activation_core_v1<Relay, Receiver, Ctl>(
    relay: &mut Relay,
    receiver: &mut Receiver,
    control: &mut Ctl,
    round_budget: u64,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
) -> CompositeActivationCoreResultV1<Relay, Receiver>
where
    Relay: CompositeActivationRelayV1,
    Receiver: CompositeActivationReceiverV1,
    Ctl: RouteRunControlV1,
{
    if round_budget == 0 || round_budget > MAX_ACTIVATION_ROUNDS_V1 {
        return Err(CompositeActivationCoreErrorV1::InvalidConfiguration);
    }
    for _ in 0..round_budget {
        if control
            .shutdown_requested()
            .map_err(CompositeActivationCoreErrorV1::Control)?
        {
            return Ok(CompositeActivationCoreExitV1::Shutdown);
        }
        // Already-rehydrated retained owners need no bootstrap or socket to
        // hand off the exact authenticated pair. Missing readiness still
        // enters the normal resume path below, with all original checks.
        if relay.bootstrap_ready_v16() {
            if let Some(ready) = receiver
                .take_activation_ready()
                .map_err(CompositeActivationCoreErrorV1::Receiver)?
            {
                return Ok(CompositeActivationCoreExitV1::Ready(ready));
            }
        }
        // One round can spend the full connect/accept/exchange bound on each
        // leg, which together may outlast the retained DOM actuator lease.
        // Renewing only between rounds therefore lets the lease expire mid
        // round. Renew at every step boundary instead: same lease duration,
        // same fenced ownership, only a cadence that matches the real work.
        renew_actuator_lease()
            .map_err(|()| CompositeActivationCoreErrorV1::ActuatorLeaseRenewal)?;
        relay
            .resume_local_activation_leg_v25(LegIdV1::Upstream, renew_actuator_lease)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        renew_actuator_lease()
            .map_err(|()| CompositeActivationCoreErrorV1::ActuatorLeaseRenewal)?;
        relay
            .resume_local_activation_leg_v25(LegIdV1::Downstream, renew_actuator_lease)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        renew_actuator_lease()
            .map_err(|()| CompositeActivationCoreErrorV1::ActuatorLeaseRenewal)?;
        if relay.bootstrap_ready_v16() {
            if let Some(ready) = receiver
                .take_activation_ready()
                .map_err(CompositeActivationCoreErrorV1::Receiver)?
            {
                return Ok(CompositeActivationCoreExitV1::Ready(ready));
            }
        }
        // Each leg's local bootstrap already ran in the resume above, in this
        // same round and with no exchange of that leg in between, so a second
        // bootstrap here would repeat the whole recovery ceremony for nothing.
        // The exchange step still re-runs it after the network exchange, which
        // is the one that can see new inbound messages.
        let mut relay_moved_traffic = false;
        for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
            relay_moved_traffic |= relay
                .step_activation_leg_exchange_v25(leg, renew_actuator_lease)
                .map_err(CompositeActivationCoreErrorV1::Relay)?;
            renew_actuator_lease()
                .map_err(|()| CompositeActivationCoreErrorV1::ActuatorLeaseRenewal)?;
        }
        if relay.bootstrap_ready_v16() {
            if let Some(ready) = receiver
                .take_activation_ready()
                .map_err(CompositeActivationCoreErrorV1::Receiver)?
            {
                return Ok(CompositeActivationCoreExitV1::Ready(ready));
            }
        }
        // Back off only on an idle round: the bootstrap/BP/signing ceremony
        // is a strict message ping-pong, and adding a poll interval after a
        // round that moved envelopes would pace the whole ceremony at the
        // idle interval. A silent peer reports no traffic and waits exactly
        // as before.
        if !relay_moved_traffic {
            control
                .wait(relay.activation_backoff())
                .map_err(CompositeActivationCoreErrorV1::Control)?;
        }
    }
    Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
}

impl ProductionCompositeActivationV1 {
    pub(crate) fn new(
        owner: ProductionRelayStage12OwnerV1,
        receiver: ProductionF6PairRuntimeReceiverV2,
        network_config: ProductionRelayNetworkConfigV1,
        config: ProductionCompositeLoopConfigV1,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        Ok(Self {
            relay: ProductionCompositeRelayLoopV1::compose(
                owner,
                &receiver,
                network_config,
                config,
            )?,
            receiver,
            round_budget: config.activation_round_budget,
            last_stall_report_v25: None,
        })
    }

    /// Drives both legs until the exact pair receiver releases the route Store.
    /// `Ready` is constructed only from a successful `take_ready()` call.
    pub(crate) fn activate_bounded<Ctl: RouteRunControlV1>(
        self,
        control: &mut Ctl,
    ) -> ProductionCompositeActivationExitV1 {
        self.activate_bounded_with_renewal_v25(control, &mut || Ok(()))
    }

    /// Same bounded activation, with a hook the composition root uses to renew
    /// the retained DOM actuator lease at every step boundary.
    pub(crate) fn activate_bounded_with_renewal_v25<Ctl: RouteRunControlV1>(
        mut self,
        control: &mut Ctl,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> ProductionCompositeActivationExitV1 {
        let outcome = match run_activation_core_v1(
            &mut self.relay,
            &mut self.receiver,
            control,
            self.round_budget,
            renew_actuator_lease,
        )
        .map_err(|error| match error {
            CompositeActivationCoreErrorV1::Relay(error) => error,
            CompositeActivationCoreErrorV1::Receiver(error) => {
                ProductionCompositeLoopErrorV1::Activation(error)
            }
            CompositeActivationCoreErrorV1::Control(error) => {
                ProductionCompositeLoopErrorV1::Control(error)
            }
            CompositeActivationCoreErrorV1::InvalidConfiguration => {
                ProductionCompositeLoopErrorV1::InvalidConfiguration
            }
            CompositeActivationCoreErrorV1::ActuatorLeaseRenewal => {
                ProductionCompositeLoopErrorV1::ActuatorLeaseRenewal
            }
        }) {
            Ok(outcome) => outcome,
            Err(error) => {
                return ProductionCompositeActivationExitV1::Failed {
                    activation: self,
                    error,
                };
            }
        };
        match outcome {
            CompositeActivationCoreExitV1::Ready(route_store) => {
                ProductionCompositeActivationExitV1::Ready {
                    relay: self.relay,
                    route_store,
                }
            }
            CompositeActivationCoreExitV1::Shutdown => {
                ProductionCompositeActivationExitV1::Shutdown(self)
            }
            CompositeActivationCoreExitV1::RoundBudgetExhausted => {
                // Liveness bound on PROGRESS, not on total time: the closed
                // snapshot below carries every observable of the ceremony
                // (lifecycles, flags, durable session revisions). While the
                // ceremony moves, however slowly, the snapshot keeps changing
                // and the clock keeps resetting. Only a snapshot identical
                // for the whole bound — a state no further round can change —
                // fails with the named cause and the report, instead of
                // spinning silently until an outer harness kills the process
                // with no diagnostic. No protocol timeout is shortened.
                const ACTIVATION_PROGRESS_BOUND_V25: Duration = Duration::from_secs(600);
                let report = self
                    .relay
                    .stage12_owner_ref_v25()
                    .activation_stall_report_v25();
                let now = std::time::Instant::now();
                match &mut self.last_stall_report_v25 {
                    Some((last, since)) if *last == report => {
                        if since.elapsed() > ACTIVATION_PROGRESS_BOUND_V25 {
                            eprintln!("DOM_ACTIVATION_STALL_V25 {report}");
                            return ProductionCompositeActivationExitV1::Failed {
                                activation: self,
                                error: ProductionCompositeLoopErrorV1::ActivationStalled,
                            };
                        }
                    }
                    other => *other = Some((report, now)),
                }
                ProductionCompositeActivationExitV1::RoundBudgetExhausted(self)
            }
        }
    }
}

/// Secret-free exit of one bounded Relay/route interleaving invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionCompositeRuntimeExitV1 {
    Shutdown {
        rounds: u64,
    },
    Terminal {
        rounds: u64,
        report: RouteDriveReportV1,
    },
    RoundBudgetExhausted {
        rounds: u64,
    },
}

trait CompositeRelayCycleV1 {
    type Error;

    fn blocking_bound_v23(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns whether the leg demonstrably moved authenticated relay
    /// traffic this round (an envelope submitted, sent or received, or an
    /// authenticated backlog still staged). The interleaved loop uses this
    /// only to skip the idle backoff while a ceremony is actively
    /// exchanging; a tolerated absence (silent peer, awaited finality)
    /// reports `false` and paces exactly as before.
    fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error>;
    /// The same step with the DOM actuator lease hook carried inside it.
    fn step_relay_leg_renewing_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<bool, Self::Error> {
        let _ = renew_actuator_lease;
        self.step_relay_leg(leg)
    }
    fn backoff(&self) -> Duration;
    /// Whether this side retains a listener on which a waiting peer can be
    /// detected. Without one the idle backoff is the control's plain wait.
    fn detects_waiting_peer_v25(&self) -> bool {
        false
    }
    /// Blocks for at most `slice` and reports whether a peer connection is
    /// already queued on a retained listener. It never accepts: the queued
    /// connection stays in the kernel backlog for the next relay half, whose
    /// accept, handshake and identity checks are unchanged.
    fn peer_waiting_within_v25(&self, slice: Duration) -> bool {
        let _ = slice;
        false
    }
    /// Whether a peer connection is queued right now on this leg's retained
    /// listener. Used only to give that leg one more pass in the same round.
    fn leg_peer_pending_v25(&self, leg: LegIdV1) -> bool {
        let _ = leg;
        false
    }
}

/// One leg's retained listener mutably, and the other leg's for readiness
/// checks only.
fn split_retained_listeners_v25(
    listeners: &mut [Option<std::net::TcpListener>; 2],
    index: usize,
) -> (
    &mut Option<std::net::TcpListener>,
    Option<&std::net::TcpListener>,
) {
    let (first, second) = listeners.split_at_mut(1);
    if index == 0 {
        (&mut first[0], second[0].as_ref())
    } else {
        (&mut second[0], first[0].as_ref())
    }
}

/// Longest uninterrupted slice of an idle backoff spent polling retained
/// listeners, so a shutdown request is still observed promptly.
const IDLE_PEER_POLL_SLICE_V25: Duration = Duration::from_millis(250);

/// Idle backoff that ends as soon as the peer is waiting on a retained
/// listener. Two daemons pace their rounds independently; a listening side
/// that sleeps through its whole backoff while the dialing peer sits in the
/// accept backlog makes the two exchange windows miss each other forever
/// (measured: peer queued for its full exchange bound while this side slept).
/// Waking early only removes idle time; the bound, the accept deadline and
/// every authentication step of the next relay half are unchanged.
fn wait_idle_or_peer_v25<Relay, Ctl>(
    relay: &Relay,
    control: &mut Ctl,
    backoff: Duration,
) -> Result<(), RouteRunControlErrorV1>
where
    Relay: CompositeRelayCycleV1,
    Ctl: RouteRunControlV1,
{
    if !relay.detects_waiting_peer_v25() {
        return control.wait(backoff);
    }
    let deadline = std::time::Instant::now() + backoff;
    loop {
        if control.shutdown_requested()? {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        if relay.peer_waiting_within_v25(remaining.min(IDLE_PEER_POLL_SLICE_V25)) {
            return Ok(());
        }
    }
}

/// Whether one relay step moved authenticated traffic. Every bound, refusal
/// and audit in the step itself is unchanged; this only classifies the
/// completed report so the caller can pace an idle loop without slowing an
/// active ceremony.
fn relay_step_moved_traffic_v1(report: &ProductionCompositeRelayStepReportV1) -> bool {
    !matches!(report.outbound, RelayOutboundStepV1::Idle)
        || report.exchange.envelopes_sent > 0
        || report.exchange.envelopes_received > 0
        || report.exchange.outbound_backlog_remains
        || report.exchange.inbound_backlog_remains
}

impl CompositeRelayCycleV1 for ProductionCompositeRelayLoopV1 {
    type Error = ProductionCompositeLoopErrorV1;

    fn blocking_bound_v23(&self) -> Duration {
        self.blocking_bound
    }

    fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
        self.step_relay_leg_renewing_v25(leg, &mut || Ok(()))
    }

    fn step_relay_leg_renewing_v25(
        &mut self,
        leg: LegIdV1,
        renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    ) -> Result<bool, Self::Error> {
        match self.step_leg_renewing_v25(leg, renew_actuator_lease) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            // The exact 0x12 remains in the durable inbox. Return to the root
            // so its scanner can acquire finality, and continue the other leg
            // and recovery clock. Never ACK or classify bad evidence as absent.
            Err(error) if is_claim_finality_awaiting_v16(&error) => Ok(false),
            Err(error) if is_template_construction_awaiting_v17(&error) => Ok(false),
            Err(error) if is_funding_handoff_awaiting_v25(&error) => Ok(false),
            // Socket absence cannot suppress an already authorized local
            // recovery tick. step_leg still polls the authenticated durable
            // inbox, and any local refusal takes precedence over network loss.
            Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn backoff(&self) -> Duration {
        self.backoff
    }

    fn detects_waiting_peer_v25(&self) -> bool {
        self.retained_listeners_v25.iter().any(Option::is_some)
    }

    fn leg_peer_pending_v25(&self, leg: LegIdV1) -> bool {
        self.retained_listeners_v25[relay_index(leg)]
            .as_ref()
            .is_some_and(crate::production_relay_network_runtime::listener_has_pending_peer_v25)
    }

    fn peer_waiting_within_v25(&self, slice: Duration) -> bool {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut fds: Vec<PollFd<'_>> = self
            .retained_listeners_v25
            .iter()
            .flatten()
            .map(|listener| PollFd::new(listener, PollFlags::IN))
            .collect();
        if fds.is_empty() {
            std::thread::sleep(slice);
            return false;
        }
        let timeout = Timespec {
            tv_sec: i64::try_from(slice.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(slice.subsec_nanos()),
        };
        // An interrupted or failed poll reports no waiting peer; the caller
        // re-checks shutdown and its own deadline before polling again.
        matches!(poll(&mut fds, Some(&timeout)), Ok(ready) if ready > 0)
    }
}

trait CompositeRouteCycleV1 {
    type Error;

    fn prepare_relay_block_v23(&mut self, _bound: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
    fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error>;
}

impl<C, F, A, O, R, E, T, X, Y> CompositeRouteCycleV1
    for ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
{
    type Error = RouteRuntimeErrorV1;

    fn prepare_relay_block_v23(&mut self, bound: Duration) -> Result<(), Self::Error> {
        // Each leg can independently exhaust its authenticated socket bound.
        // Renew before BOTH calls, not once before the whole recovery loop.
        self.prepare_bounded_external_block(bound)
    }

    fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error> {
        self.step()
    }
}

#[derive(Debug)]
enum CompositeCoreErrorV1<RelayError, RouteError> {
    Relay(RelayError),
    Route(RouteError),
    Control(RouteRunControlErrorV1),
    InvalidConfiguration,
    /// The retained DOM actuator lease could not be renewed in the runtime.
    ActuatorLeaseRenewal,
}

/// Outcome of bounded Relay work selected by the composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompositeRelayHalfV25 {
    /// Shutdown was requested before any leg ran.
    Shutdown,
    /// The selected leg set ran; `moved` says whether it moved authenticated traffic.
    Stepped { moved: bool },
}

/// Outcome of the route half of one interleaved round.
enum CompositeRouteHalfV25 {
    Terminal(RouteDriveReportV1),
    Continue,
}

/// Relay half of one round: one upstream and one downstream relay step, with
/// the DOM actuator lease renewed around each leg and inside it.
/// `prepare_relay_block_v23` only renews the route lease.
fn run_relay_half_v25<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<CompositeRelayHalfV25, CompositeCoreErrorV1<Relay::Error, Route::Error>>
where
    Relay: CompositeRelayCycleV1,
    Route: CompositeRouteCycleV1,
    Ctl: RouteRunControlV1,
{
    if control
        .shutdown_requested()
        .map_err(CompositeCoreErrorV1::Control)?
    {
        return Ok(CompositeRelayHalfV25::Shutdown);
    }
    let mut moved = false;
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        route
            .prepare_relay_block_v23(relay.blocking_bound_v23())
            .map_err(CompositeCoreErrorV1::Route)?;
        renew_actuator_lease().map_err(|()| CompositeCoreErrorV1::ActuatorLeaseRenewal)?;
        moved |= relay
            .step_relay_leg_renewing_v25(leg, renew_actuator_lease)
            .map_err(CompositeCoreErrorV1::Relay)?;
    }
    // A peer that dialed a leg while this side was serving the other one is
    // still queued: give exactly that leg one more ordinary step now instead
    // of leaving it to expire through a whole route half.
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        if !relay.leg_peer_pending_v25(leg) {
            continue;
        }
        route
            .prepare_relay_block_v23(relay.blocking_bound_v23())
            .map_err(CompositeCoreErrorV1::Route)?;
        renew_actuator_lease().map_err(|()| CompositeCoreErrorV1::ActuatorLeaseRenewal)?;
        moved |= relay
            .step_relay_leg_renewing_v25(leg, renew_actuator_lease)
            .map_err(CompositeCoreErrorV1::Relay)?;
    }
    Ok(CompositeRelayHalfV25::Stepped { moved })
}

/// One named Relay leg with the same shutdown, route-lease and actuator-lease
/// boundaries as a full Relay half. This is used only after a bilateral half
/// has synchronized native readiness; it does not weaken the leg's bootstrap,
/// Noise authentication, Store polling or retained-listener handling.
fn run_relay_leg_v25<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    leg: LegIdV1,
) -> Result<CompositeRelayHalfV25, CompositeCoreErrorV1<Relay::Error, Route::Error>>
where
    Relay: CompositeRelayCycleV1,
    Route: CompositeRouteCycleV1,
    Ctl: RouteRunControlV1,
{
    if control
        .shutdown_requested()
        .map_err(CompositeCoreErrorV1::Control)?
    {
        return Ok(CompositeRelayHalfV25::Shutdown);
    }
    route
        .prepare_relay_block_v23(relay.blocking_bound_v23())
        .map_err(CompositeCoreErrorV1::Route)?;
    renew_actuator_lease().map_err(|()| CompositeCoreErrorV1::ActuatorLeaseRenewal)?;
    let mut moved = relay
        .step_relay_leg_renewing_v25(leg, renew_actuator_lease)
        .map_err(CompositeCoreErrorV1::Relay)?;
    // accept_one_until_v25 may yield because the peer is queued on the
    // sibling listener. Honour that yield here too: a focused native burst
    // must not leave the waiting sibling behind several signing/scan ticks.
    // Only already-pending listeners get an extra step, at most once each,
    // through the ordinary bootstrap, ownership and authenticated exchange.
    let sibling = match leg {
        LegIdV1::Upstream => LegIdV1::Downstream,
        LegIdV1::Downstream => LegIdV1::Upstream,
    };
    for pending_leg in [sibling, leg] {
        if !relay.leg_peer_pending_v25(pending_leg) {
            continue;
        }
        route
            .prepare_relay_block_v23(relay.blocking_bound_v23())
            .map_err(CompositeCoreErrorV1::Route)?;
        renew_actuator_lease().map_err(|()| CompositeCoreErrorV1::ActuatorLeaseRenewal)?;
        moved |= relay
            .step_relay_leg_renewing_v25(pending_leg, renew_actuator_lease)
            .map_err(CompositeCoreErrorV1::Relay)?;
    }
    Ok(CompositeRelayHalfV25::Stepped { moved })
}

/// Route half of one round: one route step, progress record, and the idle
/// backoff. The lease is renewed right before the step, whose child calls
/// spend wall clock the DOM lease must outlive.
fn run_route_half_v25<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    relay_moved_traffic: bool,
) -> Result<CompositeRouteHalfV25, CompositeCoreErrorV1<Relay::Error, Route::Error>>
where
    Relay: CompositeRelayCycleV1,
    Route: CompositeRouteCycleV1,
    Ctl: RouteRunControlV1,
{
    // Local durable work spends the route lease too. Top up both owners at
    // this boundary rather than relying on an earlier relay/native heartbeat.
    route
        .prepare_relay_block_v23(Duration::from_millis(1))
        .map_err(CompositeCoreErrorV1::Route)?;
    renew_actuator_lease().map_err(|()| CompositeCoreErrorV1::ActuatorLeaseRenewal)?;
    crate::production_relay_stage12::mark_lease_phase_v25("route_step");
    let started_v26 = std::time::Instant::now();
    // Arm one ceiling for every bounded observation this step makes. Each of
    // them already carries a budget, but budgets do not compose: three calls
    // of 60 s, 60 s and 20 s produced a 141.7 s step against the 120 s
    // actuator lease the step is holding, and the lease lapsed mid-step. The
    // ceiling is the lease the caller just renewed, less the margin the rest
    // of the round needs. A step that reaches it returns
    // `TemporarilyUnavailable`, which the driver already treats as "not yet"
    // and retries on the next round with the lease renewed again.
    let step_ceiling_v27 = started_v26.checked_add(ROUTE_STEP_CEILING_V27);
    let report = {
        let _armed = route_step_deadline::Armed::new(step_ceiling_v27);
        route.step_route().map_err(CompositeCoreErrorV1::Route)
    }?;
    // Diagnostic only: one driver step that outlasts the actuator lease is
    // what makes the lease lapse mid-step. Names the stage that did it.
    let spent_v26 = started_v26.elapsed();
    if spent_v26 >= std::time::Duration::from_secs(20) {
        eprintln!(
            "DOM_ROUTE_STEP_SLOW_V26 ms={} stage={:?} disposition={:?}",
            spent_v26.as_millis(),
            report.stage,
            report.disposition
        );
    }
    crate::production_relay_stage12::mark_lease_phase_v25("route_step_done");
    control
        .record_progress(report)
        .map_err(CompositeCoreErrorV1::Control)?;
    if report.disposition == RouteDriveDispositionV1::Terminal {
        return Ok(CompositeRouteHalfV25::Terminal(report));
    }
    // Back off only when the round was genuinely idle: a route waiting on
    // chain finality while the Relay legs are mid-ceremony must not add a
    // poll interval to every envelope of the signing choreography. A
    // silent peer reports no traffic and paces exactly as before, so
    // every network bound and refusal is unchanged.
    if matches!(
        report.disposition,
        RouteDriveDispositionV1::Waiting | RouteDriveDispositionV1::RecoveryRequired
    ) && !relay_moved_traffic
    {
        crate::production_relay_stage12::mark_lease_phase_v25("idle_backoff");
        wait_idle_or_peer_v25(relay, control, relay.backoff())
            .map_err(CompositeCoreErrorV1::Control)?;
    }
    Ok(CompositeRouteHalfV25::Continue)
}

fn run_interleaved_core_v1<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    round_budget: u64,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<ProductionCompositeRuntimeExitV1, CompositeCoreErrorV1<Relay::Error, Route::Error>>
where
    Relay: CompositeRelayCycleV1,
    Route: CompositeRouteCycleV1,
    Ctl: RouteRunControlV1,
{
    if round_budget == 0 || round_budget > MAX_INTERLEAVED_ROUNDS_V1 {
        return Err(CompositeCoreErrorV1::InvalidConfiguration);
    }
    let mut rounds = 0_u64;
    while rounds < round_budget {
        let moved = match run_relay_half_v25(relay, route, control, renew_actuator_lease)? {
            CompositeRelayHalfV25::Shutdown => {
                return Ok(ProductionCompositeRuntimeExitV1::Shutdown { rounds });
            }
            CompositeRelayHalfV25::Stepped { moved } => moved,
        };
        let half = run_route_half_v25(relay, route, control, renew_actuator_lease, moved)?;
        rounds = rounds
            .checked_add(1)
            .ok_or(CompositeCoreErrorV1::InvalidConfiguration)?;
        if let CompositeRouteHalfV25::Terminal(report) = half {
            return Ok(ProductionCompositeRuntimeExitV1::Terminal { rounds, report });
        }
    }
    Ok(ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds })
}

/// Interleaves exactly one upstream Relay step, one downstream Relay step and
/// one concrete route-runtime step per round.
pub(crate) fn run_production_composite_runtime_bounded_v1<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    round_budget: u64,
) -> Result<ProductionCompositeRuntimeExitV1, ProductionCompositeLoopErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
    Ctl: RouteRunControlV1,
{
    run_production_composite_runtime_renewing_v25(relay, route, control, round_budget, &mut || {
        Ok(())
    })
}

/// Same interleaved runtime, renewing the retained DOM actuator lease around
/// each relay leg, inside each leg's bootstraps, and before the route step.
pub(crate) fn run_production_composite_runtime_renewing_v25<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    round_budget: u64,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<ProductionCompositeRuntimeExitV1, ProductionCompositeLoopErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
    Ctl: RouteRunControlV1,
{
    run_interleaved_core_v1(relay, route, control, round_budget, renew_actuator_lease)
        .map_err(map_composite_core_error_v25)
}

fn map_composite_core_error_v25(
    error: CompositeCoreErrorV1<ProductionCompositeLoopErrorV1, RouteRuntimeErrorV1>,
) -> ProductionCompositeLoopErrorV1 {
    match error {
        CompositeCoreErrorV1::Relay(error) => error,
        CompositeCoreErrorV1::Route(error) => ProductionCompositeLoopErrorV1::Route(error),
        CompositeCoreErrorV1::Control(error) => ProductionCompositeLoopErrorV1::Control(error),
        CompositeCoreErrorV1::InvalidConfiguration => {
            ProductionCompositeLoopErrorV1::InvalidConfiguration
        }
        CompositeCoreErrorV1::ActuatorLeaseRenewal => {
            ProductionCompositeLoopErrorV1::ActuatorLeaseRenewal
        }
    }
}

/// Relay half of exactly one production round. Together with
/// [`run_production_composite_route_half_v25`] this is one interleaved
/// round, split so the composition root can refresh state that the route
/// step consumes (the funding window) after the relay legs have spent their
/// wall clock, instead of before them.
pub(crate) fn run_production_composite_relay_half_v25<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<CompositeRelayHalfV25, ProductionCompositeLoopErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
    Ctl: RouteRunControlV1,
{
    run_relay_half_v25(relay, route, control, renew_actuator_lease)
        .map_err(map_composite_core_error_v25)
}

/// Relay one named leg after a bilateral synchronization half. The selected
/// leg still executes the complete production Relay cycle and all lease
/// checkpoints; only the unrelated socket is left unopened for this pass.
pub(crate) fn run_production_composite_relay_leg_v25<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    leg: LegIdV1,
) -> Result<CompositeRelayHalfV25, ProductionCompositeLoopErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
    Ctl: RouteRunControlV1,
{
    run_relay_leg_v25(relay, route, control, renew_actuator_lease, leg)
        .map_err(map_composite_core_error_v25)
}

/// Route half of exactly one production round; see
/// [`run_production_composite_relay_half_v25`].
pub(crate) fn run_production_composite_route_half_v25<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
    relay_moved_traffic: bool,
) -> Result<ProductionCompositeRuntimeExitV1, ProductionCompositeLoopErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
    Ctl: RouteRunControlV1,
{
    match run_route_half_v25(
        relay,
        route,
        control,
        renew_actuator_lease,
        relay_moved_traffic,
    )
    .map_err(map_composite_core_error_v25)?
    {
        CompositeRouteHalfV25::Terminal(report) => {
            Ok(ProductionCompositeRuntimeExitV1::Terminal { rounds: 1, report })
        }
        CompositeRouteHalfV25::Continue => {
            Ok(ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 1 })
        }
    }
}

/// A readiness refusal that only means "not with this observation" must not end
/// the route.
///
/// `ClaimSigningAuthorityUnavailable` is raised by the Store when the retained
/// anchor observation has aged past `MAX_V11_EXTERNAL_ANCHOR_AGE` (60 s). The
/// remedy is to observe again, which the next turn of this loop does anyway.
/// Measured on this route after the claim step became resumable, one claim
/// step alone spends 57-70 s, so a 60 s observation routinely ages out inside
/// a single step: run 84 died with "post-anchor DOM claim-signing authority is
/// unavailable" while nothing was wrong and no lease had lapsed. A busy store
/// is the same class of answer. Every other refusal stays fatal, and nothing
/// is signed or staged from evidence this boundary already refused.
fn readiness_refusal_is_retryable_v29(
    error: &crate::production_contracts::ProductionF7ReadinessErrorV19,
) -> bool {
    use dom_scriptless_store::SessionStoreError as Store;
    matches!(
        error,
        crate::production_contracts::ProductionF7ReadinessErrorV19::Store(
            Store::ClaimSigningAuthorityUnavailable | Store::StoreBusy
        )
    )
}

fn derive_noise_session(
    owner: &ProductionRelayStage12OwnerV1,
    leg: LegIdV1,
    link: &ProductionRelayNetworkLinkV1,
    local_database: relay::production::RelayDatabaseIdV1,
    exchange_timeout: Duration,
) -> Result<ProductionNoiseRelaySessionV1, ProductionCompositeLoopErrorV1> {
    let retained = owner.leg(leg);
    let wire = retained.wire();
    let chain_id = *retained.trusted_chain_id().as_bytes();
    let context = ProductionNoiseRelayRouteContextV1::new(
        chain_id,
        wire.network_id,
        wire.route_id,
        wire.session_id,
    )
    .map_err(map_noise_error)?;
    let databases =
        ProductionNoiseRelayDatabasePairV1::new(local_database, link.remote_relay_database_id())
            .map_err(map_noise_error)?;
    let session = ProductionNoiseRelaySessionV1::new(
        link.noise_role(),
        context,
        retained.noise_identity_references().clone(),
        databases,
        exchange_timeout,
    )
    .map_err(map_noise_error)?;
    let session = if let Some((chain, wire, references, parent_terms)) =
        owner.cancelled_noise_scope_v22(leg)
    {
        let cancelled_context = ProductionNoiseRelayRouteContextV1::new(
            *chain.as_bytes(),
            wire.network_id,
            wire.route_id,
            wire.session_id,
        )
        .map_err(map_noise_error)?;
        let cancelled = ProductionNoiseRelaySessionV1::new(
            link.noise_role(),
            cancelled_context,
            references,
            ProductionNoiseRelayDatabasePairV1::new(
                local_database,
                link.remote_relay_database_id(),
            )
            .map_err(map_noise_error)?,
            exchange_timeout,
        )
        .map_err(map_noise_error)?;
        session
            .with_xmr_cancelled_v22(cancelled, parent_terms)
            .map_err(map_noise_error)?
    } else {
        session
    };
    let session = if let Some(graph) = owner
        .xmr_noise_graph_offer_v22(leg)
        .map_err(ProductionCompositeLoopErrorV1::Bootstrap)?
    {
        session
            .with_xmr_graph_offer_v22(graph)
            .map_err(map_noise_error)
    } else {
        Ok(session)
    }?;
    attach_xmr_signing_noise_v23(owner, leg, link, local_database, exchange_timeout, session)
}

fn host_time_seconds() -> Result<u64, ProductionCompositeLoopErrorV1> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?
        .as_secs();
    if seconds == 0 {
        return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
    }
    Ok(seconds)
}

fn validate_nonregressing_time(
    current: u64,
    durable_floor: u64,
    process_floor: u64,
) -> Result<u64, ProductionCompositeLoopErrorV1> {
    if current == 0 || current < durable_floor || current < process_floor {
        return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
    }
    Ok(current)
}

const fn relay_position(leg: LegIdV1) -> ProductionRelayLinkPositionV1 {
    match leg {
        LegIdV1::Upstream => ProductionRelayLinkPositionV1::Upstream,
        LegIdV1::Downstream => ProductionRelayLinkPositionV1::Downstream,
    }
}

const fn relay_index(leg: LegIdV1) -> usize {
    match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }
}

fn map_network_config_error(
    error: ProductionRelayNetworkConfigErrorV1,
) -> ProductionCompositeLoopErrorV1 {
    ProductionCompositeLoopErrorV1::NetworkConfiguration(error)
}

fn map_noise_error(error: ProductionNoiseRelayErrorV1) -> ProductionCompositeLoopErrorV1 {
    ProductionCompositeLoopErrorV1::Noise(error)
}

fn is_f6_activation_awaiting(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(
        error,
        ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
            RelayWorkerInboundErrorV1::F6(route_transport::F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(_),
            )),
        ))
    )
}

fn is_template_construction_awaiting_v17(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(error, ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
        RelayWorkerInboundErrorV1::Contracts(route_transport::RouteDispatchErrorV1::Contracts(
            route_transport::FramedContractsTransportErrorV2::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingTemplateConstructionV17
                | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingBootstrapRefundHandoffV18
                | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrRefundTransportV23))))))
}

fn is_funding_handoff_awaiting_v25(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(error, ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
        RelayWorkerInboundErrorV1::Contracts(route_transport::RouteDispatchErrorV1::Contracts(
            route_transport::FramedContractsTransportErrorV2::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrFundingHandoffV25
                | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrReadinessGateV25))))))
}

fn is_claim_finality_awaiting_v16(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(error, ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
        RelayWorkerInboundErrorV1::Contracts(route_transport::RouteDispatchErrorV1::Contracts(
            route_transport::FramedContractsTransportErrorV2::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingFinalClaimObservationV16))))))
}

fn is_terminal_relay_bootstrap_awaiting_v24(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(
        error,
        ProductionCompositeLoopErrorV1::BootstrapAtV25 {
            error:
                crate::production_contracts::ProductionBootstrapRuntimeErrorV16::Ingress(
                    crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingFinalClaimObservationV16
                        | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingTemplateConstructionV17
                        | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingBootstrapRefundHandoffV18
                        | crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrRefundTransportV23,
                ),
            ..
        }
    ) || is_claim_finality_awaiting_v16(error)
        || is_template_construction_awaiting_v17(error)
}

fn is_terminal_refund_transport_awaiting_v24(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(error, ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
        RelayWorkerInboundErrorV1::Contracts(route_transport::RouteDispatchErrorV1::Contracts(
            route_transport::FramedContractsTransportErrorV2::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingNativeXmrRefundTransportV23))))))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use rfq::v2::SettlementPositionV2;

    use crate::production_f6_lifecycle::ProductionPendingAuthorityV1;
    use crate::{RouteDriveStageV1, RouteRunControlErrorV1};

    use super::*;

    #[test]
    fn terminal_refund_drain_never_renews_original_deadline_or_round_budget() {
        let start = Instant::now();
        let mut budget = TerminalRefundDrainBudgetV24::new(start).unwrap();
        let deadline = budget.deadline();
        assert_eq!(deadline.duration_since(start), Duration::from_secs(180));
        for _ in 0..TERMINAL_REFUND_DRAIN_ROUNDS_V24 {
            assert!(budget.next_round(start));
            assert_eq!(budget.deadline(), deadline);
        }
        assert!(!budget.next_round(start));
        let mut elapsed = TerminalRefundDrainBudgetV24::new(start).unwrap();
        assert!(!elapsed.next_round(deadline));
        assert!(!elapsed.permits(deadline, Duration::from_nanos(1)));
        assert!(!elapsed.permits(deadline - Duration::from_secs(1), Duration::from_secs(2)));
        assert!(!elapsed.permits(start, Duration::ZERO));
        assert!(elapsed.permits(deadline - Duration::from_secs(1), Duration::from_secs(1)));
    }

    #[test]
    fn terminal_refund_staged_frames_flush_without_another_publisher() {
        let mut progress = TerminalRefundDrainProgressV24::default();
        progress.observe_flush(true);
        assert!(
            !progress.complete(),
            "empty mailbox is not a published response"
        );
        let mut publisher_calls = 0;
        for flushed in [false, false, false, true] {
            if progress.needs_publication() {
                publisher_calls += 1;
                progress.publication_staged();
            }
            progress.observe_flush(flushed);
            assert_eq!(progress.complete(), flushed);
        }
        assert_eq!(publisher_calls, 1);
        assert!(progress.complete());
        assert!(!progress.needs_publication());
    }

    #[test]
    fn terminal_refund_drain_has_no_bootstrap_f6_or_private_recovery_edge() {
        let source = include_str!("production_composite_loop.rs");
        let body = source
            .split("pub(crate) fn step_terminal_refund_v24(")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn terminal_refund_relay_bound_v24")
            .next()
            .unwrap();
        for forbidden in [
            ".step_bootstrap",
            ".step_f7",
            ".poll_inbound(",
            ".receive_xmr_graph_candidate",
            ".cancelled_and_relay_mut",
            ".xmr_signing_and_relay_mut",
        ] {
            assert!(
                !body.contains(forbidden),
                "terminal drain regained {forbidden}"
            );
        }
        assert!(body.contains(".poll_terminal_refund_inbound_v24("));
        assert!(body.contains(".submit_terminal_refund_outbound_v24("));
        let root = include_str!("production_run_universal.rs");
        let drain = root
            .split("macro_rules! drain_terminal_refund_v24")
            .nth(1)
            .unwrap()
            .split("// Normal route loop begins here")
            .next()
            .unwrap();
        let receive = drain.find(".step_terminal_refund_v24(leg)").unwrap();
        let publish = drain.find("tick_remote_refund_bounded_v24").unwrap();
        let flush = drain.rfind(".step_terminal_refund_v24(leg)").unwrap();
        assert!(receive < publish && publish < flush);
        assert!(drain.find("funding_window_v23.close()").unwrap() < receive);
        assert!(!drain.contains("pump.tick()"));
    }

    #[derive(Default)]
    struct TestRelayV1 {
        log: Rc<RefCell<Vec<&'static str>>>,
        backoff: Duration,
    }

    impl CompositeRelayCycleV1 for TestRelayV1 {
        type Error = ();

        fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
            self.log.borrow_mut().push(match leg {
                LegIdV1::Upstream => "upstream-relay",
                LegIdV1::Downstream => "downstream-relay",
            });
            Ok(false)
        }

        fn backoff(&self) -> Duration {
            self.backoff
        }
    }

    impl CompositeActivationRelayV1 for TestRelayV1 {
        type Error = ();

        fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
            self.step_relay_leg(leg)
        }

        fn activation_backoff(&self) -> Duration {
            self.backoff
        }
    }

    struct TestActivationReceiverV1 {
        calls: u64,
        ready_on_call: u64,
    }

    struct BootstrapBarrierRelayV16 {
        ticks: [u64; 2],
        complete_after: [u64; 2],
    }
    impl CompositeActivationRelayV1 for BootstrapBarrierRelayV16 {
        type Error = ();
        fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
            self.ticks[relay_index(leg)] += 1;
            Ok(false)
        }
        fn activation_backoff(&self) -> Duration {
            Duration::from_millis(1)
        }
        fn bootstrap_ready_v16(&self) -> bool {
            self.ticks
                .iter()
                .zip(self.complete_after)
                .all(|(ticks, needed)| *ticks >= needed)
        }
    }

    #[test]
    fn v16_completed_f6_is_not_consumed_until_both_bootstrap_legs_finish() {
        let mut relay = BootstrapBarrierRelayV16 {
            ticks: [0, 0],
            complete_after: [1, 3],
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 1,
        };
        let mut control = TestControlV1::default();
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 2, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
        ));
        assert_eq!(receiver.calls, 0);
        assert_eq!(relay.ticks, [2, 2]);
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::Ready(7))
        ));
        assert_eq!(receiver.calls, 1);
        assert_eq!(relay.ticks, [3, 3]);
    }

    #[test]
    fn v16_shutdown_during_bootstrap_does_not_consume_ready_f6() {
        let mut relay = BootstrapBarrierRelayV16 {
            ticks: [0, 0],
            complete_after: [1, 1],
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 1,
        };
        let mut control = TestControlV1 {
            shutdown: true,
            ..TestControlV1::default()
        };
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::Shutdown)
        ));
        assert_eq!(receiver.calls, 0);
        assert_eq!(relay.ticks, [0, 0]);
    }

    impl CompositeActivationReceiverV1 for TestActivationReceiverV1 {
        type Ready = u8;
        type Error = ();

        fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error> {
            self.calls += 1;
            Ok((self.calls == self.ready_on_call).then_some(7))
        }
    }

    #[test]
    fn each_relay_leg_requires_a_fresh_route_lease_before_blocking() {
        struct LeaseCheckedRoute {
            log: Rc<RefCell<Vec<&'static str>>>,
            preparations: usize,
            refuse_on: usize,
        }
        impl CompositeRouteCycleV1 for LeaseCheckedRoute {
            type Error = ();
            fn prepare_relay_block_v23(&mut self, _bound: Duration) -> Result<(), ()> {
                self.preparations += 1;
                self.log.borrow_mut().push("renew-route");
                if self.preparations == self.refuse_on {
                    return Err(());
                }
                Ok(())
            }
            fn step_route(&mut self) -> Result<RouteDriveReportV1, ()> {
                self.log.borrow_mut().push("route-step");
                Ok(report(RouteDriveDispositionV1::RecoveryRequired, 4))
            }
        }
        for refuse_on in [0, 1, 2, 3] {
            let log = Rc::new(RefCell::new(Vec::new()));
            let mut relay = TestRelayV1 {
                log: Rc::clone(&log),
                backoff: Duration::from_millis(1),
            };
            let mut route = LeaseCheckedRoute {
                log: Rc::clone(&log),
                preparations: 0,
                refuse_on,
            };
            let result = run_interleaved_core_v1(
                &mut relay,
                &mut route,
                &mut TestControlV1::default(),
                1,
                &mut || Ok(()),
            );
            if refuse_on == 0 {
                assert!(result.is_ok());
                assert_eq!(
                    log.borrow().as_slice(),
                    [
                        "renew-route",
                        "upstream-relay",
                        "renew-route",
                        "downstream-relay",
                        "renew-route",
                        "route-step"
                    ]
                );
            } else {
                assert!(matches!(result, Err(CompositeCoreErrorV1::Route(()))));
                let expected: &[&str] = match refuse_on {
                    1 => &["renew-route"],
                    2 => &["renew-route", "upstream-relay", "renew-route"],
                    _ => &[
                        "renew-route",
                        "upstream-relay",
                        "renew-route",
                        "downstream-relay",
                        "renew-route",
                    ],
                };
                assert_eq!(log.borrow().as_slice(), expected);
            }
        }
    }

    struct TestRouteV1 {
        log: Rc<RefCell<Vec<&'static str>>>,
        reports: Vec<RouteDriveReportV1>,
    }

    impl CompositeRouteCycleV1 for TestRouteV1 {
        type Error = ();

        fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error> {
            self.log.borrow_mut().push("route-step");
            Ok(self.reports.remove(0))
        }
    }

    #[derive(Default)]
    struct TestControlV1 {
        shutdown: bool,
        waits: Vec<Duration>,
        progress: Vec<RouteDriveReportV1>,
    }

    impl RouteRunControlV1 for TestControlV1 {
        fn shutdown_requested(&mut self) -> Result<bool, RouteRunControlErrorV1> {
            Ok(self.shutdown)
        }

        fn wait(&mut self, duration: Duration) -> Result<(), RouteRunControlErrorV1> {
            self.waits.push(duration);
            Ok(())
        }

        fn record_progress(
            &mut self,
            report: RouteDriveReportV1,
        ) -> Result<(), RouteRunControlErrorV1> {
            self.progress.push(report);
            Ok(())
        }
    }

    fn report(disposition: RouteDriveDispositionV1, revision: u64) -> RouteDriveReportV1 {
        RouteDriveReportV1 {
            stage: RouteDriveStageV1::Admission,
            before_revision: revision,
            after_revision: revision + 1,
            disposition,
        }
    }

    #[test]
    fn focused_relay_services_peer_waiting_on_sibling_after_accept_yields() {
        struct WaitingSibling {
            selected: LegIdV1,
            pending: bool,
            calls: Vec<LegIdV1>,
        }
        impl CompositeRelayCycleV1 for WaitingSibling {
            type Error = ();

            fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<bool, ()> {
                self.calls.push(leg);
                if leg == self.selected {
                    // The selected accept has yielded to an already waiting
                    // peer on the opposite leg; no traffic moved yet.
                    Ok(false)
                } else {
                    assert!(self.pending);
                    self.pending = false;
                    Ok(true)
                }
            }
            fn backoff(&self) -> Duration {
                Duration::ZERO
            }
            fn leg_peer_pending_v25(&self, leg: LegIdV1) -> bool {
                self.pending && leg != self.selected
            }
        }
        for (selected, sibling) in [
            (LegIdV1::Upstream, LegIdV1::Downstream),
            (LegIdV1::Downstream, LegIdV1::Upstream),
        ] {
            let mut relay = WaitingSibling {
                selected,
                pending: true,
                calls: Vec::new(),
            };
            let mut route = TestRouteV1 {
                log: Rc::new(RefCell::new(Vec::new())),
                reports: Vec::new(),
            };
            let mut renewals = 0;
            assert_eq!(
                run_relay_leg_v25(
                    &mut relay,
                    &mut route,
                    &mut TestControlV1::default(),
                    &mut || {
                        renewals += 1;
                        Ok(())
                    },
                    selected,
                )
                .expect("queued sibling is serviced within the focused pass"),
                CompositeRelayHalfV25::Stepped { moved: true }
            );
            assert!(!relay.pending);
            assert_eq!(relay.calls, [selected, sibling]);
            assert_eq!(renewals, 2);
        }
    }

    #[test]
    fn focused_relay_services_only_the_selected_leg_and_honours_shutdown() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff: Duration::from_millis(1),
        };
        let mut route = TestRouteV1 {
            log: Rc::clone(&log),
            reports: Vec::new(),
        };
        let mut control = TestControlV1::default();
        let mut renewals = 0_u8;
        assert_eq!(
            run_relay_leg_v25(
                &mut relay,
                &mut route,
                &mut control,
                &mut || {
                    renewals += 1;
                    Ok(())
                },
                LegIdV1::Downstream,
            )
            .expect("focused relay leg"),
            CompositeRelayHalfV25::Stepped { moved: false }
        );
        assert_eq!(log.borrow().as_slice(), ["downstream-relay"]);
        assert_eq!(renewals, 1);

        control.shutdown = true;
        assert_eq!(
            run_relay_leg_v25(
                &mut relay,
                &mut route,
                &mut control,
                &mut || {
                    renewals += 1;
                    Ok(())
                },
                LegIdV1::Upstream,
            )
            .expect("shutdown is a normal focused-relay outcome"),
            CompositeRelayHalfV25::Shutdown
        );
        assert_eq!(log.borrow().as_slice(), ["downstream-relay"]);
        assert_eq!(renewals, 1);
    }

    #[test]
    fn interleaving_is_upstream_downstream_then_exactly_one_route_step() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff: Duration::from_millis(7),
        };
        let mut route = TestRouteV1 {
            log: Rc::clone(&log),
            reports: vec![
                report(RouteDriveDispositionV1::Progressed, 1),
                report(RouteDriveDispositionV1::Progressed, 2),
            ],
        };
        let mut control = TestControlV1::default();
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 2, &mut || Ok(()))
                .expect("bounded schedule"),
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 2 }
        );
        assert_eq!(
            log.borrow().as_slice(),
            [
                "upstream-relay",
                "downstream-relay",
                "route-step",
                "upstream-relay",
                "downstream-relay",
                "route-step"
            ]
        );
        assert_eq!(control.progress.len(), 2);
        assert!(control.waits.is_empty());
    }

    /// Reports moved traffic for the first `busy_rounds` full rounds (two leg
    /// steps each) and idles afterwards.
    struct BusyThenIdleRelayV1 {
        leg_steps: u64,
        busy_rounds: u64,
        backoff: Duration,
    }

    impl CompositeRelayCycleV1 for BusyThenIdleRelayV1 {
        type Error = ();

        fn step_relay_leg(&mut self, _: LegIdV1) -> Result<bool, Self::Error> {
            self.leg_steps += 1;
            Ok(self.leg_steps <= self.busy_rounds * 2)
        }

        fn backoff(&self) -> Duration {
            self.backoff
        }
    }

    impl CompositeActivationRelayV1 for BusyThenIdleRelayV1 {
        type Error = ();

        fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
            self.step_relay_leg(leg)
        }

        fn activation_backoff(&self) -> Duration {
            self.backoff
        }

        fn bootstrap_ready_v16(&self) -> bool {
            false
        }
    }

    #[test]
    fn waiting_route_does_not_pace_rounds_that_moved_relay_traffic() {
        let backoff = Duration::from_millis(9);
        let mut relay = BusyThenIdleRelayV1 {
            leg_steps: 0,
            busy_rounds: 2,
            backoff,
        };
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut route = TestRouteV1 {
            log,
            reports: vec![
                report(RouteDriveDispositionV1::Waiting, 1),
                report(RouteDriveDispositionV1::Waiting, 2),
                report(RouteDriveDispositionV1::Waiting, 3),
            ],
        };
        let mut control = TestControlV1::default();
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 3, &mut || Ok(()))
                .expect("bounded schedule"),
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 3 }
        );
        // Two ceremony rounds proceeded at line rate; only the idle third
        // round paid the poll interval.
        assert_eq!(control.waits, vec![backoff]);
    }

    #[test]
    fn waiting_route_still_paces_every_idle_round() {
        let backoff = Duration::from_millis(9);
        let mut relay = BusyThenIdleRelayV1 {
            leg_steps: 0,
            busy_rounds: 0,
            backoff,
        };
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut route = TestRouteV1 {
            log,
            reports: vec![
                report(RouteDriveDispositionV1::Waiting, 1),
                report(RouteDriveDispositionV1::Waiting, 2),
            ],
        };
        let mut control = TestControlV1::default();
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 2, &mut || Ok(()))
                .expect("bounded schedule"),
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 2 }
        );
        assert_eq!(control.waits, vec![backoff, backoff]);
    }

    #[test]
    fn activation_does_not_pace_rounds_that_moved_relay_traffic() {
        let backoff = Duration::from_millis(13);
        let mut relay = BusyThenIdleRelayV1 {
            leg_steps: 0,
            busy_rounds: 1,
            backoff,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: u64::MAX,
        };
        let mut control = TestControlV1::default();
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 3, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
        ));
        // The first round exchanged envelopes and skipped the poll interval;
        // the two idle rounds paid it exactly as before.
        assert_eq!(control.waits, vec![backoff, backoff]);
    }

    #[test]
    fn activation_checks_retained_receiver_before_and_after_network_round() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let backoff = Duration::from_millis(11);
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            // Initial retained check, post-resume check, then post-network.
            ready_on_call: 3,
        };
        let mut control = TestControlV1::default();
        match run_activation_core_v1(&mut relay, &mut receiver, &mut control, 3, &mut || Ok(()))
            .expect("activation schedule")
        {
            CompositeActivationCoreExitV1::Ready(value) => assert_eq!(value, 7),
            CompositeActivationCoreExitV1::Shutdown
            | CompositeActivationCoreExitV1::RoundBudgetExhausted => panic!("not ready"),
        }
        assert_eq!(
            log.borrow().as_slice(),
            ["upstream-relay", "downstream-relay"]
        );
        assert_eq!(receiver.calls, 3);
        assert!(control.waits.is_empty());
    }

    #[test]
    fn only_exact_f6_awaiting_error_is_retryable_during_pair_activation() {
        let awaiting = ProductionCompositeLoopErrorV1::Inbound(
            ProductionContractsPollErrorV1::Worker(RelayWorkerInboundErrorV1::F6(
                route_transport::F6DispatchErrorV1::F6(ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::AuthenticatedRfq {
                        position: SettlementPositionV2::Downstream,
                    },
                )),
            )),
        );
        assert!(is_f6_activation_awaiting(&awaiting));
        assert!(!is_f6_activation_awaiting(
            &ProductionCompositeLoopErrorV1::ClockUnavailable
        ));
    }

    struct RetainedActivationRelayV23 {
        resumed: bool,
        refuse_resume: bool,
        network_calls: u64,
        resume_calls: u64,
    }

    impl CompositeActivationRelayV1 for RetainedActivationRelayV23 {
        type Error = ProductionCompositeLoopErrorV1;

        fn resume_local_activation_leg_v25(
            &mut self,
            leg: LegIdV1,
            _renew_actuator_lease: &mut dyn FnMut() -> Result<(), ()>,
        ) -> Result<(), Self::Error> {
            if leg == LegIdV1::Upstream {
                return self.resume_local_activation_v23();
            }
            Ok(())
        }

        fn resume_local_activation_v23(&mut self) -> Result<(), Self::Error> {
            self.resume_calls += 1;
            if self.refuse_resume {
                return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
            }
            self.resumed = true;
            Ok(())
        }

        fn step_activation_leg(&mut self, _: LegIdV1) -> Result<bool, Self::Error> {
            self.network_calls += 1;
            Err(ProductionCompositeLoopErrorV1::Network(
                ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable,
            ))
        }

        fn bootstrap_ready_v16(&self) -> bool {
            self.resumed
        }

        fn activation_backoff(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    #[test]
    fn reopened_authenticated_ready_is_consumed_without_contacting_absent_peer() {
        let mut relay = RetainedActivationRelayV23 {
            resumed: false,
            refuse_resume: false,
            network_calls: 0,
            resume_calls: 0,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 1,
        };
        let mut control = TestControlV1::default();
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::Ready(7))
        ));
        assert!(relay.resumed);
        assert_eq!(relay.resume_calls, 1);
        assert_eq!(relay.network_calls, 0);
        assert_eq!(receiver.calls, 1);
        assert!(control.waits.is_empty());
    }

    #[test]
    fn initially_ready_activation_never_resumes_bootstrap_or_contacts_peer() {
        let mut relay = RetainedActivationRelayV23 {
            resumed: true,
            refuse_resume: true,
            network_calls: 0,
            resume_calls: 0,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 1,
        };
        let mut control = TestControlV1::default();
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::Ready(7))
        ));
        assert_eq!(relay.resume_calls, 0);
        assert_eq!(relay.network_calls, 0);
        assert_eq!(receiver.calls, 1);
        assert!(control.waits.is_empty());
    }

    #[test]
    fn refused_local_resume_never_consumes_ready_or_contacts_peer() {
        let mut relay = RetainedActivationRelayV23 {
            resumed: false,
            refuse_resume: true,
            network_calls: 0,
            resume_calls: 0,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 1,
        };
        assert!(matches!(
            run_activation_core_v1(
                &mut relay,
                &mut receiver,
                &mut TestControlV1::default(),
                1,
                &mut || Ok(())
            ),
            Err(CompositeActivationCoreErrorV1::Relay(
                ProductionCompositeLoopErrorV1::InvalidConfiguration
            ))
        ));
        assert_eq!(relay.network_calls, 0);
        assert_eq!(relay.resume_calls, 1);
        assert_eq!(receiver.calls, 0);
    }

    #[test]
    fn transport_absence_polls_durable_ingress_but_never_invents_exchange_success() {
        use ProductionRelayNetworkRuntimeErrorV1 as Network;
        for error in [
            Network::ConnectUnavailable,
            Network::AcceptDeadlineElapsed,
            Network::ChannelUnavailable,
        ] {
            let mut polled = false;
            let result = complete_exchange_poll_v23::<(), _>(
                Err(ProductionCompositeLoopErrorV1::Network(error)),
                |exchange| {
                    assert!(exchange.is_none());
                    polled = true;
                    Ok(())
                },
            );
            assert!(polled);
            assert!(
                matches!(result, Err(ProductionCompositeLoopErrorV1::Network(actual)) if actual == error)
            );
        }
    }

    #[test]
    fn authentication_configuration_and_storage_errors_are_never_peer_absence() {
        use ProductionRelayNetworkRuntimeErrorV1 as Network;
        for error in [
            Network::InvalidConfiguration,
            Network::ListenUnavailable,
            Network::AuthenticatedExchangeFailed,
            Network::DurableRelayUnavailable,
        ] {
            let result = complete_exchange_poll_v23::<(), ()>(
                Err(ProductionCompositeLoopErrorV1::Network(error)),
                |_| panic!("fatal network refusal must not poll or advance recovery"),
            );
            assert!(
                matches!(result, Err(ProductionCompositeLoopErrorV1::Network(actual)) if actual == error)
            );
            assert!(!is_peer_temporarily_unavailable_v23(
                &ProductionCompositeLoopErrorV1::Network(error)
            ));
        }
        assert!(!is_peer_temporarily_unavailable_v23(
            &ProductionCompositeLoopErrorV1::ClockUnavailable
        ));
    }

    #[test]
    fn local_validation_refusal_has_priority_over_peer_timeout() {
        let result = complete_exchange_poll_v23::<(), ()>(
            Err(ProductionCompositeLoopErrorV1::Network(
                ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed,
            )),
            |_| Err(ProductionCompositeLoopErrorV1::ClockUnavailable),
        );
        assert!(matches!(
            result,
            Err(ProductionCompositeLoopErrorV1::ClockUnavailable)
        ));
    }

    struct UnavailableCycleV23 {
        error: ProductionRelayNetworkRuntimeErrorV1,
        polls: usize,
    }

    impl CompositeRelayCycleV1 for UnavailableCycleV23 {
        type Error = ProductionCompositeLoopErrorV1;
        fn step_relay_leg(&mut self, _: LegIdV1) -> Result<bool, Self::Error> {
            let result = complete_exchange_poll_v23::<(), _>(
                Err(ProductionCompositeLoopErrorV1::Network(self.error)),
                |_| {
                    self.polls += 1;
                    Ok(())
                },
            );
            match result {
                Ok(_) => Ok(false),
                Err(error) if is_peer_temporarily_unavailable_v23(&error) => Ok(false),
                Err(error) => Err(error),
            }
        }
        fn backoff(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    impl CompositeActivationRelayV1 for UnavailableCycleV23 {
        type Error = ProductionCompositeLoopErrorV1;

        fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
            self.step_relay_leg(leg)
        }

        fn activation_backoff(&self) -> Duration {
            self.backoff()
        }
    }

    #[test]
    fn absent_peer_without_retained_f6_authority_remains_bounded_and_not_ready() {
        let mut relay = UnavailableCycleV23 {
            error: ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed,
            polls: 0,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 0,
        };
        let mut control = TestControlV1::default();
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 2, &mut || Ok(())),
            Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
        ));
        assert_eq!(relay.polls, 4);
        assert_eq!(receiver.calls, 6);
        assert_eq!(control.waits, [Duration::from_millis(1); 2]);
    }

    #[test]
    fn absent_peer_keeps_recovery_interleaved_but_failed_authentication_stops_it() {
        for (error, expected_polls) in [
            (ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable, 2),
            (
                ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed,
                2,
            ),
            (ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable, 2),
            (
                ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed,
                0,
            ),
        ] {
            let log = Rc::new(RefCell::new(Vec::new()));
            let mut route = TestRouteV1 {
                log: Rc::clone(&log),
                reports: vec![report(RouteDriveDispositionV1::RecoveryRequired, 4)],
            };
            let mut relay = UnavailableCycleV23 { error, polls: 0 };
            let mut control = TestControlV1::default();
            let result =
                run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1, &mut || Ok(()));
            assert_eq!(relay.polls, expected_polls);
            if expected_polls == 0 {
                assert!(matches!(result, Err(CompositeCoreErrorV1::Relay(_))));
                assert!(log.borrow().is_empty());
                assert!(control.progress.is_empty());
            } else {
                assert!(matches!(
                    result,
                    Ok(ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 1 })
                ));
                assert_eq!(log.borrow().as_slice(), ["route-step"]);
                assert_eq!(control.progress.len(), 1);
                assert_eq!(control.waits, [Duration::from_millis(1)]);
            }
        }
    }

    #[test]
    fn v16_only_native_verified_claim_wait_preserves_runtime_progress() {
        use crate::relay_worker::ContractsRelayIngressErrorV1 as Ingress;
        let wrap = |error| {
            ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
                RelayWorkerInboundErrorV1::Contracts(
                    route_transport::RouteDispatchErrorV1::Contracts(
                        route_transport::FramedContractsTransportErrorV2::Contracts(error),
                    ),
                ),
            ))
        };
        assert!(is_claim_finality_awaiting_v16(&wrap(
            Ingress::AwaitingFinalClaimObservationV16
        )));
        assert!(is_template_construction_awaiting_v17(&wrap(
            Ingress::AwaitingNativeXmrRefundTransportV23
        )));
        assert!(is_funding_handoff_awaiting_v25(&wrap(
            Ingress::AwaitingNativeXmrFundingHandoffV25
        )));
        assert!(is_funding_handoff_awaiting_v25(&wrap(
            Ingress::AwaitingNativeXmrReadinessGateV25
        )));
        for error in [
            Ingress::UnpreparedMessage,
            Ingress::InvalidDsc1,
            Ingress::SenderMismatch,
            Ingress::WrongAuthority,
            Ingress::InvalidReceipt,
            Ingress::Store(dom_scriptless_store::SessionStoreError::Quarantined),
            Ingress::Store(dom_scriptless_store::SessionStoreError::InvalidDomTransaction),
        ] {
            let wrapped = wrap(error);
            assert!(!is_template_construction_awaiting_v17(&wrapped));
            assert!(!is_claim_finality_awaiting_v16(&wrapped));
            assert!(!is_funding_handoff_awaiting_v25(&wrapped));
        }
    }

    #[test]
    fn shutdown_prevents_every_relay_and_route_call() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff: Duration::from_millis(7),
        };
        let mut route = TestRouteV1 {
            log: Rc::clone(&log),
            reports: vec![report(RouteDriveDispositionV1::Progressed, 1)],
        };
        let mut control = TestControlV1 {
            shutdown: true,
            ..TestControlV1::default()
        };
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1, &mut || Ok(()))
                .expect("shutdown"),
            ProductionCompositeRuntimeExitV1::Shutdown { rounds: 0 }
        );
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn waiting_uses_only_the_bounded_composite_backoff() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let backoff = Duration::from_millis(17);
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff,
        };
        let mut route = TestRouteV1 {
            log,
            reports: vec![report(RouteDriveDispositionV1::Waiting, 1)],
        };
        let mut control = TestControlV1::default();
        let _ = run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1, &mut || Ok(()))
            .expect("bounded waiting");
        assert_eq!(control.waits, vec![backoff]);
    }

    #[test]
    fn composite_bounds_reject_zero_and_long_blocking_windows() {
        let bounded = ProductionCompositeLoopConfigV1::new(
            Duration::from_secs(2),
            Duration::from_secs(3),
            Duration::from_secs(4),
            Duration::from_millis(1),
            1,
        )
        .unwrap();
        // One connection carries EXCHANGE_SCOPES_PER_CONNECTION_V25 scopes,
        // each holding the full exchange bound: max(connect, accept) + 5 * 4.
        assert_eq!(
            bounded.blocking_bound,
            Duration::from_secs(3 + 4 * u64::from(EXCHANGE_SCOPES_PER_CONNECTION_V25))
        );
        // 20 + 5 * 30 = 170 s exceeds the 5 * 30 s composite ceiling.
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::from_secs(15),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::from_millis(1),
            1,
        )
        .is_err());
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::ZERO,
            Duration::from_millis(25),
            Duration::from_millis(100),
            Duration::from_millis(1),
            1,
        )
        .is_err());
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::from_secs(31),
            Duration::from_millis(25),
            Duration::from_millis(100),
            Duration::from_millis(1),
            1,
        )
        .is_err());
    }

    #[test]
    fn relay_leg_mapping_is_exhaustive_and_stable() {
        assert_eq!(relay_index(LegIdV1::Upstream), 0);
        assert_eq!(relay_index(LegIdV1::Downstream), 1);
        assert_eq!(
            relay_position(LegIdV1::Upstream),
            ProductionRelayLinkPositionV1::Upstream
        );
        assert_eq!(
            relay_position(LegIdV1::Downstream),
            ProductionRelayLinkPositionV1::Downstream
        );
    }
}
