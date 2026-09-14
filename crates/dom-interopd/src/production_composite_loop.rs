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
const MIN_BACKOFF_V1: Duration = Duration::from_millis(1);
const MAX_ACTIVATION_ROUNDS_V1: u64 = 1_000_000;
const MAX_INTERLEAVED_ROUNDS_V1: u64 = 1_000_000;

/// Operational drain limits, not negotiated route or Relay message expiry.
/// Time is fixed once; neither an unavailable peer nor a new frame renews it.
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
        // the network runtime below.
        let blocking_bound = connect_timeout
            .max(accept_timeout)
            .checked_add(exchange_timeout)
            .filter(|bound| *bound <= MAX_COMPOSITE_BLOCKING_BOUND_V1)
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
    #[error("production composite F6 activation failed")]
    Activation(#[source] ProductionF6ActivationRefusalV2),
    #[error("production composite route runtime failed")]
    Route(#[source] RouteRuntimeErrorV1),
    #[error("production composite shutdown/backoff control failed")]
    Control(#[source] RouteRunControlErrorV1),
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
        })
    }

    /// Executes exactly one submit/exchange/poll cycle for one named leg.
    pub(crate) fn step_leg(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        self.validate_retained_peer_scope_v23()?;
        self.step_local_bootstrap_v23(leg)?;
        self.step_exchange_and_poll_v23(leg)
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
            let (identity, relay) = self.owner.identity_and_relay_mut();
            self.network
                .exchange_configured_link(
                    self.network_config.link(position),
                    &self.sessions[index],
                    identity,
                    relay,
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
        let TimelockSpec::TimestampSeconds { value: now } = self.fresh_relay_time()? else {
            return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
        };
        self.owner.step_bootstrap_v16(leg, now).map_err(|error| {
            ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                context: ProductionCompositeBootstrapContextV25::LocalBootstrap,
                error,
            }
        })?;
        if self
            .owner
            .recovery_mounted_for_readiness_v23(leg)
            .map_err(ProductionCompositeLoopErrorV1::Bootstrap)?
        {
            let selected = self.owner.leg_mut(leg);
            let chain = selected.trusted_chain_id();
            selected
                .contracts_mut()
                .step_f7_readiness_v19(chain, now)
                .map_err(ProductionCompositeLoopErrorV1::F7Readiness)?;
        }
        Ok(())
    }

    fn step_exchange_and_poll_v23(
        &mut self,
        leg: LegIdV1,
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
        let exchange = {
            let link = self.network_config.link(position);
            let session = &self.sessions[session_index];
            let (identity, relay) = self.owner.identity_and_relay_mut();
            self.network
                .exchange_configured_link(link, session, identity, relay)
                .map_err(ProductionCompositeLoopErrorV1::Network)
        };

        let (exchange, inbound) = complete_exchange_poll_v23(exchange, |exchange| {
            if let Some(candidate) = exchange.and_then(|report| report.graph_candidate_v22.take()) {
                match self.owner.receive_xmr_graph_candidate_v22(leg, candidate) {
                    Ok(()) => {}
                    // First-contact race: the peer's candidate arrived before
                    // this side retained the surfaces it binds to. It stays
                    // memory-only and unacknowledged; the peer's next
                    // exchange re-sends it and a later round consumes it
                    // through the full validation (the terminal-refund path
                    // already applies this rule). Every refusal of the
                    // candidate's own content still fails the leg below.
                    Err(
                        crate::production_contracts::ProductionBootstrapRuntimeErrorV16::AwaitingGraphCandidateSurfacesV25,
                    ) => {}
                    Err(error) => {
                        return Err(ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                            context: ProductionCompositeBootstrapContextV25::GraphCandidate,
                            error,
                        });
                    }
                }
            }
            self.poll_retained_inbound_v23(leg)
        })?;
        Ok(ProductionCompositeRelayStepReportV1 {
            leg,
            outbound,
            exchange,
            inbound,
        })
    }

    fn poll_retained_inbound_v23(
        &mut self,
        leg: LegIdV1,
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
        self.owner
            .step_bootstrap_v16(leg, after_exchange)
            .map_err(|error| ProductionCompositeLoopErrorV1::BootstrapAtV25 {
                context: ProductionCompositeBootstrapContextV25::PostExchangeBootstrap,
                error,
            })?;
        if self
            .owner
            .recovery_mounted_for_readiness_v23(leg)
            .map_err(ProductionCompositeLoopErrorV1::Bootstrap)?
        {
            let selected = self.owner.leg_mut(leg);
            let chain = selected.trusted_chain_id();
            selected
                .contracts_mut()
                .step_f7_readiness_v19(chain, after_exchange)
                .map_err(ProductionCompositeLoopErrorV1::F7Readiness)?;
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
                contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::RecoverySigningInbound)?;
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
    /// Returns whether the leg moved authenticated relay traffic this round;
    /// see [`CompositeRelayCycleV1::step_relay_leg`]. Used only to skip the
    /// idle backoff between actively exchanging rounds.
    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error>;
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

    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<bool, Self::Error> {
        match self.step_leg(leg) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            Err(error) if is_f6_activation_awaiting(&error) => Ok(false),
            Err(error) if is_template_construction_awaiting_v17(&error) => Ok(false),
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
        relay
            .resume_local_activation_v23()
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        if relay.bootstrap_ready_v16() {
            if let Some(ready) = receiver
                .take_activation_ready()
                .map_err(CompositeActivationCoreErrorV1::Receiver)?
            {
                return Ok(CompositeActivationCoreExitV1::Ready(ready));
            }
        }
        let mut relay_moved_traffic = false;
        relay_moved_traffic |= relay
            .step_activation_leg(LegIdV1::Upstream)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        relay_moved_traffic |= relay
            .step_activation_leg(LegIdV1::Downstream)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
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
        })
    }

    /// Drives both legs until the exact pair receiver releases the route Store.
    /// `Ready` is constructed only from a successful `take_ready()` call.
    pub(crate) fn activate_bounded<Ctl: RouteRunControlV1>(
        mut self,
        control: &mut Ctl,
    ) -> ProductionCompositeActivationExitV1 {
        let outcome = match run_activation_core_v1(
            &mut self.relay,
            &mut self.receiver,
            control,
            self.round_budget,
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
    fn backoff(&self) -> Duration;
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
        match self.step_leg(leg) {
            Ok(report) => Ok(relay_step_moved_traffic_v1(&report)),
            // The exact 0x12 remains in the durable inbox. Return to the root
            // so its scanner can acquire finality, and continue the other leg
            // and recovery clock. Never ACK or classify bad evidence as absent.
            Err(error) if is_claim_finality_awaiting_v16(&error) => Ok(false),
            Err(error) if is_template_construction_awaiting_v17(&error) => Ok(false),
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
}

fn run_interleaved_core_v1<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    round_budget: u64,
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
        if control
            .shutdown_requested()
            .map_err(CompositeCoreErrorV1::Control)?
        {
            return Ok(ProductionCompositeRuntimeExitV1::Shutdown { rounds });
        }
        let mut relay_moved_traffic = false;
        for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
            route
                .prepare_relay_block_v23(relay.blocking_bound_v23())
                .map_err(CompositeCoreErrorV1::Route)?;
            relay_moved_traffic |= relay
                .step_relay_leg(leg)
                .map_err(CompositeCoreErrorV1::Relay)?;
        }
        let report = route.step_route().map_err(CompositeCoreErrorV1::Route)?;
        rounds = rounds
            .checked_add(1)
            .ok_or(CompositeCoreErrorV1::InvalidConfiguration)?;
        control
            .record_progress(report)
            .map_err(CompositeCoreErrorV1::Control)?;
        if report.disposition == RouteDriveDispositionV1::Terminal {
            return Ok(ProductionCompositeRuntimeExitV1::Terminal { rounds, report });
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
            control
                .wait(relay.backoff())
                .map_err(CompositeCoreErrorV1::Control)?;
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
    run_interleaved_core_v1(relay, route, control, round_budget).map_err(|error| match error {
        CompositeCoreErrorV1::Relay(error) => error,
        CompositeCoreErrorV1::Route(error) => ProductionCompositeLoopErrorV1::Route(error),
        CompositeCoreErrorV1::Control(error) => ProductionCompositeLoopErrorV1::Control(error),
        CompositeCoreErrorV1::InvalidConfiguration => {
            ProductionCompositeLoopErrorV1::InvalidConfiguration
        }
    })
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

fn is_claim_finality_awaiting_v16(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(error, ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
        RelayWorkerInboundErrorV1::Contracts(route_transport::RouteDispatchErrorV1::Contracts(
            route_transport::FramedContractsTransportErrorV2::Contracts(
                crate::relay_worker::ContractsRelayIngressErrorV1::AwaitingFinalClaimObservationV16))))))
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
            .split("    loop {")
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 2),
            Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
        ));
        assert_eq!(receiver.calls, 0);
        assert_eq!(relay.ticks, [2, 2]);
        assert!(matches!(
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1),
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1),
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
        for refuse_on in [0, 1, 2] {
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
            let result =
                run_interleaved_core_v1(&mut relay, &mut route, &mut TestControlV1::default(), 1);
            if refuse_on == 0 {
                assert!(result.is_ok());
                assert_eq!(
                    log.borrow().as_slice(),
                    [
                        "renew-route",
                        "upstream-relay",
                        "renew-route",
                        "downstream-relay",
                        "route-step"
                    ]
                );
            } else {
                assert!(matches!(result, Err(CompositeCoreErrorV1::Route(()))));
                let expected: &[&str] = if refuse_on == 1 {
                    &["renew-route"]
                } else {
                    &["renew-route", "upstream-relay", "renew-route"]
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
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 2)
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
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 3)
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
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 2)
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 3),
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
        match run_activation_core_v1(&mut relay, &mut receiver, &mut control, 3)
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1),
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 1),
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut TestControlV1::default(), 1),
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
            run_activation_core_v1(&mut relay, &mut receiver, &mut control, 2),
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
            let result = run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1);
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
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1).expect("shutdown"),
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
        let _ = run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1)
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
        assert_eq!(bounded.blocking_bound, Duration::from_secs(7));
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::from_secs(15),
            Duration::from_secs(20),
            Duration::from_secs(11),
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
