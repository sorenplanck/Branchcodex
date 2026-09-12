//! Actual release-production child processes, not the in-process graph fixture.
//! Every chain endpoint is a private loopback ledger with Mainnet wire profiles.
//! This is not a mined-mainnet acceptance test and does not move real funds.
use super::xmr_graph_wallet_tests::native_observation_v23::Configuration;
use super::{NativeMainnetStartupV23, NativeXmrRunningColdStartV23};
use crate::production_xmr_native_binary_v23_tests::{NativeDaemonBinaryV23, NativeDaemonModeV23};
use route_executor::{
    ActionProgressV1, CoordinationPhaseV1, LegIdV1, LegSnapshotV1, RouteSnapshotV1,
    SecretVisibilityV1,
};
use std::{
    net::TcpListener,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "production_xmr_native_daemon_scenario_v23_observer.rs"]
pub(super) mod observer;
use observer::RouteObserverV23;
#[path = "production_xmr_native_daemon_scenario_v23_barrier.rs"]
mod barrier;
use barrier::{NativeBarrierV23, XmrLedgerPumpV23};
#[path = "production_xmr_native_daemon_scenario_v23_coordinator.rs"]
pub(super) mod coordinator;
use coordinator::{CoordinatorObserverV23, NativeActionV23};
use route_executor::ActionKindV1;
#[path = "production_xmr_native_refund_publication_v24_tests.rs"]
mod refund_publication_v24;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PHASE_TIMEOUT: Duration = Duration::from_secs(7200);

fn fresh_local_policy() -> Result<route_time_anchor::RouteTimePolicyLimitsV2> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    // An explicit NEW local negotiation, before registry/time signing. These
    // values never change an already-admitted route or its availability terms.
    Ok(route_time_anchor::RouteTimePolicyLimitsV2 {
        valid_from_seconds: now.checked_sub(60).ok_or("scenario clock before epoch")?,
        expires_at_seconds: now.checked_add(21600).ok_or("scenario clock overflow")?,
        max_evidence_age_seconds: 21600,
        max_anchor_interval_width_seconds: 600,
        max_anchor_time_skew_seconds: 1800,
        max_future_skew_seconds: 600,
        max_upstream_funding_anchor_delay_seconds: 14400,
        max_downstream_funding_anchor_delay_seconds: 14400,
        hub_margin_seconds: 300,
        counterparty_margin_seconds: 300,
    })
}

fn launch(
    startup: NativeMainnetStartupV23,
    binary: &NativeDaemonBinaryV23,
) -> Result<NativeXmrRunningColdStartV23> {
    // Reserve two simultaneous distinct loopback ports; release only for the
    // actual daemon bind. Bind races are failures, never silent port retries.
    let first = TcpListener::bind("127.0.0.1:0")?;
    let second = TcpListener::bind("127.0.0.1:0")?;
    let addresses = [first.local_addr()?, second.local_addr()?];
    drop((first, second));
    startup.export_and_launch_shared_peer_v23(binary, addresses, 1)
}

fn observers(running: &NativeXmrRunningColdStartV23) -> Result<[RouteObserverV23; 2]> {
    let result = [
        RouteObserverV23::new(running.state_dir(0)?)?,
        RouteObserverV23::new(running.state_dir(1)?)?,
    ];
    if result[0].route_id() != result[1].route_id() {
        return Err("actual actors exported different route identities".into());
    }
    Ok(result)
}

fn claimed(snapshot: &RouteSnapshotV1) -> bool {
    !snapshot.aborted_unfunded
        && snapshot.coordination == CoordinationPhaseV1::Terminal
        && !snapshot.has_open_funds()
        && matches!(
            snapshot.secret_visibility,
            SecretVisibilityV1::Public { .. }
        )
        && [&snapshot.upstream, &snapshot.downstream]
            .iter()
            .all(|leg| {
                leg.funding.progress() == ActionProgressV1::Final
                    && leg.claim.progress() == ActionProgressV1::Final
                    && leg.refund.progress() == ActionProgressV1::NotPrepared
                    && leg.dom_compensation_v12.is_none()
            })
}

fn require_claimed(snapshot: &RouteSnapshotV1) -> Result<()> {
    if !claimed(snapshot) {
        return Err("real daemon did not prove both funded claims final and secret public".into());
    }
    for leg in [&snapshot.upstream, &snapshot.downstream] {
        if leg.funding.transaction_id().is_none()
            || leg.claim.transaction_id().is_none()
            || leg.funding.transaction_id() == leg.claim.transaction_id()
        {
            return Err("funding and claim economic identities absent or aliased".into());
        }
    }
    Ok(())
}

fn wait_claims(
    running: &mut NativeXmrRunningColdStartV23,
    observers: &mut [RouteObserverV23; 2],
    xmr: &mut XmrLedgerPumpV23,
) -> Result<()> {
    let start = Instant::now();
    let mut announced = Duration::ZERO;
    loop {
        let mut complete = true;
        let mut scoped_snapshots = Vec::with_capacity(2);
        for actor in 0..2 {
            let exited = running.poll_actor_v23(actor)?;
            if exited.is_some_and(|status| !status.success()) {
                return Err("real daemon exited unsuccessfully before final claims".into());
            }
            match observers[actor].poll()? {
                Some(snapshot) => {
                    if snapshot.aborted_unfunded {
                        return Err(
                            "real daemon aborted unfunded; this is not a successful swap".into(),
                        );
                    }
                    if exited.is_some() && !claimed(&snapshot) {
                        return Err("daemon exit 0 did not leave both economic claims final".into());
                    }
                    complete &= claimed(&snapshot) && exited.is_some();
                    scoped_snapshots.push(snapshot);
                }
                None if exited.is_some() => return Err("daemon exit has no durable route".into()),
                None => complete = false,
            }
        }
        xmr.pump(running, &scoped_snapshots.iter().collect::<Vec<_>>())?;
        if complete {
            return Ok(());
        }
        if start.elapsed() >= PHASE_TIMEOUT {
            return Err("real daemon claim observation reached its explicit deadline".into());
        }
        if start.elapsed().saturating_sub(announced) >= Duration::from_secs(30) {
            announced = start.elapsed();
            eprintln!(
                "native real daemon: awaiting two final economic claims after {}s",
                announced.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// A dedicated dependency-gated test: absent real release binary/helper is an
/// error, not ignore/skip/fallback. CI must build those dependencies first.
#[test]
#[ignore = "dedicated real release-production daemon and GPL helper campaign; mandatory CI uses --ignored --exact"]
fn native_real_daemon_two_claims_survive_original_store_reopen_v23() -> Result<()> {
    let binary = NativeDaemonBinaryV23::from_environment()?;
    let configuration = Configuration::require()?;
    let startup = NativeMainnetStartupV23::prepare(&configuration, fresh_local_policy()?, 10_000)?;
    let mut xmr = XmrLedgerPumpV23::new(&startup)?;
    let mut running = launch(startup, &binary)?;
    let result = (|| -> Result<()> {
        let mut observers = observers(&running)?;
        wait_claims(&mut running, &mut observers, &mut xmr)?;
        running.reap_successful_actor_v23(0)?;
        running.reap_successful_actor_v23(1)?;
        let before = [
            observers[0].replay_stopped()?,
            observers[1].replay_stopped()?,
        ];
        for snapshot in &before {
            require_claimed(snapshot)?;
        }
        for actor in 0..2 {
            require_native_claims(running.state_dir(actor)?, &before[actor])?;
        }
        for (left, right) in [
            (&before[0].upstream, &before[1].upstream),
            (&before[0].downstream, &before[1].downstream),
        ] {
            if left.funding.transaction_id() != right.funding.transaction_id()
                || left.claim.transaction_id() != right.claim.transaction_id()
            {
                return Err("real actors disagree on final funding or claim identities".into());
            }
        }
        let heartbeats = [observers[0].heartbeat()?, observers[1].heartbeat()?];
        running.restart_actor(0, &binary, NativeDaemonModeV23::Reopen)?;
        running.restart_actor(1, &binary, NativeDaemonModeV23::Reopen)?;
        let restarted = Instant::now();
        loop {
            let mut ready = true;
            for actor in 0..2 {
                let exited = running.poll_actor_v23(actor)?;
                if exited.is_some_and(|status| !status.success()) {
                    return Err("reopened daemon exited unsuccessfully".into());
                }
                // Successful natural return itself proves the newly invoked
                // binary completed startup. Otherwise demand a new heartbeat.
                ready &= exited.is_some()
                    || observers[actor]
                        .heartbeat()?
                        .advanced_from(heartbeats[actor]);
            }
            if ready {
                break;
            }
            if restarted.elapsed() >= PHASE_TIMEOUT {
                return Err(
                    "reopened real daemon never renewed its durable route heartbeat".into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        wait_claims(&mut running, &mut observers, &mut xmr)?;
        running.reap_successful_actor_v23(0)?;
        running.reap_successful_actor_v23(1)?;
        for actor in 0..2 {
            let after = observers[actor].replay_stopped()?;
            require_claimed(&after)?;
            require_native_claims(running.state_dir(actor)?, &after)?;
            // Recovery may add administrative journal events, but must never
            // replace economic identities, finality evidence or first exposure.
            if before[actor].upstream != after.upstream
                || before[actor].downstream != after.downstream
                || before[actor].secret_visibility != after.secret_visibility
                || before[actor].bindings != after.bindings
            {
                return Err("reopening changed final economic state or secret evidence".into());
            }
        }
        Ok(())
    })();
    if result.is_err() {
        running.retain_failed_fixture_v23();
    } else {
        running.retain_successful_fixture_v24()?;
    }
    result
}

/// A control implementation must capture actual canonical funding bytes before
/// their inclusion, not inject a snapshot or mint a funding/finality grant.
pub(super) struct FundingBoundaryV23 {
    pub(super) survivor: usize,
    pub(super) leg: LegIdV1,
    /// Actual native XMR hash (not the coordinator's domain-separated child ID).
    pub(super) funding_transaction_id: [u8; 32],
    /// RouteSnapshot contains the separate aggregate DOM+XMR action identity.
    pub(super) funding_aggregate_id: [u8; 32],
    /// Independent native DOM collateral identity actually retained by the barrier.
    pub(super) dom_collateral_transaction_id: [u8; 32],
}

#[test]
#[ignore = "dedicated real daemon noncooperative recovery campaign; mandatory CI uses --ignored --exact"]
fn native_real_daemon_dom_compensation_without_counterparty_v23() -> Result<()> {
    let binary = NativeDaemonBinaryV23::from_environment()?;
    let configuration = Configuration::require()?;
    let startup = NativeMainnetStartupV23::prepare(&configuration, fresh_local_policy()?, 10_000)?;
    let mut control = NativeBarrierV23::arm(&startup)?;
    run_noncooperative_recovery_v23(startup, &binary, &mut control)
}

#[test]
#[ignore = "dedicated real daemon XMR refund after final public U; mandatory CI uses --ignored --exact"]
fn native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23() -> Result<()> {
    let binary = NativeDaemonBinaryV23::from_environment()?;
    let configuration = Configuration::require()?;
    let startup = NativeMainnetStartupV23::prepare(&configuration, fresh_local_policy()?, 10_000)?;
    let mut control = NativeBarrierV23::arm(&startup)?;
    run_noncooperative_exit_v23(startup, &binary, &mut control, RecoveryExitV23::XmrRefund)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryExitV23 {
    DomCompensation,
    XmrRefund,
}

pub(super) trait FundingBarrierControlV23 {
    /// Read public canonical DOM U-final evidence while the XMR signer is stopped.
    /// The returned transaction identity is test evidence, never authority.
    fn wait_public_refund_v24(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
        timeout: Duration,
    ) -> Result<[u8; 32]>;

    fn wait_retained_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        timeout: Duration,
    ) -> Result<FundingBoundaryV23>;

    /// Admit the retained bytes with the real local verifier without moving
    /// the deadline yet: the survivor must first observe its actual funding.
    fn release_retained_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
    ) -> Result<()>;

    /// Advance only after funded finality, preserving original availability.
    fn advance_recovery(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()>;

    fn pump_expected_xmr(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()>;

    fn advance_refund_window(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()>;

    fn confirm_stopped_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()>;
}

fn selected(snapshot: &RouteSnapshotV1, leg: LegIdV1) -> &LegSnapshotV1 {
    if leg == LegIdV1::Upstream {
        &snapshot.upstream
    } else {
        &snapshot.downstream
    }
}

fn recovered(snapshot: &RouteSnapshotV1, boundary: &FundingBoundaryV23) -> bool {
    let leg = selected(snapshot, boundary.leg);
    !snapshot.aborted_unfunded
        && !snapshot.has_open_funds()
        && leg.funding.progress() == ActionProgressV1::Final
        && leg.funding.transaction_id() == Some(boundary.funding_aggregate_id)
        && leg.claim.progress() == ActionProgressV1::NotPrepared
        && leg.refund.progress() == ActionProgressV1::NotPrepared
        && leg
            .dom_compensation_v12
            .as_ref()
            .is_some_and(|compensation| {
                compensation.funding_transaction_id == boundary.dom_collateral_transaction_id
                    && compensation.transaction_id != boundary.dom_collateral_transaction_id
                    && compensation.payout_noms > 0
            })
        && matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
}

fn xmr_refunded(snapshot: &RouteSnapshotV1, boundary: &FundingBoundaryV23) -> bool {
    let leg = selected(snapshot, boundary.leg);
    !snapshot.aborted_unfunded
        && !snapshot.has_open_funds()
        && matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
        && leg.funding.progress() == ActionProgressV1::Final
        && leg.funding.transaction_id() == Some(boundary.funding_aggregate_id)
        && leg.claim.progress() == ActionProgressV1::NotPrepared
        && leg.dom_compensation_v12.is_none()
        && leg.refund.progress() == ActionProgressV1::Final
        && leg.refund.transaction_id().is_some_and(|id| {
            id != [0; 32]
                && id != boundary.funding_transaction_id
                && id != boundary.dom_collateral_transaction_id
        })
}

fn exit_proven(
    snapshot: &RouteSnapshotV1,
    boundary: &FundingBoundaryV23,
    expected: RecoveryExitV23,
) -> bool {
    match expected {
        RecoveryExitV23::DomCompensation => recovered(snapshot, boundary),
        RecoveryExitV23::XmrRefund => xmr_refunded(snapshot, boundary),
    }
}

/// Caller must install its private submission barrier before launch and pass
/// the same ledger owner here. Intentionally no permissive default controller.
pub(super) fn run_noncooperative_recovery_v23(
    startup: NativeMainnetStartupV23,
    binary: &NativeDaemonBinaryV23,
    control: &mut impl FundingBarrierControlV23,
) -> Result<()> {
    run_noncooperative_exit_v23(startup, binary, control, RecoveryExitV23::DomCompensation)
}

fn run_noncooperative_exit_v23(
    startup: NativeMainnetStartupV23,
    binary: &NativeDaemonBinaryV23,
    control: &mut impl FundingBarrierControlV23,
    expected: RecoveryExitV23,
) -> Result<()> {
    let mut running = launch(startup, binary)?;
    let result = (|| -> Result<()> {
        let mut observers = observers(&running)?;
        let boundary = control.wait_retained_funding(&mut running, PHASE_TIMEOUT)?;
        if boundary.survivor > 1
            || boundary.funding_transaction_id == [0; 32]
            || boundary.funding_aggregate_id == [0; 32]
            || boundary.dom_collateral_transaction_id == [0; 32]
            || boundary.dom_collateral_transaction_id == boundary.funding_transaction_id
        {
            return Err("invalid retained-funding actor or identity".into());
        }
        // Stop and reap both at the pending boundary. Compensation never
        // restarts the absent actor. Refund temporarily restarts the private U
        // owner only in its safe window, then removes it before XMR BUILD.
        // Its private database is never copied to the survivor.
        running.crash_actor(1 - boundary.survivor)?;
        running.crash_actor(boundary.survivor)?;
        let before = observers[boundary.survivor].replay_stopped()?;
        if !matches!(before.secret_visibility, SecretVisibilityV1::Private)
            || before.aborted_unfunded
            || selected(&before, boundary.leg).claim.progress() != ActionProgressV1::NotPrepared
        {
            return Err("noncooperative funding boundary already leaked secret or aborted".into());
        }
        control.release_retained_funding(&mut running, &boundary)?;
        running.restart_actor(boundary.survivor, binary, NativeDaemonModeV23::Reopen)?;
        // No XMR candidate is included while the route writer is running.
        // Upstream cannot become Final, so downstream cannot be committed by
        // the real reducer. Stop at the actual upstream broadcast checkpoint,
        // then confirm its native bytes and age the chains while BOTH writers
        // are stopped. This removes the observer-vs-downstream-admission race.
        let funding_started = Instant::now();
        let funded_offline = loop {
            running.require_running(boundary.survivor)?;
            if let Some(snapshot) = observers[boundary.survivor].poll()? {
                let leg = selected(&snapshot, boundary.leg);
                if !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
                    || snapshot.aborted_unfunded
                {
                    return Err("offline funding boundary exposed secret or aborted".into());
                }
                if leg.funding.progress() == ActionProgressV1::Committed
                    && leg
                        .funding
                        .effect()
                        .and_then(|effect| effect.expected_transaction_id)
                        == Some(boundary.funding_aggregate_id)
                    && CoordinatorObserverV23::new(running.state_dir(boundary.survivor)?)?
                        .poll(&snapshot, boundary.leg, ActionKindV1::Funding)?
                        .is_some_and(|action| {
                            action.xmr_dispatched
                                && action.matches_xmr(boundary.funding_transaction_id)
                        })
                    && running
                        .xmr_history_status_v23()?
                        .pool_tx_hashes
                        .contains(&boundary.funding_transaction_id)
                {
                    running.crash_actor(boundary.survivor)?;
                    let stopped = observers[boundary.survivor].replay_stopped()?;
                    if stopped.downstream.has_open_funds()
                        || stopped.upstream.funding.progress() != ActionProgressV1::Committed
                    {
                        return Err(
                            "upstream pool barrier did not retain an authentic unilateral route"
                                .into(),
                        );
                    }
                    break stopped;
                }
            }
            if funding_started.elapsed() >= PHASE_TIMEOUT {
                return Err("survivor did not retain its exact upstream funding broadcast".into());
            }
            thread::sleep(Duration::from_millis(100));
        };
        // The controller verifies actual local native finality before moving
        // deadlines; funded_offline remains Committed, never forged Final.
        control.confirm_stopped_funding(&mut running, &boundary, &funded_offline)?;
        match expected {
            RecoveryExitV23::DomCompensation => {
                control.advance_recovery(&mut running, &boundary, &funded_offline)?
            }
            RecoveryExitV23::XmrRefund => {
                control.advance_refund_window(&mut running, &boundary, &funded_offline)?
            }
        }
        if expected == RecoveryExitV23::XmrRefund {
            require_unbuilt_refund_v24(&funded_offline, &boundary)?;
            let frozen = barrier::stopped_inventory_v24(running.state_dir(boundary.survivor)?)?;
            running.restart_actor(1 - boundary.survivor, binary, NativeDaemonModeV23::Reopen)?;
            let public_refund = control.wait_public_refund_v24(
                &mut running,
                &boundary,
                &funded_offline,
                PHASE_TIMEOUT,
            )?;
            running.crash_actor(1 - boundary.survivor)?;
            if running.processes.iter().any(Option::is_some)
                || frozen != barrier::stopped_inventory_v24(running.state_dir(boundary.survivor)?)?
                || observers[boundary.survivor].replay_stopped()? != funded_offline
            {
                return Err(
                    "survivor ran or changed durable state before public-U-only handoff".into(),
                );
            }
            require_unbuilt_refund_v24(&funded_offline, &boundary)?;
            eprintln!("native real daemon: public DOM U final tx={}; peer reaped before survivor refund BUILD", hex::encode(public_refund));
        }
        running.restart_actor(boundary.survivor, binary, NativeDaemonModeV23::Reopen)?;
        let start = Instant::now();
        let deadline_advanced = true;
        let mut retained_refund_without_peer = None;
        loop {
            let exited = running.poll_actor_v23(boundary.survivor)?;
            if exited.is_some_and(|status| !status.success()) {
                return Err("noncooperative survivor exited unsuccessfully".into());
            }
            if let Some(snapshot) = observers[boundary.survivor].poll()? {
                if !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
                    || snapshot.aborted_unfunded
                {
                    return Err(
                        "noncooperative recovery exposed secret or substituted an unfunded abort"
                            .into(),
                    );
                }
                // The absent peer has already been reaped before this writer
                // reopened. Retain the new exact candidate before inclusion.
                if expected != RecoveryExitV23::XmrRefund || retained_refund_without_peer.is_some()
                {
                    control.pump_expected_xmr(&mut running, &snapshot)?;
                }
                let funded = selected(&snapshot, boundary.leg);
                if funded.funding.progress() == ActionProgressV1::Final {
                    if funded.funding.transaction_id() != Some(boundary.funding_aggregate_id) {
                        return Err("survivor funded a different external transaction".into());
                    }
                    match expected {
                        RecoveryExitV23::DomCompensation => {
                            control.advance_recovery(&mut running, &boundary, &snapshot)?
                        }
                        RecoveryExitV23::XmrRefund => {}
                    }
                }
                if expected == RecoveryExitV23::XmrRefund && retained_refund_without_peer.is_none()
                {
                    if running.processes[1 - boundary.survivor].is_some() {
                        return Err(
                            "refund construction unexpectedly has a live counterpart".into()
                        );
                    }
                    if let Some(action) = CoordinatorObserverV23::new(
                        running.state_dir(boundary.survivor)?,
                    )?
                    .poll(&snapshot, boundary.leg, ActionKindV1::Refund)?
                    {
                        let history = running.xmr_history_status_v23()?;
                        if history
                            .transactions
                            .iter()
                            .any(|transaction| action.matches_xmr(transaction.tx_hash))
                        {
                            return Err(
                                "refund was confirmed before its independent-build checkpoint"
                                    .into(),
                            );
                        }
                        if let Some(id) = history
                            .pool_tx_hashes
                            .iter()
                            .copied()
                            .find(|id| action.matches_xmr(*id))
                            .filter(|_| {
                                action.xmr_externalized
                                    && retained_refund_candidate(&snapshot, &boundary)
                                        == Some(action.aggregate_id)
                            })
                        {
                            // First BUILD/sign/submit occurred with the peer
                            // absent. The GPL pool verifies proof/conservation;
                            // the controller supplies neither U nor a LOAD grant.
                            retained_refund_without_peer = Some((action.aggregate_id, id));
                            control.pump_expected_xmr(&mut running, &snapshot)?;
                        }
                    }
                }
                if deadline_advanced && exit_proven(&snapshot, &boundary, expected) {
                    if expected == RecoveryExitV23::XmrRefund
                        && retained_refund_without_peer.map(|(aggregate, _)| aggregate)
                            != selected(&snapshot, boundary.leg).refund.transaction_id()
                    {
                        return Err(
                            "final refund does not match the candidate built without the peer"
                                .into(),
                        );
                    }
                    if exited.is_some() {
                        running.reap_successful_actor_v23(boundary.survivor)?;
                    } else {
                        // A nonterminal other leg can keep the survivor running;
                        // kill only this owned live child before final replay.
                        running.crash_actor(boundary.survivor)?;
                    }
                    break;
                }
            }
            if exited.is_some() {
                return Err("survivor exit 0 did not leave a funded final recovery".into());
            }
            if start.elapsed() >= PHASE_TIMEOUT {
                return Err(
                    "noncooperative daemon recovery did not reach a funded final exit".into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        let after = observers[boundary.survivor].replay_stopped()?;
        // Native confirmation happened while the aggregate remained Committed.
        // Prove the restarted writer entered the exit-only lane through its
        // full durable journal, without relying on catching a polling instant.
        // Advancing chain heights is not evidence of wall-clock F6 expiration.
        observers[boundary.survivor]
            .require_exit_only_reopen_stopped_v24(funded_offline.revision)?;
        if !exit_proven(&after, &boundary, expected)
            || (expected == RecoveryExitV23::XmrRefund
                && retained_refund_without_peer.map(|(aggregate, _)| aggregate)
                    != selected(&after, boundary.leg).refund.transaction_id())
        {
            return Err(
                "noncooperative final exit did not survive authenticated journal replay".into(),
            );
        }
        let coordinator = CoordinatorObserverV23::new(running.state_dir(boundary.survivor)?)?;
        let funding = coordinator
            .replay_stopped(&after, boundary.leg, ActionKindV1::Funding)?
            .ok_or("final native funding coordinator absent")?;
        if !funding.xmr_final
            || !funding.matches_xmr(boundary.funding_transaction_id)
            || funding.dom_id != boundary.dom_collateral_transaction_id
        {
            return Err("final route funding differs from replayed native children".into());
        }
        if expected == RecoveryExitV23::XmrRefund {
            let refund = coordinator
                .replay_stopped(&after, boundary.leg, ActionKindV1::Refund)?
                .ok_or("final native refund coordinator absent")?;
            if !refund.xmr_final
                || retained_refund_without_peer.is_none_or(|(aggregate, raw)| {
                    aggregate != refund.aggregate_id || !refund.matches_xmr(raw)
                })
            {
                return Err("XMR refund native finality or retained identity mismatch".into());
            }
            refund_publication_v24::prove_after_restart(
                &mut running,
                &binary,
                &boundary,
                &after,
                refund,
                retained_refund_without_peer
                    .ok_or("original refund absent")?
                    .1,
            )?;
        }
        if let Some(compensation) = &selected(&after, boundary.leg).dom_compensation_v12 {
            eprintln!(
                "native real daemon: DOM compensation final; not an XMR refund (payout={} noms)",
                compensation.payout_noms
            );
        }
        Ok(())
    })();
    if result.is_err() {
        running.retain_failed_fixture_v23();
    } else {
        running.retain_successful_fixture_v24()?;
    }
    result
}

fn require_unbuilt_refund_v24(
    snapshot: &RouteSnapshotV1,
    boundary: &FundingBoundaryV23,
) -> Result<()> {
    let leg = selected(snapshot, boundary.leg);
    if snapshot.aborted_unfunded
        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
        || leg.claim.progress() != ActionProgressV1::NotPrepared
        || leg.refund.progress() != ActionProgressV1::NotPrepared
        || leg.dom_compensation_v12.is_some()
        || leg
            .funding
            .effect()
            .and_then(|effect| effect.expected_transaction_id)
            != Some(boundary.funding_aggregate_id)
    {
        return Err("public-U handoff requires original funding and no prepared XMR refund".into());
    }
    Ok(())
}

fn require_native_claims(state: &std::path::Path, snapshot: &RouteSnapshotV1) -> Result<()> {
    let observer = CoordinatorObserverV23::new(state)?;
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        let mut native = Vec::<NativeActionV23>::new();
        for action in [ActionKindV1::Funding, ActionKindV1::Claim] {
            let recorded = observer
                .replay_stopped(snapshot, leg, action)?
                .ok_or("final native coordinator action absent")?;
            if !recorded.xmr_final {
                return Err("aggregate finality lacks native XMR child finality".into());
            }
            native.push(recorded);
        }
        if native[0].xmr_id == native[1].xmr_id || native[0].dom_id == native[1].dom_id {
            return Err("native funding and claim identities aliased".into());
        }
    }
    Ok(())
}

fn retained_refund_candidate(
    snapshot: &RouteSnapshotV1,
    boundary: &FundingBoundaryV23,
) -> Option<[u8; 32]> {
    let leg = selected(snapshot, boundary.leg);
    if snapshot.aborted_unfunded
        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
        || leg.funding.progress() != ActionProgressV1::Final
        || leg.funding.transaction_id() != Some(boundary.funding_aggregate_id)
        || leg.claim.progress() != ActionProgressV1::NotPrepared
        || leg.dom_compensation_v12.is_some()
        || leg.refund.progress() != ActionProgressV1::Externalized
    {
        return None;
    }
    let id = leg.refund.transaction_id()?;
    (id != [0; 32]
        && id != boundary.funding_aggregate_id
        && id != boundary.funding_transaction_id
        && id != boundary.dom_collateral_transaction_id
        && leg.refund.effect()?.expected_transaction_id == Some(id))
    .then_some(id)
}

#[cfg(test)]
mod recovery_evidence_tests {
    use super::*;
    use route_executor::{ActionStateV1, DomCompensationRecordV12, EffectReferenceV1};

    fn action(id: [u8; 32], finality: bool) -> ActionStateV1 {
        let effect = EffectReferenceV1 {
            effect_id: [1; 32],
            fencing_epoch: 1,
            semantic_digest: [2; 32],
            contains_route_secret: false,
            expected_transaction_id: Some(id),
        };
        if finality {
            ActionStateV1::Final {
                effect,
                transaction_id: id,
                evidence_digest: [3; 32],
            }
        } else {
            ActionStateV1::Externalized {
                effect,
                transaction_id: id,
            }
        }
    }

    fn fixture() -> Result<(RouteSnapshotV1, FundingBoundaryV23)> {
        let boundary = FundingBoundaryV23 {
            survivor: 0,
            leg: LegIdV1::Upstream,
            funding_transaction_id: [9; 32],
            funding_aggregate_id: [19; 32],
            dom_collateral_transaction_id: [10; 32],
        };
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        snapshot.upstream.funding = action(boundary.funding_aggregate_id, true);
        Ok((snapshot, boundary))
    }

    #[test]
    fn compensation_is_never_counted_as_an_xmr_refund() -> Result<()> {
        let (mut snapshot, boundary) = fixture()?;
        snapshot.upstream.dom_compensation_v12 = Some(DomCompensationRecordV12 {
            dom_chain_id: [1; 32],
            session_id: [2; 32],
            terms_digest: [3; 32],
            graph_digest: [4; 32],
            funding_transaction_id: boundary.dom_collateral_transaction_id,
            transaction_id: [11; 32],
            evidence_digest: [6; 32],
            policy_hash: [7; 32],
            custody_id: [8; 32],
            recipient: [9; 32],
            payout_noms: 123,
        });
        assert!(recovered(&snapshot, &boundary));
        assert!(!xmr_refunded(&snapshot, &boundary));
        assert!(retained_refund_candidate(&snapshot, &boundary).is_none());
        snapshot
            .upstream
            .dom_compensation_v12
            .as_mut()
            .unwrap()
            .funding_transaction_id = [12; 32];
        assert!(!recovered(&snapshot, &boundary));
        Ok(())
    }

    #[test]
    fn only_exact_externalized_refund_can_trigger_native_inclusion() -> Result<()> {
        let (mut snapshot, boundary) = fixture()?;
        snapshot.upstream.refund = action([11; 32], false);
        assert_eq!(
            retained_refund_candidate(&snapshot, &boundary),
            Some([11; 32])
        );
        assert!(!xmr_refunded(&snapshot, &boundary));
        let ActionStateV1::Externalized { effect, .. } = &mut snapshot.upstream.refund else {
            unreachable!()
        };
        effect.expected_transaction_id = Some([12; 32]);
        assert!(retained_refund_candidate(&snapshot, &boundary).is_none());
        snapshot.upstream.refund = action(boundary.funding_transaction_id, false);
        assert!(retained_refund_candidate(&snapshot, &boundary).is_none());
        Ok(())
    }

    #[test]
    fn public_u_handoff_refuses_a_prebuilt_or_already_final_refund() -> Result<()> {
        let (mut snapshot, boundary) = fixture()?;
        require_unbuilt_refund_v24(&snapshot, &boundary)?;
        snapshot.upstream.refund = action([11; 32], false);
        assert!(require_unbuilt_refund_v24(&snapshot, &boundary).is_err());
        snapshot.upstream.refund = action([11; 32], true);
        assert!(require_unbuilt_refund_v24(&snapshot, &boundary).is_err());
        snapshot.upstream.refund = ActionStateV1::NotPrepared;
        snapshot.upstream.funding = action([12; 32], true);
        assert!(require_unbuilt_refund_v24(&snapshot, &boundary).is_err());
        Ok(())
    }

    #[test]
    fn actual_final_xmr_refund_does_not_close_another_open_leg() -> Result<()> {
        let (mut snapshot, boundary) = fixture()?;
        snapshot.upstream.refund = action([11; 32], true);
        assert!(xmr_refunded(&snapshot, &boundary));
        assert!(!recovered(&snapshot, &boundary));
        snapshot.downstream.funding = action([12; 32], true);
        assert!(snapshot.has_open_funds());
        assert!(!xmr_refunded(&snapshot, &boundary));
        Ok(())
    }
}
