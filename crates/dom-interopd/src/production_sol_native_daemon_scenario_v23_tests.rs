//! Actual release-production child processes for the DOM↔SOL route, not the
//! in-process graph fixture. Every chain endpoint is private loopback: the DOM
//! snapshot ledger and an owned solana-test-validator. No real funds move.
use super::{NativeSolMainnetStartupV23, NativeSolRunningColdStartV23};
use crate::production_xmr_native_binary_v23_tests::{NativeDaemonBinaryV23, NativeDaemonModeV23};
use route_executor::{
    ActionKindV1, ActionProgressV1, CoordinationPhaseV1, LegIdV1, RouteSnapshotV1,
    SecretVisibilityV1,
};
use std::{
    io::Write,
    net::TcpListener,
    os::unix::fs::OpenOptionsExt,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "production_xmr_native_daemon_scenario_v23_observer.rs"]
pub(super) mod observer;
use observer::RouteObserverV23;
#[path = "production_sol_native_daemon_scenario_v23_coordinator.rs"]
pub(super) mod coordinator;
use coordinator::{CoordinatorObserverV23, NativeSolActionV23};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// A normal funding-and-claim pass must finish promptly; refund deadlines are
/// separate recovery bounds and do not extend this operational observation.
const PHASE_TIMEOUT: Duration = Duration::from_secs(600);

fn fresh_local_policy() -> Result<route_time_anchor::RouteTimePolicyLimitsV2> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sol_timing = crate::production_sol_native_registry_fixture_v23::NATIVE_SOL_TIMING_V23;
    // One signed SOL chain carries both counterparty legs. Derive the M.8
    // floor from that registry timing, never an independent constant.
    let counterparty_margin_seconds =
        adapter_btc::timelock::minimum_safety_margin_seconds(&sol_timing, &sol_timing)?;
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
        counterparty_margin_seconds,
    })
}

#[test]
fn native_sol_real_daemon_policy_uses_the_signed_sol_m8_floor_v25() -> Result<()> {
    let timing = crate::production_sol_native_registry_fixture_v23::NATIVE_SOL_TIMING_V23;
    let expected = adapter_btc::timelock::minimum_safety_margin_seconds(&timing, &timing)?;
    assert_eq!(fresh_local_policy()?.counterparty_margin_seconds, expected);
    Ok(())
}

fn launch(
    startup: NativeSolMainnetStartupV23,
    binary: &NativeDaemonBinaryV23,
) -> Result<NativeSolRunningColdStartV23> {
    // Reserve two simultaneous distinct loopback ports; release only for the
    // actual daemon bind. Bind races are failures, never silent port retries.
    let first = TcpListener::bind("127.0.0.1:0")?;
    let second = TcpListener::bind("127.0.0.1:0")?;
    let addresses = [first.local_addr()?, second.local_addr()?];
    drop((first, second));
    startup.export_and_launch_shared_peer_v23(binary, addresses, 1)
}

fn observers(running: &NativeSolRunningColdStartV23) -> Result<[RouteObserverV23; 2]> {
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

/// Hands each root the offer its peer published, and nothing else.
///
/// The policy-17 bootstrap publishes the wallet key-proof offer as a public
/// file in the root's own state directory instead of putting it on the
/// authenticated DSC1 relay: it is wallet-owned material and the relay never
/// carries it. In production the operator moves that published file between
/// the two machines running the swap. This scenario owns both roots, so it
/// performs that one out-of-band move itself.
///
/// It copies only bytes a daemon already published as public, byte for byte,
/// and never generates, edits, reorders or re-delivers them: an offer already
/// handed over is frozen by the peer on first read and is left untouched.
fn deliver_published_wallet_offers_v25(running: &NativeSolRunningColdStartV23) -> Result<()> {
    const PUBLISHED_PREFIX: &str = "dom-wallet-offer-v18-";
    const PUBLISHED_SUFFIX: &str = ".local";
    const DELIVERED_SUFFIX: &str = ".peer";
    for (from, to) in [(0_usize, 1_usize), (1, 0)] {
        let published_dir = running.state_dir(from)?.to_owned();
        let delivery_dir = running.state_dir(to)?.to_owned();
        for entry in std::fs::read_dir(&published_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name
                .strip_prefix(PUBLISHED_PREFIX)
                .and_then(|rest| rest.strip_suffix(PUBLISHED_SUFFIX))
            else {
                continue;
            };
            if !entry.file_type()?.is_file() {
                continue;
            }
            let delivered =
                delivery_dir.join(format!("{PUBLISHED_PREFIX}{stem}{DELIVERED_SUFFIX}"));
            if delivered.symlink_metadata().is_ok() {
                continue;
            }
            // The rename publishes complete bytes only; a half-written file is
            // never visible under the name the peer reads.
            let bytes = std::fs::read(entry.path())?;
            let pending = delivery_dir.join(format!("{PUBLISHED_PREFIX}{stem}.delivering"));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&pending)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&pending, &delivered)?;
        }
    }
    Ok(())
}

/// No ledger pump: the validator produces and finalizes its own slots. Each
/// round only proves the validator is still alive.
fn wait_claims(
    running: &mut NativeSolRunningColdStartV23,
    observers: &mut [RouteObserverV23; 2],
) -> Result<()> {
    let start = Instant::now();
    let mut announced = Duration::ZERO;
    loop {
        running.require_validator_alive_v25()?;
        deliver_published_wallet_offers_v25(running)?;
        let mut complete = true;
        for actor in 0..2 {
            let exited = running.poll_actor_v23(actor)?;
            if exited.is_some_and(|status| !status.success()) {
                // The daemon's own refusal text, which names the stage and,
                // for Stage 11, the exact step that fell closed.
                if let Some(text) = running.actor_failure_text_v25(actor) {
                    eprintln!("native SOL real daemon actor={actor} refusal: {text}");
                }
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
                }
                None if exited.is_some() => return Err("daemon exit has no durable route".into()),
                None => complete = false,
            }
        }
        if complete {
            return Ok(());
        }
        if start.elapsed() >= PHASE_TIMEOUT {
            return Err("real daemon claim observation reached its explicit deadline".into());
        }
        if start.elapsed().saturating_sub(announced) >= Duration::from_secs(30) {
            announced = start.elapsed();
            eprintln!(
                "native SOL real daemon: awaiting two final economic claims after {}s",
                announced.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// A dedicated dependency-gated test: an absent real release binary,
/// validator or escrow program is an error, not ignore/skip/fallback.
#[test]
#[ignore = "dedicated real release-production daemon with an owned solana-test-validator; mandatory CI uses --ignored --exact"]
fn native_real_daemon_two_sol_claims_survive_original_store_reopen_v23() -> Result<()> {
    let binary = NativeDaemonBinaryV23::from_environment()?;
    let startup = NativeSolMainnetStartupV23::prepare(fresh_local_policy()?)?;
    let mut running = launch(startup, &binary)?;
    let result = (|| -> Result<()> {
        let mut observers = observers(&running)?;
        wait_claims(&mut running, &mut observers)?;
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
            require_native_sol_claims(&running, actor, &before[actor])?;
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
            running.require_validator_alive_v25()?;
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
        wait_claims(&mut running, &mut observers)?;
        running.reap_successful_actor_v23(0)?;
        running.reap_successful_actor_v23(1)?;
        for actor in 0..2 {
            let after = observers[actor].replay_stopped()?;
            require_claimed(&after)?;
            require_native_sol_claims(&running, actor, &after)?;
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

/// Coordinator children must be final on both faces, and the program-owned
/// state PDAs must independently show both escrows Claimed with one scalar.
fn require_native_sol_claims(
    running: &NativeSolRunningColdStartV23,
    actor: usize,
    snapshot: &RouteSnapshotV1,
) -> Result<()> {
    let observer = CoordinatorObserverV23::new(running.state_dir(actor)?)?;
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        let mut native = Vec::<NativeSolActionV23>::new();
        for action in [ActionKindV1::Funding, ActionKindV1::Claim] {
            let recorded = observer
                .replay_stopped(snapshot, leg, action)?
                .ok_or("final native coordinator action absent")?;
            if !recorded.sol_final
                || snapshot.leg(leg).action(action).transaction_id() != Some(recorded.aggregate_id)
            {
                return Err("aggregate finality lacks native SOL child finality".into());
            }
            native.push(recorded);
        }
        if native[0].sol_id == native[1].sol_id || native[0].dom_id == native[1].dom_id {
            return Err("native funding and claim identities aliased".into());
        }
    }
    let states = running.escrow_states_v25()?;
    for state in &states {
        if state.status != solana_escrow_wire::EscrowStatus::Claimed
            || state.funded_amount != state.amount
            || state.amount == 0
            || state.revealed_secret_be == [0; 32]
            || state.terminal_slot == 0
        {
            return Err("SOL escrow state is not a funded final claim".into());
        }
    }
    if states[0].revealed_secret_be != states[1].revealed_secret_be
        || states[0].dom_adaptor_point != states[1].dom_adaptor_point
        || states[0].settlement_id == states[1].settlement_id
    {
        return Err("SOL escrows do not share one route scalar across distinct settlements".into());
    }
    Ok(())
}
