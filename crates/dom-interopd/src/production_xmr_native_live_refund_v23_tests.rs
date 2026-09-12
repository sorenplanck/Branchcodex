//! Item 2 — refund and non-cooperative recovery, including restart while the
//! counterparty is gone.
//!
//! What this observes: with one side of a two-party route removed, the other
//! side keeps running, can be killed and reopened with the peer still absent,
//! loses none of its durable evidence in the process, and accepts the peer back
//! afterwards. That is the operational shape of a non-cooperative recovery: the
//! honest party must not depend on the counterparty being reachable, at any
//! point, including across its own restart.
//!
//! What it deliberately does not claim: that a refund or compensation
//! transaction was built, signed or broadcast. Those need the negotiated
//! deadlines to elapse on the real chains, which a bounded scenario cannot make
//! happen; what it can establish is that nothing about the surviving side's
//! liveness or durability depended on the peer.
use super::live_evidence_v23::{
    read_leg_evidence_v23, require_complete_recovery_graph_v23,
    require_evidence_never_regressed_v23, require_no_failed_session_v23,
};
use super::live_funding_v23::durable_inventory_v23;
use super::*;

/// One side is removed, the survivor is restarted without it, and only then is
/// the peer allowed back.
///
/// The survivor is killed rather than stopped, so its reopen has to recover from
/// the durable prefix a crash left behind *and* come up with no reachable
/// counterparty. Those two conditions together are what a real non-cooperative
/// restart looks like; either one alone would be a weaker observation.
fn non_cooperative_restart_v23(absent: usize) -> ColdStartResult<()> {
    let survivor = absent ^ 1;
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.wait_funding_ready_v24(LIVE_ROUTE_BUDGET_V23)?;

    let survivor_state = pair.state_dir(survivor)?.to_path_buf();

    // The counterparty goes away cleanly. Nothing is torn down on the survivor.
    pair.stop_actor_v23(absent)?;
    pair.require_running(survivor)?;
    hold_running_v23(&mut pair, survivor, LIVE_STARTUP_BUDGET_V23)?;
    let before = durable_inventory_v23(&survivor_state)?;

    // The survivor now loses its own process, with the peer still unreachable.
    pair.crash_actor_v23(survivor)?;
    let crashed = durable_inventory_v23(&survivor_state)?;
    require_retained_inventory_v23(&before, &crashed)?;
    // Both of this actor's processes are down, so the recovery it would have to
    // execute non-cooperatively can be read out of its own custody rather than
    // assumed from the files being intact. All three edges — cancel, the
    // U-adaptor refund and compensation — are what that recovery runs from.
    let evidence_crashed = read_leg_evidence_v23(&survivor_state)?;
    require_no_failed_session_v23(&evidence_crashed)?;
    require_complete_recovery_graph_v23(&evidence_crashed)?;

    pair.reopen_actor_v23(survivor, &binary)?;
    hold_running_v23(&mut pair, survivor, LIVE_STARTUP_BUDGET_V23)?;
    let reopened = durable_inventory_v23(&survivor_state)?;
    require_retained_inventory_v23(&crashed, &reopened)?;

    // The counterparty returns. Neither side may need the other to have been
    // present continuously for the route to be resumable.
    pair.reopen_actor_v23(absent, &binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_all_v23()?;

    // The peerless restart may not have cost the survivor any of the recovery
    // it held before it, and the returning peer must hold the same graph.
    let evidence_after = read_leg_evidence_v23(&survivor_state)?;
    require_evidence_never_regressed_v23(&evidence_crashed, &evidence_after)?;
    require_complete_recovery_graph_v23(&evidence_after)?;
    let peer_evidence = read_leg_evidence_v23(pair.state_dir(absent)?)?;
    require_no_failed_session_v23(&peer_evidence)?;
    require_complete_recovery_graph_v23(&peer_evidence)
}

/// Holds one actor to the running requirement for a bounded budget.
fn hold_running_v23(
    pair: &mut NativeXmrLivePairV23,
    actor: usize,
    budget: std::time::Duration,
) -> ColdStartResult<()> {
    if budget.is_zero() || budget > std::time::Duration::from_secs(1800) {
        return Err("bounded running-observation budget required".into());
    }
    let deadline = std::time::Instant::now() + budget;
    loop {
        pair.require_running(actor)?;
        if std::time::Instant::now() >= deadline {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Requires that no durable artifact was dropped or truncated.
///
/// This is the same monotonic requirement the funding scenario applies, stated
/// separately here because the transitions it brackets are different: a crash
/// and a peerless reopen rather than an orderly shutdown.
fn require_retained_inventory_v23(
    before: &[(String, u64)],
    after: &[(String, u64)],
) -> ColdStartResult<()> {
    if before.len() != after.len() {
        return Err("a durable artifact appeared or disappeared while the peer was gone".into());
    }
    for ((old_name, old_size), (new_name, new_size)) in before.iter().zip(after) {
        if old_name != new_name || new_size < old_size {
            return Err("the surviving side lost durable evidence without its peer".into());
        }
    }
    Ok(())
}

/// The downstream-side actor survives alone and restarts alone.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_second_actor_survives_and_restarts_with_the_first_unavailable() -> ColdStartResult<()> {
    non_cooperative_restart_v23(0)
}

/// The upstream-side actor survives alone and restarts alone.
///
/// Both directions are exercised because the two participants do not hold
/// symmetric roles: one is the route's solver and the other its initiator, and a
/// dependency on the peer could exist in only one of them.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_first_actor_survives_and_restarts_with_the_second_unavailable() -> ColdStartResult<()> {
    non_cooperative_restart_v23(1)
}

/// A route that never had a reachable counterparty at all.
///
/// The peer is stopped as soon as the pair is up and is never brought back. The
/// survivor is then restarted twice in a row, so a recovery path that only
/// worked on the first reopen after a peer had once been present would be
/// visible here.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_survivor_reopens_repeatedly_with_a_permanently_absent_counterparty() -> ColdStartResult<()> {
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_actor_v23(1)?;

    let survivor_state = pair.state_dir(0)?.to_path_buf();
    let mut previous = {
        hold_running_v23(&mut pair, 0, LIVE_STARTUP_BUDGET_V23)?;
        durable_inventory_v23(&survivor_state)?
    };
    let mut previous_evidence = None;
    for _ in 0..2 {
        pair.crash_actor_v23(0)?;
        // Read while it is down, once per cycle, so each reopen is checked
        // against what the previous cycle actually left behind.
        let evidence = read_leg_evidence_v23(&survivor_state)?;
        require_no_failed_session_v23(&evidence)?;
        if let Some(earlier) = &previous_evidence {
            require_evidence_never_regressed_v23(earlier, &evidence)?;
        }
        previous_evidence = Some(evidence);
        pair.reopen_actor_v23(0, &binary)?;
        hold_running_v23(&mut pair, 0, LIVE_STARTUP_BUDGET_V23)?;
        let current = durable_inventory_v23(&survivor_state)?;
        require_retained_inventory_v23(&previous, &current)?;
        previous = current;
    }
    pair.stop_all_v23()?;
    let final_evidence = read_leg_evidence_v23(&survivor_state)?;
    if let Some(earlier) = &previous_evidence {
        require_evidence_never_regressed_v23(earlier, &final_evidence)?;
    }
    require_no_failed_session_v23(&final_evidence)
}
