//! Item 4 — the daemon starting on DOM and XMR alone.
//!
//! What this observes: two real release-production daemons accept a cold-started
//! route whose only counterparty family is Monero, keep running, and carry no
//! EVM, Bitcoin or Solana resource of any kind. What it deliberately does not
//! claim: that either daemon reached funding, claim or recovery. Startup is the
//! property under observation here, and the later scenarios take it from there.
use super::live_evidence_v23::{read_leg_evidence_v23, require_no_failed_session_v23};
use super::*;

/// The pair starts, stays up, and its two independent public documents agree
/// that both positions are Monero on a local quorum.
///
/// The confirmation binding is checked before the launch, not after: admission
/// requires each leg's negotiated finality to equal the signed adapter profile's
/// and the daemon refuses to start when it does not, so a pair that starts at
/// all has already been bound to the depth the scenario printed.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_dom_and_xmr_only_pair_starts_and_holds_with_no_foreign_family_resource(
) -> ColdStartResult<()> {
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    let state_dirs = [
        pair.state_dir(0)?.to_path_buf(),
        pair.state_dir(1)?.to_path_buf(),
    ];
    for state_dir in &state_dirs {
        require_xmr_only_state_dir_v23(state_dir)?;
    }
    pair.require_both_running()?;
    pair.stop_all_v23()?;
    // Startup is only meaningful if the sessions it created are usable. Read
    // both positions out of each stopped actor's own custody: a pair that came
    // up and immediately closed its route is not a started DOM+XMR daemon.
    for state_dir in &state_dirs {
        require_no_failed_session_v23(&read_leg_evidence_v23(state_dir)?)?;
    }
    Ok(())
}

/// The single-owner protection on a live state directory.
///
/// A second daemon must not be able to open a state directory whose owner is
/// still running, in either mode. This is the configuration protection that
/// keeps two processes from sharing one set of durable authorities, and it is
/// the daemon's own refusal, not the harness's preflight: both attempts pass
/// that preflight and are rejected after it.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_live_state_directory_refuses_a_second_owner_in_either_mode() -> ColdStartResult<()> {
    use crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23;
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    for actor in 0..2 {
        pair.require_refused_launch_v23(actor, &binary, NativeDaemonModeV23::Reopen)?;
        pair.require_refused_launch_v23(actor, &binary, NativeDaemonModeV23::Create)?;
        // The refusals must not have disturbed the running owner.
        pair.require_running(actor)?;
    }
    pair.require_both_running()?;
    pair.stop_all_v23()
}

/// Creation is not reachable a second time, even after a clean shutdown.
///
/// Reopening is the only way back into an existing state directory. A second
/// creation would restart the provisioning journal over durable authorities that
/// already exist, so it has to be refused on a directory that was created once,
/// whether or not anything is currently running in it.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_stopped_state_directory_reopens_but_refuses_a_second_creation() -> ColdStartResult<()> {
    use crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23;
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_all_v23()?;
    for actor in 0..2 {
        pair.require_refused_launch_v23(actor, &binary, NativeDaemonModeV23::Create)?;
    }
    for actor in 0..2 {
        pair.reopen_actor_v23(actor, &binary)?;
    }
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_all_v23()
}
