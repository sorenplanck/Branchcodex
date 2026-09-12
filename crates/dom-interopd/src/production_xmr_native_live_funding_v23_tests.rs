//! Item 1 — funding under the F7 authorization, and the evidence it leaves.
//!
//! What this observes: a launched DOM+XMR pair runs its route for a real budget,
//! writes its durable authorities, survives a clean shutdown, and comes back on
//! reopen with that evidence still present and never smaller. What it
//! deliberately does not claim: that a particular settlement reached a
//! economic finality. The stopped actor's Contracts Stores are authenticated
//! below: native F7 and irreversible authorization are read directly. File
//! presence/size are secondary checks and never substitute for those facts.
use super::live_evidence_v23::{
    read_leg_evidence_v23, require_evidence_never_regressed_v23, require_f7_authorized_funding_v23,
    require_no_failed_session_v23,
};
use super::*;

/// Durable roots every started route owns, whatever stage it reaches.
///
/// EVM and Bitcoin actuator roles are deliberately absent from this list even
/// though the manifest still names them: an XMR-only route must never create
/// them, which is asserted separately by the startup scenario's directory scan.
const LIVE_MANAGED_FILE_ROLES_V23: [crate::production_config::ProductionPathRoleV1; 7] = {
    use crate::production_config::ProductionPathRoleV1 as Role;
    [
        Role::RouteStore,
        Role::TimeAnchorStore,
        Role::CoordinatorStore,
        Role::DomActuatorStore,
        Role::SolverInventoryStore,
        Role::DomUpstreamParticipantState,
        Role::DomDownstreamParticipantState,
    ]
};

const LIVE_MANAGED_DIRECTORY_ROLES_V23: [crate::production_config::ProductionPathRoleV1; 9] = {
    use crate::production_config::ProductionPathRoleV1 as Role;
    [
        Role::RelayQueue,
        Role::UpstreamRelaySender,
        Role::UpstreamRelayInbox,
        Role::UpstreamRelayFrames,
        Role::UpstreamContracts,
        Role::DownstreamRelaySender,
        Role::DownstreamRelayInbox,
        Role::DownstreamRelayFrames,
        Role::DownstreamContracts,
    ]
};

/// The state-directory name the cold-start resource producer gives one role.
///
/// Recomputed from the same role key and the same formula the producer used, so
/// this cannot drift into naming a file that was never published.
pub(super) fn path_role_file_v23(role: crate::production_config::ProductionPathRoleV1) -> String {
    format!(
        "daemon-{}",
        role.key().strip_prefix("path_").unwrap_or(role.key())
    )
}

/// Total bytes held under one durable artifact, following no symbolic link.
fn artifact_size_v23(path: &Path) -> ColdStartResult<u64> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err("durable artifact is a symbolic link".into());
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Err("durable artifact is neither a file nor a directory".into());
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        total = total
            .checked_add(artifact_size_v23(&entry?.path())?)
            .ok_or("durable artifact size overflow")?;
    }
    Ok(total)
}

/// Names and sizes of every durable artifact a started route must own.
///
/// Ordered and complete, so two snapshots can be compared entry by entry: an
/// artifact that disappeared between them is as much a finding as one that
/// shrank.
pub(super) fn durable_inventory_v23(state_dir: &Path) -> ColdStartResult<Vec<(String, u64)>> {
    let mut inventory = Vec::new();
    for role in LIVE_MANAGED_FILE_ROLES_V23 {
        let name = path_role_file_v23(role);
        let path = state_dir.join(&name);
        require_durable_artifact_v23(&path, false)?;
        inventory.push((name, artifact_size_v23(&path)?));
    }
    for role in LIVE_MANAGED_DIRECTORY_ROLES_V23 {
        let name = path_role_file_v23(role);
        let path = state_dir.join(&name);
        require_durable_artifact_v23(&path, true)?;
        inventory.push((name, artifact_size_v23(&path)?));
    }
    for position in 0..2 {
        let name = format!("daemon-xmr-{position}-actuator.sqlite");
        let path = state_dir.join(&name);
        require_durable_artifact_v23(&path, false)?;
        inventory.push((name, artifact_size_v23(&path)?));
    }
    Ok(inventory)
}

/// Requires that the later snapshot kept every artifact and shrank none of them.
fn require_monotonic_evidence_v23(
    before: &[(String, u64)],
    after: &[(String, u64)],
) -> ColdStartResult<()> {
    if before.len() != after.len() {
        return Err("a durable artifact appeared or disappeared across the restart".into());
    }
    for ((old_name, old_size), (new_name, new_size)) in before.iter().zip(after) {
        if old_name != new_name {
            return Err("durable artifact inventories are not comparable".into());
        }
        if new_size < old_size {
            return Err("a durable artifact lost content across the restart".into());
        }
    }
    Ok(())
}

/// Exactly one actor per position holds that position's private funding
/// candidate, because exactly one participant is that leg's refund recipient.
///
/// A candidate on both sides, or on neither, would mean the cold start assigned
/// the offline producer's private bytes to the wrong owner, which no later
/// authorization could repair.
fn require_single_funding_candidate_owner_v23(state_dirs: [&Path; 2]) -> ColdStartResult<()> {
    for position in 0..2 {
        let name = format!("daemon-xmr-{position}-funding.raw");
        let owners = state_dirs
            .iter()
            .filter(|state_dir| state_dir.join(&name).exists())
            .count();
        if owners != 1 {
            return Err("a position's private funding candidate has no single owner".into());
        }
    }
    Ok(())
}

/// The pair runs its route, then proves the evidence is durable by losing and
/// regaining both processes without losing anything they had written.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_route_evidence_persists_across_a_clean_shutdown_and_reopen() -> ColdStartResult<()> {
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.wait_funding_ready_v24(LIVE_ROUTE_BUDGET_V23)?;

    let state_dirs = [
        pair.state_dir(0)?.to_path_buf(),
        pair.state_dir(1)?.to_path_buf(),
    ];
    require_single_funding_candidate_owner_v23([&state_dirs[0], &state_dirs[1]])?;

    pair.stop_all_v23()?;
    let before = [
        durable_inventory_v23(&state_dirs[0])?,
        durable_inventory_v23(&state_dirs[1])?,
    ];
    // Both daemons are down, so their Contracts custody can be opened and the
    // authorization read out instead of inferred from the files around it.
    let evidence_before = [
        read_leg_evidence_v23(&state_dirs[0])?,
        read_leg_evidence_v23(&state_dirs[1])?,
    ];
    for evidence in &evidence_before {
        require_no_failed_session_v23(evidence)?;
        require_f7_authorized_funding_v23(evidence)?;
    }

    for actor in 0..2 {
        pair.reopen_actor_v23(actor, &binary)?;
    }
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_all_v23()?;

    for actor in 0..2 {
        let after = durable_inventory_v23(&state_dirs[actor])?;
        require_monotonic_evidence_v23(&before[actor], &after)?;
        let evidence_after = read_leg_evidence_v23(&state_dirs[actor])?;
        require_evidence_never_regressed_v23(&evidence_before[actor], &evidence_after)?;
        require_f7_authorized_funding_v23(&evidence_after)?;
    }
    // The candidate ownership is a property of the cold start, so losing it
    // across a restart would be a regression of the same kind as losing a store.
    require_single_funding_candidate_owner_v23([&state_dirs[0], &state_dirs[1]])
}

/// An interrupted run is recovered from whatever was already durable.
///
/// Neither process is given the chance to shut down: both are killed, so the
/// reopen has to start from the exact durable prefix the crash left behind. A
/// route that could only resume after an orderly shutdown would not survive the
/// failure this scenario stands in for.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_route_evidence_survives_an_uncontrolled_crash_of_both_daemons() -> ColdStartResult<()> {
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.wait_funding_ready_v24(LIVE_ROUTE_BUDGET_V23)?;

    let state_dirs = [
        pair.state_dir(0)?.to_path_buf(),
        pair.state_dir(1)?.to_path_buf(),
    ];
    for actor in 0..2 {
        pair.crash_actor_v23(actor)?;
    }
    let before = [
        durable_inventory_v23(&state_dirs[0])?,
        durable_inventory_v23(&state_dirs[1])?,
    ];
    let evidence_before = [
        read_leg_evidence_v23(&state_dirs[0])?,
        read_leg_evidence_v23(&state_dirs[1])?,
    ];
    for evidence in &evidence_before {
        require_no_failed_session_v23(evidence)?;
    }

    for actor in 0..2 {
        pair.reopen_actor_v23(actor, &binary)?;
    }
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
    pair.stop_all_v23()?;

    for actor in 0..2 {
        let after = durable_inventory_v23(&state_dirs[actor])?;
        require_monotonic_evidence_v23(&before[actor], &after)?;
        // A kill cannot be allowed to undo an irreversible flag, withdraw a
        // retained gate, or un-accept a signing message.
        let evidence_after = read_leg_evidence_v23(&state_dirs[actor])?;
        require_evidence_never_regressed_v23(&evidence_before[actor], &evidence_after)?;
        require_no_failed_session_v23(&evidence_after)?;
    }
    Ok(())
}
