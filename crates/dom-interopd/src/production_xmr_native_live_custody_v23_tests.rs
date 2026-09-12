//! Item 3 — durable custody and remote-sidecar recovery, and the rejections.
//!
//! What this observes: the per-position encrypted custody stores an XMR leg
//! owns survive repeated uncontrolled restarts without losing content, and a
//! daemon that is handed a corrupted durable input refuses it — where "refuses"
//! is established by the control, not by the exit alone: the same launch, with
//! the same bytes restored, is accepted.
//!
//! Both ends of the remote custody face are rebuilt by every reopen here. The
//! two participants hold opposite halves of it: the leg's beneficiary serves the
//! remote sweep and its refund recipient claims through the remote client, and
//! each side reconstructs its own half from durable state at startup. Restarting
//! both daemons together is therefore what exercises the remote face's recovery;
//! there is no separate handle to restart, because neither half survives its
//! process.
//!
//! The corrupted inputs are chosen because the harness preflight never reads
//! them. The preflight authenticates the DOM node configuration, the
//! selected-services document and the Relay network sidecar before it spawns
//! anything, so corrupting one of those would produce a harness refusal and
//! prove nothing about the daemon. The universal reopen manifest and the two
//! per-leg authority bundles all reach the real binary, and the bundles are
//! where that leg's native public authority material lives — including the
//! cross-curve refund proof the leg is admitted against. An arbitrary flipped
//! JSON byte proves rejection of that input, not specifically rejection by the
//! cross-curve equation verifier. Native proof mutation has separate coverage.
use super::live_evidence_v23::{
    read_leg_evidence_v23, require_complete_recovery_graph_v23,
    require_evidence_never_regressed_v23, require_no_failed_session_v23,
};
use super::live_funding_v23::durable_inventory_v23;
use super::*;

/// The two encrypted stores one position's custody owns, inside the actor's own
/// private custody root. Their names are the ones the cold start enrolled under
/// and the ones the leg bundle points the daemon at.
fn custody_store_paths_v23(state_dir: &Path, position: usize) -> [std::path::PathBuf; 2] {
    let root = state_dir.join(format!("cold-start-xmr-position-{position}"));
    [
        root.join("native-xmr-secrets-v23.sqlite"),
        root.join("native-xmr-nullifiers-v23.sqlite"),
    ]
}

/// Sizes of every custody store this actor owns, in a stable order.
fn custody_inventory_v23(state_dir: &Path) -> ColdStartResult<Vec<(String, u64)>> {
    let mut inventory = Vec::new();
    for position in 0..2 {
        for path in custody_store_paths_v23(state_dir, position) {
            require_durable_artifact_v23(&path, false)?;
            let name = path
                .strip_prefix(state_dir)?
                .to_str()
                .ok_or("custody store path encoding")?
                .to_owned();
            inventory.push((name, std::fs::symlink_metadata(&path)?.len()));
        }
    }
    if inventory.len() != 4 {
        return Err("an actor must own two custody stores per position".into());
    }
    Ok(inventory)
}

fn require_retained_custody_v23(
    before: &[(String, u64)],
    after: &[(String, u64)],
) -> ColdStartResult<()> {
    if before.len() != after.len() {
        return Err("a custody store appeared or disappeared across the restart".into());
    }
    for ((old_name, old_size), (new_name, new_size)) in before.iter().zip(after) {
        if old_name != new_name || new_size < old_size {
            return Err("a custody store lost content across the restart".into());
        }
    }
    Ok(())
}

/// Custody survives being interrupted repeatedly, on both sides at once.
///
/// Three crash/reopen cycles rather than one: a recovery that only works from a
/// state the first crash happens to leave behind would pass a single cycle and
/// fail here.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_custody_stores_survive_repeated_uncontrolled_restarts_on_both_sides() -> ColdStartResult<()>
{
    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.wait_funding_ready_v24(LIVE_ROUTE_BUDGET_V23)?;

    let state_dirs = [
        pair.state_dir(0)?.to_path_buf(),
        pair.state_dir(1)?.to_path_buf(),
    ];
    let mut previous = [
        custody_inventory_v23(&state_dirs[0])?,
        custody_inventory_v23(&state_dirs[1])?,
    ];
    let mut previous_evidence: Option<[_; 2]> = None;
    for _ in 0..3 {
        for actor in 0..2 {
            pair.crash_actor_v23(actor)?;
        }
        // Both sides are down: the custody each of them would have to recover
        // from, including the two halves of the remote sweep face, is read out
        // of the Stores themselves before either process exists again.
        let evidence = [
            read_leg_evidence_v23(&state_dirs[0])?,
            read_leg_evidence_v23(&state_dirs[1])?,
        ];
        for actor in 0..2 {
            require_no_failed_session_v23(&evidence[actor])?;
            require_complete_recovery_graph_v23(&evidence[actor])?;
            if let Some(earlier) = &previous_evidence {
                require_evidence_never_regressed_v23(&earlier[actor], &evidence[actor])?;
            }
        }
        previous_evidence = Some(evidence);
        for actor in 0..2 {
            pair.reopen_actor_v23(actor, &binary)?;
        }
        pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;
        for actor in 0..2 {
            let current = custody_inventory_v23(&state_dirs[actor])?;
            require_retained_custody_v23(&previous[actor], &current)?;
            previous[actor] = current;
        }
    }
    pair.stop_all_v23()
}

/// A corrupted durable input is refused, and the same input restored is not.
///
/// Each artifact is corrupted at a byte in its interior, so the change is inside
/// the authenticated body rather than at a boundary a length check alone would
/// catch. The restore is verified to be byte-exact before the accepting launch,
/// which is what makes the preceding refusal attributable to the corruption.
#[test]
#[ignore = "requires DOM_INTEROP_REAL_BINARY_V23, the offline funding helper and the real sidecar"]
fn v23_corrupted_manifest_or_leg_authority_is_refused_and_the_original_is_not(
) -> ColdStartResult<()> {
    use crate::production_config::PRODUCTION_REOPEN_CONFIG_FILE_V11;
    use crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23;

    let binary =
        crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23::from_environment()?;
    let mut pair = start_live_pair_v23(&binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;

    // Only the first actor is taken down, so the refusals below cannot be the
    // single-owner protection refusing a live directory.
    let actor = 0;
    pair.stop_actor_v23(actor)?;
    let state_dir = pair.state_dir(actor)?.to_path_buf();
    // What this actor held before any corrupted input was offered to it.
    let evidence_before = read_leg_evidence_v23(&state_dir)?;
    require_no_failed_session_v23(&evidence_before)?;

    for name in [
        PRODUCTION_REOPEN_CONFIG_FILE_V11.to_owned(),
        "daemon-xmr-0-authority.json".to_owned(),
        "daemon-xmr-1-authority.json".to_owned(),
    ] {
        let path = state_dir.join(&name);
        let original = read_public_artifact_v23(&path)?;
        if original.len() < 4 {
            return Err("durable input is too small to corrupt in its interior".into());
        }
        let mut corrupted = original.clone();
        let index = corrupted.len() / 2;
        corrupted[index] ^= 0x01;
        overwrite_public_artifact_v23(&path, &corrupted)?;
        let refused = pair.require_refused_launch_v23(actor, &binary, NativeDaemonModeV23::Reopen);
        // Restore before propagating, so one failed expectation cannot leave
        // the directory corrupted for the remaining artifacts.
        overwrite_public_artifact_v23(&path, &original)?;
        refused?;
        if read_public_artifact_v23(&path)? != original {
            return Err("durable input was not restored byte for byte".into());
        }
    }

    // Require exact equality of the authenticated evidence projection, not
    // just monotonicity. This is not a byte inventory of every Store object.
    let evidence_after_refusals = read_leg_evidence_v23(&state_dir)?;
    if evidence_before != evidence_after_refusals {
        return Err("refused launches changed authenticated custody evidence".into());
    }
    require_no_failed_session_v23(&evidence_after_refusals)?;

    // The control: with every byte back where it was, the same reopen is taken.
    pair.reopen_actor_v23(actor, &binary)?;
    pair.require_both_running_for_v23(LIVE_STARTUP_BUDGET_V23)?;

    // Custody must be exactly as durable after the rejected attempts as before.
    let inventory = durable_inventory_v23(&state_dir)?;
    if inventory.is_empty() {
        return Err("the reopened actor holds no durable evidence".into());
    }
    custody_inventory_v23(&state_dir)?;
    pair.stop_all_v23()?;
    let evidence_final = read_leg_evidence_v23(&state_dir)?;
    require_evidence_never_regressed_v23(&evidence_after_refusals, &evidence_final)?;
    require_no_failed_session_v23(&evidence_final)
}
