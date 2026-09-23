//! Ownership checkpoints around one native production phase, not an I/O timer.
//!
//! Neither an already-running syscall nor durable work can be rolled back by
//! this helper. An expired/lost lease refuses the next phase and requires the
//! existing authenticated reopen/reconciliation path. There is no retry here.

pub(super) fn with_ownership_checkpoints_v24<T, E>(
    mut checkpoint: impl FnMut() -> Result<(), E>,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    checkpoint()?;
    let outcome = operation();
    // Even an unavailable/failed phase may have used its entire observation
    // budget. Never let a retryable classification bypass ownership loss.
    checkpoint()?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn both_owners_are_checked_before_and_after_the_single_phase() {
        let order = RefCell::new(Vec::new());
        let result = with_ownership_checkpoints_v24(
            || {
                order.borrow_mut().extend(["route", "actuator"]);
                Ok::<(), &str>(())
            },
            || {
                order.borrow_mut().push("phase");
                Ok(17)
            },
        );
        assert_eq!(result, Ok(17));
        assert_eq!(
            *order.borrow(),
            ["route", "actuator", "phase", "route", "actuator"]
        );
    }

    #[test]
    fn either_initial_ownership_failure_prevents_the_phase() {
        for refusal in ["route", "actuator"] {
            let called = Cell::new(false);
            let result = with_ownership_checkpoints_v24(
                || Err(refusal),
                || {
                    called.set(true);
                    Ok(())
                },
            );
            assert_eq!(result, Err(refusal));
            assert!(!called.get());
        }
    }

    #[test]
    fn phase_failure_still_checks_ownership_without_replaying_work() {
        let checkpoints = Cell::new(0);
        let phases = Cell::new(0);
        let result: Result<(), _> = with_ownership_checkpoints_v24(
            || {
                checkpoints.set(checkpoints.get() + 1);
                Ok(())
            },
            || {
                phases.set(phases.get() + 1);
                Err("phase unavailable")
            },
        );
        assert_eq!(result, Err("phase unavailable"));
        assert_eq!(checkpoints.get(), 2);
        assert_eq!(phases.get(), 1);
    }

    #[test]
    fn lost_ownership_after_success_or_refusal_never_reports_progress_or_retries() {
        for phase_outcome in [Ok(()), Err("phase unavailable")] {
            let checkpoints = Cell::new(0);
            let phases = Cell::new(0);
            let result = with_ownership_checkpoints_v24(
                || {
                    checkpoints.set(checkpoints.get() + 1);
                    if checkpoints.get() == 1 {
                        Ok(())
                    } else {
                        Err("ownership lost")
                    }
                },
                || {
                    phases.set(phases.get() + 1);
                    phase_outcome
                },
            );
            assert_eq!(result, Err("ownership lost"));
            assert_eq!(checkpoints.get(), 2);
            assert_eq!(phases.get(), 1);
        }
    }

    #[test]
    fn production_relay_precedes_slow_f7_phases_and_their_ownership_checkpoints() {
        let source = include_str!("production_run_universal.rs");
        let round_start = source.find("// Service Relay first.").unwrap();
        let relay = source[round_start..]
            .find("\"relay_half_before_observation\"")
            .unwrap()
            + round_start;
        let recovery_activation = source[relay..]
            .find("activate_xmr_recovery_for_readiness_v25(")
            .unwrap()
            + relay;
        let readiness = source[recovery_activation..]
            .find("let mut f7_readiness_complete_v25 = f7_readiness_complete_v25!();")
            .expect("recovery activation must be followed by a durable readiness read")
            + recovery_activation;
        let readiness_pump = source[readiness..]
            .find("for _ in 0..2")
            .expect("the two-vote readiness exchange must be pumped twice")
            + readiness;
        let readiness_recheck = source[readiness_pump..]
            .find("f7_readiness_complete_v25 = f7_readiness_complete_v25!()")
            .expect("each readiness Relay pass must re-read durable state")
            + readiness_pump;
        let readiness_pump_body = &source[readiness_pump..readiness_recheck];
        assert_eq!(
            readiness_pump_body
                .matches("\"relay_half_for_f7_readiness\"")
                .count(),
            1,
            "the bounded readiness loop must perform one Relay half per pass"
        );
        let loop_start = source
            .find("// Observe/install receiver authority after the readiness Relay")
            .unwrap();
        let loop_end = source[loop_start..]
            .find("// One interleaved round")
            .expect("the owned native phase block must be bounded")
            + loop_start;
        assert!(
            relay < recovery_activation
                && recovery_activation < readiness
                && readiness < readiness_pump
                && readiness_pump < readiness_recheck
                && readiness < loop_start
        );
        let phases = &source[loop_start..loop_end];
        assert_eq!(phases.matches("owned_native_phase_v24!(").count(), 4);
        assert!(phases.contains("for native_burst_pass_v25 in 0..8"));
        assert!(phases.contains("native_idle_passes_v25 >= 2"));
        for phase in [
            "step_f7_funding_v20(",
            "step_native_xmr_f7_claim_v23(",
            "step_f7_claim_v20(",
            "step_f7_claim_receiver_v15(",
        ] {
            let position = phases.find(phase).unwrap();
            let checkpoint = phases[..position]
                .rfind("owned_native_phase_v24!(")
                .unwrap();
            assert!(!phases[checkpoint..position].contains(';'));
        }
        // RecoveryOnly intentionally permits authorized Claim/Refund exits;
        // ownership maintenance must not become a new economic veto.
        assert!(!phases.contains("HealthStateV1::"));
        let relay_after_leg = phases
            .find("\"relay_half_after_native_sync\"")
            .expect("each native leg must first perform a bilateral synchronization flush");
        let receiver = phases.find("step_f7_claim_receiver_v15(").unwrap();
        assert!(receiver < relay_after_leg);
        assert!(phases[receiver..relay_after_leg].contains("service_relay_v25!("));
        let focused_relay = phases
            .find("\"relay_leg_after_native_edge\"")
            .expect("later native edges must avoid the unrelated leg timeout");
        assert!(relay_after_leg < focused_relay);
        assert!(phases[relay_after_leg..focused_relay].contains("service_relay_leg_v25!("));
        assert!(phases[..relay_after_leg].contains("native_burst_pass_v25 == 0"));
        assert!(phases[relay_after_leg..].contains("relay_moved_v25 |= native_pass_moved_v25"));
        let recovery = &source[readiness_recheck..loop_start];
        assert_eq!(
            recovery.matches("service_relay_v25!(").count(),
            0,
            "sidecar recovery observations must not pay unrelated Relay timeouts"
        );
        let route_half = source[loop_end..]
            .find("run_production_composite_route_half_v25(")
            .unwrap()
            + loop_end;
        assert!(loop_end < route_half);
        let macro_start = source.find("macro_rules! owned_native_phase_v24").unwrap();
        let macro_end = source[macro_start..]
            .find("// Refresh before work")
            .unwrap()
            + macro_start;
        let checkpoint = &source[macro_start..macro_end];
        let route = checkpoint.find(".prepare_bounded_external_block(").unwrap();
        let actuator = checkpoint.find("actuator_heartbeat").unwrap();
        let operation = checkpoint.find("|| Ok($operation)").unwrap();
        assert!(route < actuator && actuator < operation);
    }
}
