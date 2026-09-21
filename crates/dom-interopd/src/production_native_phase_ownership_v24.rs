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
            .find("run_production_composite_relay_half_v25(")
            .unwrap()
            + round_start;
        let readiness = source[relay..]
            .find("f7_readiness_complete_v25(chain)")
            .unwrap()
            + relay;
        let loop_start = source
            .find("// Observe/install receiver authority after the readiness Relay")
            .unwrap();
        let loop_end = source[loop_start..]
            .find("// One interleaved round")
            .expect("the owned native phase block must be bounded")
            + loop_start;
        assert!(relay < readiness && readiness < loop_start);
        let phases = &source[loop_start..loop_end];
        assert_eq!(phases.matches("owned_native_phase_v24!(").count(), 4);
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
