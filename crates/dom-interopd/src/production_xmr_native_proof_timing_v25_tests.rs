//! Observational accounting for the exhaustive native-proof restart fixture.
//!
//! These phases include genuine proof work AND this fixture's deliberate
//! per-tick teardown/reopen. They are not normal daemon latency or a primitive
//! benchmark. No private value, path, transcript, or payload enters the report.
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum PhaseV25 {
    Setup = 0,
    TickMount = 1,
    TickIdentityOpen = 2,
    TickRest = 3,
    TerminalMount = 4,
    TerminalAudit = 5,
}

#[derive(Default)]
pub(super) struct ProofTimingTotalsV25 {
    actor_ticks: usize,
    tick_mounts: usize,
    identity_reopens: usize,
    terminal_mounts: usize,
    phases: [Duration; 6],
}

impl ProofTimingTotalsV25 {
    fn record(&mut self, phase: PhaseV25, elapsed: Duration) {
        self.phases[phase as usize] += elapsed;
    }

    fn total(&self) -> Duration {
        self.phases.iter().copied().sum()
    }

    pub(super) fn public_summary(&self, leg_index: usize, output_kind: &str) -> String {
        format!(
            "native proof timing v25: fixture_restart_only=true actual_daemon_latency=false \
             leg={leg_index} output={output_kind} actor_ticks={} bootstrap_resumes={} \
             tick_mounts={} identity_reopens={} terminal_mounts={} \
             setup_s={:.6} tick_mount_s={:.6} identity_open_s={:.6} \
             rest_tick_s={:.6} terminal_mount_s={:.6} terminal_audit_s={:.6} \
             native_output_total_s={:.6}",
            self.actor_ticks,
            self.tick_mounts + self.terminal_mounts,
            self.tick_mounts,
            self.identity_reopens,
            self.terminal_mounts,
            self.phases[PhaseV25::Setup as usize].as_secs_f64(),
            self.phases[PhaseV25::TickMount as usize].as_secs_f64(),
            self.phases[PhaseV25::TickIdentityOpen as usize].as_secs_f64(),
            self.phases[PhaseV25::TickRest as usize].as_secs_f64(),
            self.phases[PhaseV25::TerminalMount as usize].as_secs_f64(),
            self.phases[PhaseV25::TerminalAudit as usize].as_secs_f64(),
            self.total().as_secs_f64(),
        )
    }
}

pub(super) struct NativeProofTimingV25 {
    last: Instant,
    phase: PhaseV25,
    totals: ProofTimingTotalsV25,
}

impl NativeProofTimingV25 {
    pub(super) fn new() -> Self {
        Self {
            last: Instant::now(),
            phase: PhaseV25::Setup,
            totals: ProofTimingTotalsV25::default(),
        }
    }

    fn transition_at(&mut self, next: PhaseV25, now: Instant) {
        self.totals
            .record(self.phase, now.duration_since(self.last));
        self.phase = next;
        self.last = now;
    }

    fn transition(&mut self, next: PhaseV25) {
        self.transition_at(next, Instant::now());
    }

    pub(super) fn begin_actor_tick(&mut self) {
        self.transition(PhaseV25::TickRest);
        self.totals.actor_ticks += 1;
    }

    pub(super) fn begin_tick_mount(&mut self) {
        self.transition(PhaseV25::TickMount);
        self.totals.tick_mounts += 1;
    }

    pub(super) fn begin_identity_open(&mut self) {
        self.transition(PhaseV25::TickIdentityOpen);
        self.totals.identity_reopens += 1;
    }

    pub(super) fn resume_tick(&mut self) {
        // The next transition occurs only after the actor scope has ended:
        // owner/driver/private-material teardown remains in this phase.
        self.transition(PhaseV25::TickRest);
    }

    pub(super) fn begin_terminal_audit(&mut self) {
        self.transition(PhaseV25::TerminalAudit);
    }

    pub(super) fn begin_terminal_mount(&mut self) {
        self.transition(PhaseV25::TerminalMount);
        self.totals.terminal_mounts += 1;
    }

    pub(super) fn resume_terminal_audit(&mut self) {
        self.transition(PhaseV25::TerminalAudit);
    }

    pub(super) fn finish(mut self) -> ProofTimingTotalsV25 {
        self.transition(self.phase);
        self.totals
    }
}

#[test]
fn native_proof_restart_timing_counts_only_observed_calls_v25() {
    let mut timer = NativeProofTimingV25::new();
    assert_eq!(timer.totals.actor_ticks, 0);
    assert_eq!(timer.totals.tick_mounts, 0);
    assert_eq!(timer.totals.identity_reopens, 0);
    assert_eq!(timer.totals.terminal_mounts, 0);
    for _ in 0..3 {
        timer.begin_actor_tick();
        timer.begin_tick_mount();
        timer.resume_tick();
        timer.begin_identity_open();
        timer.resume_tick();
    }
    timer.begin_terminal_audit();
    for _ in 0..2 {
        timer.begin_terminal_mount();
        timer.resume_terminal_audit();
    }
    let totals = timer.finish();
    assert_eq!(totals.actor_ticks, 3);
    assert_eq!(totals.tick_mounts, 3);
    assert_eq!(totals.identity_reopens, 3);
    assert_eq!(totals.terminal_mounts, 2);
    let report = totals.public_summary(1, "cancelled");
    for field in [
        "fixture_restart_only=true",
        "actual_daemon_latency=false",
        "leg=1 output=cancelled",
        "actor_ticks=3 bootstrap_resumes=5",
        "tick_mounts=3 identity_reopens=3 terminal_mounts=2",
    ] {
        assert!(report.contains(field), "missing public counter: {field}");
    }
}

#[test]
fn native_proof_restart_timing_phases_are_disjoint_and_cover_total_v25() {
    let mut timer = NativeProofTimingV25::new();
    let start = timer.last;
    let mut now = start;
    // Synthetic monotonic clock: no sleeping, I/O, cryptography or fixture.
    // Repeated TickRest entries represent work before/after owner reopening.
    for (next, millis) in [
        (PhaseV25::TickRest, 2),
        (PhaseV25::TickMount, 3),
        (PhaseV25::TickRest, 5),
        (PhaseV25::TickIdentityOpen, 7),
        (PhaseV25::TickRest, 11),
        (PhaseV25::TerminalAudit, 13),
        (PhaseV25::TerminalMount, 17),
        (PhaseV25::TerminalAudit, 19),
        (PhaseV25::TerminalAudit, 23),
    ] {
        now = now.checked_add(Duration::from_millis(millis)).unwrap();
        timer.transition_at(next, now);
    }
    assert_eq!(timer.totals.phases[0], Duration::from_millis(2));
    assert_eq!(timer.totals.phases[1], Duration::from_millis(5));
    assert_eq!(timer.totals.phases[2], Duration::from_millis(11));
    assert_eq!(timer.totals.phases[3], Duration::from_millis(3 + 7 + 13));
    assert_eq!(timer.totals.phases[4], Duration::from_millis(19));
    assert_eq!(timer.totals.phases[5], Duration::from_millis(17 + 23));
    assert_eq!(timer.totals.total(), now.duration_since(start));
    assert_eq!(timer.totals.total(), Duration::from_millis(100));
    let report = timer.totals.public_summary(0, "collateral");
    assert!(report.contains("native_output_total_s=0.100000"));
    assert!(report.contains("rest_tick_s=0.023000"));
}
