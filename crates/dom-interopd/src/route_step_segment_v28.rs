//! Route-step segment timing and the lease-phase marker.
//!
//! `driver.rs` is compiled under every feature set, so these helpers live
//! here rather than in the production-only Stage-12 module they were written
//! in; that module re-exports them so its callers keep their paths.

thread_local! {
    static LEASE_PHASE_V25: std::cell::Cell<&'static str> = const { std::cell::Cell::new("start") };
}

/// Diagnostic marker of the phase currently holding the DOM actuator lease.
/// Static names only; read by the renewal hook to name an oversized gap.
pub(crate) fn mark_lease_phase_v25(phase: &'static str) {
    LEASE_PHASE_V25.with(|cell| cell.set(phase));
}

pub(crate) fn lease_phase_v25() -> &'static str {
    LEASE_PHASE_V25.with(std::cell::Cell::get)
}

/// Names and times one segment inside a single route step.
///
/// Three independent runs put the fatal claim step at 145.6 s, 144.4 s and
/// 144.3 s — a one-second spread, which is a fixed timer, not variable work.
/// The step ceiling bounds every call that reads a clock, and no child
/// operation reaches 30 s, so the segment that burns the rest has never been
/// named. This marks the lease phase (so `dom_lease_lapsed` reports where the
/// lease actually died) and prints any segment over ten seconds. Static
/// literals and a duration only: no identifier, amount or digest.
pub(crate) fn step_segment_v28<T>(segment: &'static str, run: impl FnOnce() -> T) -> T {
    let restore = lease_phase_v25();
    mark_lease_phase_v25(segment);
    let started = std::time::Instant::now();
    let outcome = run();
    let elapsed = started.elapsed();
    if elapsed >= std::time::Duration::from_secs(10) {
        eprintln!(
            "DOM_STEP_SEGMENT_SLOW_V28 segment={segment} ms={}",
            elapsed.as_millis()
        );
    }
    mark_lease_phase_v25(restore);
    outcome
}
