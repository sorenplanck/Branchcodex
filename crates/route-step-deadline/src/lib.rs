//! One wall clock shared by every blocking operation of a route step.
//!
//! A route step runs under the DOM actuator lease, renewed immediately before
//! the step and not again until it returns. Bounding each blocking call on its
//! own does not bound the step: a step makes several of them and their ceilings
//! add up. Measured on the DOM↔XMR route, per-call limits of 15 s, 30 s and
//! 60 s still produced a 145 s step against a 120 s lease.
//!
//! This crate is a leaf on purpose. The ceiling has to be visible from every
//! adapter that can block inside a step — the XMR sidecar client, the Monero
//! RPC reader, the F7 anchor scanner — and none of those may depend on the
//! composition root that arms it. The composition root arms the ceiling before
//! the step and disarms it after; every deadline constructor below it narrows
//! to the ceiling. Unarmed, every call keeps its own budget and nothing changes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::cell::Cell;
use std::time::{Duration, Instant};

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Arms the ceiling for the step about to run, returning the previous value so
/// a nested arm can restore it.
pub fn arm(deadline: Option<Instant>) -> Option<Instant> {
    DEADLINE.with(|cell| cell.replace(deadline))
}

/// The step ceiling, when one is armed.
pub fn armed() -> Option<Instant> {
    DEADLINE.with(Cell::get)
}

/// Narrows a caller's own deadline to the step ceiling. Never widens it.
pub fn clamp(own: Instant) -> Instant {
    match armed() {
        Some(step) if step < own => step,
        _ => own,
    }
}

/// A caller's optional deadline, filled from the ceiling when absent and
/// narrowed to it when present. `None` only when nothing bounds the call.
pub fn clamp_or_armed(own: Option<Instant>) -> Option<Instant> {
    match (own, armed()) {
        (Some(own), Some(step)) => Some(own.min(step)),
        (Some(own), None) => Some(own),
        (None, step) => step,
    }
}

/// The same narrowing expressed as a duration, for blocking waits that take a
/// timeout rather than a deadline. `None` when the step has no time left, which
/// the caller must treat as "not now", never as a verdict about the chain.
pub fn remaining(own: Duration) -> Option<Duration> {
    let Some(step) = armed() else {
        return Some(own);
    };
    let left = step.checked_duration_since(Instant::now())?;
    if left.is_zero() {
        return None;
    }
    Some(left.min(own))
}

/// Restores the previous ceiling when dropped, so a panic inside the step
/// cannot leave a stale ceiling armed for whatever runs next on the thread.
pub struct Armed(Option<Instant>);

impl Armed {
    /// Arms `deadline` and returns the guard that restores the prior value.
    ///
    /// Narrow-only: when a ceiling is already armed, the effective ceiling is
    /// the earlier of the two. A nested guard can therefore shorten the step
    /// it runs inside but can never extend it — an extension would let an
    /// inner phase outlive the lease the outer step is holding.
    pub fn new(deadline: Option<Instant>) -> Self {
        let effective = match (deadline, armed()) {
            (Some(own), Some(step)) => Some(own.min(step)),
            (Some(own), None) => Some(own),
            (None, step) => step,
        };
        Self(arm(effective))
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        arm(self.0);
    }
}
