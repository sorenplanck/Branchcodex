//! Observational timing only: no Store opens, RPCs, payloads or capabilities.
//! State times are polling observations, not timestamps of signing operations.
use route_executor::{ActionProgressV1, RouteSnapshotV1};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) enum LaneV24 {
    // Enrollment, route secrets and admission are per-swap work. This interval
    // also contains fixture infrastructure; conservatively include ALL of it
    // in cold-start latency, never subtract it as node/test-only setup.
    ColdSwapPreparation,
    FixtureSetup,
    NormalDaemon,
    Validation,
    InjectedRecovery,
}

impl LaneV24 {
    fn name(self) -> &'static str {
        match self {
            Self::ColdSwapPreparation => "cold_swap_preparation",
            Self::FixtureSetup => "fixture_setup",
            Self::NormalDaemon => "normal_daemon",
            Self::Validation => "validation",
            Self::InjectedRecovery => "injected_recovery",
        }
    }
}

fn milliseconds(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn event(
    scenario: &'static str,
    lane: LaneV24,
    phase: &'static str,
    state: &'static str,
    elapsed: Duration,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "DOM_NATIVE_DAEMON_TIMING_V24",
        "measurement": "offline_loopback_observation_only",
        "scenario": scenario,
        "lane": lane.name(),
        "phase": phase,
        "event": state,
        "elapsed_ms": milliseconds(elapsed),
        "cold_swap_latency_component": matches!(lane, LaneV24::ColdSwapPreparation | LaneV24::NormalDaemon),
        "includes_test_infrastructure": matches!(lane, LaneV24::ColdSwapPreparation),
    })
}

pub(super) struct PhaseV24 {
    scenario: &'static str,
    lane: LaneV24,
    phase: &'static str,
    started: Instant,
    finished: bool,
}

impl PhaseV24 {
    pub(super) fn start(scenario: &'static str, lane: LaneV24, phase: &'static str) -> Self {
        eprintln!(
            "{}",
            event(scenario, lane, phase, "started", Duration::ZERO)
        );
        Self {
            scenario,
            lane,
            phase,
            started: Instant::now(),
            finished: false,
        }
    }

    pub(super) fn finish(mut self) {
        self.finished = true;
        eprintln!(
            "{}",
            event(
                self.scenario,
                self.lane,
                self.phase,
                "completed",
                self.started.elapsed()
            ),
        );
    }
}

impl Drop for PhaseV24 {
    fn drop(&mut self) {
        if !self.finished {
            eprintln!(
                "{}",
                event(
                    self.scenario,
                    self.lane,
                    self.phase,
                    "incomplete",
                    self.started.elapsed()
                ),
            );
        }
    }
}

/// Consume snapshots that the scenario already read; never poll another owner.
/// Initial route visibility includes activation and graph rounds as ONE opaque
/// interval. We cannot infer individual round durations from this boundary.
pub(super) struct SnapshotTimingV24 {
    scenario: &'static str,
    lane: LaneV24,
    launched: Instant,
    seen: [bool; 2],
    previous: [[Option<(ActionProgressV1, Duration)>; 4]; 2],
}

impl SnapshotTimingV24 {
    pub(super) fn new(scenario: &'static str, lane: LaneV24, launched: Instant) -> Self {
        Self {
            scenario,
            lane,
            launched,
            seen: [false; 2],
            previous: [[None; 4]; 2],
        }
    }

    pub(super) fn observe(&mut self, actor: usize, snapshot: &RouteSnapshotV1) {
        for item in self.observe_at(actor, snapshot, self.launched.elapsed()) {
            eprintln!("{item}");
        }
    }

    fn observe_at(
        &mut self,
        actor: usize,
        snapshot: &RouteSnapshotV1,
        elapsed: Duration,
    ) -> Vec<serde_json::Value> {
        let Some(previous) = self.previous.get_mut(actor) else {
            // Instrumentation does not replace the scenario's actor guards.
            return Vec::new();
        };
        let mut events = Vec::new();
        if !self.seen[actor] {
            self.seen[actor] = true;
            let mut first = event(
                self.scenario,
                self.lane,
                "first_route_snapshot",
                "observed",
                elapsed,
            );
            first["actor"] = actor.into();
            first["includes_opaque_activation_and_graph_rounds"] = true.into();
            events.push(first);
        }
        let phases = [
            "upstream_funding",
            "upstream_claim",
            "downstream_funding",
            "downstream_claim",
        ];
        let current = [
            snapshot.upstream.funding.progress(),
            snapshot.upstream.claim.progress(),
            snapshot.downstream.funding.progress(),
            snapshot.downstream.claim.progress(),
        ];
        for index in 0..4 {
            if previous[index].is_some_and(|(state, _)| state == current[index]) {
                continue;
            }
            let mut item = event(self.scenario, self.lane, phases[index], "observed", elapsed);
            item["actor"] = actor.into();
            item["progress"] = progress_name(current[index]).into();
            if let Some((before, observed_at)) = previous[index] {
                item["previous_observed_progress"] = progress_name(before).into();
                item["since_previous_observation_ms"] =
                    milliseconds(elapsed.saturating_sub(observed_at)).into();
            }
            // A poll may skip states; never report an unobserved signing,
            // broadcast or finality duration as an exact operation duration.
            item["may_include_unobserved_transitions"] = true.into();
            previous[index] = Some((current[index], elapsed));
            events.push(item);
        }
        events
    }
}

fn progress_name(progress: ActionProgressV1) -> &'static str {
    match progress {
        ActionProgressV1::NotPrepared => "not_prepared",
        ActionProgressV1::Committed => "committed",
        ActionProgressV1::Externalized => "externalized",
        ActionProgressV1::Final => "final",
    }
}

#[test]
fn daemon_timing_observes_only_public_transitions_without_inventing_round_durations_v24(
) -> Result<(), Box<dyn std::error::Error>> {
    use route_executor::{ActionStateV1, EffectReferenceV1};
    let mut snapshot = RouteSnapshotV1::new([0xab; 32])?;
    let mut timing = SnapshotTimingV24::new("claims_reopen", LaneV24::NormalDaemon, Instant::now());
    let first = timing.observe_at(0, &snapshot, Duration::from_secs(40));
    assert_eq!(first.len(), 5);
    assert_eq!(first[0]["phase"], "first_route_snapshot");
    assert_eq!(first[0]["elapsed_ms"], 40_000);
    assert!(timing
        .observe_at(0, &snapshot, Duration::from_secs(50))
        .is_empty());
    snapshot.upstream.funding = ActionStateV1::Final {
        effect: EffectReferenceV1 {
            effect_id: [0xcd; 32],
            fencing_epoch: 1,
            semantic_digest: [0xde; 32],
            contains_route_secret: false,
            expected_transaction_id: Some([0xef; 32]),
        },
        transaction_id: [0xef; 32],
        evidence_digest: [0xfa; 32],
    };
    let next = timing.observe_at(0, &snapshot, Duration::from_secs(100));
    assert_eq!(next.len(), 1);
    assert_eq!(next[0]["progress"], "final");
    assert_eq!(next[0]["previous_observed_progress"], "not_prepared");
    assert_eq!(next[0]["since_previous_observation_ms"], 60_000);
    assert_eq!(next[0]["may_include_unobserved_transitions"], true);
    for item in first.iter().chain(&next) {
        assert_eq!(item["measurement"], "offline_loopback_observation_only");
        let fields = item.as_object().ok_or("timing event is not an object")?;
        assert!(!fields.keys().any(|name| name.contains("digest")
            || name.contains("transaction")
            || name.contains("secret")
            || name.ends_with("_id")));
    }
    assert_eq!(
        timing
            .observe_at(1, &snapshot, Duration::from_secs(110))
            .len(),
        5
    );
    let replay = event(
        "claims_reopen",
        LaneV24::Validation,
        "reopen_replay",
        "completed",
        Duration::from_secs(2),
    );
    assert_eq!(replay["lane"], "validation");
    assert_ne!(replay["lane"], next[0]["lane"]);
    let preparation = event(
        "claims_reopen",
        LaneV24::ColdSwapPreparation,
        "cold_swap_preparation",
        "completed",
        Duration::from_secs(90),
    );
    assert_eq!(preparation["lane"], "cold_swap_preparation");
    assert_eq!(preparation["cold_swap_latency_component"], true);
    assert_eq!(preparation["includes_test_infrastructure"], true);
    assert_eq!(next[0]["cold_swap_latency_component"], true);
    assert_eq!(replay["cold_swap_latency_component"], false);
    Ok(())
}
