//! A test-only facade over the original move-only daemon owner.
use super::*;
use crate::production_xmr_native_binary_v23_tests::{NativeDaemonBinaryV23, NativeDaemonModeV23};

pub(super) struct NativeXmrLivePairV23 {
    pub(super) running: Option<NativeXmrRunningColdStartV23>,
    pub(super) confirmations: u32,
    pub(super) last_pump: Option<Instant>,
}

impl NativeXmrLivePairV23 {
    fn owner(&self) -> Result<&NativeXmrRunningColdStartV23> {
        self.running
            .as_ref()
            .ok_or_else(|| "live owner already consumed".into())
    }
    fn owner_mut(&mut self) -> Result<&mut NativeXmrRunningColdStartV23> {
        self.running
            .as_mut()
            .ok_or_else(|| "live owner already consumed".into())
    }
    pub(super) fn state_dir(&self, actor: usize) -> Result<&Path> {
        self.owner()?.state_dir(actor)
    }
    pub(super) fn require_running(&mut self, actor: usize) -> Result<()> {
        self.owner_mut()?.require_running(actor)?;
        self.pump_funding()
    }
    pub(super) fn require_both_running(&mut self) -> Result<()> {
        self.owner_mut()?.require_running(0)?;
        self.owner_mut()?.require_running(1)?;
        self.pump_funding()
    }
    pub(super) fn require_both_running_for_v23(&mut self, budget: Duration) -> Result<()> {
        if budget.is_zero() || budget > Duration::from_secs(1800) {
            return Err("bounded live observation budget required".into());
        }
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or("live deadline overflow")?;
        loop {
            self.require_both_running()?;
            if Instant::now() >= deadline {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    pub(super) fn wait_funding_ready_v24(&mut self, budget: Duration) -> Result<()> {
        if budget.is_zero() || budget > Duration::from_secs(7200) {
            return Err("live funding observation budget must be bounded by 7200 seconds".into());
        }
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or("live funding deadline overflow")?;
        let mut observers = [
            observer::RouteObserverV23::new(self.state_dir(0)?)?,
            observer::RouteObserverV23::new(self.state_dir(1)?)?,
        ];
        if observers[0].route_id() != observers[1].route_id() {
            return Err("live actors do not observe the same route".into());
        }
        loop {
            self.require_both_running()?;
            let mut ready = true;
            for observer in &mut observers {
                let Some(snapshot) = observer.poll()? else {
                    ready = false;
                    continue;
                };
                if snapshot.aborted_unfunded
                    || matches!(
                        snapshot.health,
                        route_executor::HealthStateV1::RecoveryOnly
                            | route_executor::HealthStateV1::ManualIntervention
                    )
                {
                    return Err(
                        "live route entered an exit-only state before readiness observation".into(),
                    );
                }
                ready &= funding_progress_ready([
                    snapshot.upstream.funding.progress(),
                    snapshot.downstream.funding.progress(),
                ]);
            }
            if Instant::now() >= deadline {
                return Err(
                    "both actual actors did not retain Funding within the observation budget"
                        .into(),
                );
            }
            if ready {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    pub(super) fn stop_actor_v23(&mut self, actor: usize) -> Result<std::process::ExitStatus> {
        let child = self
            .owner_mut()?
            .processes
            .get_mut(actor)
            .ok_or("live actor index")?
            .take()
            .ok_or("live actor already stopped")?;
        let status = child.stop()?;
        use std::os::unix::process::ExitStatusExt;
        if !status.success() && status.signal() != Some(15) {
            return Err("live daemon failed before orderly shutdown".into());
        }
        Ok(status)
    }
    pub(super) fn stop_all_v23(&mut self) -> Result<()> {
        for actor in 0..2 {
            if self.owner()?.processes[actor].is_some() {
                self.stop_actor_v23(actor)?;
            }
        }
        Ok(())
    }
    pub(super) fn crash_actor_v23(&mut self, actor: usize) -> Result<()> {
        self.owner_mut()?.crash_actor(actor)
    }
    pub(super) fn reopen_actor_v23(
        &mut self,
        actor: usize,
        binary: &NativeDaemonBinaryV23,
    ) -> Result<()> {
        self.owner_mut()?
            .restart_actor(actor, binary, NativeDaemonModeV23::Reopen)
    }
    pub(super) fn require_refused_launch_v23(
        &self,
        actor: usize,
        binary: &NativeDaemonBinaryV23,
        mode: NativeDaemonModeV23,
    ) -> Result<()> {
        // The negative control must reach the binary, not the normal restart
        // facade's byte-equality guard. Reuse the original credentials only.
        let retained = self.owner()?.restart.get(actor).ok_or("live actor index")?;
        let mut child = binary.launch(&retained.state_dir, retained.credentials.clone(), mode)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.poll()? {
                if status.success() {
                    return Err("daemon accepted a forbidden launch".into());
                }
                child.stop()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                child.stop()?;
                return Err("daemon did not refuse before observation deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Confirm only daemon-dispatched Funding transactions bound by the
    /// original coordinator and route snapshot. Never pre-place candidates or
    /// indiscriminately mine pool contents; Claim/Refund are outside this suite.
    fn pump_funding(&mut self) -> Result<()> {
        if self
            .last_pump
            .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return Ok(());
        }
        self.last_pump = Some(Instant::now());
        let mut actions = Vec::new();
        for actor in 0..2 {
            let state = self.state_dir(actor)?;
            let mut observer = observer::RouteObserverV23::new(state)?;
            if let Some(snapshot) = observer.poll()? {
                let coordinator = coordinator::CoordinatorObserverV23::new(state)?;
                for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
                    if let Some(action) = coordinator.poll(&snapshot, leg, ActionKindV1::Funding)? {
                        if action.xmr_dispatched {
                            actions.push(action);
                        }
                    }
                }
            }
        }
        let history = self.owner_mut()?.xmr_history_status_v23()?;
        let mut unique = std::collections::BTreeSet::new();
        if history.pool_tx_hashes.len() > 32
            || history
                .pool_tx_hashes
                .iter()
                .any(|hash| *hash == [0; 32] || !unique.insert(*hash))
        {
            return Err("live native pool identity or bound".into());
        }
        let include = history
            .pool_tx_hashes
            .into_iter()
            .filter(|hash| actions.iter().any(|action| action.matches_xmr(*hash)))
            .collect::<Vec<_>>();
        if !include.is_empty() {
            let target = history
                .tip_height
                .checked_add(u64::from(self.confirmations))
                .ok_or("live native finality height overflow")?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            self.owner_mut()?
                .advance_xmr_history_v23(target, now, &include)?;
        }
        Ok(())
    }
}

fn funding_progress_ready(progress: [route_executor::ActionProgressV1; 2]) -> bool {
    // This is readiness to stop and inspect authenticated Contracts, NOT proof
    // that a committed aggregate was dispatched or reached chain finality.
    progress.into_iter().all(|value| {
        matches!(
            value,
            route_executor::ActionProgressV1::Committed
                | route_executor::ActionProgressV1::Externalized
                | route_executor::ActionProgressV1::Final
        )
    })
}

#[test]
fn funding_readiness_requires_both_positions_not_elapsed_time() {
    use route_executor::ActionProgressV1::*;
    assert!(!funding_progress_ready([NotPrepared, NotPrepared]));
    assert!(!funding_progress_ready([Final, NotPrepared]));
    assert!(!funding_progress_ready([NotPrepared, Committed]));
    assert!(funding_progress_ready([Committed, Committed]));
    assert!(funding_progress_ready([Final, Externalized]));
}

impl Drop for NativeXmrLivePairV23 {
    fn drop(&mut self) {
        if let Some(owner) = self.running.take() {
            // Retain originals on every result. This neutral archive operation
            // is not a success assertion; exact libtest outcomes decide that.
            let NativeXmrRunningColdStartV23 {
                processes,
                restart,
                _dependencies,
                _fixture,
            } = owner;
            drop(processes);
            drop(_dependencies);
            drop(restart);
            let path = _fixture._root.keep();
            eprintln!(
                "native live daemon: original fixture retained at {}",
                path.display()
            );
        }
    }
}
