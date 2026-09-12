//! Historical reopening is an exit-only capability, never fresh F6 admission.
use super::*;
use route_executor::{ActionProgressV1, FrozenBindingsV1, HealthStateV1, RouteSnapshotV1};

#[path = "f6_native_funding_recovery_v24.rs"]
mod native_funding;

#[derive(Clone)]
pub(crate) struct HistoricalF6RecoveryV24 {
    route_id: Digest32,
    composition: Digest32,
    frozen: FrozenBindingsV1,
    native_committed: Option<native_funding::NativeCommittedFundingV24>,
}

impl AuthenticatedProductionInputsV1 {
    /// No caller-shaped snapshot enters. Replay and the authenticated admission
    /// must agree before a previously externalized route can bypass fresh F6.
    pub(crate) fn historical_f6_recovery_v24(
        &self,
    ) -> Result<Option<HistoricalF6RecoveryV24>, ProductionInputErrorV1> {
        let replay = self.audited_recovery_snapshot_v24()?;
        if !requires_historical_exit(&replay, self.current_time_ancestry_ready()) {
            return Ok(None);
        }
        Ok(Some(HistoricalF6RecoveryV24 {
            route_id: self.admission.route_id(),
            composition: self.composition.binding_digest(),
            frozen: self.admission.frozen_bindings().clone(),
            native_committed: None,
        }))
    }

    fn audited_recovery_snapshot_v24(&self) -> Result<RouteSnapshotV1, ProductionInputErrorV1> {
        let error = || ProductionInputErrorV1::RouteStateRefused;
        let store = self.route_store.as_ref().ok_or_else(error)?;
        let checkpoint = store
            .audit_frozen_admission_checkpoint_v2(self.admission.route_id())
            .map_err(|_| error())?;
        let replay = store
            .audit_external_custody_only_v1(self.admission.route_id())
            .map_err(|_| error())?;
        if checkpoint.route_id != self.admission.route_id()
            || checkpoint.composition_v2_digest != self.composition.binding_digest()
            || &checkpoint.bindings != self.admission.frozen_bindings()
            || replay.bindings.as_ref() != Some(self.admission.frozen_bindings())
        {
            return Err(error());
        }
        Ok(replay)
    }
}

/// A funded restart is not itself a reason to abandon the normal claim lane.
/// The readiness bit is authenticated by the input loader; this is deliberately
/// not a fallback for errors from fresh F6, inventory, or other live services.
fn requires_historical_exit(snapshot: &RouteSnapshotV1, current_time_ready: bool) -> bool {
    has_externalized_funding(snapshot)
        && (snapshot.health == HealthStateV1::RecoveryOnly || !current_time_ready)
}

fn has_externalized_funding(snapshot: &RouteSnapshotV1) -> bool {
    !snapshot.aborted_unfunded
        && [&snapshot.upstream, &snapshot.downstream]
            .iter()
            .any(|leg| {
                matches!(
                    leg.funding.progress(),
                    ActionProgressV1::Externalized | ActionProgressV1::Final
                )
            })
}

impl HistoricalF6RecoveryV24 {
    pub(crate) fn require_scope(&self, route: Digest32, composition: Digest32) -> bool {
        self.route_id == route && self.composition == composition
    }

    /// Commit the exit-only lane before the first runtime tick. Identifiers
    /// bind the original composition and stay stable across all restarts.
    pub(crate) fn restrict_runtime<C: crate::supervisor::Clock>(
        &self,
        supervisor: &mut crate::supervisor::RouteSupervisorV1<C>,
    ) -> Result<(), crate::supervisor::RouteSupervisorErrorV1> {
        use crate::supervisor::RouteSupervisorErrorV1 as Error;
        let snapshot = supervisor.snapshot()?;
        if snapshot.route_id != self.route_id
            || snapshot.bindings.as_ref() != Some(&self.frozen)
            || !(has_externalized_funding(&snapshot)
                || self
                    .native_committed
                    .as_ref()
                    .is_some_and(|native| native.matches(&snapshot)))
        {
            return Err(Error::MissingFrozenBindings);
        }
        let mut bytes = b"DOM-INTEROPD/HISTORICAL-F6-RECOVERY/V24\0".to_vec();
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(&self.composition);
        let digest = route_executor::digest_bytes_v1(&bytes);
        supervisor.set_health(digest, HealthStateV1::RecoveryOnly, digest)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use route_executor::{ActionStateV1, EffectReferenceV1};

    #[test]
    fn healthy_funded_restart_keeps_normal_claim_lane_while_expiry_is_exit_only() {
        let mut snapshot = RouteSnapshotV1::new([1; 32]).unwrap();
        snapshot.upstream.funding = ActionStateV1::Externalized {
            effect: EffectReferenceV1 {
                effect_id: [2; 32],
                fencing_epoch: 1,
                semantic_digest: [3; 32],
                contains_route_secret: false,
                expected_transaction_id: Some([4; 32]),
            },
            transaction_id: [4; 32],
        };
        for health in [HealthStateV1::Running, HealthStateV1::Degraded] {
            snapshot.health = health;
            let unchanged = snapshot.clone();
            assert!(!requires_historical_exit(&snapshot, true));
            assert_eq!(snapshot, unchanged);
            assert!(requires_historical_exit(&snapshot, false));
        }
        snapshot.health = HealthStateV1::RecoveryOnly;
        assert!(requires_historical_exit(&snapshot, true));
        assert!(requires_historical_exit(&snapshot, false));
        snapshot.aborted_unfunded = true;
        assert!(!requires_historical_exit(&snapshot, false));
    }

    #[test]
    fn only_real_externalization_progress_qualifies_for_historical_reopening() {
        let mut snapshot = RouteSnapshotV1::new([1; 32]).unwrap();
        let effect = EffectReferenceV1 {
            effect_id: [2; 32],
            fencing_epoch: 1,
            semantic_digest: [3; 32],
            contains_route_secret: false,
            expected_transaction_id: Some([4; 32]),
        };
        assert!(!has_externalized_funding(&snapshot));
        snapshot.health = HealthStateV1::RecoveryOnly;
        assert!(!has_externalized_funding(&snapshot));
        snapshot.upstream.funding = ActionStateV1::Committed(effect.clone());
        assert!(!has_externalized_funding(&snapshot));
        for state in [
            ActionStateV1::Externalized {
                effect: effect.clone(),
                transaction_id: [4; 32],
            },
            ActionStateV1::Final {
                effect: effect.clone(),
                transaction_id: [4; 32],
                evidence_digest: [5; 32],
            },
            ActionStateV1::FinalityInvalidated {
                effect,
                transaction_id: [4; 32],
                prior_evidence_digest: [5; 32],
                reorg_evidence_digest: [6; 32],
            },
        ] {
            snapshot.upstream.funding = state;
            assert!(has_externalized_funding(&snapshot));
            snapshot.aborted_unfunded = true;
            assert!(!has_externalized_funding(&snapshot));
            snapshot.aborted_unfunded = false;
        }
    }
}
