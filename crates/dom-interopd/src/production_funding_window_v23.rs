//! A transient, default-closed freshness gate, never an economic authority.
//! Recovery and reconciliation deliberately bypass it. The composition root
//! opens it only after all selected native-height observations have succeeded.
use crate::supervisor::{
    AuthorityRefusalV1, RouteActionAuthority, RouteActionAuthorizationRequestV1,
};
use route_executor::{ActionIntentV1, ActionKindV1};
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildReconciliationOutcomeV1,
    ChildReconciliationRequestV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1,
};
use std::{
    cell::Cell,
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(crate) struct ProductionFundingWindowV23 {
    route_id: [u8; 32],
    valid_until: Rc<Cell<Option<Instant>>>,
}

impl ProductionFundingWindowV23 {
    pub(crate) fn new(route_id: [u8; 32]) -> Self {
        Self {
            route_id,
            valid_until: Rc::new(Cell::new(None)),
        }
    }

    pub(crate) fn close(&self) {
        self.valid_until.set(None);
    }

    // Age begins BEFORE RPC, not when a slow reply finally reaches the root.
    pub(crate) fn observed_all_before_deadline(&self, started: Instant) {
        self.valid_until
            .set(started.checked_add(Duration::from_secs(60)));
    }

    pub(crate) fn available(&self) -> bool {
        self.available_at(Instant::now())
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.valid_until
            .get()
            .map(|until| until.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::ZERO)
    }

    /// Original process-local deadline for this exact route. Reading this
    /// capability never refreshes it; callers may only shorten the deadline.
    pub(crate) fn deadline_for_route(&self, route_id: [u8; 32]) -> Option<Instant> {
        if route_id != self.route_id {
            return None;
        }
        self.valid_until
            .get()
            .filter(|until| Instant::now() < *until)
    }

    fn available_at(&self, now: Instant) -> bool {
        self.valid_until.get().is_some_and(|until| now < until)
    }

    pub(crate) fn guard<T>(&self, inner: T) -> FundingGuardV23<T> {
        FundingGuardV23 {
            window: self.clone(),
            inner,
        }
    }
}

pub(crate) struct FundingGuardV23<T> {
    window: ProductionFundingWindowV23,
    inner: T,
}

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl<T> crate::supervisor::authority_seal::Sealed for FundingGuardV23<T> {}

impl<T: RouteActionAuthority> RouteActionAuthority for FundingGuardV23<T> {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        if request.route_id() != self.window.route_id {
            return Err(AuthorityRefusalV1::Refused);
        }
        if request.action() == ActionKindV1::Funding && !self.window.available() {
            return Err(AuthorityRefusalV1::Unavailable);
        }
        self.inner.authorize_route_action(request)
    }
}

impl<T: SettlementChildAuthorityV1> SettlementChildAuthorityV1 for FundingGuardV23<T> {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        if request.route_id() != self.window.route_id {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        if request.action() == SettlementActionV1::Funding && !self.window.available() {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        self.inner.externalize_child(request)
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.inner.reconcile_child(request)
    }
}

impl<T: SettlementChildObserverV1> SettlementChildObserverV1 for FundingGuardV23<T> {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.inner.observe_child(request)
    }
}

#[cfg(test)]
#[path = "production_funding_window_v23_tests.rs"]
mod boundary_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_closed_and_revocation_reaches_every_consumer() {
        let window = ProductionFundingWindowV23::new([1; 32]);
        let consumer = window.clone();
        let now = Instant::now();
        assert!(!consumer.available_at(now));
        window.observed_all_before_deadline(now);
        assert!(consumer.available_at(now));
        window.close();
        assert!(!consumer.available_at(now));
    }

    #[test]
    fn slow_observation_does_not_renew_its_own_freshness() {
        let window = ProductionFundingWindowV23::new([1; 32]);
        let start = Instant::now();
        window.observed_all_before_deadline(start);
        assert!(window.available_at(start + Duration::from_secs(59)));
        assert!(!window.available_at(start + Duration::from_secs(60)));
        assert!(!window.available_at(start + Duration::from_secs(61)));
    }

    #[test]
    fn reopening_does_not_inherit_a_previous_process_permission() {
        let old = ProductionFundingWindowV23::new([1; 32]);
        old.observed_all_before_deadline(Instant::now());
        let reopened = ProductionFundingWindowV23::new([1; 32]);
        assert!(!reopened.available());
    }
}
