//! Carries the original funding/lease deadline through the scoped owner and
//! into the exact-byte POST. It never wraps Claim, Refund or reconciliation.
use std::time::{Duration, Instant};
use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort, SpendPortError};

pub(super) fn funding_deadline_v24(
    window: Instant,
    observed_before_clock: Instant,
    now_unix_ms: u64,
    lease_until_unix_ms: u64,
) -> Option<Instant> {
    let lease_remaining = lease_until_unix_ms.checked_sub(now_unix_ms)?;
    if lease_remaining == 0 {
        return None;
    }
    let lease = observed_before_clock.checked_add(Duration::from_millis(lease_remaining))?;
    // The route step that holds the DOM actuator lease is the outer bound on
    // all of this: a funding window still valid for the rest of the lease is
    // no licence to spend the whole step on one broadcast.
    let deadline =
        adapter_dom_real::route_step_deadline_v27::clamp_v27(window.min(lease));
    (deadline > observed_before_clock).then_some(deadline)
}

pub(super) struct FundingDeadlineBroadcastV24<'a> {
    inner: &'a mut dyn ExactBroadcastPort,
    deadline: Instant,
}
impl<'a> FundingDeadlineBroadcastV24<'a> {
    pub(super) fn new(inner: &'a mut dyn ExactBroadcastPort, deadline: Instant) -> Self {
        Self { inner, deadline }
    }
}
impl ExactBroadcastPort for FundingDeadlineBroadcastV24<'_> {
    fn submission_deadline_v24(&self) -> Option<Instant> {
        Some(self.deadline)
    }
    fn submit_exact(
        &mut self,
        hash: [u8; 32],
        raw: &[u8],
    ) -> Result<BroadcastAcceptance, SpendPortError> {
        self.submit_exact_before_v24(hash, raw, self.deadline)
    }
    fn submit_exact_before_v24(
        &mut self,
        hash: [u8; 32],
        raw: &[u8],
        deadline: Instant,
    ) -> Result<BroadcastAcceptance, SpendPortError> {
        let deadline = deadline.min(self.deadline);
        if deadline <= Instant::now() {
            return Err(SpendPortError::Retryable);
        }
        self.inner.submit_exact_before_v24(hash, raw, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Recording {
        ordinary: usize,
        bounded: Vec<Instant>,
    }
    impl ExactBroadcastPort for Recording {
        fn submit_exact(
            &mut self,
            _: [u8; 32],
            _: &[u8],
        ) -> Result<BroadcastAcceptance, SpendPortError> {
            self.ordinary += 1;
            Ok(BroadcastAcceptance::Accepted)
        }
        fn submit_exact_before_v24(
            &mut self,
            _: [u8; 32],
            _: &[u8],
            deadline: Instant,
        ) -> Result<BroadcastAcceptance, SpendPortError> {
            self.bounded.push(deadline);
            Ok(BroadcastAcceptance::Accepted)
        }
    }
    #[test]
    fn deadline_is_minimum_of_original_window_and_original_lease() {
        let now = Instant::now();
        let window = now + Duration::from_secs(60);
        assert_eq!(
            funding_deadline_v24(window, now, 100, 10100),
            Some(now + Duration::from_secs(10))
        );
        assert_eq!(funding_deadline_v24(window, now, 100, 100100), Some(window));
        assert_eq!(funding_deadline_v24(window, now, 100, 100), None);
        assert_eq!(funding_deadline_v24(window, now, 101, 100), None);
        assert_eq!(funding_deadline_v24(now, now, 100, 10100), None);
    }
    #[test]
    fn wrapper_cannot_extend_deadline_or_fall_back_to_unbounded_submission() {
        let mut port = Recording {
            ordinary: 0,
            bounded: vec![],
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        {
            let mut bounded = FundingDeadlineBroadcastV24::new(&mut port, deadline);
            assert_eq!(bounded.submission_deadline_v24(), Some(deadline));
            bounded
                .submit_exact_before_v24(
                    [1; 32],
                    b"synthetic-recording-port",
                    deadline + Duration::from_secs(30),
                )
                .unwrap();
        }
        assert_eq!(port.ordinary, 0);
        assert_eq!(port.bounded, vec![deadline]);
        let mut expired = FundingDeadlineBroadcastV24::new(&mut port, Instant::now());
        assert_eq!(
            expired.submit_exact([1; 32], b"x"),
            Err(SpendPortError::Retryable)
        );
        drop(expired);
        assert_eq!(port.bounded.len(), 1);
    }

    #[test]
    fn legacy_port_without_absolute_deadline_support_stays_closed() {
        struct Legacy;
        impl ExactBroadcastPort for Legacy {
            fn submit_exact(
                &mut self,
                _: [u8; 32],
                _: &[u8],
            ) -> Result<BroadcastAcceptance, SpendPortError> {
                panic!("bounded funding must never invoke the legacy unbounded method");
            }
        }
        let mut legacy = Legacy;
        let mut bounded =
            FundingDeadlineBroadcastV24::new(&mut legacy, Instant::now() + Duration::from_secs(30));
        assert_eq!(
            bounded.submit_exact([1; 32], b"never-submitted"),
            Err(SpendPortError::Retryable)
        );
    }
}
