//! Explicit timing budget for probabilistic proof-of-work finality.

/// Timing consequences of waiting for a number of PoW confirmations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PowFinalityBudget {
    target_block_seconds: u64,
    confirmations: u64,
    active_budget_seconds: u64,
    fixed_work_seconds: u64,
}

impl PowFinalityBudget {
    /// Construct a bounded policy. Fixed work is time outside block production.
    pub fn new(
        target_block_seconds: u64,
        confirmations: u64,
        active_budget_seconds: u64,
        fixed_work_seconds: u64,
    ) -> Result<Self, &'static str> {
        if target_block_seconds == 0 {
            return Err("target block interval must be positive");
        }
        if confirmations == 0 || confirmations > 10_000 {
            return Err("confirmation count must be between 1 and 10000");
        }
        if active_budget_seconds == 0 || fixed_work_seconds >= active_budget_seconds {
            return Err("fixed work must leave a positive confirmation budget");
        }
        Ok(Self {
            target_block_seconds,
            confirmations,
            active_budget_seconds,
            fixed_work_seconds,
        })
    }

    /// Consensus target interval for one block.
    pub const fn target_block_seconds(self) -> u64 {
        self.target_block_seconds
    }

    /// Required canonical confirmation depth.
    pub const fn confirmations(self) -> u64 {
        self.confirmations
    }

    /// Nominal time consumed by the required block arrivals alone.
    pub fn nominal_confirmation_seconds(self) -> Option<u64> {
        self.target_block_seconds.checked_mul(self.confirmations)
    }

    /// Whether nominal block time plus fixed work fits the active deadline.
    pub fn nominally_fits(self) -> bool {
        self.nominal_confirmation_seconds()
            .and_then(|seconds| seconds.checked_add(self.fixed_work_seconds))
            .is_some_and(|seconds| seconds <= self.active_budget_seconds)
    }

    /// Number of nominal block arrivals that fit after fixed work.
    pub const fn maximum_nominal_confirmations(self) -> u64 {
        (self.active_budget_seconds - self.fixed_work_seconds) / self.target_block_seconds
    }

    /// Poisson-model probability that all confirmations arrive before deadline.
    ///
    /// This is descriptive evidence, not a security guarantee. PoW block arrival
    /// has no finite deterministic upper bound.
    pub fn poisson_completion_probability(self) -> f64 {
        let available = self.active_budget_seconds - self.fixed_work_seconds;
        let mean = available as f64 / self.target_block_seconds as f64;
        let mut term = 1.0;
        let mut sum = 1.0;
        for index in 1..self.confirmations {
            term *= mean / index as f64;
            sum += term;
        }
        (1.0 - (-mean).exp() * sum).clamp(0.0, 1.0)
    }

    /// PoW confirmation time cannot provide a finite deterministic deadline.
    pub const fn deterministic_deadline(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_dom_confirmations_do_not_fit_three_minutes() {
        let budget = PowFinalityBudget::new(120, 2, 180, 0).unwrap();
        assert_eq!(budget.nominal_confirmation_seconds(), Some(240));
        assert_eq!(budget.maximum_nominal_confirmations(), 1);
        assert!(!budget.nominally_fits());
        assert!(!budget.deterministic_deadline());
        let probability = budget.poisson_completion_probability();
        assert!((probability - 0.442_174_599_6).abs() < 1e-9);
    }

    #[test]
    fn non_chain_work_reduces_the_probability_further() {
        let budget = PowFinalityBudget::new(120, 2, 180, 27).unwrap();
        assert_eq!(budget.maximum_nominal_confirmations(), 1);
        assert!(!budget.nominally_fits());
        let probability = budget.poisson_completion_probability();
        assert!((probability - 0.364_294_547_3).abs() < 1e-9);
    }

    #[test]
    fn invalid_policies_fail_closed() {
        assert!(PowFinalityBudget::new(0, 2, 180, 0).is_err());
        assert!(PowFinalityBudget::new(120, 0, 180, 0).is_err());
        assert!(PowFinalityBudget::new(120, 2, 180, 180).is_err());
        assert!(PowFinalityBudget::new(120, 10_001, 180, 0).is_err());
    }
}
