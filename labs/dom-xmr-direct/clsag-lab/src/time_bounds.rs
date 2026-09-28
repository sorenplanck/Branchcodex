//! Conditional DOM height-to-time arithmetic, NOT chain authentication or a
//! deposit authorization. A target/average block interval is never a minimum.
//! Caller must establish that the anchor remains an ancestor on the accepted
//! chain, and bound validator clock error relative to the deadline's clock.

use dom_core::{BlockHeight, Timestamp, MAX_FUTURE_BLOCK_TIME, TESTNET_MAX_FUTURE_BLOCK_TIME};

use crate::{recovery_challenge::RecoveryChallenge, xmr_recovery::XmrDirectRecoveryLink};

#[derive(Clone, Copy)]
pub enum DomClockNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl DomClockNetwork {
    pub fn future_tolerance(self) -> u64 {
        match self {
            Self::Testnet => TESTNET_MAX_FUTURE_BLOCK_TIME,
            Self::Mainnet | Self::Regtest => MAX_FUTURE_BLOCK_TIME,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingError {
    HeightAlreadyReached,
    Overflow,
    InvalidAssumption,
    InitiationWindowExhausted,
}

/// Historical one-shot client costs, re-verifying the public offer for every
/// solve. These values must never be inferred merely
/// from an average or a successful benchmark. Include startup, parsing and
/// IPC and Feldman checks in verification; include initial window validation,
/// permitted pauses and reconstruction in overhead.
#[derive(Clone, Copy)]
pub struct AssumedSerialRecoveryCosts {
    pub verification_per_candidate_secs: u64,
    pub solve_per_candidate_secs: u64,
    pub overhead_secs: u64,
}

/// Request-driven session: public verification once, then sequential
/// puzzle solves with independent scalar/Feldman checks. No parallel speedup
/// is assumed. Every duration remains a caller-supplied upper-bound assumption.
#[derive(Clone, Copy)]
pub struct AssumedSessionRecoveryCosts {
    pub public_verification_once_secs: u64,
    pub solve_and_check_per_candidate_secs: u64,
    pub overhead_secs: u64,
}

/// A live retained verifier already checked setup before puzzle disclosure,
/// and the offer/openings before funding. Those costs still belong to
/// preparation. A restart is not covered by this assumption and must never
/// restart the disclosure clock. All values are assumed upper bounds.
#[derive(Clone, Copy)]
pub struct AssumedPreparedRecoveryCosts {
    pub solve_and_check_per_candidate_secs: u64,
    pub overhead_secs: u64,
}

/// One opening for a separately verified DIRECT relation capsule. These costs
/// cannot be applied to a cut-and-choose capsule. Includes point validation;
/// overhead must cover IPC, reconstruction, shutdown and permitted pauses.
#[derive(Clone, Copy)]
pub struct AssumedDirectRecoveryCosts {
    pub opening_and_check_secs: u64,
    pub overhead_secs: u64,
}

/// An assumption record tied to an exact challenge or direct capsule link,
/// not a proof of timely recovery or permission to fund. Recoverability and
/// the respective backend's security remain separate obligations.
#[derive(Clone)]
pub struct AssumedXmrRecoveryWindow {
    capsule_binding: [u8; 64],
    disclosed_at: Timestamp,
    earliest_adversarial: Timestamp,
    latest_honest: Timestamp,
    candidates: u16,
}

#[derive(Clone, Copy)]
pub struct AssumedClaimDelays {
    pub xmr_resolution_secs: u64,
    pub observation_secs: u64,
    pub dom_resolution_secs: u64,
}

#[derive(Clone, Copy)]
pub enum InitialClaimOrder {
    XmrFirst,
    DomFirst,
}

impl AssumedXmrRecoveryWindow {
    /// Restore original assumptions from a pinned local manifest, never from
    /// the current clock. This is not evidence that those bounds are true.
    pub(crate) fn restore_original(
        capsule_binding: [u8; 64],
        candidates: u16,
        disclosed_at: Timestamp,
        earliest_adversarial: Timestamp,
        latest_honest: Timestamp,
    ) -> Result<Self, TimingError> {
        if capsule_binding == [0; 64]
            || candidates == 0
            || earliest_adversarial < disclosed_at
            || latest_honest < earliest_adversarial
        {
            return Err(TimingError::InvalidAssumption);
        }
        Ok(Self {
            capsule_binding,
            candidates,
            disclosed_at,
            earliest_adversarial,
            latest_honest,
        })
    }
    /// The link binds roster, role and capsule but does not verify the backend
    /// or establish delay. The caller must establish those premises separately.
    pub fn from_direct_costs(
        link: &XmrDirectRecoveryLink,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        costs: AssumedDirectRecoveryCosts,
    ) -> Result<Self, TimingError> {
        if costs.opening_and_check_secs == 0 {
            return Err(TimingError::InvalidAssumption);
        }
        let work_seconds = costs
            .opening_and_check_secs
            .checked_add(costs.overhead_secs)
            .ok_or(TimingError::Overflow)?;
        Self::from_bound_work(
            link.binding(),
            1,
            disclosed_at,
            minimum_adversarial_delay_secs,
            honest_solver_starts_by,
            work_seconds,
        )
    }

    pub fn from_serial_costs(
        challenge: &RecoveryChallenge,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        costs: AssumedSerialRecoveryCosts,
    ) -> Result<Self, TimingError> {
        if costs.verification_per_candidate_secs == 0 || costs.solve_per_candidate_secs == 0 {
            return Err(TimingError::InvalidAssumption);
        }
        let search_seconds = costs
            .verification_per_candidate_secs
            .checked_add(costs.solve_per_candidate_secs)
            .and_then(|t| t.checked_mul(challenge.delayed_indexes().len() as u64))
            .and_then(|t| t.checked_add(costs.overhead_secs))
            .ok_or(TimingError::Overflow)?;
        Self::from_work(
            challenge,
            disclosed_at,
            minimum_adversarial_delay_secs,
            honest_solver_starts_by,
            search_seconds,
        )
    }

    pub fn from_session_costs(
        challenge: &RecoveryChallenge,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        costs: AssumedSessionRecoveryCosts,
    ) -> Result<Self, TimingError> {
        if costs.public_verification_once_secs == 0 || costs.solve_and_check_per_candidate_secs == 0
        {
            return Err(TimingError::InvalidAssumption);
        }
        let work_seconds = costs
            .solve_and_check_per_candidate_secs
            .checked_mul(challenge.delayed_indexes().len() as u64)
            .and_then(|t| t.checked_add(costs.public_verification_once_secs))
            .and_then(|t| t.checked_add(costs.overhead_secs))
            .ok_or(TimingError::Overflow)?;
        Self::from_work(
            challenge,
            disclosed_at,
            minimum_adversarial_delay_secs,
            honest_solver_starts_by,
            work_seconds,
        )
    }

    pub fn from_prepared_costs(
        challenge: &RecoveryChallenge,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        costs: AssumedPreparedRecoveryCosts,
    ) -> Result<Self, TimingError> {
        if costs.solve_and_check_per_candidate_secs == 0 {
            return Err(TimingError::InvalidAssumption);
        }
        let work_seconds = costs
            .solve_and_check_per_candidate_secs
            .checked_mul(challenge.delayed_indexes().len() as u64)
            .and_then(|t| t.checked_add(costs.overhead_secs))
            .ok_or(TimingError::Overflow)?;
        Self::from_work(
            challenge,
            disclosed_at,
            minimum_adversarial_delay_secs,
            honest_solver_starts_by,
            work_seconds,
        )
    }

    fn from_work(
        challenge: &RecoveryChallenge,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        work_seconds: u64,
    ) -> Result<Self, TimingError> {
        // Count the entire committed delayed set, never benchmark successes.
        let candidates =
            u16::try_from(challenge.delayed_indexes().len()).map_err(|_| TimingError::Overflow)?;
        Self::from_bound_work(
            challenge.binding(),
            candidates,
            disclosed_at,
            minimum_adversarial_delay_secs,
            honest_solver_starts_by,
            work_seconds,
        )
    }

    fn from_bound_work(
        capsule_binding: [u8; 64],
        candidates: u16,
        disclosed_at: Timestamp,
        minimum_adversarial_delay_secs: u64,
        honest_solver_starts_by: Timestamp,
        work_seconds: u64,
    ) -> Result<Self, TimingError> {
        if candidates == 0 || honest_solver_starts_by < disclosed_at {
            return Err(TimingError::InvalidAssumption);
        }
        let earliest_adversarial = disclosed_at
            .0
            .checked_add(minimum_adversarial_delay_secs)
            .ok_or(TimingError::Overflow)?;
        let latest_honest = honest_solver_starts_by
            .0
            .checked_add(work_seconds)
            .ok_or(TimingError::Overflow)?;
        if latest_honest < earliest_adversarial {
            return Err(TimingError::InvalidAssumption);
        }
        Ok(Self {
            capsule_binding,
            disclosed_at,
            earliest_adversarial: Timestamp(earliest_adversarial),
            latest_honest: Timestamp(latest_honest),
            candidates,
        })
    }

    pub fn capsule_binding(&self) -> [u8; 64] {
        self.capsule_binding
    }
    pub fn candidates(&self) -> u16 {
        self.candidates
    }
    pub fn disclosed_at(&self) -> Timestamp {
        self.disclosed_at
    }
    pub fn earliest_adversarial(&self) -> Timestamp {
        self.earliest_adversarial
    }
    pub fn latest_honest(&self) -> Timestamp {
        self.latest_honest
    }

    /// Recheck immediately BEFORE exposing an initial completed claim, even
    /// if its adaptor was prepared earlier. Rejected transaction bytes can
    /// still reveal the adaptor secret to their recipient. This is conditional
    /// arithmetic, not authenticated time, persistence or funding permission.
    /// Do not apply this initiation check to an owed counterpart claim after
    /// the first leg was already paid: that obligation must still be resolved.
    /// Already exposed initial claims likewise require reconciliation rather
    /// than being forgotten when this window closes. The caller must durably
    /// distinguish private preparation from prior externalization.
    pub fn check_initial_claim_release(
        &self,
        now: Timestamp,
        order: InitialClaimOrder,
        delays: AssumedClaimDelays,
    ) -> Result<(), TimingError> {
        if now < self.disclosed_at
            || delays.xmr_resolution_secs == 0
            || delays.dom_resolution_secs == 0
        {
            return Err(TimingError::InvalidAssumption);
        }
        let prefix = match order {
            InitialClaimOrder::XmrFirst => delays.xmr_resolution_secs,
            InitialClaimOrder::DomFirst => delays
                .dom_resolution_secs
                .checked_add(delays.observation_secs)
                .and_then(|cost| cost.checked_add(delays.xmr_resolution_secs))
                .ok_or(TimingError::Overflow)?,
        };
        let resolved = now.0.checked_add(prefix).ok_or(TimingError::Overflow)?;
        if resolved >= self.earliest_adversarial.0 {
            return Err(TimingError::InitiationWindowExhausted);
        }
        Ok(())
    }

    /// Conditional XMR-first direct-pair schedule in one clock domain. The disclosure
    /// instant is retained, never restarted after funding or offer delivery.
    /// The anchor must be authenticated separately and remain an ancestor.
    /// Inclusion bounds resolve a spend or a conflict, not a guaranteed winner.
    pub fn required_dom_refund_height(
        &self,
        anchor: &AssumedDomAnchor,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        offers_ready_by: Timestamp,
        delays: AssumedClaimDelays,
    ) -> Result<BlockHeight, TimingError> {
        self.check_initial_claim_release(offers_ready_by, InitialClaimOrder::XmrFirst, delays)?;
        let last_dom_claim_resolved = self
            .latest_honest
            .0
            .checked_add(delays.xmr_resolution_secs)
            .and_then(|t| t.checked_add(delays.observation_secs))
            .and_then(|t| t.checked_add(delays.dom_resolution_secs))
            .ok_or(TimingError::Overflow)?;
        anchor.refund_height_strictly_after(
            Timestamp(last_dom_claim_resolved),
            network,
            validator_clock_ahead_secs,
        )
    }

    /// DOM-first also needs time to resolve and observe DOM before the XMR
    /// claim can resolve. The entire prefix must precede adversarial recovery.
    pub fn required_dom_refund_height_for_dom_first(
        &self,
        anchor: &AssumedDomAnchor,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        offers_ready_by: Timestamp,
        delays: AssumedClaimDelays,
    ) -> Result<BlockHeight, TimingError> {
        if offers_ready_by < self.disclosed_at {
            return Err(TimingError::InvalidAssumption);
        }
        let xmr_ready_by = offers_ready_by
            .0
            .checked_add(delays.dom_resolution_secs)
            .and_then(|time| time.checked_add(delays.observation_secs))
            .ok_or(TimingError::Overflow)?;
        self.required_dom_refund_height(
            anchor,
            network,
            validator_clock_ahead_secs,
            Timestamp(xmr_ready_by),
            delays,
        )
    }
}

/// Only an assumption record. This constructor does not validate a header,
/// its ancestry, network, proof of work, finality or clock synchronization.
pub struct AssumedDomAnchor {
    height: BlockHeight,
    timestamp: Timestamp,
}

impl AssumedDomAnchor {
    pub fn new(height: BlockHeight, timestamp: Timestamp) -> Self {
        Self { height, timestamp }
    }

    /// Conditional earliest clock time at which a refund-height block could
    /// pass the native timestamp rules. Does not predict block arrival or give
    /// an upper bound. The soft future buffer is NOT accepted consensus time.
    pub fn earliest_refund_time(
        &self,
        refund_height: BlockHeight,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
    ) -> Result<Timestamp, TimingError> {
        let blocks = refund_height
            .0
            .checked_sub(self.height.0)
            .filter(|blocks| *blocks > 0)
            .ok_or(TimingError::HeightAlreadyReached)?;
        let minimum_timestamp = self
            .timestamp
            .0
            .checked_add(blocks)
            .ok_or(TimingError::Overflow)?;
        let allowance = network
            .future_tolerance()
            .checked_add(validator_clock_ahead_secs)
            .ok_or(TimingError::Overflow)?;
        Ok(Timestamp(minimum_timestamp.saturating_sub(allowance)))
    }

    /// Minimum height whose conditional earliest time is STRICTLY after the
    /// supplied deadline. The result inherits every assumption above. It must
    /// not be confused with a guarantee the chain will reach that height soon.
    pub fn refund_height_strictly_after(
        &self,
        deadline: Timestamp,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
    ) -> Result<BlockHeight, TimingError> {
        let minimum_timestamp = deadline
            .0
            .checked_add(network.future_tolerance())
            .and_then(|t| t.checked_add(validator_clock_ahead_secs))
            .and_then(|t| t.checked_add(1))
            .ok_or(TimingError::Overflow)?;
        let blocks = minimum_timestamp.saturating_sub(self.timestamp.0).max(1);
        self.timestamp
            .0
            .checked_add(blocks)
            .ok_or(TimingError::Overflow)?;
        Ok(BlockHeight(
            self.height
                .0
                .checked_add(blocks)
                .ok_or(TimingError::Overflow)?,
        ))
    }
}
