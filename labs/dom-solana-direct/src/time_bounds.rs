//! Conditional height-to-time arithmetic relating the DOM refund height to the
//! Solana escrow's `refund_after_unix`. This is NOT chain authentication and
//! NOT an authorization to fund: a target block interval is never a minimum,
//! and the caller must still establish that the anchor remains an ancestor of
//! the accepted chain and bound validator clock error against the deadline's
//! clock.
//!
//! `DomClockNetwork` and `AssumedDomAnchor` are the operator's asset-neutral
//! arithmetic, carried over unchanged; see NOTICE.md. Everything below them is
//! written for the Solana escrow, whose timeout is a wall-clock UNIX second
//! read from the cluster, not a height.
//!
//! The one rule both claim orders express: **the party who must act after
//! seeing the secret needs the later deadline.** Which party that is depends
//! on which leg reveals first, so the inequality flips between the two orders
//! and each order gets its own constructor. Nothing here chooses the order;
//! the route does, and then this module refuses a schedule that contradicts it.

use dom_core::{BlockHeight, Timestamp, MAX_FUTURE_BLOCK_TIME, TESTNET_MAX_FUTURE_BLOCK_TIME};

/// Which leg publishes the secret first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOrderV1 {
    /// SOL -> DOM. The DOM claim is adapted with the secret and reveals it in
    /// the kernel's excess signature; the counterparty then claims the escrow.
    DomFirst,
    /// DOM -> SOL. The escrow claim carries the secret in its instruction
    /// data; the DOM side then adapts its pre-signature with it.
    SolanaFirst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// The schedule leaves the second claimant no time between the reveal and
    /// its own deadline. Refusing here is the whole point of this module.
    SecondClaimWindowExhausted,
    /// The first claimant has no time to act before its own deadline.
    InitiationWindowExhausted,
}

/// Assumed costs, in seconds, of each step of a claim. None of these may be
/// taken from an average or from one successful benchmark: each must bound the
/// slowest admissible run, including process start, parsing, RPC round trips
/// and the confirmation depth the terms demand.
#[derive(Clone, Copy, Debug)]
pub struct AssumedLegDelaysV1 {
    /// Publishing an escrow claim or refund and reaching the finality the
    /// terms require on the Solana cluster.
    pub solana_resolution_secs: u64,
    /// Noticing the counterparty's published transaction on either chain.
    pub observation_secs: u64,
    /// Publishing a DOM claim or refund and reaching its confirmation depth.
    pub dom_resolution_secs: u64,
}

impl AssumedLegDelaysV1 {
    fn validate(&self) -> Result<(), TimingError> {
        if self.solana_resolution_secs == 0
            || self.observation_secs == 0
            || self.dom_resolution_secs == 0
        {
            return Err(TimingError::InvalidAssumption);
        }
        Ok(())
    }

    fn reveal_to_solana_claim(&self) -> Result<u64, TimingError> {
        self.observation_secs
            .checked_add(self.solana_resolution_secs)
            .ok_or(TimingError::Overflow)
    }

    fn reveal_to_dom_claim(&self) -> Result<u64, TimingError> {
        self.observation_secs
            .checked_add(self.dom_resolution_secs)
            .ok_or(TimingError::Overflow)
    }
}

/// Only an assumption record. This constructor does not validate a header, its
/// ancestry, network, proof of work, finality or clock synchronization.
#[derive(Clone, Copy, Debug)]
pub struct AssumedDomAnchor {
    height: BlockHeight,
    timestamp: Timestamp,
}

impl AssumedDomAnchor {
    pub fn new(height: BlockHeight, timestamp: Timestamp) -> Self {
        Self { height, timestamp }
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Conditional earliest clock time at which a block at `refund_height`
    /// could pass the native timestamp rules. Does not predict block arrival
    /// and gives no upper bound. The soft future buffer is NOT accepted
    /// consensus time.
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
    /// supplied deadline. The result inherits every assumption above and must
    /// not be read as a promise that the chain reaches that height soon.
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

/// One leg's two deadlines, checked against each other for a claim order.
///
/// `dom_refund_height` is the DOM kernel's `lock_height`: the earliest height
/// at which the height-locked refund can be admitted. `escrow_refund_after` is
/// the escrow state's `refund_after_unix`: the earliest cluster clock second at
/// which `Refund` is accepted. Both are public and both are frozen before
/// funding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegScheduleV1 {
    pub order: ClaimOrderV1,
    pub dom_refund_height: BlockHeight,
    pub escrow_refund_after: Timestamp,
}

impl LegScheduleV1 {
    /// DOM-first: the escrow deadline must be late enough that the party
    /// claiming the escrow still has observation plus Solana resolution after
    /// the very last moment the DOM claim could have been published.
    ///
    /// Returns the minimum admissible `refund_after_unix` for a chosen DOM
    /// refund height. One second of strictness is added so that equality is
    /// never accepted.
    pub fn escrow_deadline_for_dom_first(
        anchor: &AssumedDomAnchor,
        dom_refund_height: BlockHeight,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        delays: AssumedLegDelaysV1,
    ) -> Result<Timestamp, TimingError> {
        delays.validate()?;
        let last_dom_claim =
            anchor.earliest_refund_time(dom_refund_height, network, validator_clock_ahead_secs)?;
        Ok(Timestamp(
            last_dom_claim
                .0
                .checked_add(delays.reveal_to_solana_claim()?)
                .and_then(|t| t.checked_add(1))
                .ok_or(TimingError::Overflow)?,
        ))
    }

    /// Solana-first: the DOM refund height must be late enough that the party
    /// completing the DOM claim still has observation plus DOM resolution after
    /// the very last moment the escrow claim could have been published.
    pub fn dom_refund_height_for_solana_first(
        anchor: &AssumedDomAnchor,
        escrow_refund_after: Timestamp,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        delays: AssumedLegDelaysV1,
    ) -> Result<BlockHeight, TimingError> {
        delays.validate()?;
        let last_dom_claim = Timestamp(
            escrow_refund_after
                .0
                .checked_add(delays.reveal_to_dom_claim()?)
                .ok_or(TimingError::Overflow)?,
        );
        anchor.refund_height_strictly_after(last_dom_claim, network, validator_clock_ahead_secs)
    }

    /// Re-derive both bounds from the anchor and refuse any schedule that does
    /// not satisfy the order it claims. Constructing a schedule through the two
    /// functions above and then checking it here is deliberate duplication: the
    /// check does not trust the construction, and a schedule that arrived over
    /// the wire never was constructed here at all.
    pub fn verify(
        &self,
        anchor: &AssumedDomAnchor,
        now: Timestamp,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        delays: AssumedLegDelaysV1,
    ) -> Result<(), TimingError> {
        delays.validate()?;
        let dom_deadline = anchor.earliest_refund_time(
            self.dom_refund_height,
            network,
            validator_clock_ahead_secs,
        )?;
        match self.order {
            ClaimOrderV1::DomFirst => {
                // The DOM claimant moves first and must fit before its own
                // deadline.
                let first_claim_done = now
                    .0
                    .checked_add(delays.dom_resolution_secs)
                    .ok_or(TimingError::Overflow)?;
                if first_claim_done >= dom_deadline.0 {
                    return Err(TimingError::InitiationWindowExhausted);
                }
                let latest_escrow_claim = dom_deadline
                    .0
                    .checked_add(delays.reveal_to_solana_claim()?)
                    .ok_or(TimingError::Overflow)?;
                if self.escrow_refund_after.0 <= latest_escrow_claim {
                    return Err(TimingError::SecondClaimWindowExhausted);
                }
            }
            ClaimOrderV1::SolanaFirst => {
                let first_claim_done = now
                    .0
                    .checked_add(delays.solana_resolution_secs)
                    .ok_or(TimingError::Overflow)?;
                if first_claim_done >= self.escrow_refund_after.0 {
                    return Err(TimingError::InitiationWindowExhausted);
                }
                let latest_dom_claim = self
                    .escrow_refund_after
                    .0
                    .checked_add(delays.reveal_to_dom_claim()?)
                    .ok_or(TimingError::Overflow)?;
                if dom_deadline.0 <= latest_dom_claim {
                    return Err(TimingError::SecondClaimWindowExhausted);
                }
            }
        }
        Ok(())
    }
}

/// Which deadline the route fixes first. The other one is derived from it, and
/// the claim order follows from the choice: whichever leg's deadline is chosen
/// first is the leg that claims first, because the derived deadline is always
/// the later one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleAnchorV1 {
    /// SOL -> DOM. Fix the DOM refund height; the escrow deadline follows.
    DomRefundHeight(BlockHeight),
    /// DOM -> SOL. Fix the escrow deadline; the DOM refund height follows.
    EscrowRefundAfter(Timestamp),
}

impl LegScheduleV1 {
    /// Derive the complete schedule from one chosen deadline, then verify it.
    /// A schedule this refuses is never returned, so a caller holding a
    /// `LegScheduleV1` from here holds one that satisfied its own order.
    pub fn plan(
        anchor: &AssumedDomAnchor,
        chosen: ScheduleAnchorV1,
        now: Timestamp,
        network: DomClockNetwork,
        validator_clock_ahead_secs: u64,
        delays: AssumedLegDelaysV1,
    ) -> Result<Self, TimingError> {
        let schedule = match chosen {
            ScheduleAnchorV1::DomRefundHeight(height) => Self {
                order: ClaimOrderV1::DomFirst,
                dom_refund_height: height,
                escrow_refund_after: Self::escrow_deadline_for_dom_first(
                    anchor,
                    height,
                    network,
                    validator_clock_ahead_secs,
                    delays,
                )?,
            },
            ScheduleAnchorV1::EscrowRefundAfter(deadline) => Self {
                order: ClaimOrderV1::SolanaFirst,
                dom_refund_height: Self::dom_refund_height_for_solana_first(
                    anchor,
                    deadline,
                    network,
                    validator_clock_ahead_secs,
                    delays,
                )?,
                escrow_refund_after: deadline,
            },
        };
        schedule.verify(anchor, now, network, validator_clock_ahead_secs, delays)?;
        Ok(schedule)
    }
}

/// A deadline choice expressed relative to the anchor, for callers that fix the
/// schedule before they know the canonical tip. `resolve` turns it into the
/// absolute [`ScheduleAnchorV1`] once the anchor is in hand, so the absolute
/// value is always derived from the real tip and never from a guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelativeDeadlineV1 {
    /// SOL -> DOM: this many blocks past the anchor height.
    DomRefundBlocksAhead(u64),
    /// DOM -> SOL: this many seconds past `now`.
    EscrowRefundSecondsAhead(u64),
}

impl RelativeDeadlineV1 {
    pub fn resolve(
        self,
        anchor: &AssumedDomAnchor,
        now: Timestamp,
    ) -> Result<ScheduleAnchorV1, TimingError> {
        match self {
            Self::DomRefundBlocksAhead(blocks) => {
                if blocks == 0 {
                    return Err(TimingError::InvalidAssumption);
                }
                Ok(ScheduleAnchorV1::DomRefundHeight(BlockHeight(
                    anchor
                        .height()
                        .0
                        .checked_add(blocks)
                        .ok_or(TimingError::Overflow)?,
                )))
            }
            Self::EscrowRefundSecondsAhead(seconds) => {
                if seconds == 0 {
                    return Err(TimingError::InvalidAssumption);
                }
                Ok(ScheduleAnchorV1::EscrowRefundAfter(Timestamp(
                    now.0.checked_add(seconds).ok_or(TimingError::Overflow)?,
                )))
            }
        }
    }
}

impl LegScheduleV1 {
    /// The side of the schedule that was fixed rather than derived. Feeding this
    /// back into [`Self::plan`] with the same anchor must reproduce the same
    /// schedule, which is how a second party checks the first party's arithmetic
    /// without being told the answer.
    pub fn chosen(&self) -> ScheduleAnchorV1 {
        match self.order {
            ClaimOrderV1::DomFirst => ScheduleAnchorV1::DomRefundHeight(self.dom_refund_height),
            ClaimOrderV1::SolanaFirst => {
                ScheduleAnchorV1::EscrowRefundAfter(self.escrow_refund_after)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DELAYS: AssumedLegDelaysV1 = AssumedLegDelaysV1 {
        solana_resolution_secs: 30,
        observation_secs: 20,
        dom_resolution_secs: 40,
    };

    fn anchor() -> AssumedDomAnchor {
        AssumedDomAnchor::new(BlockHeight(100), Timestamp(1_000_000))
    }

    #[test]
    fn dom_first_schedule_built_here_verifies_here() {
        let anchor = anchor();
        let height = BlockHeight(100 + 5_000);
        let deadline = LegScheduleV1::escrow_deadline_for_dom_first(
            &anchor,
            height,
            DomClockNetwork::Regtest,
            5,
            DELAYS,
        )
        .unwrap();
        let schedule = LegScheduleV1 {
            order: ClaimOrderV1::DomFirst,
            dom_refund_height: height,
            escrow_refund_after: deadline,
        };
        schedule
            .verify(
                &anchor,
                Timestamp(1_000_100),
                DomClockNetwork::Regtest,
                5,
                DELAYS,
            )
            .unwrap();
    }

    #[test]
    fn dom_first_refuses_an_escrow_deadline_one_second_too_early() {
        let anchor = anchor();
        let height = BlockHeight(100 + 5_000);
        let deadline = LegScheduleV1::escrow_deadline_for_dom_first(
            &anchor,
            height,
            DomClockNetwork::Regtest,
            5,
            DELAYS,
        )
        .unwrap();
        let schedule = LegScheduleV1 {
            order: ClaimOrderV1::DomFirst,
            dom_refund_height: height,
            escrow_refund_after: Timestamp(deadline.0 - 1),
        };
        assert_eq!(
            schedule.verify(
                &anchor,
                Timestamp(1_000_100),
                DomClockNetwork::Regtest,
                5,
                DELAYS
            ),
            Err(TimingError::SecondClaimWindowExhausted)
        );
    }

    #[test]
    fn solana_first_schedule_built_here_verifies_here() {
        let anchor = anchor();
        let escrow = Timestamp(1_002_000);
        let height = LegScheduleV1::dom_refund_height_for_solana_first(
            &anchor,
            escrow,
            DomClockNetwork::Regtest,
            5,
            DELAYS,
        )
        .unwrap();
        let schedule = LegScheduleV1 {
            order: ClaimOrderV1::SolanaFirst,
            dom_refund_height: height,
            escrow_refund_after: escrow,
        };
        schedule
            .verify(
                &anchor,
                Timestamp(1_000_100),
                DomClockNetwork::Regtest,
                5,
                DELAYS,
            )
            .unwrap();
    }

    #[test]
    fn an_order_swapped_after_the_fact_is_refused() {
        let anchor = anchor();
        let height = BlockHeight(100 + 5_000);
        let deadline = LegScheduleV1::escrow_deadline_for_dom_first(
            &anchor,
            height,
            DomClockNetwork::Regtest,
            5,
            DELAYS,
        )
        .unwrap();
        // The same two deadlines, relabelled as the opposite order: the party
        // who would now act second has no window at all.
        let schedule = LegScheduleV1 {
            order: ClaimOrderV1::SolanaFirst,
            dom_refund_height: height,
            escrow_refund_after: deadline,
        };
        assert_eq!(
            schedule.verify(
                &anchor,
                Timestamp(1_000_100),
                DomClockNetwork::Regtest,
                5,
                DELAYS
            ),
            Err(TimingError::SecondClaimWindowExhausted)
        );
    }

    #[test]
    fn zero_delays_are_never_an_assumption() {
        let anchor = anchor();
        assert_eq!(
            LegScheduleV1::escrow_deadline_for_dom_first(
                &anchor,
                BlockHeight(200),
                DomClockNetwork::Regtest,
                5,
                AssumedLegDelaysV1 {
                    solana_resolution_secs: 0,
                    observation_secs: 1,
                    dom_resolution_secs: 1,
                },
            ),
            Err(TimingError::InvalidAssumption)
        );
    }
}
