//! Fee limits are checked from canonical RingCT bytes, never a sidecar label.
use crate::{parse_exact, verify_exact_raw_sweep_v10, RawTxError, VerifiedRawSweepV10};
use monero_oxide::{
    ringct::RctType,
    transaction::{Timelock, Transaction},
};

/// Exact sweep bytes or their on-wire economics contradict the selected leg.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SweepFeeErrorV23 {
    /// Canonical parsing, hash or input verification failed.
    #[error("invalid exact sweep transaction")]
    Raw(#[from] RawTxError),
    /// Only unlocked modern CLSAG/Bulletproof+ sweeps are supported here.
    #[error("unsupported bounded sweep profile")]
    Profile,
    /// Fee is absent, exceeds the negotiated cap, or consumes the whole input.
    #[error("sweep fee violates negotiated economics")]
    Fee,
}

/// Public verified fee and input identities. This is not a signing or broadcast
/// permission and does not independently verify output ownership or CLSAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBoundedRawSweepV23 {
    sweep: VerifiedRawSweepV10,
    fee_piconero: u64,
}
impl VerifiedBoundedRawSweepV23 {
    /// Exact-byte verification and raw-derived key images.
    pub const fn sweep(&self) -> &VerifiedRawSweepV10 {
        &self.sweep
    }
    /// Fee read from the exact RingCT base covered by the transaction hash.
    pub const fn fee_piconero(&self) -> u64 {
        self.fee_piconero
    }
}

/// Check the fee against the signed terms before the daemon persists a sweep.
/// The funding amount and fee ceiling must come from the admitted leg, not RPC.
/// Destination/amount correctness remains the trusted sweep signer's duty.
pub fn verify_exact_raw_sweep_bounded_v23(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
    funded_amount_piconero: u64,
    max_fee_piconero: u64,
) -> Result<VerifiedBoundedRawSweepV23, SweepFeeErrorV23> {
    let transaction = parse_exact(raw, expected_tx_hash)?;
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &transaction
    else {
        return Err(SweepFeeErrorV23::Profile);
    };
    if proofs.rct_type() != RctType::ClsagBulletproofPlus
        || prefix.additional_timelock != Timelock::None
    {
        return Err(SweepFeeErrorV23::Profile);
    }
    let fee_piconero = proofs.base.fee;
    require_fee_v23(fee_piconero, funded_amount_piconero, max_fee_piconero)?;
    let sweep = verify_exact_raw_sweep_v10(raw, expected_tx_hash)?;
    Ok(VerifiedBoundedRawSweepV23 {
        sweep,
        fee_piconero,
    })
}

fn require_fee_v23(fee: u64, funded: u64, maximum: u64) -> Result<(), SweepFeeErrorV23> {
    if fee == 0 || maximum == 0 || fee > maximum || fee >= funded {
        return Err(SweepFeeErrorV23::Fee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_cap_is_inclusive_but_fee_cannot_consume_the_principal() {
        assert_eq!(require_fee_v23(10, 11, 10), Ok(()));
        assert_eq!(require_fee_v23(11, 100, 10), Err(SweepFeeErrorV23::Fee));
        assert_eq!(require_fee_v23(10, 10, 10), Err(SweepFeeErrorV23::Fee));
        assert_eq!(require_fee_v23(0, 100, 10), Err(SweepFeeErrorV23::Fee));
        assert_eq!(require_fee_v23(1, 100, 0), Err(SweepFeeErrorV23::Fee));
        assert_eq!(
            require_fee_v23(u64::MAX, u64::MAX, u64::MAX),
            Err(SweepFeeErrorV23::Fee)
        );
    }
}
