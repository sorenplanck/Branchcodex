//! Bind an Ed25519 timed-recovery experiment to one exact DOM reserve share.
//! A cross-curve proof permits reuse of Feldman reconstruction without treating
//! reduced scalars from different groups as interchangeable. This layer does
//! NOT verify RSA setup, puzzle range proofs, a minimum delay or chain timing.

use crate::{
    dom_reserve::{ReserveShare, VerifiedReserve},
    recovery::{RecoveryPlan, RecoveryShare, RecoveryWindow},
    recovery_challenge::RecoveryChallenge,
};
use curve25519_dalek::scalar::Scalar;
use dom_core::DomError;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use xmr_dleq_sigma::{prove, verify, CrossCurveProofBytes, CrossCurveSecret252};
use zeroize::{Zeroize, Zeroizing};

fn invalid(reason: &str) -> DomError {
    DomError::Invalid(reason.into())
}

/// Dealer material for its OWN share only. No aggregate reserve key is known.
/// The puzzle shares are secrets until selectively opened by the challenge.
pub struct DomRecoveryMaterial {
    pub plan: RecoveryPlan,
    pub cross_curve: CrossCurveProofBytes,
    pub puzzle_shares: Vec<RecoveryShare>,
}

impl Drop for DomRecoveryMaterial {
    fn drop(&mut self) {
        self.puzzle_shares.zeroize();
    }
}

impl DomRecoveryMaterial {
    pub fn create(
        share: &ReserveShare,
        reserve: &VerifiedReserve,
        index: u8,
        participants: u16,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, DomError> {
        if !(2..=512).contains(&participants)
            || !participants.is_multiple_of(2)
            || share.public_key().to_compressed_bytes()
                != reserve.share_key(index)?.to_compressed_bytes()
        {
            return Err(invalid("invalid DOM recovery dealer/context"));
        }
        let common = share.common_secret()?;
        let secret = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(
                common.xmr_share_little_endian(),
            ))
            .ok_or_else(|| invalid("noncanonical recovery scalar"))?,
        );
        let (plan, puzzle_shares) = RecoveryPlan::from_secret(
            reserve.recovery_domain(index)?,
            &secret,
            participants / 2 + 1,
            participants,
            rng,
        )
        .map_err(|_| invalid("DOM recovery sharing failed"))?;
        let cross_curve =
            prove(&common, rng).map_err(|_| invalid("DOM recovery cross-curve proof failed"))?;
        Ok(Self {
            plan,
            cross_curve,
            puzzle_shares,
        })
    }
}

/// Validated point/window/transcript linkage only; not permission to fund.
/// Callers must independently verify the actual puzzle backend before binding.
pub struct DomRecoveryLink {
    reserve_binding: [u8; 32],
    index: u8,
    plan: RecoveryPlan,
    window: RecoveryWindow,
    binding: [u8; 64],
    secp: [u8; 33],
    ed: [u8; 32],
}

impl DomRecoveryLink {
    pub fn new(
        reserve: &VerifiedReserve,
        index: u8,
        plan: &RecoveryPlan,
        cross_curve: &CrossCurveProofBytes,
        challenge: &RecoveryChallenge,
        window: &RecoveryWindow,
    ) -> Result<Self, DomError> {
        if plan.domain != reserve.recovery_domain(index)?
            || cross_curve.claim.secp_compressed != reserve.share_key(index)?.to_compressed_bytes()
            || cross_curve.claim.ed_compressed
                != plan
                    .public_key()
                    .map_err(|_| invalid("invalid recovery public key"))?
                    .compress()
                    .to_bytes()
        {
            return Err(invalid("DOM reserve and recovery share differ"));
        }
        verify(cross_curve).map_err(|_| invalid("invalid DOM recovery cross-curve proof"))?;
        challenge
            .validate_window(plan, window)
            .map_err(|_| invalid("invalid DOM recovery capsule window"))?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/DOM-reserve/recovery-link/v1");
        hash.update(reserve.binding());
        hash.update([index]);
        hash.update(
            plan.binding()
                .map_err(|_| invalid("invalid recovery plan"))?,
        );
        hash.update(challenge.binding());
        hash.update(
            window
                .binding(plan)
                .map_err(|_| invalid("invalid recovery window"))?,
        );
        hash.update(cross_curve.version.to_le_bytes());
        hash.update(cross_curve.claim.to_canonical_bytes());
        hash.update((cross_curve.proof.len() as u64).to_le_bytes());
        hash.update(&cross_curve.proof);
        Ok(Self {
            reserve_binding: reserve.binding(),
            index,
            plan: plan.clone(),
            window: window.clone(),
            binding: hash.finalize().into(),
            secp: cross_curve.claim.secp_compressed,
            ed: cross_curve.claim.ed_compressed,
        })
    }

    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }

    /// Recover only from an allowed, Feldman-verified delayed opening. There is
    /// no sleep, clock claim or inference that the backend enforced a deadline.
    pub fn recover_after_opening(
        &self,
        reserve: &VerifiedReserve,
        index: u8,
        delayed: RecoveryShare,
    ) -> Result<ReserveShare, DomError> {
        if index != self.index || reserve.binding() != self.reserve_binding {
            return Err(invalid("different recovery reservation"));
        }
        let secret = self
            .window
            .recover_with_delayed_share(&self.plan, delayed)
            .map_err(|_| invalid("DOM delayed share reconstruction failed"))?;
        let common = CrossCurveSecret252::from_little_endian(secret.to_bytes())
            .map_err(|_| invalid("recovered scalar outside common domain"))?;
        let claim = common
            .public_claim()
            .map_err(|_| invalid("invalid recovered key"))?;
        if claim.secp_compressed != self.secp || claim.ed_compressed != self.ed {
            return Err(invalid("recovered DOM key does not match capsule"));
        }
        ReserveShare::from_common_secret(&common)
    }
}
