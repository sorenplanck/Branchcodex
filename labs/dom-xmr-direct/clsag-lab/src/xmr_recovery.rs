//! Recover one original additive XMR spend share, never the aggregate key.
//! This binds public keys and a capsule window. It does not authenticate the
//! roster, verify a puzzle backend, authorize funding, or prove a minimum delay.

use std::collections::HashMap;

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    recovery::{RecoveryError, RecoveryPlan, RecoveryShare, RecoveryWindow},
    recovery_challenge::RecoveryChallenge,
    valid_point, G,
};

/// Ordered public roster for an already agreed, one-use reservation. The caller
/// must bind `reservation` to its network, address, route and authenticated
/// session. Public point consistency is not proof of possession or identity.
#[derive(Clone)]
pub struct XmrRecoveryRoster {
    keys: [EdwardsPoint; 2],
    binding: [u8; 32],
}

impl XmrRecoveryRoster {
    pub fn new(reservation: [u8; 32], keys: [EdwardsPoint; 2]) -> Result<Self, RecoveryError> {
        if reservation == [0; 32]
            || keys.iter().any(|key| !valid_point(key))
            || keys[0] == keys[1]
            || !valid_point(&(keys[0] + keys[1]))
        {
            return Err(RecoveryError::Parameters);
        }
        let mut hash = Sha256::new();
        hash.update(b"DXP1/XMR-share/recovery-roster/v1");
        hash.update(reservation);
        for key in keys {
            hash.update(key.compress().as_bytes());
        }
        Ok(Self {
            keys,
            binding: hash.finalize().into(),
        })
    }

    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub fn spend_key(&self) -> EdwardsPoint {
        self.keys[0] + self.keys[1]
    }

    pub fn share_key(&self, participant: Participant) -> Result<EdwardsPoint, RecoveryError> {
        self.keys
            .get(usize::from(u16::from(participant)) - 1)
            .copied()
            .ok_or(RecoveryError::Index)
    }

    pub fn recovery_domain(&self, participant: Participant) -> Result<[u8; 32], RecoveryError> {
        self.share_key(participant)?;
        let mut hash = Sha256::new();
        hash.update(b"DXP1/XMR-share/recovery-domain/v1");
        hash.update(self.binding);
        hash.update(u16::from(participant).to_le_bytes());
        Ok(hash.finalize().into())
    }

    fn check_original_keys(&self, keys: &ThresholdKeys<Ed25519>) -> Result<(), RecoveryError> {
        if keys.params().t() != 2
            || keys.params().n() != 2
            || keys.current_scalar() != Scalar::ONE
            || keys.current_offset() != Scalar::ZERO
            || !matches!(keys.interpolation(), Interpolation::Constant(factors)
                if factors.as_slice() == [Scalar::ONE, Scalar::ONE])
            || **keys.original_secret_share() * G != self.share_key(keys.params().i())?
            || keys.group_key().0 != self.spend_key()
        {
            return Err(RecoveryError::Parameters);
        }
        for i in 1..=2 {
            let id = Participant::new(i).ok_or(RecoveryError::Index)?;
            if keys.original_verification_share(id).0 != self.share_key(id)? {
                return Err(RecoveryError::Point);
            }
        }
        Ok(())
    }

    fn restore(
        &self,
        participant: Participant,
        secret: Zeroizing<Scalar>,
    ) -> Result<ThresholdKeys<Ed25519>, RecoveryError> {
        if *secret * G != self.share_key(participant)? {
            return Err(RecoveryError::Share);
        }
        let roster = HashMap::from([
            (Participant::new(1).unwrap(), GroupPoint(self.keys[0])),
            (Participant::new(2).unwrap(), GroupPoint(self.keys[1])),
        ]);
        let keys = ThresholdKeys::new(
            ThresholdParams::new(2, 2, participant).map_err(|_| RecoveryError::Parameters)?,
            Interpolation::Constant(vec![Scalar::ONE; 2]),
            secret,
            roster,
        )
        .map_err(|_| RecoveryError::Recovery)?;
        self.check_original_keys(&keys)?;
        Ok(keys)
    }
}

pub struct XmrRecoveryMaterial {
    pub plan: RecoveryPlan,
    pub puzzle_shares: Vec<RecoveryShare>,
}

/// One original peer share for the experimental direct relation backend.
/// Only the producer receives this material; a public verifier receives the
/// context/key and the proof. This type provides no backend or timing proof.
pub struct XmrDirectRecoveryMaterial {
    pub context: [u8; 32],
    pub public_key: EdwardsPoint,
    pub secret: Zeroizing<Scalar>,
}

impl XmrDirectRecoveryMaterial {
    pub fn create(
        keys: &ThresholdKeys<Ed25519>,
        roster: &XmrRecoveryRoster,
    ) -> Result<Self, RecoveryError> {
        roster.check_original_keys(keys)?;
        Ok(Self {
            context: roster.recovery_domain(keys.params().i())?,
            public_key: roster.share_key(keys.params().i())?,
            secret: keys.original_secret_share().clone(),
        })
    }
}

/// Exact public capsule/roster/role link for the experimental direct backend.
/// The caller must independently verify the capsule and timing BEFORE funding.
/// Hashing caller-supplied bytes is neither backend validation nor admission.
pub struct XmrDirectRecoveryLink {
    roster: XmrRecoveryRoster,
    participant: Participant,
    capsule_binding: [u8; 32],
    binding: [u8; 64],
}

impl XmrDirectRecoveryLink {
    pub fn new(
        roster: &XmrRecoveryRoster,
        participant: Participant,
        capsule_context: [u8; 32],
        capsule_public_key: EdwardsPoint,
        capsule_binding: [u8; 32],
    ) -> Result<Self, RecoveryError> {
        if capsule_context != roster.recovery_domain(participant)?
            || capsule_public_key != roster.share_key(participant)?
            || capsule_binding == [0; 32]
        {
            return Err(RecoveryError::Parameters);
        }
        let mut hash = Sha512::new();
        hash.update(b"DXP1/XMR-share/direct-recovery-link/experiment-v0");
        hash.update(roster.binding());
        hash.update(u16::from(participant).to_le_bytes());
        hash.update(capsule_binding);
        Ok(Self {
            roster: roster.clone(),
            participant,
            capsule_binding,
            binding: hash.finalize().into(),
        })
    }

    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }

    pub fn recover_after_opening(
        &self,
        roster: &XmrRecoveryRoster,
        participant: Participant,
        capsule_binding: [u8; 32],
        secret: Zeroizing<Scalar>,
    ) -> Result<ThresholdKeys<Ed25519>, RecoveryError> {
        if roster.binding() != self.roster.binding()
            || participant != self.participant
            || capsule_binding != self.capsule_binding
        {
            return Err(RecoveryError::Parameters);
        }
        self.roster.restore(participant, secret)
    }
}

impl Drop for XmrRecoveryMaterial {
    fn drop(&mut self) {
        self.puzzle_shares.zeroize();
    }
}

impl XmrRecoveryMaterial {
    /// Capsule generation precedes funding. Accept only original additive keys:
    /// the scanned output's stealth offset must be applied AFTER recovery.
    pub fn create(
        keys: &ThresholdKeys<Ed25519>,
        roster: &XmrRecoveryRoster,
        puzzles: u16,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, RecoveryError> {
        roster.check_original_keys(keys)?;
        if !(2..=512).contains(&puzzles) || !puzzles.is_multiple_of(2) {
            return Err(RecoveryError::Parameters);
        }
        let (plan, puzzle_shares) = RecoveryPlan::from_secret(
            roster.recovery_domain(keys.params().i())?,
            keys.original_secret_share(),
            puzzles / 2 + 1,
            puzzles,
            rng,
        )?;
        Ok(Self {
            plan,
            puzzle_shares,
        })
    }
}

/// An immutable link to one peer share in one capsule. Backend verification and
/// deposit policy are external; this type establishes no timing guarantee.
pub struct XmrRecoveryLink {
    roster: XmrRecoveryRoster,
    participant: Participant,
    plan: RecoveryPlan,
    window: RecoveryWindow,
    binding: [u8; 64],
}

impl XmrRecoveryLink {
    pub fn new(
        roster: &XmrRecoveryRoster,
        participant: Participant,
        plan: &RecoveryPlan,
        challenge: &RecoveryChallenge,
        window: &RecoveryWindow,
    ) -> Result<Self, RecoveryError> {
        if plan.domain != roster.recovery_domain(participant)?
            || plan.public_key()? != roster.share_key(participant)?
        {
            return Err(RecoveryError::Parameters);
        }
        challenge.validate_window(plan, window)?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/XMR-share/recovery-link/v1");
        hash.update(roster.binding());
        hash.update(u16::from(participant).to_le_bytes());
        hash.update(plan.binding()?);
        hash.update(challenge.binding());
        hash.update(window.binding(plan)?);
        Ok(Self {
            roster: roster.clone(),
            participant,
            plan: plan.clone(),
            window: window.clone(),
            binding: hash.finalize().into(),
        })
    }

    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }

    pub fn recover_after_opening(
        &self,
        roster: &XmrRecoveryRoster,
        participant: Participant,
        delayed: RecoveryShare,
    ) -> Result<ThresholdKeys<Ed25519>, RecoveryError> {
        if roster.binding() != self.roster.binding() || participant != self.participant {
            return Err(RecoveryError::Parameters);
        }
        let secret = self
            .window
            .recover_with_delayed_share(&self.plan, delayed)?;
        self.roster.restore(participant, secret)
    }
}
