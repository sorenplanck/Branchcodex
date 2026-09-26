//! Recovery share verification for DXP1 reserves.
//!
//! This module is the safety layer around a future timed capsule backend. It
//! does not implement a VDF, delay puzzle or network clock. It verifies that
//! any scalar share recovered from such a backend matches its public Feldman
//! commitment, then reconstructs the reserve key using the actual share
//! indexes that were opened.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Parameters,
    Index,
    Point,
    Share,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
pub struct RecoveryShare {
    pub index: u16,
    pub scalar: Scalar,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
pub struct RecoveryPlan {
    pub domain: [u8; 32],
    pub threshold: u16,
    pub participants: u16,
    pub commitments: Vec<EdwardsPoint>,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
pub struct RecoveryWindow {
    pub opened: Vec<RecoveryShare>,
    pub delayed_indexes: Vec<u16>,
}

fn point_is_safe(point: &EdwardsPoint) -> bool {
    point.is_torsion_free()
}

fn index_scalar(index: u16) -> Scalar {
    Scalar::from(index as u64)
}

fn polynomial_point(commitments: &[EdwardsPoint], x: Scalar) -> EdwardsPoint {
    commitments
        .iter()
        .rev()
        .fold(EdwardsPoint::identity(), |acc, point| acc * x + point)
}

fn polynomial_scalar(coefficients: &[Zeroizing<Scalar>], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, coeff| acc * x + **coeff)
}

fn lagrange_at_zero(index: usize, indexes: &[u16]) -> Scalar {
    let xi = index_scalar(indexes[index]);
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for (j, xj) in indexes.iter().enumerate() {
        if j == index {
            continue;
        }
        let xj = index_scalar(*xj);
        numerator *= -xj;
        denominator *= xi - xj;
    }
    numerator * denominator.invert()
}

impl RecoveryPlan {
    pub fn from_commitments(
        domain: [u8; 32],
        threshold: u16,
        participants: u16,
        commitments: Vec<EdwardsPoint>,
    ) -> Result<Self, RecoveryError> {
        let plan = Self {
            domain,
            threshold,
            participants,
            commitments,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Centralized lab helper. Production setup must replace this with an
    /// authenticated distributed generation flow before any reserve is funded.
    pub fn from_secret(
        domain: [u8; 32],
        secret: &Zeroizing<Scalar>,
        threshold: u16,
        participants: u16,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Vec<RecoveryShare>), RecoveryError> {
        if **secret == Scalar::ZERO {
            return Err(RecoveryError::Parameters);
        }
        if threshold == 0 || participants < threshold {
            return Err(RecoveryError::Parameters);
        }

        let mut coefficients = Vec::with_capacity(threshold as usize);
        coefficients.push(Zeroizing::new(**secret));
        for _ in 1..threshold {
            coefficients.push(Zeroizing::new(Scalar::random(rng)));
        }

        let commitments = coefficients
            .iter()
            .map(|coefficient| **coefficient * G)
            .collect::<Vec<_>>();
        let plan = Self::from_commitments(domain, threshold, participants, commitments)?;
        let shares = (1..=participants)
            .map(|index| RecoveryShare {
                index,
                scalar: polynomial_scalar(&coefficients, index_scalar(index)),
            })
            .collect();
        Ok((plan, shares))
    }

    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.domain == [0; 32]
            || self.threshold == 0
            || self.participants < self.threshold
            || self.commitments.len() != self.threshold as usize
        {
            return Err(RecoveryError::Parameters);
        }
        if self.commitments[0].is_identity()
            || self
                .commitments
                .iter()
                .any(|commitment| !point_is_safe(commitment))
        {
            return Err(RecoveryError::Point);
        }
        Ok(())
    }

    pub fn public_key(&self) -> Result<EdwardsPoint, RecoveryError> {
        self.validate()?;
        Ok(self.commitments[0])
    }

    pub fn binding(&self) -> Result<[u8; 64], RecoveryError> {
        self.validate()?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/recovery-plan/v1");
        hash.update(self.domain);
        hash.update(self.threshold.to_le_bytes());
        hash.update(self.participants.to_le_bytes());
        for commitment in &self.commitments {
            hash.update(commitment.compress().as_bytes());
        }
        Ok(hash.finalize().into())
    }

    pub fn share_point(&self, index: u16) -> Result<EdwardsPoint, RecoveryError> {
        self.validate()?;
        if index == 0 || index > self.participants {
            return Err(RecoveryError::Index);
        }
        Ok(polynomial_point(&self.commitments, index_scalar(index)))
    }

    pub fn verify_share(&self, share: &RecoveryShare) -> Result<(), RecoveryError> {
        let expected = self.share_point(share.index)?;
        if share.scalar * G != expected {
            return Err(RecoveryError::Share);
        }
        Ok(())
    }

    pub fn recover(&self, shares: &[RecoveryShare]) -> Result<Zeroizing<Scalar>, RecoveryError> {
        self.validate()?;
        if shares.len() != self.threshold as usize {
            return Err(RecoveryError::Parameters);
        }

        let mut indexes = Vec::with_capacity(shares.len());
        for share in shares {
            if share.index == 0 || share.index > self.participants || indexes.contains(&share.index)
            {
                return Err(RecoveryError::Index);
            }
            self.verify_share(share)?;
            indexes.push(share.index);
        }

        let secret = shares
            .iter()
            .enumerate()
            .fold(Scalar::ZERO, |acc, (i, share)| {
                acc + share.scalar * lagrange_at_zero(i, &indexes)
            });
        if secret * G != self.public_key()? {
            return Err(RecoveryError::Recovery);
        }
        Ok(Zeroizing::new(secret))
    }
}

impl RecoveryWindow {
    pub fn new(
        plan: &RecoveryPlan,
        opened: Vec<RecoveryShare>,
        delayed_indexes: Vec<u16>,
    ) -> Result<Self, RecoveryError> {
        plan.validate()?;
        if opened.len() + 1 != plan.threshold as usize || delayed_indexes.is_empty() {
            return Err(RecoveryError::Parameters);
        }

        let mut seen = Vec::with_capacity(opened.len() + delayed_indexes.len());
        for share in &opened {
            if share.index == 0 || share.index > plan.participants || seen.contains(&share.index) {
                return Err(RecoveryError::Index);
            }
            plan.verify_share(share)?;
            seen.push(share.index);
        }
        for index in &delayed_indexes {
            if *index == 0 || *index > plan.participants || seen.contains(index) {
                return Err(RecoveryError::Index);
            }
            seen.push(*index);
        }

        Ok(Self {
            opened,
            delayed_indexes,
        })
    }

    pub fn binding(&self, plan: &RecoveryPlan) -> Result<[u8; 64], RecoveryError> {
        Self::new(plan, self.opened.clone(), self.delayed_indexes.clone())?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/recovery-window/v1");
        hash.update(plan.binding()?);
        for share in &self.opened {
            hash.update(share.index.to_le_bytes());
            hash.update(share.scalar.to_bytes());
        }
        for index in &self.delayed_indexes {
            hash.update(index.to_le_bytes());
        }
        Ok(hash.finalize().into())
    }

    pub fn recover_with_delayed_share(
        &self,
        plan: &RecoveryPlan,
        delayed_share: RecoveryShare,
    ) -> Result<Zeroizing<Scalar>, RecoveryError> {
        // Fields remain public for laboratory inspection; revalidate at the
        // consumption boundary so mutation cannot bypass window constraints.
        Self::new(plan, self.opened.clone(), self.delayed_indexes.clone())?;
        if !self.delayed_indexes.contains(&delayed_share.index) {
            return Err(RecoveryError::Index);
        }
        let mut shares = self.opened.clone();
        shares.push(delayed_share);
        plan.recover(&shares)
    }
}
