//! Canonical cut-and-choose transcript for experiments. Opaque setup, puzzle
//! and range-proof bytes must be independently parsed and verified by a backend.
//! Deriving this challenge is NOT evidence that a capsule is recoverable.

use sha2::{Digest, Sha512};

use crate::recovery::{RecoveryError, RecoveryPlan, RecoveryShare, RecoveryWindow};

#[derive(Clone, Debug)]
pub struct RecoveryChallenge {
    plan_binding: [u8; 64],
    binding: [u8; 64],
    opened: Vec<u16>,
    delayed: Vec<u16>,
}

fn frame(hash: &mut Sha512, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

impl RecoveryChallenge {
    pub fn derive(
        plan: &RecoveryPlan,
        setup: &[u8],
        puzzles: &[Vec<u8>],
        range_proof: &[u8],
    ) -> Result<Self, RecoveryError> {
        let plan_binding = plan.binding()?;
        let n = plan.participants;
        if !(2..=512).contains(&n)
            || !n.is_multiple_of(2)
            || plan.threshold != n / 2 + 1
            || puzzles.len() != usize::from(n)
            || setup.is_empty()
            || setup.len() > 65536
            || range_proof.is_empty()
            || range_proof.len() > 4 * 1024 * 1024
            || puzzles.iter().any(|p| p.is_empty() || p.len() > 65536)
        {
            return Err(RecoveryError::Parameters);
        }
        let mut hash = Sha512::new();
        hash.update(b"DXP1/recovery-challenge/v1");
        hash.update(plan_binding);
        frame(&mut hash, setup);
        hash.update(n.to_le_bytes());
        for (i, puzzle) in puzzles.iter().enumerate() {
            hash.update(((i + 1) as u16).to_le_bytes());
            frame(&mut hash, puzzle);
        }
        frame(&mut hash, range_proof);
        let binding: [u8; 64] = hash.finalize().into();

        // Fisher-Yates with rejection sampling, not a biased modulo mapping or
        // overlapping slices of a finite hash. Security assumes a random oracle.
        let mut indexes = (1..=n).collect::<Vec<_>>();
        let mut counter = 0u64;
        for i in (1..indexes.len()).rev() {
            let bound = (i + 1) as u64;
            let cutoff = u64::MAX - (u64::MAX % bound);
            let choice = loop {
                let mut hash = Sha512::new();
                hash.update(b"DXP1/recovery-challenge/draw/v1");
                hash.update(binding);
                hash.update(counter.to_le_bytes());
                counter = counter.checked_add(1).ok_or(RecoveryError::Parameters)?;
                let digest = hash.finalize();
                let candidate = u64::from_le_bytes(digest[..8].try_into().unwrap());
                if candidate < cutoff {
                    break (candidate % bound) as usize;
                }
            };
            indexes.swap(i, choice);
        }
        let mut delayed = indexes.split_off(usize::from(n / 2));
        indexes.sort_unstable();
        delayed.sort_unstable();
        Ok(Self {
            plan_binding,
            binding,
            opened: indexes,
            delayed,
        })
    }

    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }

    pub fn opened_indexes(&self) -> &[u16] {
        &self.opened
    }

    pub fn delayed_indexes(&self) -> &[u16] {
        &self.delayed
    }

    /// Revalidate a public window before binding it to a signing session.
    /// This establishes transcript consistency, not puzzle validity or delay.
    pub fn validate_window(
        &self,
        plan: &RecoveryPlan,
        window: &RecoveryWindow,
    ) -> Result<(), RecoveryError> {
        if plan.binding()? != self.plan_binding
            || window
                .opened
                .iter()
                .map(|share| share.index)
                .collect::<Vec<_>>()
                != self.opened
            || window.delayed_indexes != self.delayed
        {
            return Err(RecoveryError::Parameters);
        }
        window.binding(plan)?;
        Ok(())
    }

    /// Validates scalar/point consistency and the exact selected index set.
    /// A caller must also check each opened puzzle with its opening nonce.
    pub fn window(
        &self,
        plan: &RecoveryPlan,
        opened: Vec<RecoveryShare>,
    ) -> Result<RecoveryWindow, RecoveryError> {
        let window = RecoveryWindow {
            opened,
            delayed_indexes: self.delayed.clone(),
        };
        self.validate_window(plan, &window)?;
        Ok(window)
    }
}
