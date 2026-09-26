//! Experimental shared reserve formation. Only public points are aggregated.
//! Reuses the pinned collaborative range prover; final proofs must pass the
//! unchanged native verifier. No funding, recovery, transport authentication,
//! crash persistence or claim of malicious-secure setup is provided here.

use dom_core::DomError;
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    range_proof_verify, schnorr_sign, schnorr_verify, PublicKey, SchnorrSignature, SecretKey,
    MAX_PROVABLE_VALUE,
};
use dom_scriptless_bulletproof::{
    bulletproof_mpc_aggregate_tau_x, bulletproof_mpc_finalize, bulletproof_mpc_round1,
    bulletproof_mpc_round2, BulletproofMpcFinalizeState, BulletproofMpcRound1State,
};
use dom_scriptless_primitives::{scalar_from_wide_be, scriptless_add_public_points};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

fn invalid(reason: &str) -> DomError {
    DomError::Invalid(reason.into())
}

/// A single party's opening. No API constructs or exports an aggregate opening.
pub struct ReserveShare {
    blind: BlindingFactor,
}

impl ReserveShare {
    /// Reserve shares intended for recovery use the same bounded integer on
    /// both curves. Ordinary generate() remains a full-width DOM-only share.
    pub fn generate_for_recovery(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, DomError> {
        Self::from_common_secret(&xmr_dleq_sigma::CrossCurveSecret252::generate(rng))
    }
    pub(crate) fn from_common_secret(
        secret: &xmr_dleq_sigma::CrossCurveSecret252,
    ) -> Result<Self, DomError> {
        Ok(Self {
            blind: BlindingFactor::from_bytes(secret.dom_secret_big_endian())?,
        })
    }
    pub(crate) fn common_secret(&self) -> Result<xmr_dleq_sigma::CrossCurveSecret252, DomError> {
        let mut bytes = Zeroizing::new(*self.blind.as_bytes());
        bytes.reverse();
        xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(*bytes)
            .map_err(|_| invalid("DOM reserve share outside recovery common domain"))
    }
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, DomError> {
        let mut wide = Zeroizing::new([0; 64]);
        rng.fill_bytes(&mut *wide);
        let bytes = scalar_from_wide_be(&wide).ok_or_else(|| invalid("zero reserve share"))?;
        Ok(Self {
            blind: BlindingFactor::from_bytes(*bytes)?,
        })
    }
    pub fn public_key(&self) -> PublicKey {
        SecretKey::from_bytes(self.blind.as_bytes())
            .expect("validated scalar")
            .public_key()
    }
    pub fn prove(&self, plan: &ReserveIntent, index: u8) -> Result<SchnorrSignature, DomError> {
        plan.check_share(index, &self.public_key())?;
        schnorr_sign(
            &SecretKey::from_bytes(self.blind.as_bytes())?,
            &plan.possession_message(index),
            &plan.chain,
        )
    }

    /// Local excess for a funding output: r_i minus only this party's debits.
    pub fn funding_key(
        &self,
        debit: Option<&BlindingFactor>,
        offset: Option<&BlindingFactor>,
    ) -> Result<SecretKey, DomError> {
        let mut excess = self.blind.clone();
        if let Some(debit) = debit {
            excess = excess.sub_nonzero(debit)?;
        }
        if let Some(offset) = offset {
            excess = excess.sub_nonzero(offset)?;
        }
        SecretKey::from_bytes(excess.as_bytes())
    }

    /// Local input contribution mask-r_i. The other party supplies its own
    /// contribution; callers never receive the aggregate reserve opening.
    pub fn debit_key(&self, mask: &BlindingFactor) -> Result<SecretKey, DomError> {
        SecretKey::from_bytes(mask.sub_nonzero(&self.blind)?.as_bytes())
    }

    /// `common_seed` must be agreed over a confidential authenticated channel;
    /// this experiment supplies it locally. Private nonces are independent.
    pub fn begin_proof(
        &self,
        plan: VerifiedReserve,
        index: u8,
        common_seed: &Zeroizing<[u8; 32]>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(ReserveRoundOne, ReserveCommitment), DomError> {
        plan.intent.check_share(index, &self.public_key())?;
        let mut hash = Sha512::new();
        hash.update(b"DXP1/DOM-reserve/common-nonce/v1");
        hash.update(plan.binding);
        hash.update(common_seed.as_slice());
        let wide = Zeroizing::new(hash.finalize().into());
        let common = scalar_from_wide_be(&wide).ok_or_else(|| invalid("zero common nonce"))?;
        let mut random = Zeroizing::new([0; 64]);
        rng.fill_bytes(&mut *random);
        let mut hash = Sha512::new();
        hash.update(b"DXP1/DOM-reserve/private-nonce/v1");
        hash.update(plan.binding);
        hash.update([index]);
        hash.update(random.as_slice());
        hash.update(self.blind.as_bytes());
        let private = scalar_from_wide_be(&Zeroizing::new(hash.finalize().into()))
            .ok_or_else(|| invalid("zero private nonce"))?;
        // Native plain outputs use empty extra_commit. Session/capsule bindings
        // belong to the protocol transcript, not a changed consensus verifier.
        let (backend, output) = bulletproof_mpc_round1(
            plan.intent.value,
            self.blind.clone(),
            *plan.intent.commitment.as_bytes(),
            common,
            private,
            &[],
        )?;
        let message = ReserveCommitment {
            plan: plan.binding,
            index,
            t_one: *output.t_one(),
            t_two: *output.t_two(),
        };
        Ok((
            ReserveRoundOne {
                plan,
                index,
                own: message.clone(),
                backend,
            },
            message,
        ))
    }
}

#[derive(Clone)]
pub struct ReserveIntent {
    value: u64,
    chain: [u8; 32],
    keys: [PublicKey; 2],
    commitment: Commitment,
    binding: [u8; 32],
}

impl ReserveIntent {
    pub fn new(
        value: u64,
        chain: [u8; 32],
        session: [u8; 32],
        terms: [u8; 32],
        keys: [PublicKey; 2],
    ) -> Result<Self, DomError> {
        if value == 0
            || value > MAX_PROVABLE_VALUE
            || chain == [0; 32]
            || session == [0; 32]
            || terms == [0; 32]
            || keys[0].to_compressed_bytes() == keys[1].to_compressed_bytes()
        {
            return Err(invalid("invalid reserve context"));
        }
        let aggregate = scriptless_add_public_points(&keys)?;
        // v*H = commit(v,1) - commit(0,1), using only native public arithmetic.
        let mut one = [0; 32];
        one[31] = 1;
        let unit = BlindingFactor::from_bytes(one)?;
        let value_point = Commitment::commit(value, &unit).sub(&Commitment::commit(0, &unit))?;
        let commitment = value_point.add(&Commitment::from_compressed_bytes(
            &aggregate.to_compressed_bytes(),
        )?)?;
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-reserve/intent/v1");
        hash.update(value.to_le_bytes());
        hash.update(chain);
        hash.update(session);
        hash.update(terms);
        for key in &keys {
            hash.update(key.to_compressed_bytes());
        }
        hash.update(commitment.as_bytes());
        Ok(Self {
            value,
            chain,
            keys,
            commitment,
            binding: hash.finalize().into(),
        })
    }
    fn check_share(&self, index: u8, key: &PublicKey) -> Result<(), DomError> {
        if index > 1
            || self.keys[usize::from(index)].to_compressed_bytes() != key.to_compressed_bytes()
        {
            return Err(invalid("reserve share mismatch"));
        }
        Ok(())
    }
    fn possession_message(&self, index: u8) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-reserve/possession/v1");
        hash.update(self.binding);
        hash.update([index]);
        hash.finalize().into()
    }
    pub fn authorize(self, proofs: [SchnorrSignature; 2]) -> Result<VerifiedReserve, DomError> {
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-reserve/authorized/v1");
        hash.update(self.binding);
        for (i, proof) in proofs.iter().enumerate() {
            if !schnorr_verify(
                proof,
                &self.keys[i],
                &self.chain,
                &self.possession_message(i as u8),
            )? {
                return Err(invalid("invalid reserve share possession proof"));
            }
            hash.update(proof.to_bytes());
        }
        Ok(VerifiedReserve {
            intent: self,
            binding: hash.finalize().into(),
        })
    }
}

/// Possession-verified public plan. A range proof is still required before funding.
#[derive(Clone)]
pub struct VerifiedReserve {
    intent: ReserveIntent,
    binding: [u8; 32],
}
impl VerifiedReserve {
    pub fn value(&self) -> u64 {
        self.intent.value
    }
    pub fn chain(&self) -> [u8; 32] {
        self.intent.chain
    }
    pub fn share_key(&self, index: u8) -> Result<&PublicKey, DomError> {
        self.intent
            .keys
            .get(usize::from(index))
            .ok_or_else(|| invalid("reserve index"))
    }
    /// Domain includes the exact approved reserve and the share's role.
    pub fn recovery_domain(&self, index: u8) -> Result<[u8; 32], DomError> {
        self.share_key(index)?;
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-reserve/recovery-domain/v1");
        hash.update(self.binding);
        hash.update([index]);
        Ok(hash.finalize().into())
    }
    pub fn commitment(&self) -> &Commitment {
        &self.intent.commitment
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

#[derive(Clone)]
pub struct ReserveCommitment {
    pub plan: [u8; 32],
    pub index: u8,
    pub t_one: [u8; 33],
    pub t_two: [u8; 33],
}
pub struct ReserveResponse {
    pub round: [u8; 32],
    pub index: u8,
    pub scalar: Zeroizing<[u8; 32]>,
}

/// One use even on error; no clone, serialization or secret state export.
pub struct ReserveRoundOne {
    plan: VerifiedReserve,
    index: u8,
    own: ReserveCommitment,
    backend: BulletproofMpcRound1State,
}
impl ReserveRoundOne {
    pub fn respond(
        self,
        peer: &ReserveCommitment,
    ) -> Result<(ReserveFinalizer, ReserveResponse), DomError> {
        if peer.index != 1 - self.index || peer.plan != self.plan.binding {
            return Err(invalid("different reserve proof context"));
        }
        let messages = if self.index == 0 {
            [self.own, peer.clone()]
        } else {
            [peer.clone(), self.own]
        };
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-reserve/proof-round/v1");
        hash.update(self.plan.binding);
        for m in &messages {
            hash.update([m.index]);
            hash.update(m.t_one);
            hash.update(m.t_two);
        }
        if messages[0].t_one == messages[1].t_one || messages[0].t_two == messages[1].t_two {
            return Err(invalid("reflected reserve nonce"));
        }
        let round = hash.finalize().into();
        let t_one = scriptless_add_public_points(&[
            PublicKey::from_compressed_bytes(&messages[0].t_one)?,
            PublicKey::from_compressed_bytes(&messages[1].t_one)?,
        ])?;
        let t_two = scriptless_add_public_points(&[
            PublicKey::from_compressed_bytes(&messages[0].t_two)?,
            PublicKey::from_compressed_bytes(&messages[1].t_two)?,
        ])?;
        let (backend, scalar) = bulletproof_mpc_round2(
            self.backend,
            &t_one.to_compressed_bytes(),
            &t_two.to_compressed_bytes(),
        )?;
        let response = ReserveResponse {
            round,
            index: self.index,
            scalar: scalar.clone(),
        };
        Ok((
            ReserveFinalizer {
                plan: self.plan,
                index: self.index,
                round,
                scalar,
                backend,
            },
            response,
        ))
    }
}

pub struct ReserveFinalizer {
    plan: VerifiedReserve,
    index: u8,
    round: [u8; 32],
    scalar: Zeroizing<[u8; 32]>,
    backend: BulletproofMpcFinalizeState,
}
impl ReserveFinalizer {
    pub fn complete(self, peer: ReserveResponse) -> Result<Vec<u8>, DomError> {
        if peer.index != 1 - self.index || peer.round != self.round {
            return Err(invalid("different reserve proof response"));
        }
        let sum = bulletproof_mpc_aggregate_tau_x(vec![self.scalar, peer.scalar])?;
        let proof = bulletproof_mpc_finalize(self.backend, sum)?;
        if !range_proof_verify(self.plan.commitment().as_bytes(), &proof)? {
            return Err(invalid("native reserve proof rejected"));
        }
        Ok(proof)
    }
}
