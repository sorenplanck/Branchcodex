//! Experimental 2-of-2 additive DOM kernel signing with two bound nonces.
//! Uses the native DOM challenge, not a standard FROST ciphersuite. Possession
//! proofs do not authenticate identities or prove a fair reserve setup.
//! No persistence/rollback protection: these states are for disposable trials.

use crate::native_dom::{DomClaimOffer, PreparedDomClaim};
use dom_core::DomError;
use dom_crypto::{
    schnorr_challenge, schnorr_sign, schnorr_verify, PartialSig, PublicKey, SchnorrSignature,
    SecretKey,
};
use dom_scriptless_primitives::{
    scalar_from_wide_be, scriptless_add_public_points, scriptless_aggregate_partial_scalars,
    scriptless_bind_public_nonces, scriptless_verify_bound_partial, secret_scalar_mul_add_assign,
    secret_scalar_public_key,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

fn invalid(reason: &str) -> DomError {
    DomError::Invalid(reason.into())
}

/// Both parties must approve the full transaction, route and ordered roster.
#[derive(Clone)]
pub struct DomSigningIntent {
    claim: PreparedDomClaim,
    adaptor: PublicKey,
    keys: [PublicKey; 2],
    binding: [u8; 32],
}

impl DomSigningIntent {
    pub fn new(
        claim: PreparedDomClaim,
        adaptor: PublicKey,
        keys: [PublicKey; 2],
        session: [u8; 32],
        route: [u8; 32],
    ) -> Result<Self, DomError> {
        if session == [0; 32]
            || route == [0; 32]
            || keys[0].to_compressed_bytes() == keys[1].to_compressed_bytes()
            || scriptless_add_public_points(&keys)?.to_compressed_bytes()
                != claim.key().to_compressed_bytes()
        {
            return Err(invalid("invalid DOM signing roster/context"));
        }
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-joint/intent/v1");
        hash.update(claim.binding()?);
        hash.update(adaptor.to_compressed_bytes());
        hash.update(session);
        hash.update(route);
        for key in &keys {
            hash.update(key.to_compressed_bytes());
        }
        Ok(Self {
            claim,
            adaptor,
            keys,
            binding: hash.finalize().into(),
        })
    }

    fn proof_message(&self, signer: u8) -> Result<[u8; 32], DomError> {
        if signer > 1 {
            return Err(invalid("invalid DOM signer index"));
        }
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-joint/possession/v1");
        hash.update(self.binding);
        hash.update([signer]);
        Ok(hash.finalize().into())
    }

    pub fn prove_share(&self, signer: u8, key: &SecretKey) -> Result<SchnorrSignature, DomError> {
        let message = self.proof_message(signer)?;
        if key.public_key().to_compressed_bytes()
            != self.keys[usize::from(signer)].to_compressed_bytes()
        {
            return Err(invalid("DOM signing share mismatch"));
        }
        schnorr_sign(key, &message, self.claim.chain())
    }

    pub fn authorize(self, proofs: [SchnorrSignature; 2]) -> Result<DomSigningPlan, DomError> {
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-joint/authorized/v1");
        hash.update(self.binding);
        for (i, proof) in proofs.iter().enumerate() {
            if !schnorr_verify(
                proof,
                &self.keys[i],
                self.claim.chain(),
                &self.proof_message(i as u8)?,
            )? {
                return Err(invalid("invalid DOM share possession proof"));
            }
            hash.update(proof.to_bytes());
        }
        Ok(DomSigningPlan {
            intent: self,
            binding: hash.finalize().into(),
        })
    }
}

#[derive(Clone)]
pub struct DomSigningPlan {
    intent: DomSigningIntent,
    binding: [u8; 32],
}

/// Public transport containers; every field is checked again when consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomCommitment {
    pub plan: [u8; 32],
    pub signer: u8,
    pub nonces: [[u8; 33]; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomResponse {
    pub round: [u8; 32],
    pub signer: u8,
    pub scalar: [u8; 32],
}

pub struct DomSigner {
    plan: DomSigningPlan,
    signer: u8,
    key: SecretKey,
}

impl DomSigner {
    pub fn new(plan: DomSigningPlan, signer: u8, key: SecretKey) -> Result<Self, DomError> {
        if signer > 1
            || key.public_key().to_compressed_bytes()
                != plan.intent.keys[usize::from(signer)].to_compressed_bytes()
        {
            return Err(invalid("DOM signing share mismatch"));
        }
        Ok(Self { plan, signer, key })
    }

    pub fn preprocess(
        self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(DomRoundOne, DomCommitment), DomError> {
        let mut nonces = Vec::with_capacity(2);
        for slot in 0..2 {
            let mut random = Zeroizing::new([0; 64]);
            rng.fill_bytes(&mut *random);
            let key = Zeroizing::new(self.key.to_be_bytes_raw());
            let mut hash = Sha512::new();
            hash.update(b"DXP1/DOM-joint/nonce/v1");
            hash.update(self.plan.binding);
            hash.update([self.signer, slot]);
            hash.update(random.as_slice());
            hash.update(key.as_slice());
            let wide = Zeroizing::new(hash.finalize().into());
            nonces.push(scalar_from_wide_be(&wide).ok_or_else(|| invalid("zero DOM nonce"))?);
        }
        let nonces: [Zeroizing<[u8; 32]>; 2] =
            nonces.try_into().map_err(|_| invalid("DOM nonce shape"))?;
        let own = DomCommitment {
            plan: self.plan.binding,
            signer: self.signer,
            nonces: [
                secret_scalar_public_key(&nonces[0])?.to_compressed_bytes(),
                secret_scalar_public_key(&nonces[1])?.to_compressed_bytes(),
            ],
        };
        Ok((
            DomRoundOne {
                signer: self,
                nonces,
                own: own.clone(),
            },
            own,
        ))
    }
}

/// Consumed on success AND failure. No Clone, Debug, serialization or nonce export.
/// ```compile_fail
/// use dom_solana_direct_lab::dom_joint::{DomRoundOne, DomCommitment};
/// fn reuse(round: DomRoundOne, peer: &DomCommitment) {
///     let _ = round.sign(peer);
///     let _ = round.sign(peer);
/// }
/// ```
pub struct DomRoundOne {
    signer: DomSigner,
    nonces: [Zeroizing<[u8; 32]>; 2],
    own: DomCommitment,
}

struct PublicRound {
    binding: [u8; 32],
    factors: [PartialSig; 2],
    nonces: [PublicKey; 2],
    aggregate: PublicKey,
    challenge: [u8; 32],
}

impl PublicRound {
    fn new(plan: &DomSigningPlan, messages: &[DomCommitment; 2]) -> Result<Self, DomError> {
        let mut hash = Sha256::new();
        hash.update(b"DXP1/DOM-joint/round/v1");
        hash.update(plan.binding);
        for (i, message) in messages.iter().enumerate() {
            if message.signer != i as u8 || message.plan != plan.binding {
                return Err(invalid("different DOM commitment context"));
            }
            hash.update([message.signer]);
            for bytes in &message.nonces {
                PublicKey::from_compressed_bytes(bytes)?;
                hash.update(bytes);
            }
        }
        // Reject repeated public nonces, including reflection across roles.
        let points: Vec<_> = messages.iter().flat_map(|m| m.nonces).collect();
        for i in 0..points.len() {
            if points[..i].contains(&points[i]) {
                return Err(invalid("duplicate DOM nonce"));
            }
        }
        let binding: [u8; 32] = hash.finalize().into();
        let mut factors = Vec::with_capacity(2);
        let mut nonces = Vec::with_capacity(2);
        for (i, message) in messages.iter().enumerate() {
            let mut hash = Sha512::new();
            hash.update(b"DXP1/DOM-joint/binding-factor/v1");
            hash.update(binding);
            hash.update([i as u8]);
            let wide: [u8; 64] = hash.finalize().into();
            let factor = PartialSig::from_bytes(
                &*scalar_from_wide_be(&wide).ok_or_else(|| invalid("zero DOM binding factor"))?,
            )?;
            nonces.push(scriptless_bind_public_nonces(
                &PublicKey::from_compressed_bytes(&message.nonces[0])?,
                &PublicKey::from_compressed_bytes(&message.nonces[1])?,
                &factor,
            )?);
            factors.push(factor);
        }
        let nonces: [PublicKey; 2] = nonces.try_into().map_err(|_| invalid("DOM nonce shape"))?;
        let factors = factors
            .try_into()
            .map_err(|_| invalid("DOM factor shape"))?;
        let aggregate = scriptless_add_public_points(&[
            nonces[0].clone(),
            nonces[1].clone(),
            plan.intent.adaptor.clone(),
        ])?;
        let challenge = *schnorr_challenge(
            &aggregate.to_compressed_bytes(),
            plan.intent.claim.key(),
            plan.intent.claim.chain(),
            plan.intent.claim.message(),
        )
        .as_bytes();
        Ok(Self {
            binding,
            factors,
            nonces,
            aggregate,
            challenge,
        })
    }
}

impl DomRoundOne {
    pub fn sign(self, peer: &DomCommitment) -> Result<(DomRoundTwo, DomResponse), DomError> {
        let index = usize::from(self.signer.signer);
        let messages = if index == 0 {
            [self.own, peer.clone()]
        } else {
            [peer.clone(), self.own]
        };
        let public = PublicRound::new(&self.signer.plan, &messages)?;
        let [mut scalar, binding_nonce] = self.nonces;
        secret_scalar_mul_add_assign(
            &mut scalar,
            &binding_nonce,
            &public.factors[index].to_bytes(),
        )?;
        let key = Zeroizing::new(self.signer.key.to_be_bytes_raw());
        secret_scalar_mul_add_assign(&mut scalar, &key, &public.challenge)?;
        let partial = PartialSig::from_bytes(&*scalar)?;
        if !scriptless_verify_bound_partial(
            &partial,
            &public.nonces[index],
            &self.signer.plan.intent.keys[index],
            &public.challenge,
        )? {
            return Err(invalid("invalid local DOM signature contribution"));
        }
        let response = DomResponse {
            round: public.binding,
            signer: index as u8,
            scalar: partial.to_bytes(),
        };
        Ok((
            DomRoundTwo {
                plan: self.signer.plan,
                signer: index,
                public,
                partial,
            },
            response,
        ))
    }
}

pub struct DomRoundTwo {
    plan: DomSigningPlan,
    signer: usize,
    public: PublicRound,
    partial: PartialSig,
}

impl DomRoundTwo {
    pub fn complete(self, peer: &DomResponse) -> Result<DomClaimOffer, DomError> {
        let other = 1 - self.signer;
        if usize::from(peer.signer) != other || peer.round != self.public.binding {
            return Err(invalid("different DOM response context"));
        }
        let partial = PartialSig::from_bytes(&peer.scalar)?;
        if !scriptless_verify_bound_partial(
            &partial,
            &self.public.nonces[other],
            &self.plan.intent.keys[other],
            &self.public.challenge,
        )? {
            return Err(invalid("invalid peer DOM signature contribution"));
        }
        let pre = scriptless_aggregate_partial_scalars(&[self.partial, partial])?;
        self.plan.intent.claim.bind_presignature(
            pre,
            self.public.aggregate,
            self.plan.intent.adaptor,
        )
    }
}
