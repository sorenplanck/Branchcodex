//! Offline research only: additive nonce adaptation of a CLSAG signature.
//!
//! This is NOT an atomic swap. The single-signer oracle holds an entire input
//! key; `joint` experiments with a separate two-party signing protocol. Review,
//! recovery, authenticated setup and route binding are still required before
//! using this in DXP1. `native` builds and checks a restricted native claim;
//! chain checks and a full durable recovery executor are outside the library.
//! `release_journal` adds a local durable first-claim exposure gate only. The
//! regtest example starts its own isolated daemon and handles test coins only.
//!
//! CLSAG transcript layout follows monero-oxide at c8be5d3; see NOTICE.md.
//! Final signatures are checked by that independent, unmodified implementation.
//! A passing algebraic experiment does not establish adaptor unforgeability.

#![forbid(unsafe_code)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
    traits::IsIdentity,
};
use monero_clsag::Clsag;
use monero_ed25519::{CompressedPoint, Point, Scalar as MoneroScalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub mod claim_resume;
pub mod capsule_checkpoint;
pub mod operation_checkpoint;
#[cfg(unix)]
pub mod preparation_gate;
#[cfg(unix)]
pub mod counterpart_delivery;
pub mod dom_joint;
pub mod dom_recovery;
pub mod dom_reserve;
pub mod joint;
pub mod native;
pub mod native_dom;
pub mod recovery;
pub mod recovery_challenge;
#[cfg(unix)]
pub mod release_journal;
pub mod time_bounds;
pub mod xmr_recovery;

pub const RING_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Context,
    Point,
    Statement,
    Key,
    PreSignature,
    Witness,
    FinalSignature,
    DifferentSignature,
}

/// Public signing data, already resolved to concrete outputs in this experiment.
/// `message` must eventually be the authentic native transaction signing hash.
/// Supplying a hash alone does not verify destinations, value, fee or maturity.
#[derive(Clone, Zeroize)]
pub struct Context {
    pub ring: [[EdwardsPoint; 2]; RING_SIZE],
    pub real: usize,
    pub image: EdwardsPoint,
    pub pseudo_out: EdwardsPoint,
    pub message: [u8; 32],
    pub route_binding: [u8; 32],
}

fn valid_point(point: &EdwardsPoint) -> bool {
    !point.is_identity() && point.is_torsion_free()
}

impl Context {
    pub fn validate(&self) -> Result<(), Error> {
        if self.real >= RING_SIZE || self.route_binding == [0; 32] {
            return Err(Error::Context);
        }
        // Stricter than legacy consensus: these are fresh experimental reserves.
        if !valid_point(&self.image)
            || !valid_point(&self.pseudo_out)
            || self.ring.iter().flatten().any(|point| !valid_point(point))
        {
            return Err(Error::Point);
        }
        for i in 0..RING_SIZE {
            if self.ring[..i]
                .iter()
                .any(|other| other[0] == self.ring[i][0])
            {
                return Err(Error::Context);
            }
        }
        Ok(())
    }

    fn image_generator(&self) -> EdwardsPoint {
        Point::biased_hash(self.ring[self.real][0].compress().to_bytes()).into()
    }

    fn binding(&self) -> [u8; 64] {
        let mut hash = Sha512::new();
        hash.update(b"DXP1/CLSAG-lab/context/v1");
        hash.update(self.route_binding);
        hash.update(self.message);
        hash.update((self.real as u64).to_le_bytes());
        for pair in &self.ring {
            for point in pair {
                hash.update(point.compress().as_bytes());
            }
        }
        hash.update(self.image.compress().as_bytes());
        hash.update(self.pseudo_out.compress().as_bytes());
        hash.finalize().into()
    }

    pub fn verify_native(&self, signature: &Clsag) -> Result<(), Error> {
        self.validate()?;
        signature
            .verify(
                self.ring
                    .iter()
                    .map(|pair| {
                        pair.map(|point| CompressedPoint::from(point.compress().to_bytes()))
                    })
                    .collect(),
                &CompressedPoint::from(self.image.compress().to_bytes()),
                &CompressedPoint::from(self.pseudo_out.compress().to_bytes()),
                &self.message,
            )
            .map_err(|_| Error::FinalSignature)
    }
}

/// Same-curve CP93 equality proof linking T=tG to U=t*Hp(P_real).
/// This is not the secp256k1/Ed25519 cross-curve proof required by the route.
#[derive(Clone, PartialEq, Debug, Zeroize)]
pub struct Statement {
    pub t_g: EdwardsPoint,
    pub t_h: EdwardsPoint,
    pub r_g: EdwardsPoint,
    pub r_h: EdwardsPoint,
    pub response: Scalar,
}

fn fresh_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Zeroizing<Scalar> {
    loop {
        let scalar = Zeroizing::new(Scalar::random(rng));
        if *scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

fn proof_challenge(context: &Context, statement: &Statement) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"DXP1/CLSAG-lab/equality/v1");
    hash.update(context.binding());
    for point in [
        G,
        context.image_generator(),
        statement.t_g,
        statement.t_h,
        statement.r_g,
        statement.r_h,
    ] {
        hash.update(point.compress().as_bytes());
    }
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

impl Statement {
    pub fn prove(
        context: &Context,
        witness: &Zeroizing<Scalar>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, Error> {
        context.validate()?;
        if **witness == Scalar::ZERO {
            return Err(Error::Witness);
        }
        let h = context.image_generator();
        let nonce = fresh_scalar(rng);
        let mut statement = Self {
            t_g: **witness * G,
            t_h: **witness * h,
            r_g: *nonce * G,
            r_h: *nonce * h,
            response: Scalar::ZERO,
        };
        statement.response = *nonce + proof_challenge(context, &statement) * **witness;
        statement.verify(context)?;
        Ok(statement)
    }

    pub fn verify(&self, context: &Context) -> Result<(), Error> {
        context.validate()?;
        if [self.t_g, self.t_h, self.r_g, self.r_h]
            .iter()
            .any(|point| !valid_point(point))
        {
            return Err(Error::Statement);
        }
        let c = proof_challenge(context, self);
        if self.response * G != self.r_g + c * self.t_g
            || self.response * context.image_generator() != self.r_h + c * self.t_h
        {
            return Err(Error::Statement);
        }
        Ok(())
    }
}

/// Public encrypted signature. It contains no signing nonce or private key.
#[derive(Clone, PartialEq, Debug, Zeroize)]
pub struct PreSignature {
    pub signature: Clsag,
    pub statement: Statement,
}

// This reproduces the native CLSAG transcript, not a new consensus format.
// The external verifier checks the result independently after adaptation.
#[derive(Zeroize)]
struct Transcript {
    mu_p: Scalar,
    mu_c: Scalar,
    round: Vec<u8>,
    d_full: EdwardsPoint,
}

// Public arithmetic only. In joint signing, both parties derive the same
// decoy responses using the upstream transcript RNG. No full spend key is
// required to prepare this ring or its challenge.
fn prepare_ring(
    context: &Context,
    transcript: &Transcript,
    d: CompressedPoint,
    nonce_g: EdwardsPoint,
    nonce_h: EdwardsPoint,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Clsag, Scalar) {
    let responses = (0..RING_SIZE)
        .map(|_| MoneroScalar::random(rng))
        .collect::<Vec<_>>();
    let mut c = transcript.challenge(nonce_g, nonce_h);
    let mut c1 = c;
    let mut index = (context.real + 1) % RING_SIZE;
    while index != context.real {
        if index == 0 {
            c1 = c;
        }
        let (l, r) = transcript.commitments(context, index, responses[index].into(), c);
        c = transcript.challenge(l, r);
        index = (index + 1) % RING_SIZE;
    }
    if context.real == 0 {
        c1 = c;
    }
    (
        Clsag {
            D: d,
            s: responses,
            c1: MoneroScalar::from(c1),
        },
        c,
    )
}

impl Transcript {
    fn new(context: &Context, d: CompressedPoint) -> Result<Self, Error> {
        let d_full = d.decompress().ok_or(Error::Point)?.into().mul_by_cofactor();
        if !valid_point(&d_full) {
            return Err(Error::Point);
        }
        let mut data = [0; 32].to_vec();
        data[..11].copy_from_slice(b"CLSAG_agg_0");
        for pair in &context.ring {
            data.extend_from_slice(pair[0].compress().as_bytes());
        }
        for pair in &context.ring {
            data.extend_from_slice(pair[1].compress().as_bytes());
        }
        data.extend_from_slice(context.image.compress().as_bytes());
        data.extend_from_slice(&d.to_bytes());
        data.extend_from_slice(context.pseudo_out.compress().as_bytes());
        let mu_p = MoneroScalar::hash(&data).into();
        data[10] = b'1';
        let mu_c = MoneroScalar::hash(&data).into();
        data.truncate((2 * RING_SIZE + 1) * 32);
        data[..32].fill(0);
        data[..11].copy_from_slice(b"CLSAG_round");
        data.extend_from_slice(context.pseudo_out.compress().as_bytes());
        data.extend_from_slice(&context.message);
        Ok(Self {
            mu_p,
            mu_c,
            round: data,
            d_full,
        })
    }

    fn challenge(&self, l: EdwardsPoint, r: EdwardsPoint) -> Scalar {
        let mut data = self.round.clone();
        data.extend_from_slice(l.compress().as_bytes());
        data.extend_from_slice(r.compress().as_bytes());
        MoneroScalar::hash(&data).into()
    }

    fn commitments(
        &self,
        context: &Context,
        index: usize,
        s: Scalar,
        c: Scalar,
    ) -> (EdwardsPoint, EdwardsPoint) {
        let [p, commitment] = context.ring[index];
        let h = Point::biased_hash(p.compress().to_bytes()).into();
        (
            s * G + (self.mu_p * c) * p + (self.mu_c * c) * (commitment - context.pseudo_out),
            s * h + (self.mu_p * c) * context.image + (self.mu_c * c) * self.d_full,
        )
    }
}

/// Single-signer algebraic experiment. This is deliberately not exposed as a
/// transaction signer: the entire input private key is held by this caller.
pub fn presign(
    context: &Context,
    statement: Statement,
    input_key: &Zeroizing<Scalar>,
    mask_delta: &Zeroizing<Scalar>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PreSignature, Error> {
    statement.verify(context)?;
    let h = context.image_generator();
    if **input_key * G != context.ring[context.real][0]
        || **input_key * h != context.image
        || **mask_delta * G != context.ring[context.real][1] - context.pseudo_out
    {
        return Err(Error::Key);
    }
    let inv_eight: Scalar = MoneroScalar::INV_EIGHT.into();
    let d = CompressedPoint::from((**mask_delta * h * inv_eight).compress().to_bytes());
    let transcript = Transcript::new(context, d)?;
    let nonce = fresh_scalar(rng);
    let (mut signature, c) = prepare_ring(
        context,
        &transcript,
        d,
        *nonce * G + statement.t_g,
        *nonce * h + statement.t_h,
        rng,
    );
    let joint_key = Zeroizing::new(transcript.mu_p * **input_key + transcript.mu_c * **mask_delta);
    signature.s[context.real] = MoneroScalar::from(*nonce - c * *joint_key);
    let result = PreSignature {
        signature,
        statement,
    };
    result.verify(context)?;
    Ok(result)
}

impl PreSignature {
    pub fn verify(&self, context: &Context) -> Result<(), Error> {
        self.statement.verify(context)?;
        if self.signature.s.len() != RING_SIZE {
            return Err(Error::PreSignature);
        }
        let transcript = Transcript::new(context, self.signature.D)?;
        let mut c: Scalar = self.signature.c1.into();
        for i in 0..RING_SIZE {
            let (mut l, mut r) = transcript.commitments(context, i, self.signature.s[i].into(), c);
            if i == context.real {
                l += self.statement.t_g;
                r += self.statement.t_h;
            }
            c = transcript.challenge(l, r);
        }
        if c != self.signature.c1.into() {
            return Err(Error::PreSignature);
        }
        Ok(())
    }

    pub fn complete(&self, context: &Context, witness: &Zeroizing<Scalar>) -> Result<Clsag, Error> {
        self.verify(context)?;
        if **witness * G != self.statement.t_g
            || **witness * context.image_generator() != self.statement.t_h
        {
            return Err(Error::Witness);
        }
        let mut final_signature = self.signature.clone();
        let response: Scalar = final_signature.s[context.real].into();
        final_signature.s[context.real] = MoneroScalar::from(response + **witness);
        context.verify_native(&final_signature)?;
        Ok(final_signature)
    }

    pub fn extract(
        &self,
        context: &Context,
        final_signature: &Clsag,
    ) -> Result<Zeroizing<Scalar>, Error> {
        self.verify(context)?;
        context.verify_native(final_signature)?;
        if self.signature.D != final_signature.D
            || self.signature.c1 != final_signature.c1
            || self
                .signature
                .s
                .iter()
                .zip(&final_signature.s)
                .enumerate()
                .any(|(i, (before, after))| i != context.real && before != after)
        {
            return Err(Error::DifferentSignature);
        }
        let before: Scalar = self.signature.s[context.real].into();
        let after: Scalar = final_signature.s[context.real].into();
        let witness = Zeroizing::new(after - before);
        if *witness * G != self.statement.t_g
            || *witness * context.image_generator() != self.statement.t_h
        {
            return Err(Error::Witness);
        }
        Ok(witness)
    }
}
