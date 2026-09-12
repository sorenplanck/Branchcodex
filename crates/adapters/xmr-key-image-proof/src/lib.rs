//! Public proof that a Monero output and key image have the same secret key.
//!
//! This is NOT a payout, amount, ownership-role, inclusion, or finality proof.
//! Context fields prevent replay into another request; binding a destination
//! in the transcript does not prove that the transaction pays that destination.
//! The caller must select the output/key image from independently parsed bytes.

#![forbid(unsafe_code)]

mod build_request;
mod local_build_request_v24;
pub use local_build_request_v24::{
    LocalRefundBuildRequestV24, LocalRefundBuildResponseV24, LocalRefundLoadRequestV24,
    LocalRefundReadyScopeV24, LOCAL_REFUND_BUILD_AUTH_DOMAIN_V24,
    LOCAL_REFUND_LOAD_AUTH_DOMAIN_V24,
};
mod request;
pub use build_request::{
    BuildSweepRequestV23, BuildSweepResponseV23, BuiltRingMemberV23, BUILD_PROOF_AUTH_DOMAIN_V23,
};
mod tx_derivation;
mod wire;
pub use request::{
    CachedInputProofRequestV23, CachedInputProofResponseV23, INPUT_PROOF_AUTH_DOMAIN_V23,
};
pub use tx_derivation::{
    prove_tx_key_derivation_v23, verify_tx_key_derivation_v23, TxKeyDerivationProofV23,
};
pub use wire::{InputSpendEnvelopeV23, INPUT_SPEND_ENVELOPE_BYTES_V23};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Hash exact canonical address text for transcript binding only (not payout proof).
pub fn destination_digest_v23(address: &str) -> [u8; 32] {
    use blake2::digest::consts::U32;
    blake2::Blake2b::<U32>::new()
        .chain_update(b"DOM-INTEROP/XMR-INPUT-PROOF-DESTINATION/V23\0")
        .chain_update((address.len() as u64).to_le_bytes())
        .chain_update(address.as_bytes())
        .finalize()
        .into()
}

const DOMAIN: &[u8] = b"DOM-INTEROP/XMR-FUNDING-INPUT-DLEQ/V23\0";

/// Closed action discriminator, domain-separated inside every proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InputSpendActionV23 {
    /// Claim sweep.
    Claim = 1,
    /// Refund sweep.
    Refund = 2,
}
impl InputSpendActionV23 {
    /// Decode the closed wire discriminator; no unknown action fallback.
    pub fn from_wire(value: u8) -> Result<Self, InputSpendProofErrorV23> {
        match value {
            1 => Ok(Self::Claim),
            2 => Ok(Self::Refund),
            _ => Err(InputSpendProofErrorV23::Scope),
        }
    }
}

/// Scope supplied by an authenticated request, not an economic authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSpendContextV23 {
    /// Monero network genesis identifier.
    pub network_genesis: [u8; 32],
    /// Route identifier.
    pub route: [u8; 32],
    /// Settlement session identifier.
    pub session: [u8; 32],
    /// Negotiated settlement terms hash.
    pub terms: [u8; 32],
    /// Consensus funding transaction hash.
    pub funding_tx: [u8; 32],
    /// Output position within the funding transaction, NOT a global ring index.
    pub output_index: u64,
    /// Consensus sweep transaction hash.
    pub sweep_tx: [u8; 32],
    /// Hash of the exact canonical payout address from the request.
    pub destination: [u8; 32],
    /// Negotiated funded amount; this proof does not authenticate its value.
    pub funded_amount: u64,
    /// Fee parsed from the sweep transaction by the verifier.
    pub fee: u64,
    /// Distinct protocol action: 1 Claim, 2 Refund.
    pub action: InputSpendActionV23,
}

impl InputSpendContextV23 {
    /// Fixed-width canonical transcript; no optional fields or implicit network.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InputSpendProofErrorV23> {
        if [
            self.network_genesis,
            self.route,
            self.session,
            self.terms,
            self.funding_tx,
            self.sweep_tx,
            self.destination,
        ]
        .iter()
        .any(|v| *v == [0; 32])
            || self.funded_amount == 0
            || self.fee == 0
            || self.fee >= self.funded_amount
        {
            return Err(InputSpendProofErrorV23::Scope);
        }
        let mut bytes = Vec::with_capacity(249);
        for field in [
            self.network_genesis,
            self.route,
            self.session,
            self.terms,
            self.funding_tx,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.output_index.to_le_bytes());
        bytes.extend_from_slice(&self.sweep_tx);
        bytes.extend_from_slice(&self.destination);
        bytes.extend_from_slice(&self.funded_amount.to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.push(self.action as u8);
        Ok(bytes)
    }
}

/// A canonical Chaum–Pedersen proof: R_G || R_H || response, exactly 96 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSpendProofV23([u8; 96]);

impl InputSpendProofV23 {
    /// Decode canonical prime-order points and canonical scalar; reject trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, InputSpendProofErrorV23> {
        let bytes: [u8; 96] = bytes
            .try_into()
            .map_err(|_| InputSpendProofErrorV23::Encoding)?;
        point(bytes[..32].try_into().unwrap())?;
        point(bytes[32..64].try_into().unwrap())?;
        scalar(bytes[64..].try_into().unwrap())?;
        Ok(Self(bytes))
    }
    /// Public wire bytes; no secret scalar is included.
    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }
}

/// Invalid proof, public scope, or producer witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSpendProofErrorV23 {
    /// Malformed or noncanonical encoding.
    Encoding,
    /// Identity, noncanonical, or non-prime-subgroup point.
    Point,
    /// Empty, unsupported, or inconsistent request scope.
    Scope,
    /// The producer's secret does not match both public values.
    Witness,
    /// The two Chaum–Pedersen equations did not verify.
    Equation,
}

impl core::fmt::Display for InputSpendProofErrorV23 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid Monero input-spend proof ({self:?})")
    }
}
impl std::error::Error for InputSpendProofErrorV23 {}

fn point(bytes: [u8; 32]) -> Result<EdwardsPoint, InputSpendProofErrorV23> {
    let p = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(InputSpendProofErrorV23::Point)?;
    if p.compress().to_bytes() != bytes || p.is_identity() || !p.is_torsion_free() {
        return Err(InputSpendProofErrorV23::Point);
    }
    Ok(p)
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar, InputSpendProofErrorV23> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(InputSpendProofErrorV23::Encoding)
}
fn hash_point(output: [u8; 32]) -> Result<EdwardsPoint, InputSpendProofErrorV23> {
    // The MIT pinned implementation is Monero hash_to_ec, including its hash.
    // Do not pre-hash P or substitute dalek's unrelated hash-to-point mapping.
    let hp: EdwardsPoint = monero_ed25519::Point::biased_hash(output).into();
    point(hp.compress().to_bytes())
}
fn challenge(scope: &[u8], p: [u8; 32], i: [u8; 32], rg: [u8; 32], rh: [u8; 32]) -> Scalar {
    let digest: [u8; 64] = Blake2b512::new()
        .chain_update(DOMAIN)
        .chain_update(scope)
        .chain_update(p)
        .chain_update(i)
        .chain_update(rg)
        .chain_update(rh)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// Prove using the *one-time output* secret, never the combined wallet spend key.
///
/// The caller owns secret custody and authorization; this mathematical helper
/// grants neither. The witness and random nonce are zeroized internally. Every
/// invocation draws a fresh nonce from the supplied cryptographic RNG.
pub fn prove_input_spend_v23<R: RngCore + CryptoRng>(
    context: &InputSpendContextV23,
    output: [u8; 32],
    image: [u8; 32],
    output_secret: &[u8; 32],
    rng: &mut R,
) -> Result<InputSpendProofV23, InputSpendProofErrorV23> {
    let scope = context.canonical_bytes()?;
    let p = point(output)?;
    let i = point(image)?;
    let hp = hash_point(output)?;
    let x = Zeroizing::new(scalar(*output_secret)?);
    if *x == Scalar::ZERO || *x * ED25519_BASEPOINT_POINT != p || *x * hp != i {
        return Err(InputSpendProofErrorV23::Witness);
    }
    let r = loop {
        let mut wide = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(&mut *wide);
        let candidate = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
        if *candidate != Scalar::ZERO {
            break candidate;
        }
    };
    let rg = (*r * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let rh = (*r * hp).compress().to_bytes();
    let c = challenge(&scope, output, image, rg, rh);
    let response = Zeroizing::new(*r + c * *x);
    let mut bytes = [0u8; 96];
    bytes[..32].copy_from_slice(&rg);
    bytes[32..64].copy_from_slice(&rh);
    bytes[64..].copy_from_slice(&response.to_bytes());
    Ok(InputSpendProofV23(bytes))
}

/// Verify only that the selected funding output is the input behind this image.
pub fn verify_input_spend_v23(
    context: &InputSpendContextV23,
    output: [u8; 32],
    image: [u8; 32],
    proof: &InputSpendProofV23,
) -> Result<(), InputSpendProofErrorV23> {
    let scope = context.canonical_bytes()?;
    let p = point(output)?;
    let i = point(image)?;
    let hp = hash_point(output)?;
    let rg_bytes = proof.0[..32].try_into().unwrap();
    let rh_bytes = proof.0[32..64].try_into().unwrap();
    let rg = point(rg_bytes)?;
    let rh = point(rh_bytes)?;
    let s = scalar(proof.0[64..].try_into().unwrap())?;
    let c = challenge(&scope, output, image, rg_bytes, rh_bytes);
    if s * ED25519_BASEPOINT_POINT != rg + c * p || s * hp != rh + c * i {
        return Err(InputSpendProofErrorV23::Equation);
    }
    Ok(())
}

#[cfg(test)]
mod build_request_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tx_derivation_tests;
#[cfg(test)]
mod wire_tests;
