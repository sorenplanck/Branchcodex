//! Proof of R=rG and D=rA for a standard Monero destination's public view A.
//! This proof alone does not prove output value, validity, or inclusion.
use super::*;

const TX_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-TX-DERIVATION-DLEQ/V23\0";

/// Public derivation proof. The verifier must match R to an actual raw tx key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxKeyDerivationProofV23 {
    /// Transaction public key R, as encoded in the transaction extra.
    pub tx_public: [u8; 32],
    /// Public shared derivation D=rA, before Monero's cofactor multiplication.
    pub derivation: [u8; 32],
    proof: [u8; 96],
}
impl TxKeyDerivationProofV23 {
    /// Decode exact public fields, rejecting malformed points/scalars.
    pub fn decode(bytes: &[u8]) -> Result<Self, InputSpendProofErrorV23> {
        if bytes.len() != 160 {
            return Err(InputSpendProofErrorV23::Encoding);
        }
        let tx_public = bytes[..32].try_into().unwrap();
        let derivation = bytes[32..64].try_into().unwrap();
        point(tx_public)?;
        point(derivation)?;
        let checked = InputSpendProofV23::decode(&bytes[64..])?;
        Ok(Self {
            tx_public,
            derivation,
            proof: *checked.as_bytes(),
        })
    }
    /// Canonical 160-byte public encoding; contains no transaction private key.
    pub fn encode(&self) -> [u8; 160] {
        let mut bytes = [0; 160];
        bytes[..32].copy_from_slice(&self.tx_public);
        bytes[32..64].copy_from_slice(&self.derivation);
        bytes[64..].copy_from_slice(&self.proof);
        bytes
    }
}
fn tx_challenge(
    scope: &[u8],
    a: [u8; 32],
    r: [u8; 32],
    d: [u8; 32],
    rg: [u8; 32],
    ra: [u8; 32],
) -> Scalar {
    let wide: [u8; 64] = Blake2b512::new()
        .chain_update(TX_DOMAIN)
        .chain_update(scope)
        .chain_update(a)
        .chain_update(r)
        .chain_update(d)
        .chain_update(rg)
        .chain_update(ra)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Mathematical producer using the actual retained transaction key, not a new
/// unrelated scalar. No signing authorization is created by this function.
pub fn prove_tx_key_derivation_v23<R: RngCore + CryptoRng>(
    context: &InputSpendContextV23,
    destination_view: [u8; 32],
    expected_tx_public: [u8; 32],
    tx_secret: &[u8; 32],
    rng: &mut R,
) -> Result<TxKeyDerivationProofV23, InputSpendProofErrorV23> {
    let scope = context.canonical_bytes()?;
    let a = point(destination_view)?;
    let r = Zeroizing::new(scalar(*tx_secret)?);
    if *r == Scalar::ZERO
        || (*r * ED25519_BASEPOINT_POINT).compress().to_bytes() != expected_tx_public
    {
        return Err(InputSpendProofErrorV23::Witness);
    }
    let d = (*r * a).compress().to_bytes();
    let n = loop {
        let mut wide = Zeroizing::new([0; 64]);
        rng.fill_bytes(&mut *wide);
        let n = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
        if *n != Scalar::ZERO {
            break n;
        }
    };
    let rg = (*n * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let ra = (*n * a).compress().to_bytes();
    let c = tx_challenge(&scope, destination_view, expected_tx_public, d, rg, ra);
    let response = Zeroizing::new(*n + c * *r);
    let mut proof = [0; 96];
    proof[..32].copy_from_slice(&rg);
    proof[32..64].copy_from_slice(&ra);
    proof[64..].copy_from_slice(&response.to_bytes());
    Ok(TxKeyDerivationProofV23 {
        tx_public: expected_tx_public,
        derivation: d,
        proof,
    })
}

/// Verify the public derivation, not a payment. Only standard address R=rG is
/// supported; a subaddress R=rB requires a distinct explicit proof profile.
pub fn verify_tx_key_derivation_v23(
    context: &InputSpendContextV23,
    destination_view: [u8; 32],
    proof: &TxKeyDerivationProofV23,
) -> Result<[u8; 32], InputSpendProofErrorV23> {
    let scope = context.canonical_bytes()?;
    let a = point(destination_view)?;
    let r = point(proof.tx_public)?;
    let d = point(proof.derivation)?;
    let rg_bytes = proof.proof[..32].try_into().unwrap();
    let ra_bytes = proof.proof[32..64].try_into().unwrap();
    let rg = point(rg_bytes)?;
    let ra = point(ra_bytes)?;
    let s = scalar(proof.proof[64..].try_into().unwrap())?;
    let c = tx_challenge(
        &scope,
        destination_view,
        proof.tx_public,
        proof.derivation,
        rg_bytes,
        ra_bytes,
    );
    if s * ED25519_BASEPOINT_POINT != rg + c * r || s * a != ra + c * d {
        return Err(InputSpendProofErrorV23::Equation);
    }
    Ok(proof.derivation)
}
