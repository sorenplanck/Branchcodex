//! The cross-curve condition that ties the two legs together.
//!
//! One 252-bit scalar `s` has two public faces, proved equal off-chain by the
//! bound DLEQ in `xmr_dleq_sigma` under the role byte
//! `ROLE_SOLANA_CONDITION_LOCK`:
//!
//! * `s * G_secp256k1`, SEC1 compressed — the adaptor point the DOM kernel
//!   pre-signature is bound to, so completing the DOM claim requires `s` and
//!   publishing that claim discloses `s`;
//! * `s * G_ed25519`, compressed — the `claim_point_ed25519` the escrow stores,
//!   so the `Claim` instruction requires `s` and carries it in its data.
//!
//! Because both faces open with the same bytes, the leg needs no third
//! mechanism: whichever side claims first publishes `s`, and the other side
//! reads it off the chain it was published on.
//!
//! Every opening is checked against BOTH faces before it is used, with the same
//! predicate each chain enforces:
//!
//! * the escrow's own domain rule — the little-endian scalar's top nibble must
//!   be clear, i.e. `s < 2^252`, which is the interval the DLEQ proves equality
//!   over (`programs/dom-solana-escrow/src/secret.rs`);
//! * `s * G_ed25519 == claim_point_ed25519`, the syscall the program calls;
//! * `s * G_secp256k1 == dom_adaptor_point`, what
//!   `scriptless_adapt_signature` will produce a valid DOM signature for.
//!
//! An opening that fails either face is refused here rather than turned into a
//! transaction that a chain would reject, or worse, one that a chain would
//! accept for the wrong settlement.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as ED25519_G, scalar::Scalar as Ed25519Scalar,
};
use dom_crypto::PublicKey;
use dom_scriptless_primitives::SecretScalar;
use solana_escrow_wire::EscrowInstructionV1;
use xmr_dleq_sigma::CrossCurvePublicClaim;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConditionError {
    #[error("the opening is zero or not below 2^252")]
    OutsideProvedDomain,
    #[error("the opening does not open the Ed25519 face of the condition")]
    Ed25519FaceMismatch,
    #[error("the opening does not open the secp256k1 face of the condition")]
    SecpFaceMismatch,
    #[error("the public condition is malformed")]
    MalformedClaim,
    #[error("the transaction data is not an escrow Claim instruction")]
    NotAClaimInstruction,
}

/// The public, settlement-bound condition. Construct it only from a claim that
/// `verify_counterparty_bundle` returned, never from loose bytes: this type
/// carries no proof of its own and exists to be compared against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConditionLockV1 {
    claim: CrossCurvePublicClaim,
}

impl ConditionLockV1 {
    pub fn from_verified_claim(claim: CrossCurvePublicClaim) -> Result<Self, ConditionError> {
        if claim.ed_compressed == [0; 32] || !matches!(claim.secp_compressed[0], 0x02 | 0x03) {
            return Err(ConditionError::MalformedClaim);
        }
        Ok(Self { claim })
    }

    /// SEC1-compressed adaptor point, for `DomSigningIntent::new`.
    pub fn dom_adaptor_point(&self) -> [u8; 33] {
        self.claim.secp_compressed
    }

    pub fn dom_adaptor_public_key(&self) -> Result<PublicKey, ConditionError> {
        PublicKey::from_compressed_bytes(&self.claim.secp_compressed)
            .map_err(|_| ConditionError::MalformedClaim)
    }

    /// Compressed Ed25519 point, for `InitializeParamsV1::claim_point_ed25519`.
    pub fn solana_claim_point(&self) -> [u8; 32] {
        self.claim.ed_compressed
    }

    /// Accept an opening only after it passes both faces and the escrow's own
    /// domain rule.
    pub fn open(
        &self,
        big_endian: Zeroizing<[u8; 32]>,
    ) -> Result<ConditionOpeningV1, ConditionError> {
        let mut little_endian = Zeroizing::new(*big_endian);
        little_endian.reverse();
        if *big_endian == [0; 32] || little_endian[31] & 0xf0 != 0 {
            return Err(ConditionError::OutsideProvedDomain);
        }
        // Below 2^252, so reduction modulo the group order is the identity and
        // this is exactly the scalar the syscall multiplies by.
        let scalar = Ed25519Scalar::from_bytes_mod_order(*little_endian);
        if (scalar * ED25519_G).compress().to_bytes() != self.claim.ed_compressed {
            return Err(ConditionError::Ed25519FaceMismatch);
        }
        let secret = SecretScalar::from_be_bytes(*big_endian)
            .map_err(|_| ConditionError::OutsideProvedDomain)?;
        let point = secret
            .public_key()
            .map_err(|_| ConditionError::SecpFaceMismatch)?;
        if point.to_compressed_bytes() != self.claim.secp_compressed {
            return Err(ConditionError::SecpFaceMismatch);
        }
        Ok(ConditionOpeningV1 {
            big_endian,
            secret,
            lock: *self,
        })
    }

    /// Read the opening out of a published escrow `Claim` instruction's data.
    /// This is the DOM<-SOL reveal path: the secret is in the instruction, so
    /// the DOM side needs nothing from the counterparty to proceed.
    pub fn open_from_escrow_claim_data(
        &self,
        instruction_data: &[u8],
    ) -> Result<ConditionOpeningV1, ConditionError> {
        match EscrowInstructionV1::decode(instruction_data)
            .map_err(|_| ConditionError::NotAClaimInstruction)?
        {
            EscrowInstructionV1::Claim { revealed_secret_be } => {
                self.open(Zeroizing::new(revealed_secret_be))
            }
            _ => Err(ConditionError::NotAClaimInstruction),
        }
    }
}

/// A checked opening of the condition. Holding one means both chains will
/// accept it; it is the only type the leg accepts where a secret is required.
pub struct ConditionOpeningV1 {
    big_endian: Zeroizing<[u8; 32]>,
    secret: SecretScalar,
    lock: ConditionLockV1,
}

impl core::fmt::Debug for ConditionOpeningV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConditionOpeningV1")
            .field("secret", &"<redacted>")
            .field("lock", &self.lock)
            .finish()
    }
}

impl ConditionOpeningV1 {
    /// For `DomClaimOffer::complete`.
    pub fn dom_secret(&self) -> &SecretScalar {
        &self.secret
    }

    /// For `EscrowInstructionV1::Claim`. The program reverses these bytes and
    /// re-checks the domain rule, so the encoding must stay big-endian.
    pub fn escrow_claim_bytes(&self) -> [u8; 32] {
        *self.big_endian
    }

    pub fn lock(&self) -> &ConditionLockV1 {
        &self.lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_route_secret::{verify_counterparty_bundle, SolanaRouteSecret};

    fn lock_and_opening() -> (ConditionLockV1, Zeroizing<[u8; 32]>) {
        let mut rng = rand::thread_rng();
        let route = SolanaRouteSecret::generate([9; 32], [8; 32], &mut rng).unwrap();
        let claim = verify_counterparty_bundle(route.proof(), &[9; 32], &[8; 32]).unwrap();
        let lock = ConditionLockV1::from_verified_claim(claim).unwrap();
        let opening =
            route.with_revealed_dom_secret(|bytes| Zeroizing::new(bytes.expose_scalar_bytes()));
        (lock, opening)
    }

    #[test]
    fn the_route_secret_opens_both_faces() {
        let (lock, opening) = lock_and_opening();
        let opened = lock.open(opening).unwrap();
        assert_eq!(opened.lock().solana_claim_point(), lock.solana_claim_point());
    }

    #[test]
    fn a_foreign_secret_opens_neither_face() {
        let (lock, _) = lock_and_opening();
        let (_, other) = lock_and_opening();
        // `ConditionOpeningV1` deliberately has no `PartialEq`: a secret is not
        // something this lab compares with `==`.
        assert!(matches!(
            lock.open(other),
            Err(ConditionError::Ed25519FaceMismatch)
        ));
    }

    #[test]
    fn an_opening_above_the_proved_domain_is_refused() {
        let (lock, opening) = lock_and_opening();
        let mut raised = *opening;
        // Big-endian byte 0 is the little-endian top byte the escrow masks.
        raised[0] |= 0xf0;
        assert!(matches!(
            lock.open(Zeroizing::new(raised)),
            Err(ConditionError::OutsideProvedDomain)
        ));
    }

    #[test]
    fn only_a_claim_instruction_yields_an_opening() {
        let (lock, _) = lock_and_opening();
        assert!(matches!(
            lock.open_from_escrow_claim_data(&EscrowInstructionV1::Refund.encode()),
            Err(ConditionError::NotAClaimInstruction)
        ));
    }
}
