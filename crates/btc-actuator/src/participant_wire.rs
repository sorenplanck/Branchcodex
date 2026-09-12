//! Purpose-limited authenticated exchange for participant-separated claims.
//!
//! These candidate V3 frames are not DSC1 messages and must not be relabelled
//! as an existing Relay type. Each peer independently obtains M.8 authority.
//! The frame signature authenticates a roster participant; it is not an F7
//! funding proof. Network delivery is outside this module.

use btc_crypto::SecpContext;

use crate::model::digest;
use crate::signer::{require_claim_timing, validate_claim_authority};
use crate::{
    BitcoinActuatorErrorV1, BitcoinClaimSessionV1, BitcoinClaimSigningContextV1,
    BitcoinParticipantClaimAuthorityV1, BitcoinParticipantRoleV1, BitcoinPreSignatureV1,
    DurableBitcoinActuatorV1, Result,
};

const MAGIC: &[u8; 8] = b"DOMBTCM3";
const DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/PARTICIPANT-MESSAGE/V3\0";
const HEADER: usize = 140;
const NONCE: u8 = 1;
const PARTIAL: u8 = 2;
/// Maximum encoded V3 participant message size, including authentication.
pub const BITCOIN_CLAIM_MESSAGE_MAX_BYTES_V3: usize = HEADER + 66 + 64;

/// Canonical, authenticated-by-consumption participant message.
///
/// Decoding only checks framing. The receiving actuator verifies the signature,
/// role, session and local M.8 result before any durable mutation. There is no
/// Debug implementation: callers must not log partial-signature material.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinClaimMessageV3 {
    bytes: Vec<u8>,
}

impl BitcoinClaimMessageV3 {
    /// Decode bounded, canonical framing; this does not authenticate the peer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER + 64
            || bytes.len() > BITCOIN_CLAIM_MESSAGE_MAX_BYTES_V3
            || &bytes[..8] != MAGIC
            || bytes[8..10] != 3_u16.to_be_bytes()
            || !matches!(bytes[11], 1 | 2)
        {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let payload = match bytes[10] {
            NONCE => 66,
            PARTIAL => 64,
            _ => return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch),
        };
        if bytes.len() != HEADER + payload + 64
            || bytes[12..HEADER]
                .chunks_exact(32)
                .any(|value| value == [0; 32])
        {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Explicit transport encoding; contains public nonce or partial material.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn payload(&self) -> &[u8] {
        &self.bytes[HEADER..self.bytes.len() - 64]
    }
}

struct MessageScope {
    session: [u8; 32],
    policy: [u8; 32],
    anchors: [u8; 32],
}

impl MessageScope {
    fn authenticate(context: &BitcoinClaimSigningContextV1<'_>) -> Result<Self> {
        require_claim_timing(&context.authorization, context.session)?;
        validate_claim_authority(context.authority, context.session)?;
        Ok(Self {
            session: context.session.session_digest()?,
            policy: context.authorization.window().policy_digest,
            anchors: context.authorization.anchor_evidence_digest(),
        })
    }

    fn sign(
        &self,
        kind: u8,
        payload: &[u8],
        authority: &BitcoinParticipantClaimAuthorityV1,
        session: &BitcoinClaimSessionV1,
    ) -> Result<BitcoinClaimMessageV3> {
        let mut bytes = Vec::with_capacity(BITCOIN_CLAIM_MESSAGE_MAX_BYTES_V3);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&3_u16.to_be_bytes());
        bytes.push(kind);
        bytes.push(role_tag(authority.role()));
        bytes.extend_from_slice(&self.session);
        bytes.extend_from_slice(&authority.participant_id());
        bytes.extend_from_slice(&self.policy);
        bytes.extend_from_slice(&self.anchors);
        bytes.extend_from_slice(payload);
        let signature = authority.sign_claim_message_v3(session, &bytes)?;
        bytes.extend_from_slice(&signature);
        BitcoinClaimMessageV3::from_bytes(&bytes)
    }

    fn verify_peer(
        &self,
        packet: &BitcoinClaimMessageV3,
        kind: u8,
        authority: &BitcoinParticipantClaimAuthorityV1,
        session: &BitcoinClaimSessionV1,
    ) -> Result<()> {
        let index = match authority.role() {
            BitcoinParticipantRoleV1::Maker => 1,
            BitcoinParticipantRoleV1::Taker => 0,
        };
        let peer = session.roster.participants()[index];
        let bytes = &packet.bytes;
        if bytes[10] != kind
            || bytes[11] == role_tag(authority.role())
            || bytes[12..44] != self.session
            || bytes[44..76] != peer.participant_id
            || bytes[76..108] != self.policy
            || bytes[108..140] != self.anchors
        {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let end = bytes.len() - 64;
        let signature: [u8; 64] = bytes[end..]
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        let public: [u8; 32] = peer.compressed_key[1..]
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        let message = digest(DOMAIN, &bytes[..end])?;
        // Verification handles public data only; the fixed context seed does
        // not generate either a signing nonce or a private key.
        SecpContext::new(&[0x63; 32])
            .verify_bip340(&public, &message, &signature)
            .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)
    }
}

impl BitcoinParticipantClaimAuthorityV1 {
    fn sign_claim_message_v3(
        &self,
        session: &BitcoinClaimSessionV1,
        bytes: &[u8],
    ) -> Result<[u8; 64]> {
        // The only caller constructs a fixed frame from durable actuator
        // output. No public arbitrary-message signing capability is exposed.
        self.sign_protocol_message_v3(session, digest(DOMAIN, bytes)?)
    }
}

impl DurableBitcoinActuatorV1 {
    /// Persist/replay the local nonce, then authenticate its exact public frame.
    pub fn expose_claim_message_v3(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
    ) -> Result<BitcoinClaimMessageV3> {
        let scope = MessageScope::authenticate(&context)?;
        let authority = context.authority;
        let session = context.session;
        let nonce = self.expose_claim_pubnonce(context)?;
        scope.sign(NONCE, &nonce.bytes(), authority, session)
    }

    /// Authenticate the peer before persisting its nonce and exposing a partial.
    pub fn produce_claim_message_v3(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
        peer_nonce: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3> {
        let scope = MessageScope::authenticate(&context)?;
        let authority = context.authority;
        let session = context.session;
        scope.verify_peer(peer_nonce, NONCE, authority, session)?;
        let nonce: [u8; 66] = peer_nonce
            .payload()
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        let partial = self.produce_claim_partial(context, nonce)?;
        let mut payload = [0; 64];
        payload[..32].copy_from_slice(&partial.transcript_digest());
        payload[32..].copy_from_slice(&partial.into_bytes());
        scope.sign(PARTIAL, &payload, authority, session)
    }

    /// Authenticate both peer frames and verify their transcript before
    /// aggregating. Restart uses the same durable transcript and nonce vault.
    pub fn aggregate_claim_messages_v3(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
        peer_nonce: &BitcoinClaimMessageV3,
        peer_partial: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinPreSignatureV1> {
        let scope = MessageScope::authenticate(&context)?;
        scope.verify_peer(peer_nonce, NONCE, context.authority, context.session)?;
        scope.verify_peer(peer_partial, PARTIAL, context.authority, context.session)?;
        let nonce: [u8; 66] = peer_nonce
            .payload()
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        let partial: [u8; 32] = peer_partial.payload()[32..]
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        // The underlying aggregate validates the real MuSig2 partial against
        // the locally reconstructed transcript, then durably marks it verified.
        // Check the packet's transcript before that mutation as well.
        let expected = self.claim_transcript_for_peer_v3(&context, nonce)?;
        if peer_partial.payload()[..32] != expected {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        self.aggregate_claim_pre_signature(context, nonce, partial)
    }
}

const fn role_tag(role: BitcoinParticipantRoleV1) -> u8 {
    match role {
        BitcoinParticipantRoleV1::Maker => 1,
        BitcoinParticipantRoleV1::Taker => 2,
    }
}
