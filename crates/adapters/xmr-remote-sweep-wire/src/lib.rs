//! Canonical public request for a remotely constructed Monero sweep.
//!
//! The request carries no private spend/view scalar and grants no signing
//! authority by itself.  A production caller must bind it to an authenticated
//! route Store decision and a confirmed DOM observation before a signer may
//! combine its locally retained share.  The eventual response is deliberately
//! a separate type: raw transaction bytes must not be accepted until the
//! input-spend, payout and RingCT verification boundary has produced a closed
//! verified value.

#![forbid(unsafe_code)]

use blake2::{digest::consts::U32, Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

const MAGIC_V23: &[u8; 8] = b"XMRSRQ23";
const DIGEST_DOMAIN_V23: &[u8] = b"DOM-INTEROP/XMR-REMOTE-SWEEP-REQUEST/V23\0";
const FIXED_PREFIX_LEN_V23: usize = 8 + 2 + 1 + 1 + 8 + (17 * 32) + 8 + 8 + 8 + 8 + 4 + 4 + 32 + 2;
const RESPONSE_MAGIC_V23: &[u8; 8] = b"XMRSRS23";
const RESPONSE_DIGEST_DOMAIN_V23: &[u8] = b"DOM-INTEROP/XMR-REMOTE-SWEEP-RESPONSE/V23\0";
const RESPONSE_FIXED_PREFIX_LEN_V23: usize = 8 + 2 + 1 + 1 + 8 + (15 * 32) + (2 * 8) + (4 * 4);

/// Long enough for canonical Monero primary/subaddresses, with no unbounded
/// allocation controlled by a peer.
pub const MAX_DESTINATION_BYTES_V23: usize = 256;
/// Largest canonical request body.
pub const MAX_REMOTE_SWEEP_REQUEST_BYTES_V23: usize =
    FIXED_PREFIX_LEN_V23 + MAX_DESTINATION_BYTES_V23;
/// Global authenticated DSC1 payload cap used by the production Relay.
pub const MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23: usize = 512 * 1024;
/// A V23 input-link proof is one canonical 96-byte Chaum--Pedersen proof.
pub const INPUT_SPEND_PROOF_BYTES_V23: usize = 96;
/// One R,D Chaum--Pedersen transaction-key derivation proof.
pub const TX_KEY_DERIVATION_PROOF_BYTES_V23: usize = 160;
/// Current modern Monero ring cardinality; the actuator supports one input.
pub const RING_MEMBERS_V23: usize = 16;
/// A standard transaction has one primary key and can add at most one key per
/// bounded output; this is distinct from the mandatory 2..16 output count.
pub const MIN_PAYOUT_PROOFS_V23: usize = 1;
pub const MAX_PAYOUT_PROOFS_V23: usize = 17;
const RING_MEMBER_BYTES_V23: usize = 8 + 32 + 32;
/// Maximum raw transaction that still leaves room for worst-case proofs and
/// typed ring members inside one authenticated DSC1 response envelope.
pub const MAX_RAW_SWEEP_BYTES_V23: usize = MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23
    - RESPONSE_FIXED_PREFIX_LEN_V23
    - INPUT_SPEND_PROOF_BYTES_V23
    - (MAX_PAYOUT_PROOFS_V23 * TX_KEY_DERIVATION_PROOF_BYTES_V23)
    - (RING_MEMBERS_V23 * RING_MEMBER_BYTES_V23);

/// A remote request is only meaningful after a public DOM-chain revelation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RemoteSweepActionV23 {
    /// Claim the Monero funding output after the claim scalar is public on DOM.
    Claim = 1,
    /// Refund the Monero funding output after the refund scalar is public on DOM.
    Refund = 2,
}

/// Copy a field only after the decoder has checked its complete fixed prefix.
fn field32_v23(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut value = [0; 32];
    for (offset, slot) in value.iter_mut().enumerate() {
        *slot = bytes[at + offset];
    }
    value
}

impl TryFrom<u8> for RemoteSweepActionV23 {
    type Error = RemoteSweepWireErrorV23;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Claim),
            2 => Ok(Self::Refund),
            _ => Err(RemoteSweepWireErrorV23::Action),
        }
    }
}

/// Exact route position; never inferred from settlement ordering at receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RemoteSweepLegV23 {
    Upstream = 1,
    Downstream = 2,
}

impl TryFrom<u8> for RemoteSweepLegV23 {
    type Error = RemoteSweepWireErrorV23;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(RemoteSweepWireErrorV23::Scope),
        }
    }
}

/// Every public fact needed to prevent cross-route, cross-session and
/// cross-deployment replay of one remote sweep request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSweepRequestV23 {
    pub network_genesis: [u8; 32],
    pub route_id: [u8; 32],
    pub session_id: [u8; 32],
    pub settlement_id: [u8; 32],
    pub terms_digest: [u8; 32],
    pub registry_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub deployment_digest: [u8; 32],
    pub route_scope_digest: [u8; 32],
    pub composition_digest: [u8; 32],
    pub role_plan_digest: [u8; 32],
    pub source_scope_digest: [u8; 32],
    pub effect_id: [u8; 32],
    pub semantic_digest: [u8; 32],
    pub public_secret_evidence_digest: [u8; 32],
    pub funding_tx_hash: [u8; 32],
    /// Digest of the freshly verified F7 Monero funding observation.
    pub funding_evidence_digest: [u8; 32],
    pub funding_output_index: u64,
    /// Canonical inclusion height authenticated by that same F7 observation.
    pub funding_block_height: u64,
    pub funded_amount_piconero: u64,
    pub max_fee_piconero: u64,
    /// Exact authenticated adapter-profile bound, never a peer-selected cap.
    pub adapter_max_raw_transaction_bytes: u32,
    /// Stricter DSC1 transport cap, derived from the adapter cap and response
    /// proof overhead rather than silently truncating a transaction.
    pub max_raw_transaction_bytes: u32,
    pub fencing_epoch: u64,
    pub action: RemoteSweepActionV23,
    pub leg: RemoteSweepLegV23,
    /// The already-public counterpart share, in canonical Monero scalar form.
    pub public_spend_share: [u8; 32],
    /// Exact negotiated destination address. Network/address validation belongs
    /// to the signer and the independent payout verifier, not this codec.
    pub destination: String,
}

impl RemoteSweepRequestV23 {
    /// Strict canonical encoding. No unknown fields, defaults or trailing data.
    pub fn encode(&self) -> Result<Vec<u8>, RemoteSweepWireErrorV23> {
        self.validate_shape()?;
        let destination = self.destination.as_bytes();
        let destination_len =
            u16::try_from(destination.len()).map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let mut bytes = Vec::with_capacity(FIXED_PREFIX_LEN_V23 + destination.len());
        bytes.extend_from_slice(MAGIC_V23);
        bytes.extend_from_slice(&23_u16.to_le_bytes());
        bytes.push(self.action as u8);
        bytes.push(self.leg as u8);
        bytes.extend_from_slice(&self.fencing_epoch.to_le_bytes());
        for field in [
            self.network_genesis,
            self.route_id,
            self.session_id,
            self.settlement_id,
            self.terms_digest,
            self.registry_digest,
            self.profile_digest,
            self.deployment_digest,
            self.route_scope_digest,
            self.composition_digest,
            self.role_plan_digest,
            self.source_scope_digest,
            self.effect_id,
            self.semantic_digest,
            self.public_secret_evidence_digest,
            self.funding_tx_hash,
            self.funding_evidence_digest,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.funding_output_index.to_le_bytes());
        bytes.extend_from_slice(&self.funding_block_height.to_le_bytes());
        bytes.extend_from_slice(&self.funded_amount_piconero.to_le_bytes());
        bytes.extend_from_slice(&self.max_fee_piconero.to_le_bytes());
        bytes.extend_from_slice(&self.adapter_max_raw_transaction_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.max_raw_transaction_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.public_spend_share);
        bytes.extend_from_slice(&destination_len.to_le_bytes());
        bytes.extend_from_slice(destination);
        debug_assert!(bytes.len() <= MAX_REMOTE_SWEEP_REQUEST_BYTES_V23);
        Ok(bytes)
    }

    /// Decodes exactly one request and re-encodes it to reject noncanonical
    /// lengths, reserved flags, malformed UTF-8 and trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, RemoteSweepWireErrorV23> {
        if bytes.len() < FIXED_PREFIX_LEN_V23
            || bytes.len() > MAX_REMOTE_SWEEP_REQUEST_BYTES_V23
            || bytes.get(..8) != Some(MAGIC_V23.as_slice())
            || read_u16(bytes, 8)? != 23
        {
            return Err(RemoteSweepWireErrorV23::Encoding);
        }
        let action = RemoteSweepActionV23::try_from(bytes[10])?;
        let leg = RemoteSweepLegV23::try_from(bytes[11])?;
        let fencing_epoch = read_u64(bytes, 12)?;
        let mut at = 20;
        let mut field = || {
            let value = field32_v23(bytes, at);
            at += 32;
            value
        };
        let request = Self {
            network_genesis: field(),
            route_id: field(),
            session_id: field(),
            settlement_id: field(),
            terms_digest: field(),
            registry_digest: field(),
            profile_digest: field(),
            deployment_digest: field(),
            route_scope_digest: field(),
            composition_digest: field(),
            role_plan_digest: field(),
            source_scope_digest: field(),
            effect_id: field(),
            semantic_digest: field(),
            public_secret_evidence_digest: field(),
            funding_tx_hash: field(),
            funding_evidence_digest: field(),
            funding_output_index: read_u64(bytes, at)?,
            funding_block_height: read_u64(bytes, at + 8)?,
            funded_amount_piconero: read_u64(bytes, at + 16)?,
            max_fee_piconero: read_u64(bytes, at + 24)?,
            adapter_max_raw_transaction_bytes: read_u32(bytes, at + 32)?,
            max_raw_transaction_bytes: read_u32(bytes, at + 36)?,
            public_spend_share: field32_v23(bytes, at + 40),
            destination: {
                let length = usize::from(read_u16(bytes, at + 72)?);
                let start = at + 74;
                let end = start
                    .checked_add(length)
                    .ok_or(RemoteSweepWireErrorV23::Bounds)?;
                if end != bytes.len() {
                    return Err(RemoteSweepWireErrorV23::Encoding);
                }
                core::str::from_utf8(&bytes[start..end])
                    .map_err(|_| RemoteSweepWireErrorV23::Destination)?
                    .to_owned()
            },
            fencing_epoch,
            action,
            leg,
        };
        request.validate_shape()?;
        if request.encode()?.as_slice() != bytes {
            return Err(RemoteSweepWireErrorV23::Encoding);
        }
        Ok(request)
    }

    /// Domain-separated digest signed by the authenticated Relay envelope and
    /// repeated by any later response/custody record.
    pub fn digest(&self) -> Result<[u8; 32], RemoteSweepWireErrorV23> {
        let canonical = self.encode()?;
        Ok(Blake2b256::new()
            .chain_update(DIGEST_DOMAIN_V23)
            .chain_update((canonical.len() as u64).to_le_bytes())
            .chain_update(canonical)
            .finalize()
            .into())
    }

    fn validate_shape(&self) -> Result<(), RemoteSweepWireErrorV23> {
        if [
            self.network_genesis,
            self.route_id,
            self.session_id,
            self.settlement_id,
            self.terms_digest,
            self.registry_digest,
            self.profile_digest,
            self.deployment_digest,
            self.route_scope_digest,
            self.composition_digest,
            self.role_plan_digest,
            self.source_scope_digest,
            self.effect_id,
            self.semantic_digest,
            self.public_secret_evidence_digest,
            self.funding_tx_hash,
            self.funding_evidence_digest,
            self.public_spend_share,
        ]
        .contains(&[0; 32])
            || self.fencing_epoch == 0
            || self.funding_block_height == 0
            || self.funded_amount_piconero == 0
            || self.max_fee_piconero == 0
            || self.max_fee_piconero >= self.funded_amount_piconero
            || self.adapter_max_raw_transaction_bytes == 0
            || usize::try_from(self.adapter_max_raw_transaction_bytes)
                .map_or(true, |maximum| maximum > 512 * 1024)
            || self.max_raw_transaction_bytes == 0
            || usize::try_from(self.max_raw_transaction_bytes)
                .map_or(true, |maximum| maximum > MAX_RAW_SWEEP_BYTES_V23)
            || self.max_raw_transaction_bytes > self.adapter_max_raw_transaction_bytes
            || !self.destination.starts_with('4')
            || self.destination.len() > MAX_DESTINATION_BYTES_V23
            || !self.destination.is_ascii()
            || self.destination.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        Ok(())
    }
}

/// Fixed-size public transaction-key derivation proof carried on the wire.
/// Canonical point/scalar validation belongs to `xmr-key-image-proof`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteTxKeyDerivationProofV23([u8; TX_KEY_DERIVATION_PROOF_BYTES_V23]);

impl RemoteTxKeyDerivationProofV23 {
    pub fn decode(bytes: &[u8]) -> Result<Self, RemoteSweepWireErrorV23> {
        let bytes = bytes
            .try_into()
            .map_err(|_| RemoteSweepWireErrorV23::Encoding)?;
        if bytes == [0; TX_KEY_DERIVATION_PROOF_BYTES_V23] {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; TX_KEY_DERIVATION_PROOF_BYTES_V23] {
        &self.0
    }
}

/// One claimed ring member. The receiver MUST resolve the same global index
/// through an authenticated Mainnet RPC quorum and compare key+commitment
/// before this value can become cryptographic ring evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteRingMemberV23 {
    pub global_index: u64,
    pub key: [u8; 32],
    pub commitment: [u8; 32],
}

impl RemoteRingMemberV23 {
    fn validate(&self) -> Result<(), RemoteSweepWireErrorV23> {
        if self.key == [0; 32] || self.commitment == [0; 32] {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        Ok(())
    }
}

/// Public response fields produced by the remote share owner.
///
/// Successful canonical decoding is deliberately not a verification result.
/// `input_spend_proof`, `payout_proofs` and `ring_members` must be decoded by
/// their dedicated cryptographic crates and checked against the exact funding
/// and sweep bytes before the raw transaction may enter actuator custody.
pub struct RemoteSweepResponseInputV23 {
    pub request_digest: [u8; 32],
    /// Exact authenticated DSC1 `0x19` message digest, not the wire digest.
    pub request_message_digest: [u8; 32],
    /// Independent signer-side F7 observation. It is intentionally distinct
    /// from the requester's tip-sensitive funding evidence digest.
    pub signer_funding_evidence_digest: [u8; 32],
    pub network_genesis: [u8; 32],
    pub route_id: [u8; 32],
    pub session_id: [u8; 32],
    pub settlement_id: [u8; 32],
    pub terms_digest: [u8; 32],
    pub registry_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub deployment_digest: [u8; 32],
    pub effect_id: [u8; 32],
    pub semantic_digest: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub key_image: [u8; 32],
    pub funded_amount_piconero: u64,
    pub fee_piconero: u64,
    pub fencing_epoch: u64,
    pub action: RemoteSweepActionV23,
    pub leg: RemoteSweepLegV23,
    pub raw_transaction: Vec<u8>,
    pub input_spend_proof: [u8; INPUT_SPEND_PROOF_BYTES_V23],
    pub payout_proofs: Vec<RemoteTxKeyDerivationProofV23>,
    pub ring_members: Vec<RemoteRingMemberV23>,
}

/// Canonical but still unverified response to one exact remote sweep request.
///
/// This type intentionally does not implement `Clone`: the exact response is
/// handed from authenticated transport into one verification/import boundary.
/// It never means that destination, amount, commitments, Bulletproof+, balance
/// or CLSAG were accepted.
pub struct RemoteSweepResponseV23(RemoteSweepResponseInputV23);

impl core::fmt::Debug for RemoteSweepResponseV23 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RemoteSweepResponseV23")
            .field("request_digest", &self.0.request_digest)
            .field("request_message_digest", &self.0.request_message_digest)
            .field("transaction_hash", &self.0.transaction_hash)
            .field("key_image", &self.0.key_image)
            .field("raw_transaction_len", &self.0.raw_transaction.len())
            .field("input_spend_proof", &"[redacted proof bytes]")
            .field("payout_proofs", &"[redacted proof bytes]")
            .field("ring_members", &self.0.ring_members.len())
            .finish()
    }
}

impl RemoteSweepResponseV23 {
    pub fn new(input: RemoteSweepResponseInputV23) -> Result<Self, RemoteSweepWireErrorV23> {
        let response = Self(input);
        response.validate_shape()?;
        Ok(response)
    }

    /// Strict canonical encoding with bounded, explicit lengths for all blobs.
    pub fn encode(&self) -> Result<Vec<u8>, RemoteSweepWireErrorV23> {
        self.validate_shape()?;
        let raw_len = u32::try_from(self.0.raw_transaction.len())
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let input_len = u32::try_from(self.0.input_spend_proof.len())
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let payout_count = u32::try_from(self.0.payout_proofs.len())
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let ring_count = u32::try_from(self.0.ring_members.len())
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let total = RESPONSE_FIXED_PREFIX_LEN_V23
            .checked_add(self.0.raw_transaction.len())
            .and_then(|value| value.checked_add(self.0.input_spend_proof.len()))
            .and_then(|value| {
                value.checked_add(self.0.payout_proofs.len() * TX_KEY_DERIVATION_PROOF_BYTES_V23)
            })
            .and_then(|value| value.checked_add(self.0.ring_members.len() * RING_MEMBER_BYTES_V23))
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(RESPONSE_MAGIC_V23);
        bytes.extend_from_slice(&23_u16.to_le_bytes());
        bytes.push(self.0.action as u8);
        bytes.push(self.0.leg as u8);
        bytes.extend_from_slice(&self.0.fencing_epoch.to_le_bytes());
        for field in [
            self.0.request_digest,
            self.0.request_message_digest,
            self.0.signer_funding_evidence_digest,
            self.0.network_genesis,
            self.0.route_id,
            self.0.session_id,
            self.0.settlement_id,
            self.0.terms_digest,
            self.0.registry_digest,
            self.0.profile_digest,
            self.0.deployment_digest,
            self.0.effect_id,
            self.0.semantic_digest,
            self.0.transaction_hash,
            self.0.key_image,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.0.funded_amount_piconero.to_le_bytes());
        bytes.extend_from_slice(&self.0.fee_piconero.to_le_bytes());
        bytes.extend_from_slice(&raw_len.to_le_bytes());
        bytes.extend_from_slice(&input_len.to_le_bytes());
        bytes.extend_from_slice(&payout_count.to_le_bytes());
        bytes.extend_from_slice(&ring_count.to_le_bytes());
        bytes.extend_from_slice(&self.0.raw_transaction);
        bytes.extend_from_slice(&self.0.input_spend_proof);
        for proof in &self.0.payout_proofs {
            bytes.extend_from_slice(proof.as_bytes());
        }
        for member in &self.0.ring_members {
            bytes.extend_from_slice(&member.global_index.to_le_bytes());
            bytes.extend_from_slice(&member.key);
            bytes.extend_from_slice(&member.commitment);
        }
        if bytes.len() != total || bytes.len() > MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23 {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        Ok(bytes)
    }

    /// Decode one response. This establishes framing only, never validity.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, RemoteSweepWireErrorV23> {
        if bytes.len() < RESPONSE_FIXED_PREFIX_LEN_V23
            || bytes.len() > MAX_REMOTE_SWEEP_RESPONSE_BYTES_V23
            || bytes.get(..8) != Some(RESPONSE_MAGIC_V23.as_slice())
            || read_u16(bytes, 8)? != 23
        {
            return Err(RemoteSweepWireErrorV23::Encoding);
        }
        let action = RemoteSweepActionV23::try_from(bytes[10])?;
        let leg = RemoteSweepLegV23::try_from(bytes[11])?;
        let fencing_epoch = read_u64(bytes, 12)?;
        let mut at = 20;
        let mut field = || {
            let value = field32_v23(bytes, at);
            at += 32;
            value
        };
        let request_digest = field();
        let request_message_digest = field();
        let signer_funding_evidence_digest = field();
        let network_genesis = field();
        let route_id = field();
        let session_id = field();
        let settlement_id = field();
        let terms_digest = field();
        let registry_digest = field();
        let profile_digest = field();
        let deployment_digest = field();
        let effect_id = field();
        let semantic_digest = field();
        let transaction_hash = field();
        let key_image = field();
        let funded_amount_piconero = read_u64(bytes, at)?;
        let fee_piconero = read_u64(bytes, at + 8)?;
        let raw_len = usize::try_from(read_u32(bytes, at + 16)?)
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let input_len = usize::try_from(read_u32(bytes, at + 20)?)
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let payout_count = usize::try_from(read_u32(bytes, at + 24)?)
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        let ring_count = usize::try_from(read_u32(bytes, at + 28)?)
            .map_err(|_| RemoteSweepWireErrorV23::Bounds)?;
        if !(MIN_PAYOUT_PROOFS_V23..=MAX_PAYOUT_PROOFS_V23).contains(&payout_count)
            || ring_count != RING_MEMBERS_V23
        {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        let payout_len = payout_count
            .checked_mul(TX_KEY_DERIVATION_PROOF_BYTES_V23)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let ring_len = ring_count
            .checked_mul(RING_MEMBER_BYTES_V23)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let raw_start = at + 32;
        let input_start = raw_start
            .checked_add(raw_len)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let payout_start = input_start
            .checked_add(input_len)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let ring_start = payout_start
            .checked_add(payout_len)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        let end = ring_start
            .checked_add(ring_len)
            .ok_or(RemoteSweepWireErrorV23::Bounds)?;
        if end != bytes.len() || input_len != INPUT_SPEND_PROOF_BYTES_V23 {
            return Err(RemoteSweepWireErrorV23::Encoding);
        }
        let payout_proofs = bytes[payout_start..ring_start]
            .chunks_exact(TX_KEY_DERIVATION_PROOF_BYTES_V23)
            .map(RemoteTxKeyDerivationProofV23::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let ring_members = bytes[ring_start..end]
            .chunks_exact(RING_MEMBER_BYTES_V23)
            .map(|encoded| {
                let member = RemoteRingMemberV23 {
                    global_index: u64::from_le_bytes(
                        encoded[..8]
                            .try_into()
                            .map_err(|_| RemoteSweepWireErrorV23::Encoding)?,
                    ),
                    key: encoded[8..40]
                        .try_into()
                        .map_err(|_| RemoteSweepWireErrorV23::Encoding)?,
                    commitment: encoded[40..72]
                        .try_into()
                        .map_err(|_| RemoteSweepWireErrorV23::Encoding)?,
                };
                member.validate()?;
                Ok(member)
            })
            .collect::<Result<Vec<_>, RemoteSweepWireErrorV23>>()?;
        let response = Self::new(RemoteSweepResponseInputV23 {
            request_digest,
            request_message_digest,
            signer_funding_evidence_digest,
            network_genesis,
            route_id,
            session_id,
            settlement_id,
            terms_digest,
            registry_digest,
            profile_digest,
            deployment_digest,
            effect_id,
            semantic_digest,
            transaction_hash,
            key_image,
            funded_amount_piconero,
            fee_piconero,
            fencing_epoch,
            action,
            leg,
            raw_transaction: bytes[raw_start..input_start].to_vec(),
            input_spend_proof: bytes[input_start..payout_start]
                .try_into()
                .map_err(|_| RemoteSweepWireErrorV23::Encoding)?,
            payout_proofs,
            ring_members,
        })?;
        if response.encode()?.as_slice() != bytes {
            return Err(RemoteSweepWireErrorV23::Encoding);
        }
        Ok(response)
    }

    /// Recheck all request/route/session/terms/deployment/effect/fence pins.
    /// This is an authentication precondition, not cryptographic acceptance.
    pub fn validate_for_request(
        &self,
        request: &RemoteSweepRequestV23,
    ) -> Result<(), RemoteSweepWireErrorV23> {
        if self.0.request_digest != request.digest()?
            || self.0.network_genesis != request.network_genesis
            || self.0.route_id != request.route_id
            || self.0.session_id != request.session_id
            || self.0.settlement_id != request.settlement_id
            || self.0.terms_digest != request.terms_digest
            || self.0.registry_digest != request.registry_digest
            || self.0.profile_digest != request.profile_digest
            || self.0.deployment_digest != request.deployment_digest
            || self.0.effect_id != request.effect_id
            || self.0.semantic_digest != request.semantic_digest
            || self.0.funded_amount_piconero != request.funded_amount_piconero
            || self.0.fee_piconero > request.max_fee_piconero
            || self.0.raw_transaction.len()
                > usize::try_from(request.max_raw_transaction_bytes)
                    .map_err(|_| RemoteSweepWireErrorV23::Scope)?
            || self.0.fencing_epoch != request.fencing_epoch
            || self.0.action != request.action
            || self.0.leg != request.leg
        {
            return Err(RemoteSweepWireErrorV23::Scope);
        }
        Ok(())
    }

    /// Bind the response to the exact authenticated DSC1 request message in
    /// addition to the canonical request payload. A response to another 0x19
    /// envelope is never reusable even when its public wire payload is equal.
    pub fn validate_for_authenticated_request(
        &self,
        request: &RemoteSweepRequestV23,
        request_message_digest: [u8; 32],
    ) -> Result<(), RemoteSweepWireErrorV23> {
        self.validate_for_request(request)?;
        if request_message_digest == [0; 32]
            || self.0.request_message_digest != request_message_digest
        {
            return Err(RemoteSweepWireErrorV23::Scope);
        }
        Ok(())
    }

    /// Domain-separated digest authenticated by the Relay response envelope.
    pub fn digest(&self) -> Result<[u8; 32], RemoteSweepWireErrorV23> {
        let canonical = self.encode()?;
        Ok(Blake2b256::new()
            .chain_update(RESPONSE_DIGEST_DOMAIN_V23)
            .chain_update((canonical.len() as u64).to_le_bytes())
            .chain_update(canonical)
            .finalize()
            .into())
    }

    pub fn transaction_hash(&self) -> [u8; 32] {
        self.0.transaction_hash
    }

    /// Public action discriminator; decoding remains separate from authority.
    pub fn action(&self) -> RemoteSweepActionV23 {
        self.0.action
    }

    pub fn request_message_digest(&self) -> [u8; 32] {
        self.0.request_message_digest
    }

    pub fn signer_funding_evidence_digest(&self) -> [u8; 32] {
        self.0.signer_funding_evidence_digest
    }

    pub fn key_image(&self) -> [u8; 32] {
        self.0.key_image
    }

    pub fn fee_piconero(&self) -> u64 {
        self.0.fee_piconero
    }

    pub fn raw_transaction(&self) -> &[u8] {
        &self.0.raw_transaction
    }

    pub fn input_spend_proof(&self) -> &[u8; INPUT_SPEND_PROOF_BYTES_V23] {
        &self.0.input_spend_proof
    }

    pub fn payout_proofs(&self) -> &[RemoteTxKeyDerivationProofV23] {
        &self.0.payout_proofs
    }

    pub fn ring_members(&self) -> &[RemoteRingMemberV23] {
        &self.0.ring_members
    }

    fn validate_shape(&self) -> Result<(), RemoteSweepWireErrorV23> {
        if [
            self.0.request_digest,
            self.0.request_message_digest,
            self.0.signer_funding_evidence_digest,
            self.0.network_genesis,
            self.0.route_id,
            self.0.session_id,
            self.0.settlement_id,
            self.0.terms_digest,
            self.0.registry_digest,
            self.0.profile_digest,
            self.0.deployment_digest,
            self.0.effect_id,
            self.0.semantic_digest,
            self.0.transaction_hash,
            self.0.key_image,
        ]
        .contains(&[0; 32])
            || self.0.fencing_epoch == 0
            || self.0.funded_amount_piconero == 0
            || self.0.fee_piconero == 0
            || self.0.fee_piconero >= self.0.funded_amount_piconero
            || self.0.raw_transaction.is_empty()
            || self.0.raw_transaction.len() > MAX_RAW_SWEEP_BYTES_V23
            || !(MIN_PAYOUT_PROOFS_V23..=MAX_PAYOUT_PROOFS_V23)
                .contains(&self.0.payout_proofs.len())
            || self.0.ring_members.len() != RING_MEMBERS_V23
        {
            return Err(RemoteSweepWireErrorV23::Bounds);
        }
        let mut previous = None;
        for member in &self.0.ring_members {
            member.validate()?;
            if previous.is_some_and(|index| index >= member.global_index) {
                return Err(RemoteSweepWireErrorV23::Bounds);
            }
            previous = Some(member.global_index);
        }
        Ok(())
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, RemoteSweepWireErrorV23> {
    let field = bytes
        .get(at..at + 2)
        .ok_or(RemoteSweepWireErrorV23::Encoding)?
        .try_into()
        .map_err(|_| RemoteSweepWireErrorV23::Encoding)?;
    Ok(u16::from_le_bytes(field))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, RemoteSweepWireErrorV23> {
    let field = bytes
        .get(at..at + 4)
        .ok_or(RemoteSweepWireErrorV23::Encoding)?
        .try_into()
        .map_err(|_| RemoteSweepWireErrorV23::Encoding)?;
    Ok(u32::from_le_bytes(field))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, RemoteSweepWireErrorV23> {
    let field = bytes
        .get(at..at + 8)
        .ok_or(RemoteSweepWireErrorV23::Encoding)?
        .try_into()
        .map_err(|_| RemoteSweepWireErrorV23::Encoding)?;
    Ok(u64::from_le_bytes(field))
}

/// Canonical framing failure. Economic or cryptographic verification uses
/// separate error types so codec success can never be mistaken for authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RemoteSweepWireErrorV23 {
    #[error("invalid remote XMR sweep request encoding")]
    Encoding,
    #[error("unsupported remote XMR sweep action")]
    Action,
    #[error("remote XMR sweep request exceeds public bounds")]
    Bounds,
    #[error("invalid remote XMR destination encoding")]
    Destination,
    #[error("remote XMR response does not match its authenticated request")]
    Scope,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RemoteSweepRequestV23 {
        let mut next = 1_u8;
        let mut field = || {
            let value = [next; 32];
            next += 1;
            value
        };
        RemoteSweepRequestV23 {
            network_genesis: field(),
            route_id: field(),
            session_id: field(),
            settlement_id: field(),
            terms_digest: field(),
            registry_digest: field(),
            profile_digest: field(),
            deployment_digest: field(),
            route_scope_digest: field(),
            composition_digest: field(),
            role_plan_digest: field(),
            source_scope_digest: field(),
            effect_id: field(),
            semantic_digest: field(),
            public_secret_evidence_digest: field(),
            funding_tx_hash: field(),
            funding_evidence_digest: field(),
            public_spend_share: field(),
            funding_output_index: 1,
            funding_block_height: 2,
            funded_amount_piconero: 5_000_000,
            max_fee_piconero: 50_000,
            adapter_max_raw_transaction_bytes: 512 * 1024,
            max_raw_transaction_bytes: 128 * 1024,
            fencing_epoch: 9,
            action: RemoteSweepActionV23::Claim,
            leg: RemoteSweepLegV23::Downstream,
            destination: "48bWuoDG75vE6cX7cD4zNQeZg1V23canonicalDestination".to_owned(),
        }
    }

    fn response_input(request: &RemoteSweepRequestV23) -> RemoteSweepResponseInputV23 {
        RemoteSweepResponseInputV23 {
            request_digest: request.digest().expect("request digest"),
            request_message_digest: [23; 32],
            signer_funding_evidence_digest: [24; 32],
            network_genesis: request.network_genesis,
            route_id: request.route_id,
            session_id: request.session_id,
            settlement_id: request.settlement_id,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            effect_id: request.effect_id,
            semantic_digest: request.semantic_digest,
            transaction_hash: [21; 32],
            key_image: [22; 32],
            funded_amount_piconero: request.funded_amount_piconero,
            fee_piconero: request.max_fee_piconero - 1,
            fencing_epoch: request.fencing_epoch,
            action: request.action,
            leg: request.leg,
            raw_transaction: vec![0x7a; 64],
            input_spend_proof: [0x31; INPUT_SPEND_PROOF_BYTES_V23],
            payout_proofs: vec![RemoteTxKeyDerivationProofV23::decode(
                &[0x41; TX_KEY_DERIVATION_PROOF_BYTES_V23],
            )
            .expect("proof shape")],
            ring_members: (0..RING_MEMBERS_V23)
                .map(|index| RemoteRingMemberV23 {
                    global_index: u64::try_from(index + 1).expect("bounded index"),
                    key: [u8::try_from(index + 1).expect("bounded key"); 32],
                    commitment: [u8::try_from(index + 33).expect("bounded commitment"); 32],
                })
                .collect(),
        }
    }

    #[test]
    fn exact_roundtrip_and_digest_bind_every_byte() {
        let request = request();
        let encoded = request.encode().expect("encode");
        assert_eq!(
            RemoteSweepRequestV23::decode_exact(&encoded),
            Ok(request.clone())
        );
        let digest = request.digest().expect("digest");
        let mut changed = request;
        changed.fencing_epoch += 1;
        assert_ne!(changed.digest().expect("changed digest"), digest);
    }

    #[test]
    fn truncation_trailing_reserved_and_zero_fields_fail_closed() {
        let request = request();
        let encoded = request.encode().expect("encode");
        assert!(RemoteSweepRequestV23::decode_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RemoteSweepRequestV23::decode_exact(&trailing).is_err());
        let mut invalid_leg = encoded.clone();
        invalid_leg[11] = 0;
        assert!(RemoteSweepRequestV23::decode_exact(&invalid_leg).is_err());
        let mut zero = request;
        zero.route_id = [0; 32];
        assert!(zero.encode().is_err());
    }

    #[test]
    fn response_roundtrip_is_canonical_and_bound_to_the_exact_request() {
        let request = request();
        let response =
            RemoteSweepResponseV23::new(response_input(&request)).expect("response shape");
        let encoded = response.encode().expect("response encode");
        let decoded = RemoteSweepResponseV23::decode_exact(&encoded).expect("response decode");
        assert_eq!(decoded.encode().expect("canonical reencode"), encoded);
        assert_eq!(decoded.action(), request.action);
        decoded
            .validate_for_authenticated_request(&request, [23; 32])
            .expect("exact request binding");
        assert_ne!(
            decoded.digest().expect("response digest"),
            request.digest().unwrap()
        );
    }

    #[test]
    fn response_truncation_trailing_counts_and_ring_order_fail_closed() {
        let request = request();
        let response = RemoteSweepResponseV23::new(response_input(&request)).unwrap();
        let encoded = response.encode().unwrap();
        assert!(RemoteSweepResponseV23::decode_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RemoteSweepResponseV23::decode_exact(&trailing).is_err());
        for offset in [516usize, 520, 524, 528] {
            let mut invalid = encoded.clone();
            invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(RemoteSweepResponseV23::decode_exact(&invalid).is_err());
        }
        let mut unordered = response_input(&request);
        unordered.ring_members[1].global_index = unordered.ring_members[0].global_index;
        assert!(RemoteSweepResponseV23::new(unordered).is_err());
    }

    #[test]
    fn response_request_digest_raw_fee_fence_and_action_mutations_fail_closed() {
        let request = request();
        let encoded = RemoteSweepResponseV23::new(response_input(&request))
            .unwrap()
            .encode()
            .unwrap();
        let decoded = RemoteSweepResponseV23::decode_exact(&encoded).unwrap();
        assert!(decoded
            .validate_for_authenticated_request(&request, [24; 32])
            .is_err());
        assert!(decoded
            .validate_for_authenticated_request(&request, [0; 32])
            .is_err());
        let mut another_request = request.clone();
        another_request.route_id[0] ^= 1;
        assert!(decoded.validate_for_request(&another_request).is_err());
        let mut altered_destination = request.clone();
        altered_destination.destination.push('x');
        assert!(decoded.validate_for_request(&altered_destination).is_err());
        let mut small_raw = request.clone();
        small_raw.max_raw_transaction_bytes = 63;
        assert!(decoded.validate_for_request(&small_raw).is_err());

        let mut excessive_fee = encoded.clone();
        excessive_fee[508..516].copy_from_slice(&(request.max_fee_piconero + 1).to_le_bytes());
        let excessive_fee = RemoteSweepResponseV23::decode_exact(&excessive_fee).unwrap();
        assert!(excessive_fee.validate_for_request(&request).is_err());

        for (offset, replacement) in [(12usize, 10_u64), (10usize, 2_u64)] {
            let mut mutated = encoded.clone();
            if offset == 12 {
                mutated[offset..offset + 8].copy_from_slice(&replacement.to_le_bytes());
            } else {
                mutated[offset] = replacement as u8;
            }
            let mutated = RemoteSweepResponseV23::decode_exact(&mutated).unwrap();
            assert!(mutated.validate_for_request(&request).is_err());
        }
    }

    #[test]
    fn response_zero_request_message_digest_is_refused() {
        let request = request();
        let mut input = response_input(&request);
        input.request_message_digest = [0; 32];
        assert!(RemoteSweepResponseV23::new(input).is_err());
    }

    #[test]
    fn response_signer_funding_evidence_is_mandatory_and_digest_bound() {
        let request = request();
        let response = RemoteSweepResponseV23::new(response_input(&request)).unwrap();
        let digest = response.digest().unwrap();
        let mut changed = response_input(&request);
        changed.signer_funding_evidence_digest[0] ^= 1;
        assert_ne!(
            RemoteSweepResponseV23::new(changed)
                .unwrap()
                .digest()
                .unwrap(),
            digest
        );
        let mut zero = response_input(&request);
        zero.signer_funding_evidence_digest = [0; 32];
        assert!(RemoteSweepResponseV23::new(zero).is_err());
    }
}
