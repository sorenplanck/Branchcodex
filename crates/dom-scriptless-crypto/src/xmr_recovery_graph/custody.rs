//! Encrypted retention of native verified public recovery artifacts and the
//! optional final refund in the U owner's custody. Opening an archive restores
//! cryptographic evidence only; it grants no funding or broadcast authority.

use super::{
    verify_xmr_recovery_graph_v11, PrivateXmrRefundTransactionV11, VerifiedXmrRecoveryGraphV11,
    XmrRecoveryGraphBindingV11, XmrRecoveryGraphRequestV11, MAX_TRANSACTION_BYTES,
};
use crate::{begin_refund_adaptor_round_v1, RefundAdaptorRoundInputsV1};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use dom_adaptor::{BindingContextV1, ParticipantPublicNoncesV1, PurposeV1};
use dom_consensus::{validate_transaction, Transaction};
use dom_crypto::{blake2b_256, PublicKey};
use dom_serialization::{DomDeserialize, DomSerialize};
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_MAGIC: &[u8; 8] = b"DOMXRSE1";
const PAYLOAD_MAGIC: &[u8; 8] = b"DOMXRSP1";
const AAD_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-RECOVERY-CUSTODY/V11\0";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 8 + NONCE_LEN + 4;
const MAX_PLAINTEXT: usize = 6 * MAX_TRANSACTION_BYTES + 2_048;

/// Strict bound applied before any allocation controlled by an archive.
pub const XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11: usize = PREFIX_LEN + MAX_PLAINTEXT + TAG_LEN;

/// Dedicated custody key. The caller must derive or generate it independently
/// of protocol witnesses, nonce keys and public identifiers. It is never logged
/// or serialized by this module.
pub struct XmrRecoverySealKeyV11(Zeroizing<[u8; 32]>);

impl XmrRecoverySealKeyV11 {
    /// Consume a nonzero key from the owner's private credential boundary.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XmrRecoveryArchiveErrorV11::InvalidScope);
        }
        Ok(Self(bytes))
    }
}

/// Redacted hard refusals. Missing files are a distinct Store-level result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmrRecoveryArchiveErrorV11 {
    /// Required custody identity or key was zero.
    InvalidScope,
    /// Bounded canonical encoding was malformed.
    InvalidEncoding,
    /// Key, authenticated binding, ciphertext or authentication tag differed.
    AuthenticationFailed,
    /// The platform could not generate an independent encryption nonce.
    RandomUnavailable,
    /// Native consensus or the retained public adaptor round rejected evidence.
    InvalidGraph,
    /// A private refund did not belong to this exact verified graph.
    InvalidPrivateRefund,
}

impl core::fmt::Display for XmrRecoveryArchiveErrorV11 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidScope => "invalid XMR recovery custody scope",
            Self::InvalidEncoding => "invalid XMR recovery archive encoding",
            Self::AuthenticationFailed => "XMR recovery archive authentication failed",
            Self::RandomUnavailable => "XMR recovery encryption nonce unavailable",
            Self::InvalidGraph => "retained XMR recovery graph failed native verification",
            Self::InvalidPrivateRefund => "private XMR recovery refund mismatch",
        })
    }
}

impl std::error::Error for XmrRecoveryArchiveErrorV11 {}
type Result<T> = core::result::Result<T, XmrRecoveryArchiveErrorV11>;

/// Public description of an opened archive, not a custody authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmrRecoveryArchiveShapeV11 {
    /// The T owner's public graph, without the completed refund.
    PublicGraphOnly,
    /// The U owner's graph and privately retained completed refund.
    WithPrivateRefund,
}

/// Authenticated, freshly reverified native graph and optional private refund.
/// No Clone, Debug, Deserialize or network operation is exposed.
pub struct OpenedXmrRecoveryArchiveV11 {
    graph: VerifiedXmrRecoveryGraphV11,
    private_refund: Option<PrivateXmrRefundTransactionV11>,
}

impl OpenedXmrRecoveryArchiveV11 {
    /// Public graph evidence, reverified with native consensus and nonce binding.
    pub const fn graph(&self) -> &VerifiedXmrRecoveryGraphV11 {
        &self.graph
    }

    /// Archive shape, which the caller must match to its authenticated custody role.
    pub const fn shape(&self) -> XmrRecoveryArchiveShapeV11 {
        match &self.private_refund {
            Some(_) => XmrRecoveryArchiveShapeV11::WithPrivateRefund,
            None => XmrRecoveryArchiveShapeV11::PublicGraphOnly,
        }
    }

    /// Private custody access only. A Store execution capability and fresh
    /// canonical reveal window remain mandatory before these bytes can be sent.
    pub fn with_private_refund<R>(
        &self,
        operation: impl FnOnce(Option<&PrivateXmrRefundTransactionV11>) -> R,
    ) -> R {
        operation(self.private_refund.as_ref())
    }
}

/// Encrypt the exact verified graph in one envelope before any XMR funding.
/// If supplied, the final refund is verified against the graph before sealing.
/// It never appears in the public cancel/punish or transport representations.
pub fn seal_xmr_recovery_archive_v11(
    graph: &VerifiedXmrRecoveryGraphV11,
    custody_id: [u8; 32],
    key: &XmrRecoverySealKeyV11,
    private_refund: Option<&PrivateXmrRefundTransactionV11>,
) -> Result<Vec<u8>> {
    let aad = associated_data(&graph.binding, graph.graph_digest(), custody_id)?;
    if let Some(private) = private_refund {
        if private.graph_digest != graph.graph_digest {
            return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
        }
        let restored = validate_private_refund(graph, &private.canonical_bytes)?;
        if restored.transaction_hash != private.transaction_hash {
            return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
        }
    }
    let mut payload = encode_payload(graph, private_refund)?;
    let mut nonce = [0; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| XmrRecoveryArchiveErrorV11::RandomUnavailable)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidScope)?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut payload)
        .map_err(|_| XmrRecoveryArchiveErrorV11::AuthenticationFailed)?;
    let length =
        u32::try_from(payload.len()).map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?;
    let mut envelope = Vec::with_capacity(PREFIX_LEN + payload.len() + TAG_LEN);
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&length.to_be_bytes());
    envelope.extend_from_slice(&payload);
    envelope.extend_from_slice(&tag);
    Ok(envelope)
}

/// Open an existing archive under externally authenticated exact scope. Public
/// nonce bindings and consensus are recomputed; no serialized capability is
/// treated as trusted merely because AEAD authentication succeeds.
pub fn open_xmr_recovery_archive_v11(
    binding: XmrRecoveryGraphBindingV11,
    expected_graph_digest: [u8; 32],
    custody_id: [u8; 32],
    key: &XmrRecoverySealKeyV11,
    envelope: &[u8],
) -> Result<OpenedXmrRecoveryArchiveV11> {
    if !(PREFIX_LEN + TAG_LEN..=XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11).contains(&envelope.len()) {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    let mut cursor = Cursor::new(envelope);
    if cursor.take(8)? != ENVELOPE_MAGIC {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    let nonce = cursor.array::<NONCE_LEN>()?;
    let length = usize::try_from(u32::from_be_bytes(cursor.array()?))
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?;
    if length > MAX_PLAINTEXT {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    let mut plaintext = Zeroizing::new(cursor.take(length)?.to_vec());
    let tag = cursor.array::<TAG_LEN>()?;
    cursor.finish()?;
    let aad = associated_data(&binding, &expected_graph_digest, custody_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidScope)?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &aad,
            &mut plaintext,
            Tag::from_slice(&tag),
        )
        .map_err(|_| XmrRecoveryArchiveErrorV11::AuthenticationFailed)?;
    decode_payload(binding, expected_graph_digest, &plaintext)
}

fn associated_data(
    binding: &XmrRecoveryGraphBindingV11,
    digest: &[u8; 32],
    custody_id: [u8; 32],
) -> Result<Vec<u8>> {
    if custody_id == [0; 32]
        || *digest == [0; 32]
        || binding.chain_id == [0; 32]
        || binding.session_id == [0; 32]
        || binding.terms_hash == [0; 32]
    {
        return Err(XmrRecoveryArchiveErrorV11::InvalidScope);
    }
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 5 * 32);
    aad.extend_from_slice(AAD_DOMAIN);
    for bytes in [
        &custody_id,
        &binding.chain_id,
        &binding.session_id,
        &binding.terms_hash,
        digest,
    ] {
        aad.extend_from_slice(bytes);
    }
    Ok(aad)
}

fn encode_payload(
    graph: &VerifiedXmrRecoveryGraphV11,
    private_refund: Option<&PrivateXmrRefundTransactionV11>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(PAYLOAD_MAGIC);
    for transaction in [&graph.funding_template, &graph.claim_template] {
        append(
            &mut out,
            &transaction
                .to_bytes()
                .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?,
        )?;
    }
    append(&mut out, &graph.cancel_bytes)?;
    append(
        &mut out,
        &graph
            .refund_template
            .to_bytes()
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?,
    )?;
    append(&mut out, &graph.punish_bytes)?;
    let pre = &graph.refund_pre_signature;
    out.extend_from_slice(pre.transcript_hash());
    let roster = pre.public_nonce_roster_v11();
    if roster.len() != 2 {
        return Err(XmrRecoveryArchiveErrorV11::InvalidGraph);
    }
    for participant in roster {
        out.extend_from_slice(&participant.participant_index.to_be_bytes());
        for point in [
            &participant.signing_key,
            &participant.first_nonce,
            &participant.second_nonce,
        ] {
            out.extend_from_slice(&point.to_compressed_bytes());
        }
    }
    out.extend_from_slice(&pre.to_bytes());
    match private_refund {
        Some(private) => {
            out.push(1);
            append(&mut out, &private.canonical_bytes)?;
        }
        None => out.push(0),
    }
    if out.len() > MAX_PLAINTEXT {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    Ok(out)
}

fn decode_payload(
    binding: XmrRecoveryGraphBindingV11,
    expected_digest: [u8; 32],
    bytes: &[u8],
) -> Result<OpenedXmrRecoveryArchiveV11> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != PAYLOAD_MAGIC {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    let funding = parse_unsigned(cursor.blob()?)?;
    let claim = parse_unsigned(cursor.blob()?)?;
    let cancel = cursor.blob()?;
    let refund = parse_unsigned(cursor.blob()?)?;
    let punish = cursor.blob()?;
    let transcript_hash = cursor.array()?;
    let mut participants = Vec::with_capacity(2);
    for _ in 0..2 {
        participants.push(ParticipantPublicNoncesV1 {
            participant_index: u16::from_be_bytes(cursor.array()?),
            signing_key: parse_point(cursor.array()?)?,
            first_nonce: parse_point(cursor.array()?)?,
            second_nonce: parse_point(cursor.array()?)?,
        });
    }
    let pre_bytes = cursor.take(crate::REFUND_ADAPTOR_PRE_SIGNATURE_LEN)?;
    let (_, template_hash) = dom_adaptor::canonical_template_v1(&refund)
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    let kernel = refund
        .kernels
        .first()
        .ok_or(XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    let round = begin_refund_adaptor_round_v1(&RefundAdaptorRoundInputsV1 {
        binding_context: BindingContextV1 {
            chain_id: binding.chain_id,
            session_id: binding.session_id,
            purpose: PurposeV1::RefundAdaptor,
            template_hash,
        },
        participants: &participants,
        refund_adaptor_point: parse_point(binding.refund_adaptor_point)?,
        aggregate_signing_key: parse_point(*kernel.excess.as_bytes())?,
        transcript_hash,
        kernel_message_digest: *dom_scriptless_consensus::scriptless_kernel_message_digest_v1(
            kernel,
        )
        .as_bytes(),
    })
    .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    let pre = round
        .restore_pre_signature_v1(pre_bytes)
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    let graph = verify_xmr_recovery_graph_v11(XmrRecoveryGraphRequestV11 {
        binding,
        funding_template: &funding,
        claim_template: &claim,
        cancel_bytes: cancel,
        refund_template: &refund,
        refund_pre_signature: pre,
        punish_bytes: punish,
    })
    .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    if graph.graph_digest != expected_digest {
        return Err(XmrRecoveryArchiveErrorV11::InvalidGraph);
    }
    let private_refund = match cursor.array::<1>()?[0] {
        0 => None,
        1 => Some(validate_private_refund(&graph, cursor.blob()?)?),
        _ => return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding),
    };
    cursor.finish()?;
    Ok(OpenedXmrRecoveryArchiveV11 {
        graph,
        private_refund,
    })
}

fn validate_private_refund(
    graph: &VerifiedXmrRecoveryGraphV11,
    bytes: &[u8],
) -> Result<PrivateXmrRefundTransactionV11> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
    }
    let mut tx = Transaction::from_bytes(bytes)
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?;
    let result = (|| {
        if tx.kernels.len() != 1 {
            return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
        }
        let canonical = Zeroizing::new(
            tx.to_bytes()
                .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?,
        );
        if canonical.as_slice() != bytes {
            return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
        }
        validate_transaction(
            &tx,
            &super::context(&graph.binding, graph.binding.cancel_height),
        )
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?;
        let _recovered = graph
            .refund_pre_signature
            .extract(&tx.kernels[0].excess_signature)
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?;
        tx.kernels[0].excess_signature.zeroize();
        let unsigned = tx
            .to_bytes()
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?;
        let expected = graph
            .refund_template
            .to_bytes()
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidPrivateRefund)?;
        if unsigned != expected {
            return Err(XmrRecoveryArchiveErrorV11::InvalidPrivateRefund);
        }
        Ok(PrivateXmrRefundTransactionV11 {
            graph_digest: graph.graph_digest,
            transaction_hash: *blake2b_256(bytes).as_bytes(),
            canonical_bytes: Zeroizing::new(bytes.to_vec()),
        })
    })();
    for kernel in &mut tx.kernels {
        kernel.excess_signature.zeroize();
    }
    result
}

fn parse_unsigned(bytes: &[u8]) -> Result<Transaction> {
    let mut tx =
        Transaction::from_bytes(bytes).map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?;
    // Refuse accidentally retained private signatures before leaving this
    // function, and wipe every such signature on the error path.
    if tx
        .kernels
        .iter()
        .any(|kernel| kernel.excess_signature != [0; 65])
    {
        for kernel in &mut tx.kernels {
            kernel.excess_signature.zeroize();
        }
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    if tx
        .to_bytes()
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?
        != bytes
    {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    Ok(tx)
}

fn parse_point(bytes: [u8; 33]) -> Result<PublicKey> {
    let point = PublicKey::from_compressed_bytes(&bytes)
        .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidGraph)?;
    if point.to_compressed_bytes() != bytes {
        return Err(XmrRecoveryArchiveErrorV11::InvalidGraph);
    }
    Ok(point)
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.remaining.len() {
            return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
        }
        let (head, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| XmrRecoveryArchiveErrorV11::InvalidEncoding)?;
        if length == 0 || length > MAX_TRANSACTION_BYTES {
            return Err(XmrRecoveryArchiveErrorV11::InvalidEncoding);
        }
        self.take(length)
    }
    fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(XmrRecoveryArchiveErrorV11::InvalidEncoding)
        }
    }
}
