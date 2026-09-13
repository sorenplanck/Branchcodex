//! Native DOM cancel/refund/punish graph validation and private refund assembly.
//!
//! This is transaction evidence, not a Store, signing or funding capability.
//! In particular, recipient commitments must come from authenticated negotiated
//! terms and wallet output provenance. Valid curve points do not establish who
//! owns an output. A complete runtime additionally needs durable independent
//! nonce rounds, custody, observation of C/D, and fresh temporal authorization.
//! The normal claim is checked only as a native unsigned spend of C. This
//! verifier does not authenticate its recipient, prove its signature is bound
//! to T, or issue the post-funding permission to sign it.
//!
//! Punish is an ordinary signed DOM payment to the XMR funder. It compensates
//! that party in DOM when the DOM funder disappears; it does NOT return XMR.
//! Making punish reveal T would introduce a race with refund U and is not
//! implemented. Both adaptor witnesses can be learned from the mempool, so the
//! caller must enforce confirmation/reorg margins before revealing either.
//! A final Schnorr signature does not reveal how it was produced. The Store
//! must independently authenticate ordinary (non-adaptor) cancel/punish rounds;
//! native transaction verification alone cannot prove that provenance.

use crate::VerifiedRefundPreSignatureV1;
use dom_adaptor::{canonical_template_v1, validate_public_range_proofs_v24, AdaptorSecret};
use dom_consensus::{
    validate_balance_equation, validate_transaction, validate_transaction_structure, Transaction,
    ValidationContext,
};
use dom_core::{BlockHeight, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{blake2b_256, PublicKey};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_serialization::{DomDeserialize, DomSerialize};
use zeroize::{Zeroize, Zeroizing};

mod custody;
mod ordinary_round;
pub use custody::{
    open_xmr_recovery_archive_v11, seal_xmr_recovery_archive_v11, OpenedXmrRecoveryArchiveV11,
    XmrRecoveryArchiveErrorV11, XmrRecoveryArchiveShapeV11, XmrRecoverySealKeyV11,
    XMR_RECOVERY_ARCHIVE_MAX_BYTES_V11,
};
pub use ordinary_round::{
    require_distinct_xmr_recovery_nonces_v12, require_ordinary_recovery_kind_admitted_v22,
    require_safe_ordinary_recovery_kind_v13, xmr_bounded_compensation_session_v23,
    xmr_compensation_session_v23, xmr_ordinary_recovery_session_v12,
    CompletedXmrOrdinaryRecoveryRoundV12, XmrCompensationFundingWitnessV22,
    XmrOrdinaryRecoveryErrorV12, XmrOrdinaryRecoveryKindV12, XmrOrdinaryRecoveryRoundV12,
};

const DOMAIN: &[u8] = b"DOM-INTEROP/XMR-CANCEL-REFUND-PUNISH/V11\0";
const MAX_TRANSACTION_BYTES: usize = 1_048_576;

/// Canonical V12 identity of the independently initialized cancellation output D.
/// This derives a public identifier only; it grants no custody or signing power.
pub fn xmr_cancelled_output_session_id_v22(
    chain_id: &[u8; 32],
    parent_session: &[u8; 32],
    terms_hash: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = b"DOM-INTEROP/XMR-CANCELLED-OUTPUT-SESSION/V12\0".to_vec();
    bytes.extend_from_slice(chain_id);
    bytes.extend_from_slice(parent_session);
    bytes.extend_from_slice(terms_hash);
    *blake2b_256(&bytes).as_bytes()
}

/// Public negotiated graph fields. This input is not authenticated authority.
/// All commitments, fees, identities and heights must be bound by both parties.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XmrRecoveryGraphBindingV11 {
    /// Authenticated native DOM chain identifier.
    pub chain_id: [u8; 32],
    /// Contract session identifier.
    pub session_id: [u8; 32],
    /// Digest of the versioned terms that authorize this recovery profile.
    pub terms_hash: [u8; 32],
    /// Funding output C, consumed by normal claim or cancel.
    pub funding_commitment: [u8; 33],
    /// New jointly controlled output D, created only by the exact cancel.
    pub cancelled_commitment: [u8; 33],
    /// Authenticated DOM-funder payout commitment of refund D -> Alice.
    pub refund_recipient_commitment: [u8; 33],
    /// Authenticated XMR-funder payout commitment of punish D -> Bob.
    pub punish_recipient_commitment: [u8; 33],
    /// Public claim point T, distinct from refund point U.
    pub claim_adaptor_point: [u8; 33],
    /// Public refund point U, whose matching private witness stays with Alice.
    pub refund_adaptor_point: [u8; 33],
    /// Earliest cancel height Hc.
    pub cancel_height: u64,
    /// Earliest punish height Hp.
    pub punish_height: u64,
    /// Negotiated inclusion, confirmation and reorg budget, in DOM blocks.
    pub reveal_safety_blocks: u64,
    /// Exact cancel fee in native noms.
    pub cancel_fee: u64,
    /// Exact refund fee in native noms.
    pub refund_fee: u64,
    /// Exact punish fee in native noms.
    pub punish_fee: u64,
}

/// Native artifacts supplied to the graph verifier. No raw secret is accepted.
pub struct XmrRecoveryGraphRequestV11<'a> {
    /// Exact, externally authenticated economic and temporal binding.
    pub binding: XmrRecoveryGraphBindingV11,
    /// Unsigned funding template, with the output C.
    pub funding_template: &'a Transaction,
    /// Unsigned normal claim template, spending C.
    pub claim_template: &'a Transaction,
    /// Canonical fully signed cancel C -> D; safe to retain publicly.
    pub cancel_bytes: &'a [u8],
    /// Unsigned refund D -> Alice, with a HEIGHT_LOCKED Hc kernel.
    pub refund_template: &'a Transaction,
    /// Native verified refund pre-signature, never its final signature.
    pub refund_pre_signature: VerifiedRefundPreSignatureV1,
    /// Canonical fully signed punish D -> Bob with HEIGHT_LOCKED Hp.
    pub punish_bytes: &'a [u8],
}

/// Exact graph or cryptographic refusal. No variant means unavailable evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmrRecoveryGraphErrorV11 {
    /// A required public identity, point, or temporal budget is invalid.
    InvalidBinding,
    /// Transaction bytes are malformed, over the bound or noncanonical.
    NonCanonicalTransaction,
    /// Native consensus rejects balance, proof, signature or kernel fields.
    ConsensusRejected,
    /// A transaction spends or creates a commitment outside the frozen graph.
    GraphMismatch,
    /// A transaction fee differs from the negotiated fee.
    FeeMismatch,
    /// The adaptor equation is bound to another key, message or template.
    RefundPreSignatureMismatch,
    /// The supplied witness does not complete the exact refund signature.
    RefundAdaptationRejected,
    /// There is no longer enough DOM block budget to reveal the witness.
    RevealWindowClosed,
}

impl core::fmt::Display for XmrRecoveryGraphErrorV11 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "invalid XMR recovery graph binding",
            Self::NonCanonicalTransaction => "noncanonical XMR recovery DOM transaction",
            Self::ConsensusRejected => "native DOM verifier rejected recovery transaction",
            Self::GraphMismatch => "DOM recovery transaction graph mismatch",
            Self::FeeMismatch => "DOM recovery transaction fee mismatch",
            Self::RefundPreSignatureMismatch => "DOM refund pre-signature binding mismatch",
            Self::RefundAdaptationRejected => "DOM refund adaptor completion rejected",
            Self::RevealWindowClosed => "DOM adaptor reveal safety window closed",
        })
    }
}

impl std::error::Error for XmrRecoveryGraphErrorV11 {}

type Result<T> = core::result::Result<T, XmrRecoveryGraphErrorV11>;

/// Native verified graph evidence. No Clone, Debug, Deserialize or authority.
/// Every public transaction has been checked by unchanged DOM consensus.
pub struct VerifiedXmrRecoveryGraphV11 {
    binding: XmrRecoveryGraphBindingV11,
    graph_digest: [u8; 32],
    cancel_bytes: Vec<u8>,
    punish_bytes: Vec<u8>,
    funding_template: Transaction,
    claim_template: Transaction,
    refund_template: Transaction,
    refund_pre_signature: VerifiedRefundPreSignatureV1,
}

/// A final refund signature is confidential until its authorized transmission:
/// together with the public pre-signature it exposes U, even before mining.
/// This container deliberately provides neither Debug nor public serialization.
pub struct PrivateXmrRefundTransactionV11 {
    graph_digest: [u8; 32],
    transaction_hash: [u8; 32],
    canonical_bytes: Zeroizing<Vec<u8>>,
}

impl PrivateXmrRefundTransactionV11 {
    /// Public hash suitable for binding an encrypted recovery record.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }
    /// Public recovery-graph digest suitable for authenticated encryption AAD.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Closure-only private access for authenticated encryption and recovery.
    /// The caller must not put these bytes into FinalRefund (0x10), logs or a
    /// public store. This method grants no network transmission authority.
    pub fn with_secret_bytes<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.canonical_bytes)
    }
}

impl VerifiedXmrRecoveryGraphV11 {
    /// Exact public fields verified by this graph. Authentication of the
    /// negotiated economic terms remains the caller's separate boundary.
    pub const fn binding(&self) -> &XmrRecoveryGraphBindingV11 {
        &self.binding
    }
    /// Exact cancel and V23 compensation auxiliary IDs for the verified graph
    /// and arithmetic-validated policy. Signatures are projected out through
    /// the native template codec. Store must still authenticate both histories,
    /// the parent terms, identities and custody; these IDs grant nothing.
    pub fn ordinary_recovery_sessions_v23(
        &self,
        policy: &xmr_compensation_policy::ValidatedXmrCompensationPolicyV11,
    ) -> Result<([u8; 32], [u8; 32])> {
        let template_hash = |bytes: &[u8]| -> Result<[u8; 32]> {
            let tx = Transaction::from_bytes(bytes)
                .map_err(|_| XmrRecoveryGraphErrorV11::GraphMismatch)?;
            canonical_template_v1(&tx)
                .map(|(_, hash)| hash)
                .map_err(|_| XmrRecoveryGraphErrorV11::GraphMismatch)
        };
        Ok((
            xmr_ordinary_recovery_session_v12(
                &self.binding,
                XmrOrdinaryRecoveryKindV12::Cancel,
                template_hash(&self.cancel_bytes)?,
            ),
            xmr_bounded_compensation_session_v23(
                &self.binding,
                policy,
                template_hash(&self.punish_bytes)?,
            )
            .map_err(|_| XmrRecoveryGraphErrorV11::GraphMismatch)?,
        ))
    }

    /// Exact native unsigned funding template. It carries no final signature.
    pub const fn funding_template(&self) -> &Transaction {
        &self.funding_template
    }
    /// Exact native unsigned claim template, before any witness completion.
    pub const fn claim_template(&self) -> &Transaction {
        &self.claim_template
    }
    /// Exact native unsigned refund template; it cannot reveal U.
    pub const fn refund_template(&self) -> &Transaction {
        &self.refund_template
    }
    /// Borrow the native reverified public refund equation and nonce context.
    /// A chain scanner must separately authenticate any observed final signature.
    pub const fn refund_pre_signature(&self) -> &VerifiedRefundPreSignatureV1 {
        &self.refund_pre_signature
    }
    /// Revalidate an observed transaction with native consensus at its actual
    /// containing height. The scanner must authenticate that height separately;
    /// this prevents accepting a stored timelocked transaction in an early block.
    /// This mathematical check creates no chain or transmission capability.
    pub fn validate_observed_transaction(
        &self,
        transaction: &Transaction,
        block_height: u64,
    ) -> Result<()> {
        validate_transaction(transaction, &context(&self.binding, block_height))
            .map_err(|_| XmrRecoveryGraphErrorV11::ConsensusRejected)
    }
    /// Digest of exact negotiated fields, all five templates and both public
    /// final transactions. Private final refund bytes are excluded.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Public cancel transaction C -> D. Publication still requires an actual
    /// Store capability and current canonical chain observation.
    pub fn cancel_bytes(&self) -> &[u8] {
        &self.cancel_bytes
    }
    /// Public punish transaction D -> Bob. Its outcome is DOM compensation.
    pub fn punish_bytes(&self) -> &[u8] {
        &self.punish_bytes
    }

    /// Refuse pre-funding compensation: the retired V22 kernel is not part
    /// of DOM consensus. A local funding witness cannot make a presigned
    /// unconditional payout safe against a non-funding counterparty.
    pub fn require_conditional_compensation_v22(&self) -> Result<()> {
        Err(XmrRecoveryGraphErrorV11::GraphMismatch)
    }

    /// Check the mathematical claim window against a supplied DOM height.
    /// The caller must authenticate and freshly revalidate the height; this
    /// helper is not a chain fact or a signing/broadcast authorization.
    pub fn require_claim_window(&self, current_height: u64) -> Result<()> {
        require_window(
            current_height,
            self.binding.reveal_safety_blocks,
            self.binding.cancel_height,
        )
    }
    /// Check the refund reveal window. Cancel must also be canonically final
    /// and D unspent; those chain facts cannot be inferred from a height.
    pub fn require_refund_window(&self, current_height: u64) -> Result<()> {
        if current_height < self.binding.cancel_height {
            return Err(XmrRecoveryGraphErrorV11::RevealWindowClosed);
        }
        require_window(
            current_height,
            self.binding.reveal_safety_blocks,
            self.binding.punish_height,
        )
    }
    /// Complete and consensus-validate the native refund entirely in private.
    /// This is safe to perform before funding only in the U owner's custody.
    /// It neither persists nor publishes the result. Public sharing of the
    /// resulting bytes would reveal U immediately, regardless of lock height.
    pub fn complete_private_refund(
        &self,
        witness: &AdaptorSecret,
    ) -> Result<PrivateXmrRefundTransactionV11> {
        let signature = Zeroizing::new(
            self.refund_pre_signature
                .adapt(witness)
                .map_err(|_| XmrRecoveryGraphErrorV11::RefundAdaptationRejected)?,
        );
        let mut transaction = self.refund_template.clone();
        transaction.kernels[0]
            .excess_signature
            .copy_from_slice(&signature[..]);
        let result = (|| {
            validate_transaction(
                &transaction,
                &context(&self.binding, self.binding.cancel_height),
            )
            .map_err(|_| XmrRecoveryGraphErrorV11::ConsensusRejected)?;
            let canonical_bytes = Zeroizing::new(
                transaction
                    .to_bytes()
                    .map_err(|_| XmrRecoveryGraphErrorV11::NonCanonicalTransaction)?,
            );
            let transaction_hash = *blake2b_256(&canonical_bytes).as_bytes();
            Ok(PrivateXmrRefundTransactionV11 {
                graph_digest: self.graph_digest,
                transaction_hash,
                canonical_bytes,
            })
        })();
        // Transaction is historically a public native type and has no secret
        // Drop implementation. Wipe its signature on both success and error.
        transaction.kernels[0].excess_signature.zeroize();
        result
    }
}

/// Verify the concrete recovery DAG using native DOM consensus and the pinned
/// refund adaptor equation. This does not approve funding or claim signing.
pub fn verify_xmr_recovery_graph_v11(
    request: XmrRecoveryGraphRequestV11<'_>,
) -> Result<VerifiedXmrRecoveryGraphV11> {
    let binding = request.binding;
    if binding.chain_id == [0; 32]
        || binding.session_id == [0; 32]
        || binding.terms_hash == [0; 32]
        || binding.cancel_height == 0
        || binding.reveal_safety_blocks == 0
        || binding
            .cancel_height
            .checked_add(binding.reveal_safety_blocks)
            .filter(|height| *height < binding.punish_height)
            .is_none()
        || binding.claim_adaptor_point == binding.refund_adaptor_point
    {
        return Err(XmrRecoveryGraphErrorV11::InvalidBinding);
    }
    let commitments = [
        binding.funding_commitment,
        binding.cancelled_commitment,
        binding.refund_recipient_commitment,
        binding.punish_recipient_commitment,
    ];
    for (index, point) in commitments.iter().enumerate() {
        if commitments[..index].contains(point) {
            return Err(XmrRecoveryGraphErrorV11::InvalidBinding);
        }
        dom_crypto::pedersen::Commitment::from_compressed_bytes(point)
            .map_err(|_| XmrRecoveryGraphErrorV11::InvalidBinding)?;
    }
    for point in [binding.claim_adaptor_point, binding.refund_adaptor_point] {
        PublicKey::from_compressed_bytes(&point)
            .map_err(|_| XmrRecoveryGraphErrorV11::InvalidBinding)?;
    }
    verify_unsigned(request.funding_template)?;
    verify_unsigned(request.claim_template)?;
    verify_unsigned(request.refund_template)?;
    let cancel = parse_signed(request.cancel_bytes, &binding, binding.cancel_height)?;
    let punish = parse_signed(request.punish_bytes, &binding, binding.punish_height)?;
    let funding = request.funding_template;
    if funding.kernels[0].features != KERNEL_FEAT_PLAIN
        || funding.kernels[0].lock_height != 0
        || funding
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &binding.funding_commitment)
            .count()
            != 1
        || funding
            .inputs
            .iter()
            .any(|input| commitments[..2].contains(input.commitment.as_bytes()))
        || funding
            .outputs
            .iter()
            .any(|output| output.commitment.as_bytes() == &binding.cancelled_commitment)
    {
        return Err(XmrRecoveryGraphErrorV11::GraphMismatch);
    }
    require_spend(
        request.claim_template,
        &binding.funding_commitment,
        None,
        KERNEL_FEAT_PLAIN,
        0,
        None,
    )?;
    require_spend(
        &cancel,
        &binding.funding_commitment,
        Some(&binding.cancelled_commitment),
        KERNEL_FEAT_HEIGHT_LOCKED,
        binding.cancel_height,
        Some(binding.cancel_fee),
    )?;
    require_spend(
        request.refund_template,
        &binding.cancelled_commitment,
        Some(&binding.refund_recipient_commitment),
        KERNEL_FEAT_HEIGHT_LOCKED,
        binding.cancel_height,
        Some(binding.refund_fee),
    )?;
    require_spend(
        &punish,
        &binding.cancelled_commitment,
        Some(&binding.punish_recipient_commitment),
        KERNEL_FEAT_HEIGHT_LOCKED,
        binding.punish_height,
        Some(binding.punish_fee),
    )?;
    if request
        .claim_template
        .outputs
        .iter()
        .any(|output| commitments[..2].contains(output.commitment.as_bytes()))
    {
        return Err(XmrRecoveryGraphErrorV11::GraphMismatch);
    }
    let pre = request.refund_pre_signature;
    let refund = request.refund_template;
    let kernel = &refund.kernels[0];
    let (_, refund_hash) = canonical_template_v1(refund)
        .map_err(|_| XmrRecoveryGraphErrorV11::NonCanonicalTransaction)?;
    if pre.chain_id() != &binding.chain_id
        || pre.session_id() != &binding.session_id
        || pre.template_hash() != &refund_hash
        || pre.refund_adaptor_point() != binding.refund_adaptor_point
        || pre.aggregate_signing_key() != *kernel.excess.as_bytes()
        || pre.kernel_message_digest() != scriptless_kernel_message_digest_v1(kernel).as_bytes()
    {
        return Err(XmrRecoveryGraphErrorV11::RefundPreSignatureMismatch);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(DOMAIN);
    encoded.extend_from_slice(&binding.chain_id);
    encoded.extend_from_slice(&binding.session_id);
    encoded.extend_from_slice(&binding.terms_hash);
    for point in commitments {
        encoded.extend_from_slice(&point);
    }
    encoded.extend_from_slice(&binding.claim_adaptor_point);
    encoded.extend_from_slice(&binding.refund_adaptor_point);
    for integer in [
        binding.cancel_height,
        binding.punish_height,
        binding.reveal_safety_blocks,
        binding.cancel_fee,
        binding.refund_fee,
        binding.punish_fee,
    ] {
        encoded.extend_from_slice(&integer.to_be_bytes());
    }
    for tx in [funding, request.claim_template, &cancel, refund, &punish] {
        let (_, hash) = canonical_template_v1(tx)
            .map_err(|_| XmrRecoveryGraphErrorV11::NonCanonicalTransaction)?;
        encoded.extend_from_slice(&hash);
    }
    encoded.extend_from_slice(blake2b_256(request.cancel_bytes).as_bytes());
    encoded.extend_from_slice(blake2b_256(request.punish_bytes).as_bytes());
    encoded.extend_from_slice(&pre.to_bytes());
    Ok(VerifiedXmrRecoveryGraphV11 {
        binding,
        graph_digest: *blake2b_256(&encoded).as_bytes(),
        cancel_bytes: request.cancel_bytes.to_vec(),
        punish_bytes: request.punish_bytes.to_vec(),
        funding_template: funding.clone(),
        claim_template: request.claim_template.clone(),
        refund_template: refund.clone(),
        refund_pre_signature: pre,
    })
}

fn require_window(height: u64, margin: u64, boundary: u64) -> Result<()> {
    if height
        .checked_add(margin)
        .filter(|sum| *sum < boundary)
        .is_none()
    {
        return Err(XmrRecoveryGraphErrorV11::RevealWindowClosed);
    }
    Ok(())
}

fn context(binding: &XmrRecoveryGraphBindingV11, height: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id: binding.chain_id,
        now: Timestamp(0),
    }
}

fn verify_unsigned(transaction: &Transaction) -> Result<()> {
    if transaction.kernels.len() != 1 || transaction.kernels[0].excess_signature != [0; 65] {
        return Err(XmrRecoveryGraphErrorV11::NonCanonicalTransaction);
    }
    validate_transaction_structure(transaction)
        .and_then(|()| validate_public_range_proofs_v24(transaction))
        .and_then(|()| validate_balance_equation(transaction))
        .map_err(|_| XmrRecoveryGraphErrorV11::ConsensusRejected)
}

fn parse_signed(
    bytes: &[u8],
    binding: &XmrRecoveryGraphBindingV11,
    height: u64,
) -> Result<Transaction> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(XmrRecoveryGraphErrorV11::NonCanonicalTransaction);
    }
    let transaction = Transaction::from_bytes(bytes)
        .map_err(|_| XmrRecoveryGraphErrorV11::NonCanonicalTransaction)?;
    if transaction
        .to_bytes()
        .map_err(|_| XmrRecoveryGraphErrorV11::NonCanonicalTransaction)?
        != bytes
    {
        return Err(XmrRecoveryGraphErrorV11::NonCanonicalTransaction);
    }
    validate_transaction(&transaction, &context(binding, height))
        .map_err(|_| XmrRecoveryGraphErrorV11::ConsensusRejected)?;
    Ok(transaction)
}

fn require_spend(
    transaction: &Transaction,
    input: &[u8; 33],
    output: Option<&[u8; 33]>,
    features: u8,
    height: u64,
    fee: Option<u64>,
) -> Result<()> {
    if transaction.inputs.len() != 1
        || transaction.kernels.len() != 1
        || transaction.inputs[0].commitment.as_bytes() != input
        || transaction.kernels[0].features != features
        || transaction.kernels[0].lock_height != height
        || transaction
            .outputs
            .iter()
            .any(|candidate| candidate.commitment.as_bytes() == input)
        || output.is_some_and(|expected| {
            transaction.outputs.len() != 1
                || transaction.outputs[0].commitment.as_bytes() != expected
        })
    {
        return Err(XmrRecoveryGraphErrorV11::GraphMismatch);
    }
    if fee.is_some_and(|expected| transaction.kernels[0].fee.noms() != expected) {
        return Err(XmrRecoveryGraphErrorV11::FeeMismatch);
    }
    Ok(())
}
