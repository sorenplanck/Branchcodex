//! Produce ordinary cancel and compensation signatures from the native
//! two-party nonce and partial-signature protocol. No final-signature import
//! constructor exists. Store separately authenticates the transport history.

use super::{context, verify_unsigned, XmrRecoveryGraphBindingV11};
use dom_adaptor::{
    aggregate_public_nonces_v1, binding_factor_v1, canonical_template_v1,
    finalize_plain_signature_v1, BindingContextV1, PartialSignatureV1, ParticipantPublicNoncesV1,
    PurposeV1,
};
use dom_consensus::{validate_transaction, Transaction};
use dom_crypto::{blake2b_256, PublicKey};
use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
use dom_serialization::DomSerialize;
use xmr_compensation_policy::ValidatedXmrCompensationPolicyV11;

/// Only ordinary signatures may terminate these recovery edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrOrdinaryRecoveryKindV12 {
    /// C -> D at the cooperative cancellation height.
    Cancel,
    /// D -> XMR funder at the later compensation height. Does not reveal T.
    Compensation,
}

/// Native refusal; missing transport material is classified by the Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrOrdinaryRecoveryErrorV12 {
    /// Session, role, template, kernel or roster differs from the graph.
    Binding,
    /// Legacy compensation lacks a DOM-consensus-verifiable XMR funding condition.
    FundingConditionUnavailable,
    /// A participant nonce has appeared in another graph round.
    NonceReuse,
    /// The native per-participant equation or final consensus check failed.
    Signature,
}

impl core::fmt::Display for XmrOrdinaryRecoveryErrorV12 {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str(match self {
            Self::FundingConditionUnavailable => {
                "unconditional XMR compensation production is disabled"
            }
            Self::Binding => "XMR ordinary recovery round binding mismatch",
            Self::NonceReuse => "XMR recovery nonce reused across rounds",
            Self::Signature => "XMR ordinary recovery signature rejected",
        })
    }
}
impl std::error::Error for XmrOrdinaryRecoveryErrorV12 {}
type Result<T> = core::result::Result<T, XmrOrdinaryRecoveryErrorV12>;

/// Domain-separated auxiliary session identity, agreed before nonce creation.
/// This is an identifier only and cannot authorize or synthesize a Store session.
pub fn xmr_ordinary_recovery_session_v12(
    graph: &XmrRecoveryGraphBindingV11,
    kind: XmrOrdinaryRecoveryKindV12,
    template_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(180);
    bytes.extend_from_slice(b"DOM-INTEROP/XMR-ORDINARY-SESSION/V12\0");
    bytes.extend_from_slice(&graph.chain_id);
    bytes.extend_from_slice(&graph.session_id);
    bytes.extend_from_slice(&graph.terms_hash);
    bytes.push(match kind {
        XmrOrdinaryRecoveryKindV12::Cancel => 1,
        XmrOrdinaryRecoveryKindV12::Compensation => 2,
    });
    bytes.extend_from_slice(&template_hash);
    *blake2b_256(&bytes).as_bytes()
}

/// V23 auxiliary identity, binding the explicit bounded compensation policy.
/// This function names a session; it does not authenticate terms or authorize signing.
pub fn xmr_compensation_session_v23(
    graph: &XmrRecoveryGraphBindingV11,
    template_hash: [u8; 32],
    policy_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = b"DOM-INTEROP/XMR-COMPENSATION-SESSION/V23\0".to_vec();
    bytes.extend_from_slice(&xmr_ordinary_recovery_session_v12(
        graph,
        XmrOrdinaryRecoveryKindV12::Compensation,
        template_hash,
    ));
    bytes.extend_from_slice(&policy_hash);
    *blake2b_256(&bytes).as_bytes()
}

/// Derive the V23 identity only after checking the validated policy's graph scope.
/// This does not authenticate terms, create a Store session, or authorize signing.
pub fn xmr_bounded_compensation_session_v23(
    graph: &XmrRecoveryGraphBindingV11,
    policy: &ValidatedXmrCompensationPolicyV11,
    template_hash: [u8; 32],
) -> Result<[u8; 32]> {
    let policy_hash = require_bounded_compensation_policy_v23(graph, policy)?;
    if template_hash == [0; 32] {
        return Err(XmrOrdinaryRecoveryErrorV12::Binding);
    }
    Ok(xmr_compensation_session_v23(
        graph,
        template_hash,
        policy_hash,
    ))
}

/// Native ordinary round. Secret nonces and participant keys remain in their
/// own nonce vaults; this object handles authenticated public round material.
pub struct XmrOrdinaryRecoveryRoundV12 {
    binding: XmrRecoveryGraphBindingV11,
    kind: XmrOrdinaryRecoveryKindV12,
    context: BindingContextV1,
    transaction: Transaction,
    participants: Vec<ParticipantPublicNoncesV1>,
    effective_nonces: Vec<PublicKey>,
    aggregate_nonce: PublicKey,
    aggregate_key: PublicKey,
    message: [u8; 32],
    bounded_policy_hash: Option<[u8; 32]>,
}

impl XmrOrdinaryRecoveryRoundV12 {
    /// Compatibility entry for local funding evidence. Compensation remains
    /// refused under the V13 rule; no consensus extension is available.
    pub fn begin_with_funding_v22(
        binding: XmrRecoveryGraphBindingV11,
        kind: XmrOrdinaryRecoveryKindV12,
        transaction: &Transaction,
        participants: &[ParticipantPublicNoncesV1],
        funding_witness: Option<&XmrCompensationFundingWitnessV22>,
    ) -> Result<Self> {
        require_ordinary_recovery_kind_admitted_v22(kind, &binding, transaction, funding_witness)?;
        Self::begin_admitted_v22(binding, kind, transaction, participants, None)
    }

    /// Begin the exact ordinary signing equation under the V13 rule.
    /// Compensation is always refused, including with local funding evidence.
    pub fn begin(
        binding: XmrRecoveryGraphBindingV11,
        kind: XmrOrdinaryRecoveryKindV12,
        transaction: &Transaction,
        participants: &[ParticipantPublicNoncesV1],
    ) -> Result<Self> {
        require_safe_ordinary_recovery_kind_v13(kind)?;
        Self::begin_admitted_v22(binding, kind, transaction, participants, None)
    }

    /// Begin ordinary compensation with the arithmetic/scope-validated V23
    /// policy, never a local funding marker. No secrets are received here.
    /// Store must separately authenticate both parties' terms, wallet ownership,
    /// nonce custody and transcript before allowing their partial signatures.
    /// This mathematical round is not a funding or broadcast authorization.
    pub fn begin_bounded_compensation_v23(
        binding: XmrRecoveryGraphBindingV11,
        policy: &ValidatedXmrCompensationPolicyV11,
        transaction: &Transaction,
        participants: &[ParticipantPublicNoncesV1],
    ) -> Result<Self> {
        let policy_hash = require_bounded_compensation_policy_v23(&binding, policy)?;
        Self::begin_admitted_v22(
            binding,
            XmrOrdinaryRecoveryKindV12::Compensation,
            transaction,
            participants,
            Some(policy_hash),
        )
    }

    /// Shared body once the kind is admitted. Private on purpose: admission
    /// happens in the public entries above, never here.
    fn begin_admitted_v22(
        binding: XmrRecoveryGraphBindingV11,
        kind: XmrOrdinaryRecoveryKindV12,
        transaction: &Transaction,
        participants: &[ParticipantPublicNoncesV1],
        bounded_policy_hash: Option<[u8; 32]>,
    ) -> Result<Self> {
        verify_unsigned(transaction).map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        if participants.len() != 2
            || binding.chain_id == [0; 32]
            || binding.session_id == [0; 32]
            || binding.terms_hash == [0; 32]
        {
            return Err(XmrOrdinaryRecoveryErrorV12::Binding);
        }
        let (input, output, height, fee) = match kind {
            XmrOrdinaryRecoveryKindV12::Cancel => (
                binding.funding_commitment,
                binding.cancelled_commitment,
                binding.cancel_height,
                binding.cancel_fee,
            ),
            XmrOrdinaryRecoveryKindV12::Compensation => (
                binding.cancelled_commitment,
                binding.punish_recipient_commitment,
                binding.punish_height,
                binding.punish_fee,
            ),
        };
        super::require_spend(
            transaction,
            &input,
            Some(&output),
            dom_core::KERNEL_FEAT_HEIGHT_LOCKED,
            height,
            Some(fee),
        )
        .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        let (_, template_hash) =
            canonical_template_v1(transaction).map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        let context = BindingContextV1 {
            chain_id: binding.chain_id,
            session_id: match bounded_policy_hash {
                Some(hash) => xmr_compensation_session_v23(&binding, template_hash, hash),
                None => xmr_ordinary_recovery_session_v12(&binding, kind, template_hash),
            },
            purpose: PurposeV1::Refund,
            template_hash,
        };
        let factor = binding_factor_v1(&context, participants, None)
            .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        let effective_nonces = participants
            .iter()
            .map(|participant| {
                factor
                    .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
                    .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)
            .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        let aggregate_key = aggregate_public_nonces_v1(
            &participants
                .iter()
                .map(|participant| participant.signing_key.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
        let kernel = &transaction.kernels[0];
        if aggregate_key.to_compressed_bytes() != *kernel.excess.as_bytes() {
            return Err(XmrOrdinaryRecoveryErrorV12::Binding);
        }
        let message = *scriptless_kernel_message_digest_v1(kernel).as_bytes();
        Ok(Self {
            binding,
            kind,
            context,
            transaction: transaction.clone(),
            participants: participants.to_vec(),
            effective_nonces,
            aggregate_nonce,
            aggregate_key,
            message,
            bounded_policy_hash,
        })
    }

    /// Exact native context which the retained auxiliary Store must authorize.
    pub const fn context(&self) -> &BindingContextV1 {
        &self.context
    }

    /// Aggregate two native checked partials into an ordinary Schnorr
    /// transaction. There is deliberately no adaptor completion alternative.
    pub fn complete(
        self,
        partials: &[PartialSignatureV1],
    ) -> Result<CompletedXmrOrdinaryRecoveryRoundV12> {
        if partials.len() != self.participants.len() {
            return Err(XmrOrdinaryRecoveryErrorV12::Signature);
        }
        for (index, (partial, participant)) in partials.iter().zip(&self.participants).enumerate() {
            if partial.participant_index() != participant.participant_index
                || !partial
                    .verify_bound(
                        PurposeV1::Refund,
                        &self.context.template_hash,
                        &self.effective_nonces[index],
                        &participant.signing_key,
                        &self.aggregate_nonce,
                        &self.aggregate_key,
                        &self.binding.chain_id,
                        &self.message,
                    )
                    .map_err(|_| XmrOrdinaryRecoveryErrorV12::Signature)?
            {
                return Err(XmrOrdinaryRecoveryErrorV12::Signature);
            }
        }
        let signature = finalize_plain_signature_v1(
            partials,
            PurposeV1::Refund,
            &self.context.template_hash,
            &self.aggregate_nonce,
            &self.aggregate_key,
            &self.binding.chain_id,
            &self.message,
        )
        .map_err(|_| XmrOrdinaryRecoveryErrorV12::Signature)?;
        let mut transaction = self.transaction;
        transaction.kernels[0].excess_signature = signature.to_bytes();
        if self.bounded_policy_hash.is_none() {
            require_safe_ordinary_recovery_kind_v13(self.kind)?;
        }
        validate_transaction(
            &transaction,
            &context(&self.binding, transaction.kernels[0].lock_height),
        )
        .map_err(|_| XmrOrdinaryRecoveryErrorV12::Signature)?;
        let bytes = transaction
            .to_bytes()
            .map_err(|_| XmrOrdinaryRecoveryErrorV12::Signature)?;
        Ok(CompletedXmrOrdinaryRecoveryRoundV12 {
            kind: self.kind,
            context: self.context,
            participants: self.participants,
            bytes,
        })
    }
}

/// Native ordinary-round result, unavailable from final signature bytes alone.
/// A separate same-Store audit still authenticates identities and journal history.
pub struct CompletedXmrOrdinaryRecoveryRoundV12 {
    kind: XmrOrdinaryRecoveryKindV12,
    context: BindingContextV1,
    participants: Vec<ParticipantPublicNoncesV1>,
    bytes: Vec<u8>,
}

impl CompletedXmrOrdinaryRecoveryRoundV12 {
    /// Exact ordinary recovery purpose.
    pub const fn kind(&self) -> XmrOrdinaryRecoveryKindV12 {
        self.kind
    }
    /// Exact auxiliary native session and template context.
    pub const fn context(&self) -> &BindingContextV1 {
        &self.context
    }
    /// Public ordinary cancellation or explicitly V23-scoped compensation.
    /// Legacy V13/V22 constructors still refuse compensation.
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Non-secret roster for cross-round nonce collision checks.
    pub fn public_nonces(&self) -> &[ParticipantPublicNoncesV1] {
        &self.participants
    }
}

/// Refuse any nonce reuse across cancellation, compensation, refund or claim.
/// Both positions of every pair are compared, regardless of participant index.
pub fn require_distinct_xmr_recovery_nonces_v12(
    rounds: &[&[ParticipantPublicNoncesV1]],
) -> Result<()> {
    let mut seen = Vec::new();
    for round in rounds {
        if round.len() != 2 {
            return Err(XmrOrdinaryRecoveryErrorV12::Binding);
        }
        for participant in *round {
            for nonce in [&participant.first_nonce, &participant.second_nonce] {
                let bytes = nonce.to_compressed_bytes();
                if seen.contains(&bytes) {
                    return Err(XmrOrdinaryRecoveryErrorV12::NonceReuse);
                }
                seen.push(bytes);
            }
        }
    }
    Ok(())
}

/// Advisory scope marker retained for source compatibility with the supplied V22.
/// Its public constructor does not verify funding and confers no authority.
/// The retired conditional kernel grants nothing: compensation admission is
/// refused even when this marker is present.
pub struct XmrCompensationFundingWitnessV22 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    funding_id: [u8; 32],
}

impl XmrCompensationFundingWitnessV22 {
    /// Builds an advisory nonzero scope marker; does not authorize payment.
    pub fn from_authorized_observation_v22(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        terms_hash: [u8; 32],
        funding_id: [u8; 32],
    ) -> Result<Self> {
        if chain_id == [0; 32]
            || session_id == [0; 32]
            || terms_hash == [0; 32]
            || funding_id == [0; 32]
        {
            return Err(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable);
        }
        Ok(Self {
            chain_id,
            session_id,
            terms_hash,
            funding_id,
        })
    }

    /// The exact funding transaction id hash this witness stands for.
    pub fn funding_id(&self) -> [u8; 32] {
        self.funding_id
    }
}

/// Preserve the V13 refusal after retiring the V22 consensus extension.
/// Local funding evidence does not authorize a pre-signed compensation.
pub fn require_ordinary_recovery_kind_admitted_v22(
    kind: XmrOrdinaryRecoveryKindV12,
    _binding: &XmrRecoveryGraphBindingV11,
    _transaction: &Transaction,
    _funding_witness: Option<&XmrCompensationFundingWitnessV22>,
) -> Result<()> {
    require_safe_ordinary_recovery_kind_v13(kind)
}

/// Reject the legacy unconditional compensation edge before allocating any
/// signing authority. Existing archived transactions remain consensus-valid:
/// this restriction prevents new production; it does not revoke signatures.
pub fn require_safe_ordinary_recovery_kind_v13(kind: XmrOrdinaryRecoveryKindV12) -> Result<()> {
    match kind {
        XmrOrdinaryRecoveryKindV12::Cancel => Ok(()),
        XmrOrdinaryRecoveryKindV12::Compensation => {
            Err(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable)
        }
    }
}

/// Shared arithmetic/scope check for signing and read-only transcript identity.
pub(super) fn require_bounded_compensation_policy_v23(
    binding: &XmrRecoveryGraphBindingV11,
    policy: &ValidatedXmrCompensationPolicyV11,
) -> Result<[u8; 32]> {
    let signed = policy.policy();
    if signed.bounded_availability_v23.is_none() {
        return Err(XmrOrdinaryRecoveryErrorV12::FundingConditionUnavailable);
    }
    if binding.chain_id != signed.dom_chain_id
        || binding.session_id != signed.session_id
        || &binding.terms_hash != policy.terms_hash()
        || binding.cancel_height != signed.cancel_height
        || binding.punish_height != signed.compensation_height
        || binding.reveal_safety_blocks != signed.reveal_safety_blocks
        || binding.cancel_fee != signed.cancel_fee_noms
        || binding.refund_fee != signed.refund_fee_noms
        || binding.punish_fee != signed.compensation_fee_noms
        || binding.refund_recipient_commitment != signed.refund_recipient_commitment
        || binding.punish_recipient_commitment != signed.compensation_recipient_commitment
    {
        return Err(XmrOrdinaryRecoveryErrorV12::Binding);
    }
    let policy_hash = signed
        .policy_hash()
        .map_err(|_| XmrOrdinaryRecoveryErrorV12::Binding)?;
    Ok(policy_hash)
}
