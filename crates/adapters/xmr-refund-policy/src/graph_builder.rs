//! Construct the native five-transaction XMR recovery graph from separate
//! collateral and cancellation shared outputs. The builder performs real DOM
//! transaction formation and completes the native public signing rounds. It
//! never owns participant signing keys and never issues funding authority.

use super::compensation::{ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11};
use super::economic_graph::{
    verify_xmr_economic_recovery_graph_v11, VerifiedXmrEconomicRecoveryGraphV11,
    XmrPayoutValueProofV11,
};
use dom_adaptor::{PartialSignatureV1, ScriptlessTransactionTemplateV1, VerifiedSharedOutputV1};
use dom_consensus::{Transaction, TransactionInput, TransactionKernel, TransactionOutput};
use dom_core::{Amount, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{blake2b_256, pedersen::Commitment, PublicKey};
use dom_scriptless_crypto::{
    require_distinct_xmr_recovery_nonces_v12, verify_xmr_recovery_graph_v11,
    xmr_ordinary_recovery_session_v12, CompletedXmrOrdinaryRecoveryRoundV12, FrozenSharedOutputV1,
    RefundAdaptorRoundV1, VerifiedXmrRecoveryGraphV11, XmrOrdinaryRecoveryKindV12,
    XmrRecoveryGraphBindingV11, XmrRecoveryGraphRequestV11,
};
use kaystra_core::terms::SettlementTermsV1;

/// Public kernel data composed by participant wallets. Native balance checks
/// ensure the key and offset match the exact transaction being constructed.
pub struct XmrGraphKernelContributionV12 {
    /// Aggregate of the authenticated participant excess public keys.
    pub excess: PublicKey,
    /// Aggregate native offset contribution, never a private signing share.
    pub offset: [u8; 32],
}

/// Exact output and kernel material supplied by the bilateral wallet protocol.
/// Funding inputs must be reserved by the DOM funder's authenticated wallet;
/// no inputs are invented or selected by this mathematical builder.
pub struct XmrGraphTemplateMaterialV12<'a> {
    /// Frozen proof of C's shared ownership and exact collateral value.
    pub collateral: FrozenSharedOutputV1,
    /// Real collaborative range proof for C.
    pub collateral_output: &'a VerifiedSharedOutputV1,
    /// Frozen independent shared ownership and exact cancelled value D.
    pub cancelled: FrozenSharedOutputV1,
    /// Real independent collaborative range proof for D.
    pub cancelled_output: &'a VerifiedSharedOutputV1,
    /// Reserved native wallet inputs for funding C.
    pub funding_inputs: Vec<TransactionInput>,
    /// Optional ordinary wallet change from the funding transaction.
    pub funding_change: Vec<TransactionOutput>,
    /// Negotiated funding fee in native noms.
    pub funding_fee_noms: u64,
    /// Actual tip used to negotiate the graph; refreshed again by funding gate.
    pub negotiated_tip: u64,
    /// Principal payout with native range proof.
    pub claim_principal: TransactionOutput,
    /// Margin/change payout with native range proof.
    pub claim_change: TransactionOutput,
    /// DOM-funder refund payout with native range proof.
    pub refund_payout: TransactionOutput,
    /// XMR-funder compensation payout with native range proof.
    pub compensation_payout: TransactionOutput,
    /// Native value/ownership proofs for principal then change.
    pub payout_value_proofs: [XmrPayoutValueProofV11; 2],
    /// Public native kernel and offset composition for each distinct edge.
    pub funding_kernel: XmrGraphKernelContributionV12,
    /// Normal claim C -> principal + margin change, eventually adaptor T.
    pub claim_kernel: XmrGraphKernelContributionV12,
    /// Ordinary cancellation C -> D.
    pub cancel_kernel: XmrGraphKernelContributionV12,
    /// Cooperative refund D -> DOM funder, eventually adaptor U.
    pub refund_kernel: XmrGraphKernelContributionV12,
    /// Ordinary compensation D -> XMR funder.
    pub compensation_kernel: XmrGraphKernelContributionV12,
    /// Authenticated setup refund point U, distinct from T in signed terms.
    pub refund_adaptor_point: [u8; 33],
}

/// Built templates awaiting native bilateral signing. No final signature and
/// no witness are present in this object or its public template accessors.
pub struct XmrRecoveryGraphTemplatesV12 {
    terms: SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    binding: XmrRecoveryGraphBindingV11,
    negotiated_tip: u64,
    collateral: FrozenSharedOutputV1,
    cancelled: FrozenSharedOutputV1,
    payouts: [XmrPayoutValueProofV11; 2],
    funding: ScriptlessTransactionTemplateV1,
    claim: ScriptlessTransactionTemplateV1,
    cancel: ScriptlessTransactionTemplateV1,
    refund: ScriptlessTransactionTemplateV1,
    compensation: ScriptlessTransactionTemplateV1,
}

/// Complete native graph and its verified economic and shared-output evidence.
/// Store must still audit ordinary auxiliary histories and bilateral readiness.
pub struct ProducedXmrRecoveryGraphV12 {
    graph: VerifiedXmrRecoveryGraphV11,
    economic: VerifiedXmrEconomicRecoveryGraphV11,
    collateral: FrozenSharedOutputV1,
    cancelled: FrozenSharedOutputV1,
    cancel_session: [u8; 32],
    compensation_session: [u8; 32],
}

impl ProducedXmrRecoveryGraphV12 {
    /// Native graph produced from ordinary and adaptor partial signatures.
    pub const fn graph(&self) -> &VerifiedXmrRecoveryGraphV11 {
        &self.graph
    }
    /// Exact value/recipient evidence checked against signed assurance terms.
    pub const fn economic(&self) -> &VerifiedXmrEconomicRecoveryGraphV11 {
        &self.economic
    }
    /// Native proof of both owners and the full prefunded collateral value.
    pub const fn collateral(&self) -> &FrozenSharedOutputV1 {
        &self.collateral
    }
    /// Native proof of the independent jointly controlled cancellation output.
    pub const fn cancelled(&self) -> &FrozenSharedOutputV1 {
        &self.cancelled
    }
    /// Exact auxiliary ordinary signing session IDs for same-Store audit.
    pub const fn ordinary_sessions(&self) -> ([u8; 32], [u8; 32]) {
        (self.cancel_session, self.compensation_session)
    }
}

/// C and D cannot reuse a shared-blinding/Bulletproof session. This public
/// identity must be passed into a real separate native initialization round.
pub fn xmr_cancelled_output_session_v12(policy: &ValidatedXmrCompensationPolicyV11) -> [u8; 32] {
    dom_scriptless_crypto::xmr_cancelled_output_session_id_v22(
        &policy.policy().dom_chain_id,
        &policy.policy().session_id,
        policy.terms_hash(),
    )
}

impl XmrRecoveryGraphTemplatesV12 {
    /// Construct all five native templates, fixing fees, two success outputs,
    /// C/D ancestry and reveal deadlines before any signing round begins.
    pub fn build(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        material: XmrGraphTemplateMaterialV12<'_>,
    ) -> Result<Self, XmrCompensationPolicyErrorV11> {
        let policy = policy.policy().validate_for(terms)?;
        let signed = policy.policy();
        let c = &material.collateral;
        let d = &material.cancelled;
        let roster = [terms.roster[0].0, terms.roster[1].0];
        if c.value_noms() != policy.collateral_noms()
            || d.value_noms() != policy.cancelled_noms()
            || c.terms_hash() != policy.terms_hash()
            || d.terms_hash() != policy.terms_hash()
            || c.statement().chain_id() != signed.dom_chain_id
            || d.statement().chain_id() != signed.dom_chain_id
            || c.statement().session_id() != signed.session_id
            || d.statement().session_id() != xmr_cancelled_output_session_v12(&policy)
            || c.statement().participant_ids() != roster.as_slice()
            || d.statement().participant_ids() != roster.as_slice()
            || !matches_capsule(c, material.collateral_output)?
            || !matches_capsule(d, material.cancelled_output)?
            || c.aggregate_commitment() == d.aggregate_commitment()
            || c.aggregate_commitment() != material.collateral_output.commitment()
            || d.aggregate_commitment() != material.cancelled_output.commitment()
            || material.claim_principal.commitment.as_bytes() != &signed.claim_principal_commitment
            || material.claim_change.commitment.as_bytes() != &signed.claim_change_commitment
            || material.refund_payout.commitment.as_bytes() != &signed.refund_recipient_commitment
            || material.compensation_payout.commitment.as_bytes()
                != &signed.compensation_recipient_commitment
            || material
                .negotiated_tip
                .checked_add(signed.reveal_safety_blocks)
                .filter(|height| *height < signed.cancel_height)
                .is_none()
            || u128::from(material.funding_fee_noms) > terms.fee_limit.dom_max
            || material.refund_adaptor_point == terms.adaptor_point_sec1
        {
            return Err(XmrCompensationPolicyErrorV11::GraphMismatch);
        }
        PublicKey::from_compressed_bytes(&material.refund_adaptor_point)
            .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let binding = XmrRecoveryGraphBindingV11 {
            chain_id: signed.dom_chain_id,
            session_id: signed.session_id,
            terms_hash: *policy.terms_hash(),
            funding_commitment: *c.aggregate_commitment(),
            cancelled_commitment: *d.aggregate_commitment(),
            refund_recipient_commitment: signed.refund_recipient_commitment,
            punish_recipient_commitment: signed.compensation_recipient_commitment,
            claim_adaptor_point: terms.adaptor_point_sec1,
            refund_adaptor_point: material.refund_adaptor_point,
            cancel_height: signed.cancel_height,
            punish_height: signed.compensation_height,
            reveal_safety_blocks: signed.reveal_safety_blocks,
            cancel_fee: signed.cancel_fee_noms,
            refund_fee: signed.refund_fee_noms,
            punish_fee: signed.compensation_fee_noms,
        };
        let funding = ScriptlessTransactionTemplateV1::funding(
            material.collateral_output,
            material.funding_inputs,
            material.funding_change,
            0,
            kernel(&material.funding_kernel, material.funding_fee_noms, None)?,
            material.funding_kernel.offset,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let claim = ScriptlessTransactionTemplateV1::claim(
            material.collateral_output,
            vec![material.claim_principal, material.claim_change],
            kernel(&material.claim_kernel, signed.claim_fee_noms, None)?,
            material.claim_kernel.offset,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let cancel = ScriptlessTransactionTemplateV1::refund(
            material.collateral_output,
            vec![material.cancelled_output.output().clone()],
            kernel(
                &material.cancel_kernel,
                signed.cancel_fee_noms,
                Some(signed.cancel_height),
            )?,
            material.cancel_kernel.offset,
            material.negotiated_tip,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let refund = ScriptlessTransactionTemplateV1::refund(
            material.cancelled_output,
            vec![material.refund_payout],
            kernel(
                &material.refund_kernel,
                signed.refund_fee_noms,
                Some(signed.cancel_height),
            )?,
            material.refund_kernel.offset,
            material.negotiated_tip,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let compensation = ScriptlessTransactionTemplateV1::refund(
            material.cancelled_output,
            vec![material.compensation_payout],
            kernel(
                &material.compensation_kernel,
                signed.compensation_fee_noms,
                Some(signed.compensation_height),
            )?,
            material.compensation_kernel.offset,
            material.negotiated_tip,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        Ok(Self {
            terms: terms.clone(),
            policy,
            binding,
            negotiated_tip: material.negotiated_tip,
            collateral: material.collateral,
            cancelled: material.cancelled,
            payouts: material.payout_value_proofs,
            funding,
            claim,
            cancel,
            refund,
            compensation,
        })
    }

    /// Historical negotiation height, not a current chain observation or time grant.
    pub const fn negotiated_tip_v22(&self) -> u64 {
        self.negotiated_tip
    }

    /// Public graph scope required by each distinct native signing session.
    pub const fn binding(&self) -> &XmrRecoveryGraphBindingV11 {
        &self.binding
    }
    /// Arithmetic-validated policy retained with the exact negotiated terms.
    /// Authentication and signing authority remain the wallet/Store's responsibility.
    pub const fn policy(&self) -> &ValidatedXmrCompensationPolicyV11 {
        &self.policy
    }

    /// Exact V23 compensation identity; not a signing or funding grant.
    pub fn compensation_session_v23(&self) -> Result<[u8; 32], XmrCompensationPolicyErrorV11> {
        let policy = self.policy.policy().validate_for(&self.terms)?;
        dom_scriptless_crypto::xmr_bounded_compensation_session_v23(
            &self.binding,
            &policy,
            *self.compensation.template_hash(),
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)
    }

    /// Unsigned funding; this accessor does not authorize its signature.
    pub fn funding(&self) -> &Transaction {
        self.funding.transaction_template()
    }
    /// Unsigned claim; adaptor T is negotiated only after canonical anchors.
    pub fn claim(&self) -> &Transaction {
        self.claim.transaction_template()
    }
    /// Unsigned ordinary cancel C -> D.
    pub fn cancel(&self) -> &Transaction {
        self.cancel.transaction_template()
    }
    /// Unsigned cooperative adaptor-U refund from D.
    pub fn refund(&self) -> &Transaction {
        self.refund.transaction_template()
    }
    /// Unsigned ordinary compensation from D; never an adaptor-T edge.
    pub fn compensation(&self) -> &Transaction {
        self.compensation.transaction_template()
    }

    /// Begin the ordinary V23 compensation equation with this builder's
    /// validated policy and exact template. Wallet/Store signing authorization
    /// is separate; this method never receives signing keys or secret nonces.
    pub fn begin_compensation_round_v23(
        &self,
        participants: &[dom_adaptor::ParticipantPublicNoncesV1],
    ) -> Result<dom_scriptless_crypto::XmrOrdinaryRecoveryRoundV12, XmrCompensationPolicyErrorV11>
    {
        let policy = self.policy.policy().validate_for(&self.terms)?;
        dom_scriptless_crypto::XmrOrdinaryRecoveryRoundV12::begin_bounded_compensation_v23(
            self.binding,
            &policy,
            self.compensation(),
            participants,
        )
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)
    }

    /// Assemble the graph from native checked ordinary and refund-adaptor
    /// partials. Final refund adaptation is deliberately absent: it belongs
    /// exclusively to the U owner's private custody handoff.
    pub fn complete(
        self,
        cancel: CompletedXmrOrdinaryRecoveryRoundV12,
        compensation: CompletedXmrOrdinaryRecoveryRoundV12,
        refund_round: &RefundAdaptorRoundV1,
        refund_partials: &[PartialSignatureV1],
    ) -> Result<ProducedXmrRecoveryGraphV12, XmrCompensationPolicyErrorV11> {
        let cancel_session = xmr_ordinary_recovery_session_v12(
            &self.binding,
            XmrOrdinaryRecoveryKindV12::Cancel,
            *self.cancel.template_hash(),
        );
        let compensation_session = self.compensation_session_v23()?;
        if cancel.kind() != XmrOrdinaryRecoveryKindV12::Cancel
            || compensation.kind() != XmrOrdinaryRecoveryKindV12::Compensation
            || cancel.context().session_id != cancel_session
            || compensation.context().session_id != compensation_session
            || cancel.context().template_hash != *self.cancel.template_hash()
            || compensation.context().template_hash != *self.compensation.template_hash()
        {
            return Err(XmrCompensationPolicyErrorV11::GraphMismatch);
        }
        let refund_pre = refund_round
            .aggregate_pre_signature_v1(refund_partials)
            .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        require_distinct_xmr_recovery_nonces_v12(&[
            cancel.public_nonces(),
            compensation.public_nonces(),
            refund_pre.public_nonce_roster_v11(),
        ])
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let graph = verify_xmr_recovery_graph_v11(XmrRecoveryGraphRequestV11 {
            binding: self.binding,
            funding_template: self.funding.transaction_template(),
            claim_template: self.claim.transaction_template(),
            cancel_bytes: cancel.transaction_bytes(),
            refund_template: self.refund.transaction_template(),
            refund_pre_signature: refund_pre,
            punish_bytes: compensation.transaction_bytes(),
        })
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?;
        let economic = verify_xmr_economic_recovery_graph_v11(
            &self.terms,
            self.policy,
            &graph,
            &self.collateral,
            &self.payouts,
        )?;
        Ok(ProducedXmrRecoveryGraphV12 {
            graph,
            economic,
            collateral: self.collateral,
            cancelled: self.cancelled,
            cancel_session,
            compensation_session,
        })
    }
}

fn matches_capsule(
    frozen: &FrozenSharedOutputV1,
    output: &VerifiedSharedOutputV1,
) -> Result<bool, XmrCompensationPolicyErrorV11> {
    let capsule = output
        .output()
        .recovery_capsule()
        .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?
        .ok_or(XmrCompensationPolicyErrorV11::GraphMismatch)?;
    Ok(frozen.statement().recovery_binding_hash() == blake2b_256(capsule.as_bytes()).as_bytes())
}

fn kernel(
    public: &XmrGraphKernelContributionV12,
    fee: u64,
    height: Option<u64>,
) -> Result<TransactionKernel, XmrCompensationPolicyErrorV11> {
    Ok(TransactionKernel {
        features: if height.is_some() {
            KERNEL_FEAT_HEIGHT_LOCKED
        } else {
            KERNEL_FEAT_PLAIN
        },
        fee: Amount::from_noms(fee).map_err(|_| XmrCompensationPolicyErrorV11::InvalidBounds)?,
        lock_height: height.unwrap_or(0),
        excess: Commitment::from_compressed_bytes(&public.excess.to_compressed_bytes())
            .map_err(|_| XmrCompensationPolicyErrorV11::GraphMismatch)?,
        excess_signature: [0; 65],
    })
}
