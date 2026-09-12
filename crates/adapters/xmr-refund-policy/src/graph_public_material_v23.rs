//! Shared reconstruction of both public offers for runtime and durable audit.
//! This material is neither peer authentication nor signing/funding authority.
use crate::{
    compensation::{ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyErrorV11 as Error},
    economic_graph::XmrPayoutValueProofV11,
    graph_builder::{
        XmrGraphKernelContributionV12, XmrGraphTemplateMaterialV12, XmrRecoveryGraphTemplatesV12,
    },
    graph_offer_v22::{XmrGraphOfferScopeV22, XmrGraphOfferV22},
    graph_signing_keys_v22::{
        XmrGraphKeyMaterialV22, XmrGraphSigningKeysV22, XmrGraphSigningStageV22,
    },
    payout_offer_v22::XmrPolicyPayoutOfferV22,
};
use dom_consensus::{TransactionInput, TransactionOutput};
use kaystra_core::SettlementTermsV1;

/// Public inputs to the five-edge builder, not a balanced or signed graph.
pub struct XmrGraphPublicMaterialV23 {
    /// DOM funder's ordinary wallet inputs.
    pub funding_inputs: Vec<TransactionInput>,
    /// DOM funder's optional ordinary change.
    pub funding_change: Vec<TransactionOutput>,
    /// Exact fee from the verified funding offer.
    pub funding_fee_noms: u64,
    /// Principal, successful change, DOM refund, XMR compensation.
    pub payouts: [TransactionOutput; 4],
    /// Principal and successful-change ownership/value proofs.
    pub payout_value_proofs: [XmrPayoutValueProofV11; 2],
    /// Funding, claim, cancel, refund, compensation contributions.
    pub kernels: [XmrGraphKernelContributionV12; 5],
    /// Both original offers and independently verified native key PoPs.
    pub signing_material: XmrGraphKeyMaterialV22,
}

impl XmrGraphPublicMaterialV23 {
    /// Reverify both offers in authenticated terms-roster order. The caller
    /// supplies independently trusted scopes; a PoP does not authenticate a peer.
    pub fn from_offers(
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        scopes: [&XmrGraphOfferScopeV22<'_>; 2],
        offers: [&XmrGraphOfferV22; 2],
    ) -> Result<Self, Error> {
        let signing_material = XmrGraphKeyMaterialV22::from_offers(terms, policy, scopes, offers)?;
        let funder = terms
            .roster
            .iter()
            .position(|participant| participant.0 == policy.policy().dom_funder)
            .ok_or(Error::GraphMismatch)?;
        let recipient = 1usize.checked_sub(funder).ok_or(Error::GraphMismatch)?;
        let principal = &offers[recipient].payouts()[0];
        let change = &offers[funder].payouts()[0];
        let copy_proof =
            |payout: &XmrPolicyPayoutOfferV22| -> Result<XmrPayoutValueProofV11, Error> {
                let proof = payout.ownership().ok_or(Error::GraphMismatch)?;
                Ok(XmrPayoutValueProofV11 {
                    statement: proof.statement.clone(),
                    proof: proof.proof.clone(),
                })
            };
        Ok(Self {
            funding_inputs: offers[funder].funding().inputs().to_vec(),
            funding_change: offers[funder]
                .funding()
                .change()
                .cloned()
                .into_iter()
                .collect(),
            funding_fee_noms: offers[funder].funding().fee(),
            payouts: [
                principal.output().clone(),
                change.output().clone(),
                offers[funder].payouts()[1].output().clone(),
                offers[recipient].payouts()[1].output().clone(),
            ],
            payout_value_proofs: [copy_proof(principal)?, copy_proof(change)?],
            kernels: XmrGraphSigningStageV22::ALL.map(|stage| signing_material.contribution(stage)),
            signing_material,
        })
    }

    /// Rebuild all five unsigned templates and bind their verified offer keys.
    /// Native outputs and setup inputs must come from independently audited
    /// owners. This does not authenticate agreement or authorize any signing.
    pub fn form_templates_v23(
        &self,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        outputs: [(
            dom_scriptless_crypto::FrozenSharedOutputV1,
            dom_adaptor::VerifiedSharedOutputV1,
        ); 2],
        negotiated_tip: u64,
        refund_point: [u8; 33],
    ) -> Result<(XmrRecoveryGraphTemplatesV12, XmrGraphSigningKeysV22), Error> {
        let [(c, c_output), (d, d_output)] = outputs;
        let kernels = |index: usize| XmrGraphKernelContributionV12 {
            excess: self.kernels[index].excess.clone(),
            offset: self.kernels[index].offset,
        };
        let payouts = std::array::from_fn(|index| XmrPayoutValueProofV11 {
            statement: self.payout_value_proofs[index].statement.clone(),
            proof: self.payout_value_proofs[index].proof.clone(),
        });
        let templates = XmrRecoveryGraphTemplatesV12::build(
            terms,
            policy,
            XmrGraphTemplateMaterialV12 {
                collateral: c,
                collateral_output: &c_output,
                cancelled: d,
                cancelled_output: &d_output,
                funding_inputs: self.funding_inputs.clone(),
                funding_change: self.funding_change.clone(),
                funding_fee_noms: self.funding_fee_noms,
                negotiated_tip,
                claim_principal: self.payouts[0].clone(),
                claim_change: self.payouts[1].clone(),
                refund_payout: self.payouts[2].clone(),
                compensation_payout: self.payouts[3].clone(),
                payout_value_proofs: payouts,
                funding_kernel: kernels(0),
                claim_kernel: kernels(1),
                cancel_kernel: kernels(2),
                refund_kernel: kernels(3),
                compensation_kernel: kernels(4),
                refund_adaptor_point: refund_point,
            },
        )?;
        templates.compensation_session_v23()?;
        let keys = self.signing_material.bind_templates(&templates)?;
        keys.require_graph(&templates)?;
        Ok((templates, keys))
    }
}
