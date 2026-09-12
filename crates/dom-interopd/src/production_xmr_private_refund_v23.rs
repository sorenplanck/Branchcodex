//! Private U adaptation using the same already-open encrypted share Store as
//! sweep. No scalar getter, new database opening, nullifier registration or RPC.
use super::*;
use std::rc::Rc;
use xmr_dleq_nullifier_store::DleqNullifierStore;

/// Move-only, scoped capability. Rc shares the existing physical databases;
/// neither this owner nor its secret-bearing fields has a public clone/getter.
pub(crate) struct ProductionXmrPrivateRefundOwnerV23 {
    secrets: Rc<EncryptedSqliteSecretStore>,
    nullifiers: Rc<DleqNullifierStore>,
    setup: ValidatedXmrSetup,
    binding: dom_actuator::DomSessionBindingV1,
    terms: SettlementTermsV1,
    refund: ProductionXmrRefundBundleV1,
    policy: xmr_refund_policy::ValidatedRefundPolicy,
}

impl ProductionXmrPrivateRefundOwnerV23 {
    pub(crate) fn complete(
        &self,
        graph: &dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11,
    ) -> Result<dom_scriptless_crypto::PrivateXmrRefundTransactionV11, Refusal> {
        let binding = graph.binding();
        if binding.session_id != self.binding.session_id()
            || binding.chain_id != self.binding.chain_id()
            || binding.terms_hash != self.binding.terms_digest()
            || binding.claim_adaptor_point != self.setup.claim().secp_compressed
            || binding.refund_adaptor_point != self.refund.adaptor_point_sec1
            || self.binding.participant().participant_id() != self.terms.dom_leg.refund_to.0
            || self.terms.dom_leg.refund_to != self.terms.counterparty_leg.beneficiary
            || dom_adaptor::canonical_template_v1(graph.refund_template())
                .map_err(|_| Refusal::Conflict)?
                .1
                != self.refund.template_hash
        {
            return Err(Refusal::Conflict);
        }
        // Revalidates registered DLEQ and encrypted row on every call. This
        // returns only the private signed transaction, never the U witness.
        xmr_session_init::complete_private_dom_refund_v12(
            &self.setup,
            self.secrets.as_ref(),
            self.nullifiers.as_ref(),
            &self.policy,
            &self.refund.proof,
            graph,
        )
        .map_err(|_| Refusal::Conflict)
    }
}

impl ProductionXmrSweepAuthorityV10 {
    pub(crate) fn retain_private_refund_owner_v23(
        &self,
        admitted: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
        nullifiers: &Rc<DleqNullifierStore>,
    ) -> Result<ProductionXmrPrivateRefundOwnerV23, Refusal> {
        if self.binding.local_role != LocalRole::ClaimReceiver
            || admitted.binding().session_id() != self.binding.session_id
            || admitted.binding().chain_id() != self.binding.dom_chain_id
            || admitted.binding().terms_digest() != self.binding.setup.terms_hash()
            || admitted.setup().binding_hash() != self.binding.setup.binding_hash()
            || admitted.terms() != &self.funding_terms_v22
            || admitted
                .admitted_refund_template()
                .map_err(|_| Refusal::Conflict)?
                != self.binding.refund_template
            || admitted.refund_point() != self.binding.refund_claim.secp_compressed
            || admitted.binding().participant().participant_id()
                != self.funding_terms_v22.dom_leg.refund_to.0
            || self.funding_terms_v22.dom_leg.refund_to
                != self.funding_terms_v22.counterparty_leg.beneficiary
        {
            return Err(Refusal::Conflict);
        }
        let refund = admitted
            .refund_bundle_v23()
            .map_err(|_| Refusal::Conflict)?;
        if refund.adaptor_point_sec1 != self.binding.refund_claim.secp_compressed
            || refund.template_hash != self.binding.refund_template
        {
            return Err(Refusal::Conflict);
        }
        let executor = DomRefundAdaptorExecutor::new(self.binding.refund_claim);
        let policy = xmr_refund_policy::admit_refund_policy(
            &self.funding_terms_v22,
            self.funding_profile_v22.network,
            xmr_refund_policy::XmrRefundModeV1::AdaptorRefundRequired,
            Some(xmr_refund_policy::XmrRefundArtifactV1 {
                template_hash: refund.template_hash,
                adaptor_point_sec1: refund.adaptor_point_sec1,
                executor_profile_hash: refund.executor_profile_hash,
                deadline: refund.deadline,
            }),
            None,
            Some(&executor),
        )
        .map_err(|_| Refusal::Conflict)?;
        xmr_session_init::resume_session_for_role_v11(
            &self.binding.setup,
            self.secrets.as_ref(),
            nullifiers.as_ref(),
            &policy,
            &refund.proof,
            xmr_session_init::XmrLocalShareRoleV11::ClaimReceiver,
        )
        .map_err(|_| Refusal::Conflict)?;
        Ok(ProductionXmrPrivateRefundOwnerV23 {
            secrets: Rc::clone(&self.secrets),
            nullifiers: Rc::clone(nullifiers),
            setup: self.binding.setup.clone(),
            binding: admitted.binding(),
            terms: self.funding_terms_v22.clone(),
            refund: refund.clone(),
            policy,
        })
    }
}
