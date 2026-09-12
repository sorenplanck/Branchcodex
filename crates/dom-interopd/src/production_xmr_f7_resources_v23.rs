//! Read-only F7 projection of the already-open XMR private resources.
//! No scalar getter, second database, sidecar connection or broadcast owner.
use super::*;
use std::{cell::RefCell, rc::Rc};

pub(crate) struct ProductionXmrF7ResourcesV23 {
    terms: SettlementTermsV1,
    setup: ValidatedXmrSetup,
    profile: XmrAdapterProfileV1,
    deployment: deployment_registry::ResolvedMoneroDeploymentV1,
    urls: Vec<String>,
    refund_proof: xmr_dleq_sigma::BoundCrossCurveProofV1,
    sidecar: Rc<RefCell<BlockingUdsSidecarPort>>,
    secrets: Rc<EncryptedSqliteSecretStore>,
}

impl ProductionXmrSweepAuthorityV10 {
    pub(crate) fn retain_f7_resources_v23(
        &self,
        admitted: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
    ) -> Result<ProductionXmrF7ResourcesV23, Refusal> {
        let quorum = self.funding_quorum_v22.as_ref().ok_or(Refusal::Conflict)?;
        if admitted.terms() != &self.funding_terms_v22
            || admitted.setup().binding_hash() != self.binding.setup.binding_hash()
            || admitted.refund_point() != self.binding.refund_claim.secp_compressed
            || admitted.genesis() != quorum.deployment.deployment().genesis_hash
        {
            return Err(Refusal::Conflict);
        }
        Ok(ProductionXmrF7ResourcesV23 {
            terms: self.funding_terms_v22.clone(),
            setup: self.binding.setup.clone(),
            profile: self.funding_profile_v22.clone(),
            deployment: quorum.deployment.clone(),
            urls: quorum.urls.clone(),
            refund_proof: admitted
                .refund_bundle_v23()
                .map_err(|_| Refusal::Conflict)?
                .proof
                .clone(),
            sidecar: Rc::clone(&self.sidecar),
            secrets: Rc::clone(&self.secrets),
        })
    }
}

impl ProductionXmrF7ResourcesV23 {
    /// Readiness and collateral come from the same reopened native F7 owner,
    /// never from caller-selected digests or a legacy template commitment.
    pub(crate) fn into_observer(
        self,
        produced: Rc<xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12>,
        custody: Rc<dom_scriptless_store::XmrRecoveryCustodyV11>,
    ) -> Result<
        crate::production_contracts::ProductionSelectedF7ObserverV12,
        crate::production_contracts::ProductionF7RuntimeErrorV12,
    > {
        use crate::production_contracts::{
            ProductionF7RuntimeErrorV12 as Error, ProductionSelectedF7ObserverV12,
            ProductionXmrF7GraphV23, ProductionXmrF7InputsV12,
        };
        let policy = *produced.economic().policy().policy();
        if policy.bounded_availability_v23.is_none()
            || produced.economic().policy().terms_hash() != &self.setup.terms_hash()
            || produced.graph().binding().refund_adaptor_point
                != self.refund_proof.bundle.claim.secp_compressed
            || custody.scope().graph_digest != *produced.graph().graph_digest()
        {
            return Err(Error::Scope);
        }
        ProductionSelectedF7ObserverV12::monero(
            &self.terms,
            ProductionXmrF7InputsV12 {
                setup: self.setup,
                profile: self.profile,
                deployment: self.deployment,
                daemon_urls: self.urls,
                policy,
                graph: ProductionXmrF7GraphV23::Native(produced),
                refund_share_proof: self.refund_proof,
                custody,
                sidecar: self.sidecar,
                secrets: self.secrets,
            },
        )
    }
}
