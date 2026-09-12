//! Export the same public setup/proofs used by native private custody. No
//! second DLEQ ceremony, scalar export, or replacement of a session owner.
use super::*;
use crate::production_inputs::{
    ProductionRoutePositionV1, ProductionXmrLegSetupV1, ProductionXmrRefundBundleV1,
};

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn participant_setup_v23(
        &self,
        position: ProductionRoutePositionV1,
        terms: &SettlementTermsV1,
    ) -> Result<ProductionXmrLegSetupV1> {
        let setup = xmr_setup_profile::validate_setup(
            terms,
            &self.profile,
            self.public_binding_v23.clone(),
            None,
        )?;
        if setup.binding_hash() != self.setup.binding_hash() {
            return Err("participant export differs from actual custody setup".into());
        }
        self.refund_policy
            .require_scope(&terms.settlement_id.0, &terms.terms_hash()?)?;
        self.refund_policy
            .require_refund_point(&self.public_refund_artifact_v23.adaptor_point_sec1)?;
        let refund_destination = self
            .claim_payout_v23
            .as_ref()
            .ok_or("participant export needs the scenario's committed refund recipient")?
            .refund_address()
            .to_owned();
        let artifact = self.public_refund_artifact_v23;
        let refund = ProductionXmrRefundBundleV1::new_v10(
            self.refund_proof.clone(),
            artifact.template_hash,
            artifact.adaptor_point_sec1,
            artifact.executor_profile_hash,
            artifact.deadline,
            refund_destination,
        )?;
        Ok(ProductionXmrLegSetupV1::new(
            position,
            self.profile.clone(),
            self.public_binding_v23.clone(),
        )?
        .with_refund(refund)?)
    }
}
