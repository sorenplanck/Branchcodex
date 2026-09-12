//! Explicit pre-template Monero provisioning profile. Not convertible into
//! the legacy pinned authority and not an executable refund/sweep capability.
use super::*;
#[path = "production_xmr_enrollment_resources_v23.rs"]
mod resources_v23;
pub(crate) use resources_v23::{ProductionOpenedXmrEnrollmentV23, ProductionXmrEnrolledFundingV23};
#[cfg(test)]
#[path = "production_xmr_enrollment_authority_codec_v23_tests.rs"]
mod codec_tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionUniversalXmrEnrollmentAuthorityV23 {
    #[serde(skip)]
    pub(super) scope: Option<LegScopeV11>,
    #[serde(skip)]
    pub(super) validated_compensation: Option<ValidatedXmrCompensationPolicyV11>,
    pub(super) compensation_policy: Vec<u8>,
    pub(super) local_participant_id: [u8; 32],
    pub(super) setup_binding_hash: [u8; 32],
    pub(super) refund_point_sec1: Vec<u8>,
    pub(super) executor_profile_hash: [u8; 32],
    pub(super) refund_deadline: u64,
    pub(super) refund_destination: String,
    pub(super) secret_store: String,
    pub(super) sidecar_socket: String,
    pub(super) sidecar_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) private_funding_v12: Option<ProductionXmrPrivateFundingConfigV12>,
    // Required. No V22 fallback or Option disguising an unbound legacy pin.
    pub(super) recovery_v23: ProductionXmrRecoveryResourcesV23,
}

impl ProductionUniversalXmrEnrollmentAuthorityV23 {
    /// Exact pre-existing files used by the independent inventory observer.
    /// This borrows the authority; it neither consumes nor duplicates a signer.
    pub(crate) fn inventory_resources_v23(
        &self,
        state_dir: &Path,
    ) -> Result<(PathBuf, PathBuf, u64), Refusal> {
        if self.scope.is_none() {
            return Err(Refusal::Conflict);
        }
        require_milliseconds(self.sidecar_timeout_ms, 180_000)?;
        Ok((
            existing_resource(state_dir, &self.secret_store, false)?,
            existing_resource(state_dir, &self.sidecar_socket, true)?,
            self.sidecar_timeout_ms,
        ))
    }

    pub(super) fn admit(
        &mut self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        scope: LegScopeV11,
    ) -> Result<(), Refusal> {
        scope.require(inputs, leg)?;
        let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let policy = self.validate_public_inputs_v23(session, terms)?;
        self.validated_compensation = Some(policy);
        self.scope = Some(scope);
        Ok(())
    }

    pub(super) fn validate_public_inputs_v23(
        &self,
        session: &crate::production_inputs::AuthenticatedXmrSessionBindingsV1,
        terms: &kaystra_core::terms::SettlementTermsV1,
    ) -> Result<ValidatedXmrCompensationPolicyV11, Refusal> {
        let enrollment = session.native_enrollment_v23().ok_or(Refusal::Conflict)?;
        let bundle = session
            .native_enrollment_bundle_v23()
            .ok_or(Refusal::Conflict)?;
        if session.refund_bundle().is_some() {
            return Err(Refusal::Conflict);
        }
        if session.session_id() != terms.session_id.0
            || session.terms_digest() != terms.terms_hash().map_err(|_| Refusal::Conflict)?
            || session.setup().terms_hash() != session.terms_digest()
        {
            return Err(Refusal::Conflict);
        }
        self.validate_enrollment_parameters_v23(terms, session.setup(), enrollment, bundle)
    }

    /// Shared public checks for canonical writing and native admission. The
    /// returned policy is negotiated metadata, never a scope/funding grant.
    pub(super) fn validate_enrollment_parameters_v23(
        &self,
        terms: &kaystra_core::terms::SettlementTermsV1,
        setup: &xmr_setup_profile::ValidatedXmrSetup,
        enrollment: &xmr_session_init::PreparedXmrShareEnrollmentV23,
        bundle: &crate::production_inputs::ProductionXmrEnrollmentBundleV23,
    ) -> Result<ValidatedXmrCompensationPolicyV11, Refusal> {
        enrollment
            .require_setup(setup, bundle.proof())
            .map_err(|_| Refusal::Conflict)?;
        if setup.settlement_id() != terms.settlement_id.0
            || setup.terms_hash() != terms.terms_hash().map_err(|_| Refusal::Conflict)?
            || self.setup_binding_hash != setup.binding_hash()
            || self.refund_point_sec1.as_slice() != bundle.adaptor_point_sec1()
            || self.executor_profile_hash != bundle.executor_profile_hash()
            || self.refund_deadline != bundle.deadline()
            || self.refund_destination != bundle.refund_destination()
            || ![
                terms.counterparty_leg.beneficiary.0,
                terms.counterparty_leg.refund_to.0,
            ]
            .contains(&self.local_participant_id)
            || !terms
                .roster
                .iter()
                .any(|id| id.0 == self.local_participant_id)
            || terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
            || self.private_funding_v12.is_some()
                != (self.local_participant_id == terms.counterparty_leg.refund_to.0)
            || !terms.recovery.refund_before_funding
        {
            return Err(Refusal::Conflict);
        }
        match terms.counterparty_leg.deadline {
            kaystra_core::types::TimelockSpec::BlockHeight { value }
                if value == self.refund_deadline => {}
            _ => return Err(Refusal::Conflict),
        }
        let policy = XmrCompensationPolicyV11::from_bytes(&self.compensation_policy)
            .map_err(|_| Refusal::Conflict)?
            .validate_for(terms)
            .map_err(|_| Refusal::Conflict)?;
        if policy.policy().bounded_availability_v23.is_none()
            || policy.policy().to_bytes().map_err(|_| Refusal::Conflict)?
                != self.compensation_policy
            || self.recovery_v23.custody_id == [0; 32]
            || Path::new(&self.recovery_v23.directory).components().count() != 1
        {
            return Err(Refusal::Conflict);
        }
        require_milliseconds(self.sidecar_timeout_ms, 180_000)?;
        let paths = self.resource_paths_v23();
        for (index, (path, _)) in paths.iter().enumerate() {
            relative_path(path)?;
            if paths[..index].iter().any(|(other, _)| {
                Path::new(path).starts_with(other) || Path::new(other).starts_with(path)
            }) {
                return Err(Refusal::Conflict);
            }
        }
        if let Some(candidate) = &self.private_funding_v12 {
            if self.local_participant_id != terms.counterparty_leg.refund_to.0
                || candidate.max_fee_piconero == 0
                || u128::from(candidate.max_fee_piconero) > terms.fee_limit.counterparty_max
            {
                return Err(Refusal::Conflict);
            }
        }
        Ok(policy)
    }

    pub(super) fn resource_paths_v23(&self) -> Vec<(&str, ProductionResourceLeafV23)> {
        use ProductionResourceLeafV23::{Existing, NativeXmrGraphCustodyDirectory};
        let mut paths = vec![
            (self.secret_store.as_str(), Existing),
            (self.sidecar_socket.as_str(), Existing),
            (
                self.recovery_v23.directory.as_str(),
                NativeXmrGraphCustodyDirectory,
            ),
            (self.recovery_v23.sealing_key_file.as_str(), Existing),
            (self.recovery_v23.nullifier_store.as_str(), Existing),
        ];
        if let Some(candidate) = &self.private_funding_v12 {
            paths.push((candidate.raw_transaction_file.as_str(), Existing));
        }
        paths
    }
}
