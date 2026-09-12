//! Immutable pre-template payout commitments, not executable refund authority.
use super::*;

impl ProductionXmrF6TermsOwnerV7 {
    pub(super) fn into_enrollment_face_v23(
        self,
        binding: &ProductionSolverF6BindingV2,
        terms: &SettlementTermsV1,
        composition: &ComposedBindingV2,
        enrollment: crate::production_inputs::ProductionXmrEnrollmentBundleV23,
    ) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ErrorV2> {
        xmr_setup_profile::require_setup_chain_profile_v24(
            terms,
            &self.profile,
            &self.setup,
            self.deployment.profile(),
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let epoch = self.deployment.registry_epoch();
        let mut record = self.scope.check(
            binding,
            terms,
            composition,
            self.deployment.registry_digest(),
            epoch,
        )?;
        if self.deployment.profile_digest() != terms.counterparty_leg.adapter_profile_hash
            || self.deployment.profile().chain_id != terms.counterparty_leg.chain_id
            || self.deployment.asset_binding().asset_id != terms.counterparty_leg.asset_id
            || !matches!(
                self.deployment.profile().kind,
                chain_profile::ChainKindV1::Monero { .. }
            )
            || terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
            || self.setup.settlement_id() != terms.settlement_id.0
            || self.setup.terms_hash() != self.scope.terms_hash
            || u128::from(self.setup.expected_amount_piconero()) != terms.counterparty_leg.amount
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let deadline = crate::production_inputs::authenticate_xmr_refund_deadline_v23(
            terms,
            &self.setup,
            enrollment.deadline(),
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        // Preserve the negotiated clock; never reinterpret height as time.
        record.push(match deadline {
            TimelockSpec::BlockHeight { .. } => 1,
            TimelockSpec::TimestampSeconds { .. } => 2,
            TimelockSpec::BtcTime512s { .. } => return Err(ProductionF6ErrorV2::InvalidTerms),
        });
        let prepared =
            xmr_session_init::prepare_xmr_share_enrollment_v23(&self.setup, enrollment.proof())
                .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        prepared
            .require_setup(&self.setup, enrollment.proof())
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        use xmr_refund_policy::NonCooperativeRefundCapability as _;
        let claim = enrollment.proof().bundle.claim;
        if claim.secp_compressed != *enrollment.adaptor_point_sec1()
            || xmr_refund_adaptor::DomRefundAdaptorExecutor::new(claim).profile_hash()
                != enrollment.executor_profile_hash()
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        for field in [
            self.deployment.profile_digest(),
            self.deployment.asset_binding_digest(),
            self.deployment.deployment().genesis_hash,
            self.setup.binding_hash(),
            self.setup.funding_tx_hash(),
            self.setup.combined_spend_public_key(),
            enrollment
                .proof()
                .binding_hash()
                .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?,
            enrollment.executor_profile_hash(),
        ] {
            record.extend_from_slice(&field);
        }
        record.extend_from_slice(enrollment.adaptor_point_sec1());
        // Both destinations are committed independently, before the native
        // template binding. No later binding may replace the initial F6 face.
        for destination in [self.setup.destination(), enrollment.refund_destination()] {
            let length =
                u16::try_from(destination.len()).map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
            if length == 0 {
                return Err(ProductionF6ErrorV2::InvalidTerms);
            }
            record.extend_from_slice(&length.to_be_bytes());
            record.extend_from_slice(destination.as_bytes());
        }
        self.scope
            .finish(terms, DOMAIN_XMR_ENROLLMENT, &record, epoch)
    }
}
