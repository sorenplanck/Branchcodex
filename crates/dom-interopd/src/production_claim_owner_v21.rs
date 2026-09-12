//! Single private owner joining the native F7 signer and DOM settlement child.
//! The child can request adaptation, never extract a share, vault or secret.
use super::*;
use dom_actuator::{DomActuatorStoreV1, DomLeaseV1, ScopedDomActionV1};
use dom_adaptor::AdaptorSecret;
use dom_scriptless_store::F7FinalClaimProgressV14;

#[derive(Default)]
pub(super) struct ProductionClaimOwnerV21 {
    pub(super) pump: Option<ProductionF7RuntimeV12<ContractsNonceVaultV1>>,
    pub(super) m8: Option<super::post_m8_claim_v22::ProductionPostM8ClaimV22>,
    pub(super) m8_start_failed: bool,
    pub(super) native_xmr_start_failed_v23: bool,
    pub(super) xmr_refund_readiness_v23:
        Option<Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>>,
    origin: Option<AdaptorSecret>,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn local_origin_needed_v21(
        &self,
        binding: DomSessionBindingV1,
        chain: &TrustedChainIdV1,
    ) -> DomActuatorResult<bool> {
        self.validate_dom_binding(binding)?;
        if self
            .store
            .post_m8_claim_exposed_v22(*chain, self.session_id)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?
        {
            return Ok(false);
        }
        if self
            .bind_dom_actuator(binding)?
            .f7_final_claim_progress_v21(chain)?
            .is_some_and(|progress| progress != F7FinalClaimProgressV14::NeedsAdaptation)
        {
            return Ok(false);
        }
        let head = self
            .store
            .load_session(self.session_id)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        Ok(!head.irreversible().adaptor_secret_exposed
            && !matches!(
                head.phase(),
                dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                    | dom_scriptless_store::SessionPhaseV1::Refunded
                    | dom_scriptless_store::SessionPhaseV1::FailedClosed
            ))
    }

    /// Import only the existing secret committed by the authenticated composed
    /// terms. The runtime verifies the point before this handoff; this owner
    /// independently requires the native role to authorize local first reveal.
    pub(crate) fn install_local_origin_v21(
        &self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        secret: AdaptorSecret,
        role: &dom_final_claim_binding::FinalClaimRolePlanEntryV1,
        expected_point: [u8; 33],
    ) -> DomActuatorResult<()> {
        self.validate_dom_binding(binding)?;
        if chain.as_bytes() != &binding.chain_id()
            || role.session_id().0 != self.session_id
            || role.dom_claim_sender_id().0 != self.local_participant
            || role.adaptor_secret_origin_id().0 != self.local_participant
            || role.secret_source()
                != dom_final_claim_binding::FinalClaimSecretSourceV1::LocalOrigin
            || secret
                .public_point()
                .map_err(|_| DomActuatorError::CapabilityMismatch)?
                .to_compressed_bytes()
                != expected_point
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let mut owner = self
            .claim_owner_v21
            .try_borrow_mut()
            .map_err(|_| DomActuatorError::ReconciliationRequired)?;
        if owner.origin.is_some() {
            return Err(DomActuatorError::InvalidStage);
        }
        owner.origin = Some(secret);
        Ok(())
    }
}

impl ProductionDomChildStoreAuthorityV1 {
    /// Called only after the coordinator's route, action and secret-source
    /// scope were authenticated. Native exposure precedes child-plan issuance.
    pub(crate) fn prepare_native_claim_child_v21(
        &self,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        chain: &TrustedChainIdV1,
        scope: ScopedDomActionV1,
        public_scalar: Option<&route_composer::RouteScalar>,
        now_unix_ms: u64,
    ) -> Result<bool, super::ProductionF7FinalClaimErrorV14> {
        let actuator = self.bind()?;
        let Some(progress) = actuator.f7_final_claim_progress_v21(chain)? else {
            if self
                .store
                .post_m8_claim_exposed_v22(*chain, scope.binding().session_id())?
            {
                // A previous tick may have persisted exposure and then failed
                // while latching the mirror. Drop its live signer before replay.
                self.claim_owner_v21
                    .try_borrow_mut()
                    .map_err(|_| super::ProductionF7FinalClaimErrorV14::AdaptationRequired)?
                    .m8 = None;
                actuator.resume_post_m8_claim_child_v22(
                    control,
                    lease,
                    chain,
                    scope,
                    now_unix_ms,
                )?;
                return Ok(true);
            }
            let mut owner = self
                .claim_owner_v21
                .try_borrow_mut()
                .map_err(|_| super::ProductionF7FinalClaimErrorV14::AdaptationRequired)?;
            let ProductionClaimOwnerV21 { m8, origin, .. } = &mut *owner;
            let Some(pump) = m8.as_mut() else {
                return Ok(false);
            };
            let public = public_scalar
                .map(|scalar| AdaptorSecret::from_be_bytes(*scalar.expose()))
                .transpose()
                .map_err(|_| super::ProductionF7FinalClaimErrorV14::Scope)?;
            let secret = match (public.as_ref(), origin.as_ref()) {
                (Some(secret), None) | (None, Some(secret)) => secret,
                _ => return Err(super::ProductionF7FinalClaimErrorV14::AdaptationRequired),
            };
            pump.expose(
                control,
                lease,
                chain,
                scope,
                secret,
                public.is_some(),
                now_unix_ms,
            )?;
            *origin = None;
            return Ok(true);
        };
        if progress != F7FinalClaimProgressV14::NeedsAdaptation {
            // Recovery is independent of the private origin file and the
            // in-memory signer. It authenticates exact bytes and repairs CAS.
            actuator.resume_f7_claim_child_v21(control, lease, chain, scope, now_unix_ms)?;
            return Ok(true);
        }
        let mut owner = self
            .claim_owner_v21
            .try_borrow_mut()
            .map_err(|_| super::ProductionF7FinalClaimErrorV14::AdaptationRequired)?;
        let ProductionClaimOwnerV21 { pump, origin, .. } = &mut *owner;
        let pump = pump
            .as_mut()
            .ok_or(super::ProductionF7FinalClaimErrorV14::AdaptationRequired)?;
        let public = public_scalar
            .map(|scalar| AdaptorSecret::from_be_bytes(*scalar.expose()))
            .transpose()
            .map_err(|_| super::ProductionF7FinalClaimErrorV14::Scope)?;
        let secret = match (public.as_ref(), origin.as_ref()) {
            (Some(secret), None) => secret,
            (None, Some(secret)) => secret,
            _ => return Err(super::ProductionF7FinalClaimErrorV14::AdaptationRequired),
        };
        pump.expose_for_child_v21(
            control,
            lease,
            chain,
            scope,
            secret,
            public.is_some(),
            now_unix_ms,
        )?;
        // Native immutable exposure is sufficient for every later recovery.
        // Drop the private origin immediately after both journals persist it.
        *origin = None;
        Ok(true)
    }
}
