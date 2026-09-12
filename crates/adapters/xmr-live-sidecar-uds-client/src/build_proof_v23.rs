//! Fresh native builder request through the same authenticated private UDS.
use super::*;
use xmr_live_sidecar_api::{BuildSweepRequestV23, BuildSweepResponseV23};

impl BlockingUdsSidecarPort {
    /// Build only from a caller-authorized local Refund effect. The HMAC proves
    /// channel possession, not public-U finality or the caller's Store authority.
    pub fn build_local_refund_with_proofs_v24(
        &mut self,
        mut request: xmr_live_sidecar_api::LocalRefundBuildRequestV24<BuildSweepRequestV2>,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>,
        SpendPortError,
    > {
        let public = xmr_live_sidecar_api::LocalRefundLoadRequestV24 {
            api_version: 24,
            request_nonce: request.build.request_nonce,
            network_genesis: request.network_genesis,
            route: request.route,
            session: request.session,
            terms: request.terms,
            effect_id: request.effect_id,
            fencing_epoch: request.fencing_epoch,
            semantic_digest: request.semantic_digest,
            dom_refund_tx_hash: request.dom_refund_tx_hash,
            graph_digest: request.graph_digest,
            settlement_id: request.build.settlement_id,
            funding_tx_hash: request.build.funding_tx_hash,
            funded_amount: request.build.expected_amount_piconero,
            destination: request.build.destination.clone(),
            expected_spend_public_key: request.build.expected_spend_public_key,
            max_fee: request.max_fee,
            auth_tag: [0; 32],
        };
        public
            .validate_scope()
            .map_err(|_| SpendPortError::Rejected)?;
        let original = xmr_live_sidecar_api::LocalRefundReadyScopeV24 {
            request: public.clone(),
            local_authorization_digest: request.local_authorization_digest,
            output_index: request.output_index,
            funding_height: request.funding_height,
        };
        self.auth_key
            .sign_local_refund_build_v24(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        match self.call(&SidecarRequestV2::BuildLocalRefundWithProofsV24(request))? {
            SidecarResponseV2::LocalRefundWithProofsV24(response) => {
                if response.public_scope != original {
                    return Err(SpendPortError::Rejected);
                }
                Self::validate_local_response_v24(&public, response)
            }
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            _ => Err(SpendPortError::Rejected),
        }
    }

    /// Reopen a complete cached result only. Missing/incomplete state cannot
    /// fall back to construction, and the HMAC cannot be replayed as a build.
    pub fn load_local_refund_with_proofs_v24(
        &mut self,
        request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>,
        SpendPortError,
    > {
        let deadline = Instant::now()
            .checked_add(self.timeout.min(Duration::from_secs(60)))
            .ok_or(SpendPortError::Rejected)?;
        self.load_local_refund_with_deadline_v24(request, deadline)
    }

    /// Public readback under the caller's ORIGINAL monotonic deadline. The
    /// effective bound cannot exceed either the configured timeout or 60s.
    /// Authentication, connection, framing and response validation share it;
    /// timeout is retryable and never falls back to BUILD or creates a signature.
    pub fn load_local_refund_with_deadline_v24(
        &mut self,
        mut request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
        deadline: Instant,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>,
        SpendPortError,
    > {
        let deadline = local_load_deadline_v24(deadline, Instant::now(), self.timeout)?;
        self.auth_key
            .sign_local_refund_load_v24(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let envelope = SidecarRequestV2::LoadLocalRefundWithProofsV24(request);
        let result = match (&envelope, self.call_until_v24(&envelope, deadline)?) {
            (
                SidecarRequestV2::LoadLocalRefundWithProofsV24(request),
                SidecarResponseV2::LocalRefundWithProofsV24(response),
            ) => Self::validate_local_response_v24(request, response),
            (_, SidecarResponseV2::Error(error)) => Err(Self::classify_error(error)),
            _ => Err(SpendPortError::Rejected),
        };
        remaining(deadline)?;
        result
    }

    fn validate_local_response_v24(
        request: &xmr_live_sidecar_api::LocalRefundLoadRequestV24,
        response: xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>,
    ) -> Result<
        xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>,
        SpendPortError,
    > {
        request
            .validate_scope()
            .map_err(|_| SpendPortError::Rejected)?;
        response
            .sweep
            .validate_for(&request.request_nonce)
            .map_err(|_| SpendPortError::Rejected)?;
        let c = response
            .validate_framing()
            .map_err(|_| SpendPortError::Rejected)?;
        if response
            .public_scope
            .request
            .canonical_auth_bytes()
            .map_err(|_| SpendPortError::Rejected)?
            != request
                .canonical_auth_bytes()
                .map_err(|_| SpendPortError::Rejected)?
            || response.effect_id != request.effect_id
            || response.fencing_epoch != request.fencing_epoch
            || response.semantic_digest != request.semantic_digest
            || response.dom_refund_tx_hash != request.dom_refund_tx_hash
            || response.graph_digest != request.graph_digest
            || c.destination != xmr_live_sidecar_api::destination_digest_v23(&request.destination)
            || c.network_genesis != request.network_genesis
            || c.route != request.route
            || c.session != request.session
            || c.terms != request.terms
            || c.funding_tx != request.funding_tx_hash
            || c.funded_amount != request.funded_amount
            || c.sweep_tx != response.sweep.tx_hash
            || c.fee > request.max_fee
        {
            return Err(SpendPortError::Rejected);
        }
        Ok(response)
    }

    /// Build one native sweep with durable public proofs. This returns wire
    /// data, not economic authority: caller verifies raw bytes, payout, and
    /// independently resolves the returned ring members using chain quorum.
    pub fn build_sweep_with_proofs_v23(
        &mut self,
        mut request: BuildSweepRequestV23<BuildSweepRequestV2>,
    ) -> Result<BuildSweepResponseV23<BuildSweepResponseV2>, SpendPortError> {
        request
            .validate_scope()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_build_proof_v23(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let envelope = SidecarRequestV2::BuildWithProofsV23(request);
        match (&envelope, self.call(&envelope)?) {
            (
                SidecarRequestV2::BuildWithProofsV23(request),
                SidecarResponseV2::SweepWithProofsV23(response),
            ) => {
                response
                    .sweep
                    .validate_for(&request.build.request_nonce)
                    .map_err(|_| SpendPortError::Rejected)?;
                let c = response
                    .validate_framing()
                    .map_err(|_| SpendPortError::Rejected)?;
                if response.request_message_digest != request.request_message_digest
                    || response.authorization_digest != request.authorization_digest
                    || c.destination
                        != xmr_live_sidecar_api::destination_digest_v23(&request.build.destination)
                    || c.network_genesis != request.network_genesis
                    || c.route != request.route
                    || c.session != request.session
                    || c.terms != request.terms
                    || c.funding_tx != request.build.funding_tx_hash
                    || c.output_index != request.output_index
                    || c.funded_amount != request.build.expected_amount_piconero
                    || c.sweep_tx != response.sweep.tx_hash
                    || c.fee > request.max_fee
                    || c.action
                        != request
                            .validate_scope()
                            .map_err(|_| SpendPortError::Rejected)?
                {
                    return Err(SpendPortError::Rejected);
                }
                Ok(response)
            }
            (_, SidecarResponseV2::Error(error)) => Err(Self::classify_error(error)),
            _ => Err(SpendPortError::Rejected),
        }
    }
}

pub(super) fn local_load_deadline_v24(
    original: Instant,
    now: Instant,
    configured: Duration,
) -> Result<Instant, SpendPortError> {
    if original <= now || configured.is_zero() {
        return Err(SpendPortError::Retryable);
    }
    let maximum = now
        .checked_add(configured.min(Duration::from_secs(60)))
        .ok_or(SpendPortError::Rejected)?;
    Ok(original.min(maximum))
}
