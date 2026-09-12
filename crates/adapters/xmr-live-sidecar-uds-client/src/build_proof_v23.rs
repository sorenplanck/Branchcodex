//! Fresh native builder request through the same authenticated private UDS.
use super::*;
use xmr_live_sidecar_api::{BuildSweepRequestV23, BuildSweepResponseV23};

impl BlockingUdsSidecarPort {
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
