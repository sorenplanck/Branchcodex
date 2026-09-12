//! Role-scoped construction for an authenticated, independently observed
//! remote request. Neither this owner nor the sidecar publishes a transaction.
use super::*;
use crate::production_xmr_remote_sweep_v23::AuthenticatedRemoteSweepBuildV23;
use xmr_live_sidecar_api::{BuildSweepRequestV23, BuildSweepResponseV2, BuildSweepResponseV23};
use xmr_remote_sweep_wire::RemoteSweepActionV23;

impl ProductionXmrSweepAuthorityV10 {
    pub(crate) fn build_authenticated_remote_sweep_v23(
        &mut self,
        authorized: &AuthenticatedRemoteSweepBuildV23<'_>,
    ) -> Result<BuildSweepResponseV23<BuildSweepResponseV2>, Refusal> {
        let request = authorized.request();
        let setup = &self.binding.setup;
        let funding = authorized.funding();
        if funding.facts().age() > std::time::Duration::from_secs(60) {
            return Err(Refusal::Unavailable);
        }
        // This is the signer's own quorum/view-scan token, moved into the
        // witness by its private constructor; the peer cannot choose height.
        if funding.funding_id()
            != &f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(setup.funding_tx_hash())
            || funding.setup_binding_hash() != &setup.binding_hash()
            || funding.facts().settlement_id() != &setup.settlement_id()
            || funding.facts().terms_hash() != &setup.terms_hash()
            || request.funding_evidence_digest == [0; 32]
            || funding.block_height() != request.funding_block_height
            || u64::from(funding.output_index()) != request.funding_output_index
        {
            return Err(Refusal::Conflict);
        }
        let quorum = self.funding_quorum_v22.as_ref().ok_or(Refusal::Conflict)?;
        let refund = request.action == RemoteSweepActionV23::Refund;
        let expected_destination = if refund {
            self.binding.refund_destination.as_str()
        } else {
            setup.destination()
        };
        if request.session_id != self.binding.session_id
            || request.settlement_id != setup.settlement_id()
            || request.terms_digest != setup.terms_hash()
            || request.funding_tx_hash != setup.funding_tx_hash()
            || request.funded_amount_piconero != setup.expected_amount_piconero()
            || request.destination != expected_destination
            || request.network_genesis != quorum.deployment.deployment().genesis_hash
            || request.registry_digest != quorum.deployment.registry_digest()
            || request.profile_digest != quorum.deployment.profile_digest()
            || request.max_fee_piconero == 0
            || request.max_fee_piconero > self.binding.max_fee_piconero
            || request.max_fee_piconero > quorum.deployment.deployment().max_fee_piconero
            || usize::try_from(request.adapter_max_raw_transaction_bytes).ok()
                != Some(self.binding.max_raw_bytes)
            || request.max_raw_transaction_bytes > request.adapter_max_raw_transaction_bytes
            || request.max_raw_transaction_bytes == 0
        {
            return Err(Refusal::Conflict);
        }
        let remote = match request.action {
            RemoteSweepActionV23::Claim => {
                if self.binding.local_role != LocalRole::ClaimReceiver {
                    return Err(Refusal::Conflict);
                }
                // This RouteScalar comes from the verified DOM observation,
                // never from deserializing the peer's public scalar field.
                let scalar = authorized.claim_scalar().ok_or(Refusal::Conflict)?;
                let bytes = revealed_dom_secret_to_xmr_scalar(*scalar.expose(), &setup.claim())
                    .map_err(|_| Refusal::Conflict)?;
                XmrSpendShare::from_canonical_bytes(bytes).map_err(|_| Refusal::Conflict)?
            }
            RemoteSweepActionV23::Refund => {
                if self.binding.local_role != LocalRole::RefundReceiver
                    || authorized.claim_scalar().is_some()
                {
                    return Err(Refusal::Conflict);
                }
                // Independently re-read the existing private-refund source;
                // authenticated transport alone never grants access to U.
                let revealed = self
                    .refund_source
                    .as_ref()
                    .ok_or(Refusal::Conflict)?
                    .observe()?;
                revealed.require_binding(&self.binding)?;
                let executor = DomRefundAdaptorExecutor::new(self.binding.refund_claim);
                revealed
                    .expose(|bytes| executor.recover_share(*bytes))
                    .map_err(|_| Refusal::Conflict)?
            }
        };
        if !remote.expose(|bytes| *bytes == request.public_spend_share) {
            return Err(Refusal::Conflict);
        }
        let material = self.material()?;
        let (local, view) = self.binding.local_keys(&material)?;
        let combined = local.combine(&remote).map_err(|_| Refusal::Conflict)?;
        if combined.public_key().map_err(|_| Refusal::Conflict)?
            != setup.combined_spend_public_key()
        {
            return Err(Refusal::Conflict);
        }
        let build = BuildSweepRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce: request.effect_id,
            settlement_id: setup.settlement_id(),
            funding_tx_hash: setup.funding_tx_hash(),
            expected_amount_piconero: setup.expected_amount_piconero(),
            destination: expected_destination.to_owned(),
            spend_scalar: combined.expose(|bytes| SecretScalarBytes::new(*bytes)),
            expected_spend_public_key: setup.combined_spend_public_key(),
            view_scalar: view.expose(|bytes| SecretScalarBytes::new(*bytes)),
            auth_tag: [0; 32],
        };
        let response = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_sweep_with_proofs_v23(BuildSweepRequestV23 {
                api_version: 23,
                build,
                network_genesis: request.network_genesis,
                route: request.route_id,
                session: request.session_id,
                authorization_digest: request.digest().map_err(|_| Refusal::Conflict)?,
                request_message_digest: authorized.request_message_digest(),
                terms: request.terms_digest,
                output_index: request.funding_output_index,
                funding_height: request.funding_block_height,
                max_fee: request.max_fee_piconero,
                action: request.action as u8,
                auth_tag: [0; 32],
            })
            .map_err(map_port)?;
        if response.sweep.raw_tx.len()
            > usize::try_from(request.max_raw_transaction_bytes).map_err(|_| Refusal::Conflict)?
        {
            return Err(Refusal::Conflict);
        }
        // No economic receipt: the requester still authenticates the ring
        // membership and runs the complete cryptographic/fenced import path.
        verify_exact_raw_sweep_bounded_v23(
            &response.sweep.raw_tx,
            response.sweep.tx_hash,
            setup.expected_amount_piconero(),
            request.max_fee_piconero,
        )
        .map_err(|_| Refusal::Conflict)?;
        // Long RPC/signing never silently extends the observation window.
        // Cached bytes remain durable if this return is refused.
        if funding.facts().age() > std::time::Duration::from_secs(60) {
            return Err(Refusal::Unavailable);
        }
        Ok(response)
    }
}
