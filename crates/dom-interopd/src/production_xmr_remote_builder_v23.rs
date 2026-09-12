//! Role-scoped construction for an authenticated, independently observed
//! remote request. Neither this owner nor the sidecar publishes a transaction.
use super::*;
use crate::production_xmr_remote_sweep_v23::AuthenticatedRemoteSweepBuildV23;
use xmr_live_sidecar_api::{BuildSweepRequestV23, BuildSweepResponseV2, BuildSweepResponseV23};
use xmr_remote_sweep_wire::RemoteSweepActionV23;

impl ProductionXmrSweepAuthorityV10 {
    /// Local signing is independent of a remote request. Public readback has
    /// a separate method below which never loads or combines private material.
    pub(crate) fn build_local_refund_with_proofs_v24(
        &mut self,
        authorized: &crate::production_xmr_remote_sweep_v23::AuthorizedLocalXmrRefundV24,
    ) -> Result<xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>, Refusal>
    {
        authorized.require_recent()?;
        let request = authorized.request();
        let observed = authorized.observed();
        let setup = &self.binding.setup;
        let quorum = self.funding_quorum_v22.as_ref().ok_or(Refusal::Conflict)?;
        let funding = authorized.funding();
        if self.binding.local_role != LocalRole::RefundReceiver
            || request.action != RemoteSweepActionV23::Refund
            || request.session_id != self.binding.session_id
            || request.settlement_id != setup.settlement_id()
            || request.terms_digest != setup.terms_hash()
            || request.funding_tx_hash != setup.funding_tx_hash()
            || request.destination != self.binding.refund_destination
            || request.funded_amount_piconero != setup.expected_amount_piconero()
            || request.network_genesis != quorum.deployment.deployment().genesis_hash
            || request.registry_digest != quorum.deployment.registry_digest()
            || request.profile_digest != quorum.deployment.profile_digest()
            || request.max_fee_piconero != self.binding.max_fee_piconero
            || request.max_fee_piconero > quorum.deployment.deployment().max_fee_piconero
            || usize::try_from(request.adapter_max_raw_transaction_bytes).ok()
                != Some(self.binding.max_raw_bytes)
            || funding.setup_binding_hash() != &setup.binding_hash()
            || funding.block_height() != request.funding_block_height
            || u64::from(funding.output_index()) != request.funding_output_index
            || observed.chain_id() != self.binding.dom_chain_id
            || observed.session_id() != self.binding.session_id
            || observed.template_hash() != self.binding.refund_template
            || observed.refund_point() != self.binding.refund_claim.secp_compressed
            || observed.finality().terms_hash() != setup.terms_hash()
        {
            return Err(Refusal::Conflict);
        }
        let executor = DomRefundAdaptorExecutor::new(self.binding.refund_claim);
        let remote = observed
            .expose(|bytes| executor.recover_share(*bytes))
            .map_err(|_| Refusal::Conflict)?;
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
        // Recheck immediately before the secret-bearing authenticated UDS call.
        authorized.require_recent()?;
        let build = xmr_live_sidecar_api::LocalRefundBuildRequestV24 {
            api_version: 24,
            build: BuildSweepRequestV2 {
                api_version: API_VERSION_V2,
                request_nonce: request.effect_id,
                settlement_id: setup.settlement_id(),
                funding_tx_hash: setup.funding_tx_hash(),
                expected_amount_piconero: setup.expected_amount_piconero(),
                destination: self.binding.refund_destination.clone(),
                spend_scalar: combined.expose(|bytes| SecretScalarBytes::new(*bytes)),
                expected_spend_public_key: setup.combined_spend_public_key(),
                view_scalar: view.expose(|bytes| SecretScalarBytes::new(*bytes)),
                auth_tag: [0; 32],
            },
            network_genesis: request.network_genesis,
            route: request.route_id,
            session: request.session_id,
            terms: request.terms_digest,
            effect_id: request.effect_id,
            fencing_epoch: request.fencing_epoch,
            semantic_digest: request.semantic_digest,
            local_authorization_digest: authorized.authorization_digest(),
            dom_refund_tx_hash: observed.finality().transaction_hash(),
            graph_digest: observed.finality().graph_digest(),
            output_index: request.funding_output_index,
            funding_height: request.funding_block_height,
            max_fee: request.max_fee_piconero,
            auth_tag: [0; 32],
        };
        let mut sidecar = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?;
        let response = sidecar
            .build_local_refund_with_proofs_v24(build)
            .map_err(map_port)?;
        authorized.require_recent()?;
        Ok(response)
    }

    /// Public Ready lookup only. No material(), local_keys(), scalar recovery,
    /// signing endpoint or funding scanner is reachable from this method.
    pub(crate) fn load_local_refund_with_proofs_v24(
        &self,
        request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
    ) -> Result<xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>, Refusal>
    {
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(60))
            .ok_or(Refusal::Unavailable)?;
        self.load_local_refund_with_deadline_v24(request, deadline)
    }

    pub(crate) fn load_local_refund_with_deadline_v24(
        &self,
        request: xmr_live_sidecar_api::LocalRefundLoadRequestV24,
        deadline: std::time::Instant,
    ) -> Result<xmr_live_sidecar_api::LocalRefundBuildResponseV24<BuildSweepResponseV2>, Refusal>
    {
        self.sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .load_local_refund_with_deadline_v24(request, deadline)
            .map_err(map_port)
    }

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
        let build = BuildSweepRequestV23 {
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
        };
        let mut sidecar = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?;
        // Custody reads and key preparation may consume the observation's
        // original lifetime. Check again after that work, immediately before
        // handing secret material to the signing client. The post-call check
        // below alone cannot prevent a call made with already-expired evidence.
        let response = with_recent_remote_build_v24(
            || funding.facts().age(),
            || sidecar.build_sweep_with_proofs_v23(build).map_err(map_port),
        )?;
        drop(sidecar);
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

/// A veto at this module's secret-bearing client handoff, not a new authority
/// or a renewal of the original observation. Once admitted, the synchronous
/// client call may complete; the caller independently checks freshness again
/// before returning its result. Durable sidecar cache bytes are never removed.
fn with_recent_remote_build_v24<T>(
    current_age: impl FnOnce() -> std::time::Duration,
    build: impl FnOnce() -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    if current_age() > f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE {
        return Err(Refusal::Unavailable);
    }
    build()
}

#[cfg(test)]
mod remote_build_freshness_tests_v24 {
    use super::*;
    use f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE;
    use std::{cell::Cell, time::Duration};

    #[test]
    fn expired_during_custody_preparation_never_reaches_remote_signing_client() {
        // Models only elapsed time and call ordering, never a fabricated
        // funding capability, signing request or native key.
        let age = Cell::new(Duration::ZERO);
        assert!(age.get() <= MAX_V11_EXTERNAL_ANCHOR_AGE);
        age.set(MAX_V11_EXTERNAL_ANCHOR_AGE + Duration::from_nanos(1));
        let calls = Cell::new(0);
        let outcome = with_recent_remote_build_v24(
            || age.get(),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert_eq!(outcome, Err(Refusal::Unavailable));
        assert_eq!(calls.get(), 0);
        assert!(age.get() > MAX_V11_EXTERNAL_ANCHOR_AGE);
    }

    #[test]
    fn remote_build_handoff_preserves_existing_boundary_and_client_refusals() {
        for age in [Duration::ZERO, MAX_V11_EXTERNAL_ANCHOR_AGE] {
            let calls = Cell::new(0);
            let original_identity = ([7; 32], 9u64, [11; 32]);
            assert_eq!(
                with_recent_remote_build_v24(
                    || age,
                    || {
                        calls.set(calls.get() + 1);
                        Ok(original_identity)
                    },
                ),
                Ok(original_identity)
            );
            assert_eq!(calls.get(), 1);
            for refusal in [Refusal::Conflict, Refusal::Unavailable] {
                assert_eq!(
                    with_recent_remote_build_v24(|| age, || Err::<(), _>(refusal)),
                    Err(refusal)
                );
            }
        }
    }
}
