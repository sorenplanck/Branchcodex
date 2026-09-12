//! Actual refund sweep after durable canonical U observation; no peer callback.
//! Requires a coherent offline ledger RPC; never replaces it with an echo.
//! No broadcast, admission receipt or generic private-key getter.
use super::*;

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn build_observed_refund_sweep_v23(
        &self,
        actor: usize,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: dom_actuator::DomSessionBindingV1,
        chain: dom_adaptor::TrustedChainIdV1,
        runtime: &adapter_dom_real::RealDomRpcRuntimeV1,
        authority: &dom_scriptless_store::VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &dom_scriptless_store::XmrRecoveryCustodyV11,
        sidecar: &mut xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
        nonce: [u8; 32],
    ) -> Result<crate::production_child_xmr::XmrBuiltSweepV1> {
        use xmr_secret_store::SecretMaterialStore;
        use xmr_spend_port::SweepBuildPort;
        let owner = self.actors.get(actor).ok_or("unknown sweep receiver")?;
        let payout = self
            .claim_payout_v23
            .as_ref()
            .ok_or("no frozen Claim payout wallet")?;
        if owner.role != XmrLocalShareRoleV11::RefundReceiver
            || self.setup.terms_hash() != binding.terms_digest()
            || chain.as_bytes() != &binding.chain_id()
            || self.setup.destination() != payout.address()
            || nonce == [0; 32]
        {
            return Err("native sweep scope mismatch".into());
        }
        xmr_session_init::resume_session_for_role_v11(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            owner.role,
        )?;
        store.validate_xmr_recovery_attachment_v12(
            &store.resume_f7_funding_gate_v12(chain, binding.session_id())?,
            custody,
        )?;
        authority.require_custody(custody)?;
        let adapter_dom_real::VerifiedDomXmrRecoveryStateV11::Refunded(revealed) =
            runtime.observe_xmr_recovery_v12(authority, custody)?
        else {
            return Err("canonical confirmed Refund U required".into());
        };
        if revealed.session_id() != binding.session_id()
            || revealed.chain_id() != binding.chain_id()
            || revealed.finality().terms_hash() != binding.terms_digest()
            || revealed.template_hash()
                != custody.with_graph(|graph| *graph.refund_pre_signature().template_hash())?
        {
            return Err("observed Refund scope mismatch".into());
        }
        let refund_claim = xmr_refund_adaptor::verify_refund_bundle(
            &self.refund_proof,
            &self.setup.settlement_id(),
            self.setup.proof_context_hash(),
        )?;
        self.refund_policy
            .require_refund_point(&refund_claim.secp_compressed)?;
        if revealed.refund_point() != refund_claim.secp_compressed {
            return Err("observed refund point mismatch".into());
        }
        let executor = DomRefundAdaptorExecutor::new(refund_claim);
        let remote = revealed.expose(|bytes| executor.recover_share(*bytes))?;
        let material = owner
            .secrets
            .load(&self.setup.settlement_id(), &self.setup.terms_hash())?;
        let result = material.expose(|spend, view| -> Result<_> {
            let local = xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)?;
            let combined = local.combine(&remote)?;
            if combined.public_key()? != self.setup.combined_spend_public_key() {
                return Err("native sweep combined key mismatch".into());
            }
            let request = xmr_live_sidecar_api::BuildSweepRequestV2 {
                api_version: xmr_live_sidecar_api::API_VERSION_V2,
                request_nonce: nonce,
                settlement_id: self.setup.settlement_id(),
                funding_tx_hash: self.setup.funding_tx_hash(),
                expected_amount_piconero: self.setup.expected_amount_piconero(),
                destination: payout.refund_address().to_owned(),
                spend_scalar: combined.expose(|s| xmr_live_sidecar_api::SecretScalarBytes::new(*s)),
                expected_spend_public_key: self.setup.combined_spend_public_key(),
                view_scalar: xmr_live_sidecar_api::SecretScalarBytes::new(*view),
                auth_tag: [0; 32],
            };
            request.validate_public_fields()?;
            Ok(sidecar.build_sweep(request)?)
        })?;
        result.validate_for(&nonce)?;
        let verified = xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
            &result.raw_tx,
            result.tx_hash,
            self.setup.expected_amount_piconero(),
            payout.max_fee,
        )?;
        let [image] = verified.sweep().key_images.as_slice() else {
            return Err("native sweep requires one exact input key image".into());
        };
        let amount = self
            .setup
            .expected_amount_piconero()
            .checked_sub(verified.fee_piconero())
            .ok_or("sweep fee exceeds funded amount")?;
        payout.verify_refund_payment(&result.raw_tx, result.tx_hash, amount)?;
        Ok(crate::production_child_xmr::XmrBuiltSweepV1 {
            tx_hash: result.tx_hash,
            key_image: *image,
            raw_transaction: result.raw_tx,
            remote_custody_v23: None,
        })
    }
}
