//! Actual sidecar sweep construction after durable receiver observation.
//! Requires a coherent offline ledger RPC; never replaces it with an echo.
//! No broadcast, admission receipt or generic private-key getter.
use super::*;

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn build_observed_claim_sweep_v23(
        &self,
        actor: usize,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: dom_actuator::DomSessionBindingV1,
        chain: dom_adaptor::TrustedChainIdV1,
        runtime: &adapter_dom_real::RealDomRpcRuntimeV1,
        sidecar: &mut xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
        nonce: [u8; 32],
    ) -> Result<crate::production_child_xmr::XmrBuiltSweepV1> {
        use xmr_secret_store::SecretMaterialStore;
        use xmr_spend_port::SweepBuildPort;
        use zeroize::Zeroize;
        let owner = self.actors.get(actor).ok_or("unknown sweep receiver")?;
        let payout = self
            .claim_payout_v23
            .as_ref()
            .ok_or("no frozen Claim payout wallet")?;
        if owner.role != XmrLocalShareRoleV11::ClaimReceiver
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
        let facts = store
            .f7_claim_receiver_facts_v15(
                chain,
                binding.session_id(),
                binding.participant().participant_id(),
            )?
            .ok_or("receiver lacks accepted Claim")?;
        let observed = store
            .resume_f7_claim_observation_v15(chain, binding.session_id())?
            .ok_or("receiver observation not durable")?;
        let mut revealed = runtime.consume_observed_f7_claim_v15(&facts, &observed)?;
        let secret = Zeroizing::new(revealed.expose_scalar_bytes());
        revealed.zeroize();
        let remote = xmr_crypto::XmrSpendShare::from_canonical_bytes(
            xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar(*secret, &self.setup.claim())?,
        )?;
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
                destination: payout.address().to_owned(),
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
        payout.verify_payment(&result.raw_tx, result.tx_hash, amount)?;
        Ok(crate::production_child_xmr::XmrBuiltSweepV1 {
            tx_hash: result.tx_hash,
            key_image: *image,
            raw_transaction: result.raw_tx,
            remote_custody_v23: None,
        })
    }
}
