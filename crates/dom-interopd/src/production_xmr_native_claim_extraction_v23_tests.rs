//! Closed receiver operation after actual DOM verifier extraction. No spend
//! submission or combined-key export; checks the exact XMR destination only.
use super::*;

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn verify_extracted_claim_destination_v23(
        &self,
        actor: usize,
        revealed: counterparty_api::RevealedSecretBytes,
    ) -> Result<()> {
        use xmr_secret_store::SecretMaterialStore;
        use zeroize::Zeroize;
        let owner = self
            .actors
            .get(actor)
            .ok_or("unknown extracted Claim receiver")?;
        if owner.role != XmrLocalShareRoleV11::ClaimReceiver {
            return Err("only U owner may combine observed T for XMR Claim".into());
        }
        xmr_session_init::resume_session_for_role_v11(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            owner.role,
        )?;
        let mut revealed = revealed;
        let bytes = Zeroizing::new(revealed.expose_scalar_bytes());
        revealed.zeroize();
        let remote_bytes = Zeroizing::new(xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar(
            *bytes,
            &self.setup.claim(),
        )?);
        let remote = xmr_crypto::XmrSpendShare::from_canonical_bytes(*remote_bytes)?;
        let material = owner
            .secrets
            .load(&self.setup.settlement_id(), &self.setup.terms_hash())?;
        material.expose(|spend, _view| {
            let local = xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)?;
            if local.public_share()?
                != xmr_refund_adaptor::verify_refund_bundle(
                    &self.refund_proof,
                    &self.setup.settlement_id(),
                    self.setup.proof_context_hash(),
                )?
                .ed_compressed
            {
                return Err("receiver retained U point mismatch".into());
            }
            let combined = local.combine(&remote)?;
            if combined.public_key()? != self.setup.combined_spend_public_key() {
                return Err("observed T plus retained U destination mismatch".into());
            }
            Ok(())
        })
    }
}
