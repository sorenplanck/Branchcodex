//! Closed fixture operation on retained T. No scalar or transaction-byte getter.
//! Uses actual F7/actuator fencing; does not represent daemon route admission.
use super::*;

impl NativeXmrCustodyFixtureV23 {
    pub(crate) fn expose_native_claim_v23(
        &self,
        actor: usize,
        store: &dom_scriptless_store::ContractsSessionStoreV1,
        binding: dom_actuator::DomSessionBindingV1,
        chain: dom_adaptor::TrustedChainIdV1,
        authority: &dom_scriptless_store::ConsumedF7ClaimAuthorizationV12,
        role: &dom_final_claim_binding::FinalClaimRoleBindingV1,
        control: &mut dom_actuator::DomActuatorStoreV1,
        lease: dom_actuator::DomLeaseV1,
        scope: dom_actuator::ScopedDomActionV1,
        now: u64,
    ) -> Result<dom_actuator::DomF7FinalClaimSubmissionV14> {
        use xmr_secret_store::SecretMaterialStore;
        let owner = self.actors.get(actor).ok_or("unknown native Claim owner")?;
        let local = binding.participant().participant_id();
        if owner.role != XmrLocalShareRoleV11::RefundReceiver
            || role.secret_source()
                != dom_final_claim_binding::FinalClaimSecretSourceV1::LocalOrigin
            || role.dom_claim_sender_id().0 != local
            || role.terms().counterparty_leg.refund_to.0 != local
            || role.session_id().0 != binding.session_id()
            || role.route_id() != binding.route_id()
            || self.setup.terms_hash() != binding.terms_digest()
            || self.setup.settlement_id() != role.settlement_id().0
            || chain.as_bytes() != &binding.chain_id()
            || scope.binding() != binding
        {
            return Err("native private T Claim scope mismatch".into());
        }
        xmr_session_init::resume_session_for_role_v11(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            owner.role,
        )?;
        // Refuse stale or wrong-sender authority before decrypting local T.
        eprintln!("DIAG expose: passed scope checks, calling revalidate_f7_final_claim_authority_v14 (recency)");
        store.revalidate_f7_final_claim_authority_v14(authority, chain, local)?;
        eprintln!("DIAG expose: authority recency OK, loading secret + prepare_and_expose");
        let material = owner
            .secrets
            .load(&self.setup.settlement_id(), &self.setup.terms_hash())?;
        material.expose(|spend, _view| {
            let scalar = CrossCurveSecret252::from_little_endian(*spend)?;
            let public = scalar.public_claim()?;
            if public.ed_compressed != self.setup.claim().ed_compressed
                || public.secp_compressed != self.setup.claim().secp_compressed
                || public.secp_compressed != role.adaptor_point_sec1()
            {
                return Err("retained T does not match native Claim points".into());
            }
            let bytes = Zeroizing::new(scalar.dom_secret_big_endian());
            let secret = dom_adaptor::AdaptorSecret::from_be_bytes(*bytes)?;
            let height = store.load_session(binding.session_id())?.chain().tip_height;
            eprintln!("DIAG expose: validation_height (session tip_height) = {height}");
            Ok(dom_actuator::DomContractsActuatorV1::bind(store, binding)?
                .prepare_and_expose_f7_final_claim_v14(
                    control,
                    lease,
                    &chain,
                    dom_actuator::DomF7FinalClaimRequestV14 {
                        scope,
                        authority,
                        secret: &secret,
                        validation_height: height,
                        now_unix_ms: now,
                    },
                )?)
        })
    }
}
