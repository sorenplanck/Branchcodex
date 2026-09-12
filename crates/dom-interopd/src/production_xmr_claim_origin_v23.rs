//! Private T handoff from the already-open selected XMR share custody.
//! This installs no exposure, performs no RPC and exports no scalar getter.
use super::*;
use dom_final_claim_binding::FinalClaimSecretSourceV1;

impl ProductionXmrSweepAuthorityV10 {
    pub(crate) fn install_native_claim_origin_v23<F: route_transport::F6TransportPortV1>(
        &self,
        admitted: &crate::production_xmr_graph_setup_v22::ProductionXmrGraphSetupV22,
        chain: dom_adaptor::TrustedChainIdV1,
        contracts: &crate::production_contracts::ProductionContractsV1<F>,
    ) -> Result<(), Refusal> {
        let binding = admitted.binding();
        let (plan, source, leg) = admitted.claim_context_v23().ok_or(Refusal::Conflict)?;
        let role = plan.entry(*leg);
        if admitted.terms() != &self.funding_terms_v22
            || admitted.setup().binding_hash() != self.binding.setup.binding_hash()
            || binding.chain_id() != self.binding.dom_chain_id
            || binding.session_id() != self.binding.session_id
            || binding.terms_digest() != self.binding.setup.terms_hash()
            || chain.as_bytes() != &binding.chain_id()
            || role.session_id().0 != binding.session_id()
            || plan.route_id() != binding.route_id()
            || role.secret_source_scope_digest() != source.digest()
        {
            return Err(Refusal::Conflict);
        }
        // A public-source leg must wait for the authenticated route revelation,
        // even if this process happens to retain a scalar with the same point.
        if !should_retain_native_origin_v23(
            role.secret_source(),
            role.adaptor_secret_origin_id().0,
            role.dom_claim_sender_id().0,
            binding.participant().participant_id(),
            self.funding_terms_v22.counterparty_leg.refund_to.0,
            self.binding.local_role,
        )? {
            return Ok(());
        }
        if !contracts
            .local_origin_needed_v21(binding, &chain)
            .map_err(|_| Refusal::Conflict)?
        {
            // An exposed/recovered claim is replayed from its immutable journal,
            // without rereading the original T from private share custody.
            return Ok(());
        }
        let material = self.material()?;
        self.binding.local_keys(&material)?;
        material.expose(|spend, _view| {
            let scalar = xmr_dleq_sigma::CrossCurveSecret252::from_little_endian(*spend)
                .map_err(|_| Refusal::Conflict)?;
            let public = scalar.public_claim().map_err(|_| Refusal::Conflict)?;
            if public.ed_compressed != self.binding.setup.claim().ed_compressed
                || public.secp_compressed != self.binding.setup.claim().secp_compressed
                || public.secp_compressed != admitted.terms().adaptor_point_sec1
            {
                return Err(Refusal::Conflict);
            }
            let bytes = zeroize::Zeroizing::new(scalar.dom_secret_big_endian());
            let secret =
                dom_adaptor::AdaptorSecret::from_be_bytes(*bytes).map_err(|_| Refusal::Conflict)?;
            // Only the same scoped Claim owner receives T. Its later exposure
            // still requires fresh two-chain F7, the role and the route action.
            contracts
                .install_local_origin_v21(
                    binding,
                    chain,
                    secret,
                    role,
                    admitted.terms().adaptor_point_sec1,
                )
                .map_err(|_| Refusal::Conflict)
        })
    }
}

// Evaluated only after the admitted route/terms/source binding is authenticated.
// This predicate grants neither signature nor exposure; it controls a private read.
fn should_retain_native_origin_v23(
    source: FinalClaimSecretSourceV1,
    origin: [u8; 32],
    sender: [u8; 32],
    local: [u8; 32],
    xmr_t_owner: [u8; 32],
    role: LocalRole,
) -> Result<bool, Refusal> {
    if source != FinalClaimSecretSourceV1::LocalOrigin {
        return Ok(false);
    }
    if origin != xmr_t_owner {
        return Err(Refusal::Conflict);
    }
    if origin != local {
        return Ok(false);
    }
    if sender != local || role != LocalRole::RefundReceiver {
        return Err(Refusal::Conflict);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_source_never_installs_an_early_local_origin() {
        for source in [
            FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
            FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23,
        ] {
            assert_eq!(
                should_retain_native_origin_v23(
                    source,
                    [1; 32],
                    [1; 32],
                    [1; 32],
                    [1; 32],
                    LocalRole::RefundReceiver,
                ),
                Ok(false)
            );
        }
    }

    #[test]
    fn native_origin_is_only_the_local_t_owner_and_dom_sender() {
        let origin = FinalClaimSecretSourceV1::LocalOrigin;
        assert_eq!(
            should_retain_native_origin_v23(
                origin,
                [1; 32],
                [1; 32],
                [1; 32],
                [1; 32],
                LocalRole::RefundReceiver
            ),
            Ok(true)
        );
        // The U owner participates in signing without obtaining T from its row.
        assert_eq!(
            should_retain_native_origin_v23(
                origin,
                [1; 32],
                [1; 32],
                [2; 32],
                [1; 32],
                LocalRole::ClaimReceiver
            ),
            Ok(false)
        );
        assert!(should_retain_native_origin_v23(
            origin,
            [1; 32],
            [2; 32],
            [1; 32],
            [1; 32],
            LocalRole::RefundReceiver
        )
        .is_err());
        assert!(should_retain_native_origin_v23(
            origin,
            [1; 32],
            [1; 32],
            [1; 32],
            [1; 32],
            LocalRole::ClaimReceiver
        )
        .is_err());
        assert!(should_retain_native_origin_v23(
            origin,
            [2; 32],
            [2; 32],
            [2; 32],
            [1; 32],
            LocalRole::RefundReceiver
        )
        .is_err());
    }
}
