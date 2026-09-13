// Included in the existing tests module to reuse the threshold-verified
// registry fixture. These exercise private consistency checks, not an opaque
// refund authority, signed consent, or a grant to move funds.
#[cfg(test)]
mod dom_profile_domains_v25_tests {
    use super::*;

    #[test]
    fn refund_dom_profile_domains_match_real_registry_and_wallet_independently_v25() {
        let fixture = time_common::fixture();
        let deployment = fixture
            .registry
            .resolve_dom()
            .expect("verified DOM deployment");
        let adapter = route_time_anchor::resolved_dom_deployment_profile_digest_v25(deployment)
            .expect("complete adapter profile");
        let consensus = deployment.deployment().consensus_rules_digest;
        assert_eq!(
            adapter,
            route_time_anchor::resolved_dom_profile_digest_v1(&fixture.registry)
                .expect("original signed-registry profile")
        );
        assert_ne!(adapter, consensus);
        for terms in [&fixture.upstream, &fixture.downstream] {
            let pins = admission_pins_for_fixture(
                &fixture,
                terms.counterparty_leg.chain_id,
                terms.counterparty_leg.asset_id,
                terms.terms_hash().expect("original terms"),
            );
            let binding = DomSessionBindingV1::from_resolved_deployment(
                digest(0x91),
                terms.session_id.0,
                DomParticipantV1::new(terms.dom_leg.beneficiary.0, 1)
                    .expect("original participant"),
                terms.terms_hash().expect("original terms"),
                deployment,
            )
            .expect("real wallet session binding");
            assert_eq!(binding.profile_digest(), consensus);
            assert_eq!(pins.dom_profile_digest, consensus);
            assert_eq!(pins.dom_adapter_profile_digest, adapter);
            assert_eq!(terms.dom_leg.adapter_profile_hash, adapter);
            assert!(validate_dom_settlement_pins_v25(binding, terms, pins).is_ok());
        }
    }

    #[test]
    fn refund_dom_profile_domain_substitution_and_foreign_pins_refuse_v25() {
        let fixture = time_common::fixture();
        let terms = &fixture.upstream;
        let deployment = fixture
            .registry
            .resolve_dom()
            .expect("verified DOM deployment");
        let pins = admission_pins_for_fixture(
            &fixture,
            terms.counterparty_leg.chain_id,
            terms.counterparty_leg.asset_id,
            terms.terms_hash().expect("original terms"),
        );
        let binding = DomSessionBindingV1::from_resolved_deployment(
            digest(0x91),
            terms.session_id.0,
            DomParticipantV1::new(terms.dom_leg.beneficiary.0, 1).expect("participant"),
            terms.terms_hash().expect("original terms"),
            deployment,
        )
        .expect("real wallet session binding");
        let original_terms = terms.canonical_bytes().expect("canonical original terms");
        for case in 0..7 {
            let mut changed = pins;
            match case {
                0 => changed.dom_adapter_profile_digest = pins.dom_profile_digest,
                1 => changed.dom_adapter_profile_digest = ZERO_DIGEST,
                2 => changed.dom_adapter_profile_digest[0] ^= 1,
                3 => changed.dom_profile_digest = pins.dom_adapter_profile_digest,
                4 => changed.registry_digest[0] ^= 1,
                5 => changed.registry_epoch += 1,
                6 => changed.dom_asset_binding_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_dom_settlement_pins_v25(binding, terms, changed),
                Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration),
                "both profile domains and their authenticated deployment remain mandatory"
            );
        }
        let mut substituted = terms.clone();
        substituted.dom_leg.adapter_profile_hash = binding.profile_digest();
        assert_eq!(
            validate_dom_settlement_pins_v25(binding, &substituted, pins),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        assert!(validate_dom_settlement_pins_v25(binding, terms, pins).is_ok());
        assert_eq!(
            terms.canonical_bytes().expect("original terms"),
            original_terms
        );
    }
}
