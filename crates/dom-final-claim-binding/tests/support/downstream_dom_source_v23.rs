use super::*;

fn source_input(f: &Fixture) -> FinalClaimSecretSourceScopeInputV1 {
    FinalClaimSecretSourceScopeInputV1 {
        secret_source: FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23,
        reveal_mode: FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
        route_id: f.route_id,
        composition_binding_digest: f.composition_binding_digest,
        source_chain_id: f.downstream.dom_leg.chain_id,
        source_settlement_id: f.downstream.settlement_id,
        source_session_id: f.downstream.session_id,
        source_claim_template_hash: f.downstream_scope.source_claim_template_hash(),
        adaptor_point_sec1: f.downstream.adaptor_point_sec1,
        adaptor_secret_origin_id: f.sender,
        dom_claim_sender_id: f.sender,
    }
}

fn bind(
    f: &Fixture,
    input: FinalClaimSecretSourceScopeInputV1,
) -> Result<ComposedFinalClaimRolePlanV1, FinalClaimBindingError> {
    let upstream_scope = FinalClaimSecretSourceScopeV1::new(input)?;
    ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
        route_id: f.route_id,
        route_scope_digest: f.route_scope_digest,
        composition_binding_digest: f.composition_binding_digest,
        upstream_terms: &f.upstream,
        downstream_terms: &f.downstream,
        upstream_selection: FinalClaimRoleSelectionV1::new(
            f.sender,
            f.sender,
            f.receiver,
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            FinalClaimSecretSourceV1::VerifiedDownstreamDomClaimV23,
            upstream_scope,
        )?,
        downstream_selection: FinalClaimRoleSelectionV1::new(
            f.sender,
            f.sender,
            f.receiver,
            FinalClaimRevealModeV1::DomRevealsFirst,
            FinalClaimSecretSourceV1::LocalOrigin,
            f.downstream_scope.clone(),
        )?,
    })
}

#[test]
fn downstream_dom_dependency_is_exact_and_not_local_origin() {
    let f = Fixture::new();
    let source = FinalClaimSecretSourceScopeV1::new(source_input(&f)).unwrap();
    let plan = bind(&f, source_input(&f)).unwrap();
    let decoded = ComposedFinalClaimRolePlanV1::decode_canonical(&plan.canonical_bytes()).unwrap();
    decoded
        .authenticate(
            &f.upstream,
            &f.downstream,
            source.clone(),
            f.downstream_scope.clone(),
        )
        .unwrap();
    assert_eq!(source.secret_source().to_byte(), 3);
    assert_ne!(
        source.secret_source(),
        FinalClaimSecretSourceV1::LocalOrigin
    );
    assert_eq!(source.source_session_id(), f.downstream.session_id);
    assert_ne!(source.source_session_id(), f.upstream.session_id);
    assert_eq!(
        FinalClaimSecretSourceScopeV1::decode_canonical(&source.canonical_bytes()).unwrap(),
        source
    );
}

#[test]
fn downstream_dom_dependency_refuses_scope_or_template_substitution() {
    let f = Fixture::new();
    for mutation in 0..7 {
        let mut input = source_input(&f);
        match mutation {
            0 => input.source_claim_template_hash[0] ^= 1,
            1 => input.source_session_id = f.upstream.session_id,
            2 => input.source_settlement_id = f.upstream.settlement_id,
            3 => input.source_chain_id = f.downstream.counterparty_leg.chain_id,
            4 => input.route_id[0] ^= 1,
            5 => input.composition_binding_digest[0] ^= 1,
            _ => input.adaptor_point_sec1 = point(TWO_G),
        }
        assert!(bind(&f, input).is_err(), "mutation {mutation}");
    }
    let mut early = source_input(&f);
    early.reveal_mode = FinalClaimRevealModeV1::DomRevealsFirst;
    assert_eq!(
        FinalClaimSecretSourceScopeV1::new(early).unwrap_err(),
        FinalClaimBindingError::InvalidModeSource
    );
}
