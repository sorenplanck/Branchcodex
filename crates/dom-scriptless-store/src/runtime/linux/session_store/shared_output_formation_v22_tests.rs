// Included in the native session-store tests; uses real signed early messages.
#[test]
fn retained_shared_formation_reopens_and_refuses_value_terms_capsule_substitution(
) -> Result<(), Box<dyn Error>> {
    let temporary = TestDirectory::create()?;
    let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
    let (store, initial, fixture) = early_transport_store(&temporary, &evidence_policy)?;
    let shares = fixture
        .signing_shares
        .iter()
        .map(|share| share.public_key().clone())
        .collect::<Vec<_>>();
    let statement = BpStatementV1::new(
        &fixture.trusted_chain_id,
        initial.session_id(),
        fixture.participant_ids.to_vec(),
        42,
        shares.clone(),
        BpStatementV1::aggregate_commitment_from_shares(&shares, 42)?,
        Some(*blake2b_256(fixture.recovery_capsule.as_bytes()).as_bytes()),
    )?;
    assert!(store
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            42,
            &statement,
            &fixture.recovery_capsule,
        )?
        .is_none());
    let current = complete_prepared_early_transport(&store, &initial, &fixture)?;
    let frozen = store
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            42,
            &statement,
            &fixture.recovery_capsule,
        )?
        .ok_or("completed early journal must reconstruct formation")?;
    assert_eq!(frozen.statement().to_bytes(), statement.to_bytes());
    assert_eq!(frozen.value_noms(), 42);
    assert_eq!(frozen.terms_hash(), &initial.terms_hash());
    let bytes = frozen.statement().to_bytes();
    drop(store);
    let reopened = ContractsSessionStoreV1::open_evidence_only(
        temporary.capability()?,
        "sessions",
        evidence_policy,
    )?;
    let frozen = reopened
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            42,
            &statement,
            &fixture.recovery_capsule,
        )?
        .ok_or("reopened journal must preserve native formation")?;
    assert_eq!(frozen.statement().to_bytes(), bytes);
    assert!(reopened
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            41,
            &statement,
            &fixture.recovery_capsule,
        )
        .is_err());
    let mut terms = initial.terms_hash();
    terms[0] ^= 1;
    assert!(reopened
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            terms,
            42,
            &statement,
            &fixture.recovery_capsule,
        )
        .is_err());
    let mut capsule = fixture.recovery_capsule.as_bytes().to_vec();
    *capsule.last_mut().ok_or("capsule must not be empty")? ^= 1;
    let capsule = RecoveryCapsule::from_bytes(&capsule)?;
    assert!(reopened
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            42,
            &statement,
            &capsule,
        )
        .is_err());
    assert_eq!(
        reopened.load_session(initial.session_id())?.as_bytes(),
        current.as_bytes()
    );
    Ok(())
}
