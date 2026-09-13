// Included in parent Store tests. Exercises cache publication/reopen, NOT a
// bilateral agreement or successful reconstruction of a complete graph.
#[test]
fn unsigned_xmr_candidate_cache_is_immutable_scoped_and_not_a_transport_grant(
) -> Result<(), Box<dyn Error>> {
    use super::xmr_graph_candidate_v22 as candidate;
    let temporary = TestDirectory::create()?;
    let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
    let (store, initial, fixture) = early_transport_store(&temporary, &evidence_policy)?;
    let bytes = candidate::framing_fixture_for_test(
        *fixture.trusted_chain_id.as_bytes(),
        initial.session_id(),
        initial.terms_hash(),
    )?;
    let name = format!("{}{}", hex_lower(&initial.session_id()), candidate::SUFFIX);
    let staging = format!(".{name}.staging");
    // Direct native publication is a test fixture. Production only accepts an
    // opaque audit token and rechecks the actual parent's 17-message journal.
    publish_immutable(&store.rosters, &staging, &name, &bytes, candidate::MAX)?;
    publish_immutable(&store.rosters, &staging, &name, &bytes, candidate::MAX)?;
    let changed = candidate::framing_fixture_for_test(
        *fixture.trusted_chain_id.as_bytes(),
        initial.session_id(),
        [0xfa; 32],
    )?;
    assert!(matches!(
        publish_immutable(&store.rosters, &staging, &name, &changed, candidate::MAX),
        Err(SessionStoreError::Conflict)
    ));
    assert_eq!(
        store
            .read_xmr_graph_candidate_v22(initial.session_id())?
            .encode()?,
        bytes
    );
    assert_eq!(
        store.load_session(initial.session_id())?.as_bytes(),
        initial.as_bytes()
    );
    // Native graph commits now have a registered 32-byte payload. Registration
    // and a scope-valid unsigned cache still cannot authorize a new envelope.
    assert_eq!(transport_payload_cap(0x18), Some(32));
    let signed_commit = transport_signed_bytes(
        &fixture.identity_keys[0],
        *fixture.trusted_chain_id.as_bytes(),
        initial.session_id(),
        fixture.participant_ids[0],
        0,
        initial.transcript_hash(),
        0x18,
        &[0x55; 32],
    )?;
    ParsedTransportEnvelopeV1::parse(&signed_commit)?
        .verify(&fixture.identity_keys[0].public_key())?;
    let require_no_grant =
        |candidate_store: &ContractsSessionStoreV1| -> Result<(), Box<dyn Error>> {
            let before = snapshot_store_tree(&temporary.0.join("sessions"))?;
            assert!(matches!(
                candidate_store.accept_transport_message_derived(&signed_commit),
                Err(SessionStoreError::InvalidTransition)
            ));
            // The fixture's unsigned proposal uses this route, but never supplies
            // the native graph-commit context required by the real request owner.
            assert!(matches!(
                candidate_store.prepare_xmr_graph_commit_dsc1_signing_request_v23(
                    fixture.trusted_chain_id,
                    [5; 32],
                    initial.session_id(),
                ),
                Err(SessionStoreError::SessionNotFound)
            ));
            assert_eq!(
                candidate_store
                    .load_session(initial.session_id())?
                    .as_bytes(),
                initial.as_bytes()
            );
            // Do not print the synthetic Store contents on failure.
            assert!(snapshot_store_tree(&temporary.0.join("sessions"))? == before);
            Ok(())
        };
    require_no_grant(&store)?;
    drop(store);
    let reopened = ContractsSessionStoreV1::open_evidence_only(
        temporary.capability()?,
        "sessions",
        evidence_policy.clone(),
    )?;
    assert_eq!(
        reopened
            .read_xmr_graph_candidate_v22(initial.session_id())?
            .encode()?,
        bytes
    );
    assert_eq!(
        reopened.load_session(initial.session_id())?.as_bytes(),
        initial.as_bytes()
    );
    require_no_grant(&reopened)?;
    // No parent ceremony exists in this fixture: framing alone cannot produce
    // the native C provenance required by candidate reconstruction.
    assert!(
        super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::capture_locked(
            &reopened,
            initial.session_id(),
        )
        .is_err()
    );
    drop(reopened);
    let final_path = temporary.0.join("sessions").join(ROSTERS_NAME).join(&name);
    std::fs::rename(&final_path, temporary.0.join("saved-candidate"))?;
    write_store_test_file(&temporary, "sessions", ROSTERS_NAME, &name, &changed)?;
    assert!(ContractsSessionStoreV1::open_evidence_only(
        temporary.capability()?,
        "sessions",
        evidence_policy,
    )
    .is_err());
    Ok(())
}
