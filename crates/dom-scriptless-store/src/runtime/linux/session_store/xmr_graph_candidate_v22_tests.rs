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
    assert_eq!(transport_payload_cap(0x18), None);
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
