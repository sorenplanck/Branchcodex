// Included in the parent Store tests: real early/BP journals, not a graph grant.
#[test]
fn graph_output_audit_requires_exact_completed_native_proof_and_survives_reopen(
) -> Result<(), Box<dyn Error>> {
    let temporary = TestDirectory::create()?;
    let evidence_policy = policy(BudgetPolicyProfileV1::EvidenceOnly)?;
    let (store, initial, fixture) = early_transport_store(&temporary, &evidence_policy)?;
    let (current, payloads) =
        complete_prepared_operational_bp_transport(&store, &initial, &fixture)?;
    let frozen = store
        .retained_shared_output_formation_v22(
            fixture.trusted_chain_id,
            initial.terms_hash(),
            42,
            &payloads.statement,
            &fixture.recovery_capsule,
        )?
        .ok_or("native formation required")?;
    let output = TransactionOutput::with_recovery_capsule(
        Commitment::from_compressed_bytes(frozen.aggregate_commitment())?,
        payloads.messages[10].clone(),
        &fixture.recovery_capsule,
    )?;
    let check = |store: &ContractsSessionStoreV1, value, terms, expected: &TransactionOutput| {
        store.audit_graph_output_for_test_v22(
            fixture.trusted_chain_id,
            initial.session_id(),
            terms,
            value,
            expected,
        )
    };
    let unfinished_directory = TestDirectory::create()?;
    let (unfinished, unfinished_initial, _) =
        early_transport_store(&unfinished_directory, &evidence_policy)?;
    assert!(check(&unfinished, 42, initial.terms_hash(), &output).is_err());
    assert_eq!(
        unfinished
            .load_session(unfinished_initial.session_id())?
            .as_bytes(),
        unfinished_initial.as_bytes()
    );
    check(&store, 42, initial.terms_hash(), &output)?;
    assert!(check(&store, 41, initial.terms_hash(), &output).is_err());
    assert!(check(&store, 42, [0xff; 32], &output).is_err());
    let mut changed_proof = payloads.messages[10].clone();
    changed_proof[0] ^= 1;
    let changed_output = TransactionOutput::with_recovery_capsule(
        Commitment::from_compressed_bytes(frozen.aggregate_commitment())?,
        changed_proof,
        &fixture.recovery_capsule,
    )?;
    assert!(check(&store, 42, initial.terms_hash(), &changed_output).is_err());
    let mut changed_capsule = output.clone();
    *changed_capsule
        .proof
        .last_mut()
        .ok_or("nonempty output envelope")? ^= 1;
    assert!(check(&store, 42, initial.terms_hash(), &changed_capsule).is_err());
    assert_eq!(
        store.load_session(initial.session_id())?.as_bytes(),
        current.as_bytes()
    );
    // The durable graph agreement will need public evidence that is verifiable
    // without reopening D or trusting a checksum as participant authentication.
    let roster = store.load_transport_roster(initial.session_id())?;
    let portable = {
        let _guard = store.operation_lock()?;
        super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::capture_locked(
            &store,
            initial.session_id(),
        )?
        .encode()?
    };
    drop(store);
    let journal = super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(&portable)?;
    assert_eq!(journal.encode()?, portable);
    assert_eq!(
        journal.verify(
            fixture.trusted_chain_id,
            initial.session_id(),
            initial.terms_hash(),
            42,
            &roster,
            &output
        )?,
        *blake2b_256(&payloads.messages[10]).as_bytes()
    );
    assert!(
        super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(
            &portable[..portable.len() - 1],
        )
        .is_err()
    );
    let mut trailing = portable.clone();
    trailing.push(0);
    assert!(
        super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(&trailing).is_err()
    );
    // Alter each signed message while preserving the public authority records
    // and framing. A decoder may accept the shape; signatures must still fail.
    let mut position = 8usize;
    for field in 0..19 {
        let length = u32::from_le_bytes(portable[position..position + 4].try_into()?) as usize;
        position += 4;
        if field >= 2 {
            let mut changed = portable.clone();
            changed[position + length - 1] ^= 1;
            if let Ok(changed) =
                super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(&changed)
            {
                assert!(
                    changed
                        .verify(
                            fixture.trusted_chain_id,
                            initial.session_id(),
                            initial.terms_hash(),
                            42,
                            &roster,
                            &output
                        )
                        .is_err(),
                    "message {}",
                    field - 2
                );
            }
        }
        position += length;
    }
    assert_eq!(position, portable.len());
    let reopened = ContractsSessionStoreV1::open_evidence_only(
        temporary.capability()?,
        "sessions",
        evidence_policy,
    )?;
    check(&reopened, 42, initial.terms_hash(), &output)?;
    assert_eq!(
        reopened.load_session(initial.session_id())?.as_bytes(),
        current.as_bytes()
    );
    Ok(())
}
