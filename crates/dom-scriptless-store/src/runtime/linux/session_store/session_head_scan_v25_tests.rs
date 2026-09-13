// Included inside the existing session_store::tests module to reuse its real
// filesystem fixture and evidence-only policy. These are record-loader tests,
// not substitutes for transport, signing, funding or recovery authorization.
#[cfg(test)]
mod session_head_scan_v25_tests {
    use super::*;

    fn fixture() -> Result<(TestDirectory, ContractsSessionStoreV1), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let store = ContractsSessionStoreV1::create_evidence_only(
            directory.capability()?,
            "head-scan",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        Ok((directory, store))
    }

    fn history(session: [u8; 32], count: usize) -> Result<Vec<SessionRecordV1>, Box<dyn Error>> {
        let mut records = vec![record_with_session_and_terms_hash(
            session,
            SessionPhaseV1::Created,
            [0x32; 32],
        )?];
        for index in 1..count {
            let previous = records.last().unwrap();
            records.push(previous.advance(
                previous.revision(),
                SessionPhaseV1::TermsCommitted,
                [index as u8; 32],
                previous.irreversible(),
                previous.chain(),
                previous.encrypted_payload(),
            )?);
        }
        Ok(records)
    }

    // Independent baseline retains the original lexicographic scanner. This
    // deliberately does not use the new unordered scanner or cached heads.
    fn original_lexical_head(
        store: &ContractsSessionStoreV1,
        session: [u8; 32],
    ) -> Result<SessionRecordV1, SessionStoreError> {
        let mut records = Vec::new();
        store.records.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let (owner, revision) = parse_session_record_name(name)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            if owner != hex_lower(&session) {
                return Ok(());
            }
            let bytes = store.records.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                SESSION_RECORD_MAX_LEN,
            )?;
            let record = SessionRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.session_id() != session || record.revision() != revision {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            records.push(record);
            Ok(())
        })?;
        records.sort_by_key(SessionRecordV1::revision);
        if records
            .first()
            .ok_or(SessionStoreError::SessionNotFound)?
            .revision()
            != 0
        {
            return Err(SessionStoreError::Quarantined);
        }
        for pair in records.windows(2) {
            if pair[0].revision().checked_add(1) != Some(pair[1].revision())
                || require_exact_successor(&pair[0], pair[0].revision(), &pair[1]).is_err()
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        records.pop().ok_or(SessionStoreError::SessionNotFound)
    }

    #[test]
    fn session_head_scan_shuffled_revisions_match_original_lexical_head_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store) = fixture()?;
        let target = history([0x61; 32], 40)?;
        let foreign = history([0x62; 32], 17)?;
        assert!(matches!(
            store.load_session(target[0].session_id()),
            Err(SessionStoreError::SessionNotFound)
        ));
        // Multiplication by 17 permutes all 40 positions. Physical publication
        // order is neither chronological nor lexicographic.
        for index in 0..40 {
            store.persist_session_record(&target[(index * 17) % 40])?;
            if index < foreign.len() {
                store.persist_session_record(&foreign[foreign.len() - 1 - index])?;
            }
        }
        for records in [&target, &foreign] {
            let expected = original_lexical_head(&store, records[0].session_id())?;
            assert_eq!(expected.as_bytes(), records.last().unwrap().as_bytes());
            assert_eq!(
                store.load_session(records[0].session_id())?.as_bytes(),
                expected.as_bytes()
            );
        }
        assert!(matches!(
            store.load_session([0x7f; 32]),
            Err(SessionStoreError::SessionNotFound)
        ));
        Ok(())
    }

    #[test]
    fn session_head_scan_missing_origin_and_interior_gap_stay_quarantined_v25(
    ) -> Result<(), Box<dyn Error>> {
        for missing in [0, 2] {
            let (_directory, store) = fixture()?;
            let records = history([0x63; 32], 5)?;
            for (index, record) in records.iter().enumerate().rev() {
                if index != missing {
                    store.persist_session_record(record)?;
                }
            }
            assert_quarantined(original_lexical_head(&store, records[0].session_id()));
            assert_quarantined(store.load_session(records[0].session_id()));
        }
        Ok(())
    }

    #[test]
    fn session_head_scan_changed_terms_and_irreversible_regression_refuse_v25(
    ) -> Result<(), Box<dyn Error>> {
        for changed_terms in [true, false] {
            let (_directory, store) = fixture()?;
            let records = history([0x64; 32], 2)?;
            let successor = &records[1];
            let mut irreversible = successor.irreversible();
            if !changed_terms {
                irreversible.any_signing_share_sent = false;
            }
            let invalid = SessionRecordV1::new(
                SessionRecordFieldsV1 {
                    session_id: successor.session_id(),
                    revision: successor.revision(),
                    phase: successor.phase(),
                    terms_hash: if changed_terms {
                        [0x99; 32]
                    } else {
                        successor.terms_hash()
                    },
                    transcript_hash: successor.transcript_hash(),
                    irreversible,
                    chain: successor.chain(),
                },
                successor.encrypted_payload(),
            )?;
            store.persist_session_record(&records[0])?;
            store.persist_session_record(&invalid)?;
            assert_quarantined(original_lexical_head(&store, successor.session_id()));
            assert_quarantined(store.load_session(successor.session_id()));
        }
        Ok(())
    }

    #[test]
    fn session_head_scan_projection_is_exact_scoped_and_never_a_cached_head_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store) = fixture()?;
        let records = history([0x65; 32], 3)?;
        let foreign = history([0x66; 32], 2)?;
        store.persist_session_record(&records[0])?;
        // Private projected RECORD data only. This tests the existing loader's
        // merge, and creates no recovery plan, transport receipt or authority.
        let projection = ContractsStoreRecoveryProjectionV1 {
            records: [records[2].clone(), foreign[1].clone(), records[1].clone()]
                .into_iter()
                .map(|record| ((record.session_id(), record.revision()), record))
                .collect(),
            artifacts: BTreeMap::new(),
            consumptions: BTreeMap::new(),
        };
        *store.recovery_projection.lock().unwrap() = Some(projection);
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[2].as_bytes()
        );
        // Foreign revision one must not borrow this session's revision zero.
        assert_quarantined(store.load_session(foreign[0].session_id()));
        store.recovery_projection.lock().unwrap().take();
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[0].as_bytes()
        );
        Ok(())
    }

    #[test]
    fn session_head_scan_disk_projection_duplicate_revision_is_not_deduplicated_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store) = fixture()?;
        let records = history([0x67; 32], 2)?;
        for record in &records {
            store.persist_session_record(record)?;
        }
        *store.recovery_projection.lock().unwrap() = Some(ContractsStoreRecoveryProjectionV1 {
            records: [(
                (records[1].session_id(), records[1].revision()),
                records[1].clone(),
            )]
            .into_iter()
            .collect(),
            artifacts: BTreeMap::new(),
            consumptions: BTreeMap::new(),
        });
        assert_quarantined(store.load_session(records[0].session_id()));
        store.recovery_projection.lock().unwrap().take();
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[1].as_bytes()
        );
        Ok(())
    }

    #[test]
    fn session_head_scan_invalid_foreign_registered_entry_cannot_be_filtered_out_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store) = fixture()?;
        let initial = history([0x68; 32], 1)?.remove(0);
        store.persist_session_record(&initial)?;
        assert_eq!(
            store.load_session(initial.session_id())?.as_bytes(),
            initial.as_bytes()
        );
        // This is a registered regular filename, but belongs at the Store
        // root, never inside the session-record namespace. An unregistered
        // arbitrary name would fail before reaching the loader under test.
        let component = ValidatedComponent::registered(POLICY_NAME)?;
        let retained = store
            .records
            .create_immutable_file(&component, b"not a session record")?;
        assert_quarantined(original_lexical_head(&store, initial.session_id()));
        assert_quarantined(store.load_session(initial.session_id()));
        store.records.unlink_verified_file(&component, &retained)?;
        assert_eq!(
            store.load_session(initial.session_id())?.as_bytes(),
            initial.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn session_head_scan_filename_cannot_substitute_record_session_or_revision_v25(
    ) -> Result<(), Box<dyn Error>> {
        for wrong_session in [true, false] {
            let (_directory, store) = fixture()?;
            let records = history([0x70; 32], 2)?;
            store.persist_session_record(&records[0])?;
            let foreign = history([0x71; 32], 2)?;
            let body = if wrong_session {
                &foreign[1]
            } else {
                &records[1]
            };
            let component = ValidatedComponent::registered(&session_record_name(
                records[0].session_id(),
                if wrong_session { 1 } else { 2 },
            ))?;
            store
                .records
                .create_immutable_file(&component, body.as_bytes())?;
            assert_quarantined(original_lexical_head(&store, records[0].session_id()));
            assert_quarantined(store.load_session(records[0].session_id()));
        }
        Ok(())
    }

    #[test]
    fn session_head_scan_same_open_observes_append_then_removed_origin_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store) = fixture()?;
        let records = history([0x69; 32], 3)?;
        store.persist_session_record(&records[0])?;
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[0].as_bytes()
        );
        store.persist_session_record(&records[1])?;
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[1].as_bytes()
        );
        store.persist_session_record(&records[2])?;
        assert_eq!(
            store.load_session(records[0].session_id())?.as_bytes(),
            records[2].as_bytes()
        );
        let component =
            ValidatedComponent::registered(&session_record_name(records[0].session_id(), 0))?;
        let retained = store.records.open_file(&component, false)?;
        store.records.unlink_verified_file(&component, &retained)?;
        assert_quarantined(store.load_session(records[0].session_id()));
        Ok(())
    }
}
