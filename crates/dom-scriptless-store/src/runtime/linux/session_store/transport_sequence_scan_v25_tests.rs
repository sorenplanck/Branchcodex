// Included inside session_store::tests. Histories come from the real early
// transport authority and signed ingress; mutations below are deliberate disk
// corruption. The sequence helper is not a substitute for the full Store audit.
#[cfg(test)]
mod transport_sequence_scan_v25_tests {
    use super::*;

    fn completed_history() -> Result<
        (
            TestDirectory,
            ContractsSessionStoreV1,
            SessionRecordV1,
            EarlyTransportTestFixture,
        ),
        Box<dyn Error>,
    > {
        let directory = TestDirectory::create()?;
        let (store, initial, fixture) =
            early_transport_store(&directory, &policy(BudgetPolicyProfileV1::EvidenceOnly)?)?;
        complete_prepared_early_transport(&store, &initial, &fixture)?;
        Ok((directory, store, initial, fixture))
    }

    // Keep the original implementation independent of the new scanner. In
    // particular, decoding precedes the revision filter, and gaps/duplicates
    // are rejected after sorting the embedded sequence numbers.
    fn original_lexical_sequence(
        store: &ContractsSessionStoreV1,
        session_id: [u8; 32],
        sender_id: [u8; 32],
        inclusive_revision: u64,
    ) -> Result<u64, SessionStoreError> {
        let prefix = format!("{}-{}-", hex_lower(&session_id), hex_lower(&sender_id));
        let mut sequences = Vec::new();
        store.messages.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            if !name.starts_with(&prefix) || !name.ends_with(".message") {
                return Ok(());
            }
            let bytes = store.messages.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                TRANSPORT_MESSAGE_MAX_LEN,
            )?;
            let record = TransportMessageRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.successor.revision() <= inclusive_revision {
                sequences.push(record.sequence);
            }
            Ok(())
        })?;
        sequences.sort_unstable();
        for (index, sequence) in sequences.iter().enumerate() {
            if *sequence != u64::try_from(index).map_err(|_| SessionStoreError::Quarantined)? {
                return Err(SessionStoreError::Quarantined);
            }
        }
        u64::try_from(sequences.len()).map_err(|_| SessionStoreError::CapacityExceeded)
    }

    fn retained_message(
        store: &ContractsSessionStoreV1,
        session: [u8; 32],
        sender: [u8; 32],
        sequence: u64,
    ) -> Result<(String, TransportMessageRecordV1), Box<dyn Error>> {
        let name = transport_message_name(session, sender, sequence, false);
        let bytes = store.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        Ok((name, TransportMessageRecordV1::from_bytes(&bytes)?))
    }

    fn unlink_message(store: &ContractsSessionStoreV1, name: &str) -> Result<(), Box<dyn Error>> {
        let component = ValidatedComponent::registered(name)?;
        let retained = store.messages.open_file(&component, false)?;
        store.messages.unlink_verified_file(&component, &retained)?;
        Ok(())
    }

    fn publish_message(
        store: &ContractsSessionStoreV1,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        publish_immutable(
            &store.messages,
            &format!(".{name}.staging"),
            name,
            bytes,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        Ok(())
    }

    fn assert_sequence(
        store: &ContractsSessionStoreV1,
        session: [u8; 32],
        sender: [u8; 32],
        revision: u64,
        expected: u64,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            original_lexical_sequence(store, session, sender, revision)?,
            expected
        );
        assert_eq!(
            store.transport_sequence_at_revision(session, sender, revision)?,
            expected
        );
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_real_ingress_zero_inclusive_and_live_append_v25(
    ) -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let (store, initial, fixture) =
            early_transport_store(&directory, &policy(BudgetPolicyProfileV1::EvidenceOnly)?)?;
        let session = initial.session_id();
        for sender in fixture.participant_ids {
            assert_sequence(&store, session, sender, u64::MAX, 0)?;
        }
        let authority = store.prepare_early_transport_authority(
            fixture.trusted_chain_id,
            [&fixture.shared_bindings[0], &fixture.shared_bindings[1]],
        )?;
        let payloads = EarlyTransportPayloads::new(&initial, &fixture, &authority)?;
        let mut current = initial.clone();
        let mut counts = [0_u64; 2];
        for position in 0..6 {
            let before = current.revision();
            current = accept_early_transport_position(
                &store,
                &authority,
                &fixture,
                &current,
                position,
                payloads.message(position),
            )?
            .0;
            let direction = if position % 2 == 0 {
                DirectionV1::Initiator
            } else {
                DirectionV1::Responder
            };
            let participant = fixture.index_for_direction(direction)?;
            // A query on this same retained Store must see the new record,
            // while the previous revision still excludes it.
            assert_sequence(
                &store,
                session,
                fixture.participant_ids[participant],
                before,
                counts[participant],
            )?;
            counts[participant] += 1;
            for (index, sender) in fixture.participant_ids.iter().enumerate() {
                assert_sequence(&store, session, *sender, current.revision(), counts[index])?;
                assert_sequence(&store, session, *sender, u64::MAX, counts[index])?;
                assert_sequence(&store, session, *sender, initial.revision(), 0)?;
            }
        }
        assert_eq!(counts, [3, 3]);
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_shuffled_publication_and_real_reopen_match_lexical_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (directory, store, initial, fixture) = completed_history()?;
        let session = initial.session_id();
        let mut messages = Vec::new();
        for sender in fixture.participant_ids {
            for sequence in 0..3 {
                messages.push(retained_message(&store, session, sender, sequence)?);
            }
        }
        for (name, _) in &messages {
            unlink_message(&store, name)?;
        }
        // Re-publish the exact signed durable records in non-lexical order.
        for index in [4, 1, 5, 0, 3, 2] {
            let (name, message) = &messages[index];
            publish_message(&store, name, &message.bytes)?;
        }
        for sender in fixture.participant_ids {
            for revision in 0..=store.load_session(session)?.revision() + 1 {
                let expected = messages
                    .iter()
                    .filter(|(_, message)| {
                        message.sender_id == sender && message.successor.revision() <= revision
                    })
                    .count() as u64;
                assert_sequence(&store, session, sender, revision, expected)?;
            }
        }
        let expected_head = store.load_session(session)?.as_bytes().to_vec();
        drop(store);
        let reopened = ContractsSessionStoreV1::open_evidence_only(
            directory.capability()?,
            "sessions",
            policy(BudgetPolicyProfileV1::EvidenceOnly)?,
        )?;
        assert_eq!(
            reopened.load_session(session)?.as_bytes(),
            expected_head.as_slice()
        );
        for sender in fixture.participant_ids {
            assert_sequence(&reopened, session, sender, u64::MAX, 3)?;
        }
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_sender_session_and_equivocation_scope_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store, initial, fixture) = completed_history()?;
        let session = initial.session_id();
        let foreign_session = [0x7f; 32];
        let foreign_sender = [0x7e; 32];
        assert_ne!(session, foreign_session);
        assert!(!fixture.participant_ids.contains(&foreign_sender));
        for sender in fixture.participant_ids {
            assert_sequence(&store, session, sender, u64::MAX, 3)?;
            assert_sequence(&store, foreign_session, sender, u64::MAX, 0)?;
        }
        assert_sequence(&store, session, foreign_sender, u64::MAX, 0)?;
        // The original helper ignores the distinct equivocation suffix. This
        // corruption fixture pins that filter only, not full audit acceptance.
        let sender = fixture.participant_ids[0];
        let (_, record) = retained_message(&store, session, sender, 0)?;
        let name = transport_message_name(session, sender, 0, true);
        publish_message(&store, &name, &record.bytes)?;
        assert_sequence(&store, session, sender, u64::MAX, 3)?;
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_missing_zero_and_interior_gap_quarantine_v25(
    ) -> Result<(), Box<dyn Error>> {
        for missing in [0, 1] {
            let (_directory, store, initial, fixture) = completed_history()?;
            let session = initial.session_id();
            let sender = fixture.participant_ids[0];
            assert_sequence(&store, session, sender, u64::MAX, 3)?;
            let name = transport_message_name(session, sender, missing, false);
            unlink_message(&store, &name)?;
            assert_quarantined(original_lexical_sequence(&store, session, sender, u64::MAX));
            assert_quarantined(store.transport_sequence_at_revision(session, sender, u64::MAX));
            // The other sender remains an independent sequence namespace.
            assert_sequence(&store, session, fixture.participant_ids[1], u64::MAX, 3)?;
        }
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_duplicate_embedded_sequence_quarantines_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store, initial, fixture) = completed_history()?;
        let session = initial.session_id();
        let sender = fixture.participant_ids[0];
        let (_, record) = retained_message(&store, session, sender, 0)?;
        // A distinct, registered filename cannot conceal a duplicate embedded
        // sequence. These remain the exact original signed bytes, not a newly
        // fabricated transport authority or unsigned acceptance.
        let name = transport_message_name(session, sender, 3, false);
        publish_message(&store, &name, &record.bytes)?;
        assert_quarantined(original_lexical_sequence(&store, session, sender, u64::MAX));
        assert_quarantined(store.transport_sequence_at_revision(session, sender, u64::MAX));
        Ok(())
    }

    #[test]
    fn transport_sequence_scan_tamper_is_fresh_and_decoded_before_revision_filter_v25(
    ) -> Result<(), Box<dyn Error>> {
        let (_directory, store, initial, fixture) = completed_history()?;
        let session = initial.session_id();
        let sender = fixture.participant_ids[0];
        let (name, record) = retained_message(&store, session, sender, 2)?;
        assert_sequence(&store, session, sender, u64::MAX, 3)?;
        let mut corrupt = record.bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        unlink_message(&store, &name)?;
        publish_message(&store, &name, &corrupt)?;
        for revision in [initial.revision(), u64::MAX] {
            assert_quarantined(original_lexical_sequence(&store, session, sender, revision));
            assert_quarantined(store.transport_sequence_at_revision(session, sender, revision));
        }
        Ok(())
    }
}
