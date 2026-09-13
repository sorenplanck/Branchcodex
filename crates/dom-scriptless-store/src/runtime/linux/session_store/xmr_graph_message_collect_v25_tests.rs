//! Real retained-directory and TransportMessageRecordV1 codec regressions.
//! The envelopes deliberately have no identity signature: these tests exercise
//! untrusted collection, not a complete signed graph or Store authorization.
use super::*;
use crate::runtime::linux::session_store::evidence_only_staging::record_with_session_and_terms_hash;
use crate::runtime::linux::tests::with_root_v25;
use crate::SessionRecordFieldsV1;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const SESSION: [u8; 32] = [0x61; 32];
const FOREIGN: [u8; 32] = [0x62; 32];
type Inventory = Vec<(String, Vec<u8>)>;

fn with_messages<T>(
    inspect: impl FnOnce(&Path, &RetainedDirectory) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    with_root_v25(|path, root| {
        let messages =
            root.create_child_directory(ValidatedComponent::registered(MESSAGES_NAME)?)?;
        inspect(&path.join("contracts-store").join(MESSAGES_NAME), &messages)
    })
}

fn framed_record(
    session: [u8; 32],
    sender: u8,
    sequence: u64,
    revision: u64,
) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let initial = record_with_session_and_terms_hash(session, SessionPhaseV1::Created, [0x31; 32])?;
    let successor = SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: session,
            revision,
            phase: SessionPhaseV1::TemplatesCommitted,
            terms_hash: initial.terms_hash(),
            transcript_hash: [revision as u8; 32],
            irreversible: initial.irreversible(),
            chain: initial.chain(),
        },
        initial.encrypted_payload(),
    )?;
    let candidate = outbound_dsc1_candidate_bytes(&OutboundDsc1UnsignedFieldsV1 {
        message_type: 0x18,
        chain_id: [0x21; 32],
        session_id: session,
        sender_id: [sender; 32],
        sequence,
        previous_transcript_hash: [0x41; 32],
        payload: &[0x51; 32],
    })?;
    let envelope = ParsedTransportEnvelopeV1::parse(&candidate)?;
    let record = TransportMessageRecordV1::new(
        &envelope,
        &candidate,
        &successor,
        DirectionV1::Initiator,
        false,
    )?;
    // Use the real encoder/decoder, including record digest and DSC1 framing.
    assert_eq!(
        TransportMessageRecordV1::from_bytes(&record.bytes)?.bytes,
        record.bytes
    );
    Ok((
        transport_message_name(session, [sender; 32], sequence, false),
        record.bytes,
    ))
}

fn publish(
    directory: &RetainedDirectory,
    record: &(String, Vec<u8>),
) -> Result<(), LinuxCapabilityError> {
    directory
        .create_immutable_file(&ValidatedComponent::registered(&record.0)?, &record.1)
        .map(|_| ())
}

// Independent baseline: the original callback and lexical scanner, including
// its exact filter and error flattening. Do not implement it via the new helper.
fn original_lexical(
    messages: &RetainedDirectory,
    session: [u8; 32],
) -> Result<Inventory, LinuxCapabilityError> {
    let prefix = format!("{}-", hex_lower(&session));
    let mut retained = Vec::new();
    messages.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if !name.starts_with(&prefix) || !name.ends_with(".message") {
            return Ok(());
        }
        let bytes = messages.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?;
        let record = TransportMessageRecordV1::from_bytes(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        retained.push((name.to_owned(), record.bytes));
        Ok(())
    })?;
    Ok(retained)
}

fn collected(
    messages: &RetainedDirectory,
    session: [u8; 32],
) -> Result<Inventory, LinuxCapabilityError> {
    collect_untrusted_messages_v25(messages, session).map(|records| {
        records
            .into_iter()
            .map(|(name, record)| (name, record.bytes))
            .collect()
    })
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn same_refusal(messages: &RetainedDirectory, expected: LinuxCapabilityError) {
    assert_eq!(original_lexical(messages, SESSION).unwrap_err(), expected);
    assert_eq!(collected(messages, SESSION).unwrap_err(), expected);
}

#[test]
fn graph_message_collect_shuffled_physical_records_preserve_lexical_bytes_v25(
) -> Result<(), Box<dyn Error>> {
    with_messages(|_, messages| {
        assert_eq!(
            collected(messages, SESSION)?,
            original_lexical(messages, SESSION)?
        );
        for index in 0..24 {
            let sequence = (index * 7) % 24;
            let record = framed_record(
                SESSION,
                0x71 + (sequence % 2) as u8,
                sequence,
                24 - sequence,
            )?;
            publish(messages, &record)?;
            if index < 7 {
                publish(messages, &framed_record(FOREIGN, 0x73, index, index + 1)?)?;
            }
        }
        let actual = collected(messages, SESSION)?;
        assert_eq!(actual, original_lexical(messages, SESSION)?);
        assert_eq!(actual.len(), 24);
        assert!(actual.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let revisions = actual
            .iter()
            .map(|(_, bytes)| {
                TransportMessageRecordV1::from_bytes(bytes)
                    .map(|record| record.successor.revision())
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(revisions.windows(2).any(|pair| pair[0] > pair[1]));
        // The collector does not replace either caller's later revision sort.
        assert_eq!(collected(messages, FOREIGN)?.len(), 7);
        Ok(())
    })
}

#[test]
fn graph_message_collect_preserves_foreign_and_equivocation_suffix_filters_v25(
) -> Result<(), Box<dyn Error>> {
    with_messages(|path, messages| {
        let wanted = framed_record(SESSION, 0x71, 0, 1)?;
        publish(messages, &wanted)?;
        // The old collector does not decode these physically valid files.
        let foreign = transport_message_name(FOREIGN, [0x72; 32], 0, false);
        private_write(&path.join(foreign), b"not a transport record")?;
        let equivocation = transport_message_name(SESSION, [0x71; 32], 0, true);
        private_write(&path.join(equivocation), b"not a transport record")?;
        assert_eq!(collected(messages, SESSION)?, vec![wanted]);
        assert_eq!(
            collected(messages, SESSION)?,
            original_lexical(messages, SESSION)?
        );
        assert_eq!(collected(messages, [0x63; 32])?, vec![]);
        assert_eq!(
            collected(messages, FOREIGN).unwrap_err(),
            LinuxCapabilityError::ExactBytesMismatch,
        );
        Ok(())
    })
}

#[test]
fn graph_message_collect_checks_invalid_and_foreign_physical_entries_before_filter_v25(
) -> Result<(), Box<dyn Error>> {
    for case in 0..7 {
        with_messages(|path, messages| {
            let wanted = framed_record(SESSION, 0x71, 0, 1)?;
            publish(messages, &wanted)?;
            let foreign = path.join(transport_message_name(FOREIGN, [0x72; 32], 0, false));
            let expected = match case {
                0 => {
                    private_write(&path.join("unknown"), b"invalid namespace")?;
                    LinuxCapabilityError::InvalidComponent
                }
                1 => {
                    fs::create_dir(&foreign)?;
                    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700))?;
                    LinuxCapabilityError::InvalidObject
                }
                2 => {
                    private_write(&foreign, b"foreign")?;
                    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o644))?;
                    LinuxCapabilityError::InvalidObject
                }
                3 => {
                    symlink(path.join(&wanted.0), &foreign)?;
                    LinuxCapabilityError::InvalidObject
                }
                4 => {
                    fs::hard_link(path.join(&wanted.0), &foreign)?;
                    LinuxCapabilityError::InvalidObject
                }
                5 => {
                    private_write(&path.join(format!(".{}.staging", wanted.0)), b"staging")?;
                    LinuxCapabilityError::InvalidObject
                }
                6 => {
                    messages.create_child_directory(ValidatedComponent::registered("journal")?)?;
                    LinuxCapabilityError::InvalidObject
                }
                _ => unreachable!(),
            };
            same_refusal(messages, expected);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn graph_message_collect_corruption_keeps_original_error_flattening_v25(
) -> Result<(), Box<dyn Error>> {
    for case in 0..3 {
        with_messages(|path, messages| {
            let (name, mut bytes) = framed_record(SESSION, 0x71, 0, 1)?;
            match case {
                0 => {
                    bytes.truncate(16);
                }
                1 => {
                    bytes[TRANSPORT_MESSAGE_PREFIX_LEN + 148] ^= 1;
                }
                2 => {
                    // Even rechecksumming the outer record cannot hide a changed
                    // DSC1 payload from the original decoder's digest checks.
                    bytes[TRANSPORT_MESSAGE_PREFIX_LEN + 148] ^= 1;
                    let end = bytes.len() - DIGEST_LEN;
                    let digest = tagged_hash(MESSAGE_RECORD_HASH_TAG, &bytes[..end]);
                    bytes[end..].copy_from_slice(&digest);
                }
                _ => unreachable!(),
            }
            private_write(&path.join(name), &bytes)?;
            same_refusal(messages, LinuxCapabilityError::ExactBytesMismatch);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn graph_message_collect_fresh_reload_observes_append_remove_and_tamper_v25(
) -> Result<(), Box<dyn Error>> {
    with_root_v25(|path, root| {
        let messages =
            root.create_child_directory(ValidatedComponent::registered(MESSAGES_NAME)?)?;
        let first = framed_record(SESSION, 0x71, 0, 1)?;
        let next = framed_record(SESSION, 0x72, 0, 2)?;
        publish(&messages, &first)?;
        assert_eq!(collected(&messages, SESSION)?, vec![first.clone()]);
        publish(&messages, &next)?;
        let expected = original_lexical(&messages, SESSION)?;
        assert_eq!(collected(&messages, SESSION)?, expected);
        drop(messages);
        let reopened = root.open_child_directory(ValidatedComponent::registered(MESSAGES_NAME)?)?;
        assert_eq!(collected(&reopened, SESSION)?, expected);
        let base = path.join("contracts-store").join(MESSAGES_NAME);
        fs::remove_file(base.join(&first.0))?;
        assert_eq!(collected(&reopened, SESSION)?, vec![next.clone()]);
        private_write(
            &base.join(&next.0),
            b"changed after previous successful collection",
        )?;
        same_refusal(&reopened, LinuxCapabilityError::ExactBytesMismatch);
        Ok(())
    })
}

#[test]
fn graph_message_collect_exclusions_require_original_physical_identity_v25(
) -> Result<(), Box<dyn Error>> {
    with_messages(|path, messages| {
        let wanted = framed_record(SESSION, 0x71, 0, 1)?;
        publish(messages, &wanted)?;
        let excluded = format!(".{}.staging", wanted.0);
        private_write(&path.join(&excluded), b"not parsed while exactly excluded")?;
        let component = ValidatedComponent::registered(&excluded)?;
        let pinned = messages.open_file(&component, false)?;
        let mut exclusions = BTreeMap::new();
        exclusions.insert(excluded.clone(), pinned.identity);
        messages.install_scan_exclusions(exclusions)?;
        assert_eq!(collected(messages, SESSION)?, vec![wanted]);
        assert_eq!(
            collected(messages, SESSION)?,
            original_lexical(messages, SESSION)?
        );
        // Keep the old descriptor alive, so inode reuse cannot make the new
        // same-name file match the exclusion's original physical identity.
        fs::remove_file(path.join(&excluded))?;
        private_write(&path.join(&excluded), b"replacement staging")?;
        same_refusal(messages, LinuxCapabilityError::IdentityMismatch);
        drop(pinned);
        messages.clear_scan_exclusions()?;
        same_refusal(messages, LinuxCapabilityError::InvalidObject);
        Ok(())
    })
}

#[test]
fn graph_message_collect_never_deduplicates_or_authenticates_records_v25(
) -> Result<(), Box<dyn Error>> {
    with_messages(|_, messages| {
        let first = framed_record(SESSION, 0x71, 0, 1)?;
        let duplicate_revision = framed_record(SESSION, 0x72, 0, 1)?;
        publish(messages, &first)?;
        publish(messages, &duplicate_revision)?;
        let records = collect_untrusted_messages_v25(messages, SESSION)?;
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|(_, record)| record.successor.revision() == 1));
        for (_, record) in &records {
            let envelope = ParsedTransportEnvelopeV1::parse(&record.signed_bytes)?;
            assert_eq!(envelope.signature, [0; 65]);
            assert!(SchnorrSignature::from_bytes(&envelope.signature).is_err());
        }
        assert_eq!(
            collected(messages, SESSION)?,
            original_lexical(messages, SESSION)?
        );
        // Wrong filename-to-record binding also remains an authentication error
        // for the original callers, never silently repaired by this collector.
        let mut mismatched = framed_record(FOREIGN, 0x73, 0, 2)?;
        mismatched.0 = transport_message_name(SESSION, [0x73; 32], 0, false);
        publish(messages, &mismatched)?;
        let records = collect_untrusted_messages_v25(messages, SESSION)?;
        assert_eq!(records.len(), 3);
        assert!(records
            .iter()
            .any(|(_, record)| record.session_id == FOREIGN));
        assert_eq!(
            collected(messages, SESSION)?,
            original_lexical(messages, SESSION)?
        );
        Ok(())
    })
}
