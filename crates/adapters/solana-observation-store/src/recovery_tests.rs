use super::*;
use kaystra_core::settlement_engine::{ChainRecordV1, ChainSourceV1};
use solana_kaystra_source::SolanaKaystraSource;

const CHAIN: ChainId = ChainId([1; 32]);
const SETTLEMENT: [u8; 32] = [2; 32];
const TERMS: [u8; 32] = [3; 32];

fn event(slot: u64, tx: u8, kind: VerifiedSolanaEventKind) -> VerifiedSolanaEvent {
    VerifiedSolanaEvent {
        settlement_id: SETTLEMENT,
        terms_hash: TERMS,
        kind,
        evidence: EvidenceRefV1 {
            chain_id: CHAIN,
            tx_id: [tx; 32],
            event_index: 0,
            block_height: slot,
            block_anchor: [slot as u8; 32],
        },
    }
}

fn open(path: &Path) -> SqliteVerifiedSolanaFeed {
    SqliteVerifiedSolanaFeed::open(path, CHAIN, SETTLEMENT, TERMS).unwrap()
}

#[test]
fn old_observation_preserves_newer_events_tip_and_duplicate_revision() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    let newer = event(20, 10, VerifiedSolanaEventKind::Claim);
    let older = event(10, 11, VerifiedSolanaEventKind::Funding);
    feed.persist_observation(&newer).unwrap();
    feed.persist_observation(&older).unwrap();
    assert_eq!(feed.tip().unwrap(), Some(20));
    assert_eq!(feed.events(0, 30).unwrap(), vec![older.clone(), newer]);
    let revision = feed.changes_since(0).unwrap().revision;
    feed.persist_observation(&older).unwrap();
    assert_eq!(
        feed.changes_since(revision).unwrap(),
        SolanaFeedChangesV2 {
            revision,
            earliest_slot: None,
            first_reorg: None,
        }
    );
}

#[test]
fn conflict_rolls_back_new_anchor_event_revision_and_tip() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    let original = event(10, 11, VerifiedSolanaEventKind::Funding);
    feed.persist_observation(&original).unwrap();
    let revision = feed.changes_since(0).unwrap().revision;
    let transplanted = event(20, 11, VerifiedSolanaEventKind::Funding);
    assert_eq!(
        feed.persist_observation(&transplanted),
        Err(ObservationStoreError::Conflict)
    );
    assert_eq!(
        feed.block_hash(20).unwrap(),
        None,
        "new anchor must rollback with event refusal"
    );
    assert_eq!(feed.tip().unwrap(), Some(10));
    assert_eq!(feed.events(0, 30).unwrap(), vec![original]);
    assert_eq!(feed.changes_since(revision).unwrap().revision, revision);
}

#[test]
fn same_slot_keeps_all_transactions_and_refuses_action_relabeling() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    let one = event(10, 11, VerifiedSolanaEventKind::Funding);
    let two = event(10, 12, VerifiedSolanaEventKind::Claim);
    feed.persist_observation(&one).unwrap();
    feed.persist_observation(&two).unwrap();
    let mut relabeled = one.clone();
    relabeled.kind = VerifiedSolanaEventKind::Refund;
    assert_eq!(
        feed.persist_observation(&relabeled),
        Err(ObservationStoreError::Conflict)
    );
    assert_eq!(feed.events(10, 10).unwrap(), vec![one, two]);
}

#[test]
fn scanner_recovers_late_event_after_reopen_without_emitting_false_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("feed.sqlite");
    let feed = open(&path);
    let newer = event(20, 10, VerifiedSolanaEventKind::Claim);
    feed.persist_observation(&newer).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (initial, cursor) = source.scan(&source.genesis_cursor().unwrap()).unwrap();
    assert_eq!(
        initial,
        vec![ChainRecordV1::Claim {
            evidence: newer.evidence
        }]
    );
    drop(source);
    let feed = open(&path);
    let late = event(10, 11, VerifiedSolanaEventKind::Funding);
    feed.persist_observation(&late).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (records, cursor) = source.scan(&cursor).unwrap();
    assert_eq!(
        records,
        vec![
            ChainRecordV1::Funding {
                evidence: late.evidence
            },
            ChainRecordV1::Claim {
                evidence: newer.evidence
            }
        ]
    );
    let (empty, _) = source.scan(&cursor).unwrap();
    assert!(
        empty.is_empty(),
        "no endless replay once change revision is consumed"
    );
}

#[test]
fn explicit_reorg_still_invalidates_and_then_replays_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    let original = event(10, 11, VerifiedSolanaEventKind::Funding);
    feed.persist_observation(&original).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (_, cursor) = source.scan(&source.genesis_cursor().unwrap()).unwrap();
    let feed = source.into_inner();
    let mut replacement = original.clone();
    replacement.evidence.tx_id = [12; 32];
    replacement.evidence.block_anchor = [0xaa; 32];
    feed.replace_canonical_suffix(
        10,
        10,
        &[SolanaSlotAnchor {
            slot: 10,
            blockhash: replacement.evidence.block_anchor,
        }],
    )
    .unwrap();
    feed.insert_event(&replacement).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (records, rewind) = source.scan(&cursor).unwrap();
    assert_eq!(
        records,
        vec![ChainRecordV1::Reorg {
            from_height: 10,
            old_anchor: original.evidence.block_anchor,
        }]
    );
    let (records, _) = source.scan(&rewind).unwrap();
    assert_eq!(
        records,
        vec![ChainRecordV1::Funding {
            evidence: replacement.evidence
        }]
    );
}

#[test]
fn database_identity_cannot_be_rebound_even_when_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("feed.sqlite");
    drop(open(&path));
    for (chain, settlement, terms) in [
        (ChainId([9; 32]), SETTLEMENT, TERMS),
        (CHAIN, [9; 32], TERMS),
        (CHAIN, SETTLEMENT, [9; 32]),
    ] {
        assert!(matches!(
            SqliteVerifiedSolanaFeed::open(&path, chain, settlement, terms),
            Err(ObservationStoreError::Conflict)
        ));
    }
    assert!(open(&path).tip().unwrap().is_none());
}

#[test]
fn legacy_database_migration_marks_existing_history_for_catchup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("feed.sqlite");
    let feed = open(&path);
    feed.persist_observation(&event(10, 11, VerifiedSolanaEventKind::Funding))
        .unwrap();
    drop(feed);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TABLE solana_feed_binding_v2; DROP TABLE solana_feed_changes_v2;")
        .unwrap();
    drop(connection);
    let feed = open(&path);
    let changes = feed.changes_since(0).unwrap();
    assert!(changes.revision > 0);
    assert_eq!(changes.earliest_slot, Some(10));
    assert_eq!(feed.events(0, 20).unwrap().len(), 1);
}

#[test]
fn deep_reorg_outside_cursor_history_is_not_misclassified_as_late_insertion() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    let mut anchors: Vec<_> = (10..=600)
        .map(|slot| SolanaSlotAnchor {
            slot,
            blockhash: [u8::try_from(slot % 250 + 1).unwrap(); 32],
        })
        .collect();
    feed.replace_canonical_suffix(10, 600, &anchors).unwrap();
    let mut original = event(10, 11, VerifiedSolanaEventKind::Funding);
    original.evidence.block_anchor = anchors[0].blockhash;
    feed.insert_event(&original).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (_, cursor) = source.scan(&source.genesis_cursor().unwrap()).unwrap();
    let feed = source.into_inner();
    anchors[0].blockhash = [0xab; 32];
    feed.replace_canonical_suffix(10, 600, &anchors).unwrap();
    let mut replacement = original.clone();
    replacement.evidence.tx_id = [12; 32];
    replacement.evidence.block_anchor = anchors[0].blockhash;
    feed.insert_event(&replacement).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (records, rewind) = source.scan(&cursor).unwrap();
    assert_eq!(
        records,
        vec![ChainRecordV1::Reorg {
            from_height: 10,
            old_anchor: original.evidence.block_anchor,
        }]
    );
    let (records, scanned) = source.scan(&rewind).unwrap();
    assert_eq!(
        records,
        vec![ChainRecordV1::Funding {
            evidence: replacement.evidence
        }]
    );
    // A safe checkpoint must retain the revision already acknowledged above.
    let checkpoint = source.cursor_at_from_scan(100, &scanned).unwrap();
    let (records, _) = source.scan(&checkpoint).unwrap();
    assert!(
        records.is_empty(),
        "historical reorg must not loop after a safe checkpoint"
    );
}

#[test]
fn checkpoint_does_not_acknowledge_a_later_writer_revision() {
    let dir = tempfile::tempdir().unwrap();
    let feed = open(&dir.path().join("feed.sqlite"));
    feed.persist_observation(&event(20, 12, VerifiedSolanaEventKind::Claim))
        .unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    let (_, scanned) = source.scan(&source.genesis_cursor().unwrap()).unwrap();
    let feed = source.into_inner();
    let late = event(10, 11, VerifiedSolanaEventKind::Funding);
    feed.persist_observation(&late).unwrap();
    let source = SolanaKaystraSource::new(feed, SETTLEMENT, TERMS).unwrap();
    // Slot 15 is skipped, which must still permit a safe bounded checkpoint.
    let checkpoint = source.cursor_at_from_scan(15, &scanned).unwrap();
    let (records, _) = source.scan(&checkpoint).unwrap();
    assert_eq!(
        records.first(),
        Some(&ChainRecordV1::Funding {
            evidence: late.evidence
        })
    );
}

struct RacingFeed {
    inner: SqliteVerifiedSolanaFeed,
    changed: std::cell::Cell<bool>,
}

impl VerifiedSolanaFeed for RacingFeed {
    fn chain_id(&self) -> ChainId {
        self.inner.chain_id()
    }
    fn changes_since(&self, revision: u64) -> Result<SolanaFeedChangesV2, VerifiedFeedError> {
        self.inner.changes_since(revision)
    }
    fn tip(&self) -> Result<Option<u64>, VerifiedFeedError> {
        self.inner.tip()
    }
    fn block_hash(&self, slot: u64) -> Result<Option<[u8; 32]>, VerifiedFeedError> {
        self.inner.block_hash(slot)
    }
    fn events(&self, from: u64, to: u64) -> Result<Vec<VerifiedSolanaEvent>, VerifiedFeedError> {
        self.inner.events(from, to)
    }
    fn anchors(&self, from: u64, to: u64) -> Result<Vec<SolanaSlotAnchor>, VerifiedFeedError> {
        let anchors = self.inner.anchors(from, to)?;
        if !self.changed.replace(true) {
            self.inner
                .persist_observation(&event(10, 11, VerifiedSolanaEventKind::Funding))
                .unwrap();
        }
        Ok(anchors)
    }
}

#[test]
fn concurrent_commit_during_scan_cannot_emit_a_mixed_revision() {
    let dir = tempfile::tempdir().unwrap();
    let inner = open(&dir.path().join("feed.sqlite"));
    inner
        .persist_observation(&event(20, 12, VerifiedSolanaEventKind::Claim))
        .unwrap();
    let source = SolanaKaystraSource::new(
        RacingFeed {
            inner,
            changed: std::cell::Cell::new(false),
        },
        SETTLEMENT,
        TERMS,
    )
    .unwrap();
    let cursor = source.genesis_cursor().unwrap();
    assert_eq!(
        source.scan(&cursor),
        Err(kaystra_core::settlement_engine::ChainSourceErrorV1::StaleCursor)
    );
    let (records, _) = source.scan(&cursor).unwrap();
    assert_eq!(records.len(), 2);
    assert!(matches!(records[0], ChainRecordV1::Funding { .. }));
}
