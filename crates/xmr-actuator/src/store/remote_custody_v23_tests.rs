//! Journal-only regressions. Fixture bytes are not asserted to be a valid
//! Monero transaction; production crypto verification happens before this API.
use super::*;
use crate::model::XmrOperationKindV1;

fn scope() -> (
    XmrActuatorLeaseV1,
    XmrOperationLocatorV1,
    XmrRemoteCustodyDigestsV23,
) {
    (
        XmrActuatorLeaseV1::new([1; 32], [2; 32], [3; 32], 1, 1000).unwrap(),
        XmrOperationLocatorV1 {
            settlement_id: [4; 32],
            kind: XmrOperationKindV1::Claim,
        },
        XmrRemoteCustodyDigestsV23::new([7; 32], [8; 32], [9; 32], [10; 32]).unwrap(),
    )
}

#[test]
fn remote_marker_reopens_exactly_and_rejects_downgrade_or_changed_ancestry() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("operations.sqlite");
    let (lease, locator, digests) = scope();
    let raw = b"journal-only public bytes";
    let store = XmrOperationStoreV1::open(&path).unwrap();
    let initial = store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], raw, digests, 1)
        .unwrap();
    let replay = store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], raw, digests, 2)
        .unwrap();
    assert_eq!(initial, replay);
    assert!(store
        .prepare_signed(&lease, locator, [5; 32], [6; 32], raw, 3)
        .is_err());
    let changed = XmrRemoteCustodyDigestsV23::new([11; 32], [8; 32], [9; 32], [10; 32]).unwrap();
    assert!(store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], raw, changed, 3)
        .is_err());
    drop(store);
    let store = XmrOperationStoreV1::open_existing_production(&path).unwrap();
    assert_eq!(
        store
            .require_remote_custody_v23(&lease, locator, 4)
            .unwrap(),
        digests
    );
    assert_eq!(store.retained_transaction(locator).unwrap(), raw);
    assert_eq!(store.view(locator).unwrap(), initial);
    assert!(store
        .require_remote_custody_v23(&lease, locator, 1000)
        .is_err());
}

#[test]
fn absent_marker_is_never_recreated_over_existing_remote_raw() {
    let temp = tempfile::tempdir().unwrap();
    let store = XmrOperationStoreV1::open(temp.path().join("ops.sqlite")).unwrap();
    let (lease, locator, digests) = scope();
    store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], b"raw", digests, 1)
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("DELETE FROM xmr_remote_custody_v23", [])
        .unwrap();
    assert!(store
        .require_remote_custody_v23(&lease, locator, 2)
        .is_err());
    assert!(store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], b"raw", digests, 2)
        .is_err());
}

#[test]
fn marker_failure_rolls_back_raw_insertion_and_corrupt_marker_blocks_view() {
    let temp = tempfile::tempdir().unwrap();
    let store = XmrOperationStoreV1::open(temp.path().join("ops.sqlite")).unwrap();
    let (lease, locator, digests) = scope();
    store.lock().unwrap().execute_batch("CREATE TRIGGER refuse_remote BEFORE INSERT ON xmr_remote_custody_v23 BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], b"raw", digests, 1)
        .is_err());
    assert!(matches!(
        store.view(locator),
        Err(XmrActuatorErrorV1::NotFound)
    ));
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_remote;")
        .unwrap();
    store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], b"raw", digests, 2)
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("UPDATE xmr_remote_custody_v23 SET marker=zeroblob(329)", [])
        .unwrap();
    assert!(store.view(locator).is_err());
    assert!(store
        .require_remote_custody_v23(&lease, locator, 3)
        .is_err());
}

#[test]
fn local_custody_cannot_be_relabelled_remote_and_legacy_reopen_does_not_migrate() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("legacy.sqlite");
    let (lease, locator, digests) = scope();
    let store = XmrOperationStoreV1::open(&path).unwrap();
    store
        .prepare_signed(&lease, locator, [5; 32], [6; 32], b"local", 1)
        .unwrap();
    assert!(store
        .prepare_signed_remote_v23(&lease, locator, [5; 32], [6; 32], b"local", digests, 2)
        .is_err());
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE xmr_remote_custody_v23;")
        .unwrap();
    drop(store);
    let store = XmrOperationStoreV1::open_existing_production(&path).unwrap();
    assert_eq!(store.retained_transaction(locator).unwrap(), b"local");
    assert!(store.view(locator).is_ok());
    assert!(store
        .require_remote_custody_v23(&lease, locator, 3)
        .is_err());
    let other = XmrOperationLocatorV1 {
        settlement_id: [12; 32],
        kind: XmrOperationKindV1::Refund,
    };
    assert!(store
        .prepare_signed_remote_v23(&lease, other, [13; 32], [14; 32], b"new remote", digests, 3)
        .is_err());
    assert!(matches!(
        store.view(other),
        Err(XmrActuatorErrorV1::NotFound)
    ));
    let tables: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='xmr_remote_custody_v23'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0);
}
