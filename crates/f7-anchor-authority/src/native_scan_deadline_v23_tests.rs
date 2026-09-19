//! Pure scheduling boundaries; no fabricated chain evidence or sleeping.
use super::*;

#[test]
fn native_scan_does_not_start_another_page_at_or_after_external_expiry() {
    let now = Instant::now();
    let deadline = now.checked_add(Duration::from_secs(60)).unwrap();
    assert!(require_external_scan_deadline_v23(Some(deadline), now).is_ok());
    assert!(require_external_scan_deadline_v23(Some(deadline), deadline).is_err());
    assert!(require_external_scan_deadline_v23(
        Some(deadline),
        deadline.checked_add(Duration::from_nanos(1)).unwrap(),
    )
    .is_err());
    // Legacy callers do not acquire a newly inferred external lifetime.
    assert!(require_external_scan_deadline_v23(None, deadline).is_ok());
}

#[test]
fn incremental_funding_prefix_is_retained_only_for_the_exact_scope() {
    let first = [0x31; 32];
    let second = [0x32; 32];
    let mut progress = DomFundingScanProgressV24::new();
    progress.bind_scope(first);
    progress.cursor = ScriptlessScanCursorV1 {
        next_height: 9,
        anchor_hash: Some([0x41; 32]),
    };
    progress.found = Some(([0x42; 32], 4, 123));

    progress.bind_scope(first);
    assert_eq!(progress.cursor.next_height, 9);
    assert_eq!(progress.cursor.anchor_hash, Some([0x41; 32]));
    assert_eq!(progress.found, Some(([0x42; 32], 4, 123)));

    progress.bind_scope(second);
    assert_eq!(progress.scope, Some(second));
    assert_eq!(progress.cursor, ScriptlessScanCursorV1::genesis());
    assert!(progress.found.is_none());
}

#[test]
fn reorg_reset_discards_cursor_candidate_and_scope() {
    let mut progress = DomFundingScanProgressV24 {
        scope: Some([0x51; 32]),
        cursor: ScriptlessScanCursorV1 {
            next_height: 7,
            anchor_hash: Some([0x52; 32]),
        },
        found: Some(([0x53; 32], 3, 456)),
    };
    progress.reset();
    assert!(progress.scope.is_none());
    assert_eq!(progress.cursor, ScriptlessScanCursorV1::genesis());
    assert!(progress.found.is_none());
}
