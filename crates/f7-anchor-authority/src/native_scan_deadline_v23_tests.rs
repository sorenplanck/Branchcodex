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
