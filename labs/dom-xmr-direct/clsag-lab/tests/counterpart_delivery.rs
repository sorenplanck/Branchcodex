#![cfg(unix)]
use dxp1_clsag_lab::counterpart_delivery::{
    CounterpartDelivery, DeliveryAction as Action, DeliveryBinding, DeliveryError,
    Observation as Seen,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "delivery-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> PathBuf {
        self.0.join("delivery.wal")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn binding() -> DeliveryBinding {
    DeliveryBinding {
        manifest: [1; 32],
        first_claim: [2; 32],
        first_block: [3; 32],
        first_height: 7,
        target_chain: [4; 32],
    }
}
const PAYLOAD: &[u8] = b"exact already-owed counterpart transaction";

#[test]
fn ambiguous_send_reopens_exposed_and_only_retries_the_same_bytes() {
    let s = Scratch::new();
    let b = binding();
    let mut j = CounterpartDelivery::create(&s.path(), b, PAYLOAD).unwrap();
    let h = j.payload_digest();
    assert_eq!(
        j.prepare_attempt(b.target_chain, h, Seen::AbsentAndUnspent)
            .unwrap(),
        PAYLOAD
    );
    let saved = fs::read(s.path()).unwrap();
    drop(j);
    let mut j = CounterpartDelivery::open(&s.path(), b).unwrap();
    assert!(j.possibly_exposed().unwrap());
    assert!(matches!(
        j.prepare_attempt(b.target_chain, h, Seen::Unknown),
        Err(DeliveryError::NeedsReconciliation)
    ));
    assert!(matches!(
        j.prepare_attempt(b.target_chain, h, Seen::InPool),
        Err(DeliveryError::NeedsReconciliation)
    ));
    assert_eq!(
        j.prepare_attempt(b.target_chain, h, Seen::AbsentAndUnspent)
            .unwrap(),
        PAYLOAD
    );
    assert_eq!(fs::read(s.path()).unwrap(), saved);
}

#[test]
fn canonical_observation_is_not_cached_across_rpc_failure_or_reorg() {
    let s = Scratch::new();
    let b = binding();
    let mut j = CounterpartDelivery::create(&s.path(), b, PAYLOAD).unwrap();
    let h = j.payload_digest();
    j.prepare_attempt(b.target_chain, h, Seen::AbsentAndUnspent)
        .unwrap();
    drop(j);
    for (seen, expected) in [
        (Seen::InPool, Action::MonitorPool),
        (
            Seen::Included {
                block: [7; 32],
                height: 80,
            },
            Action::MonitorInclusion,
        ),
        (Seen::Unknown, Action::Reconcile),
        (Seen::AbsentAndUnspent, Action::RetryExactBytes),
        (
            Seen::ConflictingSpend {
                transaction: [9; 32],
            },
            Action::ResolveConflict,
        ),
    ] {
        let j = CounterpartDelivery::open(&s.path(), b).unwrap();
        assert_eq!(j.reconcile(b.target_chain, h, seen).unwrap(), expected);
        assert!(j.possibly_exposed().unwrap());
        assert_eq!(
            j.reconcile(b.target_chain, h, Seen::Unknown).unwrap(),
            Action::Reconcile
        );
    }
}

#[test]
fn wrong_transaction_chain_or_original_operation_cannot_reconcile_or_send() {
    let s = Scratch::new();
    let b = binding();
    let mut j = CounterpartDelivery::create(&s.path(), b, PAYLOAD).unwrap();
    let h = j.payload_digest();
    assert!(matches!(
        j.prepare_attempt([8; 32], h, Seen::AbsentAndUnspent),
        Err(DeliveryError::Binding)
    ));
    assert!(matches!(
        j.prepare_attempt(b.target_chain, [8; 32], Seen::AbsentAndUnspent),
        Err(DeliveryError::Binding)
    ));
    assert!(!j.possibly_exposed().unwrap());
    drop(j);
    for changed in [
        DeliveryBinding {
            manifest: [8; 32],
            ..b
        },
        DeliveryBinding {
            first_claim: [8; 32],
            ..b
        },
        DeliveryBinding {
            first_block: [8; 32],
            ..b
        },
        DeliveryBinding {
            first_height: 8,
            ..b
        },
        DeliveryBinding {
            target_chain: [8; 32],
            ..b
        },
    ] {
        assert!(CounterpartDelivery::open(&s.path(), changed).is_err());
    }
}

#[test]
fn missing_partial_corrupted_and_appended_records_fail_without_repair() {
    let s = Scratch::new();
    let b = binding();
    assert!(CounterpartDelivery::open(&s.path(), b).is_err());
    assert!(!s.path().exists());
    let mut j = CounterpartDelivery::create(&s.path(), b, PAYLOAD).unwrap();
    let prefix = fs::metadata(s.path()).unwrap().len() as usize;
    j.prepare_attempt(b.target_chain, j.payload_digest(), Seen::AbsentAndUnspent)
        .unwrap();
    drop(j);
    let bytes = fs::read(s.path()).unwrap();
    let bad = Scratch::new();
    // Exact removal of the complete event is malicious storage/backup rollback,
    // outside the trusted filesystem model. Partial event loss is rejected.
    for end in (0..prefix).chain(prefix + 1..bytes.len()) {
        fs::write(bad.path(), &bytes[..end]).unwrap();
        assert!(CounterpartDelivery::open(&bad.path(), b).is_err());
        assert_eq!(fs::metadata(bad.path()).unwrap().len(), end as u64);
    }
    for i in 0..bytes.len() {
        let mut data = bytes.clone();
        data[i] ^= 1;
        fs::write(bad.path(), data).unwrap();
        assert!(CounterpartDelivery::open(&bad.path(), b).is_err());
    }
    let mut data = bytes;
    data.push(0);
    fs::write(bad.path(), data).unwrap();
    assert!(CounterpartDelivery::open(&bad.path(), b).is_err());
}

#[test]
fn exclusive_creation_and_open_lock_prevent_competing_delivery_handles() {
    let s = Scratch::new();
    let b = binding();
    let j = CounterpartDelivery::create(&s.path(), b, PAYLOAD).unwrap();
    assert!(CounterpartDelivery::create(&s.path(), b, b"another signature").is_err());
    assert!(matches!(
        CounterpartDelivery::open(&s.path(), b),
        Err(DeliveryError::Locked)
    ));
    drop(j);
    assert_eq!(
        CounterpartDelivery::open(&s.path(), b).unwrap().payload(),
        PAYLOAD
    );
}
