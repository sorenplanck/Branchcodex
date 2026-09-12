//! Filesystem/AEAD regressions only. No signable transaction or authority is forged.
use super::*;

#[test]
fn encrypted_plan_roundtrip_and_wrong_key_or_request_are_closed() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [1; 32];
    let digest = [2; 32];
    let key = [3; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    let plaintext = b"test-only AEAD payload; not a signing plan";
    guard.store_plan(&key, plaintext).unwrap();
    assert_eq!(
        guard.load_plan(&key).unwrap().unwrap().as_slice(),
        plaintext
    );
    assert!(guard.load_plan(&[4; 32]).is_err());
    assert!(guard.store_plan(&key, plaintext).is_err());
    drop(guard);
    assert!(cache.begin_build_v23(nonce, [5; 32]).is_err());
    let reopened = cache.begin_build_v23(nonce, digest).unwrap();
    assert_eq!(
        reopened.load_plan(&key).unwrap().unwrap().as_slice(),
        plaintext
    );
}

#[test]
fn request_lock_prevents_concurrent_new_plan_and_plan_links_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [6; 32];
    let digest = [7; 32];
    let key = [8; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    assert!(cache.begin_build_v23(nonce, digest).is_err());
    guard.store_plan(&key, b"test-only plaintext").unwrap();
    let path = directory
        .path()
        .join("build-proofs-v23")
        .join(format!("{}.plan", hex::encode(nonce)));
    let extra = directory.path().join("unexpected-hardlink");
    fs::hard_link(&path, &extra).unwrap();
    assert!(guard.load_plan(&key).is_err());
}

#[test]
fn issued_tombstone_without_ready_is_corruption_not_recreation() {
    let directory = tempfile::tempdir().unwrap();
    let cache = SweepCache::open(directory.path()).unwrap();
    let nonce = [9; 32];
    let digest = [10; 32];
    let guard = cache.begin_build_v23(nonce, digest).unwrap();
    // Simulates loss of a public result after an issued marker. This marker is
    // deliberately invalid test state, not a fake proof or economic receipt.
    let path = directory
        .path()
        .join("build-proofs-v23")
        .join(format!("{}.issued", hex::encode(nonce)));
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&[11; 32]).unwrap();
    file.sync_all().unwrap();
    assert!(guard.load_ready().is_err());
}
