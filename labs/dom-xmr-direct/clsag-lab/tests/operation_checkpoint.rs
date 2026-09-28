use dxp1_clsag_lab::{
    claim_resume::digest,
    operation_checkpoint::{ClaimManifest, OperationCheckpoint},
};

fn checkpoint() -> OperationCheckpoint {
    OperationCheckpoint {
        operation: [1; 32],
        manifest: [2; 32],
        dom_chain: [3; 32],
        dom_genesis: [4; 32],
        xmr_genesis: [5; 32],
        dom_token: [6; 32],
        dom_port: 1234,
        xmr_port: 2345,
    }
}
fn manifest(checkpoint: &mut OperationCheckpoint) -> Vec<u8> {
    let mut bytes = b"DXP1/claim-manifest/v2\0".to_vec();
    bytes.extend(checkpoint.operation);
    bytes.extend([7; 32]);
    bytes.extend([8; 32]);
    bytes.extend([9; 64]);
    bytes.extend(1u16.to_le_bytes());
    for time in [100u64, 130, 200] {
        bytes.extend(time.to_le_bytes());
    }
    bytes.push(1);
    for cost in [2u64, 3, 4] {
        bytes.extend(cost.to_le_bytes());
    }
    checkpoint.manifest = digest(&bytes);
    bytes
}

#[test]
fn original_manifest_and_clock_survive_checkpoint_restore() {
    let mut original = checkpoint();
    let record = manifest(&mut original);
    let bytes = original.encode().unwrap();
    let restored = OperationCheckpoint::decode(&bytes, original.operation).unwrap();
    assert!(restored == original);
    let loaded = ClaimManifest::decode(&record, &restored).unwrap();
    assert_eq!(
        (
            loaded.disclosed_at,
            loaded.earliest_adversarial,
            loaded.latest_honest
        ),
        (100, 130, 200)
    );
    assert_eq!(
        (
            loaded.xmr_resolution_secs,
            loaded.observation_secs,
            loaded.dom_resolution_secs
        ),
        (2, 3, 4)
    );
    assert!(loaded.dom_first);
    assert_eq!(loaded.xmr_record, [7; 32]);
    assert_eq!(loaded.dom_record, [8; 32]);
}

#[test]
fn checkpoint_rejects_damage_truncation_trailing_data_and_other_operation() {
    let original = checkpoint();
    let bytes = original.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(OperationCheckpoint::decode(&bytes[..end], original.operation).is_none());
    }
    for index in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1;
        assert!(OperationCheckpoint::decode(&damaged, original.operation).is_none());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(OperationCheckpoint::decode(&extra, original.operation).is_none());
    assert!(OperationCheckpoint::decode(&bytes, [99; 32]).is_none());
    let mut invalid = original.clone();
    invalid.dom_port = invalid.xmr_port;
    assert!(invalid.encode().is_none());
    invalid = original;
    invalid.dom_token = [0; 32];
    assert!(invalid.encode().is_none());
}

#[test]
fn manifest_rejects_changed_original_binding_and_invalid_canonical_order() {
    let mut original = checkpoint();
    let bytes = manifest(&mut original);
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(ClaimManifest::decode(&changed, &original).is_none());
    let mut other = original.clone();
    other.operation = [99; 32];
    assert!(ClaimManifest::decode(&bytes, &other).is_none());
    // Even a correctly checksummed record must obey its typed grammar.
    let order = bytes.len() - 25;
    let mut malformed = bytes.clone();
    malformed[order] = 2;
    original.manifest = digest(&malformed);
    assert!(ClaimManifest::decode(&malformed, &original).is_none());
    let mut trailing = bytes;
    trailing.push(0);
    original.manifest = digest(&trailing);
    assert!(ClaimManifest::decode(&trailing, &original).is_none());
}

#[tokio::test]
async fn restored_policy_checks_original_exposure_and_exact_first_bytes() {
    use dom_core::Timestamp;
    use dxp1_clsag_lab::release_journal::{InitialClaimJournal, ReleaseState};
    let mut original = checkpoint();
    let bytes = manifest(&mut original);
    let mut loaded = ClaimManifest::decode(&bytes, &original).unwrap();
    let root = std::env::temp_dir().join(format!(
        "dxp1-original-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("initial.wal");
    let first = b"exact original native claim";
    let mut journal = InitialClaimJournal::create(
        &path,
        loaded.original_release_policy(first).unwrap(),
        Timestamp(101),
    )
    .unwrap();
    journal
        .release_once(first, || Timestamp(102), || async {})
        .await
        .unwrap();
    drop(journal);
    let restored =
        InitialClaimJournal::open(&path, loaded.original_release_policy(first).unwrap()).unwrap();
    assert_eq!(restored.state().unwrap(), ReleaseState::ExposurePossible);
    drop(restored);
    assert!(InitialClaimJournal::open(
        &path,
        loaded.original_release_policy(b"different claim").unwrap()
    )
    .is_err());
    // Neither a refreshed timestamp nor a reduced workload may reinterpret
    // an original exposure event, even if the new policy is locally plausible.
    loaded.disclosed_at = 110;
    assert!(
        InitialClaimJournal::open(&path, loaded.original_release_policy(first).unwrap()).is_err()
    );
    loaded.disclosed_at = 100;
    loaded.candidates = 99;
    assert!(
        InitialClaimJournal::open(&path, loaded.original_release_policy(first).unwrap()).is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn restoring_assumptions_rejects_missing_work_and_inverted_bounds() {
    let mut original = checkpoint();
    let bytes = manifest(&mut original);
    let mut loaded = ClaimManifest::decode(&bytes, &original).unwrap();
    loaded.candidates = 0;
    assert!(loaded.original_release_policy(b"first").is_none());
    loaded.candidates = 1;
    loaded.latest_honest = 120;
    assert!(loaded.original_release_policy(b"first").is_none());
}
