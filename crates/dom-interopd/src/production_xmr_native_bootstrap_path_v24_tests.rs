//! The daemon's native path must reopen the original private ceremony owner.
//! Fast path-selection tests plus one real initial C/D custody ceremony: no
//! collaborative Bulletproofs, recovery signing rounds, funding or network.
use super::*;
use std::os::unix::fs::MetadataExt as _;
use xmr_coldstart_v23::retained_native_bootstrap_name_v24;

const PUBLIC_COPY: &str = "native-contracts-bootstrap.bin";

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("private path fixture");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private path fixture mode");
    root
}

// Public artifact bytes and physical identity only, never a key or share.
fn artifact_snapshot(path: &Path) -> (Vec<u8>, u64, u64, u32, i64, i64) {
    let metadata = std::fs::symlink_metadata(path).expect("artifact metadata");
    (
        std::fs::read(path).expect("public artifact"),
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

#[test]
fn original_native_bootstrap_path_is_selected_without_rewriting_v24() {
    let root = private_root();
    let expected = b"previously authenticated completed public artifact";
    let original = root.path().join(ARTIFACT);
    let copy = root.path().join(PUBLIC_COPY);
    write(&original, expected);
    write(
        &copy,
        b"an unrelated public-only copy must never be selected",
    );
    let original_before = artifact_snapshot(&original);
    let copy_before = artifact_snapshot(&copy);
    assert_eq!(
        retained_native_bootstrap_name_v24(root.path(), expected).expect("retained original"),
        ARTIFACT,
    );
    assert_ne!(ARTIFACT, PUBLIC_COPY);
    assert_eq!(artifact_snapshot(&original), original_before);
    assert_eq!(artifact_snapshot(&copy), copy_before);
    assert_eq!(
        std::fs::read_dir(root.path()).expect("directory").count(),
        2
    );
}

#[test]
fn missing_copied_mutated_or_nonprivate_bootstrap_never_recreates_owner_v24() {
    let root = private_root();
    let expected = b"previously authenticated completed public artifact";
    let original = root.path().join(ARTIFACT);
    let copy = root.path().join(PUBLIC_COPY);
    assert!(retained_native_bootstrap_name_v24(root.path(), expected).is_err());
    assert_eq!(
        std::fs::read_dir(root.path()).expect("empty root").count(),
        0
    );

    // Reproduce the failed daemon: exact public bytes at the wrong basename
    // cannot cause the missing native owner to be created, renamed or copied.
    write(&copy, expected);
    let copy_before = artifact_snapshot(&copy);
    assert!(retained_native_bootstrap_name_v24(root.path(), expected).is_err());
    assert!(!original.exists());
    assert_eq!(artifact_snapshot(&copy), copy_before);

    let mut changed = expected.to_vec();
    changed[0] ^= 1;
    write(&original, &changed);
    let changed_before = artifact_snapshot(&original);
    assert!(retained_native_bootstrap_name_v24(root.path(), expected).is_err());
    assert_eq!(artifact_snapshot(&original), changed_before);

    write(&original, expected);
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644))
        .expect("negative nonprivate artifact");
    let nonprivate_before = artifact_snapshot(&original);
    assert!(retained_native_bootstrap_name_v24(root.path(), expected).is_err());
    assert_eq!(artifact_snapshot(&original), nonprivate_before);

    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600))
        .expect("restore private fixture mode");
    assert!(retained_native_bootstrap_name_v24(root.path(), b"").is_err());
    let mut oversized = expected.to_vec();
    oversized.push(0);
    write(&original, &oversized);
    let oversized_before = artifact_snapshot(&original);
    assert!(retained_native_bootstrap_name_v24(root.path(), expected).is_err());
    assert_eq!(artifact_snapshot(&original), oversized_before);
    assert_eq!(artifact_snapshot(&copy), copy_before);
    assert_eq!(
        std::fs::read_dir(root.path()).expect("directory").count(),
        2
    );
}

#[test]
fn selected_native_bootstrap_path_reopens_real_xmr_private_owners_v24() {
    // This existing fixture stops at signed commitments/capsule reveals. It
    // does not form C/D Bulletproofs or execute any expensive graph scenario.
    let (fixture, bytes) = completed_fixture_with_xmr(true);
    let actor = 0;
    let root = &fixture.work[actor];
    let plan: Plan = serde_json::from_slice(
        &std::fs::read(&fixture.plan[actor]).expect("original ceremony plan"),
    )
    .expect("canonical fixture plan");
    let secp = SecpContext::new(&[13; 32]);
    let context = load_context(&plan, &secp, true).expect("authenticated original context");
    let verified =
        authenticate_against_expected_v1(&bytes, &context.expected, &context.rosters, &secp)
            .expect("real signed native artifact");
    let positions = [0, 1].map(|leg| {
        context.rosters.legs()[leg]
            .members
            .iter()
            .position(|member| member.participant_id.0 == plan.local_participant_id)
            .expect("local original participant")
    });
    let bindings = [
        context.bindings[0][positions[0]],
        context.bindings[1][positions[1]],
    ];
    let copy = root.join(PUBLIC_COPY);
    write(&copy, &bytes);
    // Production deliberately leaves externally prepared public-only paths
    // outside the native mount. Preserve that behavior, not a guard bypass.
    assert!(resume_completed_bootstrap_v13(
        &copy,
        &verified,
        bindings,
        &plan.identity_store,
        b"test-passphrase-v13",
    )
    .expect("public-only path remains distinct")
    .is_none());

    let selected = retained_native_bootstrap_name_v24(root, &bytes)
        .expect("select actual retained ceremony artifact");
    assert_eq!(selected, ARTIFACT);
    let original = root.join(selected);
    let original_before = artifact_snapshot(&original);
    let copy_before = artifact_snapshot(&copy);
    for _ in 0..2 {
        let mounted = resume_completed_bootstrap_v13(
            &original,
            &verified,
            bindings,
            &plan.identity_store,
            b"test-passphrase-v13",
        )
        .expect("reopen original native custody")
        .expect("native artifact must mount a private owner, not silently downgrade");
        for leg in 0..2 {
            assert!(mounted._cancelled_shares[leg].is_some());
            assert!(mounted._cancelled_contracts[leg].is_some());
            assert_eq!(
                mounted._shares[leg]
                    .capability
                    .binding()
                    .share_point()
                    .to_compressed_bytes(),
                *verified.legs()[leg].participants()[positions[leg]].share_point(),
            );
            assert_eq!(
                mounted._shares[leg].capability.binding().session_id(),
                &bindings[leg].session_id(),
            );
        }
        drop(mounted);
        assert_eq!(artifact_snapshot(&original), original_before);
        assert_eq!(artifact_snapshot(&copy), copy_before);
    }
}
