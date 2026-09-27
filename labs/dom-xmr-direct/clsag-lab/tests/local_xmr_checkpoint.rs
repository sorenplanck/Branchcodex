//! State persistence only. Capsule bytes here are NOT a cryptographic proof.
use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt, process::Command};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::{
    capsule_checkpoint::CapsuleCheckpoint,
    xmr_recovery::{checkpoint::LocalXmrRecoveryCheckpoint, XmrRecoveryRoster},
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn fixture(local: usize) -> (XmrRecoveryRoster, ThresholdKeys<Ed25519>, CapsuleCheckpoint) {
    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let secrets = Zeroizing::new([Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)]);
    let points = secrets.map(|s| s * G);
    let roster = XmrRecoveryRoster::new([41; 32], points).unwrap();
    let key = ThresholdKeys::new(
        ThresholdParams::new(2, 2, ids[local]).unwrap(),
        Interpolation::Constant(vec![Scalar::ONE; 2]),
        Zeroizing::new(secrets[local]),
        HashMap::from([
            (ids[0], GroupPoint(points[0])),
            (ids[1], GroupPoint(points[1])),
        ]),
    )
    .unwrap();
    let payload = "codec fixture only".to_owned();
    let capsule = CapsuleCheckpoint {
        context: roster.recovery_domain(ids[1 - local]).unwrap(),
        public: points[1 - local].compress().to_bytes(),
        binding: Sha256::digest(payload.as_bytes()).into(),
        received_unix_seconds: 1000,
        squarings: 10_000_000,
        preparation_seconds: [1.0; 3],
        setup: "opaque fixture".into(),
        payload,
    };
    (roster, key, capsule)
}

#[test]
fn restores_original_roles_and_rejects_mismatched_capsule_or_derived_keys() {
    for role in 0..2 {
        let (roster, key, capsule) = fixture(role);
        let state = LocalXmrRecoveryCheckpoint::new(&roster, &key, &capsule).unwrap();
        let loaded = LocalXmrRecoveryCheckpoint::decode(&state.encode(), state.binding()).unwrap();
        let (restored, restored_roster, link) = loaded.restore(&capsule).unwrap();
        assert_eq!(restored.params().i(), key.params().i());
        assert_eq!(
            restored.original_secret_share(),
            key.original_secret_share()
        );
        assert_eq!(restored.current_offset(), Scalar::ZERO);
        assert_eq!(restored.current_scalar(), Scalar::ONE);
        assert_eq!(restored_roster.binding(), roster.binding());
        assert_ne!(link.binding(), [0; 64]);
        for case in 0..6 {
            let mut changed = capsule.clone();
            match case {
                0 => changed.context[0] ^= 1,
                1 => {
                    changed.public = roster
                        .share_key(key.params().i())
                        .unwrap()
                        .compress()
                        .to_bytes()
                }
                2 => changed.received_unix_seconds += 1,
                3 => changed.squarings = 200_000,
                4 => {
                    changed.payload.push(' ');
                    changed.binding = Sha256::digest(changed.payload.as_bytes()).into();
                }
                _ => changed.payload.push(' '),
            }
            assert!(loaded.restore(&changed).is_none(), "case {case}");
        }
        assert!(LocalXmrRecoveryCheckpoint::new(
            &roster,
            &key.clone().offset(Scalar::ONE),
            &capsule
        )
        .is_none());
        assert!(LocalXmrRecoveryCheckpoint::new(
            &roster,
            &key.clone().scale(Scalar::from(2u64)).unwrap(),
            &capsule
        )
        .is_none());
    }
}

#[test]
fn damage_truncation_substitution_and_noncanonical_secrets_are_rejected() {
    let (roster, key, capsule) = fixture(0);
    let state = LocalXmrRecoveryCheckpoint::new(&roster, &key, &capsule).unwrap();
    let bytes = state.encode();
    for i in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[i] ^= 1;
        assert!(LocalXmrRecoveryCheckpoint::decode(&mutated, state.binding()).is_none());
        assert!(LocalXmrRecoveryCheckpoint::decode(&bytes[..i], state.binding()).is_none());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(LocalXmrRecoveryCheckpoint::decode(&extended, state.binding()).is_none());
    assert!(LocalXmrRecoveryCheckpoint::decode(&bytes, [0; 32]).is_none());
    assert!(LocalXmrRecoveryCheckpoint::decode(&bytes, [2; 32]).is_none());
    let public_end = bytes.len() - 64;
    for secret in [[255; 32], [0; 32], Scalar::from(3u64).to_bytes()] {
        let mut mutated = bytes.clone();
        mutated[public_end..public_end + 32].copy_from_slice(&secret);
        let checksum = Sha256::digest(&mutated[..public_end + 32]);
        mutated[public_end + 32..].copy_from_slice(&checksum);
        assert!(LocalXmrRecoveryCheckpoint::decode(&mutated, state.binding()).is_none());
    }
    // A new checksum does not allow public identity/receipt/role substitution.
    for i in 0..public_end {
        let mut mutated = bytes.clone();
        mutated[i] ^= 1;
        let checksum = Sha256::digest(&mutated[..public_end + 32]);
        mutated[public_end + 32..].copy_from_slice(&checksum);
        assert!(LocalXmrRecoveryCheckpoint::decode(&mutated, state.binding()).is_none());
    }
}

#[test]
fn disk_is_private_create_only_and_rejects_missing_partial_public_or_symlink() {
    let root = std::env::temp_dir().join(format!("dxp1-local-xmr-disk-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let path = root.join("local.record");
    let (roster, key, capsule) = fixture(0);
    let state = LocalXmrRecoveryCheckpoint::new(&roster, &key, &capsule).unwrap();
    assert!(LocalXmrRecoveryCheckpoint::read(&path, state.binding()).is_err());
    state.write_new(&path).unwrap();
    let before = Zeroizing::new(fs::read(&path).unwrap());
    assert!(state.write_new(&path).is_err());
    assert!(LocalXmrRecoveryCheckpoint::read(&path, state.binding()).is_ok());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let symlink = root.join("symlink");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(LocalXmrRecoveryCheckpoint::read(&symlink, state.binding()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalXmrRecoveryCheckpoint::read(&path, state.binding()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &before[..before.len() - 1]).unwrap();
    assert!(LocalXmrRecoveryCheckpoint::read(&path, state.binding()).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        (before.len() - 1) as u64
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fresh_process_restores_only_from_persisted_state_for_both_roles() {
    for role in 0..2 {
        let root = std::env::temp_dir().join(format!(
            "dxp1-local-xmr-child-{}-{role}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::File::open(&root).unwrap().sync_all().unwrap();
        fs::File::open(root.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        let (identity, capsule_binding, expected) = {
            let (roster, key, capsule) = fixture(role);
            let state = LocalXmrRecoveryCheckpoint::new(&roster, &key, &capsule).unwrap();
            state.write_new(&root.join("local.record")).unwrap();
            capsule.write_new(&root.join("capsule.record")).unwrap();
            let h: curve25519_dalek::edwards::EdwardsPoint =
                monero_ed25519::Point::biased_hash([9; 32]).into();
            let expected = (h * **key.original_secret_share()).compress().to_bytes();
            (state.binding(), capsule.binding, expected)
        };
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "restore_child", "--nocapture"])
            .env("DXP1_LOCAL_STATE_TEST_ROOT", &root)
            .env(
                "DXP1_LOCAL_STATE_TEST_ID",
                serde_json::to_string(&identity).unwrap(),
            )
            .env(
                "DXP1_LOCAL_STATE_TEST_CAPSULE",
                serde_json::to_string(&capsule_binding).unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(root.join("public-response")).unwrap(), expected);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[ignore = "executed in a fresh child by the parent test"]
fn restore_child() {
    let root = std::path::PathBuf::from(std::env::var_os("DXP1_LOCAL_STATE_TEST_ROOT").unwrap());
    let identity =
        serde_json::from_str(&std::env::var("DXP1_LOCAL_STATE_TEST_ID").unwrap()).unwrap();
    let binding =
        serde_json::from_str(&std::env::var("DXP1_LOCAL_STATE_TEST_CAPSULE").unwrap()).unwrap();
    let state = LocalXmrRecoveryCheckpoint::read(&root.join("local.record"), identity).unwrap();
    let capsule = CapsuleCheckpoint::read(&root.join("capsule.record"), binding).unwrap();
    let (local, _, _) = state.restore(&capsule).unwrap();
    let h: curve25519_dalek::edwards::EdwardsPoint =
        monero_ed25519::Point::biased_hash([9; 32]).into();
    let image = h * **local.original_secret_share();
    fs::write(root.join("public-response"), image.compress().to_bytes()).unwrap();
    std::process::exit(0);
}
