use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use dxp1_clsag_lab::capsule_checkpoint::{CapsuleCheckpoint, MAX_CAPSULE_BYTES};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt};

fn fixture() -> CapsuleCheckpoint {
    // Codec fixture only; this payload is deliberately NOT an accepted proof.
    let payload = "{\"codec_fixture\":true}".to_owned();
    CapsuleCheckpoint {
        context: [7; 32],
        public: ED25519_BASEPOINT_POINT.compress().to_bytes(),
        binding: Sha256::digest(payload.as_bytes()).into(),
        received_unix_seconds: 1000,
        squarings: 10_000_000,
        preparation_seconds: [31.0, 15.0, 7.0],
        setup: "{\"opaque_setup\":true}".to_owned(),
        payload,
    }
}

#[test]
fn corruption_truncation_and_substitution_do_not_restore_a_capsule() {
    let original = fixture();
    let bytes = original.encode().unwrap();
    assert!(CapsuleCheckpoint::decode(&bytes, original.binding).unwrap() == original);
    assert!(CapsuleCheckpoint::decode(&bytes, [2; 32]).is_none());
    for i in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[i] ^= 1;
        assert!(CapsuleCheckpoint::decode(&corrupt, original.binding).is_none());
        assert!(CapsuleCheckpoint::decode(&bytes[..i], original.binding).is_none());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(CapsuleCheckpoint::decode(&extended, original.binding).is_none());
    let mut changed = original.clone();
    changed.payload.push(' ');
    assert!(changed.encode().is_none());
    changed.binding = Sha256::digest(changed.payload.as_bytes()).into();
    assert!(CapsuleCheckpoint::decode(&changed.encode().unwrap(), original.binding).is_none());
    // Even a valid checksum must not bypass policy validation on reopen.
    let mut invalid_time = bytes;
    let timestamp_offset = b"DXP1/direct-capsule-checkpoint/v2\0".len() + 96;
    invalid_time[timestamp_offset..timestamp_offset + 8].fill(0);
    let end = invalid_time.len() - 32;
    let checksum = Sha256::digest(&invalid_time[..end]);
    invalid_time[end..].copy_from_slice(&checksum);
    assert!(CapsuleCheckpoint::decode(&invalid_time, original.binding).is_none());
}

#[test]
fn arbitrary_precision_offer_and_setup_stay_opaque() {
    let mut value = fixture();
    value.setup = format!("{{\"N\":{}}}", "9".repeat(1234));
    value.payload = format!("{{\"proof_integer\":{}}}", "9".repeat(2000));
    value.binding = Sha256::digest(value.payload.as_bytes()).into();
    let encoded = value.encode().unwrap();
    assert!(CapsuleCheckpoint::decode(&encoded, value.binding).unwrap() == value);
    value.setup = "x".repeat(65537);
    assert!(value.encode().is_none());
    value.setup.clear();
    assert!(value.encode().is_none());
}

#[test]
fn invalid_shapes_work_points_and_measurements_are_rejected() {
    for mutation in 0..9 {
        let mut value = fixture();
        match mutation {
            0 => value.context = [0; 32],
            1 => value.public = [0; 32],
            2 => value.squarings = 1,
            3 => value.received_unix_seconds = 0,
            4 => value.preparation_seconds[0] = f64::NAN,
            5 => value.preparation_seconds[1] = f64::INFINITY,
            6 => value.preparation_seconds[2] = -1.0,
            7 => {
                value.payload = "x".repeat(MAX_CAPSULE_BYTES);
                value.binding = Sha256::digest(value.payload.as_bytes()).into();
            }
            _ => {
                value.payload.push('\n');
                value.binding = Sha256::digest(value.payload.as_bytes()).into();
            }
        }
        assert!(value.encode().is_none(), "case {mutation}");
    }
}

#[test]
fn disk_record_is_private_immutable_and_never_repairs_bad_input() {
    let root = std::env::temp_dir().join(format!("dxp1-capsule-checkpoint-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let path = root.join("capsule.record");
    let value = fixture();
    assert!(CapsuleCheckpoint::read(&path, value.binding).is_err());
    value.write_new(&path).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(value.write_new(&path).is_err());
    assert!(CapsuleCheckpoint::read(&path, value.binding).unwrap() == value);
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(CapsuleCheckpoint::read(&path, value.binding).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &before[..before.len() - 1]).unwrap();
    assert!(CapsuleCheckpoint::read(&path, value.binding).is_err());
    assert_eq!(fs::read(&path).unwrap(), before[..before.len() - 1]);
    fs::remove_dir_all(root).unwrap();
}
