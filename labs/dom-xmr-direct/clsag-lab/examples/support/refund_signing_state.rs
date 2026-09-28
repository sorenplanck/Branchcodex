//! Local completed opening checkpoint, not a proof/timing authority. Contains
//! one recovered ORIGINAL peer share: private participant storage is required.
//! Only valid after public capsule verification/opening under RecoveryOnly.
use super::refund_recovery_worker::{read_private, write_private};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"DXP1/completed-private-opening/v1\0";
const LIMIT: usize = 32768;
pub fn encode(job: [u8; 32], secret: &Scalar, report: &Value) -> Zeroizing<Vec<u8>> {
    assert_ne!(job, [0; 32]);
    let mut bytes = Zeroizing::new(MAGIC.to_vec());
    bytes.extend(job);
    let scalar = Zeroizing::new(secret.to_bytes());
    bytes.extend_from_slice(&*scalar);
    let report = serde_json::to_vec(report).unwrap();
    assert!(report.len() <= LIMIT);
    bytes.extend((report.len() as u32).to_le_bytes());
    bytes.extend(report);
    let checksum = Sha256::digest(&*bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}
pub fn decode(
    bytes: &[u8],
    job: [u8; 32],
    public: EdwardsPoint,
) -> Option<(Zeroizing<Scalar>, Value)> {
    let data = bytes.strip_prefix(MAGIC)?;
    if job == [0; 32]
        || data.len() < 100
        || data[..32] != job
        || bytes.len() > LIMIT + MAGIC.len() + 100
    {
        return None;
    }
    let scalar = Zeroizing::new(<[u8; 32]>::try_from(&data[32..64]).ok()?);
    let scalar = Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(
        *scalar,
    ))?);
    if *scalar * G != public {
        return None;
    }
    let length = u32::from_le_bytes(data[64..68].try_into().ok()?) as usize;
    if length > LIMIT || data.len() != 100 + length {
        return None;
    }
    let end = bytes.len() - 32;
    if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return None;
    }
    let report: Value = serde_json::from_slice(&data[68..68 + length]).ok()?;
    if !report.is_object() {
        return None;
    }
    Some((scalar, report))
}

// No overwrite/rename over an existing final. The caller holds PreparationGate.
// A full durable pending file can be promoted after a crash. Callers must
// validate its bytes and purpose BEFORE calling this function.
pub fn promote(root: &Path, pending: &str, final_name: &str) {
    File::open(root.join(pending)).unwrap().sync_all().unwrap();
    fs::hard_link(root.join(pending), root.join(final_name)).unwrap();
    File::open(root).unwrap().sync_all().unwrap();
    fs::remove_file(root.join(pending)).unwrap();
    File::open(root).unwrap().sync_all().unwrap();
}
pub fn persist(root: &Path, job: [u8; 32], secret: &Scalar, report: &Value) {
    let bytes = encode(job, secret, report);
    write_private(&root.join("refund-opening.pending"), &bytes);
    promote(root, "refund-opening.pending", "refund-opening.record");
}
pub fn restore(
    root: &Path,
    job: [u8; 32],
    public: EdwardsPoint,
) -> Option<(Zeroizing<Scalar>, Value)> {
    let final_path = root.join("refund-opening.record");
    if final_path.try_exists().unwrap() {
        return Some(
            decode(&read_private(&final_path), job, public).expect("invalid completed opening"),
        );
    }
    let pending = root.join("refund-opening.pending");
    if pending.try_exists().unwrap() {
        let value =
            decode(&read_private(&pending), job, public).expect("incomplete opening checkpoint");
        promote(root, "refund-opening.pending", "refund-opening.record");
        return Some(value);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_share_is_canonical_and_bound_to_job_and_public_key() {
        let scalar = Scalar::from(41u64);
        let job = [1; 32];
        let public = scalar * G;
        let original = encode(job, &scalar, &serde_json::json!({"opening_seconds":30}));
        assert_eq!(*decode(&original, job, public).unwrap().0, scalar);
        assert!(decode(&original, [2; 32], public).is_none());
        assert!(decode(&original, job, Scalar::from(42u64) * G).is_none());
        for cut in 0..original.len() {
            assert!(decode(&original[..cut], job, public).is_none());
        }
        for offset in 0..original.len() {
            let mut bad = original.clone();
            bad[offset] ^= 1;
            assert!(decode(&bad, job, public).is_none());
        }
        // A recomputed checksum is not sufficient to accept another scalar.
        let mut bad = original.clone();
        bad[MAGIC.len() + 32..MAGIC.len() + 64].fill(255);
        let end = bad.len() - 32;
        let hash = Sha256::digest(&bad[..end]);
        bad[end..].copy_from_slice(&hash);
        assert!(decode(&bad, job, public).is_none());
    }
    #[test]
    fn durable_pending_opening_promotes_without_reopening_or_overwriting() {
        let root = std::env::temp_dir().join(format!("dxp1-opening-stage-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let secret = Scalar::from(41u64);
        let job = [1; 32];
        let bytes = encode(job, &secret, &serde_json::json!({}));
        write_private(&root.join("refund-opening.pending"), &bytes);
        let (loaded, _) = restore(&root, job, secret * G).unwrap();
        assert_eq!(*loaded, secret);
        assert!(!root.join("refund-opening.pending").exists());
        assert_eq!(*read_private(&root.join("refund-opening.record")), *bytes);
        assert!(std::panic::catch_unwind(|| promote(
            &root,
            "refund-opening.record",
            "refund-opening.record"
        ))
        .is_err());
        assert_eq!(*read_private(&root.join("refund-opening.record")), *bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_opening_is_not_repaired_or_treated_as_missing() {
        let root =
            std::env::temp_dir().join(format!("dxp1-partial-opening-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let bytes = encode([1; 32], &Scalar::from(41u64), &serde_json::json!({}));
        write_private(
            &root.join("refund-opening.pending"),
            &bytes[..bytes.len() / 2],
        );
        assert!(
            std::panic::catch_unwind(|| restore(&root, [1; 32], Scalar::from(41u64) * G)).is_err()
        );
        assert!(!root.join("refund-opening.record").exists());
        assert_eq!(
            *read_private(&root.join("refund-opening.pending")),
            bytes[..bytes.len() / 2]
        );
        fs::remove_dir_all(root).unwrap();
    }
}
