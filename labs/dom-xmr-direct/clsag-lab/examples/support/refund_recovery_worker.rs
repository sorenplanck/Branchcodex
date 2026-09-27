//! Owned-regtest recovery/signing worker. No spend shares are returned to the
//! supervisor. A separate delivery worker publishes the persisted exact bytes.
use super::{direct_recovery_bridge, fresh_secret, presign, unix_seconds};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dxp1_clsag_lab::{
    capsule_checkpoint::CapsuleCheckpoint,
    native::PreparedClaim,
    preparation_gate::{PreparationBinding, PreparationGate},
    xmr_recovery::checkpoint::LocalXmrRecoveryCheckpoint,
    Statement,
};
use frost::Participant;
use monero_wallet::{ed25519::Point, transaction::Transaction};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"DXP1/owned-refund-worker/v2\0";
const LIMIT: usize = 2 * 1024 * 1024;

pub fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
pub(super) fn read_private(path: &Path) -> Zeroizing<Vec<u8>> {
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(
        meta.is_file() && meta.permissions().mode() & 0o777 == 0o600 && meta.len() <= LIMIT as u64
    );
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)
        .unwrap()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= LIMIT);
    bytes
}
fn take<const N: usize>(input: &mut &[u8]) -> [u8; N] {
    let (value, rest) = input.split_at(N);
    *input = rest;
    value.try_into().unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Job {
    pub local_identity: [u8; 32],
    pub capsule: [u8; 32],
    pub link: [u8; 64],
    pub received: u64,
    pub latest: u64,
    pub network: [u8; 32],
    pub offset: Zeroizing<Scalar>,
    pub unsigned: Zeroizing<Vec<u8>>,
}
impl Job {
    pub fn persist(&self, root: &Path) -> [u8; 32] {
        let mut bytes = Zeroizing::new(MAGIC.to_vec());
        bytes.extend(self.local_identity);
        bytes.extend(self.capsule);
        bytes.extend(self.link);
        bytes.extend(self.received.to_le_bytes());
        bytes.extend(self.latest.to_le_bytes());
        bytes.extend(self.network);
        let offset = Zeroizing::new(self.offset.to_bytes());
        bytes.extend_from_slice(&*offset);
        bytes.extend_from_slice(&self.unsigned);
        assert!(bytes.len() <= LIMIT);
        write_private(&root.join("refund-recovery.job"), &bytes);
        Sha256::digest(&*bytes).into()
    }
    pub(super) fn load(root: &Path, expected: [u8; 32]) -> Self {
        let bytes = read_private(&root.join("refund-recovery.job"));
        assert_ne!(expected, [0; 32]);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&*bytes)), expected);
        let mut input = bytes.strip_prefix(MAGIC).unwrap();
        let local_identity = take(&mut input);
        let capsule = take(&mut input);
        let link = take(&mut input);
        let received = u64::from_le_bytes(take(&mut input));
        let latest = u64::from_le_bytes(take(&mut input));
        let network = take(&mut input);
        assert_ne!(network, [0; 32]);
        let encoded = Zeroizing::new(take(&mut input));
        let offset =
            Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(*encoded)).unwrap());
        // Exact current LAB assumption; never recompute a deadline from now.
        assert_eq!(received.checked_add(100), Some(latest));
        assert_ne!(local_identity, [0; 32]);
        assert_ne!(capsule, [0; 32]);
        assert_ne!(link, [0; 64]);
        Self {
            local_identity,
            capsule,
            link,
            received,
            latest,
            network,
            offset,
            unsigned: Zeroizing::new(input.to_vec()),
        }
    }
    pub(super) fn prepared(&self) -> PreparedClaim {
        let value = PreparedClaim::from_recovery_bytes(
            &self.unsigned,
            dxp1_clsag_lab::claim_resume::digest(&self.unsigned),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            value.context().route_binding,
            <[u8; 32]>::from(Sha256::digest(self.link))
        );
        value
    }
}

pub fn run(
    root: PathBuf,
    bridge: PathBuf,
    expected: [u8; 32],
) -> (PreparedClaim, Transaction, Value) {
    let began = Instant::now();
    let spawn_signer = |action: &str, solver: &Path, code: i32| {
        let mut process = super::ManagedDaemon(
            Command::new(std::env::current_exe().unwrap())
                .arg("--xmr-refund-recovery-worker")
                .arg(&root)
                .arg(solver)
                .arg(hex(&expected))
                .arg(action)
                .spawn()
                .unwrap(),
        );
        let pid = process.0.id();
        assert_eq!(process.0.wait().unwrap().code(), Some(code));
        pid
    };
    let opened_pid = spawn_signer("crash-after-opening", &bridge, 82);
    // These workers cannot start a solver: they have only the original local
    // checkpoint plus a completed opening, and an intentionally invalid path.
    let no_solver = Path::new("/nonexistent-solver-must-not-reopen");
    let opening_before = Sha256::digest(&*read_private(&root.join("refund-opening.record")));
    let partial_pid = spawn_signer("crash-partial-signature", no_solver, 83);
    assert!(!root.join("refund-signed.tx").exists());
    assert!(!root.join("refund-send.intent").exists());
    let signature_pid = spawn_signer("crash-after-signature", no_solver, 84);
    let signed_stage = read_private(&root.join("refund-signed.pending"));
    assert!(!root.join("refund-signed.tx").exists());
    let pid = spawn_signer("sign", no_solver, 0);
    assert_eq!(
        Sha256::digest(&*read_private(&root.join("refund-opening.record"))),
        opening_before
    );
    let job = Job::load(&root, expected);
    let prepared = job.prepared();
    let bytes = read_private(&root.join("refund-signed.tx"));
    let mut input = bytes.as_slice();
    let tx = Transaction::read(&mut input).unwrap();
    assert!(input.is_empty());
    assert_eq!(tx.serialize(), *bytes);
    assert_eq!(*bytes, *signed_stage);
    prepared.verify_final(&tx, &mut OsRng).unwrap();
    let mut report: Value =
        serde_json::from_slice(&read_private(&root.join("refund-worker-report.json"))).unwrap();
    report["refund_recovery_worker_pid"] = json!(pid);
    report["refund_opening_worker_pid"] = json!(opened_pid);
    report["refund_partial_signature_worker_pid"] = json!(partial_pid);
    report["refund_signature_producer_pid"] = json!(signature_pid);
    report["worker_recovery_and_signing_seconds"] = json!(began.elapsed().as_secs_f64());
    report["completed_opening_unchanged_across_restarts"] = json!(true);
    report["staged_signature_promoted_without_resigning"] = json!(true);
    report["partial_signature_never_published"] = json!(true);
    // The signing process has exited. These processes receive no keys or
    // solver path and can only reconcile/publish the durable signed bytes.
    let before_rpc = super::refund_delivery::run(&root, expected, "send-crash-before-rpc");
    let intent = read_private(&root.join("refund-send.intent"));
    let failed = super::refund_delivery::run(&root, expected, "send-crash-after-ack");
    let resumed = super::refund_delivery::run(&root, expected, "send");
    assert_eq!(resumed["observation"], "InPool");
    assert_eq!(resumed["submitted"], false);
    assert_eq!(*read_private(&root.join("refund-signed.tx")), *bytes);
    assert_eq!(*read_private(&root.join("refund-send.intent")), *intent);
    report["refund_delivery_before_rpc_crashed_pid"] = before_rpc["pid"].clone();
    report["refund_delivery_crashed_pid"] = failed["pid"].clone();
    report["refund_delivery_resumed"] = resumed;
    report["refund_worker_independently_publishes"] = json!(true);
    report["refund_signed_bytes_and_send_intent_unchanged"] = json!(true);
    (prepared, tx, report)
}

pub fn worker(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let began = Instant::now();
    let root = PathBuf::from(args.next().unwrap());
    let bridge = PathBuf::from(args.next().unwrap());
    let raw = args.next().unwrap().into_string().unwrap();
    assert_eq!(raw.len(), 64);
    let expected = std::array::from_fn(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).unwrap());
    assert_eq!(hex(&expected), raw);
    let action = args
        .next()
        .map(|v| v.into_string().unwrap())
        .unwrap_or_else(|| "sign".to_owned());
    assert!(matches!(
        action.as_str(),
        "sign" | "crash-after-opening" | "crash-partial-signature" | "crash-after-signature"
    ));
    assert!(args.next().is_none());
    let job = Job::load(&root, expected);
    assert!(unix_seconds() >= job.received && unix_seconds() <= job.latest);
    // Hold this local lock through recovery/signing. Never infer non-exposure
    // from a missing initial-claim journal or recreate a missing phase gate.
    let mut phase = PreparationGate::open(
        &root.join("preparation.wal"),
        PreparationBinding {
            capsule_link: job.link,
            received: job.received,
        },
    )
    .unwrap();
    phase
        .claim_recovery(expected)
        .expect("private-abandonment recovery is not authorized");
    assert!(
        root.join("refund-signed.tx").try_exists().unwrap()
            || !root.join("refund-send.intent").try_exists().unwrap(),
        "missing possibly published refund"
    );
    assert!(unix_seconds() >= job.received && unix_seconds() <= job.latest);
    let capsule =
        CapsuleCheckpoint::read(&root.join("direct-capsule.record"), job.capsule).unwrap();
    assert_eq!(capsule.received_unix_seconds, job.received);
    let state = LocalXmrRecoveryCheckpoint::read(
        &root.join("local-xmr-recovery.record"),
        job.local_identity,
    )
    .unwrap();
    let (local, roster, link) = state.restore(&capsule).unwrap();
    assert_eq!(link.binding(), job.link);
    let prepared = job.prepared();
    assert_eq!(
        roster.spend_key() + *job.offset * G,
        prepared.context().ring[prepared.context().real][0]
    );
    let peer = Participant::new(3 - u16::from(local.params().i())).unwrap();
    let restored_opening =
        super::refund_signing_state::restore(&root, expected, roster.share_key(peer).unwrap());
    let reused_opening = restored_opening.is_some();
    let (opening, mut details) = if let Some(value) = restored_opening {
        value
    } else {
        assert!(!root.join("refund-signed.tx").try_exists().unwrap());
        assert!(!root.join("refund-signed.pending").try_exists().unwrap());
        assert!(!root.join("refund-send.intent").try_exists().unwrap());
        let public = direct_recovery_bridge::DirectPublicCapsule::restore_with_local_receipt(
            &bridge,
            &root.join("direct-capsule.record"),
            job.capsule,
            &root.join("local-verifier-authority.key"),
        );
        let (opening, details) = public.open();
        // Validate the original peer/roster relation before persisting any
        // completed opening. This record contains sensitive key material.
        drop(
            link.recover_after_opening(&roster, peer, job.capsule, opening.clone())
                .unwrap(),
        );
        assert!(
            unix_seconds() <= job.latest,
            "opening exceeded original deadline"
        );
        super::refund_signing_state::persist(&root, expected, &opening, &details);
        (opening, details)
    };
    if action == "crash-after-opening" {
        std::process::exit(82);
    }
    details["completed_opening_restored"] = json!(reused_opening);
    assert!(link
        .recover_after_opening(
            &roster,
            peer,
            job.capsule,
            Zeroizing::new(*opening + Scalar::ONE)
        )
        .is_err());
    let recovered = link
        .recover_after_opening(&roster, peer, job.capsule, opening)
        .unwrap();
    let mut keys = [local, recovered];
    keys.sort_by_key(|key| u16::from(key.params().i()));
    let keys = keys.map(|key| key.offset(*job.offset));
    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let h: curve25519_dalek::edwards::EdwardsPoint = Point::biased_hash(
        prepared.context().ring[prepared.context().real][0]
            .compress()
            .to_bytes(),
    )
    .into();
    assert_eq!(
        keys.iter()
            .map(|key| h * **key.view(ids.to_vec()).unwrap().secret_share())
            .sum::<curve25519_dalek::edwards::EdwardsPoint>(),
        prepared.context().image
    );
    let final_path = root.join("refund-signed.tx");
    let pending_path = root.join("refund-signed.pending");
    let mut recovered_stage = false;
    let tx = if final_path.try_exists().unwrap() {
        validated_signed(&prepared, &read_private(&final_path))
            .expect("invalid final refund signature")
    } else {
        // A missing final after possible publication must never be replaced
        // by newly signed bytes, even if a private partial stage remains.
        assert!(
            !root.join("refund-send.intent").try_exists().unwrap(),
            "missing possibly published refund"
        );
        let staged = if pending_path.try_exists().unwrap() {
            let value = validated_signed(&prepared, &read_private(&pending_path));
            if value.is_none() {
                // Only the unpublished staging path may be discarded. The
                // completed opening survives; fresh signing uses fresh nonces.
                fs::remove_file(&pending_path).unwrap();
                File::open(&root).unwrap().sync_all().unwrap();
            }
            value
        } else {
            None
        };
        let tx = if let Some(tx) = staged {
            recovered_stage = true;
            tx
        } else {
            let witness = Zeroizing::new(Scalar::random(&mut OsRng));
            let statement = Statement::prove(prepared.context(), &witness, &mut OsRng).unwrap();
            let pre = presign(&prepared, statement, keys, *fresh_secret());
            let tx = prepared.complete(&pre, &witness, &mut OsRng).unwrap();
            let bytes = tx.serialize();
            if action == "crash-partial-signature" {
                write_private(&pending_path, &bytes[..bytes.len() / 2]);
                std::process::exit(83);
            }
            write_private(&pending_path, &bytes);
            tx
        };
        if action == "crash-after-signature" {
            std::process::exit(84);
        }
        super::refund_signing_state::promote(&root, "refund-signed.pending", "refund-signed.tx");
        tx
    };
    prepared.verify_final(&tx, &mut OsRng).unwrap();
    assert!(
        unix_seconds() <= job.latest,
        "original recovery deadline exceeded"
    );
    details["signature_restored_from_complete_stage"] = json!(recovered_stage);
    details["refund_signed_in_fresh_rust_process"] = json!(true);
    details["local_xmr_state_restored_in_fresh_process"] = json!(true);
    details["worker_exports_spend_shares"] = json!(false);
    details["last_signing_worker_seconds"] = json!(began.elapsed().as_secs_f64());
    details["worker_preserves_original_deadline"] = json!(true);
    details["preparation_gate_recovery_only"] = json!(true);
    if !root.join("refund-worker-report.json").try_exists().unwrap() {
        write_private(
            &root.join("refund-worker-report.json"),
            &serde_json::to_vec(&details).unwrap(),
        );
    }
    drop(phase);
}

fn validated_signed(prepared: &PreparedClaim, bytes: &[u8]) -> Option<Transaction> {
    let mut input = bytes;
    let tx = Transaction::read(&mut input).ok()?;
    if !input.is_empty() || tx.serialize() != bytes {
        return None;
    }
    prepared.verify_final(&tx, &mut OsRng).ok()?;
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_possibly_published_signature_never_restarts_opening_or_signing() {
        let root = std::env::temp_dir().join(format!("dxp1-missing-final-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let received = unix_seconds();
        let job = Job {
            local_identity: [1; 32],
            capsule: [2; 32],
            link: [3; 64],
            received,
            latest: received + 100,
            network: [9; 32],
            offset: Zeroizing::new(Scalar::ZERO),
            unsigned: Zeroizing::new(vec![7; 16]),
        };
        let identity = job.persist(&root);
        let mut gate = PreparationGate::create(
            &root.join("preparation.wal"),
            PreparationBinding {
                capsule_link: job.link,
                received,
            },
        )
        .unwrap();
        gate.claim_recovery(identity).unwrap();
        drop(gate);
        write_private(
            &root.join("refund-send.intent"),
            b"possible previous publication",
        );
        write_private(&root.join("refund-signed.pending"), b"partial");
        let result = std::panic::catch_unwind(|| {
            worker(
                vec![
                    root.clone().into_os_string(),
                    "/nonexistent-solver".into(),
                    hex(&identity).into(),
                ]
                .into_iter(),
            )
        });
        let panic = result.expect_err("missing final was repaired");
        let text = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(text.contains("missing possibly published refund"));
        assert_eq!(
            *read_private(&root.join("refund-signed.pending")),
            b"partial"
        );
        assert!(!root.join("refund-signed.tx").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exposed_operation_is_rejected_before_loading_shares_or_starting_solver() {
        let root =
            std::env::temp_dir().join(format!("dxp1-refund-exposure-gate-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let received = unix_seconds();
        let job = Job {
            local_identity: [1; 32],
            capsule: [2; 32],
            link: [3; 64],
            received,
            latest: received + 100,
            network: [9; 32],
            offset: Zeroizing::new(Scalar::ZERO),
            unsigned: Zeroizing::new(vec![7; 16]),
        };
        let identity = job.persist(&root);
        let mut gate = PreparationGate::create(
            &root.join("preparation.wal"),
            PreparationBinding {
                capsule_link: job.link,
                received,
            },
        )
        .unwrap();
        gate.begin_exchange([4; 32]).unwrap();
        drop(gate);
        let before = fs::read(root.join("preparation.wal")).unwrap();
        let result = std::panic::catch_unwind(|| {
            worker(
                vec![
                    root.clone().into_os_string(),
                    std::ffi::OsString::from("/nonexistent-solver-must-not-start"),
                    hex(&identity).into(),
                ]
                .into_iter(),
            )
        });
        let panic = result.expect_err("exposed operation reached recovery");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(message.contains("private-abandonment recovery is not authorized"));
        assert_eq!(fs::read(root.join("preparation.wal")).unwrap(), before);
        assert!(!root.join("refund-signed.tx").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_restores_real_unsigned_intent_with_the_codec_digest_domain() {
        use dxp1_clsag_lab::{native::ClaimTerms, RING_SIZE};
        use monero_wallet::{
            address::Network,
            ed25519::{Commitment, Scalar as MoneroScalar},
            interface::FeeRate,
            OutputWithDecoys, ViewPair,
        };
        let key = Point::from(Scalar::from(3u64) * G);
        let commitment = Commitment::new(MoneroScalar::from(Scalar::from(2u64)), 5_000_000_000_000);
        let mut ring = (0..RING_SIZE)
            .map(|i| {
                [
                    Point::from(Scalar::from(100 + i as u64) * G),
                    Commitment::new(MoneroScalar::from(Scalar::from(200 + i as u64)), 1000)
                        .commit(),
                ]
            })
            .collect::<Vec<_>>();
        ring[7] = [key, commitment.commit()];
        let decoys = monero_clsag::Decoys::new(vec![1; RING_SIZE], 7, ring).unwrap();
        let mut encoded = Zeroizing::new(key.compress().to_bytes().to_vec());
        MoneroScalar::from(Scalar::ZERO)
            .write(&mut *encoded)
            .unwrap();
        commitment.write(&mut *encoded).unwrap();
        decoys.write(&mut *encoded).unwrap();
        let input = OutputWithDecoys::read(&mut encoded.as_slice()).unwrap();
        let view = |spend: u64, secret: u64| {
            ViewPair::new(
                Point::from(Scalar::from(spend) * G),
                Zeroizing::new(MoneroScalar::from(Scalar::from(secret))),
            )
            .unwrap()
        };
        let link = [3; 64];
        let h: curve25519_dalek::edwards::EdwardsPoint =
            Point::biased_hash(key.compress().to_bytes()).into();
        let prepared = PreparedClaim::new(
            input,
            h * Scalar::from(3u64),
            ClaimTerms {
                recipient: view(4, 5).legacy_address(Network::Testnet),
                amount: 1_000_000_000_000,
                change: view(6, 7),
                fee_rate: FeeRate::new(1500, 10000).unwrap(),
                max_fee: 1_000_000_000_000,
            },
            Zeroizing::new([1; 32]),
            Sha256::digest(link).into(),
            &mut OsRng,
        )
        .unwrap();
        let bytes = prepared.to_recovery_bytes().unwrap();
        assert!(PreparedClaim::from_recovery_bytes(
            &bytes,
            Sha256::digest(&*bytes).into(),
            &mut OsRng
        )
        .is_err());
        let expected_message = prepared.context().message;
        drop(prepared);
        let job = Job {
            local_identity: [1; 32],
            capsule: [2; 32],
            link,
            received: 1000,
            latest: 1100,
            network: [9; 32],
            offset: Zeroizing::new(Scalar::ZERO),
            unsigned: bytes,
        };
        let root = std::env::temp_dir().join(format!("dxp1-refund-intent-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let identity = job.persist(&root);
        drop(job);
        let restored = Job::load(&root, identity).prepared();
        assert_eq!(restored.context().message, expected_message);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_job_rejects_substitution_and_deadline_renewal() {
        let root = std::env::temp_dir().join(format!("dxp1-refund-job-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let job = Job {
            local_identity: [1; 32],
            capsule: [2; 32],
            link: [3; 64],
            received: 1000,
            latest: 1100,
            network: [9; 32],
            offset: Zeroizing::new(Scalar::ONE),
            unsigned: Zeroizing::new(vec![7; 16]),
        };
        let identity = job.persist(&root);
        let restored = Job::load(&root, identity);
        assert_eq!(restored.received, 1000);
        assert_eq!(restored.latest, 1100);
        assert_eq!(restored.local_identity, job.local_identity);
        let before = read_private(&root.join("refund-recovery.job"));
        assert!(std::panic::catch_unwind(|| job.persist(&root)).is_err());
        for offset in [
            MAGIC.len(),
            MAGIC.len() + 32,
            MAGIC.len() + 64,
            MAGIC.len() + 128,
            MAGIC.len() + 136,
            MAGIC.len() + 144,
            before.len() - 1,
        ] {
            let mut changed = before.clone();
            changed[offset] ^= 1;
            fs::write(root.join("refund-recovery.job"), &*changed).unwrap();
            assert!(std::panic::catch_unwind(|| Job::load(&root, identity)).is_err());
        }
        // Deliberately approving a new digest still cannot silently renew the
        // original fixture's deadline relative to its recorded receipt.
        let mut changed = before.clone();
        let latest = MAGIC.len() + 128 + 8;
        changed[latest..latest + 8].copy_from_slice(&1101u64.to_le_bytes());
        fs::write(root.join("refund-recovery.job"), &*changed).unwrap();
        assert!(
            std::panic::catch_unwind(|| Job::load(&root, Sha256::digest(&*changed).into()))
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
