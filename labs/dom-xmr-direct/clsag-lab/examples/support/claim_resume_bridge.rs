//! Owned local worker experiment. Parent authenticates canonical inclusion;
//! workers validate the pinned claim artifacts and the supplied native bytes.
//! This is not daemon restart, chain authentication or a production transport.

use curve25519_dalek::scalar::Scalar;
use dom_consensus::{Transaction as DomTransaction, ValidationContext};
use dom_core::{BlockHeight, Timestamp};
use dom_scriptless_primitives::SecretScalar;
use dom_serialization::{DomDeserialize, DomSerialize};
use dxp1_clsag_lab::{
    claim_resume::{digest, MAX_RECORD_BYTES},
    native::XmrClaimEnvelope,
    native_dom::DomClaimOffer,
    time_bounds::{AssumedClaimDelays, AssumedXmrRecoveryWindow},
};
use monero_wallet::transaction::Transaction as XmrTransaction;
use rand_core::OsRng;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn write_new(path: &Path, bytes: &[u8]) {
    assert!(bytes.len() <= MAX_RECORD_BYTES);
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

fn read_bounded(path: &Path) -> Vec<u8> {
    let mut bytes = vec![];
    File::open(path)
        .unwrap()
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= MAX_RECORD_BYTES);
    bytes
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let result = std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap());
    assert_eq!(hex(&result), value);
    result
}

struct OwnedWorker(Child);
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct ResumeArtifacts {
    root: PathBuf,
    xmr_digest: [u8; 32],
    dom_digest: [u8; 32],
    manifest_digest: [u8; 32],
}

impl ResumeArtifacts {
    pub fn persist(
        root: &Path,
        xmr: &XmrClaimEnvelope,
        dom: &DomClaimOffer,
        operation: [u8; 32],
        window: &AssumedXmrRecoveryWindow,
        dom_first: bool,
        delays: AssumedClaimDelays,
    ) -> Self {
        let root = root.join("claim-resume");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        File::open(root.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        let xmr = xmr.to_resume_bytes().unwrap();
        let dom = dom.to_resume_bytes().unwrap();
        write_new(&root.join("xmr.record"), &xmr);
        write_new(&root.join("dom.record"), &dom);
        let mut manifest = b"DXP1/claim-manifest/v1\0".to_vec();
        manifest.extend(operation);
        manifest.extend(digest(&xmr));
        manifest.extend(digest(&dom));
        manifest.extend(window.capsule_binding());
        manifest.extend(window.disclosed_at().0.to_le_bytes());
        manifest.extend(window.earliest_adversarial().0.to_le_bytes());
        manifest.extend(window.latest_honest().0.to_le_bytes());
        manifest.push(u8::from(dom_first));
        manifest.extend(delays.xmr_resolution_secs.to_le_bytes());
        manifest.extend(delays.observation_secs.to_le_bytes());
        manifest.extend(delays.dom_resolution_secs.to_le_bytes());
        write_new(&root.join("manifest.record"), &manifest);
        Self {
            root,
            xmr_digest: digest(&xmr),
            dom_digest: digest(&dom),
            manifest_digest: digest(&manifest),
        }
    }

    pub fn load(&self) -> (XmrClaimEnvelope, DomClaimOffer) {
        assert_eq!(
            digest(&read_bounded(&self.root.join("manifest.record"))),
            self.manifest_digest
        );
        (
            XmrClaimEnvelope::from_resume_bytes(
                &read_bounded(&self.root.join("xmr.record")),
                self.xmr_digest,
                &mut OsRng,
            )
            .unwrap(),
            DomClaimOffer::from_resume_bytes(
                &read_bounded(&self.root.join("dom.record")),
                self.dom_digest,
            )
            .unwrap(),
        )
    }

    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Start one worker which dies after restoring the records, then a fresh
    /// worker which extracts from the already paid first leg and completes the
    /// counterpart. Neither worker receives a witness or any signing key.
    pub fn crash_then_complete(
        &self,
        dom_first: bool,
        observed: &[u8],
        context: &ValidationContext,
    ) -> (Vec<u8>, serde_json::Value) {
        let started = Instant::now();
        write_new(&self.root.join("observed.tx"), observed);
        let mut pids = vec![];
        for (action, expected) in [("crash", 73), ("complete", 0)] {
            let mut child = OwnedWorker(
                Command::new(std::env::current_exe().unwrap())
                    .arg("--claim-resume-worker")
                    .arg(&self.root)
                    .arg(action)
                    .arg(if dom_first { "dom-first" } else { "xmr-first" })
                    .arg(hex(&self.xmr_digest))
                    .arg(hex(&self.dom_digest))
                    .arg(hex(&self.manifest_digest))
                    .arg(hex(&context.chain_id))
                    .arg(context.current_height.0.to_string())
                    .arg(context.now.0.to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            pids.push(child.0.id());
            let began = Instant::now();
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    began.elapsed() < Duration::from_secs(10),
                    "owned resume worker exceeded 10 seconds"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(status.code(), Some(expected));
            if action == "crash" {
                assert!(!self.root.join("counterpart.tx").exists());
            }
        }
        let bytes = read_bounded(&self.root.join("counterpart.tx"));
        let evidence = serde_json::json!({
            "claim_worker_crash_exit":73,"claim_worker_restart_exit":0,"claim_worker_pids":pids,
            "claim_worker_seconds":started.elapsed().as_secs_f64(),
            "claim_records_synced_before_initial_claim":true,
            "worker_receives_original_witness":false,"worker_receives_signing_keys_or_nonces":false,
            "worker_chain_inclusion_verified_by_parent":true,"worker_queries_chain_independently":false,
            "xmr_resume_digest":hex(&self.xmr_digest),"dom_resume_digest":hex(&self.dom_digest),
            "full_executor_restart_exercised":false,
        });
        (bytes, evidence)
    }
}

pub fn worker(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let root = PathBuf::from(args.next().unwrap());
    let action = args.next().unwrap().into_string().unwrap();
    let order = args.next().unwrap().into_string().unwrap();
    assert!(matches!(action.as_str(), "crash" | "complete"));
    assert!(matches!(order.as_str(), "dom-first" | "xmr-first"));
    let xmr_digest = unhex(&args.next().unwrap().into_string().unwrap());
    let dom_digest = unhex(&args.next().unwrap().into_string().unwrap());
    let manifest_digest = unhex(&args.next().unwrap().into_string().unwrap());
    let context = ValidationContext {
        chain_id: unhex(&args.next().unwrap().into_string().unwrap()),
        current_height: BlockHeight(args.next().unwrap().into_string().unwrap().parse().unwrap()),
        now: Timestamp(args.next().unwrap().into_string().unwrap().parse().unwrap()),
    };
    assert!(args.next().is_none());
    let artifacts = ResumeArtifacts {
        root,
        xmr_digest,
        dom_digest,
        manifest_digest,
    };
    let (xmr, dom) = artifacts.load();
    if action == "crash" {
        std::process::exit(73);
    }
    let observed = read_bounded(&artifacts.root.join("observed.tx"));
    let counterpart = if order == "dom-first" {
        let tx = DomTransaction::from_bytes(&observed).unwrap();
        assert_eq!(tx.to_bytes().unwrap(), observed);
        let mut bytes = dom.extract(&tx, &context).unwrap();
        bytes.reverse();
        let witness =
            Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).unwrap());
        xmr.complete(&witness, &mut OsRng).unwrap().serialize()
    } else {
        let mut input = observed.as_slice();
        let tx = XmrTransaction::read(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(tx.serialize(), observed);
        let mut bytes = Zeroizing::new(xmr.extract(&tx, &mut OsRng).unwrap().to_bytes());
        bytes.reverse();
        dom.complete(&SecretScalar::from_be_bytes(*bytes).unwrap(), &context)
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    write_new(&artifacts.root.join("counterpart.tx"), &counterpart);
}
