//! Local IPC experiment, not an authenticated transport or funding policy.
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use dxp1_clsag_lab::capsule_checkpoint::CapsuleCheckpoint;
use dxp1_clsag_lab::xmr_recovery::XmrDirectRecoveryMaterial;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

struct LabProcess(Child);
impl Drop for LabProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(binary: &Path, mode: &str) -> (LabProcess, ChildStdin, BufReader<ChildStdout>) {
    assert!(binary.is_absolute() && binary.is_file());
    let mut child = Command::new(binary)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let writer = child.stdin.take().unwrap();
    let reader = BufReader::new(child.stdout.take().unwrap());
    (LabProcess(child), writer, reader)
}

fn frame(reader: &mut impl BufRead) -> Value {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(2 * 1024 * 1024 + 1)
        .read_until(b'\n', &mut bytes)
        .unwrap();
    assert!(bytes.len() <= 2 * 1024 * 1024 && bytes.last() == Some(&b'\n'));
    serde_json::from_slice(&bytes).unwrap()
}

fn send(writer: &mut impl Write, message: &Value) {
    serde_json::to_writer(&mut *writer, message).unwrap();
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn seconds(frame: &Value, field: &str) -> f64 {
    let value = frame[field].as_f64().unwrap();
    assert!(value.is_finite() && value >= 0.0);
    value
}

pub struct DirectPublicCapsule {
    binding: [u8; 32],
    expected_context: [u8; 32],
    expected_public: EdwardsPoint,
    process: LabProcess,
    writer: ChildStdin,
    reader: BufReader<ChildStdout>,
    received_at: Instant,
    received_unix_seconds: u64,
    setup_seconds: f64,
    generation_seconds: f64,
    verification_seconds: f64,
    squarings: u64,
    payload: String,
    setup: String,
    restoration_report: Value,
}

impl DirectPublicCapsule {
    pub fn prepare(binary: &Path, material: XmrDirectRecoveryMaterial) -> Self {
        Self::prepare_with_work(binary, material, 200_000)
    }

    pub fn prepare_with_work(
        binary: &Path,
        material: XmrDirectRecoveryMaterial,
        squarings: u64,
    ) -> Self {
        assert!(
            matches!(squarings, 200_000 | 10_000_000),
            "unsupported lab profile"
        );
        let expected_context = material.context;
        let expected_public = material.public_key;
        assert_eq!(*material.secret * G, expected_public);
        let (mut producer, mut writer, mut reader) = spawn(binary, "direct-produce");
        let request = Zeroizing::new(
            serde_json::to_vec(&json!({
                "secret":material.secret.to_bytes(), "context":expected_context,
                "squarings":squarings,
            }))
            .unwrap(),
        );
        writer.write_all(&request).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
        drop(request);
        drop(material);
        let announced = frame(&mut reader);
        assert_eq!(announced["result"], "setup");
        assert_eq!(announced["squarings"], squarings);
        assert_eq!(announced["context"], json!(expected_context));
        assert_eq!(
            announced["public"],
            json!(expected_public.compress().to_bytes())
        );
        let setup = announced["setup"].as_str().unwrap();
        let setup_binding = hex(&Sha256::digest(setup.as_bytes()));
        let (process, mut public_writer, mut public_reader) = spawn(binary, "direct-prepare");
        send(
            &mut public_writer,
            &json!({
                "setup":setup, "context":expected_context, "public":expected_public.compress().to_bytes(),
                "squarings":squarings,
            }),
        );
        let setup_ready = frame(&mut public_reader);
        assert_eq!(setup_ready["result"], "setup_ready");
        assert_eq!(setup_ready["setup_binding"], setup_binding);
        assert_eq!(setup_ready["setup_verifications"], 1);
        assert_eq!(setup_ready["squarings"], squarings);
        let setup_seconds = seconds(&setup_ready, "setup_verification_seconds");
        send(&mut writer, &json!({"accepted_setup":setup_binding}));
        drop(writer);
        let offered = frame(&mut reader);
        let received_at = Instant::now();
        let received_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(offered["result"], "offer");
        let payload = offered["payload"].as_str().unwrap();
        let binding: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
        assert_eq!(offered["offer_binding"], hex(&binding));
        let generation_seconds = seconds(&offered, "proof_generation_seconds");
        assert!(producer.0.wait().unwrap().success());
        drop(producer);
        // The public process has received no private scalar or producer nonce.
        send(&mut public_writer, &json!({"payload":payload}));
        let ready = frame(&mut public_reader);
        assert_eq!(ready["result"], "ready");
        assert_eq!(ready["offer_binding"], hex(&binding));
        assert_eq!(ready["context"], json!(expected_context));
        assert_eq!(
            ready["public"],
            json!(expected_public.compress().to_bytes())
        );
        assert_eq!(ready["setup_verified_before_offer"], true);
        assert_eq!(ready["public_verifier_no_share_secret"], true);
        assert_eq!(ready["squarings"], squarings);
        let verification_seconds = seconds(&ready, "proof_verification_seconds");
        Self {
            binding,
            expected_context,
            expected_public,
            process,
            writer: public_writer,
            reader: public_reader,
            received_at,
            received_unix_seconds,
            setup_seconds,
            generation_seconds,
            verification_seconds,
            squarings,
            payload: payload.to_owned(),
            setup: setup.to_owned(),
            restoration_report: json!({}),
        }
    }

    /// Call after verification and BEFORE either shared reserve is funded.
    #[allow(dead_code)]
    pub fn persist(&self, path: &Path) {
        CapsuleCheckpoint {
            context: self.expected_context,
            public: self.expected_public.compress().to_bytes(),
            binding: self.binding,
            received_unix_seconds: self.received_unix_seconds,
            squarings: self.squarings,
            preparation_seconds: [
                self.setup_seconds,
                self.generation_seconds,
                self.verification_seconds,
            ],
            payload: self.payload.clone(),
            setup: self.setup.clone(),
        }
        .write_new(path)
        .unwrap();
    }

    /// Abruptly terminate ONLY this verifier. This does not restart the Rust
    /// supervisor, native nodes, roster or signing material.
    #[allow(dead_code)]
    pub fn kill_for_restart(mut self) -> Value {
        use std::os::unix::process::ExitStatusExt;
        let pid = self.process.0.id();
        self.process.0.kill().unwrap();
        let status = self.process.0.wait().unwrap();
        assert_eq!(status.signal(), Some(9));
        json!({"old_public_solver_pid":pid,"old_public_solver_signal":9})
    }

    /// Rebuild from the immutable record and approved link binding. Repeats
    /// all setup/proof checks; no trusted "already verified" shortcut.
    #[allow(dead_code)]
    pub fn restore(binary: &Path, path: &Path, expected_binding: [u8; 32]) -> Self {
        let began = Instant::now();
        let saved = CapsuleCheckpoint::read(path, expected_binding).unwrap();
        let setup = &saved.setup;
        let (process, mut writer, mut reader) = spawn(binary, "direct-prepare");
        let pid = process.0.id();
        send(
            &mut writer,
            &json!({"setup":setup,"context":saved.context,
            "public":saved.public,"squarings":saved.squarings}),
        );
        let prepared = frame(&mut reader);
        assert_eq!(prepared["result"], "setup_ready");
        assert_eq!(
            prepared["setup_binding"],
            hex(&Sha256::digest(setup.as_bytes()))
        );
        assert_eq!(prepared["squarings"], saved.squarings);
        assert_eq!(prepared["setup_verifications"], 1);
        send(&mut writer, &json!({"payload":saved.payload}));
        let ready = frame(&mut reader);
        assert_eq!(ready["result"], "ready");
        assert_eq!(ready["offer_binding"], hex(&saved.binding));
        assert_eq!(ready["context"], json!(saved.context));
        assert_eq!(ready["public"], json!(saved.public));
        assert_eq!(ready["squarings"], saved.squarings);
        assert_eq!(ready["public_verifier_no_share_secret"], true);
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .checked_sub(Duration::from_secs(saved.received_unix_seconds))
            .expect("clock predates original capsule receipt");
        let received_at = Instant::now().checked_sub(elapsed).unwrap();
        let restoration_report = json!({
            "public_solver_restored_from_record":true,"restored_public_solver_pid":pid,
            "restoration_seconds":began.elapsed().as_secs_f64(),
            "restoration_setup_verification_seconds":seconds(&prepared,"setup_verification_seconds"),
            "restoration_proof_verification_seconds":seconds(&ready,"proof_verification_seconds"),
            "original_receipt_preserved":true,"restoration_repeats_full_public_verification":true,
            "restored_elapsed_uses_original_floor_second":true,"new_producer_or_proof_generation":false,
            "full_coordinator_restarted":false,
        });
        Self {
            binding: saved.binding,
            expected_context: saved.context,
            expected_public: curve25519_dalek::edwards::CompressedEdwardsY(saved.public)
                .decompress()
                .unwrap(),
            process,
            writer,
            reader,
            received_at,
            received_unix_seconds: saved.received_unix_seconds,
            setup_seconds: saved.preparation_seconds[0],
            generation_seconds: saved.preparation_seconds[1],
            verification_seconds: saved.preparation_seconds[2],
            squarings: saved.squarings,
            payload: saved.payload,
            setup: saved.setup,
            restoration_report,
        }
    }

    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub fn context(&self) -> [u8; 32] {
        self.expected_context
    }

    pub fn public_key(&self) -> EdwardsPoint {
        self.expected_public
    }

    // Local complete-frame receipt only. This is NOT authenticated first
    // disclosure and cannot establish a production adversarial deadline.
    #[allow(dead_code)] // This support module is also built by the opening-only example.
    pub fn received_unix_seconds(&self) -> u64 {
        self.received_unix_seconds
    }

    #[allow(dead_code)]
    pub fn preparation_report(&self) -> Value {
        let mut report = json!({
            "setup_verification_seconds":self.setup_seconds,
            "proof_generation_seconds":self.generation_seconds,
            "proof_verification_seconds":self.verification_seconds,
            "squarings":self.squarings,
            "offer_received_unix_seconds":self.received_unix_seconds,
            "offer_received_elapsed_seconds":self.received_at.elapsed().as_secs_f64(),
            "setup_verified_before_offer":true,"producer_exited_before_opening":true,
            "public_verifier_no_share_secret":true,"exact_capsule_binding_checked":true,
        });
        report
            .as_object_mut()
            .unwrap()
            .extend(self.restoration_report.as_object().unwrap().clone());
        report
    }

    #[allow(dead_code)]
    pub fn cancel(self) -> Value {
        let mut report = self.preparation_report();
        let Self {
            binding,
            mut process,
            writer,
            mut reader,
            ..
        } = self;
        drop(writer);
        let closed = frame(&mut reader);
        assert_eq!(closed["result"], "closed");
        assert_eq!(closed["completed"], 0);
        assert_eq!(closed["offer_binding"], hex(&binding));
        assert!(process.0.wait().unwrap().success());
        report["openings"] = json!(0);
        report["public_solver_cancelled_without_opening"] = json!(true);
        report
    }

    pub fn open(self) -> (Zeroizing<Scalar>, Value) {
        let Self {
            binding,
            expected_context: _,
            expected_public,
            mut process,
            mut writer,
            mut reader,
            received_at,
            received_unix_seconds,
            setup_seconds,
            generation_seconds,
            verification_seconds,
            squarings,
            payload: _,
            setup: _,
            restoration_report,
        } = self;
        let elapsed_since_offer = received_at.elapsed().as_secs_f64();
        let started = Instant::now();
        send(
            &mut writer,
            &json!({"action":"open", "offer_binding":hex(&binding)}),
        );
        drop(writer);
        let opened = frame(&mut reader);
        assert_eq!(opened["result"], "opened");
        assert_eq!(opened["offer_binding"], hex(&binding));
        let bytes =
            Zeroizing::new(serde_json::from_value::<[u8; 32]>(opened["scalar"].clone()).unwrap());
        let scalar =
            Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).unwrap());
        assert_eq!(*scalar * G, expected_public);
        let solve_seconds = seconds(&opened, "solve_seconds");
        let closed = frame(&mut reader);
        assert_eq!(closed["result"], "closed");
        assert_eq!(closed["completed"], 1);
        assert_eq!(closed["offer_binding"], hex(&binding));
        assert!(process.0.wait().unwrap().success());
        let mut report = json!({
            "setup_verification_seconds":setup_seconds, "proof_generation_seconds":generation_seconds,
            "proof_verification_seconds":verification_seconds, "opening_seconds":solve_seconds,
            "opening_session_seconds":started.elapsed().as_secs_f64(),
            "offer_received_to_open_start_seconds":elapsed_since_offer,
            "offer_received_unix_seconds":received_unix_seconds,
            "setup_verified_before_offer":true, "producer_exited_before_opening":true,
            "public_verifier_no_share_secret":true, "exact_capsule_binding_checked":true,
            "rust_ed25519_point_checked":true, "openings":1,
            "squarings":squarings,
        });
        report
            .as_object_mut()
            .unwrap()
            .extend(restoration_report.as_object().unwrap().clone());
        (scalar, report)
    }
}
