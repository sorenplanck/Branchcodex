//! A loopback delivery bridge deliberately withholds its acknowledgment AFTER
//! native admission. The sending worker exits on EOF; a reopened journal must
//! reconcile. The parent still owns/authenticates the nodes and operation.
use dxp1_clsag_lab::{
    claim_resume::{digest, MAX_RECORD_BYTES},
    counterpart_delivery::{CounterpartDelivery, DeliveryAction, DeliveryBinding, Observation},
};
use rand_core::{OsRng, RngCore};
use std::{
    future::Future,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let b = std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap());
    assert_eq!(hex(&b), s);
    b
}
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct PendingDelivery {
    path: PathBuf,
    binding: DeliveryBinding,
    digest: [u8; 32],
    pub evidence: serde_json::Value,
}
impl PendingDelivery {
    /// Test-only tracking: verifies the result of an independent native sender.
    /// This helper does not create an obligation, submit bytes or authorize it.
    pub fn track_native_sender(
        root: &Path,
        binding: DeliveryBinding,
        payload: &[u8],
        evidence: serde_json::Value,
    ) -> Self {
        let path = root.join("counterpart-delivery.wal");
        let journal = CounterpartDelivery::open(&path, binding).unwrap();
        assert_eq!(journal.payload(), payload);
        assert!(journal.possibly_exposed().unwrap());
        drop(journal);
        Self {
            path,
            binding,
            digest: digest(payload),
            evidence,
        }
    }
    pub fn reconcile(&self, observation: Observation, expected: DeliveryAction) {
        let journal = CounterpartDelivery::open(&self.path, self.binding).unwrap();
        assert!(journal.possibly_exposed().unwrap());
        assert_eq!(
            journal
                .reconcile(self.binding.target_chain, self.digest, observation)
                .unwrap(),
            expected
        );
        // A query failure after any observation cannot reuse that observation.
        assert_eq!(
            journal
                .reconcile(self.binding.target_chain, self.digest, Observation::Unknown)
                .unwrap(),
            DeliveryAction::Reconcile
        );
    }
}

/// Caller checked exact absence and unspentness at the owned node immediately
/// before this call. The callback must admit exactly `payload`, already verified.
pub async fn send_without_reply<F: Future<Output = ()>>(
    root: &Path,
    binding: DeliveryBinding,
    payload: &[u8],
    send: impl FnOnce() -> F,
) -> PendingDelivery {
    let started = Instant::now();
    let path = root.join("counterpart-delivery.wal");
    // The fresh recovery worker, not this host/sender, created the obligation
    // after independently verifying the original first payment.
    let prepared = CounterpartDelivery::open(&path, binding).unwrap();
    assert_eq!(prepared.payload(), payload);
    assert!(!prepared.possibly_exposed().unwrap());
    drop(prepared);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut token = [0; 32];
    OsRng.fill_bytes(&mut token);
    let mut worker = Owned(
        Command::new(std::env::current_exe().unwrap())
            .arg("--counterpart-delivery-worker")
            .arg(&path)
            .arg(hex(&binding.manifest))
            .arg(hex(&binding.first_claim))
            .arg(hex(&binding.first_block))
            .arg(binding.first_height.to_string())
            .arg(hex(&binding.target_chain))
            .arg(listener.local_addr().unwrap().port().to_string())
            .arg(hex(&token))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let pid = worker.0.id();
    let mut socket = loop {
        match listener.accept() {
            Ok((s, addr)) => {
                assert!(addr.ip().is_loopback());
                break s;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(started.elapsed() < Duration::from_secs(10));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => panic!("owned delivery listener: {e}"),
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut incoming_token = [0; 32];
    socket.read_exact(&mut incoming_token).unwrap();
    assert_eq!(incoming_token, token);
    let mut length = [0; 4];
    socket.read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!(length <= MAX_RECORD_BYTES);
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, payload);
    send().await;
    // No application acknowledgment is delivered to the submitting worker.
    socket.shutdown(Shutdown::Both).unwrap();
    drop(socket);
    let status = loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < Duration::from_secs(15));
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(status.code(), Some(74));
    let delivery = PendingDelivery {
        path,
        binding,
        digest: digest(payload),
        evidence: serde_json::json!({
            "counterpart_ack_deliberately_withheld_after_native_admission":true,
            "counterpart_sender_exit":74,"counterpart_sender_pid":pid,
            "counterpart_delivery_seconds":started.elapsed().as_secs_f64(),
            "counterpart_bytes_fsynced_before_send":true,"counterpart_exposure_fsynced_before_send":true,
        "counterpart_signature_recreated_after_send":false,"counterpart_pending_retry_dispatched":false,
            "full_coordinator_restart_exercised":false,
        }),
    };
    delivery.reconcile(Observation::Unknown, DeliveryAction::Reconcile);
    delivery
}

pub fn worker(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let path = PathBuf::from(args.next().unwrap());
    let binding = DeliveryBinding {
        manifest: unhex(&args.next().unwrap().into_string().unwrap()),
        first_claim: unhex(&args.next().unwrap().into_string().unwrap()),
        first_block: unhex(&args.next().unwrap().into_string().unwrap()),
        first_height: args.next().unwrap().into_string().unwrap().parse().unwrap(),
        target_chain: unhex(&args.next().unwrap().into_string().unwrap()),
    };
    let port: u16 = args.next().unwrap().into_string().unwrap().parse().unwrap();
    let token = unhex(&args.next().unwrap().into_string().unwrap());
    assert!(args.next().is_none());
    let mut journal = CounterpartDelivery::open(&path, binding).unwrap();
    let hash = journal.payload_digest();
    // The trusted bridge's parent supplied the coherent native pre-send check.
    let bytes = journal
        .prepare_attempt(binding.target_chain, hash, Observation::AbsentAndUnspent)
        .unwrap();
    let mut socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket.write_all(&token).unwrap();
    socket
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .unwrap();
    socket.write_all(bytes).unwrap();
    let mut ack = [0; 1];
    assert_eq!(
        socket.read(&mut ack).unwrap(),
        0,
        "lost-ack fixture unexpectedly acknowledged"
    );
    std::process::exit(74);
}
