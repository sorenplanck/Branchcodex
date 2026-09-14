//! Authenticated bounded blocking Unix-domain sidecar client.
//!
//! The socket path carries the route's spend and view scalars, so the peer
//! must prove itself before any request leaves this process. Three fences,
//! all fail-closed, guard the channel:
//!
//! 1. the socket path must be absolute and outside every world-writable
//!    standard directory, so an unprivileged squatter cannot pre-bind it;
//! 2. the connected peer must run under this process's own effective uid,
//!    checked through `SO_PEERCRED` before a single byte is written;
//! 3. the sidecar must answer a fresh challenge nonce with an HMAC proof of
//!    the shared key, in its own domain, before the request — and with it
//!    the scalars — is transmitted.

#![forbid(unsafe_code)]

mod build_proof_v23;
mod input_proof_v23;
#[cfg(all(test, unix))]
mod local_load_deadline_v24_tests;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rand::RngCore as _;
use xmr_live_sidecar_api::{
    BuildSweepRequestV2, BuildSweepResponseV2, SidecarHelloProofV1, SidecarHelloV1,
    SidecarRequestV2, SidecarResponseV2, VerifyFundingRequestV2, VerifyFundingResponseV2,
    API_VERSION_V2, MAX_FRAME_BYTES,
};
use xmr_sidecar_auth::SidecarAuthKey;
use xmr_spend_port::{FundingVerifyPort, SpendPortError, SweepBuildPort};
use zeroize::Zeroizing;

/// Standard world-writable roots a secret-carrying socket must never live in.
const WORLD_WRITABLE_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
/// The hello proof is one small JSON object; anything larger is an impostor.
const MAX_HELLO_PROOF_BYTES: usize = 1024;
/// Error codes are diagnostic labels, never free-form log content.
const MAX_SIDECAR_ERROR_CODE_BYTES: usize = 128;

/// Preferred Linux sidecar transport.
pub struct BlockingUdsSidecarPort {
    socket_path: PathBuf,
    timeout: Duration,
    auth_key: SidecarAuthKey,
}

impl core::fmt::Debug for BlockingUdsSidecarPort {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BlockingUdsSidecarPort")
            .field("socket_path", &self.socket_path)
            .field("timeout", &self.timeout)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl BlockingUdsSidecarPort {
    /// Constructs a finite-timeout client over a permissioned socket path.
    ///
    /// The path must be absolute and outside `/tmp`, `/var/tmp` and
    /// `/dev/shm`: a socket in a world-writable directory can be pre-bound
    /// by any local process, and this client's first application frame
    /// carries key material.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        auth_key: SidecarAuthKey,
    ) -> Result<Self, SpendPortError> {
        Self::with_timeout(socket_path, auth_key, Duration::from_secs(180))
    }

    /// Uses one absolute I/O budget for connect, authentication and response.
    /// An unresponsive or trickling peer cannot restart this budget per byte.
    pub fn with_timeout(
        socket_path: impl Into<PathBuf>,
        auth_key: SidecarAuthKey,
        timeout: Duration,
    ) -> Result<Self, SpendPortError> {
        let socket_path = socket_path.into();
        if socket_path.as_os_str().is_empty()
            || !socket_path.is_absolute()
            || path_in_world_writable_root(&socket_path)
            || timeout.is_zero()
            || timeout > Duration::from_secs(180)
        {
            return Err(SpendPortError::Rejected);
        }
        Ok(Self {
            socket_path,
            timeout,
            auth_key,
        })
    }

    /// Socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(unix)]
    fn call(&self, request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(SpendPortError::Rejected)?;
        self.call_until_v24(request, deadline)
    }

    #[cfg(unix)]
    fn call_until_v24(
        &self,
        request: &SidecarRequestV2,
        deadline: Instant,
    ) -> Result<SidecarResponseV2, SpendPortError> {
        remaining(deadline)?;
        // The serialized request contains private scalars as well as its tag.
        let bytes =
            Zeroizing::new(serde_json::to_vec(request).map_err(|_| SpendPortError::Rejected)?);
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(SpendPortError::Rejected);
        }
        let mut stream = connect_bounded(&self.socket_path, deadline)?;
        remaining(deadline)?;
        require_same_uid_peer(&stream)?;
        remaining(deadline)?;
        self.handshake(&mut stream, deadline)?;
        write_frame(&mut stream, &bytes, deadline)?;
        let response = read_frame(&mut stream, MAX_FRAME_BYTES, deadline)?;
        let decoded = serde_json::from_slice(&response).map_err(|_| SpendPortError::Rejected)?;
        remaining(deadline)?;
        Ok(decoded)
    }

    /// Refuses to transmit anything but a fresh nonce until the peer proves
    /// possession of the shared HMAC key over exactly that nonce.
    #[cfg(unix)]
    fn handshake(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        deadline: Instant,
    ) -> Result<(), SpendPortError> {
        remaining(deadline)?;
        let mut challenge_nonce = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut challenge_nonce)
            .map_err(|_| SpendPortError::Retryable)?;
        let hello = SidecarHelloV1 {
            api_version: API_VERSION_V2,
            challenge_nonce,
        };
        hello.validate().map_err(|_| SpendPortError::Retryable)?;
        let hello_bytes = serde_json::to_vec(&hello).map_err(|_| SpendPortError::Rejected)?;
        write_frame(stream, &hello_bytes, deadline)?;
        let proof_bytes = read_frame(stream, MAX_HELLO_PROOF_BYTES, deadline)?;
        let proof: SidecarHelloProofV1 =
            serde_json::from_slice(&proof_bytes).map_err(|_| SpendPortError::Rejected)?;
        proof.validate().map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .verify_challenge_proof(&challenge_nonce, &proof.proof)
            .map_err(|_| SpendPortError::Rejected)?;
        remaining(deadline)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn call(&self, _request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        Err(SpendPortError::Rejected)
    }

    #[cfg(not(unix))]
    fn call_until_v24(
        &self,
        _request: &SidecarRequestV2,
        _deadline: Instant,
    ) -> Result<SidecarResponseV2, SpendPortError> {
        Err(SpendPortError::Rejected)
    }

    fn classify_error(error: xmr_live_sidecar_api::SidecarErrorBody) -> SpendPortError {
        // Preserve the stable, non-secret sidecar code at the process boundary.
        // SpendPortError intentionally remains the coarse retry/reject contract
        // consumed by the state machine, but operators must not lose the stage
        // that produced that classification.
        //
        // `retryable` is the only authority on that classification. The code is
        // a diagnostic label: it is sanitized for logging and never consulted
        // for the outcome. Rejecting on a malformed label would turn a backend
        // outage the sidecar declared retryable into a permanent refusal, which
        // downstream reads as a retained-state conflict on a settlement child
        // rather than "try again" — a settlement decision taken on the shape of
        // a string.
        //
        // The warning below needs an installed tracing subscriber to appear;
        // the daemon does not install one today, so the durable record of the
        // stage is the code the sidecar returns, not this line.
        let safe_code = sanitized_error_code(&error.code);
        tracing::warn!(
            sidecar_code = %safe_code,
            retryable = error.retryable,
            "XMR sidecar request failed"
        );
        if error.retryable {
            SpendPortError::Retryable
        } else {
            SpendPortError::Rejected
        }
    }
}

/// Renders a sidecar error code safe to place in a log line.
///
/// The sidecar's own codes are already fixed `[a-z0-9_]` labels, so this is a
/// boundary guard, not a translation: a code that is empty, over-long, or
/// carries anything else — a newline that would forge a second log line, say —
/// is truncated and folded to underscores instead of being trusted verbatim.
/// It never inspects meaning and never influences the retry classification.
fn sanitized_error_code(code: &str) -> String {
    if code.is_empty() {
        return "absent".to_owned();
    }
    code.bytes()
        .take(MAX_SIDECAR_ERROR_CODE_BYTES)
        .map(|byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' {
                char::from(byte)
            } else {
                '_'
            }
        })
        .collect()
}

fn path_in_world_writable_root(path: &Path) -> bool {
    WORLD_WRITABLE_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
}

#[cfg(unix)]
fn connect_bounded(
    path: &Path,
    deadline: Instant,
) -> Result<std::os::unix::net::UnixStream, SpendPortError> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    remaining(deadline)?;
    let address = UnixAddr::new(path).map_err(|_| SpendPortError::Rejected)?;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|_| SpendPortError::Retryable)?;
    // A full Unix listen backlog reports EAGAIN. Close and retry the entire
    // authenticated call later; never block on connect or send before success.
    remaining(deadline)?;
    connect(fd.as_raw_fd(), &address).map_err(|_| SpendPortError::Retryable)?;
    remaining(deadline)?;
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|_| SpendPortError::Retryable)?;
    Ok(stream)
}

fn remaining(deadline: Instant) -> Result<Duration, SpendPortError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(SpendPortError::Retryable)
}

#[cfg(unix)]
fn write_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), SpendPortError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| SpendPortError::Retryable)?;
        match stream.write(bytes) {
            Ok(0) => return Err(SpendPortError::Retryable),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SpendPortError::Retryable),
        }
    }
    remaining(deadline)?;
    Ok(())
}

#[cfg(unix)]
fn read_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), SpendPortError> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| SpendPortError::Retryable)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(SpendPortError::Retryable),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SpendPortError::Retryable),
        }
    }
    remaining(deadline)?;
    Ok(())
}

/// Requires the connected peer to run as this process's own effective uid.
///
/// Kernel-attested through `SO_PEERCRED`, so a proxying impostor cannot
/// forward its way around it: the credential is of the process actually
/// holding the other end of this exact socket.
#[cfg(unix)]
fn require_same_uid_peer(stream: &std::os::unix::net::UnixStream) -> Result<(), SpendPortError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|_| SpendPortError::Rejected)?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err(SpendPortError::Rejected);
    }
    Ok(())
}

#[cfg(unix)]
fn write_frame(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), SpendPortError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(SpendPortError::Rejected);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| SpendPortError::Rejected)?;
    write_deadline(stream, &length.to_be_bytes(), deadline)?;
    write_deadline(stream, bytes, deadline)?;
    Ok(())
}

#[cfg(unix)]
fn read_frame(
    stream: &mut std::os::unix::net::UnixStream,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, SpendPortError> {
    let mut prefix = [0_u8; 4];
    read_deadline(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > max_bytes {
        return Err(SpendPortError::Rejected);
    }
    let mut frame = vec![0_u8; length];
    read_deadline(stream, &mut frame, deadline)?;
    Ok(frame)
}

impl FundingVerifyPort for BlockingUdsSidecarPort {
    fn verify_funding(
        &mut self,
        mut request: VerifyFundingRequestV2,
    ) -> Result<VerifyFundingResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_funding(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let envelope = SidecarRequestV2::VerifyFunding(request);
        match (&envelope, self.call(&envelope)?) {
            (SidecarRequestV2::VerifyFunding(expected), SidecarResponseV2::Funding(response)) => {
                response
                    .validate_for(expected)
                    .map_err(|_| SpendPortError::Rejected)?;
                Ok(response)
            }
            (_, SidecarResponseV2::Error(error)) => Err(Self::classify_error(error)),
            _ => Err(SpendPortError::Rejected),
        }
    }
}

impl SweepBuildPort for BlockingUdsSidecarPort {
    fn build_sweep(
        &mut self,
        mut request: BuildSweepRequestV2,
    ) -> Result<BuildSweepResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_build(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let nonce = request.request_nonce;
        match self.call(&SidecarRequestV2::BuildSweep(request))? {
            SidecarResponseV2::Sweep(response) => {
                response
                    .validate_for(&nonce)
                    .map_err(|_| SpendPortError::Rejected)?;
                Ok(response)
            }
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            SidecarResponseV2::Funding(_)
            | SidecarResponseV2::InputProofV23(_)
            | SidecarResponseV2::LocalRefundWithProofsV24(_)
            | SidecarResponseV2::SweepWithProofsV23(_) => Err(SpendPortError::Rejected),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    use xmr_live_sidecar_api::SecretScalarBytes;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The client refuses sockets under `/tmp`, where `tempdir()` would put
    /// them, and `connect(2)` bounds the whole path by `SUN_LEN` (~108
    /// bytes), so the scratch directory is the first short-enough private
    /// base: the runtime dir, the crate dir, or the home directory.
    pub(super) fn socket_scratch_dir() -> tempfile::TempDir {
        let candidates = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
            std::env::var_os("HOME").map(PathBuf::from),
        ];
        let base = candidates
            .into_iter()
            .flatten()
            .find(|base| {
                base.is_absolute()
                    && !path_in_world_writable_root(base)
                    && base.exists()
                    && base.as_os_str().len() < 70
            })
            .expect("no short private base directory for a test Unix socket");
        tempfile::tempdir_in(base).expect("scratch dir")
    }

    const KEY: [u8; 32] = [7; 32];
    const WRONG_KEY: [u8; 32] = [9; 32];

    fn funding_request() -> VerifyFundingRequestV2 {
        VerifyFundingRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce: [1; 32],
            settlement_id: [2; 32],
            funding_tx_hash: [3; 32],
            expected_amount_piconero: 1_000,
            expected_spend_public_key: [4; 32],
            view_scalar: SecretScalarBytes::new([5; 32]),
            auth_tag: [0; 32],
        }
    }

    pub(super) fn read_test_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut frame)?;
        Ok(frame)
    }

    pub(super) fn write_test_frame(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
        let length = u32::try_from(bytes.len()).expect("frame length");
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(bytes)?;
        stream.flush()
    }

    /// Serves one connection: answers the hello with a proof under
    /// `proof_key`, then reports whether any request bytes followed.
    fn one_shot_sidecar(
        listener: UnixListener,
        proof_key: [u8; 32],
    ) -> std::thread::JoinHandle<(bool, Option<SidecarRequestV2>)> {
        one_shot_sidecar_response(listener, proof_key, valid_funding_response())
    }

    fn valid_funding_response() -> SidecarResponseV2 {
        SidecarResponseV2::Funding(VerifyFundingResponseV2 {
            api_version: API_VERSION_V2,
            request_nonce: [1; 32],
            funding_tx_hash: [3; 32],
            event_index: 0,
            received_amount_piconero: 1_000,
            spendable: true,
        })
    }

    fn one_shot_sidecar_response(
        listener: UnixListener,
        proof_key: [u8; 32],
        response: SidecarResponseV2,
    ) -> std::thread::JoinHandle<(bool, Option<SidecarRequestV2>)> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let hello_bytes = read_test_frame(&mut stream).expect("read hello");
            let hello: SidecarHelloV1 = serde_json::from_slice(&hello_bytes).expect("decode hello");
            hello.validate().expect("valid hello");
            let proof_source = SidecarAuthKey::new(proof_key).expect("key");
            let proof = SidecarHelloProofV1 {
                api_version: API_VERSION_V2,
                proof: proof_source
                    .challenge_proof(&hello.challenge_nonce)
                    .expect("proof"),
            };
            write_test_frame(
                &mut stream,
                &serde_json::to_vec(&proof).expect("encode proof"),
            )
            .expect("write proof");
            match read_test_frame(&mut stream) {
                Ok(frame) => {
                    let request =
                        serde_json::from_slice::<SidecarRequestV2>(&frame).expect("request");
                    let _ = write_test_frame(
                        &mut stream,
                        &serde_json::to_vec(&response).expect("encode response"),
                    );
                    (true, Some(request))
                }
                Err(_) => (false, None),
            }
        })
    }

    #[test]
    fn honest_sidecar_completes_handshake_then_serves_the_request() -> TestResult {
        let directory = socket_scratch_dir();
        let socket_path = directory.path().join("sidecar.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let served = one_shot_sidecar(listener, KEY);
        let mut port =
            BlockingUdsSidecarPort::new(&socket_path, SidecarAuthKey::new(KEY).unwrap())?;
        let response = port.verify_funding(funding_request());
        assert!(response.is_ok(), "honest sidecar must serve: {response:?}");
        let (request_seen, request) = served.join().expect("sidecar thread");
        assert!(request_seen);
        assert!(matches!(request, Some(SidecarRequestV2::VerifyFunding(_))));
        Ok(())
    }

    #[test]
    fn impostor_with_wrong_key_never_receives_the_request() -> TestResult {
        let directory = socket_scratch_dir();
        let socket_path = directory.path().join("impostor.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let served = one_shot_sidecar(listener, WRONG_KEY);
        let mut port =
            BlockingUdsSidecarPort::new(&socket_path, SidecarAuthKey::new(KEY).unwrap())?;
        let response = port.verify_funding(funding_request());
        assert!(matches!(response, Err(SpendPortError::Rejected)));
        // The class being closed: the impostor answered the hello but must
        // observe the connection die with no request — and no scalar — ever
        // transmitted.
        let (request_seen, request) = served.join().expect("sidecar thread");
        assert!(!request_seen, "no request frame may reach an unproven peer");
        assert!(request.is_none());
        Ok(())
    }

    #[test]
    fn world_writable_and_relative_socket_paths_are_refused() {
        let auth = || SidecarAuthKey::new(KEY).unwrap();
        for path in [
            "/tmp/dom-xmr-sidecar.sock",
            "/tmp/nested/dom-xmr-sidecar.sock",
            "/var/tmp/dom-xmr-sidecar.sock",
            "/dev/shm/dom-xmr-sidecar.sock",
            "relative/sidecar.sock",
        ] {
            assert!(
                BlockingUdsSidecarPort::new(path, auth()).is_err(),
                "path must be refused: {path}"
            );
        }
        assert!(BlockingUdsSidecarPort::new("/run/dom/sidecar.sock", auth()).is_ok());
    }

    #[test]
    fn v9_authenticated_but_mismatched_funding_is_hard_rejected() -> TestResult {
        for mutation in 0..5 {
            let SidecarResponseV2::Funding(mut response) = valid_funding_response() else {
                panic!("funding fixture");
            };
            match mutation {
                0 => response.api_version += 1,
                1 => response.request_nonce[0] ^= 1,
                2 => response.funding_tx_hash[0] ^= 1,
                3 => response.received_amount_piconero += 1,
                _ => response.spendable = false,
            }
            let directory = socket_scratch_dir();
            let path = directory.path().join("sidecar.sock");
            let worker = one_shot_sidecar_response(
                UnixListener::bind(&path)?,
                KEY,
                SidecarResponseV2::Funding(response),
            );
            let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
            assert!(matches!(
                client.verify_funding(funding_request()),
                Err(SpendPortError::Rejected)
            ));
            assert!(worker.join().expect("sidecar thread").0);
        }
        Ok(())
    }

    #[test]
    fn v9_retryable_sidecar_error_remains_distinct_from_rejection() -> TestResult {
        for retryable in [true, false] {
            let directory = socket_scratch_dir();
            let path = directory.path().join("sidecar.sock");
            let worker = one_shot_sidecar_response(
                UnixListener::bind(&path)?,
                KEY,
                SidecarResponseV2::Error(xmr_live_sidecar_api::SidecarErrorBody {
                    code: "funding_unavailable".into(),
                    message: "funding unavailable".into(),
                    retryable,
                }),
            );
            let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
            match client.verify_funding(funding_request()) {
                Err(SpendPortError::Retryable) => assert!(retryable),
                Err(SpendPortError::Rejected) => assert!(!retryable),
                Ok(_) => panic!("error response cannot authorize funding"),
            }
            assert!(worker.join().expect("sidecar thread").0);
        }
        Ok(())
    }

    #[test]
    fn a_malformed_error_code_is_sanitized_and_never_changes_the_classification() -> TestResult {
        // A diagnostic label must not decide a settlement outcome. Whatever the
        // code looks like, `retryable` alone separates "try again" from a
        // permanent refusal, because downstream a refusal reads as a retained
        // state conflict on a settlement child rather than a backend outage.
        for code in ["", "funding\nunavailable", "funding-UNAVAILABLE", "x"] {
            for retryable in [true, false] {
                let directory = socket_scratch_dir();
                let path = directory.path().join("sidecar.sock");
                let worker = one_shot_sidecar_response(
                    UnixListener::bind(&path)?,
                    KEY,
                    SidecarResponseV2::Error(xmr_live_sidecar_api::SidecarErrorBody {
                        code: code.into(),
                        message: "untrusted diagnostic".into(),
                        retryable,
                    }),
                );
                let mut client = BlockingUdsSidecarPort::new(&path, SidecarAuthKey::new(KEY)?)?;
                match client.verify_funding(funding_request()) {
                    Err(SpendPortError::Retryable) => assert!(retryable),
                    Err(SpendPortError::Rejected) => assert!(!retryable),
                    Ok(_) => panic!("error response cannot authorize funding"),
                }
                assert!(worker.join().expect("sidecar thread").0);
            }
        }
        Ok(())
    }

    #[test]
    fn sanitizing_a_code_bounds_it_and_cannot_forge_a_second_log_line() {
        assert_eq!(sanitized_error_code(""), "absent");
        assert_eq!(
            sanitized_error_code("v23_build_unavailable"),
            "v23_build_unavailable"
        );
        assert_eq!(
            sanitized_error_code("funding\nunavailable"),
            "funding_unavailable"
        );
        // Uppercase and the hyphen each fold to one underscore, byte for byte.
        assert_eq!(
            sanitized_error_code("Funding-Unavailable"),
            "_unding__navailable"
        );
        let long = "a".repeat(MAX_SIDECAR_ERROR_CODE_BYTES + 64);
        assert_eq!(
            sanitized_error_code(&long).len(),
            MAX_SIDECAR_ERROR_CODE_BYTES
        );
    }

    #[test]
    fn v9_one_deadline_bounds_a_trickling_frame_and_refuses_invalid_budgets() -> TestResult {
        for timeout in [Duration::ZERO, Duration::from_secs(181)] {
            assert!(matches!(
                BlockingUdsSidecarPort::with_timeout(
                    "/run/dom/sidecar.sock",
                    SidecarAuthKey::new(KEY)?,
                    timeout
                ),
                Err(SpendPortError::Rejected)
            ));
        }
        let (mut client, mut peer) = UnixStream::pair()?;
        let start = Instant::now();
        let deadline = start + Duration::from_millis(40);
        let worker = std::thread::spawn(move || {
            // All bytes arrive individually within the old per-read timeout,
            // but the complete declared frame exceeds the call's budget.
            if peer.write_all(&100_u32.to_be_bytes()).is_err() {
                return;
            }
            for _ in 0..100 {
                if peer.write_all(&[b'a']).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let result = read_frame(&mut client, MAX_FRAME_BYTES, deadline);
        drop(client);
        worker.join().expect("trickling peer");
        assert!(matches!(result, Err(SpendPortError::Retryable)));
        assert!(start.elapsed() < Duration::from_secs(2));
        Ok(())
    }
}
