//! Owned test subprocesses only. No shell, inherited credentials, or plaintext
//! credential files/log output. Exit status is not evidence of an economic exit.
use super::Result;
use std::{
    io::{Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_CAPTURE: usize = 256 * 1024;
type Capture = Receiver<std::io::Result<Zeroizing<Vec<u8>>>>;
/// Bytes read so far, readable before the pipe closes. The daemon's own
/// children inherit its stderr, so a live helper keeps the pipe open long
/// after the daemon exits and an EOF-only capture returns nothing for that
/// actor: exactly half of a bilateral failure disappears. The reader thread
/// keeps this in step with what it has consumed.
type LiveCapture = std::sync::Arc<std::sync::Mutex<Zeroizing<Vec<u8>>>>;

mod exit_diagnostic_v24;

fn retain_stderr_once_v24(
    receiver: &Capture,
    retained: &mut Option<std::io::Result<Zeroizing<Vec<u8>>>>,
    timeout: Duration,
) {
    if retained.is_none() {
        if let Ok(capture) = receiver.recv_timeout(timeout) {
            *retained = Some(capture);
        }
    }
}

fn drain(stream: impl Read + Send + 'static) -> Capture {
    drain_live(stream).0
}

fn drain_live(mut stream: impl Read + Send + 'static) -> (Capture, LiveCapture) {
    let (send, receive) = mpsc::sync_channel(1);
    let live: LiveCapture = std::sync::Arc::new(std::sync::Mutex::new(Zeroizing::new(Vec::new())));
    let writer = std::sync::Arc::clone(&live);
    thread::spawn(move || {
        let result = (|| {
            // Allocate before reading so a reallocation cannot leave a copy.
            let mut bytes = Zeroizing::new(vec![0; MAX_CAPTURE]);
            let mut length = 0;
            // Past the bound the overflow is read into a fixed scratch buffer
            // and dropped. Retaining the first bytes rather than failing keeps
            // the earliest diagnostics — the ones that name where a run first
            // went wrong — instead of discarding the whole capture because a
            // later, noisier phase overran it; and it keeps reading, so the
            // daemon never blocks on a full pipe.
            let mut overflow = Zeroizing::new(vec![0; 8 * 1024]);
            loop {
                let read = if length < MAX_CAPTURE {
                    stream.read(&mut bytes[length..])
                } else {
                    stream.read(&mut overflow)
                };
                match read {
                    Ok(0) => break,
                    Ok(count) => {
                        let previous = length;
                        length = length.saturating_add(count).min(MAX_CAPTURE);
                        if let Ok(mut live) = writer.lock() {
                            live.extend_from_slice(&bytes[previous..length]);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            bytes.truncate(length);
            Ok(bytes)
        })();
        let _ = send.send(result);
    });
    (receive, live)
}

pub(super) struct CapturedExit {
    pub(super) status: ExitStatus,
    pub(super) stdout: Zeroizing<Vec<u8>>,
    // Retain only long enough to close the owned pipe; never format its bytes.
    _stderr: Zeroizing<Vec<u8>>,
}

pub(crate) struct NativeDaemonProcessV23 {
    child: Child,
    status: Option<ExitStatus>,
    stdout: Capture,
    stderr: Capture,
    stderr_live: LiveCapture,
    captured_stderr: Option<std::io::Result<Zeroizing<Vec<u8>>>>,
    failure_reported: bool,
}

impl NativeDaemonProcessV23 {
    pub(super) fn start(mut command: Command, input: Zeroizing<Vec<u8>>) -> Result<Self> {
        use std::os::unix::process::CommandExt;
        command
            .env_clear()
            .env("RUST_BACKTRACE", "0")
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|_| "real daemon could not start")?;
        // Stdio::piped guarantees all three handles after a successful spawn.
        let stdout = drain(child.stdout.take().ok_or("missing daemon stdout pipe")?);
        let (stderr, stderr_live) =
            drain_live(child.stderr.take().ok_or("missing daemon stderr pipe")?);
        let mut owned = Self {
            child,
            status: None,
            stdout,
            stderr,
            stderr_live,
            captured_stderr: None,
            failure_reported: false,
        };
        let mut stdin = owned
            .child
            .stdin
            .take()
            .ok_or("missing private stdin pipe")?;
        let flags = rustix::fs::fcntl_getfl(&stdin)?;
        rustix::fs::fcntl_setfl(&stdin, flags | rustix::fs::OFlags::NONBLOCK)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut written = 0;
        while written < input.len() {
            if Instant::now() >= deadline || owned.poll()?.is_some() {
                return Err("daemon did not consume the private stream in time".into());
            }
            match stdin.write(&input[written..]) {
                Ok(0) => return Err("private stream write stopped".into()),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err("private stream delivery failed".into()),
            }
        }
        drop(stdin); // V4 requires EOF, without appending a trailing newline.
        drop(input);
        Ok(owned)
    }

    pub(crate) fn poll(&mut self) -> Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self
                .child
                .try_wait()
                .map_err(|_| "daemon status unavailable")?;
        }
        if self.status.is_some_and(|status| !status.success()) {
            self.report_diagnostics_v25();
        }
        Ok(self.status)
    }

    /// Echo this daemon's allowlisted diagnostics exactly once, whatever its
    /// exit status was. A clean exit that did not finish the swap is still a
    /// failed run, and it is the one the caller most needs explained; gating
    /// the echo on an unsuccessful status left that case mute.
    pub(crate) fn report_diagnostics_v25(&mut self) {
        if !self.failure_reported {
            // A failed process can be noticed by either poll_actor or
            // require_running. Preserve the one received Zeroizing buffer for
            // finish: diagnostics never consume stdout/self-check evidence.
            retain_stderr_once_v24(
                &self.stderr,
                &mut self.captured_stderr,
                Duration::from_secs(2),
            );
            // The pipe may still be held open by an inherited helper. Fall back
            // to whatever the reader has already consumed rather than report
            // nothing for this actor.
            if self.captured_stderr.is_none() {
                if let Ok(live) = self.stderr_live.lock() {
                    self.captured_stderr = Some(Ok(live.clone()));
                }
            }
            let code = match self.captured_stderr.as_ref() {
                Some(Ok(bytes)) => exit_diagnostic_v24::classify(bytes),
                _ => "unknown",
            };
            let detail = self.captured_stderr.as_ref().and_then(|capture| {
                capture
                    .as_ref()
                    .ok()
                    .and_then(|bytes| exit_diagnostic_v24::composite_detail_v25(bytes))
            });
            if let Some(detail) = detail {
                eprintln!(
                    "DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code={code} stage={} cause={}",
                    detail.stage_code(),
                    detail.cause_code(),
                );
            } else {
                eprintln!("DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code={code}");
            }

            if let Some(status) = self.status {
                use std::os::unix::process::ExitStatusExt;
                eprintln!(
                    "DOM_NATIVE_EXIT_STATUS_V25 code={:?} signal={:?}",
                    status.code(),
                    status.signal()
                );
            }
            if let Some(Ok(bytes)) = self.captured_stderr.as_ref() {
                let text = String::from_utf8_lossy(bytes);
                // A panic header names only the source location; the message
                // body after it is never echoed.
                for line in text.lines().filter(|line| line.starts_with("thread '")) {
                    let location = line.split(" panicked at ").nth(1).unwrap_or("?");
                    eprintln!("DOM_DAEMON_PANIC_V25 at {}", location.trim_end_matches(':'));
                }
                for line in text.lines() {
                    if line.contains("DOM_ACTIVATION_STALL_V25")
                        || line.contains("DOM_F6_INITIATOR_DIAG_V25")
                        || line.contains("DOM_F6_BIND_DIAG_V25")
                        || line.contains("DOM_PHASE_SLOW_V25")
                        || line.contains("DOM_RECOVERY_PHASE_V25")
                        || line.contains("DOM_LEASE_GAP_V25")
                        || line.contains("DOM_ROUTE_LEASE_GAP_V26")
                        || line.contains("DOM_RENEW_SITE_V26")
                        || line.contains("DOM_RENEW_INTERVAL_V26")
                        || line.contains("DOM_ROUTE_STEP_SLOW_V26")
                        || line.contains("DOM_PLAN_SOURCE_DIAG_V25")
                        || line.contains("DOM_ROUTE_RUNTIME_DIAG_V25")
                        || line.contains("DOM_SIGBUS_DIAG_V25")
                        || line.contains("DOM_ACTION_AUTH_DIAG_V25")
                        || line.contains("DOM_MATERIALIZER_DIAG_V25")
                        || line.contains("DOM_CHILD_CONFLICT_V25")
                        || line.contains("DOM_CHILD_MATERIALIZE_PIN_V25")
                        || line.contains("DOM_CHILD_STATIC_PIN_V25")
                        || line.contains("DOM_CHILD_RETAINED_PIN_V25")
                        || line.contains("DOM_CHILD_FACE_DIAG_V25")
                        || line.contains("DOM_F7_FUNDING_GATE_V25")
                        || line.contains("DOM_EXCHANGE_SHAPE_V25")
                        || line.contains("DOM_READY_QUORUM_V25")
                        || line.contains("DOM_READY_SIGNER_V25")
                        || line.contains("DOM_GRAPH_SETUP_V25")
                        || line.contains("DOM_READY_ENTRY_V25")
                        || line.contains("DOM_READY_APPLY_V25")
                        || line.contains("DOM_READY_SIGNER_V25")
                        || line.contains("DOM_GRAPH_SETUP_V25")
                        || line.contains("DOM_READY_ENTRY_V25")
                        || line.contains("DOM_READY_APPLY_V25")
                        || line.contains("DOM_FUNDING_WINDOW_REFUSAL_V25")
                        || line.contains("DOM_F7_ACTIVATE_RECOVERY_V25")
                        || line.contains("DOM_F7_FUNDING_RETRYABLE_V25")
                        || line.contains("DOM_FUNDING_WINDOW_V25")
                        || line.contains("DOM_NATIVE_F7_FUNDING_V24")
                        || line.contains("DOM_XMR_FUNDING_REFUSAL_V25")
                        || line.contains("DOM_LEASE_DIAG_V25")
                        || line.contains("DOM_SETTLEMENT_CHILD_DIAG_V26")
                        || line.contains("DOM_ACTUATOR_OPEN_DIAG_V25")
                        || line.contains("production DOM actuator store unavailable")
                        || line.contains("production settlement child authority unavailable")
                        || line.contains("production route runtime failed")
                        || line.contains("production composite relay loop failed")
                    {
                        eprintln!("DOM_DAEMON_STDERR_V25 {line}");
                    }
                }
            }
            self.failure_reported = true;
        }
    }

    /// Terminate this harness-owned daemon so its stderr can be drained and
    /// reported. A stalled run is the one failure that produced no diagnostic
    /// at all: the daemons stay alive past the phase deadline, so their stderr
    /// pipe never reaches EOF and `poll` never has anything to classify. The
    /// signalled exit is not evidence of an economic outcome; the caller has
    /// already decided the run failed.
    pub(crate) fn report_stall_v25(&mut self) -> Result<()> {
        if self.status.is_none() {
            self.signal(rustix::process::Signal::TERM)?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if self.poll()?.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        // The daemon handles SIGTERM and exits cleanly, so the status alone
        // proves nothing here — report unconditionally.
        self.report_diagnostics_v25();
        Ok(())
    }

    pub(crate) fn require_running(&mut self) -> Result<()> {
        if self.poll()?.is_some() {
            return Err("daemon exited before the required durable boundary".into());
        }
        Ok(())
    }

    fn signal(&mut self, signal: rustix::process::Signal) -> Result<()> {
        if self.poll()?.is_none() {
            let pid = i32::try_from(self.child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .ok_or("invalid owned daemon PID")?;
            rustix::process::kill_process_group(pid, signal)
                .map_err(|_| "could not signal the owned daemon process group")?;
        }
        Ok(())
    }

    pub(super) fn finish(mut self, timeout: Duration) -> Result<CapturedExit> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err("bounded process-exit deadline required".into());
        }
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.poll()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("daemon exit deadline elapsed".into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = self
            .stdout
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "daemon stdout did not close")?
            .map_err(|_| "bounded daemon stdout capture failed")?;
        let stderr = match self.captured_stderr.take() {
            Some(captured) => captured,
            None => self
                .stderr
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| "daemon stderr did not close")?,
        }
        .map_err(|_| "bounded daemon stderr capture failed")?;
        Ok(CapturedExit {
            status,
            stdout,
            _stderr: stderr,
        })
    }

    /// Crash only this harness-owned process group, then reap it. The caller
    /// must independently inspect durable state before launching Reopen.
    pub(crate) fn crash_for_reopen(mut self) -> Result<()> {
        self.require_running()?;
        self.signal(rustix::process::Signal::KILL)?;
        let result = self.finish(Duration::from_secs(10))?;
        use std::os::unix::process::ExitStatusExt;
        if result.status.signal() != Some(9) {
            return Err("planned daemon crash was not observed".into());
        }
        Ok(())
    }

    pub(crate) fn stop(mut self) -> Result<ExitStatus> {
        self.signal(rustix::process::Signal::TERM)?;
        Ok(self.finish(Duration::from_secs(30))?.status)
    }
}

impl Drop for NativeDaemonProcessV23 {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        let _ = self.signal(rustix::process::Signal::KILL);
        // signal() may already have reaped a naturally exited child.
        if self.status.is_some() {
            return;
        }
        let _ = self.child.kill();
        // Never leave the calling test indefinitely stuck in wait()/join().
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.status = Some(status);
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
    }
}
