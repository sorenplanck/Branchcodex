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

fn drain(mut stream: impl Read + Send + 'static) -> Capture {
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            // Allocate before reading so a reallocation cannot leave a copy.
            let mut bytes = Zeroizing::new(vec![0; MAX_CAPTURE + 1]);
            let mut length = 0;
            loop {
                match stream.read(&mut bytes[length..]) {
                    Ok(0) => break,
                    Ok(count) => {
                        length += count;
                        if length > MAX_CAPTURE {
                            return Err(std::io::Error::other("daemon output exceeded bound"));
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
    receive
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
        let stderr = drain(child.stderr.take().ok_or("missing daemon stderr pipe")?);
        let mut owned = Self {
            child,
            status: None,
            stdout,
            stderr,
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
        if self.status.is_some_and(|status| !status.success()) && !self.failure_reported {
            // A failed process can be noticed by either poll_actor or
            // require_running. Preserve the one received Zeroizing buffer for
            // finish: diagnostics never consume stdout/self-check evidence.
            retain_stderr_once_v24(
                &self.stderr,
                &mut self.captured_stderr,
                Duration::from_secs(2),
            );
            let code = match self.captured_stderr.as_ref() {
                Some(Ok(bytes)) => exit_diagnostic_v24::classify(bytes),
                _ => "unknown",
            };
            eprintln!("DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code={code}");
            self.failure_reported = true;
        }
        Ok(self.status)
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
