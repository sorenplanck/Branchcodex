//! Test-owned counterpart of `ProductionSolanaUnixSignerV7`: one private Unix
//! socket per actor and position, serving the OTHER role's scoped local signer.
//! It signs only messages whose entire legacy envelope the V7 binding rebuilds.
use crate::production_inputs::AuthenticatedSolanaSessionBindingsV1;
use crate::production_solana_signer::{
    ProductionSolanaLocalSignerV7, ProductionSolanaSignerBindingV7, ProductionSolanaSignerRoleV7,
};
use std::{
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Must be listening before the daemon starts: `bind_signers` connects once
/// during startup and never reconnects an ambiguous stream.
pub(crate) struct NativeSolPeerSignerOwnerV23 {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    socket: PathBuf,
}

impl NativeSolPeerSignerOwnerV23 {
    pub(crate) fn bind(
        socket: &Path,
        session: &AuthenticatedSolanaSessionBindingsV1,
        served_role: ProductionSolanaSignerRoleV7,
        seed: Zeroizing<[u8; 32]>,
        frame_timeout: Duration,
    ) -> Result<Self> {
        let parent = socket.parent().ok_or("peer signer socket parent")?;
        let meta = std::fs::symlink_metadata(parent)?;
        if !socket.is_absolute()
            || std::fs::canonicalize(parent)? != parent
            || !meta.is_dir()
            || meta.uid() != rustix::process::getuid().as_raw()
            || meta.mode() & 0o077 != 0
            || frame_timeout.is_zero()
            || frame_timeout > Duration::from_secs(60)
        {
            return Err("peer signer requires a private canonical parent and bounded frames".into());
        }
        // Native SOL only: no token accounts are bound for this scenario.
        let binding = ProductionSolanaSignerBindingV7::authenticate(session, served_role, None)
            .map_err(|_| "peer signer session binding refused")?;
        let signer = ProductionSolanaLocalSignerV7::new(binding, seed)
            .map_err(|_| "peer signer seed does not derive the served account")?;
        let listener = UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        std::fs::File::open(parent)?.sync_all()?;
        let signer = Arc::new(Mutex::new(signer));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut connections = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let signer = Arc::clone(&signer);
                        let stop = Arc::clone(&worker_stop);
                        connections.push(thread::spawn(move || {
                            serve_connection(stream, &signer, &stop, frame_timeout)
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            for connection in connections {
                let _ = connection.join();
            }
        });
        Ok(Self {
            stop,
            worker: Some(worker),
            socket: socket.to_path_buf(),
        })
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }
}

/// Idle time between daemon requests is unbounded (the funding and claim are
/// minutes apart), but each request frame keeps the V7 60-second deadline.
/// A peeked byte starts one `serve_once`; any refusal closes this stream.
fn serve_connection(
    stream: UnixStream,
    signer: &Mutex<ProductionSolanaLocalSignerV7>,
    stop: &AtomicBool,
    frame_timeout: Duration,
) {
    let mut stream = stream;
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .is_err()
    {
        return;
    }
    let mut probe = [0u8; 1];
    while !stop.load(Ordering::Acquire) {
        match nix::sys::socket::recv(
            stream.as_raw_fd(),
            &mut probe,
            nix::sys::socket::MsgFlags::MSG_PEEK,
        ) {
            Ok(0) => return,
            Ok(_) => {
                let Ok(mut owned) = signer.lock() else {
                    return;
                };
                if owned.serve_once(&mut stream, frame_timeout).is_err() {
                    return;
                }
                // serve_once sets its own deadlines; restore the idle probe.
                if stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .is_err()
                {
                    return;
                }
            }
            Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return,
        }
    }
}

impl Drop for NativeSolPeerSignerOwnerV23 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
