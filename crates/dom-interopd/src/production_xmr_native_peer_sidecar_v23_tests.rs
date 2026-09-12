//! A second independently credentialed sidecar for the SAME retained funding
//! history. Never regenerate a different transaction for the other actor.
use super::*;

pub(crate) struct PeerSidecarOwnerV23 {
    process: ProcessOwner,
    root: tempfile::TempDir,
}
impl PeerSidecarOwnerV23 {
    pub(crate) fn socket(&self) -> PathBuf {
        self.root.path().join("sidecar.sock")
    }
    pub(crate) fn require_alive(&mut self) -> Result<()> {
        if self.process.child.try_wait()?.is_some() {
            return Err("peer sidecar process exited".into());
        }
        Ok(())
    }
}

impl Configuration {
    pub(crate) fn start_peer_sidecar_at_v23(
        &self,
        funding: &FundingOwner,
        parent: &Path,
        auth: [u8; 32],
    ) -> Result<PeerSidecarOwnerV23> {
        self.start_peer_sidecar_for_urls_v23(funding.urls(), parent, auth)
    }

    pub(crate) fn start_peer_sidecar_for_urls_v23(
        &self,
        urls: &[String],
        parent: &Path,
        auth: [u8; 32],
    ) -> Result<PeerSidecarOwnerV23> {
        for url in urls {
            xmr_rpc_broadcast_blocking::BlockingMoneroDaemonReaderV1::new(url.clone())?;
        }
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(parent)?;
        if auth == [0; 32]
            || !parent.is_absolute()
            || std::fs::canonicalize(parent)? != parent
            || !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::getuid().as_raw()
        {
            return Err("peer sidecar requires private original actor parent".into());
        }
        let root = tempfile::Builder::new()
            .prefix("xmr-peer-v23-")
            .tempdir_in(parent)?;
        let socket = root.path().join("sidecar.sock");
        let url = urls.first().ok_or("funding RPC absent")?;
        let child = Command::new(&self.sidecar)
            .env_clear()
            .env("DOM_XMR_SIDECAR_LISTEN", "127.0.0.1:0")
            .env("DOM_XMR_MONEROD_URL", url)
            .env("DOM_XMR_SIDECAR_AUTH_HEX", hex::encode(auth))
            .env("DOM_XMR_SIDECAR_CACHE_DIR", root.path().join("cache"))
            .env("DOM_XMR_SIDECAR_UDS", &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut process = ProcessOwner { child, input: None };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            if process.child.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err("peer sidecar failed to expose its private socket".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let meta = std::fs::symlink_metadata(&socket)?;
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket()
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::getuid().as_raw()
        {
            return Err("peer sidecar socket ownership".into());
        }
        Ok(PeerSidecarOwnerV23 { process, root })
    }
}
