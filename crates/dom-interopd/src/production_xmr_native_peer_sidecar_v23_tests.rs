//! A second independently credentialed sidecar for the SAME retained funding
//! history. Never regenerate a different transaction for the other actor.
use super::*;

pub(crate) struct PeerSidecarOwnerV23 {
    process: Option<ProcessOwner>,
    // The enclosing fixture owns cleanup. Dropping dependencies must stop the
    // helper without deleting its original Ready/cache evidence before archive.
    root: PathBuf,
    executable: PathBuf,
    executable_digest: [u8; 32],
    url: String,
    auth: Zeroizing<[u8; 32]>,
}
impl PeerSidecarOwnerV23 {
    pub(crate) fn socket(&self) -> PathBuf {
        self.root.join("sidecar.sock")
    }
    pub(crate) fn require_alive(&mut self) -> Result<()> {
        if self
            .process
            .as_mut()
            .ok_or("peer sidecar is stopped")?
            .child
            .try_wait()?
            .is_some()
        {
            return Err("peer sidecar process exited".into());
        }
        Ok(())
    }

    /// The caller owns the fixture and must already have reaped both daemons.
    /// The closure runs only after this exact helper is killed and reaped.
    pub(crate) fn with_stopped_v24<T>(
        &mut self,
        operation: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        self.require_alive()?;
        let process = self.process.as_mut().ok_or("sidecar process absent")?;
        process.child.kill()?;
        process.child.wait()?;
        // Drop's wait is idempotent; no helper PID remains live during closure.
        drop(self.process.take());
        let cache = self.root.join("cache");
        require_private_directory_v24(&cache)?;
        use std::os::unix::fs::MetadataExt;
        let before = std::fs::symlink_metadata(&cache)?;
        let result = operation(&cache);
        // Preserve the operation's error and restore the same sidecar even
        // when retirement/audit fails. Never regenerate credentials or cache.
        let restored = (|| -> Result<()> {
            require_private_directory_v24(&cache)?;
            let after = std::fs::symlink_metadata(&cache)?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err("original sidecar cache directory was replaced".into());
            }
            self.restart_original_v24()
        })();
        match (result, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(operation), Err(restart)) => Err(format!(
                "sidecar stopped operation failed: {operation}; original restart failed: {restart}"
            )
            .into()),
        }
    }

    fn restart_original_v24(&mut self) -> Result<()> {
        if self.process.is_some() {
            return Err("cannot replace a live sidecar".into());
        }
        require_private_directory_v24(&self.root)?;
        require_private_directory_v24(&self.root.join("cache"))?;
        if executable_digest_v24(&self.executable)? != self.executable_digest {
            return Err("original sidecar executable changed".into());
        }
        let socket = self.socket();
        match std::fs::symlink_metadata(&socket) {
            Ok(metadata) => require_private_socket_v24(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let child = Command::new(&self.executable)
            .env_clear()
            .env("DOM_XMR_SIDECAR_LISTEN", "127.0.0.1:0")
            .env("DOM_XMR_MONEROD_URL", &self.url)
            .env("DOM_XMR_SIDECAR_AUTH_HEX", hex::encode(*self.auth))
            .env("DOM_XMR_SIDECAR_CACHE_DIR", self.root.join("cache"))
            .env("DOM_XMR_SIDECAR_UDS", &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.process = Some(ProcessOwner { child, input: None });
        let readiness = self.require_authenticated_ready_v24();
        if readiness.is_err() {
            // No ambiguous live helper is left for a later scenario step.
            if let Some(mut process) = self.process.take() {
                let _ = process.child.kill();
                let _ = process.child.wait();
            }
        }
        readiness
    }

    fn require_authenticated_ready_v24(&mut self) -> Result<()> {
        use std::os::unix::net::UnixStream;
        use xmr_live_sidecar_api::{SidecarHelloProofV1, SidecarHelloV1, API_VERSION_V2};
        let deadline = Instant::now() + Duration::from_secs(10);
        let socket = self.socket();
        let mut stream = loop {
            self.require_alive()?;
            if Instant::now() >= deadline {
                return Err("sidecar readiness timed out".into());
            }
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        require_private_socket_v24(&std::fs::symlink_metadata(&socket)?)?;
        let credentials =
            nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
        let pid = self
            .process
            .as_ref()
            .ok_or("sidecar process absent")?
            .child
            .id();
        if credentials.uid() != rustix::process::geteuid().as_raw()
            || u32::try_from(credentials.pid())? != pid
        {
            return Err("readiness socket is not owned by the exact restarted sidecar".into());
        }
        let remaining = || -> Result<Duration> {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| "sidecar hello deadline exhausted".into())
        };
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| "sidecar readiness nonce unavailable")?;
        let hello = SidecarHelloV1 {
            api_version: API_VERSION_V2,
            challenge_nonce: nonce,
        };
        hello.validate()?;
        let bytes = serde_json::to_vec(&hello)?;
        stream.set_write_timeout(Some(remaining()?))?;
        stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        stream.set_write_timeout(Some(remaining()?))?;
        stream.write_all(&bytes)?;
        let mut length = [0; 4];
        stream.set_read_timeout(Some(remaining()?))?;
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > 1024 {
            return Err("sidecar hello proof bound".into());
        }
        let mut bytes = vec![0; length];
        stream.set_read_timeout(Some(remaining()?))?;
        stream.read_exact(&mut bytes)?;
        let proof: SidecarHelloProofV1 = serde_json::from_slice(&bytes)?;
        proof.validate()?;
        xmr_sidecar_auth::SidecarAuthKey::new(*self.auth)?
            .verify_challenge_proof(&nonce, &proof.proof)?;
        remaining()?;
        self.require_alive()
    }
}

fn require_private_directory_v24(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path)? != path
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err("original private sidecar directory required".into());
    }
    Ok(())
}

fn require_private_socket_v24(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err("original private sidecar socket required".into());
    }
    Ok(())
}

fn executable_digest_v24(path: &Path) -> Result<[u8; 32]> {
    use blake2::digest::{Update, VariableOutput};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !path.is_absolute()
        || std::fs::canonicalize(path)? != path
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.len() == 0
        || metadata.len() > 256 * 1024 * 1024
    {
        return Err("original sidecar executable ownership/bound".into());
    }
    let mut reader = file.take(256 * 1024 * 1024 + 1);
    let mut hash = blake2::Blake2bVar::new(32)?;
    let mut buffer = [0; 65536];
    let mut length = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        length += count as u64;
    }
    if length != metadata.len() {
        return Err("sidecar executable changed during read".into());
    }
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)?;
    Ok(digest)
}

#[test]
fn stopped_sidecar_directory_guard_rejects_link_and_permissive_cache_v24() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    require_private_directory_v24(root.path())?;
    let link = root.path().join("cache-link");
    std::os::unix::fs::symlink(root.path(), &link)?;
    assert!(require_private_directory_v24(&link).is_err());
    let cache = root.path().join("cache");
    std::fs::create_dir(&cache)?;
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755))?;
    assert!(require_private_directory_v24(&cache).is_err());
    Ok(())
}

#[test]
fn sidecar_readiness_cannot_reuse_another_hello_nonce_v24() -> Result<()> {
    let auth = xmr_sidecar_auth::SidecarAuthKey::new([7; 32])?;
    let proof = auth.challenge_proof(&[8; 32])?;
    auth.verify_challenge_proof(&[8; 32], &proof)?;
    assert!(auth.verify_challenge_proof(&[9; 32], &proof).is_err());
    assert!(xmr_sidecar_auth::SidecarAuthKey::new([10; 32])?
        .verify_challenge_proof(&[8; 32], &proof)
        .is_err());
    Ok(())
}

#[test]
fn sidecar_drop_preserves_cache_until_private_parent_cleanup_v24() -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = tempfile::tempdir()?;
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
    let child = tempfile::Builder::new()
        .prefix("xmr-peer-v23-")
        .tempdir_in(parent.path())?;
    std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o700))?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(child.path().join("cache"))?;
    require_private_directory_v24(parent.path())?;
    require_private_directory_v24(child.path())?;
    let retained = child.keep();
    // This lifetime regression does not start or emulate a native process.
    let owner = PeerSidecarOwnerV23 {
        process: None,
        root: retained.clone(),
        executable: parent.path().join("not-executed"),
        executable_digest: [1; 32],
        url: "http://127.0.0.1:1".into(),
        auth: Zeroizing::new([2; 32]),
    };
    drop(owner);
    assert!(retained.join("cache").is_dir());
    drop(parent);
    assert_eq!(
        std::fs::symlink_metadata(&retained)
            .err()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
    Ok(())
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
        // `tempdir_in` follows the process umask. GitHub runners commonly use
        // 0002, which can leave this original cache owner group-accessible.
        // Tighten the actual directory before either the cache or sidecar is
        // created; restart_original_v24 then verifies the same inode/mode.
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(root.path().join("cache"))?;
        let url = urls.first().ok_or("funding RPC absent")?;
        let mut owner = PeerSidecarOwnerV23 {
            process: None,
            root: root.path().to_path_buf(),
            executable: self.sidecar.clone(),
            executable_digest: executable_digest_v24(&self.sidecar)?,
            url: url.clone(),
            auth: Zeroizing::new(auth),
        };
        owner.restart_original_v24()?;
        // Until readiness succeeds, the temporary guard removes failed startup
        // material after the process owner drops. Successful helper evidence is
        // then owned by the original outer fixture, not by dependency teardown.
        require_private_directory_v24(parent)?;
        require_private_directory_v24(root.path())?;
        owner.root = root.keep();
        Ok(owner)
    }
}
