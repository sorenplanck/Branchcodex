//! Harness boundary for the REAL release-production executable. This does not
//! mint admission, simulate `run`, or replace missing companions with fixtures.
//! Exporters must supply authenticated V11 state and independent V4 owners.
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use zeroize::Zeroizing;

mod network;
mod process;
pub(crate) use process::NativeDaemonProcessV23;
pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) enum NativeDaemonModeV23 {
    Create,
    Reopen,
}

// Retain the opened inode: every self-check/run executes that same descriptor,
// not a path that a concurrent build could replace after fingerprint checking.
pub(crate) struct NativeDaemonBinaryV23 {
    executable: File,
    path: PathBuf,
    fingerprint: [u8; 32],
}

impl NativeDaemonBinaryV23 {
    /// Missing binary/fingerprint is an explicit dependency failure, never skip.
    /// Do not call until the implementation-writing phase is complete.
    pub(crate) fn from_environment() -> Result<Self> {
        let path = std::env::var_os("DOM_INTEROP_REAL_BINARY_V23")
            .map(PathBuf::from)
            .ok_or("DOM_INTEROP_REAL_BINARY_V23 is required")?;
        let expected = std::env::var("DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23")
            .map_err(|_| "DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23 is required")?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(
                "expected binary fingerprint must be 64 lowercase hexadecimal digits".into(),
            );
        }
        let expected: [u8; 32] = hex::decode(expected)?
            .try_into()
            .map_err(|_| "binary fingerprint length")?;
        Self::open(&path, expected)
    }

    fn open(path: &Path, expected: [u8; 32]) -> Result<Self> {
        if !path.is_absolute() || expected == [0; 32] {
            return Err("absolute executable path and nonzero fingerprint required".into());
        }
        let named = std::fs::symlink_metadata(path)?;
        if !named.is_file()
            || named.file_type().is_symlink()
            || named.mode() & 0o6022 != 0
            || named.mode() & 0o111 == 0
            || named.len() < 64
            || named.len() > 1024 * 1024 * 1024
        {
            return Err("daemon executable metadata rejected".into());
        }
        let mut executable = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        let opened = executable.metadata()?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() || opened.len() != named.len()
        {
            return Err("daemon executable changed while opening".into());
        }
        let mut magic = [0; 4];
        executable.read_exact(&mut magic)?;
        if magic != *b"\x7fELF" {
            return Err("a real Linux ELF executable is required".into());
        }
        executable.seek(SeekFrom::Start(0))?;
        let mut hasher = Blake2bVar::new(32).map_err(|_| "binary hash initialization")?;
        let mut buffer = [0; 65_536];
        let mut length = 0u64;
        loop {
            let count = executable.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or("binary length overflow")?;
            if length > opened.len() {
                return Err("daemon executable grew during read".into());
            }
            hasher.update(&buffer[..count]);
        }
        let mut fingerprint = [0; 32];
        hasher
            .finalize_variable(&mut fingerprint)
            .map_err(|_| "binary fingerprint")?;
        let after = executable.metadata()?;
        if fingerprint != expected
            || length != opened.len()
            || after.len() != opened.len()
            || after.mtime() != opened.mtime()
            || after.mtime_nsec() != opened.mtime_nsec()
        {
            return Err("daemon executable fingerprint changed or mismatched".into());
        }
        let binary = Self {
            executable,
            path: path.to_owned(),
            fingerprint,
        };
        let mut command = binary.command();
        command.arg("self-check").arg("--json");
        let checked = process::NativeDaemonProcessV23::start(command, Zeroizing::new(Vec::new()))?
            .finish(Duration::from_secs(10))?;
        if !checked.status.success() {
            return Err("real binary self-check refused".into());
        }
        let attestation: serde_json::Value = serde_json::from_slice(&checked.stdout)
            .map_err(|_| "real binary self-check JSON rejected")?;
        if attestation["mode"] != "production"
            || attestation["profile"] != "release"
            || attestation["operational_artifact"] != true
            || attestation["laboratory_surfaces_absent"] != true
            || attestation["real_dom_adaptor"] != true
            || attestation["durable_authorities"] != true
            || attestation["git_commit"] != env!("DOM_INTEROP_GIT_COMMIT")
            || attestation["cargo_lock_blake2b256"] != env!("DOM_INTEROP_CARGO_LOCK_BLAKE2B256")
        {
            return Err("binary is not the expected release-production artifact".into());
        }
        Ok(binary)
    }

    // Recheck the retained inode before each restart as well as the first run.
    // Positional reads avoid changing the descriptor offset used by other readers.
    fn require_fingerprint(&self) -> Result<()> {
        let before = self.executable.metadata()?;
        if !before.is_file()
            || before.mode() & 0o6022 != 0
            || before.mode() & 0o111 == 0
            || before.len() < 64
            || before.len() > 1024 * 1024 * 1024
        {
            return Err("retained daemon executable metadata rejected".into());
        }
        let mut digest = Blake2bVar::new(32).map_err(|_| "binary hash initialization")?;
        let mut bytes = [0u8; 65_536];
        let mut offset = 0u64;
        loop {
            let count = self.executable.read_at(&mut bytes, offset)?;
            if count == 0 {
                break;
            }
            offset = offset
                .checked_add(count as u64)
                .ok_or("binary length overflow")?;
            if offset > before.len() {
                return Err("retained executable grew".into());
            }
            digest.update(&bytes[..count]);
        }
        let mut actual = [0u8; 32];
        digest
            .finalize_variable(&mut actual)
            .map_err(|_| "binary fingerprint")?;
        let after = self.executable.metadata()?;
        if actual != self.fingerprint
            || offset != before.len()
            || after.len() != before.len()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec()
            || after.mode() != before.mode()
        {
            return Err("retained daemon executable changed".into());
        }
        Ok(())
    }

    fn command(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()))
    }

    /// Credentials are parsed by the real V4 decoder, then sent only by pipe.
    /// The release binary still performs its own artifact/config/admission checks.
    pub(crate) fn launch(
        &self,
        state_dir: &Path,
        credentials: Zeroizing<Vec<u8>>,
        mode: NativeDaemonModeV23,
    ) -> Result<NativeDaemonProcessV23> {
        if !state_dir.is_absolute() || credentials.len() > 65_536 {
            return Err("bounded credentials and absolute state directory required".into());
        }
        let directory = std::fs::symlink_metadata(state_dir)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != rustix::process::getuid().as_raw()
            || directory.mode() & 0o7777 != 0o700
        {
            return Err("daemon state directory must be owned and private".into());
        }
        let parsed = crate::production_node::ProductionSecretsV4::read(credentials.as_slice())
            .map_err(|_| "private V4 stream rejected before launch")?;
        parsed
            .require_families([crate::production_config::ProductionChainFamilyV11::Xmr; 2])
            .map_err(|_| "native harness requires two selected XMR positions")?;
        drop(parsed);
        network::require_local_services(state_dir)?;
        self.require_fingerprint()?;
        let mut command = self.command();
        command.arg("run").arg("--state-dir").arg(state_dir);
        if matches!(mode, NativeDaemonModeV23::Create) {
            command.arg("--create");
        }
        process::NativeDaemonProcessV23::start(command, credentials)
    }

    /// Public artifact identity only; no credential or daemon output getter.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
