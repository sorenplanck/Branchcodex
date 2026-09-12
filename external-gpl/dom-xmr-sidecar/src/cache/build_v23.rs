//! Per-request locked, encrypted pre-signing plan and immutable public result.
//! A published result is never recreated. No private outgoing key is plaintext.
use super::*;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use xmr_key_image_proof::BuildSweepResponseV23;
use zeroize::Zeroizing;

const MAX_PLAN: usize = 256 * 1024;
const MAX_READY: usize = 4 * 1024 * 1024;
type Response = BuildSweepResponseV23<BuildSweepResponseV2>;

pub(crate) struct BuildGuardV23 {
    _lock: fs::File,
    directory: PathBuf,
    stem: String,
    request_hash: [u8; 32],
}

impl SweepCache {
    pub(crate) fn begin_build_v23(
        &self,
        nonce: [u8; 32],
        request_hash: [u8; 32],
    ) -> Result<BuildGuardV23, CacheError> {
        if nonce == [0; 32] || request_hash == [0; 32] {
            return Err(CacheError::Corrupt);
        }
        // No reinterpretation of a V2 request's already published bytes.
        match fs::symlink_metadata(self.path(&nonce)) {
            Ok(_) => return Err(CacheError::Conflict),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CacheError::Unavailable),
        }
        let parent = fs::symlink_metadata(&self.directory).map_err(|_| CacheError::Unavailable)?;
        if !parent.is_dir()
            || parent.file_type().is_symlink()
            || parent.permissions().mode() & 0o022 != 0
            || parent.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(CacheError::Corrupt);
        }
        let directory = self.directory.join("build-proofs-v23");
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CacheError::Unavailable),
        }
        let meta = fs::symlink_metadata(&directory).map_err(|_| CacheError::Unavailable)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(CacheError::Corrupt);
        }
        let stem = hex::encode(nonce);
        let lock_path = directory.join(format!("{stem}.lock"));
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(|_| CacheError::Unavailable)?;
        require_file(&lock)?;
        lock.try_lock_exclusive()
            .map_err(|_| CacheError::Unavailable)?;
        let guard = BuildGuardV23 {
            _lock: lock,
            directory,
            stem,
            request_hash,
        };
        match guard.read("scope", 32)? {
            Some(scope) if scope.as_slice() == request_hash.as_slice() => {}
            Some(_) => return Err(CacheError::Conflict),
            None => guard.publish("scope", &request_hash)?,
        }
        Ok(guard)
    }
}

fn require_file(file: &fs::File) -> Result<(), CacheError> {
    let meta = file.metadata().map_err(|_| CacheError::Unavailable)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(CacheError::Corrupt);
    }
    Ok(())
}
impl BuildGuardV23 {
    fn path(&self, suffix: &str) -> PathBuf {
        self.directory.join(format!("{}.{suffix}", self.stem))
    }
    fn read(&self, suffix: &str, bound: usize) -> Result<Option<Vec<u8>>, CacheError> {
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path(suffix))
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Unavailable),
        };
        require_file(&file)?;
        let mut bytes = Vec::new();
        file.take((bound + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Unavailable)?;
        if bytes.is_empty() || bytes.len() > bound {
            return Err(CacheError::Corrupt);
        }
        Ok(Some(bytes))
    }
    fn publish(&self, suffix: &str, bytes: &[u8]) -> Result<(), CacheError> {
        if self.read(suffix, bytes.len())?.is_some() {
            return Err(CacheError::Conflict);
        }
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let temporary = self.directory.join(format!(
            "{}.{}.staging-{}",
            self.stem,
            suffix,
            hex::encode(random)
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| CacheError::Unavailable)?;
        file.write_all(bytes).map_err(|_| CacheError::Unavailable)?;
        file.sync_all().map_err(|_| CacheError::Unavailable)?;
        // NOREPLACE publication; only encrypted plan/public proof bytes.
        fs::hard_link(&temporary, self.path(suffix)).map_err(|_| CacheError::Conflict)?;
        fs::remove_file(&temporary).map_err(|_| CacheError::Unavailable)?;
        fs::File::open(&self.directory)
            .and_then(|d| d.sync_all())
            .map_err(|_| CacheError::Unavailable)?;
        Ok(())
    }
    pub(crate) fn load_ready(&self) -> Result<Option<Response>, CacheError> {
        let Some(bytes) = self.read("ready", MAX_READY)? else {
            if self.read("issued", 32)?.is_some() {
                return Err(CacheError::Corrupt);
            }
            return Ok(None);
        };
        let digest = SweepCache::request_hash(&bytes);
        let issued = self.read("issued", 32)?;
        match &issued {
            Some(retained) if retained.as_slice() == digest.as_slice() => {}
            Some(_) => return Err(CacheError::Corrupt),
            None => {}
        }
        if self.read("plan", MAX_PLAN + 64)?.is_none() {
            return Err(CacheError::Corrupt);
        }
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| CacheError::Corrupt)?;
        response
            .validate_framing()
            .map_err(|_| CacheError::Corrupt)?;
        if hex::encode(response.sweep.request_nonce) != self.stem {
            return Err(CacheError::Corrupt);
        }
        if issued.is_none() {
            self.publish("issued", &digest)?;
        }
        Ok(Some(response))
    }
    pub(crate) fn load_plan(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {
        let Some(bytes) = self.read("plan", MAX_PLAN + 64)? else {
            return Ok(None);
        };
        if bytes.len() < 24 + 16 {
            return Err(CacheError::Corrupt);
        }
        let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CacheError::Corrupt)?;
        let plaintext = aead
            .decrypt(
                XNonce::from_slice(&bytes[..24]),
                Payload {
                    msg: &bytes[24..],
                    aad: &self.request_hash,
                },
            )
            .map_err(|_| CacheError::Corrupt)?;
        Ok(Some(Zeroizing::new(plaintext)))
    }
    pub(crate) fn store_plan(&self, key: &[u8; 32], plan: &[u8]) -> Result<(), CacheError> {
        if plan.is_empty() || plan.len() > MAX_PLAN || self.read("ready", MAX_READY)?.is_some() {
            return Err(CacheError::Corrupt);
        }
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CacheError::Corrupt)?;
        let encrypted = aead
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plan,
                    aad: &self.request_hash,
                },
            )
            .map_err(|_| CacheError::Corrupt)?;
        let mut bytes = nonce.to_vec();
        bytes.extend(encrypted);
        self.publish("plan", &bytes)
    }
    pub(crate) fn store_ready(&self, response: &Response) -> Result<(), CacheError> {
        if self.read("plan", MAX_PLAN + 64)?.is_none() {
            return Err(CacheError::Corrupt);
        }
        response
            .validate_framing()
            .map_err(|_| CacheError::Corrupt)?;
        let bytes = serde_json::to_vec(response).map_err(|_| CacheError::Corrupt)?;
        if bytes.len() > MAX_READY {
            return Err(CacheError::Corrupt);
        }
        self.publish("ready", &bytes)?;
        self.publish("issued", &SweepCache::request_hash(&bytes))
    }
}
