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
use xmr_key_image_proof::{BuildSweepResponseV23, LocalRefundBuildResponseV24};
use zeroize::Zeroizing;

const MAX_PLAN: usize = 256 * 1024;
const MAX_READY: usize = 4 * 1024 * 1024;
type Response = BuildSweepResponseV23<BuildSweepResponseV2>;
type LocalResponse = LocalRefundBuildResponseV24<BuildSweepResponseV2>;

/// The complete public result and its original public scope form one immutable,
/// authenticated publication. The private plan is not needed for public reads.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalReadyV24 {
    scope: Vec<u8>,
    response: LocalResponse,
    tag: [u8; 32],
}

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
        self.begin_build_domain(nonce, Some(request_hash), "build-proofs-v23", true)
    }

    pub(crate) fn begin_local_refund_build_v24(
        &self,
        nonce: [u8; 32],
        request_hash: [u8; 32],
    ) -> Result<BuildGuardV23, CacheError> {
        self.begin_build_domain(
            nonce,
            Some(request_hash),
            "local-refund-build-proofs-v24",
            true,
        )
    }

    pub(crate) fn begin_local_refund_read_v24(
        &self,
        nonce: [u8; 32],
        request_hash: [u8; 32],
    ) -> Result<BuildGuardV23, CacheError> {
        self.begin_build_domain(
            nonce,
            Some(request_hash),
            "local-refund-build-proofs-v24",
            false,
        )
    }

    pub(crate) fn lookup_local_refund_v24(
        &self,
        nonce: [u8; 32],
    ) -> Result<BuildGuardV23, CacheError> {
        self.begin_build_domain(nonce, None, "local-refund-build-proofs-v24", false)
    }

    fn begin_build_domain(
        &self,
        nonce: [u8; 32],
        request_hash: Option<[u8; 32]>,
        domain: &str,
        create: bool,
    ) -> Result<BuildGuardV23, CacheError> {
        if nonce == [0; 32] || request_hash == Some([0; 32]) || (create && request_hash.is_none()) {
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
        let directory = self.directory.join(domain);
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => fs::File::open(&self.directory)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|_| CacheError::Unavailable)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(CacheError::Unavailable),
            }
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
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(|_| CacheError::Unavailable)?;
        require_file(&lock)?;
        lock.try_lock_exclusive()
            .map_err(|_| CacheError::Unavailable)?;
        // Read the original identity only after obtaining the existing lock.
        // Lookup never creates a scope, lock, directory, issued marker or plan.
        let scope = read_private_file(&directory.join(format!("{stem}.scope")), 32)?;
        let retained_hash = match (scope, request_hash) {
            (Some(scope), expected) => {
                let actual: [u8; 32] = scope.try_into().map_err(|_| CacheError::Corrupt)?;
                if actual == [0; 32] || expected.is_some_and(|value| value != actual) {
                    return Err(CacheError::Conflict);
                }
                actual
            }
            (None, Some(expected)) if create => expected,
            _ => return Err(CacheError::Unavailable),
        };
        let guard = BuildGuardV23 {
            _lock: lock,
            directory,
            stem,
            request_hash: retained_hash,
        };
        match guard.read("scope", 32)? {
            Some(scope) if scope.as_slice() == retained_hash.as_slice() => {}
            Some(_) => return Err(CacheError::Conflict),
            None if create => guard.publish("scope", &retained_hash)?,
            None => return Err(CacheError::Unavailable),
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
        read_private_file(&self.path(suffix), bound)
    }

    pub(crate) fn request_hash_v24(&self) -> [u8; 32] {
        self.request_hash
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
}

fn read_private_file(path: &std::path::Path, bound: usize) -> Result<Option<Vec<u8>>, CacheError> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
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

impl BuildGuardV23 {
    pub(crate) fn load_ready(&self) -> Result<Option<Response>, CacheError> {
        self.load_ready_typed(|response: &Response| {
            response
                .validate_framing()
                .map_err(|_| CacheError::Corrupt)?;
            Ok(response.sweep.request_nonce)
        })
    }

    pub(crate) fn load_local_ready(
        &self,
        scope: &[u8],
        auth: &crate::auth::AuthKey,
    ) -> Result<Option<LocalResponse>, CacheError> {
        self.load_local_ready_mode(scope, auth, true)
    }

    /// PUBLIC LOAD: no plan access, decryption, randomness, RPC or publication.
    pub(crate) fn load_public_local_ready_v24(
        &self,
        scope: &[u8],
        auth: &crate::auth::AuthKey,
    ) -> Result<Option<LocalResponse>, CacheError> {
        self.load_local_ready_mode(scope, auth, false)
    }

    fn load_local_ready_mode(
        &self,
        scope: &[u8],
        auth: &crate::auth::AuthKey,
        finish_build_publication: bool,
    ) -> Result<Option<LocalResponse>, CacheError> {
        let Some(bytes) = self.read("ready", MAX_READY)? else {
            return if self.read("issued", 32)?.is_some() {
                Err(CacheError::Corrupt)
            } else {
                Ok(None)
            };
        };
        let issued = self.read("issued", 32)?;
        let digest = SweepCache::request_hash(&bytes);
        match &issued {
            Some(value) if value.as_slice() == digest.as_slice() => {}
            Some(_) => return Err(CacheError::Corrupt),
            None if !finish_build_publication => return Err(CacheError::Unavailable),
            None => {}
        }
        let ready: LocalReadyV24 =
            serde_json::from_slice(&bytes).map_err(|_| CacheError::Corrupt)?;
        let response_bytes =
            serde_json::to_vec(&ready.response).map_err(|_| CacheError::Corrupt)?;
        let tag =
            auth.local_refund_ready_tag_v24(&self.request_hash, &ready.scope, &response_bytes);
        if tag
            .iter()
            .zip(ready.tag)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            != 0
            || ready.scope
                != ready
                    .response
                    .public_scope
                    .canonical_bytes()
                    .map_err(|_| CacheError::Corrupt)?
            || ready
                .response
                .public_scope
                .request
                .canonical_auth_bytes()
                .map_err(|_| CacheError::Corrupt)?
                != scope
            || ready.response.cache_request_hash != self.request_hash
            || hex::encode(ready.response.sweep.request_nonce) != self.stem
        {
            return Err(CacheError::Corrupt);
        }
        let context = ready
            .response
            .validate_framing()
            .map_err(|_| CacheError::Corrupt)?;
        if ready.response.sweep.api_version != crate::wire::API_VERSION_V2
            || ready.response.sweep.request_nonce != ready.response.effect_id
            || ready.response.sweep.tx_hash != context.sweep_tx
            || ready.response.sweep.raw_tx.is_empty()
            || ready.response.sweep.raw_tx.len() > crate::wire::MAX_RAW_TX_BYTES
        {
            return Err(CacheError::Corrupt);
        }
        if issued.is_none() {
            // Only an explicit BUILD may finish its interrupted publication.
            self.publish("issued", &digest)?;
        }
        Ok(Some(ready.response))
    }

    fn load_ready_typed<T: serde::de::DeserializeOwned>(
        &self,
        validate: impl FnOnce(&T) -> Result<[u8; 32], CacheError>,
    ) -> Result<Option<T>, CacheError> {
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
        let response: T = serde_json::from_slice(&bytes).map_err(|_| CacheError::Corrupt)?;
        if hex::encode(validate(&response)?) != self.stem {
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
        response
            .validate_framing()
            .map_err(|_| CacheError::Corrupt)?;
        self.store_ready_typed(response)
    }

    pub(crate) fn store_local_ready(
        &self,
        response: &LocalResponse,
        scope: &[u8],
        auth: &crate::auth::AuthKey,
    ) -> Result<(), CacheError> {
        response
            .validate_framing()
            .map_err(|_| CacheError::Corrupt)?;
        if response.cache_request_hash != self.request_hash
            || scope.is_empty()
            || scope.len() > 4096
            || hex::encode(response.sweep.request_nonce) != self.stem
        {
            return Err(CacheError::Corrupt);
        }
        if response
            .public_scope
            .request
            .canonical_auth_bytes()
            .map_err(|_| CacheError::Corrupt)?
            != scope
        {
            return Err(CacheError::Corrupt);
        }
        let full_scope = response
            .public_scope
            .canonical_bytes()
            .map_err(|_| CacheError::Corrupt)?;
        let response_bytes = serde_json::to_vec(response).map_err(|_| CacheError::Corrupt)?;
        let ready = LocalReadyV24 {
            scope: full_scope.clone(),
            response: response.clone(),
            tag: auth.local_refund_ready_tag_v24(&self.request_hash, &full_scope, &response_bytes),
        };
        self.store_ready_typed(&ready)
    }

    fn store_ready_typed(&self, response: &impl serde::Serialize) -> Result<(), CacheError> {
        if self.read("plan", MAX_PLAN + 64)?.is_none() {
            return Err(CacheError::Corrupt);
        }
        let bytes = serde_json::to_vec(response).map_err(|_| CacheError::Corrupt)?;
        if bytes.len() > MAX_READY {
            return Err(CacheError::Corrupt);
        }
        self.publish("ready", &bytes)?;
        self.publish("issued", &SweepCache::request_hash(&bytes))
    }
}
