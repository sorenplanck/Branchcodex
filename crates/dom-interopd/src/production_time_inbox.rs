//! Capability-relative transport for signed live time evidence. Reading is
//! not authentication: the retained time store verifies the candidate next.
use crate::supervisor::AuthorityRefusalV1;
use cap_std::fs::{Dir, MetadataExt as _, OpenOptions, OpenOptionsExt as _};
use route_time_anchor::SignedRouteTimeEvidenceV2;
use std::{
    io::{ErrorKind, Read},
    os::unix::fs::MetadataExt as _,
    sync::Arc,
};

pub(crate) const TIME_REFRESH_FILE_V5: &str = "route-time-refresh.v2";
const MAX_REFRESH_BYTES: u64 = 16_384;

/// Retains the authenticated state-directory capability. Construction does
/// no I/O, so a broken feed cannot prevent startup solely for recovery.
pub(crate) struct ProductionTimeEvidenceInboxV5 {
    root: Arc<Dir>,
}
impl core::fmt::Debug for ProductionTimeEvidenceInboxV5 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProductionTimeEvidenceInboxV5([redacted])")
    }
}
impl ProductionTimeEvidenceInboxV5 {
    pub(crate) fn new(root: Arc<Dir>) -> Self {
        Self { root }
    }

    /// Missing means no refresh, never funding authorization. A malformed
    /// present file is refused. NONBLOCK avoids waiting on a raced-in FIFO.
    pub(crate) fn read_candidate(
        &self,
    ) -> Result<Option<SignedRouteTimeEvidenceV2>, AuthorityRefusalV1> {
        let before = match self.root.symlink_metadata(TIME_REFRESH_FILE_V5) {
            Ok(value) => value,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AuthorityRefusalV1::Unavailable),
        };
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.nlink() != 1
            || before.mode() & 0o7777 != 0o600
            || before.uid() != rustix::process::geteuid().as_raw()
            || before.len() == 0
            || before.len() > MAX_REFRESH_BYTES
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
        let mut file = self
            .root
            .open_with(TIME_REFRESH_FILE_V5, &options)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?
            .into_std();
        let opened = file
            .metadata()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if !opened.is_file()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.nlink() != 1
            || opened.uid() != before.uid()
            || opened.mode() & 0o7777 != 0o600
            || opened.len() != before.len()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.by_ref()
            .take(MAX_REFRESH_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let after = file
            .metadata()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let named = self
            .root
            .symlink_metadata(TIME_REFRESH_FILE_V5)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if bytes.len() as u64 != opened.len()
            || bytes.len() as u64 > MAX_REFRESH_BYTES
            || after.len() != opened.len()
            || after.mtime() != opened.mtime()
            || after.mtime_nsec() != opened.mtime_nsec()
            || after.ctime() != opened.ctime()
            || after.ctime_nsec() != opened.ctime_nsec()
            || after.nlink() != 1
            || named.file_type().is_symlink()
            || !named.is_file()
            || named.dev() != after.dev()
            || named.ino() != after.ino()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        SignedRouteTimeEvidenceV2::decode(&bytes)
            .map(Some)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)
    }
}
