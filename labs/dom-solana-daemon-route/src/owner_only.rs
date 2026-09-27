//! Every path this bootstrap creates, with the permissions the daemon requires.
//!
//! `dom-interopd` validates its whole layout before reading any of it: every
//! directory must be exactly `0o700` and every file exactly `0o600`, neither may be a
//! symlink, a file must have exactly one link, and both must be owned by the effective
//! uid. `deployment-registry` applies the same two modes to the registry database and
//! the directory holding it. A path that misses either is refused with
//! `InvalidStorageAuthority` or the layout's own error, and the refusal is right: an
//! artifact another account can read or replace is not authority.
//!
//! `std::fs::create_dir_all` creates `0o777 & !umask`, which on a CI runner is `0o755`
//! -- group- and world-readable. That is what refused the first registry the
//! provisioner tried to install. `std::fs::write` is the same story for files. So no
//! module here calls either one directly; they all come through this one.
//!
//! The mode is set twice on purpose, exactly as the daemon's own writer does it: once
//! as the creating mode so the path is never briefly wider than it should be, and once
//! afterwards because a umask can only remove bits from the mode a create requests.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// `0o700`, as both `dom-interopd` and `deployment-registry` require of a directory.
pub const DIRECTORY_MODE: u32 = 0o700;
/// `0o600`, as both require of a file.
pub const FILE_MODE: u32 = 0o600;

/// Create a directory and every missing parent, owner-only at each level.
///
/// An existing directory is left in place but its mode is corrected, because the
/// daemon checks the directory it will read and not the one this call created.
pub fn directory(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIRECTORY_MODE)
        .create(path)
        .map_err(|error| format!("directory {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|error| format!("directory mode {}: {error}", path.display()))
}

/// Write one new artifact, owner-only, refusing to replace an existing one.
///
/// Refusing replacement is deliberate: an artifact is pinned by its digest, so
/// overwriting one silently would leave a bootstrap whose pins name bytes that are no
/// longer there. A provisioner that means to start over removes the state directory.
pub fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        directory(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(FILE_MODE);
    let mut file = options
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    use std::io::Write as _;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))?;
    drop(file);
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|error| format!("file mode {}: {error}", path.display()))
}
