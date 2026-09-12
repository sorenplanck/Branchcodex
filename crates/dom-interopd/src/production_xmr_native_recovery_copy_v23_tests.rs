//! Private bounded byte copies of quiescent test Stores; no hard-link snapshots.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    copy(source, destination, 0, &mut 8192, &mut (1024 * 1024 * 1024))
}
fn copy(
    source: &Path,
    destination: &Path,
    depth: usize,
    entries: &mut usize,
    remaining: &mut u64,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(source)?;
    if depth > 10
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
    {
        return Err("recovery copy directory scope".into());
    }
    std::fs::DirBuilder::new().mode(0o700).create(destination)?;
    for entry in std::fs::read_dir(source)? {
        *entries = entries.checked_sub(1).ok_or("copy entry budget")?;
        let entry = entry?;
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let named = std::fs::symlink_metadata(&path)?;
        if named.is_dir() {
            copy(&path, &target, depth + 1, entries, remaining)?;
            continue;
        }
        if !named.is_file()
            || named.file_type().is_symlink()
            || named.nlink() != 1
            || named.uid() != rustix::process::getuid().as_raw()
            || named.mode() & 0o7777 != 0o600
            || named.len() > 64 * 1024 * 1024
            || named.len() > *remaining
        {
            return Err("recovery copy file scope".into());
        }
        let mut input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        let opened = input.metadata()?;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.len() != named.len()
            || opened.nlink() != 1
        {
            return Err("recovery copy raced open".into());
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(target)?;
        let copied = std::io::copy(
            &mut std::io::Read::take(&mut input, named.len() + 1),
            &mut output,
        )?;
        let after = std::fs::symlink_metadata(&path)?;
        if copied != named.len()
            || after.dev() != named.dev()
            || after.ino() != named.ino()
            || after.len() != named.len()
            || after.mtime() != named.mtime()
            || after.mtime_nsec() != named.mtime_nsec()
            || after.nlink() != 1
        {
            return Err("recovery copy changed during read".into());
        }
        output.sync_all()?;
        *remaining -= copied;
    }
    let after = std::fs::symlink_metadata(source)?;
    if after.dev() != meta.dev() || after.ino() != meta.ino() {
        return Err("recovery directory changed".into());
    }
    std::fs::File::open(destination)?.sync_all()?;
    Ok(())
}
