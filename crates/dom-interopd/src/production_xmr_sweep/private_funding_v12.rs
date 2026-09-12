//! Private funding bytes retain the exact owner-only inode across submission.
//! Startup imports and verifies the candidate again; no serialized flag can
//! replace destination, amount, hash, commitment and fee verification.

use fs2::FileExt;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use xmr_rpc_broadcast_blocking::PreparedPrivateFundingV12;
use zeroize::Zeroizing;

pub(super) struct RetainedPrivateFundingV12 {
    root: PathBuf,
    relative: String,
    file: File,
    device: u64,
    inode: u64,
    owner: u32,
    maximum: usize,
    candidate: PreparedPrivateFundingV12,
}

impl RetainedPrivateFundingV12 {
    pub(super) fn open(
        root: &Path,
        relative: &str,
        maximum: usize,
        tx_hash: [u8; 32],
        spend: [u8; 32],
        view: &[u8; 32],
        amount: u64,
        maximum_fee: u64,
    ) -> Result<Self, Refusal> {
        if maximum == 0
            || maximum > xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES
            || maximum_fee == 0
        {
            return Err(Refusal::Conflict);
        }
        let path =
            crate::production_universal_leg_authority::existing_resource(root, relative, false)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
        let mut file = options.open(path).map_err(|_| Refusal::Unavailable)?;
        file.try_lock_exclusive()
            .map_err(|_| Refusal::Unavailable)?;
        let metadata = file.metadata().map_err(|_| Refusal::Unavailable)?;
        let raw = read_private(&mut file, maximum)?;
        let candidate =
            PreparedPrivateFundingV12::import(raw, tx_hash, spend, view, amount, maximum_fee)
                .map_err(|_| Refusal::Conflict)?;
        let mut retained = Self {
            root: root.to_owned(),
            relative: relative.to_owned(),
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            maximum,
            candidate,
        };
        retained.revalidate()?;
        // Ensure the exact candidate and its directory entry survive a crash
        // before the native custody intent and any network effect are emitted.
        retained.file.sync_all().map_err(|_| Refusal::Unavailable)?;
        let path =
            crate::production_universal_leg_authority::existing_resource(root, relative, false)?;
        File::open(path.parent().ok_or(Refusal::Conflict)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Refusal::Unavailable)?;
        Ok(retained)
    }

    pub(super) fn candidate(&self) -> &PreparedPrivateFundingV12 {
        &self.candidate
    }

    pub(super) fn revalidate(&mut self) -> Result<(), Refusal> {
        let path = crate::production_universal_leg_authority::existing_resource(
            &self.root,
            &self.relative,
            false,
        )?;
        let named = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
        let retained = self.file.metadata().map_err(|_| Refusal::Unavailable)?;
        for metadata in [&named, &retained] {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.uid() != self.owner
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(Refusal::Conflict);
            }
        }
        let raw = Zeroizing::new(read_private(&mut self.file, self.maximum)?);
        if !self
            .candidate
            .with_raw(|expected| expected == raw.as_slice())
        {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }
}

fn read_private(file: &mut File, maximum: usize) -> Result<Vec<u8>, Refusal> {
    let length = file.metadata().map_err(|_| Refusal::Unavailable)?.len();
    if length == 0 || length > maximum as u64 {
        return Err(Refusal::Conflict);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Refusal::Unavailable)?;
    let mut raw = Zeroizing::new(Vec::with_capacity(length as usize));
    file.take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Refusal::Unavailable)?;
    if raw.len() != length as usize {
        return Err(Refusal::Conflict);
    }
    // Hand ownership to the candidate, which immediately wraps and zeroizes it.
    Ok(std::mem::take(&mut *raw))
}
