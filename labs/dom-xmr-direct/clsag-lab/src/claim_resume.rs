//! Encoding helpers for pinned claim recovery artifacts. A digest must come
//! from the original approved operation, not from the file being loaded.
//! These records contain no signing secrets but reveal the real ring member
//! and transaction linkage. Keep them private to the participants.

use sha2::{Digest, Sha256};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DXP1/claim-resume/record/v1");
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

pub(crate) fn checked<'a>(bytes: &'a [u8], expected: [u8; 32], magic: &[u8]) -> Option<&'a [u8]> {
    if expected == [0; 32] || bytes.len() > MAX_RECORD_BYTES || digest(bytes) != expected {
        return None;
    }
    bytes.strip_prefix(magic)
}

pub(crate) fn take<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = bytes.split_at_checked(N)?;
    *bytes = tail;
    head.try_into().ok()
}
