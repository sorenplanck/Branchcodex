//! Immutable public capsule material for a cold verifier restart.
//! Loading this record never means the proof/setup have been verified: the
//! receiver MUST reverify both before opening unless a SEPARATE local verifier
//! acceptance capability authenticates the original setup and exact offer.
//! This codec alone supplies no such capability. Receipt time is local evidence,
//! not authenticated first disclosure. Requires trusted participant storage;
//! checksum and payload binding do not defend against hostile metadata rewrites.
//! The caller must establish a durable parent directory before write_new.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use sha2::{Digest, Sha256};

use crate::claim_resume::take;

const MAGIC: &[u8] = b"DXP1/direct-capsule-checkpoint/v2\0";
pub const MAX_CAPSULE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = MAX_CAPSULE_BYTES + 65536 + 256;

#[derive(Clone, PartialEq)]
pub struct CapsuleCheckpoint {
    pub context: [u8; 32],
    pub public: [u8; 32],
    pub binding: [u8; 32],
    pub received_unix_seconds: u64,
    pub squarings: u64,
    /// Original measurements, retained only for reporting; never deadlines.
    pub preparation_seconds: [f64; 3],
    /// Opaque Go setup. The fresh Go verifier must bind it to the offer; Rust
    /// must not parse arbitrary-precision proof numbers just to extract it.
    pub setup: String,
    pub payload: String,
}

impl CapsuleCheckpoint {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let point = CompressedEdwardsY(self.public).decompress()?;
        if self.context == [0; 32]
            || self.binding == [0; 32]
            || point.is_identity()
            || !point.is_torsion_free()
            || point.compress().to_bytes() != self.public
            || self.received_unix_seconds == 0
            || !matches!(self.squarings, 200_000 | 10_000_000)
            || self
                .preparation_seconds
                .iter()
                .any(|v| !v.is_finite() || *v < 0.0)
            || self.payload.is_empty()
            || self.setup.is_empty()
            || self.setup.len() > 65536
            || self.payload.len() >= MAX_CAPSULE_BYTES
            || self.payload.contains(['\r', '\n'])
            || <[u8; 32]>::from(Sha256::digest(self.payload.as_bytes())) != self.binding
        {
            return None;
        }
        let mut bytes = MAGIC.to_vec();
        for field in [self.context, self.public, self.binding] {
            bytes.extend(field);
        }
        bytes.extend(self.received_unix_seconds.to_le_bytes());
        bytes.extend(self.squarings.to_le_bytes());
        for seconds in self.preparation_seconds {
            bytes.extend(seconds.to_le_bytes());
        }
        bytes.extend((self.setup.len() as u32).to_le_bytes());
        bytes.extend(self.setup.as_bytes());
        bytes.extend((self.payload.len() as u32).to_le_bytes());
        bytes.extend(self.payload.as_bytes());
        bytes.extend(Sha256::digest(&bytes));
        Some(bytes)
    }

    /// expected_binding comes from the approved recovery link, not this file.
    /// This is a bounded codec, not cryptographic acceptance of the capsule.
    pub fn decode(bytes: &[u8], expected_binding: [u8; 32]) -> Option<Self> {
        if bytes.len() > MAX_RECORD_BYTES || expected_binding == [0; 32] {
            return None;
        }
        let (body, checksum) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
        if Sha256::digest(body).as_slice() != checksum {
            return None;
        }
        let mut input = body.strip_prefix(MAGIC)?;
        let context = take(&mut input)?;
        let public = take(&mut input)?;
        let binding = take(&mut input)?;
        let received_unix_seconds = u64::from_le_bytes(take(&mut input)?);
        let squarings = u64::from_le_bytes(take(&mut input)?);
        let preparation_seconds = [
            f64::from_le_bytes(take(&mut input)?),
            f64::from_le_bytes(take(&mut input)?),
            f64::from_le_bytes(take(&mut input)?),
        ];
        let setup_length = u32::from_le_bytes(take(&mut input)?) as usize;
        if setup_length > 65536 {
            return None;
        }
        let (raw_setup, rest) = input.split_at_checked(setup_length)?;
        let setup = std::str::from_utf8(raw_setup).ok()?.to_owned();
        input = rest;
        let length = u32::from_le_bytes(take(&mut input)?) as usize;
        if input.len() != length || binding != expected_binding {
            return None;
        }
        let result = Self {
            context,
            public,
            binding,
            received_unix_seconds,
            squarings,
            preparation_seconds,
            setup,
            payload: std::str::from_utf8(input).ok()?.to_owned(),
        };
        (result.encode()? == bytes).then_some(result)
    }

    pub fn write_new(&self, path: &Path) -> io::Result<()> {
        let bytes = self.encode().ok_or_else(invalid)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(path.parent().ok_or_else(invalid)?)?.sync_all()
    }

    pub fn read(path: &Path, expected_binding: [u8; 32]) -> io::Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take((MAX_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::decode(&bytes, expected_binding).ok_or_else(invalid)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid direct capsule checkpoint",
    )
}
