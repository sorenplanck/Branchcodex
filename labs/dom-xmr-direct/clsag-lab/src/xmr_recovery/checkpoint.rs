//! Private original local share and public recovery identity, persisted BEFORE
//! funding. No signing nonces, offsets or aggregate secret are serialized.
//! Trusted local storage is required: checksum is not authentication/rollback
//! protection. Loading neither verifies a capsule proof nor authorizes a send.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use curve25519_dalek::edwards::CompressedEdwardsY;

use super::*;
use crate::{capsule_checkpoint::CapsuleCheckpoint, claim_resume::take};

const MAGIC: &[u8] = b"DXP1/local-xmr-recovery/v1\0";
const PUBLIC_LEN: usize = MAGIC.len() + 32 + 64 + 2 + 32 + 8 + 8;
const RECORD_LEN: usize = PUBLIC_LEN + 32 + 32;

/// One local ORIGINAL share, never an offset share or two-party aggregate.
/// Deliberately no Debug/Clone implementation for the private record.
pub struct LocalXmrRecoveryCheckpoint {
    roster: XmrRecoveryRoster,
    local: Participant,
    secret: Zeroizing<Scalar>,
    capsule: [u8; 32],
    received: u64,
    work: u64,
}

impl LocalXmrRecoveryCheckpoint {
    /// The caller must independently accept the capsule before funding.
    pub fn new(
        roster: &XmrRecoveryRoster,
        local: &ThresholdKeys<Ed25519>,
        capsule: &CapsuleCheckpoint,
    ) -> Option<Self> {
        roster.check_original_keys(local).ok()?;
        let result = Self {
            roster: roster.clone(),
            local: local.params().i(),
            secret: local.original_secret_share().clone(),
            capsule: capsule.binding,
            received: capsule.received_unix_seconds,
            work: capsule.squarings,
        };
        result.check_capsule(capsule)?;
        Some(result)
    }

    fn peer(&self) -> Participant {
        Participant::new(3 - u16::from(self.local)).unwrap()
    }

    fn public_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(self.roster.reservation);
        for key in self.roster.keys {
            out.extend(key.compress().to_bytes());
        }
        out.extend(u16::from(self.local).to_le_bytes());
        out.extend(self.capsule);
        out.extend(self.received.to_le_bytes());
        out.extend(self.work.to_le_bytes());
        out
    }

    /// Approved public identity; caller retains this independently of the file.
    /// This digest contains no secret and is not a peer authentication scheme.
    pub fn binding(&self) -> [u8; 32] {
        Sha256::digest(self.public_bytes()).into()
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(self.public_bytes());
        let scalar = Zeroizing::new(self.secret.to_bytes());
        out.extend_from_slice(&*scalar);
        let checksum = Sha256::digest(&*out);
        out.extend_from_slice(&checksum);
        out
    }

    pub fn decode(bytes: &[u8], expected_identity: [u8; 32]) -> Option<Self> {
        if bytes.len() != RECORD_LEN || expected_identity == [0; 32] {
            return None;
        }
        let (body, checksum) = bytes.split_at(RECORD_LEN - 32);
        if Sha256::digest(body).as_slice() != checksum
            || <[u8; 32]>::from(Sha256::digest(&body[..PUBLIC_LEN])) != expected_identity
        {
            return None;
        }
        let mut input = body.strip_prefix(MAGIC)?;
        let reservation = take(&mut input)?;
        let mut keys = [G; 2];
        for key in &mut keys {
            let encoded = take(&mut input)?;
            *key = CompressedEdwardsY(encoded).decompress()?;
            if key.compress().to_bytes() != encoded {
                return None;
            }
        }
        let local = Participant::new(u16::from_le_bytes(take(&mut input)?))?;
        if !matches!(u16::from(local), 1 | 2) {
            return None;
        }
        let capsule = take(&mut input)?;
        let received = u64::from_le_bytes(take(&mut input)?);
        let work = u64::from_le_bytes(take(&mut input)?);
        let encoded = Zeroizing::new(take(&mut input)?);
        let secret = Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(
            *encoded,
        ))?);
        if !input.is_empty()
            || capsule == [0; 32]
            || received == 0
            || !matches!(work, 200_000 | 10_000_000)
        {
            return None;
        }
        let roster = XmrRecoveryRoster::new(reservation, keys).ok()?;
        if *secret * G != roster.share_key(local).ok()? {
            return None;
        }
        Some(Self {
            roster,
            local,
            secret,
            capsule,
            received,
            work,
        })
    }

    fn check_capsule(&self, capsule: &CapsuleCheckpoint) -> Option<()> {
        capsule.encode()?; // Codec/binding validation only; NOT proof acceptance.
        if capsule.binding != self.capsule
            || capsule.received_unix_seconds != self.received
            || capsule.squarings != self.work
            || capsule.context != self.roster.recovery_domain(self.peer()).ok()?
            || capsule.public
                != self
                    .roster
                    .share_key(self.peer())
                    .ok()?
                    .compress()
                    .to_bytes()
        {
            return None;
        }
        Some(())
    }

    /// Restores original keys/link; no nonce, signing offset, timing policy or
    /// network authorization. Caller must check original policy and proof.
    pub fn restore(
        &self,
        capsule: &CapsuleCheckpoint,
    ) -> Option<(
        ThresholdKeys<Ed25519>,
        XmrRecoveryRoster,
        XmrDirectRecoveryLink,
    )> {
        self.check_capsule(capsule)?;
        let local = self.roster.restore(self.local, self.secret.clone()).ok()?;
        let link = XmrDirectRecoveryLink::new(
            &self.roster,
            self.peer(),
            capsule.context,
            self.roster.share_key(self.peer()).ok()?,
            capsule.binding,
        )
        .ok()?;
        Some((local, self.roster.clone(), link))
    }

    /// Caller establishes a durable private parent directory first. A partial
    /// write is never replaced/repaired by a subsequent invocation.
    pub fn write_new(&self, path: &Path) -> io::Result<()> {
        let bytes = self.encode();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(path.parent().ok_or_else(invalid)?)?.sync_all()
    }

    pub fn read(path: &Path, expected_identity: [u8; 32]) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != RECORD_LEN as u64
        {
            return Err(invalid());
        }
        // The directory is trusted; this is not protection from a hostile
        // local process replacing files between metadata and open.
        let file = File::open(path)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take((RECORD_LEN + 1) as u64).read_to_end(&mut bytes)?;
        Self::decode(&bytes, expected_identity).ok_or_else(invalid)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid local XMR recovery checkpoint",
    )
}
