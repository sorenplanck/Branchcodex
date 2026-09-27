//! Immutable local operation checkpoint for the owned-node recovery experiment.
//! A checksum detects damage, not hostile local replacement or backup rollback.
//! The caller supplies the original operation ID and protects the directory.
//! The RPC credential and transaction linkage must remain participant-private.

use crate::claim_resume::{checked, digest, take};

const MAGIC: &[u8] = b"DXP1/operation-checkpoint/v1\0";
const MANIFEST: &[u8] = b"DXP1/claim-manifest/v2\0";

#[derive(Clone, PartialEq, Eq)]
pub struct OperationCheckpoint {
    pub operation: [u8; 32],
    pub manifest: [u8; 32],
    pub dom_chain: [u8; 32],
    pub dom_genesis: [u8; 32],
    pub xmr_genesis: [u8; 32],
    pub dom_port: u16,
    pub xmr_port: u16,
    pub dom_token: [u8; 32],
}

impl OperationCheckpoint {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if [
            self.operation,
            self.manifest,
            self.dom_chain,
            self.dom_genesis,
            self.xmr_genesis,
            self.dom_token,
        ]
        .contains(&[0; 32])
            || self.dom_port == 0
            || self.xmr_port == 0
            || self.dom_port == self.xmr_port
        {
            return None;
        }
        let mut bytes = MAGIC.to_vec();
        for field in [
            self.operation,
            self.manifest,
            self.dom_chain,
            self.dom_genesis,
            self.xmr_genesis,
            self.dom_token,
        ] {
            bytes.extend(field);
        }
        bytes.extend(self.dom_port.to_le_bytes());
        bytes.extend(self.xmr_port.to_le_bytes());
        bytes.extend(digest(&bytes));
        Some(bytes)
    }

    pub fn decode(bytes: &[u8], expected_operation: [u8; 32]) -> Option<Self> {
        let (body, checksum) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
        let mut input = checked(body, checksum.try_into().ok()?, MAGIC)?;
        let result = Self {
            operation: take(&mut input)?,
            manifest: take(&mut input)?,
            dom_chain: take(&mut input)?,
            dom_genesis: take(&mut input)?,
            xmr_genesis: take(&mut input)?,
            dom_token: take(&mut input)?,
            dom_port: u16::from_le_bytes(take(&mut input)?),
            xmr_port: u16::from_le_bytes(take(&mut input)?),
        };
        if !input.is_empty() || result.operation != expected_operation || result.encode()? != bytes
        {
            return None;
        }
        Some(result)
    }
}

/// Strict parser of the original manifest, including its unchanged timing
/// assumptions. Loading it never starts a new disclosure clock or initial gate.
pub struct ClaimManifest {
    pub operation: [u8; 32],
    pub xmr_record: [u8; 32],
    pub dom_record: [u8; 32],
    pub capsule: [u8; 64],
    pub candidates: u16,
    pub disclosed_at: u64,
    pub earliest_adversarial: u64,
    pub latest_honest: u64,
    pub dom_first: bool,
    pub xmr_resolution_secs: u64,
    pub observation_secs: u64,
    pub dom_resolution_secs: u64,
}

impl ClaimManifest {
    pub fn decode(bytes: &[u8], checkpoint: &OperationCheckpoint) -> Option<Self> {
        let mut input = checked(bytes, checkpoint.manifest, MANIFEST)?;
        let result = Self {
            operation: take(&mut input)?,
            xmr_record: take(&mut input)?,
            dom_record: take(&mut input)?,
            capsule: take(&mut input)?,
            candidates: u16::from_le_bytes(take(&mut input)?),
            disclosed_at: u64::from_le_bytes(take(&mut input)?),
            earliest_adversarial: u64::from_le_bytes(take(&mut input)?),
            latest_honest: u64::from_le_bytes(take(&mut input)?),
            dom_first: match take::<1>(&mut input)?[0] {
                0 => false,
                1 => true,
                _ => return None,
            },
            xmr_resolution_secs: u64::from_le_bytes(take(&mut input)?),
            observation_secs: u64::from_le_bytes(take(&mut input)?),
            dom_resolution_secs: u64::from_le_bytes(take(&mut input)?),
        };
        if !input.is_empty()
            || result.operation != checkpoint.operation
            || result.xmr_record == [0; 32]
            || result.dom_record == [0; 32]
            || result.capsule == [0; 64]
            || result.candidates == 0
            || result.disclosed_at > result.earliest_adversarial
            || result.earliest_adversarial > result.latest_honest
        {
            return None;
        }
        Some(result)
    }

    /// Rebuild the ORIGINAL policy to check the durable exposure journal.
    /// This does not reopen the initial gate or authorize any new release.
    pub fn original_release_policy(
        &self,
        payload: &[u8],
    ) -> Option<crate::release_journal::ReleasePolicy> {
        use crate::time_bounds::{AssumedClaimDelays, AssumedXmrRecoveryWindow, InitialClaimOrder};
        use dom_core::Timestamp;
        let window = AssumedXmrRecoveryWindow::restore_original(
            self.capsule,
            self.candidates,
            Timestamp(self.disclosed_at),
            Timestamp(self.earliest_adversarial),
            Timestamp(self.latest_honest),
        )
        .ok()?;
        crate::release_journal::ReleasePolicy::new(
            self.operation,
            &window,
            if self.dom_first {
                InitialClaimOrder::DomFirst
            } else {
                InitialClaimOrder::XmrFirst
            },
            AssumedClaimDelays {
                xmr_resolution_secs: self.xmr_resolution_secs,
                observation_secs: self.observation_secs,
                dom_resolution_secs: self.dom_resolution_secs,
            },
            crate::release_journal::claim_digest(payload),
        )
        .ok()
    }
}
