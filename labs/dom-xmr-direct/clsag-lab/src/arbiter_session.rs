//! Durable ordering journal for one DXA1 DOM↔XMR operation.
//!
//! Recovery offers are fixed in the header before DOM funding. A claim offer
//! can be recorded only after both the DOM funding and the confirmed, usable
//! XMR reserve have been recorded. Every transition is append-only, chained,
//! locked and synced. Chain observations still have to be independently
//! reconciled by the caller after restart.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use dom_consensus::{SwapArbiterContract, SwapArbiterPath, Transaction};
use dom_core::{
    BlockHeight, KERNEL_FEAT_SWAP_CLAIM, KERNEL_FEAT_SWAP_PUNISH, KERNEL_FEAT_SWAP_REFUND,
    SWAP_ARBITER_CONTRACT_SIZE,
};
use dom_serialization::DomSerialize;
use sha2::{Digest, Sha256};

use crate::{
    arbiter_pair::VerifiedArbiterSharesV1, claim_resume::digest, native_dom::DomClaimOffer,
};

const MAGIC: &[u8] = b"DXA1/arbiter-session/v2\0";
const HEADER_BODY: usize =
    MAGIC.len() + 32 + 32 + 32 + SWAP_ARBITER_CONTRACT_SIZE + 32 + 32 + 32 + 33 + 8;
const HEADER: usize = HEADER_BODY + 32;
const MAX_FILE_BYTES: u64 = 4096;

#[derive(Debug)]
pub enum ArbiterSessionError {
    Io(io::Error),
    Locked,
    Binding,
    Corrupt,
    Denied,
    Poisoned,
}

impl From<io::Error> for ArbiterSessionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArbiterSessionBinding {
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    chain_id: [u8; 32],
    contract: [u8; SWAP_ARBITER_CONTRACT_SIZE],
    refund_offer: [u8; 32],
    punish_offer: [u8; 32],
    joint_xmr_key: [u8; 32],
    claim_adaptor: [u8; 33],
    max_dom_inclusion_blocks: u64,
}

impl ArbiterSessionBinding {
    pub fn new(
        chain_id: [u8; 32],
        contract: &SwapArbiterContract,
        shares: &VerifiedArbiterSharesV1,
        refund_offer: &DomClaimOffer,
        punish_offer: &DomClaimOffer,
        max_dom_inclusion_blocks: u64,
    ) -> Result<Self, ArbiterSessionError> {
        let refund_bytes = refund_offer
            .to_swap_arbiter_resume_bytes()
            .map_err(|_| ArbiterSessionError::Binding)?;
        let punish_bytes = punish_offer
            .to_swap_arbiter_resume_bytes()
            .map_err(|_| ArbiterSessionError::Binding)?;
        let result = Self {
            settlement_id: *shares.settlement_id(),
            context_hash: *shares.context_hash(),
            chain_id,
            contract: contract.to_bytes(),
            refund_offer: digest(&refund_bytes),
            punish_offer: digest(&punish_bytes),
            joint_xmr_key: shares
                .joint_xmr_spend_key()
                .map_err(|_| ArbiterSessionError::Binding)?,
            claim_adaptor: shares
                .adaptor_point(SwapArbiterPath::Claim)
                .map_err(|_| ArbiterSessionError::Binding)?
                .to_compressed_bytes(),
            max_dom_inclusion_blocks,
        };
        result.validate_offer(refund_offer, SwapArbiterPath::Refund, result.refund_offer)?;
        result.validate_offer(punish_offer, SwapArbiterPath::Punish, result.punish_offer)?;
        for (path, offer) in [
            (SwapArbiterPath::Refund, refund_offer),
            (SwapArbiterPath::Punish, punish_offer),
        ] {
            if offer.adaptor_point().to_compressed_bytes()
                != shares
                    .adaptor_point(path)
                    .map_err(|_| ArbiterSessionError::Binding)?
                    .to_compressed_bytes()
            {
                return Err(ArbiterSessionError::Binding);
            }
        }
        result.header()?;
        Ok(result)
    }

    fn contract(&self) -> Result<SwapArbiterContract, ArbiterSessionError> {
        SwapArbiterContract::from_bytes(&self.contract).map_err(|_| ArbiterSessionError::Binding)
    }

    fn validate_offer(
        &self,
        offer: &DomClaimOffer,
        path: SwapArbiterPath,
        expected_digest: [u8; 32],
    ) -> Result<(), ArbiterSessionError> {
        if offer.chain_id() != &self.chain_id
            || offer
                .swap_arbiter_path()
                .map_err(|_| ArbiterSessionError::Binding)?
                != path
            || offer
                .swap_arbiter_intent()
                .map_err(|_| ArbiterSessionError::Binding)?
                != self.contract()?.intent(path)
            || digest(
                &offer
                    .to_swap_arbiter_resume_bytes()
                    .map_err(|_| ArbiterSessionError::Binding)?,
            ) != expected_digest
        {
            return Err(ArbiterSessionError::Binding);
        }
        Ok(())
    }

    fn header(&self) -> Result<Vec<u8>, ArbiterSessionError> {
        if self.settlement_id == [0; 32]
            || self.context_hash == [0; 32]
            || self.chain_id == [0; 32]
            || self.refund_offer == [0; 32]
            || self.punish_offer == [0; 32]
            || self.refund_offer == self.punish_offer
            || self.joint_xmr_key == [0; 32]
            || self.max_dom_inclusion_blocks == 0
        {
            return Err(ArbiterSessionError::Binding);
        }
        self.contract()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.settlement_id);
        bytes.extend(self.context_hash);
        bytes.extend(self.chain_id);
        bytes.extend(self.contract);
        bytes.extend(self.refund_offer);
        bytes.extend(self.punish_offer);
        bytes.extend(self.joint_xmr_key);
        bytes.extend(self.claim_adaptor);
        bytes.extend(self.max_dom_inclusion_blocks.to_le_bytes());
        debug_assert_eq!(bytes.len(), HEADER_BODY);
        bytes.extend(Sha256::digest(&bytes));
        Ok(bytes)
    }

    pub fn joint_xmr_spend_key(&self) -> &[u8; 32] {
        &self.joint_xmr_key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainObservation {
    pub id: [u8; 32],
    pub height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomSettlement {
    pub path: SwapArbiterPath,
    pub transaction: ChainObservation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArbiterSessionState {
    pub dom_funding: Option<ChainObservation>,
    pub xmr_ready: Option<ChainObservation>,
    pub claim_offer: Option<[u8; 32]>,
    pub dom_release: Option<DomSettlement>,
    pub dom_settlement: Option<DomSettlement>,
    pub xmr_settlement: Option<[u8; 32]>,
}

pub struct ArbiterSessionJournal {
    file: File,
    binding: ArbiterSessionBinding,
    state: ArbiterSessionState,
    last_digest: [u8; 32],
    poisoned: bool,
}

fn open_file(path: &Path, create: bool) -> Result<File, ArbiterSessionError> {
    if !create {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(ArbiterSessionError::Corrupt);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(create)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => ArbiterSessionError::Locked,
        std::fs::TryLockError::Error(error) => ArbiterSessionError::Io(error),
    })?;
    Ok(file)
}

fn sync_parent(path: &Path) -> Result<(), ArbiterSessionError> {
    File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(ArbiterSessionError::Binding)?,
    )?
    .sync_all()?;
    Ok(())
}

fn event_payload_len(tag: u8) -> Option<usize> {
    match tag {
        1 | 2 => Some(40),
        3 | 6 => Some(32),
        4 | 5 => Some(41),
        _ => None,
    }
}

fn nonzero_observation(payload: &[u8]) -> Result<ChainObservation, ArbiterSessionError> {
    let id: [u8; 32] = payload[..32]
        .try_into()
        .map_err(|_| ArbiterSessionError::Corrupt)?;
    let height = u64::from_le_bytes(
        payload[32..40]
            .try_into()
            .map_err(|_| ArbiterSessionError::Corrupt)?,
    );
    if id == [0; 32] || height == 0 {
        return Err(ArbiterSessionError::Denied);
    }
    Ok(ChainObservation { id, height })
}

fn decode_path(value: u8) -> Result<SwapArbiterPath, ArbiterSessionError> {
    match value {
        1 => Ok(SwapArbiterPath::Claim),
        2 => Ok(SwapArbiterPath::Refund),
        3 => Ok(SwapArbiterPath::Punish),
        _ => Err(ArbiterSessionError::Corrupt),
    }
}

fn encode_path(path: SwapArbiterPath) -> u8 {
    match path {
        SwapArbiterPath::Claim => 1,
        SwapArbiterPath::Refund => 2,
        SwapArbiterPath::Punish => 3,
    }
}

impl ArbiterSessionJournal {
    pub fn create(
        path: &Path,
        binding: ArbiterSessionBinding,
    ) -> Result<Self, ArbiterSessionError> {
        let header = binding.header()?;
        let mut file = open_file(path, true)?;
        file.write_all(&header)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            file,
            binding,
            state: ArbiterSessionState::default(),
            last_digest: header[HEADER_BODY..].try_into().unwrap(),
            poisoned: false,
        })
    }

    pub fn open(path: &Path, binding: ArbiterSessionBinding) -> Result<Self, ArbiterSessionError> {
        let header = binding.header()?;
        let mut file = open_file(path, false)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE_BYTES as usize
            || bytes.len() < HEADER
            || bytes[..HEADER] != header
        {
            return Err(ArbiterSessionError::Corrupt);
        }
        let mut state = ArbiterSessionState::default();
        let mut previous: [u8; 32] = header[HEADER_BODY..].try_into().unwrap();
        let mut input = &bytes[HEADER..];
        while !input.is_empty() {
            let payload_len = event_payload_len(input[0]).ok_or(ArbiterSessionError::Corrupt)?;
            let event_len = 1 + payload_len;
            if input.len() < event_len + 32 {
                return Err(ArbiterSessionError::Corrupt);
            }
            let (event, rest) = input.split_at(event_len);
            let (checksum, rest) = rest.split_at(32);
            let mut hash = Sha256::new();
            hash.update(previous);
            hash.update(event);
            let calculated: [u8; 32] = hash.finalize().into();
            if checksum != calculated {
                return Err(ArbiterSessionError::Corrupt);
            }
            Self::apply_event(&binding, &mut state, event)
                .map_err(|_| ArbiterSessionError::Corrupt)?;
            previous = calculated;
            input = rest;
        }
        Ok(Self {
            file,
            binding,
            state,
            last_digest: previous,
            poisoned: false,
        })
    }

    pub fn state(&self) -> Result<ArbiterSessionState, ArbiterSessionError> {
        if self.poisoned {
            Err(ArbiterSessionError::Poisoned)
        } else {
            Ok(self.state)
        }
    }

    fn apply_event(
        binding: &ArbiterSessionBinding,
        state: &mut ArbiterSessionState,
        event: &[u8],
    ) -> Result<(), ArbiterSessionError> {
        let payload = &event[1..];
        match event[0] {
            1 if state.dom_funding.is_none() && *state == ArbiterSessionState::default() => {
                state.dom_funding = Some(nonzero_observation(payload)?);
            }
            2 if state.dom_funding.is_some()
                && state.xmr_ready.is_none()
                && state.dom_release.is_none()
                && state.dom_settlement.is_none() =>
            {
                state.xmr_ready = Some(nonzero_observation(payload)?);
            }
            3 if state.dom_funding.is_some()
                && state.xmr_ready.is_some()
                && state.claim_offer.is_none()
                && state.dom_release.is_none()
                && state.dom_settlement.is_none() =>
            {
                let value: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| ArbiterSessionError::Corrupt)?;
                if value == [0; 32] {
                    return Err(ArbiterSessionError::Denied);
                }
                state.claim_offer = Some(value);
            }
            4 if state.dom_funding.is_some()
                && state.dom_release.is_none()
                && state.dom_settlement.is_none() =>
            {
                let path = decode_path(payload[0])?;
                if path == SwapArbiterPath::Claim
                    && (state.xmr_ready.is_none() || state.claim_offer.is_none())
                {
                    return Err(ArbiterSessionError::Denied);
                }
                let transaction = nonzero_observation(&payload[1..])?;
                let contract = binding.contract()?;
                let last_bounded_height = transaction
                    .height
                    .checked_add(binding.max_dom_inclusion_blocks - 1)
                    .ok_or(ArbiterSessionError::Denied)?;
                let allowed = match path {
                    SwapArbiterPath::Claim => last_bounded_height <= contract.claim_until(),
                    SwapArbiterPath::Refund => {
                        transaction.height > contract.claim_until()
                            && last_bounded_height <= contract.refund_until()
                    }
                    SwapArbiterPath::Punish => transaction.height > contract.refund_until(),
                };
                if !allowed {
                    return Err(ArbiterSessionError::Denied);
                }
                state.dom_release = Some(DomSettlement { path, transaction });
            }
            5 if state.dom_release.is_some() && state.dom_settlement.is_none() => {
                let path = decode_path(payload[0])?;
                let transaction = nonzero_observation(&payload[1..])?;
                let released = state.dom_release.unwrap();
                let last_bounded_height = released
                    .transaction
                    .height
                    .checked_add(binding.max_dom_inclusion_blocks - 1)
                    .ok_or(ArbiterSessionError::Denied)?;
                if path != released.path
                    || transaction.id != released.transaction.id
                    || transaction.height < released.transaction.height
                    || transaction.height > last_bounded_height
                {
                    return Err(ArbiterSessionError::Denied);
                }
                state.dom_settlement = Some(DomSettlement { path, transaction });
            }
            6 if state.xmr_ready.is_some()
                && state.dom_settlement.is_some()
                && state.xmr_settlement.is_none() =>
            {
                let value: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| ArbiterSessionError::Corrupt)?;
                if value == [0; 32] {
                    return Err(ArbiterSessionError::Denied);
                }
                state.xmr_settlement = Some(value);
            }
            _ => return Err(ArbiterSessionError::Denied),
        }
        Ok(())
    }

    fn append(&mut self, event: Vec<u8>) -> Result<(), ArbiterSessionError> {
        self.state()?;
        let mut next = self.state;
        Self::apply_event(&self.binding, &mut next, &event)?;
        let mut hash = Sha256::new();
        hash.update(self.last_digest);
        hash.update(&event);
        let checksum: [u8; 32] = hash.finalize().into();
        self.poisoned = true;
        self.file.write_all(&event)?;
        self.file.write_all(&checksum)?;
        self.file.sync_all()?;
        self.state = next;
        self.last_digest = checksum;
        self.poisoned = false;
        Ok(())
    }

    pub fn record_dom_funding(
        &mut self,
        transaction: [u8; 32],
        height: u64,
    ) -> Result<(), ArbiterSessionError> {
        let mut event = vec![1];
        event.extend(transaction);
        event.extend(height.to_le_bytes());
        self.append(event)
    }

    pub fn record_xmr_ready(
        &mut self,
        output: [u8; 32],
        height: u64,
    ) -> Result<(), ArbiterSessionError> {
        let mut event = vec![2];
        event.extend(output);
        event.extend(height.to_le_bytes());
        self.append(event)
    }

    pub fn record_claim_ready(
        &mut self,
        offer: &DomClaimOffer,
    ) -> Result<[u8; 32], ArbiterSessionError> {
        let bytes = offer
            .to_swap_arbiter_resume_bytes()
            .map_err(|_| ArbiterSessionError::Binding)?;
        let offer_digest = digest(&bytes);
        self.binding
            .validate_offer(offer, SwapArbiterPath::Claim, offer_digest)?;
        if offer.adaptor_point().to_compressed_bytes() != self.binding.claim_adaptor {
            return Err(ArbiterSessionError::Binding);
        }
        let mut event = vec![3];
        event.extend(offer_digest);
        self.append(event)?;
        Ok(offer_digest)
    }

    fn validated_dom_transaction(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<(SwapArbiterPath, [u8; 32]), ArbiterSessionError> {
        let kernel = transaction
            .kernels
            .first()
            .ok_or(ArbiterSessionError::Binding)?;
        let path = match kernel.features {
            KERNEL_FEAT_SWAP_CLAIM => SwapArbiterPath::Claim,
            KERNEL_FEAT_SWAP_REFUND => SwapArbiterPath::Refund,
            KERNEL_FEAT_SWAP_PUNISH => SwapArbiterPath::Punish,
            _ => return Err(ArbiterSessionError::Binding),
        };
        self.binding
            .contract()?
            .validate_spend(transaction, BlockHeight(height))
            .map_err(|_| ArbiterSessionError::Binding)?;
        let transaction = *dom_crypto::blake2b_256(
            &transaction
                .to_bytes()
                .map_err(|_| ArbiterSessionError::Binding)?,
        )
        .as_bytes();
        Ok((path, transaction))
    }

    /// Persist the exact exposure before any network send. `target_height` is
    /// the earliest block for which the transaction is being submitted.
    pub fn record_dom_release(
        &mut self,
        transaction: &Transaction,
        target_height: u64,
    ) -> Result<[u8; 32], ArbiterSessionError> {
        let (path, transaction) = self.validated_dom_transaction(transaction, target_height)?;
        let mut event = vec![4, encode_path(path)];
        event.extend(transaction);
        event.extend(target_height.to_le_bytes());
        self.append(event)?;
        Ok(transaction)
    }

    /// Record canonical inclusion only when it matches the previously synced
    /// release and falls inside its declared bounded-inclusion margin.
    pub fn record_dom_settlement(
        &mut self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<[u8; 32], ArbiterSessionError> {
        let (path, transaction) = self.validated_dom_transaction(transaction, height)?;
        let mut event = vec![5, encode_path(path)];
        event.extend(transaction);
        event.extend(height.to_le_bytes());
        self.append(event)?;
        Ok(transaction)
    }

    pub fn record_xmr_settlement(
        &mut self,
        transaction: [u8; 32],
    ) -> Result<(), ArbiterSessionError> {
        let mut event = vec![6];
        event.extend(transaction);
        self.append(event)
    }
}
