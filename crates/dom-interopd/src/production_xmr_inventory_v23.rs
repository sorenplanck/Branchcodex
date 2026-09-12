//! Durable, fail-closed ownership of an independent Mainnet XMR inventory output.
//!
//! The public descriptor is not funding authority: it carries only exact raw
//! provenance and route/public-wallet bindings. Spend/view scalars remain in
//! the existing encrypted XMR share Store and are released only under the
//! descriptor-derived AEAD associated data. Reopening never initializes a
//! file, row, wallet, or network resource.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use xmr_actuator::XmrObservationPortV1 as _;
use xmr_live_sidecar_api::VerifyFundingRequestV2;
use xmr_secret_store::{
    EncryptedSqliteSecretStore, SecretMaterialStore, SecretStoreMasterKey, XmrSecretMaterial,
};
use xmr_spend_port::FundingVerifyPort as _;
use zeroize::Zeroizing;

pub(crate) const NATIVE_XMR_INVENTORY_DESCRIPTOR_V23: &str =
    "native-xmr-inventory-authority-v23.bin";
const MAGIC: &[u8; 8] = b"XMRINV23";
const VERSION: u16 = 23;
const PREFIX_BYTES: usize = 356;
const MAX_DESTINATION_BYTES: usize = 256;
const MAX_BYTES: usize =
    PREFIX_BYTES + MAX_DESTINATION_BYTES + xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES + 32;
const MAX_PREPARE_INPUT_BYTES: u64 =
    (xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES as u64) * 2 + 16_384;

pub const PREPARE_XMR_INVENTORY_USAGE_V23: &str =
    "usage: dom-interopd prepare-xmr-inventory-v23 --state-dir ABSOLUTE_PRIVATE_DIRECTORY --secret-store ABSOLUTE_EXISTING_SQLITE\n       Read one strict JSON object from non-terminal stdin. The object imports (never generates) an independent Mainnet wallet spend scalar, view scalar, Store master key, exact funding raw/txid/economics, route_funding_tx_hashes_hex as the two selected XMR funding txids, and the public route/network/session/terms/solver/genesis scope. It writes no chain data and never broadcasts.";

#[derive(Debug, thiserror::Error)]
pub enum PrepareXmrInventoryErrorV23 {
    #[error("XMR inventory preparation requires an operational production artifact")]
    Artifact,
    #[error("XMR inventory input must arrive through non-terminal standard input")]
    Terminal,
    #[error("XMR inventory preparation input refused")]
    Input,
    #[error("XMR inventory preparation directory or Store refused")]
    Storage,
    #[error("XMR inventory descriptor conflicts with retained custody")]
    Conflict,
}

#[derive(Debug, Serialize)]
pub struct PreparedXmrInventoryReportV23 {
    pub schema: &'static str,
    pub funding_tx_hash: String,
    pub output_index: u32,
    pub spend_public_key: String,
    pub destination: String,
    pub amount_piconero: u64,
    pub max_fee_piconero: u64,
    pub descriptor_file: &'static str,
    pub broadcast: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInputV23<'a> {
    schema: String,
    network_id_hex: String,
    route_id_hex: String,
    session_ids_hex: [String; 2],
    terms_digests_hex: [String; 2],
    solver_id_hex: String,
    mainnet_genesis_hex: String,
    funding_tx_hash_hex: String,
    route_funding_tx_hashes_hex: Vec<String>,
    amount_piconero: u64,
    max_fee_piconero: u64,
    #[serde(borrow)]
    funding_raw_hex: &'a str,
    #[serde(borrow)]
    spend_scalar_hex: &'a str,
    #[serde(borrow)]
    view_scalar_hex: &'a str,
    #[serde(borrow)]
    store_master_key_hex: &'a str,
}

/// Offline import only. The raw transaction must already exist and no RPC,
/// wallet, broadcast, deployment or L1 operation is reachable from this path.
pub fn prepare_xmr_inventory_command_v23(
    state_dir: &Path,
    secret_store: &Path,
) -> core::result::Result<PreparedXmrInventoryReportV23, PrepareXmrInventoryErrorV23> {
    use std::io::IsTerminal as _;
    crate::require_operational_artifact_v1().map_err(|_| PrepareXmrInventoryErrorV23::Artifact)?;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(PrepareXmrInventoryErrorV23::Terminal);
    }
    let bytes = bounded_prepare_input(stdin.lock())?;
    prepare_xmr_inventory_from_bytes_v23(state_dir, secret_store, &bytes)
}

fn bounded_prepare_input(
    mut input: impl std::io::Read,
) -> core::result::Result<Zeroizing<Vec<u8>>, PrepareXmrInventoryErrorV23> {
    let capacity = usize::try_from(MAX_PREPARE_INPUT_BYTES)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(PrepareXmrInventoryErrorV23::Input)?;
    let mut bytes = Zeroizing::new(vec![0; capacity]);
    let mut length = 0usize;
    while length < bytes.len() {
        match input.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(count) => length = length.saturating_add(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PrepareXmrInventoryErrorV23::Input),
        }
    }
    if length == 0 || u64::try_from(length).unwrap_or(u64::MAX) > MAX_PREPARE_INPUT_BYTES {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn prepare_xmr_inventory_from_bytes_v23(
    state_dir: &Path,
    secret_store: &Path,
    bytes: &[u8],
) -> core::result::Result<PreparedXmrInventoryReportV23, PrepareXmrInventoryErrorV23> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if bytes.contains(&b'\\') {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    let input: PrepareInputV23<'_> =
        serde_json::from_slice(bytes).map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    if input.schema != "DOM-XMR-INVENTORY-PREPARE-V23"
        || input.amount_piconero == 0
        || input.max_fee_piconero == 0
        || input.funding_raw_hex.is_empty()
        || input.funding_raw_hex.len() % 2 != 0
        || input.funding_raw_hex.len()
            > xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES.saturating_mul(2)
        || input.route_funding_tx_hashes_hex.len() != 2
    {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    let state_metadata =
        std::fs::symlink_metadata(state_dir).map_err(|_| PrepareXmrInventoryErrorV23::Storage)?;
    let store_metadata = std::fs::symlink_metadata(secret_store)
        .map_err(|_| PrepareXmrInventoryErrorV23::Storage)?;
    if !state_dir.is_absolute()
        || !secret_store.is_absolute()
        || std::fs::canonicalize(state_dir).ok().as_deref() != Some(state_dir)
        || std::fs::canonicalize(secret_store).ok().as_deref() != Some(secret_store)
        || !secret_store.starts_with(state_dir)
        || !state_metadata.is_dir()
        || state_metadata.file_type().is_symlink()
        || state_metadata.uid() != rustix::process::getuid().as_raw()
        || state_metadata.permissions().mode() & 0o077 != 0
        || !store_metadata.is_file()
        || store_metadata.file_type().is_symlink()
        || store_metadata.nlink() != 1
        || store_metadata.uid() != rustix::process::getuid().as_raw()
        || store_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PrepareXmrInventoryErrorV23::Storage);
    }
    let network_id = decode_public_32(&input.network_id_hex)?;
    let route_id = decode_public_32(&input.route_id_hex)?;
    let sessions = [
        decode_public_32(&input.session_ids_hex[0])?,
        decode_public_32(&input.session_ids_hex[1])?,
    ];
    let terms = [
        decode_public_32(&input.terms_digests_hex[0])?,
        decode_public_32(&input.terms_digests_hex[1])?,
    ];
    let authority_id = decode_public_32(&input.solver_id_hex)?;
    let genesis = decode_public_32(&input.mainnet_genesis_hex)?;
    let tx_hash = decode_public_32(&input.funding_tx_hash_hex)?;
    let route_funding = input
        .route_funding_tx_hashes_hex
        .iter()
        .map(|value| decode_public_32(value))
        .collect::<core::result::Result<Vec<_>, _>>()?;
    validate_prepare_scope_v23(genesis, sessions, terms, &route_funding, tx_hash)?;
    let spend = decode_secret_32(input.spend_scalar_hex)?;
    let view = decode_secret_32(input.view_scalar_hex)?;
    let master = decode_secret_32(input.store_master_key_hex)?;
    if *spend == *view || *spend == *master || *view == *master {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    let raw = decode_secret_hex(input.funding_raw_hex)?;
    let spend_public = xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)
        .and_then(|value| value.public_share())
        .map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let destination = xmr_raw_tx_verify::standard_funding_address_v12(1, spend_public, &view)
        .map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let owned = xmr_raw_tx_verify::derive_owned_funding_key_image_v23(
        &raw,
        tx_hash,
        &spend,
        &view,
        input.amount_piconero,
        input.max_fee_piconero,
    )
    .map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let descriptor = DescriptorV23 {
        network_id,
        route_id,
        sessions,
        terms,
        authority_id,
        genesis,
        tx_hash,
        spend_public,
        amount_piconero: input.amount_piconero,
        max_fee_piconero: input.max_fee_piconero,
        output_index: owned.funding().output_index(),
        destination: destination.clone(),
        raw,
    };
    let descriptor_bytes = descriptor
        .encode()
        .map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let (record_id, binding) =
        custody_ids(&descriptor).map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let material =
        XmrSecretMaterial::new(*spend, *view).map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    let store = EncryptedSqliteSecretStore::open_existing(
        secret_store,
        SecretStoreMasterKey::new(*master).map_err(|_| PrepareXmrInventoryErrorV23::Input)?,
    )
    .map_err(|_| PrepareXmrInventoryErrorV23::Storage)?;
    store
        .insert(record_id, binding, &material, &mut rand::thread_rng())
        .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
    let restored = store
        .load(&record_id, &binding)
        .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
    authenticate_material(&descriptor, &restored)
        .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
    publish_descriptor_no_replace(state_dir, &descriptor_bytes)?;
    Ok(PreparedXmrInventoryReportV23 {
        schema: "DOM-XMR-INVENTORY-PREPARED-V23",
        funding_tx_hash: input.funding_tx_hash_hex,
        output_index: descriptor.output_index,
        spend_public_key: encode_hex(&spend_public),
        destination,
        amount_piconero: input.amount_piconero,
        max_fee_piconero: input.max_fee_piconero,
        descriptor_file: NATIVE_XMR_INVENTORY_DESCRIPTOR_V23,
        broadcast: false,
    })
}

fn validate_prepare_scope_v23(
    genesis: [u8; 32],
    sessions: [[u8; 32]; 2],
    terms: [[u8; 32]; 2],
    route_funding: &[[u8; 32]],
    inventory_tx: [u8; 32],
) -> core::result::Result<(), PrepareXmrInventoryErrorV23> {
    if genesis != crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23
        || sessions[0] == sessions[1]
        || terms[0] == terms[1]
        || route_funding.len() != 2
        || route_funding[0] == route_funding[1]
        || route_funding.contains(&[0; 32])
        || route_funding.contains(&inventory_tx)
    {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    Ok(())
}

fn publish_descriptor_no_replace(
    state_dir: &Path,
    bytes: &[u8],
) -> core::result::Result<(), PrepareXmrInventoryErrorV23> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let final_path = state_dir.join(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23);
    if final_path.exists() {
        let retained = crate::production_config::read_owner_file_bounded(
            &final_path,
            u64::try_from(MAX_BYTES).map_err(|_| PrepareXmrInventoryErrorV23::Storage)?,
            crate::production_config::ProductionConfigErrorV1::InvalidPublicBinding,
        )
        .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
        return if retained == bytes {
            Ok(())
        } else {
            Err(PrepareXmrInventoryErrorV23::Conflict)
        };
    }
    let staging = state_dir.join(".native-xmr-inventory-authority-v23.preparing");
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging);
    match opened {
        Ok(mut file) => file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| PrepareXmrInventoryErrorV23::Storage)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let retained = crate::production_config::read_owner_file_bounded(
                &staging,
                u64::try_from(MAX_BYTES).map_err(|_| PrepareXmrInventoryErrorV23::Storage)?,
                crate::production_config::ProductionConfigErrorV1::InvalidPublicBinding,
            )
            .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
            if retained != bytes {
                return Err(PrepareXmrInventoryErrorV23::Conflict);
            }
        }
        Err(_) => return Err(PrepareXmrInventoryErrorV23::Storage),
    }
    match std::fs::hard_link(&staging, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let retained = crate::production_config::read_owner_file_bounded(
                &final_path,
                u64::try_from(MAX_BYTES).map_err(|_| PrepareXmrInventoryErrorV23::Storage)?,
                crate::production_config::ProductionConfigErrorV1::InvalidPublicBinding,
            )
            .map_err(|_| PrepareXmrInventoryErrorV23::Conflict)?;
            if retained != bytes {
                return Err(PrepareXmrInventoryErrorV23::Conflict);
            }
        }
        Err(_) => return Err(PrepareXmrInventoryErrorV23::Storage),
    }
    std::fs::File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PrepareXmrInventoryErrorV23::Storage)?;
    match std::fs::remove_file(&staging) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrepareXmrInventoryErrorV23::Storage),
    }
    std::fs::File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PrepareXmrInventoryErrorV23::Storage)
}

fn decode_public_32(value: &str) -> core::result::Result<[u8; 32], PrepareXmrInventoryErrorV23> {
    Ok(*decode_secret_32(value)?)
}

fn decode_secret_32(
    value: &str,
) -> core::result::Result<Zeroizing<[u8; 32]>, PrepareXmrInventoryErrorV23> {
    if value.len() != 64 {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    let decoded = decode_secret_hex(value)?;
    let value: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| PrepareXmrInventoryErrorV23::Input)?;
    if value == [0; 32] {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    Ok(Zeroizing::new(value))
}

fn decode_secret_hex(
    value: &str,
) -> core::result::Result<Zeroizing<Vec<u8>>, PrepareXmrInventoryErrorV23> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PrepareXmrInventoryErrorV23::Input);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let digit = |byte| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        output.push(digit(pair[0]) * 16 + digit(pair[1]));
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionXmrInventoryErrorV23 {
    #[error("XMR inventory descriptor unavailable")]
    Unavailable,
    #[error("XMR inventory descriptor or route binding refused")]
    Binding,
    #[error("XMR inventory encrypted custody refused")]
    Custody,
    #[error("XMR inventory ownership proof refused")]
    Ownership,
    #[error("XMR inventory quorum evidence unavailable")]
    Quorum,
}

type Result<T> = core::result::Result<T, ProductionXmrInventoryErrorV23>;

pub(crate) struct NativeF6XmrInventoryExpectedV23 {
    pub(crate) network_id: [u8; 32],
    pub(crate) route_id: [u8; 32],
    pub(crate) sessions: [[u8; 32]; 2],
    pub(crate) terms: [[u8; 32]; 2],
    pub(crate) authority_id: [u8; 32],
    pub(crate) genesis: [u8; 32],
    pub(crate) chain_id: [u8; 32],
    pub(crate) asset_id: [u8; 32],
    pub(crate) amount_piconero: u64,
    pub(crate) max_fee_piconero: u64,
    pub(crate) min_confirmations: u64,
    pub(crate) route_funding_tx_hashes: Vec<[u8; 32]>,
    pub(crate) max_age_seconds: u64,
}

struct DescriptorV23 {
    network_id: [u8; 32],
    route_id: [u8; 32],
    sessions: [[u8; 32]; 2],
    terms: [[u8; 32]; 2],
    authority_id: [u8; 32],
    genesis: [u8; 32],
    tx_hash: [u8; 32],
    spend_public: [u8; 32],
    amount_piconero: u64,
    max_fee_piconero: u64,
    output_index: u32,
    destination: String,
    raw: Zeroizing<Vec<u8>>,
}

impl DescriptorV23 {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PREFIX_BYTES + 32
            || bytes.len() > MAX_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        let payload_end = bytes
            .len()
            .checked_sub(32)
            .ok_or(ProductionXmrInventoryErrorV23::Binding)?;
        let expected = digest(
            b"DOM/PRODUCTION/XMR-INVENTORY-DESCRIPTOR/V23\0",
            &[&bytes[..payload_end]],
        )?;
        if bytes[payload_end..] != expected {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        let mut cursor = Cursor { bytes, at: 10 };
        let network_id = cursor.array()?;
        let route_id = cursor.array()?;
        let sessions = [cursor.array()?, cursor.array()?];
        let terms = [cursor.array()?, cursor.array()?];
        let authority_id = cursor.array()?;
        let genesis = cursor.array()?;
        let tx_hash = cursor.array()?;
        let spend_public = cursor.array()?;
        let amount_piconero = cursor.u64()?;
        let max_fee_piconero = cursor.u64()?;
        let output_index = cursor.u32()?;
        let destination_len = usize::from(cursor.u16()?);
        let raw_len =
            usize::try_from(cursor.u32()?).map_err(|_| ProductionXmrInventoryErrorV23::Binding)?;
        if destination_len == 0
            || destination_len > MAX_DESTINATION_BYTES
            || raw_len == 0
            || raw_len > xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES
            || cursor
                .at
                .checked_add(destination_len)
                .and_then(|value| value.checked_add(raw_len))
                != Some(payload_end)
        {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        let destination = std::str::from_utf8(cursor.take(destination_len)?)
            .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?
            .to_owned();
        let raw = Zeroizing::new(cursor.take(raw_len)?.to_vec());
        let value = Self {
            network_id,
            route_id,
            sessions,
            terms,
            authority_id,
            genesis,
            tx_hash,
            spend_public,
            amount_piconero,
            max_fee_piconero,
            output_index,
            destination,
            raw,
        };
        if value.encode()? != bytes {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        Ok(value)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if [
            self.network_id,
            self.route_id,
            self.sessions[0],
            self.sessions[1],
            self.terms[0],
            self.terms[1],
            self.authority_id,
            self.genesis,
            self.tx_hash,
            self.spend_public,
        ]
        .contains(&[0; 32])
            || self.sessions[0] == self.sessions[1]
            || self.terms[0] == self.terms[1]
            || self.amount_piconero == 0
            || self.max_fee_piconero == 0
            || self.destination.is_empty()
            || !self.destination.is_ascii()
            || self.destination.len() > MAX_DESTINATION_BYTES
            || self.raw.is_empty()
            || self.raw.len() > xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES
        {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        let mut bytes =
            Vec::with_capacity(PREFIX_BYTES + self.destination.len() + self.raw.len() + 32);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        for value in [
            self.network_id,
            self.route_id,
            self.sessions[0],
            self.sessions[1],
            self.terms[0],
            self.terms[1],
            self.authority_id,
            self.genesis,
            self.tx_hash,
            self.spend_public,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.amount_piconero.to_be_bytes());
        bytes.extend_from_slice(&self.max_fee_piconero.to_be_bytes());
        bytes.extend_from_slice(&self.output_index.to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.destination.len())
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.raw.len())
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.destination.as_bytes());
        bytes.extend_from_slice(&self.raw);
        let checksum = digest(b"DOM/PRODUCTION/XMR-INVENTORY-DESCRIPTOR/V23\0", &[&bytes])?;
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn require_expected(&self, expected: &NativeF6XmrInventoryExpectedV23) -> Result<()> {
        if self.network_id != expected.network_id
            || self.route_id != expected.route_id
            || self.sessions != expected.sessions
            || self.terms != expected.terms
            || self.authority_id != expected.authority_id
            || self.genesis != expected.genesis
            || self.genesis != crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23
            || self.amount_piconero != expected.amount_piconero
            || expected.route_funding_tx_hashes.contains(&self.tx_hash)
            || expected.route_funding_tx_hashes.is_empty()
            || expected.route_funding_tx_hashes.contains(&[0; 32])
            || expected
                .route_funding_tx_hashes
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || self.max_fee_piconero == 0
            || self.max_fee_piconero > expected.max_fee_piconero
            || expected.min_confirmations == 0
            || expected.max_age_seconds == 0
            || expected.chain_id == [0; 32]
            || expected.asset_id == [0; 32]
        {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        Ok(())
    }
}

/// Reopened production source. It retains no V4 bytes and has no method that
/// can sign or broadcast; the only terminal product is a public F6 match token.
pub(crate) struct NativeF6XmrInventorySourceV23 {
    descriptor: DescriptorV23,
    store: EncryptedSqliteSecretStore,
    record_id: [u8; 32],
    binding: [u8; 32],
    sidecar: xmr_live_sidecar_uds_client::BlockingUdsSidecarPort,
    observation: crate::production_children::QuorumXmrObservationPortV1,
    expected: NativeF6XmrInventoryExpectedV23,
}

pub(crate) struct NativeF6XmrInventoryOpenV23 {
    pub(crate) state_dir: PathBuf,
    pub(crate) secret_store: PathBuf,
    pub(crate) sidecar_socket: PathBuf,
    pub(crate) sidecar_timeout_ms: u64,
    pub(crate) local_store_key: Zeroizing<[u8; 32]>,
    pub(crate) sidecar_auth: Zeroizing<[u8; 32]>,
    pub(crate) observation: crate::production_children::QuorumXmrObservationPortV1,
    pub(crate) expected: NativeF6XmrInventoryExpectedV23,
}

impl NativeF6XmrInventorySourceV23 {
    /// Reopen only. Both files and the exact AEAD row must already exist.
    pub(crate) fn reopen(request: NativeF6XmrInventoryOpenV23) -> Result<Self> {
        if !request.state_dir.is_absolute()
            || !request.secret_store.starts_with(&request.state_dir)
            || !request.sidecar_socket.starts_with(&request.state_dir)
            || request.sidecar_timeout_ms == 0
            || request.sidecar_timeout_ms > 180_000
            || *request.local_store_key == [0; 32]
            || *request.sidecar_auth == [0; 32]
            || *request.local_store_key == *request.sidecar_auth
        {
            return Err(ProductionXmrInventoryErrorV23::Binding);
        }
        let descriptor_path = request.state_dir.join(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23);
        let bytes = crate::production_config::read_owner_file_bounded(
            &descriptor_path,
            u64::try_from(MAX_BYTES).map_err(|_| ProductionXmrInventoryErrorV23::Binding)?,
            crate::production_config::ProductionConfigErrorV1::InvalidPublicBinding,
        )
        .map_err(|_| ProductionXmrInventoryErrorV23::Unavailable)?;
        let descriptor = DescriptorV23::decode(&bytes)?;
        descriptor.require_expected(&request.expected)?;
        let (record_id, binding) = custody_ids(&descriptor)?;
        let store = EncryptedSqliteSecretStore::open_existing(
            &request.secret_store,
            SecretStoreMasterKey::new(*request.local_store_key)
                .map_err(|_| ProductionXmrInventoryErrorV23::Custody)?,
        )
        .map_err(|_| ProductionXmrInventoryErrorV23::Custody)?;
        let material = store
            .load(&record_id, &binding)
            .map_err(|_| ProductionXmrInventoryErrorV23::Custody)?;
        let owned = authenticate_material(&descriptor, &material)?;
        if owned.funding().output_index() != descriptor.output_index {
            return Err(ProductionXmrInventoryErrorV23::Ownership);
        }
        let sidecar = xmr_live_sidecar_uds_client::BlockingUdsSidecarPort::with_timeout(
            request.sidecar_socket,
            xmr_sidecar_auth::SidecarAuthKey::new(*request.sidecar_auth)
                .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?,
            std::time::Duration::from_millis(request.sidecar_timeout_ms),
        )
        .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?;
        Ok(Self {
            descriptor,
            store,
            record_id,
            binding,
            sidecar,
            observation: request.observation,
            expected: request.expected,
        })
    }

    /// Authenticate sidecar ownership, exact independent quorum bytes,
    /// canonical inclusion/finality and absence of the owned key image.
    pub(crate) fn observe(mut self) -> Result<ProductionXmrInventoryVerifiedV23> {
        let material = self
            .store
            .load(&self.record_id, &self.binding)
            .map_err(|_| ProductionXmrInventoryErrorV23::Custody)?;
        let owned = authenticate_material(&self.descriptor, &material)?;
        let nonce = digest(
            b"DOM/PRODUCTION/XMR-INVENTORY-SIDECAR/V23\0",
            &[
                &self.expected.network_id,
                &self.expected.route_id,
                &self.expected.sessions[0],
                &self.expected.sessions[1],
                &self.descriptor.tx_hash,
            ],
        )?;
        material.expose(|_, view| {
            let request = VerifyFundingRequestV2 {
                api_version: xmr_live_sidecar_api::API_VERSION_V2,
                request_nonce: nonce,
                settlement_id: self.expected.sessions[0],
                funding_tx_hash: self.descriptor.tx_hash,
                expected_amount_piconero: self.descriptor.amount_piconero,
                expected_spend_public_key: self.descriptor.spend_public,
                view_scalar: xmr_live_sidecar_api::SecretScalarBytes::new(*view),
                auth_tag: [0; 32],
            };
            let response = self
                .sidecar
                .verify_funding(request)
                .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?;
            if response.api_version != xmr_live_sidecar_api::API_VERSION_V2
                || response.request_nonce != nonce
                || response.funding_tx_hash != self.descriptor.tx_hash
                || response.received_amount_piconero != self.descriptor.amount_piconero
                || !response.spendable
                || response.event_index != self.descriptor.output_index
            {
                return Err(ProductionXmrInventoryErrorV23::Ownership);
            }
            Ok(())
        })?;
        let quorum_raw = self
            .observation
            .authenticated_funding_raw_v23(self.descriptor.tx_hash)
            .map_err(|_| ProductionXmrInventoryErrorV23::Quorum)?;
        if quorum_raw.as_slice() != self.descriptor.raw.as_slice() {
            return Err(ProductionXmrInventoryErrorV23::Quorum);
        }
        let inclusion = self
            .observation
            .transaction_inclusion(self.descriptor.tx_hash)
            .map_err(|_| ProductionXmrInventoryErrorV23::Quorum)?
            .ok_or(ProductionXmrInventoryErrorV23::Quorum)?;
        if inclusion.confirmations < self.expected.min_confirmations
            || self
                .observation
                .key_image_spent(owned.key_image())
                .map_err(|_| ProductionXmrInventoryErrorV23::Quorum)?
        {
            return Err(ProductionXmrInventoryErrorV23::Quorum);
        }
        let evidence_digest = digest(
            b"DOM/PRODUCTION/XMR-INVENTORY-EVIDENCE/V23\0",
            &[
                &self.expected.network_id,
                &self.expected.route_id,
                &self.expected.sessions[0],
                &self.expected.sessions[1],
                &self.expected.terms[0],
                &self.expected.terms[1],
                &self.expected.genesis,
                &self.descriptor.tx_hash,
                &owned.funding().transaction().raw_fingerprint,
                &self.descriptor.output_index.to_be_bytes(),
                &owned.output_key(),
                &owned.key_image(),
                &self.descriptor.amount_piconero.to_be_bytes(),
                &owned.funding().fee_piconero().to_be_bytes(),
                &inclusion.height.to_be_bytes(),
                &inclusion.block_hash,
            ],
        )?;
        Ok(ProductionXmrInventoryVerifiedV23 {
            chain_id: self.expected.chain_id,
            asset_id: self.expected.asset_id,
            authority_id: self.expected.authority_id,
            amount_piconero: self.descriptor.amount_piconero,
            height: inclusion.height,
            block_hash: inclusion.block_hash,
            evidence_digest,
            observed_at: std::time::Instant::now(),
            max_age: std::time::Duration::from_secs(self.expected.max_age_seconds),
        })
    }
}

/// Public-only token binding the signed F6 artifact to the live observation.
pub(crate) struct ProductionXmrInventoryVerifiedV23 {
    chain_id: [u8; 32],
    asset_id: [u8; 32],
    authority_id: [u8; 32],
    amount_piconero: u64,
    height: u64,
    block_hash: [u8; 32],
    evidence_digest: [u8; 32],
    observed_at: std::time::Instant,
    max_age: std::time::Duration,
}

impl ProductionXmrInventoryVerifiedV23 {
    pub(crate) fn matches(&self, value: &solver_inventory::InventoryObservationV1) -> bool {
        self.observed_at.elapsed() <= self.max_age
            && value.key.chain_id.0 == self.chain_id
            && value.key.asset_id.0 == self.asset_id
            && value.key.authority_id.0 == self.authority_id
            && value.spendable_amount == u128::from(self.amount_piconero)
            && value.canonical_height == self.height
            && value.canonical_anchor_digest == self.block_hash
            && value.evidence_digest == self.evidence_digest
    }
}

fn authenticate_material(
    descriptor: &DescriptorV23,
    material: &XmrSecretMaterial,
) -> Result<xmr_raw_tx_verify::VerifiedOwnedFundingKeyImageV23> {
    material.expose(|spend, view| {
        let public = xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)
            .and_then(|value| value.public_share())
            .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?;
        let destination =
            xmr_raw_tx_verify::standard_funding_address_v12(1, descriptor.spend_public, view)
                .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?;
        if public != descriptor.spend_public || destination != descriptor.destination {
            return Err(ProductionXmrInventoryErrorV23::Ownership);
        }
        let owned = xmr_raw_tx_verify::derive_owned_funding_key_image_v23(
            &descriptor.raw,
            descriptor.tx_hash,
            spend,
            view,
            descriptor.amount_piconero,
            descriptor.max_fee_piconero,
        )
        .map_err(|_| ProductionXmrInventoryErrorV23::Ownership)?;
        if owned.funding().transaction().tx_hash != descriptor.tx_hash
            || owned.funding().output_index() != descriptor.output_index
            || owned.funding().amount_piconero() != descriptor.amount_piconero
            || owned.funding().fee_piconero() > descriptor.max_fee_piconero
        {
            return Err(ProductionXmrInventoryErrorV23::Ownership);
        }
        Ok(owned)
    })
}

fn custody_ids(descriptor: &DescriptorV23) -> Result<([u8; 32], [u8; 32])> {
    let record = digest(
        b"DOM/PRODUCTION/XMR-INVENTORY-CUSTODY-RECORD/V23\0",
        &[
            &descriptor.network_id,
            &descriptor.route_id,
            &descriptor.sessions[0],
            &descriptor.sessions[1],
            &descriptor.tx_hash,
            &descriptor.output_index.to_be_bytes(),
        ],
    )?;
    let binding = digest(
        b"DOM/PRODUCTION/XMR-INVENTORY-CUSTODY-BINDING/V23\0",
        &[
            &descriptor.network_id,
            &descriptor.route_id,
            &descriptor.sessions[0],
            &descriptor.sessions[1],
            &descriptor.terms[0],
            &descriptor.terms[1],
            &descriptor.authority_id,
            &descriptor.genesis,
            &descriptor.tx_hash,
            &descriptor.spend_public,
            &descriptor.amount_piconero.to_be_bytes(),
            &descriptor.max_fee_piconero.to_be_bytes(),
            &descriptor.output_index.to_be_bytes(),
            descriptor.destination.as_bytes(),
        ],
    )?;
    Ok((record, binding))
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut hash = Blake2bVar::new(32).map_err(|_| ProductionXmrInventoryErrorV23::Binding)?;
    hash.update(domain);
    for part in parts {
        hash.update(
            &u64::try_from(part.len())
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?
                .to_be_bytes(),
        );
        hash.update(part);
    }
    let mut value = [0; 32];
    hash.finalize_variable(&mut value)
        .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?;
    if value == [0; 32] {
        return Err(ProductionXmrInventoryErrorV23::Binding);
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8]> {
        let end = self
            .at
            .checked_add(length)
            .ok_or(ProductionXmrInventoryErrorV23::Binding)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(ProductionXmrInventoryErrorV23::Binding)?;
        self.at = end;
        Ok(value)
    }
    fn array(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| ProductionXmrInventoryErrorV23::Binding)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?,
        ))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ProductionXmrInventoryErrorV23::Binding)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hex_is_strict_lowercase_and_nonzero_for_keys() {
        assert!(decode_secret_32(&"01".repeat(32)).is_ok());
        assert!(decode_secret_32(&"00".repeat(32)).is_err());
        assert!(decode_secret_32(&"AA".repeat(32)).is_err());
        assert!(decode_secret_32("01").is_err());
    }

    #[test]
    fn descriptor_codec_rejects_trailing_or_mutated_bytes() {
        let value = DescriptorV23 {
            network_id: [1; 32],
            route_id: [2; 32],
            sessions: [[3; 32], [4; 32]],
            terms: [[5; 32], [6; 32]],
            authority_id: [7; 32],
            genesis: crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23,
            tx_hash: [8; 32],
            spend_public: [9; 32],
            amount_piconero: 10,
            max_fee_piconero: 11,
            output_index: 0,
            destination: "mainnet-public-destination".to_owned(),
            raw: Zeroizing::new(vec![12]),
        };
        let bytes = value.encode().expect("bounded public descriptor");
        assert!(DescriptorV23::decode(&bytes).is_ok());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DescriptorV23::decode(&trailing).is_err());
        let mut mutated = bytes;
        mutated[42] ^= 1;
        assert!(DescriptorV23::decode(&mutated).is_err());
    }

    #[test]
    fn prepare_json_is_closed_and_bounded_before_any_store_open() {
        assert!(prepare_xmr_inventory_from_bytes_v23(
            Path::new("relative"),
            Path::new("relative.sqlite"),
            br#"{"schema":"DOM-XMR-INVENTORY-PREPARE-V23","unknown":true}"#,
        )
        .is_err());
        assert!(bounded_prepare_input(&b""[..]).is_err());
    }

    #[test]
    fn prepare_scope_requires_canonical_mainnet_and_exactly_two_route_funding_txids() {
        let genesis = crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23;
        let sessions = [[1; 32], [2; 32]];
        let terms = [[3; 32], [4; 32]];
        let funding = [[5; 32], [6; 32]];
        assert!(validate_prepare_scope_v23(genesis, sessions, terms, &funding, [7; 32]).is_ok());
        assert!(
            validate_prepare_scope_v23(genesis, sessions, terms, &funding[..1], [7; 32]).is_err()
        );
        assert!(validate_prepare_scope_v23([9; 32], sessions, terms, &funding, [7; 32]).is_err());
        assert!(
            validate_prepare_scope_v23(genesis, sessions, terms, &funding, funding[0]).is_err()
        );
    }

    #[test]
    fn descriptor_publication_retry_is_idempotent_and_never_replaces() {
        let directory = tempfile::tempdir().expect("private directory");
        let bytes = b"authenticated-public-descriptor";
        publish_descriptor_no_replace(directory.path(), bytes).expect("first publication");
        publish_descriptor_no_replace(directory.path(), bytes).expect("resume publication");
        assert!(publish_descriptor_no_replace(directory.path(), b"divergent").is_err());
        assert_eq!(
            std::fs::read(directory.path().join(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23))
                .expect("retained descriptor"),
            bytes
        );
    }

    #[test]
    fn expired_local_token_cannot_match_the_preflight_observation() {
        let token = ProductionXmrInventoryVerifiedV23 {
            chain_id: [1; 32],
            asset_id: [2; 32],
            authority_id: [3; 32],
            amount_piconero: 4,
            height: 5,
            block_hash: [6; 32],
            evidence_digest: [7; 32],
            observed_at: std::time::Instant::now() - std::time::Duration::from_secs(2),
            max_age: std::time::Duration::from_secs(1),
        };
        let observation = solver_inventory::InventoryObservationV1 {
            key: solver_inventory::InventoryKeyV1 {
                chain_id: rfq::ChainId([1; 32]),
                asset_id: rfq::AssetId([2; 32]),
                authority_id: rfq::ParticipantId([3; 32]),
            },
            spendable_amount: 4,
            canonical_height: 5,
            canonical_anchor_digest: [6; 32],
            evidence_digest: [7; 32],
            registry_manifest_digest: [8; 32],
            profile_bundle_digest: [9; 32],
            asset_binding_digest: [10; 32],
            observed_at_unix_ms: 11,
            valid_until_unix_ms: 12,
            acknowledged_consumption_sequence: 0,
            kind: solver_inventory::InventoryObservationKindV1::Forward,
        };
        assert!(!token.matches(&observation));
    }
}
