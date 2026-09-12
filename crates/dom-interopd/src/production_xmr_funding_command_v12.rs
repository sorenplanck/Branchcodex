//! Pre-admission private XMR funding construction. No broadcast authority enters.
//! One bounded JSON stdin request becomes owner-only durable candidate bytes and
//! a public binding report. The setup can pin that report's exact txid afterwards.

use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, MetadataExt as _, OpenOptions, OpenOptionsExt as _,
};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt as _;
use std::{
    ffi::OsString,
    fs::File,
    io::{IsTerminal, Read, Write},
    path::{Component, Path},
};
use xmr_raw_tx_verify::standard_funding_address_v12;
use xmr_rpc_broadcast_blocking::{
    BlockingPrivateFundingWalletV12, PreparedPrivateFundingV12, PrivateFundingErrorV12,
    PrivateFundingRequestV12,
};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 16_384;
const RAW_FILE: &str = "funding-candidate.raw";
const REPORT_FILE: &str = "funding-public.json";
const INTENT_FILE: &str = "request-public.json";
const SCHEMA: &str = "DOM-XMR-PRIVATE-FUNDING-V12";

/// Exact command usage. The request contains a view scalar, never a spend share.
pub const PREPARE_XMR_FUNDING_USAGE_V12: &str = "usage: dom-interopd prepare-xmr-funding-v12 --output-dir ABSOLUTE_PATH\n       Read one private JSON object from non-terminal stdin, then EOF (maximum 16384 bytes).\n       Fields: schema, wallet_rpc_url, network_tag, combined_spend_public_hex,\n               view_scalar_hex, amount_piconero, max_fee_piconero, account_index,\n               subaddr_indices, priority.\n       schema must be DOM-XMR-PRIVATE-FUNDING-V12.\n       The parent directory must already exist, belong to this user, and have mode 0700.\n       Creates funding-candidate.raw and funding-public.json with mode 0600.\n       Signs privately with do_not_relay=true; never broadcasts.";

/// Redacted failures do not echo stdin, wallet responses, credentials or raw bytes.
#[derive(Debug, thiserror::Error)]
pub enum PrepareXmrFundingCommandErrorV12 {
    /// A release production artifact is required before private input is read.
    #[error("private funding requires an operational production artifact")]
    Artifact,
    /// No interactive private-key prompt is supported.
    #[error("private funding JSON must arrive through non-terminal standard input")]
    Terminal,
    /// Bounded strict JSON input was rejected.
    #[error("invalid private funding JSON or input bound")]
    Input,
    /// A destination or retained staging directory already exists.
    #[error("funding output or staging already exists; inspect retained files before another wallet request")]
    AlreadyPresent,
    /// Parent directory is not the selected user's canonical owner-only directory.
    #[error("funding output parent must be a canonical owner-only directory")]
    Directory,
    /// Preserve staging after ambiguous creation or incomplete durable publication.
    #[error("private funding storage failed; preserve and inspect the output and .preparing-v12 staging directories")]
    Storage,
    /// Native wallet errors are already redacted and distinguish contradictions.
    #[error("{0}; preserve any .preparing-v12 staging directory before retrying")]
    Wallet(#[from] PrivateFundingErrorV12),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateJsonV12<'a> {
    schema: String,
    wallet_rpc_url: String,
    network_tag: u8,
    combined_spend_public_hex: String,
    // Borrow directly from zeroized input. No unprotected allocated secret String
    // survives a later unknown/duplicate-field deserialization failure.
    #[serde(borrow)]
    view_scalar_hex: &'a str,
    amount_piconero: u64,
    max_fee_piconero: u64,
    account_index: u32,
    subaddr_indices: Vec<u32>,
    priority: u8,
}

/// Public bindings only. File names are relative to the published output directory.
#[derive(Debug, Serialize)]
pub struct PreparedXmrFundingReportV12 {
    /// Stable report version.
    pub schema: &'static str,
    /// Exact privately prepared transaction hash, to pin in final XMR setup.
    pub funding_tx_hash: String,
    /// Domain-separated fingerprint of the exact raw bytes.
    pub raw_fingerprint: String,
    /// Raw-file name, containing a private signed broadcasting capability.
    pub candidate_file: &'static str,
    /// Network tag used to derive the funding address.
    pub network_tag: u8,
    /// Shared public spend key, not a private spend share.
    pub combined_spend_public_hex: String,
    /// Derived shared funding address, not the final sweep destination.
    pub funding_address: String,
    /// Exact independently verified principal.
    pub amount_piconero: u64,
    /// Exact independently decoded transaction fee.
    pub fee_piconero: u64,
    /// Unique shared funding output position.
    pub output_index: u32,
    /// False: this command neither broadcasts nor proves chain inclusion.
    pub broadcast: bool,
}

#[derive(Serialize)]
struct PublicIntentV12<'a> {
    schema: &'static str,
    network_tag: u8,
    combined_spend_public_hex: &'a str,
    funding_address: &'a str,
    amount_piconero: u64,
    max_fee_piconero: u64,
    account_index: u32,
    subaddr_indices: &'a [u32],
    priority: u8,
    do_not_relay: bool,
}

/// Real pre-admission command: strict private stdin, one wallet transfer, exact
/// independent economic verification, durable no-replace filesystem publication.
pub fn prepare_xmr_funding_command_v12(
    output_dir: &Path,
) -> Result<PreparedXmrFundingReportV12, PrepareXmrFundingCommandErrorV12> {
    crate::require_operational_artifact_v1()
        .map_err(|_| PrepareXmrFundingCommandErrorV12::Artifact)?;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(PrepareXmrFundingCommandErrorV12::Terminal);
    }
    let bytes = bounded_input(stdin.lock())?;
    execute(output_dir, &bytes)
}

fn bounded_input(
    mut input: impl Read,
) -> Result<Zeroizing<Vec<u8>>, PrepareXmrFundingCommandErrorV12> {
    // Allocate the complete bound before any secret arrives. Reading only into
    // existing slices cannot relocate/free an earlier unzeroized allocation.
    let mut bytes = Zeroizing::new(vec![0u8; MAX_INPUT_BYTES as usize + 1]);
    let mut length = 0;
    while length < bytes.len() {
        match input.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PrepareXmrFundingCommandErrorV12::Input),
        }
    }
    if length == 0 || length as u64 > MAX_INPUT_BYTES {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    bytes.truncate(length);
    Ok(bytes)
}
fn strict_json(bytes: &[u8]) -> Result<PrivateJsonV12<'_>, PrepareXmrFundingCommandErrorV12> {
    // No field needs JSON escapes. Refuse them before serde could allocate an
    // unzeroized scratch string while attempting to deserialize borrowed hex.
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES || bytes.contains(&b'\\') {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    let input: PrivateJsonV12<'_> =
        serde_json::from_slice(bytes).map_err(|_| PrepareXmrFundingCommandErrorV12::Input)?;
    if input.schema != SCHEMA
        || input.wallet_rpc_url.len() > 1024
        || input.priority > 4
        || input.amount_piconero == 0
        || input.max_fee_piconero == 0
        || input.subaddr_indices.is_empty()
        || input.subaddr_indices.len() > 256
    {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    let unique: std::collections::BTreeSet<_> = input.subaddr_indices.iter().collect();
    if unique.len() != input.subaddr_indices.len() {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    decode_32(&input.combined_spend_public_hex)?;
    let _view = decode_32(input.view_scalar_hex)?;
    Ok(input)
}
fn decode_32(value: &str) -> Result<Zeroizing<[u8; 32]>, PrepareXmrFundingCommandErrorV12> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if *bytes == [0; 32] {
        return Err(PrepareXmrFundingCommandErrorV12::Input);
    }
    Ok(bytes)
}

fn execute(
    output_dir: &Path,
    bytes: &[u8],
) -> Result<PreparedXmrFundingReportV12, PrepareXmrFundingCommandErrorV12> {
    let input = strict_json(bytes)?;
    let spend = *decode_32(&input.combined_spend_public_hex)?;
    let view = decode_32(input.view_scalar_hex)?;
    let address = standard_funding_address_v12(input.network_tag, spend, &view)
        .map_err(|_| PrepareXmrFundingCommandErrorV12::Input)?;
    let request = PrivateFundingRequestV12 {
        network_tag: input.network_tag,
        combined_spend_public: spend,
        amount_piconero: input.amount_piconero,
        max_fee_piconero: input.max_fee_piconero,
        account_index: input.account_index,
        subaddr_indices: input.subaddr_indices.clone(),
        priority: input.priority,
    };
    let wallet = BlockingPrivateFundingWalletV12::new(&input.wallet_rpc_url)?;
    // Durable public intent precedes the single private wallet operation. A
    // crash/timeout leaves a non-reusable staging path, never an automatic retry.
    let publication = PrivatePublicationV12::create(output_dir)?;
    let intent = PublicIntentV12 {
        schema: SCHEMA,
        network_tag: input.network_tag,
        combined_spend_public_hex: &input.combined_spend_public_hex,
        funding_address: &address,
        amount_piconero: input.amount_piconero,
        max_fee_piconero: input.max_fee_piconero,
        account_index: input.account_index,
        subaddr_indices: &input.subaddr_indices,
        priority: input.priority,
        do_not_relay: true,
    };
    publication.write_new(
        INTENT_FILE,
        &serde_json::to_vec_pretty(&intent)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?,
    )?;
    publication.sync_staging()?;
    let candidate = wallet.prepare(&request, &view)?;
    let report = report(&candidate, &request, address);
    candidate.with_raw(|raw| publication.write_new(RAW_FILE, raw))?;
    publication.write_new(
        REPORT_FILE,
        &serde_json::to_vec_pretty(&report)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?,
    )?;
    publication.publish()?;
    Ok(report)
}
fn report(
    candidate: &PreparedPrivateFundingV12,
    request: &PrivateFundingRequestV12,
    funding_address: String,
) -> PreparedXmrFundingReportV12 {
    let verified = candidate.verified();
    PreparedXmrFundingReportV12 {
        schema: SCHEMA,
        funding_tx_hash: encode_hex_32(verified.transaction().tx_hash),
        raw_fingerprint: encode_hex_32(verified.transaction().raw_fingerprint),
        candidate_file: RAW_FILE,
        network_tag: request.network_tag,
        combined_spend_public_hex: encode_hex_32(request.combined_spend_public),
        funding_address,
        amount_piconero: verified.amount_piconero(),
        fee_piconero: verified.fee_piconero(),
        output_index: verified.output_index(),
        broadcast: false,
    }
}
fn encode_hex_32(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in bytes {
        result.push(char::from(DIGITS[(byte >> 4) as usize]));
        result.push(char::from(DIGITS[(byte & 15) as usize]));
    }
    result
}

struct PrivatePublicationV12 {
    parent: Dir,
    staging: Dir,
    final_name: OsString,
    staging_name: OsString,
}
impl PrivatePublicationV12 {
    fn create(output: &Path) -> Result<Self, PrepareXmrFundingCommandErrorV12> {
        if !output.is_absolute()
            || output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(PrepareXmrFundingCommandErrorV12::Directory);
        }
        let final_name = output
            .file_name()
            .filter(|n| n.len() <= 200)
            .ok_or(PrepareXmrFundingCommandErrorV12::Directory)?
            .to_owned();
        let parent_path = output
            .parent()
            .ok_or(PrepareXmrFundingCommandErrorV12::Directory)?;
        if std::fs::canonicalize(parent_path)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Directory)?
            != parent_path
        {
            return Err(PrepareXmrFundingCommandErrorV12::Directory);
        }
        let before = std::fs::symlink_metadata(parent_path)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Directory)?;
        if !before.is_dir()
            || before.file_type().is_symlink()
            || before.mode() & 0o7777 != 0o700
            || before.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(PrepareXmrFundingCommandErrorV12::Directory);
        }
        let retained =
            File::open(parent_path).map_err(|_| PrepareXmrFundingCommandErrorV12::Directory)?;
        let after = retained
            .metadata()
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Directory)?;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.mode() != before.mode()
            || after.uid() != before.uid()
        {
            return Err(PrepareXmrFundingCommandErrorV12::Directory);
        }
        let parent = Dir::from_std_file(retained);
        let mut staging_name = final_name.clone();
        staging_name.push(".preparing-v12");
        require_absent(&parent, &final_name)?;
        require_absent(&parent, &staging_name)?;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(&staging_name, &builder)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    PrepareXmrFundingCommandErrorV12::AlreadyPresent
                } else {
                    PrepareXmrFundingCommandErrorV12::Storage
                }
            })?;
        sync_directory(&parent)?;
        let staging = parent
            .open_dir(&staging_name)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        let metadata = staging
            .dir_metadata()
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        if !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700 || metadata.uid() != before.uid()
        {
            return Err(PrepareXmrFundingCommandErrorV12::Directory);
        }
        Ok(Self {
            parent,
            staging,
            final_name,
            staging_name,
        })
    }
    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), PrepareXmrFundingCommandErrorV12> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = self
            .staging
            .open_with(name, &options)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        let metadata = file
            .metadata()
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        if !metadata.is_file()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(PrepareXmrFundingCommandErrorV12::Storage);
        }
        file.write_all(bytes)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        file.sync_all()
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        let named = self
            .staging
            .symlink_metadata(name)
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?;
        if named.file_type().is_symlink()
            || named.dev() != metadata.dev()
            || named.ino() != metadata.ino()
            || named.len() != bytes.len() as u64
            || named.nlink() != 1
        {
            return Err(PrepareXmrFundingCommandErrorV12::Storage);
        }
        Ok(())
    }
    fn sync_staging(&self) -> Result<(), PrepareXmrFundingCommandErrorV12> {
        sync_directory(&self.staging)
    }
    fn publish(self) -> Result<(), PrepareXmrFundingCommandErrorV12> {
        self.sync_staging()?;
        let parent_fd = self
            .parent
            .open(".")
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?
            .into_std();
        rustix::fs::renameat_with(
            &parent_fd,
            self.staging_name.as_os_str(),
            &parent_fd,
            self.final_name.as_os_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                PrepareXmrFundingCommandErrorV12::AlreadyPresent
            } else {
                PrepareXmrFundingCommandErrorV12::Storage
            }
        })?;
        parent_fd
            .sync_all()
            .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)
    }
}
fn require_absent(
    parent: &Dir,
    name: &std::ffi::OsStr,
) -> Result<(), PrepareXmrFundingCommandErrorV12> {
    match parent.symlink_metadata(name) {
        Ok(_) => Err(PrepareXmrFundingCommandErrorV12::AlreadyPresent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrepareXmrFundingCommandErrorV12::Storage),
    }
}
fn sync_directory(dir: &Dir) -> Result<(), PrepareXmrFundingCommandErrorV12> {
    dir.open(".")
        .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)?
        .into_std()
        .sync_all()
        .map_err(|_| PrepareXmrFundingCommandErrorV12::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn request() -> String {
        r#"{"schema":"DOM-XMR-PRIVATE-FUNDING-V12","wallet_rpc_url":"http://127.0.0.1:18083/","network_tag":2,"combined_spend_public_hex":"5866666666666666666666666666666666666666666666666666666666666666","view_scalar_hex":"0100000000000000000000000000000000000000000000000000000000000000","amount_piconero":100,"max_fee_piconero":10,"account_index":0,"subaddr_indices":[0],"priority":0}"#.to_owned()
    }
    fn private_parent() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn strict_input_rejects_spend_material_duplicate_keys_trailing_objects_and_limits() {
        let valid = request();
        assert!(strict_json(valid.as_bytes()).is_ok());
        for suffix in [
            ",\"spend_scalar_hex\":\"secret\"}",
            ",\"priority\":1}",
            ",\"view_scalar_hex\":\"00\"}",
        ] {
            let changed = format!("{}{suffix}", &valid[..valid.len() - 1]);
            assert!(strict_json(changed.as_bytes()).is_err());
        }
        assert!(strict_json(format!("{valid} {{}}").as_bytes()).is_err());
        assert!(strict_json(
            valid
                .replace("\"subaddr_indices\":[0]", "\"subaddr_indices\":[0,0]")
                .as_bytes()
        )
        .is_err());
        assert!(bounded_input(vec![b' '; MAX_INPUT_BYTES as usize + 1].as_slice()).is_err());
        assert!(bounded_input(&b""[..]).is_err());
        assert!(decode_32(&"AA".repeat(32)).is_err());
        assert!(decode_32(&"00".repeat(32)).is_err());
        let escaped = valid.replace(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "\\u0030100000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(strict_json(escaped.as_bytes()).is_err());
        let read = bounded_input(valid.as_bytes()).unwrap();
        assert_eq!(read.as_slice(), valid.as_bytes());
        assert_eq!(read.capacity(), MAX_INPUT_BYTES as usize + 1);
    }
    #[test]
    fn publication_keeps_exact_owner_only_bytes_and_never_overwrites() {
        let parent = private_parent();
        let output = parent.path().join("candidate");
        let publication = PrivatePublicationV12::create(&output).unwrap();
        publication
            .write_new(RAW_FILE, b"private-byte-custody-fixture")
            .unwrap();
        assert!(publication.write_new(RAW_FILE, b"replacement").is_err());
        publication
            .write_new(REPORT_FILE, b"{\"broadcast\":false}")
            .unwrap();
        assert!(!output.exists());
        publication.publish().unwrap();
        assert_eq!(
            std::fs::read(output.join(RAW_FILE)).unwrap(),
            b"private-byte-custody-fixture"
        );
        assert_eq!(std::fs::metadata(&output).unwrap().mode() & 0o7777, 0o700);
        for name in [RAW_FILE, REPORT_FILE] {
            let metadata = std::fs::metadata(output.join(name)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert!(matches!(
            PrivatePublicationV12::create(&output),
            Err(PrepareXmrFundingCommandErrorV12::AlreadyPresent)
        ));
    }
    #[test]
    fn no_replace_commit_preserves_a_concurrently_created_destination() {
        let parent = private_parent();
        let output = parent.path().join("candidate");
        let publication = PrivatePublicationV12::create(&output).unwrap();
        publication.write_new(RAW_FILE, b"retained").unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join("existing"), b"do-not-replace").unwrap();
        assert!(matches!(
            publication.publish(),
            Err(PrepareXmrFundingCommandErrorV12::AlreadyPresent)
        ));
        assert_eq!(
            std::fs::read(output.join("existing")).unwrap(),
            b"do-not-replace"
        );
        assert_eq!(
            std::fs::read(parent.path().join("candidate.preparing-v12").join(RAW_FILE)).unwrap(),
            b"retained"
        );
    }
    #[test]
    fn insecure_parent_and_preexisting_symlink_are_refused_before_wallet_construction() {
        let parent = private_parent();
        let output = parent.path().join("candidate");
        std::os::unix::fs::symlink("elsewhere", &output).unwrap();
        assert!(matches!(
            PrivatePublicationV12::create(&output),
            Err(PrepareXmrFundingCommandErrorV12::AlreadyPresent)
        ));
        std::fs::remove_file(&output).unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            PrivatePublicationV12::create(&output),
            Err(PrepareXmrFundingCommandErrorV12::Directory)
        ));
    }
}
