//! Offline, pre-economic custody writer. No wallet, RPC or authority is created.

use crate::production_inputs::{
    enrollment_context_v23::{self, EnrollmentContextV23},
    ProductionRoutePositionV1,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, MetadataExt as _, OpenOptions, OpenOptionsExt as _,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{IsTerminal, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt as _},
    path::{Path, PathBuf},
};
use xmr_dleq_nullifier_store::DleqNullifierStore;
use xmr_secret_store::{EncryptedSqliteSecretStore, SecretStoreMasterKey};
use xmr_session_init::{
    initialize_enrolled_session_for_role_v23, resume_enrolled_session_for_role_v23,
    XmrLocalSessionSecretsV11, XmrLocalShareRoleV11,
};
use zeroize::Zeroizing;

const SCHEMA: &str = "DOM-XMR-ENROLLMENT-V23";
const LIMIT: u64 = 4096;
const SECRETS: &str = "secrets.sqlite";
const NULLIFIERS: &str = "nullifiers.sqlite";
const RECEIPT: &str = "enrollment-public.json";
type LocalMaterialV23 = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Input credentials are never command-line arguments or public output.
pub const PREPARE_XMR_ENROLLMENT_USAGE_V23: &str = "usage: dom-interopd prepare-xmr-enrollment-v23 --state-dir ABSOLUTE_PRIVATE_PATH --position upstream|downstream --output-dir ABSOLUTE_PRIVATE_PATH [--reopen]\nRead one JSON from non-terminal stdin, then EOF; maximum 4096 bytes.\nFields: schema=DOM-XMR-ENROLLMENT-V23, local_participant_id (32-byte array), master_key_hex (64 lowercase hex); create also requires spend_share_le_hex and view_key_le_hex (64 lowercase hex each). Reopen forbids those two fields.\nUses the existing V11 create/reopen manifest, signed registry, terms, roster and participant bundle with both native DLEQs. Does not need or create F6, route/time stores, wallet or sidecar.\nRole is derived from authenticated terms and checked against the local share.\nCreates secrets.sqlite, nullifiers.sqlite and enrollment-public.json atomically in a NEW directory (0700; files 0600). Existing output or .preparing-v23 is never overwritten or repaired. Reopen requires complete existing custody and the original key.\nCustody only: this does not authorize funding, replace authenticated route admission, prove remote availability or broadcast transactions.";

/// Errors never include paths, credentials, proofs or decrypted material.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentErrorV23 {
    /// Bounded private input is invalid.
    #[error("invalid bounded enrollment credentials")]
    Input,
    /// Existing public commitments or proofs do not authenticate this session.
    #[error("enrollment public context refused")]
    Context,
    /// Only canonical private directories are accepted.
    #[error("enrollment directory must be canonical, owner-only and private")]
    Directory,
    /// Immutable output or retained crash staging cannot be overwritten.
    #[error("enrollment output or .preparing-v23 already exists; preserve retained custody")]
    AlreadyPresent,
    /// Missing, conflicting or incomplete custody is never recreated.
    #[error("enrollment custody refused; preserve output and staging for inspection")]
    Custody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateInput<'a> {
    schema: &'a str,
    local_participant_id: [u8; 32],
    master_key_hex: &'a str,
    #[serde(borrow, default, deserialize_with = "supplied_secret")]
    spend_share_le_hex: Option<&'a str>,
    #[serde(borrow, default, deserialize_with = "supplied_secret")]
    view_key_le_hex: Option<&'a str>,
}

fn supplied_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<&'de str>, D::Error> {
    // Presence must carry an actual borrowed string. In particular `null`
    // cannot disguise a prohibited share field on the reopen path.
    <&str>::deserialize(deserializer).map(Some)
}

/// Public receipt is scope metadata, never a funding/admission capability.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedXmrEnrollmentReportV23 {
    schema: String,
    network_id: [u8; 32],
    route_id: [u8; 32],
    registry_digest: [u8; 32],
    participant_digest: [u8; 32],
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    setup_binding_hash: [u8; 32],
    local_participant_id: [u8; 32],
    position: String,
    role: String,
    secret_store: String,
    nullifier_store: String,
    network_access: bool,
}

fn secret(text: &str) -> Result<Zeroizing<[u8; 32]>, EnrollmentErrorV23> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnrollmentErrorV23::Input);
    }
    let mut out = Zeroizing::new([0; 32]);
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    if *out == [0; 32] {
        return Err(EnrollmentErrorV23::Input);
    }
    Ok(out)
}

/// Produces encrypted local SDK custody, then verifies it through real reopen.
pub fn prepare_xmr_enrollment_command_v23(
    state_dir: &Path,
    position: ProductionRoutePositionV1,
    output_dir: &Path,
    reopen: bool,
) -> Result<PreparedXmrEnrollmentReportV23, EnrollmentErrorV23> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(EnrollmentErrorV23::Input);
    }
    // A fixed reservation prevents read_to_end from leaving earlier private
    // allocations behind when its buffer grows.
    let mut input = Zeroizing::new(Vec::with_capacity((LIMIT + 1) as usize));
    stdin
        .lock()
        .take(LIMIT + 1)
        .read_to_end(&mut input)
        .map_err(|_| EnrollmentErrorV23::Input)?;
    // No accepted field needs escapes. Reject them before serde can decode
    // private text into its non-zeroizing scratch allocation.
    if input.is_empty() || input.len() as u64 > LIMIT || input.contains(&b'\\') {
        return Err(EnrollmentErrorV23::Input);
    }
    let private: PrivateInput<'_> =
        serde_json::from_slice(&input).map_err(|_| EnrollmentErrorV23::Input)?;
    if private.schema != SCHEMA
        || private.local_participant_id == [0; 32]
        || (reopen && (private.spend_share_le_hex.is_some() || private.view_key_le_hex.is_some()))
    {
        return Err(EnrollmentErrorV23::Input);
    }
    let master = secret(private.master_key_hex)?;
    let material = if reopen {
        None
    } else {
        Some((
            secret(
                private
                    .spend_share_le_hex
                    .ok_or(EnrollmentErrorV23::Input)?,
            )?,
            secret(private.view_key_le_hex.ok_or(EnrollmentErrorV23::Input)?)?,
        ))
    };
    if let Some((spend, view)) = &material {
        // Same separation as the existing private inventory writer and V4
        // credential boundary, not a new protocol or consensus rule.
        if **spend == **view || **spend == *master || **view == *master {
            return Err(EnrollmentErrorV23::Input);
        }
    }
    let context =
        enrollment_context_v23::load(state_dir, position, private.local_participant_id, reopen)?;
    let report = report(&context, position, private.local_participant_id);
    retain_custody(&context, output_dir, reopen, &master, material, &report)?;
    Ok(report)
}

fn retain_custody(
    context: &EnrollmentContextV23,
    output_dir: &Path,
    reopen: bool,
    master: &[u8; 32],
    material: Option<LocalMaterialV23>,
    report: &PreparedXmrEnrollmentReportV23,
) -> Result<(), EnrollmentErrorV23> {
    let receipt = serde_json::to_vec(report).map_err(|_| EnrollmentErrorV23::Custody)?;
    if reopen {
        let directory = private_directory(output_dir)?;
        reopen_custody(&directory, context, master, &receipt)?;
    } else {
        let publication = Publication::create(output_dir)?;
        // The enclosing directory capability stays pinned while SQLite opens
        // its database and adjacent WAL files through this Linux fd path.
        let retained = publication
            .staging
            .open(".")
            .map_err(|_| EnrollmentErrorV23::Custody)?
            .into_std();
        let root = fd_path(&retained);
        for name in [SECRETS, NULLIFIERS] {
            write_new(&publication.staging, name, &[])?;
        }
        {
            let store = EncryptedSqliteSecretStore::open(root.join(SECRETS), master_key(master)?)
                .map_err(|_| EnrollmentErrorV23::Custody)?;
            let nullifiers = DleqNullifierStore::open(root.join(NULLIFIERS))
                .map_err(|_| EnrollmentErrorV23::Custody)?;
            let (spend_share, view_key) = material.ok_or(EnrollmentErrorV23::Input)?;
            initialize_enrolled_session_for_role_v23(
                &context.enrollment,
                &store,
                &nullifiers,
                XmrLocalSessionSecretsV11 {
                    role: context.role,
                    spend_share,
                    view_key,
                },
                &mut rand::rngs::OsRng,
            )
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        }
        write_new(&publication.staging, RECEIPT, &receipt)?;
        reopen_custody(&publication.staging, context, master, &receipt)?;
        sync_files(&publication.staging)?;
        publication.publish()?;
    }
    Ok(())
}

fn report(
    context: &EnrollmentContextV23,
    position: ProductionRoutePositionV1,
    participant: [u8; 32],
) -> PreparedXmrEnrollmentReportV23 {
    let setup = context.enrollment.setup();
    PreparedXmrEnrollmentReportV23 {
        schema: SCHEMA.into(),
        network_id: context.network_id,
        route_id: context.route_id,
        registry_digest: context.registry_digest,
        participant_digest: context.participant_digest,
        settlement_id: setup.settlement_id(),
        session_id: context.session_id,
        terms_hash: setup.terms_hash(),
        setup_binding_hash: setup.binding_hash(),
        local_participant_id: participant,
        position: match position {
            ProductionRoutePositionV1::Upstream => "upstream",
            ProductionRoutePositionV1::Downstream => "downstream",
        }
        .into(),
        role: match context.role {
            XmrLocalShareRoleV11::ClaimReceiver => "claim_receiver",
            XmrLocalShareRoleV11::RefundReceiver => "refund_receiver",
        }
        .into(),
        secret_store: SECRETS.into(),
        nullifier_store: NULLIFIERS.into(),
        network_access: false,
    }
}

fn master_key(bytes: &[u8; 32]) -> Result<SecretStoreMasterKey, EnrollmentErrorV23> {
    SecretStoreMasterKey::new(*bytes).map_err(|_| EnrollmentErrorV23::Input)
}
fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn private_directory(path: &Path) -> Result<Dir, EnrollmentErrorV23> {
    crate::production_config::validate_state_dir(path)
        .map_err(|_| EnrollmentErrorV23::Directory)?;
    let before = std::fs::symlink_metadata(path).map_err(|_| EnrollmentErrorV23::Directory)?;
    let file = File::open(path).map_err(|_| EnrollmentErrorV23::Directory)?;
    let after = file.metadata().map_err(|_| EnrollmentErrorV23::Directory)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != rustix::process::geteuid().as_raw()
        || after.mode() & 0o7777 != 0o700
        || !after.is_dir()
    {
        return Err(EnrollmentErrorV23::Directory);
    }
    Ok(Dir::from_std_file(file))
}

fn checked_file(dir: &Dir, name: &str) -> Result<cap_std::fs::File, EnrollmentErrorV23> {
    let before = dir
        .symlink_metadata(name)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(EnrollmentErrorV23::Custody);
    }
    let file = dir.open(name).map_err(|_| EnrollmentErrorV23::Custody)?;
    let after = file.metadata().map_err(|_| EnrollmentErrorV23::Custody)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(EnrollmentErrorV23::Custody);
    }
    Ok(file)
}

fn check_files(dir: &Dir) -> Result<(), EnrollmentErrorV23> {
    for name in [SECRETS, NULLIFIERS, RECEIPT] {
        checked_file(dir, name)?;
    }
    for entry in dir.entries().map_err(|_| EnrollmentErrorV23::Custody)? {
        let entry = entry.map_err(|_| EnrollmentErrorV23::Custody)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(EnrollmentErrorV23::Custody)?;
        if ![
            SECRETS,
            NULLIFIERS,
            RECEIPT,
            "secrets.sqlite-wal",
            "secrets.sqlite-shm",
            "nullifiers.sqlite-wal",
            "nullifiers.sqlite-shm",
        ]
        .contains(&name)
        {
            return Err(EnrollmentErrorV23::Custody);
        }
        checked_file(dir, name)?;
    }
    Ok(())
}

fn reopen_custody(
    dir: &Dir,
    context: &EnrollmentContextV23,
    master: &[u8; 32],
    receipt: &[u8],
) -> Result<(), EnrollmentErrorV23> {
    check_files(dir)?;
    let mut actual = Vec::new();
    checked_file(dir, RECEIPT)?
        .take(8193)
        .read_to_end(&mut actual)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    if actual != receipt {
        return Err(EnrollmentErrorV23::Custody);
    }
    let retained = dir
        .open(".")
        .map_err(|_| EnrollmentErrorV23::Custody)?
        .into_std();
    let root = fd_path(&retained);
    let store = EncryptedSqliteSecretStore::open_existing(root.join(SECRETS), master_key(master)?)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    let nullifiers = DleqNullifierStore::open_existing(root.join(NULLIFIERS))
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    resume_enrolled_session_for_role_v23(&context.enrollment, &store, &nullifiers, context.role)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    Ok(())
}

fn write_new(dir: &Dir, name: &str, bytes: &[u8]) -> Result<(), EnrollmentErrorV23> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = dir
        .open_with(name, &options)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    file.write_all(bytes)
        .map_err(|_| EnrollmentErrorV23::Custody)?;
    file.sync_all().map_err(|_| EnrollmentErrorV23::Custody)?;
    checked_file(dir, name)?;
    Ok(())
}

fn sync_files(dir: &Dir) -> Result<(), EnrollmentErrorV23> {
    check_files(dir)?;
    for entry in dir.entries().map_err(|_| EnrollmentErrorV23::Custody)? {
        let name = entry.map_err(|_| EnrollmentErrorV23::Custody)?.file_name();
        checked_file(dir, name.to_str().ok_or(EnrollmentErrorV23::Custody)?)?
            .sync_all()
            .map_err(|_| EnrollmentErrorV23::Custody)?;
    }
    dir.open(".")
        .and_then(|file| file.sync_all())
        .map_err(|_| EnrollmentErrorV23::Custody)
}

struct Publication {
    parent: Dir,
    staging: Dir,
    name: OsString,
    staging_name: OsString,
}
impl Publication {
    fn create(output: &Path) -> Result<Self, EnrollmentErrorV23> {
        if !output.is_absolute()
            || output.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(EnrollmentErrorV23::Directory);
        }
        let parent = private_directory(output.parent().ok_or(EnrollmentErrorV23::Directory)?)?;
        let name = output
            .file_name()
            .filter(|name| name.len() <= 160)
            .ok_or(EnrollmentErrorV23::Directory)?
            .to_owned();
        let mut staging_name = name.clone();
        staging_name.push(".preparing-v23");
        for candidate in [&name, &staging_name] {
            match parent.symlink_metadata(candidate) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(EnrollmentErrorV23::AlreadyPresent),
            }
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(&staging_name, &builder)
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        parent
            .open(".")
            .and_then(|file| file.sync_all())
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        let staging = parent
            .open_dir(&staging_name)
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        Ok(Self {
            parent,
            staging,
            name,
            staging_name,
        })
    }
    fn publish(self) -> Result<(), EnrollmentErrorV23> {
        let named = self
            .parent
            .symlink_metadata(&self.staging_name)
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        let held = self
            .staging
            .dir_metadata()
            .map_err(|_| EnrollmentErrorV23::Custody)?;
        if named.file_type().is_symlink() || named.dev() != held.dev() || named.ino() != held.ino()
        {
            return Err(EnrollmentErrorV23::Custody);
        }
        let root = self
            .parent
            .open(".")
            .map_err(|_| EnrollmentErrorV23::Custody)?
            .into_std();
        rustix::fs::renameat_with(
            &root,
            &self.staging_name,
            &root,
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| EnrollmentErrorV23::Custody)?;
        root.sync_all().map_err(|_| EnrollmentErrorV23::Custody)
    }
}

#[cfg(test)]
#[path = "production_prepare_xmr_enrollment_v23_tests.rs"]
mod tests;
