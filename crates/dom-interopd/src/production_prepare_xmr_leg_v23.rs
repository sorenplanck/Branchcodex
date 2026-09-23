//! Offline publication of the public XMR enrollment authority description.
//! No secret credential, signing authority or resource-opening API enters.
use crate::production_inputs::{enrollment_context_v23, ProductionRoutePositionV1};
use crate::production_universal_leg_authority::{
    encode_xmr_enrollment_leg_authority_bundle_v23, ProductionXmrEnrollmentLegResourcesV23,
};
use cap_std::fs::{Dir, MetadataExt as _, OpenOptions, OpenOptionsExt as _};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{IsTerminal, Read, Write},
    os::unix::fs::MetadataExt as _,
    path::{Component, Path},
};
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;
use zeroize::Zeroizing;

const SCHEMA: &str = "DOM-XMR-LEG-V23";
const MAX_INPUT: u64 = 16_384;

/// Complete operator interface; credentials never belong in this public input.
pub const PREPARE_XMR_LEG_USAGE_V23: &str = "usage: dom-interopd prepare-xmr-leg-v23 --state-dir ABSOLUTE_PRIVATE_PATH --position upstream|downstream --output-file ABSOLUTE_NEW_FILE\nRead one public JSON from non-terminal stdin, then EOF; maximum 16384 bytes.\nFields: schema=DOM-XMR-LEG-V23, compensation_policy (canonical negotiated bytes as an integer array), resources.\nresources fields: local_participant_id (32-byte array), secret_store, sidecar_socket, sidecar_timeout_ms, custody_directory, sealing_key_file, custody_id (32-byte array), nullifier_store; XMR funder also requires private_funding={raw_transaction_file,max_fee_piconero}.\nEvery resource path is state-relative. custody_directory is a separate single root-level graph archive name; it cannot contain/alias the enrollment databases. Sidecar timeout is 1..60000 milliseconds.\nUses the existing V11 create manifest, signed registry, terms, roster and both selected native DLEQs. Policy/availability must match the negotiated terms; no default is supplied.\nPublishes canonical XMR_ENROLLMENT_V23 bytes as NEW mode-0600 file under a canonical owner-0700 parent, with atomic durable no-overwrite publication. Existing output or .preparing-v23 is refused.\nstdout contains only the byte count and manifest authority_bundle_digest. Set that digest/path in the operator's final manifest; this command does not rewrite it.\nDoes not read/create wallets, keys, stores, sidecars or private candidates, does not call RPC, and grants no F6/funding/signing/route admission.";

/// Redacted command errors do not print paths, input JSON or credentials.
#[derive(Debug, thiserror::Error)]
pub enum PrepareXmrLegErrorV23 {
    /// Invalid or oversized public input.
    #[error("invalid bounded public XMR leg input")]
    Input,
    /// Public commitments, proofs or negotiated policy do not match.
    #[error("public XMR leg context or negotiated policy refused")]
    Context,
    /// Output parent is not a canonical owner-only directory.
    #[error("XMR leg output requires a canonical owner-only directory")]
    Directory,
    /// Output or interrupted publication already exists.
    #[error("XMR leg output or .preparing-v23 already exists; preserve retained files")]
    AlreadyPresent,
    /// Ambiguous publication must be inspected, never overwritten.
    #[error("XMR leg publication failed; preserve output and .preparing-v23")]
    Storage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    schema: String,
    compensation_policy: Vec<u8>,
    resources: ProductionXmrEnrollmentLegResourcesV23,
}

/// Only public metadata is printed. The digest pins bytes, not an authority.
#[derive(Serialize)]
pub struct PreparedXmrLegReportV23 {
    schema: &'static str,
    authority_bundle_digest: String,
    bytes: usize,
    network_access: bool,
}

/// Publishes a native enrollment leg description without touching its resources.
pub fn prepare_xmr_leg_command_v23(
    state_dir: &Path,
    position: ProductionRoutePositionV1,
    output_file: &Path,
) -> Result<PreparedXmrLegReportV23, PrepareXmrLegErrorV23> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(PrepareXmrLegErrorV23::Input);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity((MAX_INPUT + 1) as usize));
    stdin
        .lock()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PrepareXmrLegErrorV23::Input)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT {
        return Err(PrepareXmrLegErrorV23::Input);
    }
    let input: PublicInput =
        serde_json::from_slice(&bytes).map_err(|_| PrepareXmrLegErrorV23::Input)?;
    if input.schema != SCHEMA {
        return Err(PrepareXmrLegErrorV23::Input);
    }
    let policy = XmrCompensationPolicyV11::from_bytes(&input.compensation_policy)
        .map_err(|_| PrepareXmrLegErrorV23::Input)?;
    // Refuse an existing destination before costly verification, but never
    // create staging until all cryptographic/public validation succeeds.
    let destination = Destination::inspect(output_file)?;
    let context = enrollment_context_v23::load(
        state_dir,
        position,
        input.resources.local_participant_id,
        false,
    )
    .map_err(|_| PrepareXmrLegErrorV23::Context)?;
    let encoded = encode_xmr_enrollment_leg_authority_bundle_v23(
        &context.terms,
        &context.enrollment,
        &context.public_enrollment,
        &policy,
        input.resources,
    )
    .map_err(|_| PrepareXmrLegErrorV23::Context)?;
    destination.publish(encoded.bytes())?;
    Ok(PreparedXmrLegReportV23 {
        schema: SCHEMA,
        authority_bundle_digest: hex::encode(encoded.digest()),
        bytes: encoded.bytes().len(),
        network_access: false,
    })
}

struct Destination {
    parent: Dir,
    name: OsString,
    staging: OsString,
}
impl Destination {
    fn inspect(output: &Path) -> Result<Self, PrepareXmrLegErrorV23> {
        use PrepareXmrLegErrorV23::Directory;
        if !output.is_absolute()
            || output
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(Directory);
        }
        let name = output
            .file_name()
            .filter(|name| name.len() <= 160)
            .ok_or(Directory)?
            .to_owned();
        let parent_path = output.parent().ok_or(Directory)?;
        crate::production_config::validate_state_dir(parent_path).map_err(|_| Directory)?;
        let before = std::fs::symlink_metadata(parent_path).map_err(|_| Directory)?;
        let file = File::open(parent_path).map_err(|_| Directory)?;
        let held = file.metadata().map_err(|_| Directory)?;
        if !held.is_dir()
            || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o7777 != 0o700
            || held.dev() != before.dev()
            || held.ino() != before.ino()
        {
            return Err(Directory);
        }
        let parent = Dir::from_std_file(file);
        let mut staging = name.clone();
        staging.push(".preparing-v23");
        absent(&parent, &name)?;
        absent(&parent, &staging)?;
        Ok(Self {
            parent,
            name,
            staging,
        })
    }
    fn publish(self, bytes: &[u8]) -> Result<(), PrepareXmrLegErrorV23> {
        use PrepareXmrLegErrorV23::Storage;
        absent(&self.parent, &self.name)?;
        absent(&self.parent, &self.staging)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = self
            .parent
            .open_with(&self.staging, &options)
            .map_err(|_| Storage)?;
        let held = file.metadata().map_err(|_| Storage)?;
        if !held.is_file()
            || held.nlink() != 1
            || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o7777 != 0o600
        {
            return Err(Storage);
        }
        file.write_all(bytes).map_err(|_| Storage)?;
        file.sync_all().map_err(|_| Storage)?;
        let named = self
            .parent
            .symlink_metadata(&self.staging)
            .map_err(|_| Storage)?;
        if named.file_type().is_symlink()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.nlink() != 1
            || named.len() != bytes.len() as u64
        {
            return Err(Storage);
        }
        let directory = self.parent.open(".").map_err(|_| Storage)?.into_std();
        directory.sync_all().map_err(|_| Storage)?;
        rustix::fs::renameat_with(
            &directory,
            &self.staging,
            &directory,
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                PrepareXmrLegErrorV23::AlreadyPresent
            } else {
                Storage
            }
        })?;
        directory.sync_all().map_err(|_| Storage)
    }
}
fn absent(parent: &Dir, name: &OsString) -> Result<(), PrepareXmrLegErrorV23> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(PrepareXmrLegErrorV23::AlreadyPresent),
        Err(_) => Err(PrepareXmrLegErrorV23::Storage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn public_leg_publication_is_durable_private_and_never_overwrites() {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let output = root.path().join("leg.json");
        Destination::inspect(&output)
            .unwrap()
            .publish(b"canonical-fixture")
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"canonical-fixture");
        assert_eq!(std::fs::metadata(&output).unwrap().mode() & 0o7777, 0o600);
        assert!(!root.path().join("leg.json.preparing-v23").exists());
        assert!(Destination::inspect(&output).is_err());
        for (index, kind) in ["symlink", "hardlink", "file"].into_iter().enumerate() {
            let name = format!("blocked-{index}.json");
            let blocked = root.path().join(&name);
            let staging = root.path().join(format!("{name}.preparing-v23"));
            match kind {
                "symlink" => symlink(&output, &staging).unwrap(),
                "hardlink" => std::fs::hard_link(&output, &staging).unwrap(),
                _ => std::fs::write(&staging, b"interrupted").unwrap(),
            }
            assert!(Destination::inspect(&blocked).is_err());
            assert!(!blocked.exists());
            assert_eq!(std::fs::read(&output).unwrap(), b"canonical-fixture");
        }
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Destination::inspect(&root.path().join("unsafe.json")).is_err());
    }
}
