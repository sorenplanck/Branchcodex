//! The two inputs the daemon requires that are not digest-pinned artifacts of this
//! bootstrap, and the directories its layout is resolved against.
//!
//! `resolve_and_validate_layout` sorts every path role by kind. An `InputFile` must
//! exist, be owner-only and be non-empty. A `ManagedFile` or `ManagedDirectory` must be
//! ABSENT in `Create` mode, because the daemon creates it and refuses to adopt one it
//! did not. And `validate_parent_chain` walks from the state directory down to each
//! path, requiring every directory on the way to exist and be owner-only -- including
//! the parents of the managed paths it then demands be absent.
//!
//! So a state directory the daemon will accept has: nine input files present, the
//! managed paths absent, and every parent directory of all of them present. This module
//! supplies the last two of the nine inputs and the directories.
//!
//! # Why these two are not provisioned like the others
//!
//! `DomWallet` is the encrypted DOM participant wallet. Nothing in the bootstrap pins
//! its digest and nothing in `load_authenticated_production_inputs_v1` opens it: it is
//! opened later by `production_chain_signers` with a passphrase, which is a run-time
//! secret this crate must never hold. The layout only requires a non-empty owner-only
//! file. The daemon's own fixture writes `b"encrypted-wallet-fixture"` there for exactly
//! that reason, and this module will write whatever bytes a caller hands it and refuse
//! to invent any.
//!
//! `AuthorityBundleV7` is the F6 authority bundle. `authenticate_f6_bundle_file_v8`
//! reads it and compares `production_f6_authority_bundle_digest_v8` of its bytes with
//! the digest the manifest declares, and that is the whole of what bootstrap validation
//! does with it -- the F6 factory parses its contents at run time. So this module
//! measures the digest of the bytes it is given, which makes the file and the manifest
//! agree by construction, and says plainly that agreement is not authentication of the
//! bundle's contents.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use dom_interopd::production_f6_authority_bundle_digest_v8;

use crate::owner_only;

/// Write the F6 authority bundle and return the digest the manifest must declare.
///
/// The digest is `BLAKE2b-256(domain || len_be || bytes)` over exactly these bytes, as
/// `production_f6_authority_bundle_digest_v8` computes it -- the daemon's own function,
/// not a second implementation of the same hash.
pub fn write_f6_authority_bundle(
    state_dir: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<[u8; 32], String> {
    if bytes.is_empty() {
        return Err("an empty F6 authority bundle is refused by its own digest".to_owned());
    }
    let digest = production_f6_authority_bundle_digest_v8(bytes)
        .map_err(|error| format!("f6 authority bundle digest: {error:?}"))?;
    owner_only::write(&state_dir.join(relative), bytes)?;
    Ok(digest)
}

/// Write the DOM participant wallet file.
///
/// The bytes are the caller's. This crate does not create a wallet: a wallet is a
/// keyholder's artifact and its passphrase is a run-time secret.
pub fn write_dom_wallet(state_dir: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("the layout refuses an empty input file".to_owned());
    }
    owner_only::write(&state_dir.join(relative), bytes)
}

/// Exactly the byte length the daemon requires of a Contracts bootstrap artifact.
///
/// `CONTRACTS_BOOTSTRAP_BYTES_V1` is `pub(crate)` in `dom-interopd`, so it cannot be
/// referenced. It is restated here from the constants the module lists beside it, with
/// the arithmetic written out so a reader can check it rather than trust it:
///
/// * `COMMIT_UNSIGNED_BYTES_V1` = 1194, plus
/// * `STAGE_SIGNATURE_BYTES_V1` = `SIGNATURE_COUNT_V1` (4) * `SIGNATURE_BYTES_V1` (64)
///   = 256, which is `REVEAL_STAGE_OFFSET_V1` = 1450, plus
/// * `REVEAL_UNSIGNED_BYTES_V1` = 832, plus another 256.
///
/// A wrong value here is refused by `read_retained_contracts_bootstrap_v5` before the
/// loader reads anything else, which is exactly how it would be noticed.
pub const CONTRACTS_BOOTSTRAP_BYTES: usize = 1_194 + 256 + 832 + 256;

/// Place the Contracts bootstrap artifact the two-party ceremony produced.
///
/// # Why this places an artifact rather than producing one
///
/// The Contracts bootstrap is not something a route provisioner can write. It is a
/// two-stage artifact -- a commit stage and a reveal stage, four signatures each, with
/// Schnorr keys, share points and recovery capsules -- bound to the composition, the
/// registry and both relay rosters, and it is the output of a ceremony BETWEEN THE TWO
/// PARTICIPANTS. The daemon ships the driver for it: `bootstrap_command_v13`, whose own
/// documentation is "advance only the bootstrap ceremony using public files and a
/// bounded private stdin; repeat with the same plan/custody after copying the missing
/// peer files". It reads secrets from stdin and refuses a terminal.
///
/// Both the producer and `authenticate_contracts_bootstrap_v1` are `pub(crate)`, so this
/// crate could not build one even if it should. It should not: driving both custodies
/// from one process would collapse a two-party protocol into a single party holding
/// everything, which is the opposite of what the artifact exists to prove.
///
/// So this function writes the bytes it is handed, checks only the length the daemon
/// checks first, and says plainly that the ceremony is the operator's step.
pub fn place_contracts_bootstrap(
    state_dir: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() != CONTRACTS_BOOTSTRAP_BYTES {
        return Err(format!(
            "a Contracts bootstrap artifact is exactly {CONTRACTS_BOOTSTRAP_BYTES} bytes, not {}",
            bytes.len()
        ));
    }
    owner_only::write(&state_dir.join(relative), bytes)
}

/// Write the Contracts budget policy.
///
/// An input file the layout requires in create and in reopen alike. Its bytes are a
/// policy the deployment decides, so they are the caller's.
pub fn write_contracts_budget_policy(
    state_dir: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("the layout refuses an empty input file".to_owned());
    }
    owner_only::write(&state_dir.join(relative), bytes)
}

/// Create the Contracts transport identity authority directory.
///
/// A directory, and one the layout requires to exist in create and in reopen alike:
/// "provisioned outside the daemon, never created and never repaired here". Creating it
/// empty is what a provisioner can do; what goes in it belongs to the identity
/// authority.
pub fn create_contracts_transport_identity(
    state_dir: &Path,
    relative: &str,
) -> Result<(), String> {
    owner_only::directory(&state_dir.join(relative))
}

/// Create the parent directory of every path in the layout, and nothing else.
///
/// Parents only. Creating any of the managed paths themselves would make `Create` mode
/// refuse the directory, which is the daemon declining to adopt state it did not make.
pub fn create_parent_directories(state_dir: &Path, relatives: &[&str]) -> Result<(), String> {
    owner_only::directory(state_dir)?;
    for relative in relatives {
        let path = state_dir.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| format!("{relative} has no parent inside the state directory"))?;
        owner_only::directory(parent)?;
    }
    verify_parent_chains(state_dir, relatives)
}

/// Check what `validate_parent_chain` checks, and name the path that fails.
///
/// The daemon walks from the state directory down to every path and requires each
/// directory on the way to exist, to be a directory, to be owner-only and to be owned by
/// the effective uid -- and it refuses all four the same way, with
/// `InvalidStateAuthority` and no path. That refusal is unactionable: the first time it
/// arrived it could have meant any of forty-six chains or the state directory itself.
///
/// So the same conditions are checked here, where the path is still in hand.
pub fn verify_parent_chains(state_dir: &Path, relatives: &[&str]) -> Result<(), String> {
    // The state directory must be canonical: `validate_state_dir` refuses a path whose
    // `canonicalize` differs from itself, so a symlink anywhere above it is fatal.
    let canonical = state_dir
        .canonicalize()
        .map_err(|error| format!("canonicalize {}: {error}", state_dir.display()))?;
    if canonical.as_path() != state_dir {
        return Err(format!(
            "the state directory must already be canonical: {} resolves to {}",
            state_dir.display(),
            canonical.display()
        ));
    }
    // Every directory must be owned by the effective uid. Rather than reach for a libc
    // call -- this crate forbids unsafe code -- the state directory's own owner is the
    // reference: this process created it, so its uid IS the effective uid, and the
    // daemon then checks that same directory against `geteuid` itself. A directory
    // owned by anyone else therefore still fails here, by name.
    let owner = owner_uid(state_dir)?;
    owner_only_directory_is_valid(state_dir, owner)?;
    for relative in relatives {
        let mut current = state_dir.to_path_buf();
        let path = state_dir.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| format!("{relative} has no parent"))?;
        let inside = parent
            .strip_prefix(state_dir)
            .map_err(|_| format!("{relative} is not inside the state directory"))?;
        for component in inside.components() {
            current.push(component);
            owner_only_directory_is_valid(&current, owner)
                .map_err(|error| format!("on the way to {relative}: {error}"))?;
        }
    }
    Ok(())
}

fn owner_uid(path: &Path) -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(std::fs::symlink_metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .uid())
}

fn owner_only_directory_is_valid(path: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != owner_only::DIRECTORY_MODE {
        return Err(format!("{} is {mode:04o}, not 0700", path.display()));
    }
    if metadata.uid() != owner {
        return Err(format!(
            "{} is owned by {}, not by {owner}",
            path.display(),
            metadata.uid()
        ));
    }
    Ok(())
}
