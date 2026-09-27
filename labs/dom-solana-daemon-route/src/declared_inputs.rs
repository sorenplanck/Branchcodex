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
    Ok(())
}
