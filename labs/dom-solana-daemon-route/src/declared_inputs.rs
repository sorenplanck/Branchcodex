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

/// Write one position's authority bundle and return the digest the manifest must declare.
///
/// The digest is `ProductionUniversalLegV11::bundle_digest` -- the daemon's own public
/// function, over a domain, the length and the bytes -- so the file and the manifest agree
/// by construction. `read_bundle` computes the same value and refuses anything else.
///
/// Its contents are the position's authority material and therefore the caller's, like the
/// wallet: a provisioner places them.
pub fn write_leg_authority_bundle(
    state_dir: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<[u8; 32], String> {
    if bytes.is_empty() {
        return Err("an empty leg authority bundle is refused by its own digest".to_owned());
    }
    let digest = dom_interopd::ProductionUniversalLegV11::bundle_digest(bytes)
        .map_err(|error| format!("leg authority bundle digest: {error:?}"))?;
    owner_only::write(&state_dir.join(relative), bytes)?;
    Ok(digest)
}

/// Write the Contracts budget policy, as a policy rather than as bytes.
///
/// # Why this is not the caller's bytes any more
///
/// The layout requires only a non-empty owner-only file here, so an arbitrary string passed
/// every check this crate made -- and the ceremony then refused the route with `Binding`,
/// because it PARSES this file:
///
/// ```text
/// let policy = BudgetPolicyV1::from_bytes(&bounded_owner_read(&plan.budget_policy_file, 4096)?)
///     .map_err(|_| Binding)?;
/// if policy.profile() != BudgetPolicyProfileV1::ProductionRatified { return Err(Binding); }
/// ```
///
/// An input whose contents something downstream parses is not an opaque blob, whatever the
/// layout says about it.
///
/// # The format, and where it comes from
///
/// `BudgetPolicyV1` has no public constructor, only `from_bytes`, so the canonical bytes are
/// emitted here against the layout that parser accepts: the magic `DOMNVBP1`, version one
/// little-endian, the profile byte, a fixed `0x01`, four reserved zero bytes, a non-zero
/// thirty-two byte policy id, then seven non-zero budget numbers and a reserved zero pair,
/// and finally the store's own authoritative digest over the first hundred and twelve bytes.
/// `crates/dom-leg/src/f7_wallet_tests.rs` builds one the same way; the digest comes from
/// `dom_scriptless_crypto::authoritative_storage_hash_v1`, never restated.
///
/// The numbers are laboratory values, conservative rather than tuned: a deployment ratifies
/// its own budget, and `from_bytes`'s own documentation says parsing "does not establish that
/// a production composition root ratified the policy values".
pub fn write_contracts_budget_policy(state_dir: &Path, relative: &str) -> Result<(), String> {
    use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
    use dom_scriptless_store::{BudgetPolicyProfileV1, BudgetPolicyV1, BUDGET_POLICY_LEN};

    let mut bytes = [0u8; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
    bytes[11] = 1;
    // A non-zero policy identity. Named by this route rather than fixed, so two laboratories
    // do not describe one policy.
    bytes[16..48].copy_from_slice(&{
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, b"DOM-SOLANA-DAEMON-ROUTE/BUDGET-POLICY-ID/V1\0");
        sha2::Digest::update(&mut hasher, relative.as_bytes());
        let out: [u8; 32] = sha2::Digest::finalize(hasher).into();
        out
    });
    bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
    bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
    bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
    let digest = authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
    bytes[112..].copy_from_slice(&digest);

    // Parsed back before it is written: a policy this crate cannot read is one the ceremony
    // cannot either, and finding that out here names the format rather than the route.
    let policy = BudgetPolicyV1::from_bytes(&bytes)
        .map_err(|error| format!("the emitted budget policy does not parse: {error:?}"))?;
    if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
        return Err("the emitted budget policy is not the ratified profile".to_owned());
    }
    owner_only::write(&state_dir.join(relative), &bytes)
}

/// Create the Contracts transport identity authority.
///
/// A directory the layout requires to exist in create and in reopen alike: "provisioned
/// outside the daemon, never created and never repaired here". An empty one satisfies the
/// LAYOUT, which checks only that it is an owner-only directory -- and satisfies nothing
/// else, because the Contracts bootstrap ceremony opens it with a passphrase.
///
/// So this creates a real one, through the store's own public constructor. That
/// constructor publishes the named root itself, from a staging directory it renames, so
/// only the PARENT is created here; pre-creating the target would leave it with a root the
/// store did not make.
///
/// The passphrase is the caller's. A laboratory holds one; a deployment's belongs to
/// whoever holds the identity.
pub fn create_contracts_transport_identity(
    state_dir: &Path,
    relative: &str,
    passphrase: &[u8],
) -> Result<[u8; 33], String> {
    use std::sync::Arc;

    let path = state_dir.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("{relative} has no parent inside the state directory"))?;
    let root_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{relative} has no usable final component"))?;
    owner_only::directory(parent)?;

    let parent_dir = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .map_err(|error| format!("identity parent capability: {error}"))?;
    let passphrase = dom_scriptless_identity_store::ContractsIdentityPassphraseV1::new(
        passphrase.to_vec(),
    )
    .map_err(|error| format!("identity passphrase: {error:?}"))?;
    let store = dom_scriptless_identity_store::ContractsTransportIdentityStoreV1::create_production(
        Arc::new(parent_dir),
        root_name,
        &passphrase,
    )
    .map_err(|error| format!("identity authority: {error:?}"))?;
    // The Schnorr key of the identity that was just published. A participant id is derived
    // from it, so the caller needs it before it can name the participant this identity speaks
    // for. Dropped right after: the store holds an exclusive lock while it lives, and the
    // ceremony reopens it with the same passphrase.
    let schnorr_public_key = *store.reference().schnorr_public_key();
    drop(store);

    // The layout requires this directory to be owner-only, and the store chose its own
    // mode. Report a disagreement rather than silently widening or narrowing it: if the
    // two requirements ever conflict, that is worth knowing by name.
    let owner = owner_uid(state_dir)?;
    owner_only_directory_is_valid(&path, owner).map_err(|error| {
        format!("the identity authority the store created is not owner-only: {error}")
    })?;
    Ok(schnorr_public_key)
}

/// The participant id an identity speaks for, derived the way the ceremony audits it.
///
/// `audit_retained_participant_id_v1` recomputes `derive_participant_id(dom_chain_id,
/// identity_key)` and refuses anything else, so a participant id is not a label a provisioner
/// may choose: it IS the identity, read through the DOM chain the route settles its hub leg
/// on. `derive_participant_id` is private, and `ParticipantIdentityV1::new` is the public
/// surface that performs it.
///
/// The signing key and the direction do not enter the derivation. The identity key is passed
/// for both because only one of them is being asked about, and the direction is the one the
/// roster role implies.
pub fn participant_id_for_identity(
    dom_genesis_hash: [u8; 32],
    dom_network_magic: u32,
    schnorr_public_key: &[u8; 33],
    direction: dom_adaptor::DirectionV1,
) -> Result<[u8; 32], String> {
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        dom_network_magic,
        &dom_core::Hash256::from_bytes(dom_genesis_hash),
    );
    let key = dom_crypto::PublicKey::from_compressed_bytes(schnorr_public_key)
        .map_err(|error| format!("the identity key is not a point: {error:?}"))?;
    let identity = dom_adaptor::ParticipantIdentityV1::new(&chain, key, key, direction)
        .map_err(|error| format!("derive the participant id: {error:?}"))?;
    Ok(*identity.participant_id())
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
