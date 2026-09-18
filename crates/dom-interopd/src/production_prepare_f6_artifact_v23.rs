//! Offline public F6 signing requests. No request or signature checked here
//! is an admission capability: the daemon independently authenticates F6.
use crate::production_f6_factory::artifact_writer_v23::*;
use crate::production_inputs::{ProductionAuthorityBundleV1, ProductionRelayRosterBundleV1};
use btc_crypto::SecpContext;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, MetadataExt as _, OpenOptions, OpenOptionsExt as _,
};
use deployment_registry::AuthoritySetV1;
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use route_composer::{ComposedFinalClaimRolePlanV1, FinalClaimSecretSourceScopeV1};
use route_time_anchor::PreF6TimePolicyLimitsV2;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const INPUT_SCHEMA: &str = "DOM-F6-PUBLIC-INPUT-V23";
const REPORT_SCHEMA: &str = "DOM-F6-UNTRUSTED-REQUEST-V23";
const SIGNATURE_SCHEMA: &str = "DOM-F6-EXTERNAL-SIGNATURES-V23";
const LIMIT: usize = 262_144;
const SNAPSHOT: &str = "public-input.json";
const PREFIX: &str = "signing-prefix.bin";
const REPORT: &str = "signing-request.json";
const FINAL: &str = "finalized";
const BUNDLE: &str = "authority.bundle";
const FINAL_REPORT: &str = "bundle-report.json";

pub const PREPARE_F6_ARTIFACT_USAGE_V23: &str = "F6 public artifact workflow (no authority granted):\nprepare-f6-artifact-v23 --input ABSOLUTE_PRIVATE_JSON --output-dir ABSOLUTE_NEW_DIRECTORY\nprepare-f6-artifact-v23 --resume --request-dir ABSOLUTE_PRIVATE_DIRECTORY\nprepare-f6-artifact-v23 --finalize --request-dir ABSOLUTE_PRIVATE_DIRECTORY --signatures ABSOLUTE_PRIVATE_JSON\nInputs and files: 0600, owner-only, bounded; parent directories: canonical 0700. No private keys are accepted. Registry owners sign the reported digest externally. Claim profiles: bound, native_enrollment, solana_enrollment; solana_enrollment requires two policy-17 conditioned SOL legs and is independently rechecked by the daemon. Final bytes remain subject to independent daemon admission. See docs/interop/hardening/PREPARE-F6-ARTIFACT-V23.md.";

#[derive(Debug, thiserror::Error)]
pub enum PrepareF6ArtifactErrorV23 {
    #[error("invalid bounded public F6 input")]
    Input,
    #[error("private F6 artifact path refused")]
    Path,
    #[error("F6 output or retained staging already exists; nothing overwritten")]
    AlreadyPresent,
    #[error("F6 request is missing, corrupt or inconsistent; no repair performed")]
    RetainedRequest,
    #[error("external signatures do not authorize this exact request under supplied roots")]
    Signatures,
    #[error("F6 artifact storage unavailable; preserve any retained staging")]
    Storage,
}
type Result<T> = std::result::Result<T, PrepareF6ArtifactErrorV23>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum ArtifactSource {
    File { path: PathBuf },
    CanonicalHex { hex: String },
}
impl ArtifactSource {
    fn snapshot(&mut self, allow_files: bool) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::File { path } if allow_files => read_private_path(path, LIMIT)?.to_vec(),
            Self::File { .. } => return Err(PrepareF6ArtifactErrorV23::RetainedRequest),
            Self::CanonicalHex { hex } => decode_hex(hex, LIMIT)?,
        };
        *self = Self::CanonicalHex {
            hex: hex::encode(&bytes),
        };
        Ok(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePins {
    network_id: [u8; 32],
    route_id: [u8; 32],
    composition_digest: [u8; 32],
    route_scope_digest: [u8; 32],
    registry_digest: [u8; 32],
    registry_epoch: u64,
    profile_bundle_digest: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Economics {
    solver: [u8; 32],
    inventory_binding_digest: [u8; 32],
    bond_policy_hash: [u8; 32],
    bond_asset_binding_digest: [u8; 32],
    required_collateral: u128,
    status_max_lifetime_seconds: u64,
    valid_from_seconds: u64,
    expires_at_seconds: u64,
    max_evidence_age_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signer {
    independent_authority_id: [u8; 32],
    signer_index: u16,
    signer_public_key: [u8; 32],
    endpoint_uid: u32,
    endpoint: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case", deny_unknown_fields)]
enum ClaimProfile {
    NativeEnrollment,
    /// DOMF6A25: Solana role enrollment for a DOM-mainnet SOL route.
    SolanaEnrollment,
    Bound {
        role_plan: ArtifactSource,
        sources: [ArtifactSource; 2],
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    schema: String,
    route: RoutePins,
    economics: Economics,
    authorities: ArtifactSource,
    relay_roster: ArtifactSource,
    upstream_terms: ArtifactSource,
    downstream_terms: ArtifactSource,
    bond_authorities: ArtifactSource,
    status_authorities: ArtifactSource,
    reserved_participant_keys: Vec<[u8; 32]>,
    signers: [Vec<Signer>; 2],
    claim_profile: ClaimProfile,
}

/// A report of public bytes only, deliberately not a Verified/Authenticated type.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPublicF6ReportV23 {
    pub schema: String,
    pub authenticated_authority: bool,
    pub signing_digest_hex: String,
    pub supplied_registry_roots_hex: String,
    pub signing_prefix_bytes: usize,
    pub finalized: bool,
    pub bundle_digest_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSignatures {
    schema: String,
    signing_digest_hex: String,
    signatures: Vec<ExternalSignature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSignature {
    signer_index: u16,
    signature_hex: String,
}

fn decode_hex(text: &str, maximum: usize) -> Result<Vec<u8>> {
    if text.is_empty()
        || text.len() % 2 != 0
        || text.len() > maximum * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    hex::decode(text).map_err(|_| PrepareF6ArtifactErrorV23::Input)
}
fn secp() -> Result<SecpContext> {
    // Randomization of the verification backend only, never a signing key.
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    Ok(SecpContext::new(&seed))
}

fn prepare_snapshot(
    input: &mut PublicInput,
    allow_files: bool,
    secp: &SecpContext,
) -> Result<(PreparedUntrustedF6ArtifactV23, PreparedPublicF6ReportV23)> {
    let invalid = |_| PrepareF6ArtifactErrorV23::Input;
    if input.schema != INPUT_SCHEMA {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    let authorities =
        ProductionAuthorityBundleV1::decode_canonical(&input.authorities.snapshot(allow_files)?)
            .map_err(invalid)?;
    for set in [
        authorities.registry(),
        authorities.time_policy(),
        authorities.time_evidence(),
    ] {
        set.validate_with_context(secp)
            .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    }
    let roster =
        ProductionRelayRosterBundleV1::decode_canonical(&input.relay_roster.snapshot(allow_files)?)
            .map_err(invalid)?;
    let up = SettlementTermsV1::decode(&input.upstream_terms.snapshot(allow_files)?)
        .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    let down = SettlementTermsV1::decode(&input.downstream_terms.snapshot(allow_files)?)
        .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    if roster.network_id() != input.route.network_id
        || roster.route_id() != input.route.route_id
        || route_time_anchor::route_scope_digest(&up, &down)
            .map_err(|_| PrepareF6ArtifactErrorV23::Input)?
            != input.route.route_scope_digest
    {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    for (leg, terms) in roster.legs().iter().zip([&up, &down]) {
        if leg.session_id != terms.session_id.0 || leg.policy_version != terms.policy_version {
            return Err(PrepareF6ArtifactErrorV23::Input);
        }
        let participants: BTreeSet<_> = leg.members.iter().map(|m| m.participant_id).collect();
        if participants != terms.roster.into_iter().collect() {
            return Err(PrepareF6ArtifactErrorV23::Input);
        }
        for member in leg.members {
            secp.validate_xonly_key(&member.xonly_key)
                .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
        }
    }
    let relay_keys = roster
        .legs()
        .iter()
        .flat_map(|leg| leg.members.iter().map(|m| m.xonly_key))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let chain_keys: BTreeSet<_> = authorities
        .registry()
        .xonly_keys()
        .iter()
        .chain(authorities.time_policy().xonly_keys())
        .chain(authorities.time_evidence().xonly_keys())
        .copied()
        .collect();
    if chain_keys.len()
        != authorities.registry().xonly_keys().len()
            + authorities.time_policy().xonly_keys().len()
            + authorities.time_evidence().xonly_keys().len()
    {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    let claim_profile = match &mut input.claim_profile {
        ClaimProfile::NativeEnrollment => PublicF6ClaimProfileV23::NativeEnrollment {
            upstream: up,
            downstream: down,
        },
        ClaimProfile::SolanaEnrollment => PublicF6ClaimProfileV23::SolanaEnrollment {
            upstream: up,
            downstream: down,
        },
        ClaimProfile::Bound { role_plan, sources } => {
            let role_plan =
                ComposedFinalClaimRolePlanV1::decode_canonical(&role_plan.snapshot(allow_files)?)
                    .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
            let sources = [
                FinalClaimSecretSourceScopeV1::decode_canonical(&sources[0].snapshot(allow_files)?)
                    .map_err(|_| PrepareF6ArtifactErrorV23::Input)?,
                FinalClaimSecretSourceScopeV1::decode_canonical(&sources[1].snapshot(allow_files)?)
                    .map_err(|_| PrepareF6ArtifactErrorV23::Input)?,
            ];
            role_plan
                .authenticate(&up, &down, sources[0].clone(), sources[1].clone())
                .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
            PublicF6ClaimProfileV23::Bound { role_plan, sources }
        }
    };
    let bond_authorities =
        AuthoritySetV1::decode_canonical(&input.bond_authorities.snapshot(allow_files)?)
            .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    let status_authorities =
        AuthoritySetV1::decode_canonical(&input.status_authorities.snapshot(allow_files)?)
            .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    let r = &input.route;
    let e = &input.economics;
    let roots = hex::encode(
        authorities
            .registry()
            .canonical_bytes()
            .map_err(|_| PrepareF6ArtifactErrorV23::Input)?,
    );
    let prepared = PreparedUntrustedF6ArtifactV23::prepare(
        PublicF6ArtifactInputsV23 {
            route: UntrustedF6RoutePinsV23 {
                network_id: r.network_id,
                route_id: r.route_id,
                composition_digest: r.composition_digest,
                route_scope_digest: r.route_scope_digest,
                registry_digest: r.registry_digest,
                registry_epoch: r.registry_epoch,
                profile_bundle_digest: r.profile_bundle_digest,
            },
            solver: ParticipantId(e.solver),
            inventory_binding_digest: e.inventory_binding_digest,
            bond_policy_hash: e.bond_policy_hash,
            bond_asset_binding_digest: e.bond_asset_binding_digest,
            required_collateral: e.required_collateral,
            status_max_lifetime_seconds: e.status_max_lifetime_seconds,
            pre_f6_limits: PreF6TimePolicyLimitsV2 {
                valid_from_seconds: e.valid_from_seconds,
                expires_at_seconds: e.expires_at_seconds,
                max_evidence_age_seconds: e.max_evidence_age_seconds,
            },
            supplied_registry_roots: authorities.registry().clone(),
            bond_authorities,
            status_authorities,
            reserved_relay_keys: relay_keys,
            reserved_chain_keys: chain_keys.into_iter().collect(),
            reserved_participant_keys: input.reserved_participant_keys.clone(),
            signers: std::array::from_fn(|i| {
                input.signers[i]
                    .iter()
                    .map(|s| PublicF6SignerEndpointV23 {
                        independent_authority_id: s.independent_authority_id,
                        signer_index: s.signer_index,
                        signer_public_key: s.signer_public_key,
                        endpoint_uid: s.endpoint_uid,
                        endpoint: s.endpoint.clone(),
                    })
                    .collect()
            }),
            claim_profile,
        },
        secp,
    )
    .map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    let report = PreparedPublicF6ReportV23 {
        schema: REPORT_SCHEMA.into(),
        authenticated_authority: false,
        signing_digest_hex: hex::encode(prepared.signing_digest()),
        supplied_registry_roots_hex: roots,
        signing_prefix_bytes: prepared.canonical_signing_prefix().len(),
        finalized: false,
        bundle_digest_hex: None,
    };
    Ok((prepared, report))
}

/// Snapshot public inputs and publish a request without invoking any signer.
pub fn prepare_f6_artifact_command_v23(
    input_file: &Path,
    output_dir: &Path,
) -> Result<PreparedPublicF6ReportV23> {
    let bytes = read_private_path(input_file, LIMIT)?;
    let mut input: PublicInput =
        serde_json::from_slice(&bytes).map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    let (prepared, report) = prepare_snapshot(&mut input, true, &secp()?)?;
    let snapshot = serde_json::to_vec(&input).map_err(|_| PrepareF6ArtifactErrorV23::Input)?;
    if snapshot.len() > LIMIT {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    let publication = Publication::create(output_dir)?;
    write_new(&publication.staging, SNAPSHOT, &snapshot)?;
    write_new(
        &publication.staging,
        PREFIX,
        prepared.canonical_signing_prefix(),
    )?;
    write_new(&publication.staging, REPORT, &report_bytes(&report)?)?;
    publication.publish()?;
    Ok(report)
}

fn retained(
    dir: &Dir,
    secp: &SecpContext,
) -> Result<(PreparedUntrustedF6ArtifactV23, PreparedPublicF6ReportV23)> {
    check_names(
        dir,
        &[SNAPSHOT, PREFIX, REPORT, FINAL, "finalized.preparing-v23"],
    )?;
    match dir.symlink_metadata("finalized.preparing-v23") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Ok(_) => return Err(PrepareF6ArtifactErrorV23::AlreadyPresent),
        Err(_) => return Err(PrepareF6ArtifactErrorV23::Storage),
    }
    let snapshot = read_file(dir, SNAPSHOT, LIMIT)?;
    let mut input: PublicInput = serde_json::from_slice(&snapshot)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    let (prepared, report) = prepare_snapshot(&mut input, false, secp)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    if serde_json::to_vec(&input).map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?
        != *snapshot
        || read_file(dir, PREFIX, 32_768)?.as_slice() != prepared.canonical_signing_prefix()
        || read_file(dir, REPORT, 8192)?.as_slice() != report_bytes(&report)?
    {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    Ok((prepared, report))
}

/// Rebuild the immutable request from its snapshot, never from changed source files.
pub fn resume_f6_artifact_command_v23(request_dir: &Path) -> Result<PreparedPublicF6ReportV23> {
    let dir = private_dir(request_dir)?;
    let context = secp()?;
    let (prepared, report) = retained(&dir, &context)?;
    match dir.symlink_metadata(FINAL) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(report),
        Ok(_) => verify_final(&dir, prepared, report, &context),
        Err(_) => Err(PrepareF6ArtifactErrorV23::Storage),
    }
}

/// Verify externally supplied registry signatures and atomically publish bytes.
/// Does not contact signers or claim that supplied roots are the daemon's roots.
pub fn finalize_f6_artifact_command_v23(
    request_dir: &Path,
    signatures_file: &Path,
) -> Result<PreparedPublicF6ReportV23> {
    let dir = private_dir(request_dir)?;
    let context = secp()?;
    let (prepared, mut report) = retained(&dir, &context)?;
    let input = read_private_path(signatures_file, 8192)?;
    let supplied: ExternalSignatures =
        serde_json::from_slice(&input).map_err(|_| PrepareF6ArtifactErrorV23::Signatures)?;
    if supplied.schema != SIGNATURE_SCHEMA
        || supplied.signing_digest_hex != report.signing_digest_hex
        || supplied.signatures.len() > 16
    {
        return Err(PrepareF6ArtifactErrorV23::Signatures);
    }
    let signatures: Vec<_> = supplied
        .signatures
        .into_iter()
        .map(|s| {
            let bytes = decode_hex(&s.signature_hex, 64)
                .map_err(|_| PrepareF6ArtifactErrorV23::Signatures)?;
            Ok((
                s.signer_index,
                bytes
                    .try_into()
                    .map_err(|_| PrepareF6ArtifactErrorV23::Signatures)?,
            ))
        })
        .collect::<Result<_>>()?;
    let bundle = prepared
        .finalize(&signatures, &context)
        .map_err(|_| PrepareF6ArtifactErrorV23::Signatures)?;
    finish_report(&mut report, &bundle)?;
    match dir.symlink_metadata(FINAL) {
        Ok(_) => {
            let final_dir = child_dir(&dir, FINAL)?;
            check_names(&final_dir, &[BUNDLE, FINAL_REPORT])?;
            if read_file(&final_dir, BUNDLE, 32_768)?.as_slice() != bundle
                || read_file(&final_dir, FINAL_REPORT, 8192)?.as_slice() != report_bytes(&report)?
            {
                return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let publication = Publication::under(dir, FINAL.into())?;
            write_new(&publication.staging, BUNDLE, &bundle)?;
            write_new(&publication.staging, FINAL_REPORT, &report_bytes(&report)?)?;
            publication.publish()?;
        }
        Err(_) => return Err(PrepareF6ArtifactErrorV23::Storage),
    }
    Ok(report)
}

fn finish_report(report: &mut PreparedPublicF6ReportV23, bundle: &[u8]) -> Result<()> {
    let digest = crate::production_config::production_f6_authority_bundle_digest_v8(bundle)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    report.finalized = true;
    report.bundle_digest_hex = Some(hex::encode(digest));
    Ok(())
}
fn verify_final(
    dir: &Dir,
    prepared: PreparedUntrustedF6ArtifactV23,
    mut report: PreparedPublicF6ReportV23,
    secp: &SecpContext,
) -> Result<PreparedPublicF6ReportV23> {
    let final_dir = child_dir(dir, FINAL)?;
    check_names(&final_dir, &[BUNDLE, FINAL_REPORT])?;
    let bundle = read_file(&final_dir, BUNDLE, 32_768)?;
    let prefix = prepared.canonical_signing_prefix();
    if !bundle.starts_with(prefix) {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    let tail = &bundle[prefix.len()..];
    if tail.len() < 2 {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    let count = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
    if count > 16 || tail.len() != 2 + 66 * count {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    let signatures: Vec<_> = tail[2..]
        .chunks_exact(66)
        .map(|s| {
            Ok((
                u16::from_be_bytes([s[0], s[1]]),
                s[2..]
                    .try_into()
                    .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?,
            ))
        })
        .collect::<Result<_>>()?;
    let exact = prepared
        .finalize(&signatures, secp)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    if exact != *bundle {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    finish_report(&mut report, &bundle)?;
    if read_file(&final_dir, FINAL_REPORT, 8192)?.as_slice() != report_bytes(&report)? {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    Ok(report)
}
fn report_bytes(report: &PreparedPublicF6ReportV23) -> Result<Vec<u8>> {
    serde_json::to_vec(report).map_err(|_| PrepareF6ArtifactErrorV23::Storage)
}

fn private_dir(path: &Path) -> Result<Dir> {
    crate::production_config::validate_state_dir(path)
        .map_err(|_| PrepareF6ArtifactErrorV23::Path)?;
    let before = std::fs::symlink_metadata(path).map_err(|_| PrepareF6ArtifactErrorV23::Path)?;
    let file = File::open(path).map_err(|_| PrepareF6ArtifactErrorV23::Path)?;
    let after = file
        .metadata()
        .map_err(|_| PrepareF6ArtifactErrorV23::Path)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_dir()
        || after.uid() != rustix::process::geteuid().as_raw()
        || after.mode() & 0o7777 != 0o700
    {
        return Err(PrepareF6ArtifactErrorV23::Path);
    }
    Ok(Dir::from_std_file(file))
}
fn child_dir(parent: &Dir, name: &str) -> Result<Dir> {
    let before = parent
        .symlink_metadata(name)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    if !before.is_dir()
        || before.file_type().is_symlink()
        || before.mode() & 0o7777 != 0o700
        || before.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    let dir = parent
        .open_dir(name)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    let after = dir
        .dir_metadata()
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_dir()
        || after.mode() & 0o7777 != 0o700
        || after.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
    }
    Ok(dir)
}
fn checked_file(dir: &Dir, name: &str) -> Result<cap_std::fs::File> {
    let before = dir
        .symlink_metadata(name)
        .map_err(|_| PrepareF6ArtifactErrorV23::RetainedRequest)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o600
    {
        return Err(PrepareF6ArtifactErrorV23::Path);
    }
    let file = dir
        .open(name)
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    let after = file
        .metadata()
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    // Check the opened object as well: metadata can change between the
    // directory-relative lookup and opening the pinned file descriptor.
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_file()
        || after.nlink() != 1
        || after.mode() & 0o7777 != 0o600
        || after.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(PrepareF6ArtifactErrorV23::Path);
    }
    Ok(file)
}
fn read_file(dir: &Dir, name: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    checked_file(dir, name)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(PrepareF6ArtifactErrorV23::Input);
    }
    Ok(bytes)
}
fn read_private_path(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let dir = private_dir(path.parent().ok_or(PrepareF6ArtifactErrorV23::Path)?)?;
    read_file(
        &dir,
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or(PrepareF6ArtifactErrorV23::Path)?,
        limit,
    )
}
fn check_names(dir: &Dir, allowed: &[&str]) -> Result<()> {
    for entry in dir
        .entries()
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?
    {
        let name = entry
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?
            .file_name();
        if !allowed.contains(
            &name
                .to_str()
                .ok_or(PrepareF6ArtifactErrorV23::RetainedRequest)?,
        ) {
            return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
        }
    }
    Ok(())
}
fn write_new(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = dir
        .open_with(name, &options)
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
    checked_file(dir, name)?;
    Ok(())
}
struct Publication {
    parent: Dir,
    staging: Dir,
    name: OsString,
    staging_name: OsString,
}
impl Publication {
    fn create(output: &Path) -> Result<Self> {
        let parent = private_dir(output.parent().ok_or(PrepareF6ArtifactErrorV23::Path)?)?;
        let name = output
            .file_name()
            .filter(|n| n.len() <= 160)
            .ok_or(PrepareF6ArtifactErrorV23::Path)?
            .to_owned();
        Self::under(parent, name)
    }
    fn under(parent: Dir, name: OsString) -> Result<Self> {
        let mut staging_name = name.clone();
        staging_name.push(".preparing-v23");
        for candidate in [&name, &staging_name] {
            match parent.symlink_metadata(candidate) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(PrepareF6ArtifactErrorV23::AlreadyPresent),
            }
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(&staging_name, &builder)
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        parent
            .open(".")
            .and_then(|f| f.sync_all())
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        let staging = parent
            .open_dir(&staging_name)
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        Ok(Self {
            parent,
            staging,
            name,
            staging_name,
        })
    }
    fn publish(self) -> Result<()> {
        self.staging
            .open(".")
            .and_then(|f| f.sync_all())
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        let named = self
            .parent
            .symlink_metadata(&self.staging_name)
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        let held = self
            .staging
            .dir_metadata()
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        if named.file_type().is_symlink() || named.dev() != held.dev() || named.ino() != held.ino()
        {
            return Err(PrepareF6ArtifactErrorV23::RetainedRequest);
        }
        let root = self
            .parent
            .open(".")
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?
            .into_std();
        rustix::fs::renameat_with(
            &root,
            &self.staging_name,
            &root,
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| PrepareF6ArtifactErrorV23::Storage)?;
        root.sync_all()
            .map_err(|_| PrepareF6ArtifactErrorV23::Storage)
    }
}

#[cfg(test)]
#[path = "production_prepare_f6_artifact_v23_tests.rs"]
mod tests;
