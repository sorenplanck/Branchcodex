//! Offline, pre-F6 production planning from signed public artifacts.
//! No keys, network clients, daemon manifest or F6 permission are accepted.
use crate::production_inputs::planning_context_v23::{
    ProductionPreF6PlanningContextV23, ProductionPreF6PlanningInputsV23,
};
use crate::production_inputs::{ProductionAuthorityBundleV1, ProductionRelayRosterBundleV1};
use btc_crypto::SecpContext;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, MetadataExt as _, OpenOptions, OpenOptionsExt as _,
};
use deployment_registry::{RegistryStoreV1, SignedRegistryV1};
use kaystra_core::terms::SettlementTermsV1;
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeEvidenceV2, SignedRouteTimeEvidenceV2,
    SignedRouteTimePolicyV2,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt as _,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const SCHEMA: &str = "DOM-PRE-F6-PLANNING-INPUT-V23";
const REPORT_SCHEMA: &str = "DOM-PRE-F6-PLANNING-REPORT-V23";
const LIMIT: usize = 1_048_576;
const ARTIFACT_LIMIT: usize = 262_144;
const SNAPSHOT: &str = "public-input.json";
const ROUTE: &str = "route-pins.json";
const REPORT: &str = "planning-report.json";
const REGISTRY: &str = "planning-registry.sqlite";
const TIME: &str = "planning-time.sqlite";

pub const PREPARE_PLANNING_USAGE_V23: &str = "Pre-F6 public planning (no funding authority):\nprepare-planning-v23 --input ABSOLUTE_PRIVATE_JSON --output-dir ABSOLUTE_NEW_DIRECTORY\nAuthenticates supplied registry roots, terms, rosters, signed time policy and evidence. Produces route-pins.json for prepare-f6-artifact-v23 and dedicated durable planning stores. No private keys, signer, network, funds or daemon startup. Files must be 0600; parents canonical 0700. Existing output or incomplete staging is never overwritten or repaired. See docs/interop/hardening/PREPARE-PLANNING-V23.md.";

#[derive(Debug, thiserror::Error)]
pub enum PreparePlanningErrorV23 {
    #[error("invalid bounded public planning input")]
    Input,
    #[error("private planning path refused")]
    Path,
    #[error("planning output or incomplete staging already exists; nothing overwritten")]
    AlreadyPresent,
    #[error("signed registry, roster or route-time planning verification failed")]
    Verification,
    #[error("current planning clock is unavailable or moved backwards")]
    Clock,
    #[error("planning storage unavailable; preserve any incomplete staging")]
    Storage,
}
type Result<T> = std::result::Result<T, PreparePlanningErrorV23>;

#[derive(Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum ArtifactSource {
    File { path: PathBuf },
    CanonicalHex { hex: String },
}
impl ArtifactSource {
    fn snapshot(&mut self) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::File { path } => read_private(path, ARTIFACT_LIMIT)?.to_vec(),
            Self::CanonicalHex { hex } => {
                if hex.is_empty()
                    || hex.len() % 2 != 0
                    || hex.len() > ARTIFACT_LIMIT * 2
                    || !hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(PreparePlanningErrorV23::Input);
                }
                hex::decode(hex).map_err(|_| PreparePlanningErrorV23::Input)?
            }
        };
        *self = Self::CanonicalHex {
            hex: hex::encode(&bytes),
        };
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    schema: String,
    network_id: [u8; 32],
    route_id: [u8; 32],
    minimum_registry_epoch: u64,
    authorities: ArtifactSource,
    signed_registry: ArtifactSource,
    upstream_terms: ArtifactSource,
    downstream_terms: ArtifactSource,
    relay_roster: ArtifactSource,
    signed_time_policy: ArtifactSource,
    signed_time_evidence: ArtifactSource,
}

struct DecodedInput {
    network_id: [u8; 32],
    route_id: [u8; 32],
    minimum_registry_epoch: u64,
    authorities: ProductionAuthorityBundleV1,
    registry: SignedRegistryV1,
    terms: [SettlementTermsV1; 2],
    roster: ProductionRelayRosterBundleV1,
    policy: SignedRouteTimePolicyV2,
    evidence: SignedRouteTimeEvidenceV2,
}
impl DecodedInput {
    fn from_input(input: &mut PublicInput) -> Result<Self> {
        if input.schema != SCHEMA {
            return Err(PreparePlanningErrorV23::Input);
        }
        let invalid = |_| PreparePlanningErrorV23::Input;
        Ok(Self {
            network_id: input.network_id,
            route_id: input.route_id,
            minimum_registry_epoch: input.minimum_registry_epoch,
            authorities: ProductionAuthorityBundleV1::decode_canonical(
                &input.authorities.snapshot()?,
            )
            .map_err(invalid)?,
            registry: SignedRegistryV1::decode(&input.signed_registry.snapshot()?)
                .map_err(|_| PreparePlanningErrorV23::Input)?,
            terms: [
                SettlementTermsV1::decode(&input.upstream_terms.snapshot()?)
                    .map_err(|_| PreparePlanningErrorV23::Input)?,
                SettlementTermsV1::decode(&input.downstream_terms.snapshot()?)
                    .map_err(|_| PreparePlanningErrorV23::Input)?,
            ],
            roster: ProductionRelayRosterBundleV1::decode_canonical(
                &input.relay_roster.snapshot()?,
            )
            .map_err(invalid)?,
            policy: SignedRouteTimePolicyV2::decode(&input.signed_time_policy.snapshot()?)
                .map_err(|_| PreparePlanningErrorV23::Input)?,
            evidence: SignedRouteTimeEvidenceV2::decode(&input.signed_time_evidence.snapshot()?)
                .map_err(|_| PreparePlanningErrorV23::Input)?,
        })
    }
    fn planning(&self, now_seconds: u64) -> ProductionPreF6PlanningInputsV23<'_> {
        ProductionPreF6PlanningInputsV23 {
            signed_registry: &self.registry,
            authorities: &self.authorities,
            terms: [&self.terms[0], &self.terms[1]],
            signed_policy: &self.policy,
            signed_evidence: &self.evidence,
            rosters: &self.roster,
            route_id: self.route_id,
            network_id: self.network_id,
            minimum_registry_epoch: self.minimum_registry_epoch,
            now_seconds,
        }
    }
}

/// Public request facts verified under the supplied roots, not a transferable
/// capability. The daemon must separately pin those roots and reauthenticate.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlanningReportV23 {
    pub schema: String,
    pub grants_funding_authority: bool,
    pub network_access: bool,
    pub original_validation_seconds: u64,
    pub validated_at_seconds: u64,
    pub supplied_registry_roots_hex: String,
    pub route: serde_json::Value,
}

/// Create one immutable, owner-only planning export. No caller-selected clock
/// is exposed: canonical composition uses signed observation time, while the
/// real system clock gates registry/time freshness at entry and publication.
pub fn prepare_planning_command_v23(
    input_file: &Path,
    output_dir: &Path,
) -> Result<PreparedPlanningReportV23> {
    prepare_with_clock(input_file, output_dir, now_seconds)
}

fn now_seconds() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreparePlanningErrorV23::Clock)?
        .as_secs();
    if now == 0 {
        return Err(PreparePlanningErrorV23::Clock);
    }
    Ok(now)
}

fn prepare_with_clock(
    input_file: &Path,
    output_dir: &Path,
    mut clock: impl FnMut() -> Result<u64>,
) -> Result<PreparedPlanningReportV23> {
    let bytes = read_private(input_file, LIMIT)?;
    let mut input: PublicInput =
        serde_json::from_slice(&bytes).map_err(|_| PreparePlanningErrorV23::Input)?;
    let decoded = DecodedInput::from_input(&mut input)?;
    let snapshot = serde_json::to_vec(&input).map_err(|_| PreparePlanningErrorV23::Input)?;
    if snapshot.len() > LIMIT {
        return Err(PreparePlanningErrorV23::Input);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| PreparePlanningErrorV23::Storage)?;
    let secp = SecpContext::new(&seed);
    let now = clock()?;
    let planning_input = decoded.planning(now);
    let config = planning_input
        .time_store_config(&secp)
        .map_err(|_| PreparePlanningErrorV23::Verification)?;
    let publication = Publication::create(output_dir)?;
    publication.require_named()?;
    // These backends require canonical absolute filenames, not /proc/self/fd
    // aliases. The parent/staging capabilities remain held and are reconciled
    // before/after store use and again before no-replace publication.
    let registry = RegistryStoreV1::create(&publication.staging_path.join(REGISTRY))
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    let mut time =
        DurableRouteTimeAnchorStoreV2::create(&publication.staging_path.join(TIME), config)
            .map_err(|_| PreparePlanningErrorV23::Storage)?;
    let context =
        ProductionPreF6PlanningContextV23::prepare(registry, &mut time, &planning_input, &secp)
            .map_err(|_| PreparePlanningErrorV23::Verification)?;
    let route =
        serde_json::to_value(context.route_pins()).map_err(|_| PreparePlanningErrorV23::Storage)?;
    write_new(&publication.staging, SNAPSHOT, &snapshot)?;
    write_new(
        &publication.staging,
        ROUTE,
        &serde_json::to_vec(&route).map_err(|_| PreparePlanningErrorV23::Storage)?,
    )?;
    let current = clock()?;
    if current < now {
        return Err(PreparePlanningErrorV23::Clock);
    }
    context
        .require_current(&mut time, &planning_input, current, &secp)
        .map_err(|_| PreparePlanningErrorV23::Verification)?;
    let report = PreparedPlanningReportV23 {
        schema: REPORT_SCHEMA.into(),
        grants_funding_authority: false,
        network_access: false,
        original_validation_seconds: RouteTimeEvidenceV2::decode(decoded.evidence.evidence_bytes())
            .map_err(|_| PreparePlanningErrorV23::Input)?
            .observed_at_seconds(),
        validated_at_seconds: current,
        supplied_registry_roots_hex: hex::encode(
            decoded
                .authorities
                .registry()
                .authority_set_digest()
                .map_err(|_| PreparePlanningErrorV23::Verification)?,
        ),
        route,
    };
    // Close/checkpoint SQLite before renaming its directory. No open backend
    // is carried across publication and no temporary state is auto-deleted.
    drop(context);
    drop(time);
    publication.require_named()?;
    write_new(
        &publication.staging,
        REPORT,
        &serde_json::to_vec(&report).map_err(|_| PreparePlanningErrorV23::Storage)?,
    )?;
    publication.sync_files()?;
    publication.publish()?;
    Ok(report)
}

fn private_directory(path: &Path) -> Result<Dir> {
    crate::production_config::validate_state_dir(path)
        .map_err(|_| PreparePlanningErrorV23::Path)?;
    let before = std::fs::symlink_metadata(path).map_err(|_| PreparePlanningErrorV23::Path)?;
    let file = File::open(path).map_err(|_| PreparePlanningErrorV23::Path)?;
    let after = file.metadata().map_err(|_| PreparePlanningErrorV23::Path)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_dir()
        || after.uid() != rustix::process::geteuid().as_raw()
        || after.mode() & 0o7777 != 0o700
    {
        return Err(PreparePlanningErrorV23::Path);
    }
    Ok(Dir::from_std_file(file))
}
fn checked_file(dir: &Dir, name: &std::ffi::OsStr) -> Result<cap_std::fs::File> {
    let before = dir
        .symlink_metadata(name)
        .map_err(|_| PreparePlanningErrorV23::Path)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o600
    {
        return Err(PreparePlanningErrorV23::Path);
    }
    let file = dir
        .open(name)
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    let after = file
        .metadata()
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || !after.is_file()
        || after.nlink() != 1
        || after.uid() != rustix::process::geteuid().as_raw()
        || after.mode() & 0o7777 != 0o600
    {
        return Err(PreparePlanningErrorV23::Path);
    }
    Ok(file)
}
fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(PreparePlanningErrorV23::Path);
    }
    let dir = private_directory(path.parent().ok_or(PreparePlanningErrorV23::Path)?)?;
    let file = checked_file(&dir, path.file_name().ok_or(PreparePlanningErrorV23::Path)?)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit + 1));
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(PreparePlanningErrorV23::Input);
    }
    Ok(bytes)
}
fn write_new(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = dir
        .open_with(name, &options)
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
    checked_file(dir, name.as_ref())?;
    Ok(())
}

struct Publication {
    parent: Dir,
    staging: Dir,
    parent_path: PathBuf,
    staging_path: PathBuf,
    name: OsString,
    staging_name: OsString,
}
impl Publication {
    fn create(output: &Path) -> Result<Self> {
        if !output.is_absolute()
            || output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(PreparePlanningErrorV23::Path);
        }
        let parent_path = output
            .parent()
            .ok_or(PreparePlanningErrorV23::Path)?
            .to_path_buf();
        let parent = private_directory(&parent_path)?;
        let name = output
            .file_name()
            .filter(|name| name.len() <= 160)
            .ok_or(PreparePlanningErrorV23::Path)?
            .to_owned();
        let mut staging_name = name.clone();
        staging_name.push(".preparing-v23");
        for candidate in [&name, &staging_name] {
            match parent.symlink_metadata(candidate) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(PreparePlanningErrorV23::AlreadyPresent),
            }
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(&staging_name, &builder)
            .map_err(|_| PreparePlanningErrorV23::Storage)?;
        parent
            .open(".")
            .and_then(|f| f.sync_all())
            .map_err(|_| PreparePlanningErrorV23::Storage)?;
        let staging = parent
            .open_dir(&staging_name)
            .map_err(|_| PreparePlanningErrorV23::Storage)?;
        let staging_path = parent_path.join(&staging_name);
        let value = Self {
            parent,
            staging,
            parent_path,
            staging_path,
            name,
            staging_name,
        };
        value.require_named()?;
        Ok(value)
    }
    fn require_named(&self) -> Result<()> {
        let named_parent = private_directory(&self.parent_path)?;
        let named_staging = private_directory(&self.staging_path)?;
        for (named, held) in [
            (&named_parent, &self.parent),
            (&named_staging, &self.staging),
        ] {
            let named = named
                .dir_metadata()
                .map_err(|_| PreparePlanningErrorV23::Path)?;
            let held = held
                .dir_metadata()
                .map_err(|_| PreparePlanningErrorV23::Path)?;
            if named.dev() != held.dev() || named.ino() != held.ino() {
                return Err(PreparePlanningErrorV23::Path);
            }
        }
        Ok(())
    }
    fn sync_files(&self) -> Result<()> {
        for entry in self
            .staging
            .entries()
            .map_err(|_| PreparePlanningErrorV23::Storage)?
        {
            let name = entry
                .map_err(|_| PreparePlanningErrorV23::Storage)?
                .file_name();
            checked_file(&self.staging, &name)?
                .sync_all()
                .map_err(|_| PreparePlanningErrorV23::Storage)?;
        }
        self.staging
            .open(".")
            .and_then(|f| f.sync_all())
            .map_err(|_| PreparePlanningErrorV23::Storage)
    }
    fn publish(self) -> Result<()> {
        self.require_named()?;
        let root = self
            .parent
            .open(".")
            .map_err(|_| PreparePlanningErrorV23::Storage)?
            .into_std();
        rustix::fs::renameat_with(
            &root,
            &self.staging_name,
            &root,
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| PreparePlanningErrorV23::Storage)?;
        root.sync_all()
            .map_err(|_| PreparePlanningErrorV23::Storage)
    }
}

#[cfg(test)]
#[path = "production_prepare_planning_v23_tests.rs"]
mod tests;
