//! Resumable pre-admission bootstrap ceremony. The output uses the existing
//! bilateral codec; production admission independently reauthenticates it.
//! This command has no funding, claim, RPC broadcast or external signer port.
use super::*;
use crate::production_dom_shared_bootstrap_v12::{
    bootstrap_scope, shared_bootstrap_journal_binding_v12, ProductionBoundDomSharedOutputV12,
    ProductionDomSharedBootstrapV12,
};
use crate::production_dom_vaults_v12::provision_bootstrap_vault_v13;
use crate::production_inputs::ProductionAuthorityBundleV1;
use cap_std::fs::Dir;
use deployment_registry::{RegistryStoreV1, RegistryValidationPolicyV1};
use dom_actuator::{DomParticipantV1, DomSessionBindingV1};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{BudgetPolicyProfileV1, BudgetPolicyV1};
use serde::{Deserialize, Serialize};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[path = "production_bootstrap_xmr_cancelled_v22.rs"]
mod xmr_cancelled_v22;
pub(crate) use xmr_cancelled_v22::MountedCancelledContractsV22;

/// Durability barrier through a real descriptor.
///
/// The cap-std directory handle is O_PATH on Linux: *at() calls resolve
/// through it, but fsync on an O_PATH descriptor fails with EBADF whatever
/// the directory is, so "." is reopened as a plain directory fd first. This
/// mirrors `sync_directory` in the btc-vault and btc-live stores.
fn fsync_capability_dir(dir: &cap_std::fs::Dir) -> Result<(), rustix::io::Errno> {
    use std::os::fd::AsFd as _;
    let fd = rustix::fs::openat(
        dir.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    rustix::fs::fsync(fd.as_fd())
}

const NS: &[u8] = b"dom.bootstrap.ceremony.v13";
const OFFER: usize = 8 + 97 + 201;
const MAX_PACKET: u64 = 16_384;
const ARTIFACT: &str = "contracts-bootstrap-v13.bin";
const PLAN: &str = "bootstrap-plan.json";

/// Redacted preparation failures never contain keys, private input or peer bytes.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapCommandErrorV13 {
    /// Invalid public plan, credentials or native authenticated binding.
    #[error("bootstrap V13 input or binding refused")]
    Binding,
    /// Missing, replaced, corrupted or incorrectly unlocked local custody.
    #[error("bootstrap V13 retained custody refused; preserve its files")]
    Custody,
    /// A peer message contradicts the selected session or signed transcript.
    #[error("bootstrap V13 peer message conflicts with the ceremony")]
    Peer,
    /// Durable publication or journal recovery failed.
    #[error("bootstrap V13 storage refused; preserve its files before retry")]
    Storage,
}
type Result13<T> = Result<T, BootstrapCommandErrorV13>;

/// Public progress; no private scalar or signed transaction is serialized.
#[derive(Debug, Serialize)]
pub struct BootstrapProgressV13 {
    /// Current completed barrier or next required peer files.
    pub stage: &'static str,
    /// Locally published public packets to exchange with the other participants.
    pub local_packets: Vec<String>,
    /// Missing packet names. Absence is not a malformed-message result.
    pub awaiting: Vec<String>,
    /// Exact final commit digest for the existing V5+ manifest pins.
    pub commit_stage_digest: Option<String>,
    /// Exact final reveal digest for the existing V5+ manifest pins.
    pub reveal_stage_digest: Option<String>,
    /// Always false: bootstrap preparation does not admit or fund a route.
    pub funding_authorized: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: u32,
    network_id: [u8; 32],
    route_id: [u8; 32],
    registry_authority_set_digest: [u8; 32],
    registry_manifest_digest: [u8; 32],
    minimum_registry_epoch: u64,
    terms_digests: [[u8; 32]; 2],
    roster_digest: [u8; 32],
    local_participant_id: [u8; 32],
    authority_bundle_file: PathBuf,
    registry_store: PathBuf,
    terms_files: [PathBuf; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    xmr_compensation_policy_files: Option<[Option<PathBuf>; 2]>,
    roster_file: PathBuf,
    identity_store: PathBuf,
    budget_policy_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets<'a> {
    #[serde(borrow)]
    identity_passphrase: &'a str,
    #[serde(borrow)]
    upstream_relay_secret: Option<&'a str>,
    #[serde(borrow)]
    downstream_relay_secret: Option<&'a str>,
}
struct Context {
    expected: ExpectedContextV1,
    rosters: ProductionRelayRosterBundleV1,
    bindings: [[DomSessionBindingV1; 2]; 2],
    chain: TrustedChainIdV1,
    xmr_policies: [Option<xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11>; 2],
}

fn bounded_owner_read(path: &Path, max: u64) -> Result13<Vec<u8>> {
    crate::production_config::read_owner_file_bounded(
        path,
        max,
        crate::production_config::ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| BootstrapCommandErrorV13::Storage)
}
fn private_directory(path: &Path) -> Result13<Arc<Dir>> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| BootstrapCommandErrorV13::Storage)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o7777 != 0o700
        || meta.uid() != rustix::process::getuid().as_raw()
    {
        return Err(BootstrapCommandErrorV13::Storage);
    }
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
        .map(Arc::new)
        .map_err(|_| BootstrapCommandErrorV13::Storage)
}
fn lock_preparation(work: &Path, cap: &Dir) -> Result13<std::fs::File> {
    use BootstrapCommandErrorV13::Storage;
    let path = work.join("bootstrap-owner-v13.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| Storage)?;
    let m = file.metadata().map_err(|_| Storage)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() != 0
        || m.mode() & 0o7777 != 0o600
        || m.uid() != rustix::process::getuid().as_raw()
    {
        return Err(Storage);
    }
    rustix::fs::flock(
        file.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_| Storage)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| Storage)?;
    if named.dev() != m.dev() || named.ino() != m.ino() {
        return Err(Storage);
    }
    file.sync_all().map_err(|_| Storage)?;
    fsync_capability_dir(cap).map_err(|_| Storage)?;
    Ok(file)
}
fn packet_name(stage: &str, slot: usize) -> String {
    format!("{stage}-{slot}.bin")
}
fn hash(domain: &[u8], bytes: &[u8]) -> Result13<[u8; 32]> {
    digest_v1(domain, bytes).map_err(|_| BootstrapCommandErrorV13::Binding)
}
fn array<const N: usize>(bytes: &[u8]) -> Result13<[u8; N]> {
    bytes.try_into().map_err(|_| BootstrapCommandErrorV13::Peer)
}
fn key(text: &str) -> Result13<Zeroizing<[u8; 32]>> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BootstrapCommandErrorV13::Binding);
    }
    let mut out = Zeroizing::new([0; 32]);
    for (i, p) in text.as_bytes().chunks_exact(2).enumerate() {
        let d = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = d(p[0]) * 16 + d(p[1]);
    }
    if *out == [0; 32] {
        return Err(BootstrapCommandErrorV13::Binding);
    }
    Ok(out)
}
fn read_secrets(mut reader: impl Read) -> Result13<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0; 16_385]);
    let mut length = 0;
    while length < bytes.len() {
        match reader.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(n) => length += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(BootstrapCommandErrorV13::Binding),
        }
    }
    if length == 0 || length > 16_384 {
        return Err(BootstrapCommandErrorV13::Binding);
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn load_context(plan: &Plan, secp: &SecpContext, resume: bool) -> Result13<Context> {
    use BootstrapCommandErrorV13::Binding;
    if plan.schema != 13
        || plan.local_participant_id == [0; 32]
        || plan.route_id == [0; 32]
        || plan.network_id == [0; 32]
        || plan.minimum_registry_epoch == 0
    {
        return Err(Binding);
    }
    let authorities = ProductionAuthorityBundleV1::decode_canonical(&bounded_owner_read(
        &plan.authority_bundle_file,
        65536,
    )?)
    .map_err(|_| Binding)?;
    authorities
        .registry()
        .validate_with_context(secp)
        .map_err(|_| Binding)?;
    if authorities
        .registry()
        .authority_set_digest()
        .map_err(|_| Binding)?
        != plan.registry_authority_set_digest
    {
        return Err(Binding);
    }
    let registry_store =
        RegistryStoreV1::open_existing(&plan.registry_store).map_err(|_| Binding)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Binding)?
        .as_secs();
    let registry = if resume {
        registry_store.load_pinned(
            plan.registry_manifest_digest,
            authorities.registry(),
            secp,
            plan.network_id,
        )
    } else {
        registry_store.load_current(
            authorities.registry(),
            secp,
            RegistryValidationPolicyV1 {
                now_seconds: now,
                expected_network_id: plan.network_id,
                minimum_epoch: plan.minimum_registry_epoch,
            },
        )
    }
    .map_err(|_| Binding)?
    .ok_or(Binding)?;
    if registry.manifest_digest() != plan.registry_manifest_digest {
        return Err(Binding);
    }
    let rosters = ProductionRelayRosterBundleV1::decode_canonical(&bounded_owner_read(
        &plan.roster_file,
        8192,
    )?)
    .map_err(|_| Binding)?;
    if rosters.bundle_digest().map_err(|_| Binding)? != plan.roster_digest
        || rosters.network_id() != plan.network_id
        || rosters.route_id() != plan.route_id
    {
        return Err(Binding);
    }
    let mut expected_legs = Vec::new();
    let mut bindings = Vec::new();
    let mut xmr_policies = Vec::new();
    for i in 0..2 {
        let bytes = bounded_owner_read(&plan.terms_files[i], 8192)?;
        let terms = SettlementTermsV1::decode(&bytes).map_err(|_| Binding)?;
        if terms.canonical_bytes().map_err(|_| Binding)? != bytes
            || terms.terms_hash().map_err(|_| Binding)? != plan.terms_digests[i]
        {
            return Err(Binding);
        }
        let policy_path = plan
            .xmr_compensation_policy_files
            .as_ref()
            .and_then(|paths| paths[i].as_ref());
        let xmr_policy = if let Some(path) = policy_path {
            let bytes = bounded_owner_read(path, 4096)?;
            Some(
                xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(&bytes)
                    .map_err(|_| Binding)?
                    .validate_for(&terms)
                    .map_err(|_| Binding)?,
            )
        } else {
            if plan.xmr_compensation_policy_files.is_some()
                && terms.counterparty_leg.mechanism
                    == kaystra_core::types::LockMechanism::CrossCurveSharedSpend
            {
                return Err(Binding);
            }
            None
        };
        xmr_policies.push(xmr_policy);
        expected_legs.push(
            ExpectedLegV1::from_authenticated(&terms, &rosters.legs()[i]).map_err(|_| Binding)?,
        );
        let mut leg = Vec::new();
        for p in 0..2 {
            let mut encoded_key = [2; 33];
            encoded_key[1..].copy_from_slice(&rosters.legs()[i].members[p].xonly_key);
            PublicKey::from_compressed_bytes(&encoded_key).map_err(|_| Binding)?;
            leg.push(
                DomSessionBindingV1::from_resolved_deployment(
                    plan.route_id,
                    terms.session_id.0,
                    DomParticipantV1::new(terms.roster[p].0, p as u8).map_err(|_| Binding)?,
                    plan.terms_digests[i],
                    registry.resolve_dom().map_err(|_| Binding)?,
                )
                .map_err(|_| Binding)?,
            );
        }
        bindings.push(leg.try_into().map_err(|_| Binding)?);
    }
    let dom = registry.resolve_dom().map_err(|_| Binding)?;
    let expected = ExpectedContextV1 {
        network_id: plan.network_id,
        route_id: plan.route_id,
        registry_digest: registry.manifest_digest(),
        registry_epoch: registry.epoch(),
        dom_chain_id: dom.deployment().chain_id.0,
        dom_genesis_hash: dom.deployment().genesis_hash,
        legs: expected_legs.try_into().map_err(|_| Binding)?,
    };
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        dom.deployment().runtime_identity.network_magic,
        &dom_core::Hash256::from_bytes(expected.dom_genesis_hash),
    );
    if chain.as_bytes() != &expected.dom_chain_id {
        return Err(Binding);
    }
    Ok(Context {
        expected,
        rosters,
        bindings: bindings.try_into().map_err(|_| Binding)?,
        chain,
        xmr_policies: xmr_policies.try_into().map_err(|_| Binding)?,
    })
}

fn blank_bundle(context: &Context) -> Result13<DecodedBundleV1> {
    let e = &context.expected;
    let mut legs = Vec::new();
    for i in 0..2 {
        let roster = &context.rosters.legs()[i];
        let mut participants = Vec::new();
        for p in 0..2 {
            participants.push(DecodedParticipantV1 {
                participant_id: roster.members[p].participant_id,
                direction: direction_for_relay_role(roster.members[p].role)
                    .map_err(|_| BootstrapCommandErrorV13::Binding)?,
                key_reference: [0; 32],
                noise_public_key: [0; 32],
                schnorr_public_key: [0; 33],
                share_point: [0; 33],
                contribution_commitment: [0; 32],
                contribution_reveal: [0; DECOY_VARIABLE_LEN],
            });
        }
        legs.push(DecodedLegV1 {
            position: roster.position,
            session_id: e.legs[i].session_id,
            terms_hash: e.legs[i].terms_hash,
            roster_snapshot: roster.roster_snapshot,
            policy_version: roster.policy_version,
            participants: participants
                .try_into()
                .map_err(|_| BootstrapCommandErrorV13::Binding)?,
            recovery_capsule: [0; 96],
        });
    }
    Ok(DecodedBundleV1 {
        network_id: e.network_id,
        route_id: e.route_id,
        registry_digest: e.registry_digest,
        registry_epoch: e.registry_epoch,
        dom_chain_id: e.dom_chain_id,
        dom_genesis_hash: e.dom_genesis_hash,
        contract_kind: ContractKindV1::WitnessOrTimeout,
        legs: legs
            .try_into()
            .map_err(|_| BootstrapCommandErrorV13::Binding)?,
        claimed_commit_digest: [0; 32],
        commit_signatures: [[0; 64]; 4],
        reveal_signatures: [[0; 64]; 4],
    })
}

fn apply_offer(
    context: &Context,
    decoded: &mut DecodedBundleV1,
    slot: usize,
    bytes: &[u8],
    secp: &SecpContext,
) -> Result13<()> {
    use BootstrapCommandErrorV13::Peer;
    if bytes.len() != OFFER || &bytes[..8] != b"DOMBOF13" {
        return Err(Peer);
    }
    let (l, p) = (slot / 2, slot % 2);
    let r = &context.rosters.legs()[l];
    let commit = &bytes[105..];
    if &commit[..8] != b"DOMSCM12"
        || commit[8..40] != bootstrap_scope(context.bindings[l][p], r)
        || commit[40..72] != r.members[p].participant_id.0
    {
        return Err(Peer);
    }
    secp.verify_bip340(
        &r.members[p].xonly_key,
        &hash(b"DOM/SHARED-BOOTSTRAP/SIGNATURE/V12\0", &commit[..137])?,
        &array(&commit[137..])?,
    )
    .map_err(|_| Peer)?;
    let entry = &mut decoded.legs[l].participants[p];
    entry.key_reference = array(&bytes[8..40])?;
    entry.noise_public_key = array(&bytes[40..72])?;
    entry.schnorr_public_key = array(&bytes[72..105])?;
    entry.share_point = array(&commit[72..105])?;
    entry.contribution_commitment = array(&commit[105..137])?;
    let public = PublicKey::from_compressed_bytes(&entry.schnorr_public_key).map_err(|_| Peer)?;
    audit_retained_participant_id_v1(
        &context.expected.dom_chain_id,
        &entry.participant_id.0,
        &public,
    )
    .map_err(|_| Peer)?;
    PublicKey::from_compressed_bytes(&entry.share_point).map_err(|_| Peer)?;
    if entry.key_reference == [0; 32]
        || entry.noise_public_key == [0; 32]
        || entry.contribution_commitment == [0; 32]
        || context
            .rosters
            .legs()
            .iter()
            .flat_map(|leg| leg.members.iter())
            .any(|member| member.xonly_key == entry.schnorr_public_key[1..])
    {
        return Err(Peer);
    }
    Ok(())
}
pub(super) fn signer_digest(
    decoded: &DecodedBundleV1,
    rosters: &ProductionRelayRosterBundleV1,
    slot: usize,
    reveal: bool,
) -> Result13<[u8; 32]> {
    let commit = digest_v1(COMMIT_DIGEST_DOMAIN_V1, &encode_commit_unsigned_v1(decoded))
        .map_err(|_| BootstrapCommandErrorV13::Binding)?;
    let stage = if reveal {
        digest_v1(
            REVEAL_DIGEST_DOMAIN_V1,
            &encode_reveal_unsigned_v1(decoded, commit),
        )
        .map_err(|_| BootstrapCommandErrorV13::Binding)?
    } else {
        commit
    };
    stage_signer_digest_v1(
        if reveal {
            REVEAL_SIGNER_DIGEST_DOMAIN_V1
        } else {
            COMMIT_SIGNER_DIGEST_DOMAIN_V1
        },
        stage,
        reveal.then_some(commit),
        &decoded.legs[slot / 2],
        &decoded.legs[slot / 2].participants[slot % 2],
        rosters.legs()[slot / 2].members[slot % 2].role,
        rosters.legs()[slot / 2].members[slot % 2].xonly_key,
    )
    .map_err(|_| BootstrapCommandErrorV13::Binding)
}
fn apply_reveal(
    context: &Context,
    decoded: &mut DecodedBundleV1,
    slot: usize,
    bytes: &[u8],
    offer: &[u8],
    secp: &SecpContext,
) -> Result13<()> {
    use BootstrapCommandErrorV13::Peer;
    if bytes.len() != 260
        || &bytes[..8] != b"DOMSRV12"
        || bytes[8..72] != offer[113..177]
        || bytes[72..104] != hash(b"DOM/SHARED-BOOTSTRAP/COMMIT/V12\0", &offer[105..242])?
    {
        return Err(Peer);
    }
    secp.verify_bip340(
        &context.rosters.legs()[slot / 2].members[slot % 2].xonly_key,
        &hash(b"DOM/SHARED-BOOTSTRAP/SIGNATURE/V12\0", &bytes[..196])?,
        &array(&bytes[196..])?,
    )
    .map_err(|_| Peer)?;
    decoded.legs[slot / 2].participants[slot % 2].contribution_reveal = array(&bytes[104..196])?;
    Ok(())
}

fn open_prepared_journal(
    path: &Path,
    binding: store::ProductionStoreBindingV1,
    allow_create: bool,
) -> Result13<store::Store> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_create => {
            store::Store::prepare_resume_create_production(path, binding)
                .map_err(|_| BootstrapCommandErrorV13::Storage)?;
        }
        Err(_) => return Err(BootstrapCommandErrorV13::Custody),
    }
    store::Store::open_or_resume_prepared_production(path, binding, binding)
        .map_err(|_| BootstrapCommandErrorV13::Storage)
}

struct Journal {
    store: store::Store,
    path: PathBuf,
    cap: Arc<Dir>,
}
impl Journal {
    fn retain(&mut self, name: &str, bytes: &[u8]) -> Result13<()> {
        if bytes.len() > MAX_PACKET as usize {
            return Err(BootstrapCommandErrorV13::Storage);
        }
        self.store
            .put_opaque(NS, name.as_bytes(), bytes)
            .map_err(|_| BootstrapCommandErrorV13::Storage)
    }
    fn get(&self, name: &str) -> Result13<Option<Vec<u8>>> {
        self.store
            .opaque(NS, name.as_bytes())
            .map_err(|_| BootstrapCommandErrorV13::Storage)
    }
    fn receive(&mut self, name: &str) -> Result13<Option<Vec<u8>>> {
        let path = self.path.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = bounded_owner_read(&path, MAX_PACKET)?;
                if let Some(retained) = self.get(name)? {
                    if retained != bytes {
                        return Err(BootstrapCommandErrorV13::Peer);
                    }
                }
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.get(name),
            Err(_) => Err(BootstrapCommandErrorV13::Storage),
        }
    }
    fn publish(&mut self, name: &str, bytes: &[u8]) -> Result13<()> {
        self.retain(name, bytes)?;
        // Under the native exclusive Store lock, a public output can resume only
        // an exact prefix of its immutable journal record. Never replace bytes.
        let path = self.path.join(name);
        write_exact_public(self.cap.as_ref(), &path, bytes)
    }
}
fn write_exact_public(cap: &Dir, path: &Path, bytes: &[u8]) -> Result13<()> {
    if bytes.len() > MAX_PACKET as usize {
        return Err(BootstrapCommandErrorV13::Storage);
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| BootstrapCommandErrorV13::Storage)?;
    let m = file
        .metadata()
        .map_err(|_| BootstrapCommandErrorV13::Storage)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.uid() != rustix::process::getuid().as_raw()
        || m.len() > bytes.len() as u64
    {
        return Err(BootstrapCommandErrorV13::Storage);
    }
    let mut previous = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_PACKET + 1)
        .read_to_end(&mut previous)
        .map_err(|_| BootstrapCommandErrorV13::Storage)?;
    if !bytes.starts_with(&previous) {
        return Err(BootstrapCommandErrorV13::Storage);
    }
    file.write_all(&bytes[previous.len()..])
        .and_then(|_| file.sync_all())
        .map_err(|_| BootstrapCommandErrorV13::Storage)?;
    let named = std::fs::symlink_metadata(&path).map_err(|_| BootstrapCommandErrorV13::Storage)?;
    if named.dev() != m.dev()
        || named.ino() != m.ino()
        || named.len() != bytes.len() as u64
        || named.nlink() != 1
    {
        return Err(BootstrapCommandErrorV13::Storage);
    }
    fsync_capability_dir(cap).map_err(|_| BootstrapCommandErrorV13::Storage)?;
    Ok(())
}
struct Local {
    slot: usize,
    owner: Option<ProductionDomSharedBootstrapV12>,
    bound: Option<ProductionBoundDomSharedOutputV12>,
}

/// Advance only the bootstrap ceremony using public files and a bounded private
/// stdin. Repeat with the same plan/custody after copying the missing peer files.
pub fn bootstrap_command_v13(plan_path: &Path, work_dir: &Path) -> Result13<BootstrapProgressV13> {
    crate::require_operational_artifact_v1().map_err(|_| BootstrapCommandErrorV13::Binding)?;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(BootstrapCommandErrorV13::Binding);
    }
    let secret_bytes = read_secrets(stdin.lock())?;
    execute(plan_path, work_dir, &secret_bytes)
}
fn execute(
    plan_path: &Path,
    work_dir: &Path,
    secret_bytes: &[u8],
) -> Result13<BootstrapProgressV13> {
    use BootstrapCommandErrorV13::{Binding, Custody, Peer, Storage};
    if !plan_path.is_absolute() || secret_bytes.contains(&b'\\') {
        return Err(Binding);
    }
    let secrets: Secrets<'_> = serde_json::from_slice(secret_bytes).map_err(|_| Binding)?;
    if secrets.identity_passphrase.is_empty() || secrets.identity_passphrase.len() > 4096 {
        return Err(Binding);
    }
    let relay = [
        secrets.upstream_relay_secret.map(key).transpose()?,
        secrets.downstream_relay_secret.map(key).transpose()?,
    ];
    if matches!((&relay[0],&relay[1]),(Some(a),Some(b)) if a.as_slice()==b.as_slice()) {
        return Err(Binding);
    }
    let plan_bytes = bounded_owner_read(plan_path, 16_384)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes).map_err(|_| Binding)?;
    let mut entropy = Zeroizing::new([0; 32]);
    getrandom::getrandom(entropy.as_mut()).map_err(|_| Custody)?;
    let secp = SecpContext::new(&entropy);
    let context = load_context(&plan, &secp, false)?;
    for l in 0..2 {
        let participates = context.rosters.legs()[l]
            .members
            .iter()
            .any(|m| m.participant_id.0 == plan.local_participant_id);
        if participates != relay[l].is_some() {
            return Err(Binding);
        }
        if let Some(secret) = &relay[l] {
            let public = secp.xonly_public_key(secret).map_err(|_| Binding)?;
            let member = context.rosters.legs()[l]
                .members
                .iter()
                .find(|m| m.participant_id.0 == plan.local_participant_id)
                .ok_or(Binding)?;
            if public != member.xonly_key {
                return Err(Binding);
            }
        }
    }
    let root = private_directory(work_dir)?;
    let _preparation_lock = lock_preparation(work_dir, root.as_ref())?;
    let policy = BudgetPolicyV1::from_bytes(&bounded_owner_read(&plan.budget_policy_file, 4096)?)
        .map_err(|_| Binding)?;
    if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
        return Err(Binding);
    }
    let identity_parent = private_directory(plan.identity_store.parent().ok_or(Binding)?)?;
    let passphrase =
        ContractsIdentityPassphraseV1::new(secrets.identity_passphrase.as_bytes().to_vec())
            .map_err(|_| Custody)?;
    let identity = ContractsTransportIdentityStoreV1::open_production(
        identity_parent,
        plan.identity_store
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Binding)?,
        &passphrase,
    )
    .map_err(|_| Custody)?;
    let reference = identity.reference();
    audit_retained_participant_id_v1(
        &context.expected.dom_chain_id,
        &plan.local_participant_id,
        &PublicKey::from_compressed_bytes(reference.schnorr_public_key()).map_err(|_| Binding)?,
    )
    .map_err(|_| Binding)?;
    let binding =
        store::ProductionStoreBindingV1::new(hash(b"DOM/BOOTSTRAP-JOURNAL/V13\0", &plan_bytes)?)
            .map_err(|_| Binding)?;
    // This immutable public preparation record is durable before native
    // prepared Store creation. Re-entry is authorized only for identical bytes.
    write_exact_public(root.as_ref(), &work_dir.join(PLAN), &plan_bytes)?;
    let journal_path = work_dir.join("ceremony.sqlite");
    let native = open_prepared_journal(&journal_path, binding, true)?;
    let mut journal = Journal {
        store: native,
        path: work_dir.to_path_buf(),
        cap: Arc::clone(&root),
    };
    let snapshot = journal
        .store
        .production_audit_snapshot(
            store::ProductionAuditLimitsV1::new(32, 262144, MAX_PACKET).map_err(|_| Storage)?,
        )
        .map_err(|_| Storage)?;
    if !snapshot.revisions().is_empty()
        || !snapshot.journal().is_empty()
        || snapshot
            .opaque_records()
            .iter()
            .any(|r| r.namespace() != NS || !valid_record_name(r.key()))
    {
        return Err(Storage);
    }
    drop(snapshot);
    let mut unlock_material =
        Zeroizing::new(Vec::with_capacity(secrets.identity_passphrase.len() + 32));
    unlock_material.extend_from_slice(secrets.identity_passphrase.as_bytes());
    unlock_material.extend_from_slice(&plan.local_participant_id);
    let unlock = Zeroizing::new(hash(b"DOM/BOOTSTRAP-PRIVATE-ROOT/V13\0", &unlock_material)?);
    let mut locals = Vec::new();
    for l in 0..2 {
        for p in 0..2 {
            if context.rosters.legs()[l].members[p].participant_id.0 == plan.local_participant_id {
                let slot = l * 2 + p;
                let b = context.bindings[l][p];
                let allow_create = journal.get(&packet_name("offer", slot))?.is_none();
                let vault = provision_bootstrap_vault_v13(
                    Arc::clone(&root),
                    b,
                    &unlock,
                    policy.clone(),
                    allow_create,
                )
                .map_err(|_| Custody)?;
                let private_path = work_dir.join(format!("shared-{slot}.sqlite"));
                let sb = shared_bootstrap_journal_binding_v12(b, &context.rosters.legs()[l])
                    .map_err(|_| Binding)?;
                let shared = open_prepared_journal(&private_path, sb, allow_create)?;
                let owner = if allow_create {
                    ProductionDomSharedBootstrapV12::open(
                        vault,
                        shared,
                        b,
                        context.chain,
                        context.rosters.legs()[l],
                    )
                } else {
                    ProductionDomSharedBootstrapV12::open_retained(
                        vault,
                        shared,
                        b,
                        context.chain,
                        context.rosters.legs()[l],
                    )
                }
                .map_err(|_| Custody)?;
                locals.push(Local {
                    slot,
                    owner: Some(owner),
                    bound: None,
                });
            }
        }
    }
    if locals.is_empty() {
        return Err(Binding);
    }
    let mut progress = BootstrapProgressV13 {
        stage: "offers",
        local_packets: Vec::new(),
        awaiting: Vec::new(),
        commit_stage_digest: None,
        reveal_stage_digest: None,
        funding_authorized: false,
    };
    if !xmr_cancelled_v22::prepare(
        &context,
        &plan,
        &root,
        work_dir,
        &unlock,
        &policy,
        &relay,
        &mut journal,
        &mut progress,
    )? {
        return Ok(progress);
    }
    for local in &mut locals {
        let mut packet = b"DOMBOF13".to_vec();
        packet.extend_from_slice(reference.key_reference());
        packet.extend_from_slice(reference.noise_public_key());
        packet.extend_from_slice(reference.schnorr_public_key());
        packet.extend_from_slice(
            &local
                .owner
                .as_mut()
                .ok_or(Custody)?
                .local_commit(relay[local.slot / 2].as_deref().ok_or(Custody)?)
                .map_err(|_| Custody)?,
        );
        let name = packet_name("offer", local.slot);
        journal.publish(&name, &packet)?;
        progress.local_packets.push(name);
    }
    let mut decoded = blank_bundle(&context)?;
    let mut offers = Vec::new();
    for slot in 0..4 {
        let name = packet_name("offer", slot);
        match journal.receive(&name)? {
            Some(bytes) => {
                apply_offer(&context, &mut decoded, slot, &bytes, &secp)?;
                journal.retain(&name, &bytes)?;
                offers.push(bytes);
            }
            None => progress.awaiting.push(name),
        }
    }
    if !progress.awaiting.is_empty() {
        return Ok(progress);
    }
    verify_scope_v1(&decoded, &context.expected, &context.rosters).map_err(|_| Peer)?;
    // Public identity/reference/point collisions are rejected before any
    // commit signature. Reveal-dependent checks follow only the commit barrier.
    for a in 0..4 {
        for b in 0..a {
            let x = &decoded.legs[a / 2].participants[a % 2];
            let y = &decoded.legs[b / 2].participants[b % 2];
            if x.share_point == y.share_point
                || (x.participant_id == y.participant_id
                    && (x.key_reference != y.key_reference
                        || x.noise_public_key != y.noise_public_key
                        || x.schnorr_public_key != y.schnorr_public_key))
                || (x.participant_id != y.participant_id
                    && (x.key_reference == y.key_reference
                        || x.noise_public_key == y.noise_public_key
                        || x.schnorr_public_key == y.schnorr_public_key))
            {
                return Err(Peer);
            }
        }
    }
    for local in &mut locals {
        local
            .owner
            .as_mut()
            .ok_or(Custody)?
            .accept_peer_commit(&offers[local.slot ^ 1][105..])
            .map_err(|_| Peer)?;
    }
    if !signature_barrier(
        &mut journal,
        &context.rosters,
        &mut decoded,
        &locals,
        &relay,
        &secp,
        &mut progress,
        false,
    )? {
        return Ok(progress);
    }
    for local in &mut locals {
        let bytes = local
            .owner
            .as_mut()
            .ok_or(Custody)?
            .local_reveal(relay[local.slot / 2].as_deref().ok_or(Custody)?)
            .map_err(|_| Custody)?;
        let name = packet_name("reveal", local.slot);
        journal.publish(&name, &bytes)?;
        progress.local_packets.push(name);
    }
    progress.stage = "reveals";
    let mut reveals = Vec::new();
    for slot in 0..4 {
        let name = packet_name("reveal", slot);
        match journal.receive(&name)? {
            Some(bytes) => {
                apply_reveal(&context, &mut decoded, slot, &bytes, &offers[slot], &secp)?;
                journal.retain(&name, &bytes)?;
                reveals.push(bytes);
            }
            None => progress.awaiting.push(name),
        }
    }
    if !progress.awaiting.is_empty() {
        return Ok(progress);
    }
    for l in 0..2 {
        let a = DecoyRevealV1::from_bytes(decoded.legs[l].participants[0].contribution_reveal);
        let b = DecoyRevealV1::from_bytes(decoded.legs[l].participants[1].contribution_reveal);
        let commit =
            DecoyCommitmentV1::from_bytes(decoded.legs[l].participants[1].contribution_commitment);
        decoded.legs[l].recovery_capsule = *combine_decoy_capsule_v1(&a, &b, &commit)
            .map_err(|_| Peer)?
            .as_bytes();
    }
    verify_public_material_v1(&decoded, &context.rosters).map_err(|_| Peer)?;
    for local in &mut locals {
        let bound = local
            .owner
            .take()
            .ok_or(Custody)?
            .finish(&reveals[local.slot ^ 1])
            .map_err(|_| Custody)?;
        if bound.capsule.as_bytes() != &decoded.legs[local.slot / 2].recovery_capsule {
            return Err(Custody);
        }
        local.bound = Some(bound);
    }
    if !signature_barrier(
        &mut journal,
        &context.rosters,
        &mut decoded,
        &locals,
        &relay,
        &secp,
        &mut progress,
        true,
    )? {
        return Ok(progress);
    }
    let commit_unsigned = encode_commit_unsigned_v1(&decoded);
    let commit_digest =
        digest_v1(COMMIT_DIGEST_DOMAIN_V1, &commit_unsigned).map_err(|_| Binding)?;
    let mut artifact = commit_unsigned;
    for signature in decoded.commit_signatures {
        artifact.extend_from_slice(&signature);
    }
    artifact.extend_from_slice(&encode_reveal_unsigned_v1(&decoded, commit_digest));
    for signature in decoded.reveal_signatures {
        artifact.extend_from_slice(&signature);
    }
    let verified =
        authenticate_against_expected_v1(&artifact, &context.expected, &context.rosters, &secp)
            .map_err(|_| Peer)?;
    xmr_cancelled_v22::prepare_contracts(
        &context,
        &plan,
        &root,
        work_dir,
        &unlock,
        &policy,
        &identity,
        &verified,
        &mut journal,
    )?;
    journal.publish(ARTIFACT, &artifact)?;
    progress.local_packets.push(ARTIFACT.into());
    progress.stage = "complete";
    progress.commit_stage_digest = Some(hex::encode(verified.commit_stage_digest()));
    progress.reveal_stage_digest = Some(hex::encode(verified.reveal_stage_digest()));
    Ok(progress)
}
/// Private owners mounted by Stage 10 and retained for the live Stage-12 graph.
/// No scalar export or public constructor; a completed signed artifact alone
/// is insufficient to manufacture this ownership.
pub(crate) struct MountedBootstrapV13 {
    pub(crate) _shares: [ProductionBoundDomSharedOutputV12; 2],
    pub(crate) _cancelled_shares: [Option<ProductionBoundDomSharedOutputV12>; 2],
    pub(crate) _cancelled_contracts: [Option<MountedCancelledContractsV22>; 2],
    _ceremony: Journal,
}

/// The reserved basename is part of the operator's pinned bootstrap path.
/// A selected V13 artifact cannot silently downgrade when custody is missing.
pub(crate) fn resume_completed_bootstrap_v13(
    artifact_path: &Path,
    expected: &AuthenticatedContractsBootstrapV1,
    bindings: [DomSessionBindingV1; 2],
    identity_path: &Path,
    identity_passphrase: &[u8],
) -> Result13<Option<MountedBootstrapV13>> {
    use BootstrapCommandErrorV13::{Binding, Custody, Peer, Storage};
    if artifact_path.file_name() != Some(std::ffi::OsStr::new(ARTIFACT)) {
        return Ok(None);
    }
    let work = artifact_path.parent().ok_or(Binding)?;
    let cap = private_directory(work)?;
    let bytes = bounded_owner_read(&work.join(PLAN), MAX_PACKET)?;
    let plan: Plan = serde_json::from_slice(&bytes).map_err(|_| Binding)?;
    if plan.identity_store != identity_path
        || identity_passphrase.is_empty()
        || identity_passphrase.len() > 4096
    {
        return Err(Binding);
    }
    let mut entropy = Zeroizing::new([0; 32]);
    getrandom::getrandom(entropy.as_mut()).map_err(|_| Custody)?;
    let secp = SecpContext::new(&entropy);
    let context = load_context(&plan, &secp, true)?;
    let sb = store::ProductionStoreBindingV1::new(hash(b"DOM/BOOTSTRAP-JOURNAL/V13\0", &bytes)?)
        .map_err(|_| Binding)?;
    // Runtime is reopen-only; it never prepares or creates missing databases.
    let native =
        store::Store::open_production(&work.join("ceremony.sqlite"), sb).map_err(|_| Custody)?;
    let mut journal = Journal {
        store: native,
        path: work.to_path_buf(),
        cap: Arc::clone(&cap),
    };
    let audit = journal
        .store
        .production_audit_snapshot(
            store::ProductionAuditLimitsV1::new(32, 262144, MAX_PACKET).map_err(|_| Storage)?,
        )
        .map_err(|_| Storage)?;
    if !audit.revisions().is_empty()
        || !audit.journal().is_empty()
        || audit
            .opaque_records()
            .iter()
            .any(|r| r.namespace() != NS || !valid_record_name(r.key()))
    {
        return Err(Storage);
    }
    drop(audit);
    let artifact = bounded_owner_read(artifact_path, MAX_PACKET)?;
    if journal.get(ARTIFACT)?.as_deref() != Some(artifact.as_slice()) {
        return Err(Custody);
    }
    let authenticated =
        authenticate_against_expected_v1(&artifact, &context.expected, &context.rosters, &secp)
            .map_err(|_| Peer)?;
    if authenticated.commit_stage_digest() != expected.commit_stage_digest()
        || authenticated.reveal_stage_digest() != expected.reveal_stage_digest()
    {
        return Err(Binding);
    }
    let policy = BudgetPolicyV1::from_bytes(&bounded_owner_read(&plan.budget_policy_file, 4096)?)
        .map_err(|_| Binding)?;
    if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
        return Err(Binding);
    }
    let mut material = Zeroizing::new(Vec::with_capacity(identity_passphrase.len() + 32));
    material.extend_from_slice(identity_passphrase);
    material.extend_from_slice(&plan.local_participant_id);
    let unlock = Zeroizing::new(hash(b"DOM/BOOTSTRAP-PRIVATE-ROOT/V13\0", &material)?);
    let mut shares = Vec::new();
    for leg in 0..2 {
        let position = context.rosters.legs()[leg]
            .members
            .iter()
            .position(|m| m.participant_id.0 == plan.local_participant_id)
            .ok_or(Binding)?;
        let binding = context.bindings[leg][position];
        if binding != bindings[leg] {
            return Err(Binding);
        }
        let slot = 2 * leg + position;
        let vault = provision_bootstrap_vault_v13(
            Arc::clone(&cap),
            binding,
            &unlock,
            policy.clone(),
            false,
        )
        .map_err(|_| Custody)?;
        let private_binding =
            shared_bootstrap_journal_binding_v12(binding, &context.rosters.legs()[leg])
                .map_err(|_| Binding)?;
        let private = store::Store::open_production(
            &work.join(format!("shared-{slot}.sqlite")),
            private_binding,
        )
        .map_err(|_| Custody)?;
        let share = ProductionDomSharedBootstrapV12::open_retained(
            vault,
            private,
            binding,
            context.chain,
            context.rosters.legs()[leg],
        )
        .map_err(|_| Custody)?
        .finish_retained()
        .map_err(|_| Custody)?;
        if share
            .capability
            .binding()
            .share_point()
            .to_compressed_bytes()
            != *expected.legs()[leg].participants()[position].share_point()
            || share.capsule.as_bytes() != expected.legs()[leg].recovery_capsule()
        {
            return Err(Custody);
        }
        shares.push(share);
    }
    let cancelled_shares =
        xmr_cancelled_v22::resume(&context, &plan, &cap, work, &unlock, &policy)?;
    Ok(Some(MountedBootstrapV13 {
        _shares: shares.try_into().map_err(|_| Custody)?,
        _cancelled_shares: cancelled_shares,
        _cancelled_contracts: xmr_cancelled_v22::resume_contracts(
            &context, &plan, &cap, &policy, &journal,
        )?,
        _ceremony: journal,
    }))
}

fn valid_record_name(name: &[u8]) -> bool {
    name == ARTIFACT.as_bytes()
        || (0..4).any(|slot| {
            [
                "offer",
                "commit-signature",
                "reveal",
                "reveal-signature",
                "cancelled-offer",
                "cancelled-reveal",
                "cancelled-contracts-prepare",
                "cancelled-contracts-ready",
            ]
            .iter()
            .any(|stage| name == packet_name(stage, slot).as_bytes())
        })
}
fn signature_barrier(
    journal: &mut Journal,
    rosters: &ProductionRelayRosterBundleV1,
    decoded: &mut DecodedBundleV1,
    locals: &[Local],
    relay: &[Option<Zeroizing<[u8; 32]>>; 2],
    secp: &SecpContext,
    progress: &mut BootstrapProgressV13,
    reveal: bool,
) -> Result13<bool> {
    use BootstrapCommandErrorV13::{Custody, Peer};
    let stage = if reveal {
        "reveal-signature"
    } else {
        "commit-signature"
    };
    progress.stage = stage;
    for local in locals {
        let name = packet_name(stage, local.slot);
        let digest = signer_digest(decoded, rosters, local.slot, reveal)?;
        let signature = if let Some(bytes) = journal.get(&name)? {
            bytes
        } else {
            let mut aux = Zeroizing::new([0; 32]);
            getrandom::getrandom(aux.as_mut()).map_err(|_| Custody)?;
            secp.sign_bip340(
                relay[local.slot / 2].as_deref().ok_or(Custody)?,
                &digest,
                &aux,
            )
            .map_err(|_| Custody)?
            .0
            .to_vec()
        };
        secp.verify_bip340(
            &rosters.legs()[local.slot / 2].members[local.slot % 2].xonly_key,
            &digest,
            &array(&signature)?,
        )
        .map_err(|_| Peer)?;
        journal.publish(&name, &signature)?;
        progress.local_packets.push(name);
    }
    for slot in 0..4 {
        let name = packet_name(stage, slot);
        match journal.receive(&name)? {
            Some(bytes) => {
                let signature = array(&bytes)?;
                secp.verify_bip340(
                    &rosters.legs()[slot / 2].members[slot % 2].xonly_key,
                    &signer_digest(decoded, rosters, slot, reveal)?,
                    &signature,
                )
                .map_err(|_| Peer)?;
                journal.retain(&name, &bytes)?;
                if reveal {
                    decoded.reveal_signatures[slot] = signature;
                } else {
                    decoded.commit_signatures[slot] = signature;
                }
            }
            None => progress.awaiting.push(name),
        }
    }
    Ok(progress.awaiting.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn journal(path: &Path) -> Journal {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binding = store::ProductionStoreBindingV1::new([13; 32]).unwrap();
        Journal {
            store: store::Store::create_production(&path.join("ceremony.sqlite"), binding).unwrap(),
            path: path.to_path_buf(),
            cap: private_directory(path).unwrap(),
        }
    }
    fn progress() -> BootstrapProgressV13 {
        BootstrapProgressV13 {
            stage: "offers",
            local_packets: vec![],
            awaiting: vec![],
            commit_stage_digest: None,
            reveal_stage_digest: None,
            funding_authorized: false,
        }
    }
    #[test]
    fn publication_resumes_every_exact_prefix_and_never_replaces_conflict() {
        let temporary = tempfile::tempdir().unwrap();
        let mut journal = journal(temporary.path());
        let packet = b"public bootstrap message";
        for cut in 0..=packet.len() {
            let name = format!("offer-{cut}.bin");
            let path = temporary.path().join(&name);
            std::fs::write(&path, &packet[..cut]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            journal.publish(&name, packet).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), packet);
            assert!(journal.publish(&name, b"another value").is_err());
            assert_eq!(std::fs::read(&path).unwrap(), packet);
        }
    }
    #[test]
    fn absent_packet_is_distinct_from_corrupt_or_substituted_packet() {
        let temporary = tempfile::tempdir().unwrap();
        let mut journal = journal(temporary.path());
        assert!(journal.receive("offer-0.bin").unwrap().is_none());
        journal.publish("offer-0.bin", b"retained").unwrap();
        std::fs::write(temporary.path().join("offer-0.bin"), b"different").unwrap();
        assert!(matches!(
            journal.receive("offer-0.bin"),
            Err(BootstrapCommandErrorV13::Peer)
        ));
        std::fs::remove_file(temporary.path().join("offer-0.bin")).unwrap();
        assert_eq!(
            journal.receive("offer-0.bin").unwrap(),
            Some(b"retained".to_vec())
        );
    }
    #[test]
    fn no_follow_and_no_hardlink_for_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let mut journal = journal(temporary.path());
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, temporary.path().join("offer-0.bin")).unwrap();
        assert!(journal.publish("offer-0.bin", b"desired").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        std::fs::hard_link(&outside, temporary.path().join("offer-1.bin")).unwrap();
        assert!(journal.publish("offer-1.bin", b"desired").is_err());
    }
    #[test]
    fn private_input_is_bounded_and_borrowed_without_escapes() {
        let bytes = read_secrets(&b"{}"[..]).unwrap();
        assert_eq!(bytes.capacity(), 16_385);
        assert!(read_secrets(std::io::repeat(b'x').take(16_385)).is_err());
        let request=br#"{"identity_passphrase":"private","upstream_relay_secret":null,"downstream_relay_secret":null}"#;
        let parsed: Secrets<'_> = serde_json::from_slice(request).unwrap();
        let pointer = parsed.identity_passphrase.as_ptr() as usize;
        assert!(
            (request.as_ptr() as usize..request.as_ptr() as usize + request.len())
                .contains(&pointer)
        );
        assert!(serde_json::from_slice::<Secrets<'_>>(
            br#"{"identity_passphrase":"private","unknown":true}"#
        )
        .is_err());
    }
    #[test]
    fn four_actual_signature_slots_gate_both_stages_and_reassemble_legacy_artifact() {
        let fixture = super::super::tests::fixture();
        let mut decoded = decode_canonical_v1(&fixture.bytes).unwrap();
        decoded.commit_signatures = [[0; 64]; 4];
        decoded.reveal_signatures = [[0; 64]; 4];
        let temporary = tempfile::tempdir().unwrap();
        let mut journal = journal(temporary.path());
        for reveal in [false, true] {
            for slot in 0..4 {
                let public = fixture.roster.legs()[slot / 2].members[slot % 2].xonly_key;
                let secret = super::super::tests::RELAY_SECRETS
                    .into_iter()
                    .find(|key| {
                        fixture.secp.sign_bip340(key, &[1; 32], &[2; 32]).unwrap().1 == public
                    })
                    .unwrap();
                let mut relay: [Option<Zeroizing<[u8; 32]>>; 2] = [None, None];
                relay[slot / 2] = Some(Zeroizing::new(secret));
                let local = [Local {
                    slot,
                    owner: None,
                    bound: None,
                }];
                let mut result = progress();
                let complete = signature_barrier(
                    &mut journal,
                    &fixture.roster,
                    &mut decoded,
                    &local,
                    &relay,
                    &fixture.secp,
                    &mut result,
                    reveal,
                )
                .unwrap();
                assert_eq!(complete, slot == 3);
                assert_eq!(result.awaiting.len(), 3 - slot);
                assert!(!result.funding_authorized);
            }
        }
        let commit = encode_commit_unsigned_v1(&decoded);
        let digest = digest_v1(COMMIT_DIGEST_DOMAIN_V1, &commit).unwrap();
        let mut artifact = commit;
        for sig in decoded.commit_signatures {
            artifact.extend_from_slice(&sig);
        }
        artifact.extend_from_slice(&encode_reveal_unsigned_v1(&decoded, digest));
        for sig in decoded.reveal_signatures {
            artifact.extend_from_slice(&sig);
        }
        authenticate_against_expected_v1(
            &artifact,
            &fixture.expected,
            &fixture.roster,
            &fixture.secp,
        )
        .unwrap();
        let commit_digest = signer_digest(&decoded, &fixture.roster, 0, false).unwrap();
        let reveal_digest = signer_digest(&decoded, &fixture.roster, 0, true).unwrap();
        assert_ne!(commit_digest, reveal_digest);
        assert!(fixture
            .secp
            .verify_bip340(
                &fixture.roster.legs()[0].members[0].xonly_key,
                &reveal_digest,
                &decoded.commit_signatures[0]
            )
            .is_err());
        // Restart reuses the exact old signatures, including their randomness.
        let old = journal.get("commit-signature-0.bin").unwrap().unwrap();
        drop(journal);
        let mut reopened = Journal {
            store: store::Store::open_production(
                &temporary.path().join("ceremony.sqlite"),
                store::ProductionStoreBindingV1::new([13; 32]).unwrap(),
            )
            .unwrap(),
            path: temporary.path().into(),
            cap: private_directory(temporary.path()).unwrap(),
        };
        reopened.publish("commit-signature-0.bin", &old).unwrap();
        assert_eq!(
            reopened.receive("commit-signature-0.bin").unwrap().unwrap(),
            old
        );
    }
    #[test]
    fn concurrent_preparation_is_rejected_before_plan_publication() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let cap = private_directory(temporary.path()).unwrap();
        let first = lock_preparation(temporary.path(), cap.as_ref()).unwrap();
        assert!(lock_preparation(temporary.path(), cap.as_ref()).is_err());
        assert!(!temporary.path().join(PLAN).exists());
        drop(first);
        drop(lock_preparation(temporary.path(), cap.as_ref()).unwrap());
    }
    #[test]
    fn record_namespace_is_closed() {
        for slot in 0..4 {
            for stage in ["offer", "commit-signature", "reveal", "reveal-signature"] {
                assert!(valid_record_name(packet_name(stage, slot).as_bytes()));
            }
        }
        for invalid in [
            b"offer-4.bin".as_slice(),
            b"../offer-0.bin",
            b"reveal-00.bin",
            b"claim-0.bin",
        ] {
            assert!(!valid_record_name(invalid));
        }
    }
}

#[cfg(test)]
#[path = "production_bootstrap_v13_tests.rs"]
pub(crate) mod native_ceremony_tests;
