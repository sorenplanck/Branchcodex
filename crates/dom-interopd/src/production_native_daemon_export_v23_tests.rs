//! Test-only writer for the real daemon's signed F6 bundle and V11 companions.
//! This accepts full authenticated admission, not the graph component fixture.
//! The six RFQ-late F6 stores remain absent: Stage 11 publishes their native
//! prepared prefixes and the authenticated pair factory finishes them later.
use super::*;
use crate::production_config::{
    load_production_bootstrap_v11, production_f6_authority_bundle_digest_v8,
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    ProductionUniversalBootstrapFieldsV11, ProductionUniversalLegV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_REOPEN_CONFIG_FILE_V11,
};

#[path = "production_native_f6_context_v23_tests.rs"]
mod context_v23;
pub(crate) use context_v23::NativeF6ContextV23;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Public signer endpoint descriptor; the signing key stays with the HSM owner.
pub(crate) struct NativeF6SignerEndpointV23 {
    pub independent_authority_id: Digest32,
    pub signer_index: u16,
    pub signer_public_key: [u8; 32],
    pub endpoint_uid: u32,
    pub endpoint: PathBuf,
}

pub(crate) enum NativeF6ClaimInputsV23 {
    Bound {
        role_plan: ComposedFinalClaimRolePlanV1,
        sources: [FinalClaimSecretSourceScopeV1; 2],
    },
    /// Initial roles/T/terms only. Real Store templates are required later.
    NativeEnrollment,
}

/// Economic inputs must come from the scenario's actual inventory/bond owners.
/// No default digest or authority is supplied by this writer.
pub(crate) struct NativeF6BundleInputsV23 {
    pub solver: ParticipantId,
    pub inventory_binding_digest: Digest32,
    pub bond_policy_hash: Digest32,
    pub bond_asset_binding_digest: Digest32,
    pub required_collateral: u128,
    pub status_max_lifetime_seconds: u64,
    pub pre_f6_limits: PreF6TimePolicyLimitsV2,
    pub bond_authorities: AuthoritySetV1,
    pub status_authorities: AuthoritySetV1,
    pub reserved_participant_keys: Vec<[u8; 32]>,
    pub signers: [Vec<NativeF6SignerEndpointV23>; 2],
    pub claim_profile: NativeF6ClaimInputsV23,
}

/// Encodes exactly DOMF6A07 and verifies threshold signatures through the
/// production signature verifier before returning public bytes. First-export
/// later runs the complete production decoder against reloaded admission.
/// The callback signs the
/// domain-separated digest with real fixture-owned registry authority keys.
pub(crate) fn encode_native_f6_bundle_v23(
    admitted: &impl NativeF6ContextV23,
    input: &NativeF6BundleInputsV23,
    sign: impl FnOnce(Digest32) -> Result<Vec<(u16, [u8; 64])>>,
) -> Result<Vec<u8>> {
    context_v23::validate_input(admitted, input)?;
    let mut bytes = Vec::new();
    let (magic, version, domain) = match &input.claim_profile {
        NativeF6ClaimInputsV23::Bound { .. } => {
            (BUNDLE_MAGIC_V7, BUNDLE_VERSION_V7, BUNDLE_DOMAIN_V7)
        }
        NativeF6ClaimInputsV23::NativeEnrollment => (
            claim_enrollment_v23::MAGIC_V23,
            claim_enrollment_v23::VERSION_V23,
            claim_enrollment_v23::DOMAIN_V23,
        ),
    };
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    for digest in [
        admitted.roster_bundle().network_id(),
        admitted.admission().route_id(),
        admitted.composition().binding_digest(),
        admitted.composition().route_scope_digest(),
        admitted.resolved_registry().manifest_digest(),
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&admitted.resolved_registry().epoch().to_be_bytes());
    for digest in [
        admitted.admission().frozen_bindings().profile_bundle_digest,
        input.solver.0,
        input.inventory_binding_digest,
        input.bond_policy_hash,
        input.bond_asset_binding_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&input.required_collateral.to_be_bytes());
    for value in [
        input.status_max_lifetime_seconds,
        input.pre_f6_limits.valid_from_seconds,
        input.pre_f6_limits.expires_at_seconds,
        input.pre_f6_limits.max_evidence_age_seconds,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for authority in [&input.bond_authorities, &input.status_authorities] {
        append_sized(
            &mut bytes,
            &authority.canonical_bytes()?,
            MAX_AUTHORITY_BYTES_V7,
        )?;
    }
    let relay = admitted
        .roster_bundle()
        .legs()
        .iter()
        .flat_map(|leg| leg.members.iter().map(|member| member.xonly_key))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let chain = admitted
        .registry_authorities()
        .xonly_keys()
        .iter()
        .chain(admitted.time_policy_authorities().xonly_keys())
        .chain(admitted.time_evidence_authorities().xonly_keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    for keys in [&relay, &input.reserved_participant_keys, &chain] {
        if keys.is_empty() || keys.len() > MAX_SIGNERS_V7 {
            return Err("native F6 reserved key count".into());
        }
        bytes.extend_from_slice(&u16::try_from(keys.len())?.to_be_bytes());
        for key in keys {
            bytes.extend_from_slice(key);
        }
    }
    for signers in &input.signers {
        if !(2..=MAX_SIGNERS_V7).contains(&signers.len()) {
            return Err("native F6 signer count".into());
        }
        bytes.extend_from_slice(&u16::try_from(signers.len())?.to_be_bytes());
        for signer in signers {
            bytes.extend_from_slice(&signer.independent_authority_id);
            bytes.extend_from_slice(&signer.signer_index.to_be_bytes());
            bytes.extend_from_slice(&signer.signer_public_key);
            bytes.extend_from_slice(&signer.endpoint_uid.to_be_bytes());
            append_sized(
                &mut bytes,
                signer
                    .endpoint
                    .to_str()
                    .ok_or("native F6 endpoint encoding")?
                    .as_bytes(),
                MAX_ENDPOINT_BYTES_V7,
            )?;
        }
    }
    match &input.claim_profile {
        NativeF6ClaimInputsV23::Bound { role_plan, sources } => {
            bytes.extend_from_slice(&role_plan.canonical_bytes());
            for source in sources {
                bytes.extend_from_slice(&source.canonical_bytes());
            }
        }
        NativeF6ClaimInputsV23::NativeEnrollment => {
            bytes.extend_from_slice(
                claim_enrollment_v23::NativeClaimEnrollmentV23::from_composition(
                    admitted.composition(),
                )?
                .bytes(),
            );
        }
    }
    let signed_prefix_len = bytes.len();
    let signatures = sign(digest_parts(&[domain, &bytes])?)?;
    if signatures.len() > MAX_SIGNERS_V7 {
        return Err("native F6 root signature count".into());
    }
    bytes.extend_from_slice(&u16::try_from(signatures.len())?.to_be_bytes());
    for (index, signature) in signatures {
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&signature);
    }
    let mut signatures = BundleReaderV7::new(&bytes[signed_prefix_len..]);
    verify_bundle_signatures(
        &mut signatures,
        &bytes[..signed_prefix_len],
        admitted.registry_authorities(),
        admitted.verification_context(),
    )?;
    signatures.finish()?;
    Ok(bytes)
}

fn append_sized(bytes: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err("native F6 bounded field".into());
    }
    bytes.extend_from_slice(&u16::try_from(value.len())?.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

/// Only a fully checked export can be handed to the process runner. No Clone
/// or Debug implementation can copy/log its stdin credentials implicitly.
pub(crate) struct ExportedNativeDaemonV23 {
    pub(crate) state_dir: PathBuf,
    pub(crate) stdin_v4: Zeroizing<Vec<u8>>,
    pub(crate) route_id: Digest32,
    pub(crate) config_digest: Digest32,
}

/// Paths are chosen by the scenario; identities are always overwritten from
/// the exact authenticated topology and terms, never supplied as hash literals.
pub(crate) fn export_native_daemon_v23(
    state: &Path,
    admitted: &AuthenticatedProductionInputsV1,
    common: [ProductionBootstrapConfigV1; 2],
    mut fields: ProductionUniversalBootstrapFieldsV11,
    bundle: &[u8],
    leg_bundles: [&[u8]; 2],
    stdin_v4: Zeroizing<Vec<u8>>,
) -> Result<ExportedNativeDaemonV23> {
    use settlement_coordinator::SettlementFaceV1;
    let topology =
        crate::production_route_topology::ProductionRouteTopologyV4::authenticate(admitted)?;
    AuthenticatedProductionF6AuthorityBundleV7::decode_and_authenticate(bundle, admitted)?;
    fields.f6_authority_bundle_digest = production_f6_authority_bundle_digest_v8(bundle)?;
    for (index, terms) in [
        admitted.composition().upstream(),
        admitted.composition().downstream(),
    ]
    .into_iter()
    .enumerate()
    {
        let leg = topology.legs[index];
        if leg.face != SettlementFaceV1::Monero {
            return Err("native daemon exporter requires XMR positions".into());
        }
        fields.legs[index] = ProductionUniversalLegV11 {
            family: ProductionChainFamilyV11::Xmr,
            settlement_id: leg.settlement_id,
            session_id: terms.session_id.0,
            chain_id: leg.chain_id,
            authority_bundle_digest: ProductionUniversalLegV11::bundle_digest(leg_bundles[index])?,
            ..fields.legs[index].clone()
        };
    }
    for (index, leg) in [
        route_executor::LegIdV1::Upstream,
        route_executor::LegIdV1::Downstream,
    ]
    .into_iter()
    .enumerate()
    {
        crate::production_universal_leg_authority::ProductionUniversalLegAuthorityV11::decode(
            leg_bundles[index],
            &fields.legs[index],
            admitted,
            leg,
        )?;
    }
    let decoded = crate::production_node::ProductionSecretsV4::read(stdin_v4.as_slice())?;
    // Parsing and exact family matching precede filesystem publication.
    let _ = decoded.into_parts([ProductionChainFamilyV11::Xmr; 2])?;
    for config in &common {
        let pins = config.pins();
        if pins.network_id != admitted.roster_bundle().network_id()
            || pins.route_id != topology.route_id
            || pins.registry_manifest_digest != topology.registry_digest
            || pins.registry_minimum_epoch > admitted.resolved_registry().epoch()
            || pins.registry_authority_set_digest
                != admitted.registry_authorities().authority_set_digest()?
            || pins.upstream_terms_digest != admitted.composition().upstream().terms_hash()?
            || pins.downstream_terms_digest != admitted.composition().downstream().terms_hash()?
            || pins.route_scope_digest != admitted.composition().route_scope_digest()
            || pins.relay_binding_digest != admitted.roster_bundle().bundle_digest()?
        {
            return Err("native daemon common pins differ from authenticated admission".into());
        }
    }
    let [create, reopen] = common;
    if create.mode() != ProductionBootstrapModeV1::Create
        || reopen.mode() != ProductionBootstrapModeV1::ReopenExisting
    {
        return Err("native daemon companion modes".into());
    }
    let create = ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(create, fields.clone())?;
    let reopen = ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(reopen, fields.clone())?;
    let create_bytes = create.canonical_bytes()?;
    let reopen_bytes = reopen.canonical_bytes()?;
    // Both manifests must encode the same public configuration except mode.
    // The canonical loader below checks companions and every external input.
    for (leg, bytes) in fields.legs.iter().zip(leg_bundles) {
        publish_input(state, &leg.authority_bundle, bytes)?;
    }
    publish_input(state, &fields.f6_paths[6], bundle)?;
    publish_input(state, PRODUCTION_CREATE_CONFIG_FILE_V11, &create_bytes)?;
    publish_input(state, PRODUCTION_REOPEN_CONFIG_FILE_V11, &reopen_bytes)?;
    let loaded = load_production_bootstrap_v11(state, ProductionBootstrapModeV1::Create)?;
    loaded.require_universal_admission_v11(admitted)?;
    Ok(ExportedNativeDaemonV23 {
        state_dir: state.to_path_buf(),
        stdin_v4,
        route_id: topology.route_id,
        config_digest: digest_parts(&[
            b"DOM-INTEROP/TEST/DAEMON-EXPORT/V23\0",
            &create_bytes,
            &reopen_bytes,
        ])?,
    })
}

fn publish_input(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(relative);
    if !root.is_absolute()
        || std::fs::canonicalize(root)? != root
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("native daemon export path".into());
    }
    let mut parent = root.to_path_buf();
    for component in std::iter::once(None).chain(
        path.parent()
            .into_iter()
            .flat_map(|p| p.components())
            .map(Some),
    ) {
        if let Some(component) = component {
            parent.push(component.as_os_str());
        }
        let metadata = std::fs::symlink_metadata(&parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native daemon export parent".into());
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
        .open(root.join(path))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
