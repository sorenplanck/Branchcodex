//! Restricted pre-economic enrollment: no F6, route journal or time-store access.
//! This verifies public commitments and both native DLEQs, but never issues an
//! admission, signing, funding or time capability.

use super::*;
use crate::production_config::{
    validate_state_dir, ProductionBootstrapConfigV1, ProductionChainFamilyV11,
    MAX_PRODUCTION_BOOTSTRAP_BYTES_V1, PRODUCTION_CREATE_CONFIG_FILE_V11,
    PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use crate::production_prepare_xmr_enrollment_v23::EnrollmentErrorV23 as Error;
use std::path::{Path, PathBuf};
use xmr_session_init::{PreparedXmrShareEnrollmentV23, XmrLocalShareRoleV11};

pub(crate) struct EnrollmentContextV23 {
    pub enrollment: PreparedXmrShareEnrollmentV23,
    pub terms: SettlementTermsV1,
    pub public_enrollment: ProductionXmrEnrollmentBundleV23,
    pub role: XmrLocalShareRoleV11,
    pub network_id: [u8; 32],
    pub route_id: [u8; 32],
    pub registry_digest: [u8; 32],
    pub participant_digest: [u8; 32],
    pub session_id: [u8; 32],
}

fn resource(root: &Path, relative: &Path) -> Result<PathBuf, Error> {
    let path = crate::production_universal_leg_authority::existing_resource(
        root,
        relative.to_str().ok_or(Error::Context)?,
        false,
    )
    .map_err(|_| Error::Context)?;
    use std::os::unix::fs::MetadataExt;
    if std::fs::symlink_metadata(&path)
        .map_err(|_| Error::Context)?
        .nlink()
        != 1
    {
        return Err(Error::Context);
    }
    Ok(path)
}

fn public_bytes(path: &Path, bound: u64) -> Result<Vec<u8>, Error> {
    read_owner_file_bounded(
        path,
        bound,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| Error::Context)
}

pub(crate) fn load(
    state_dir: &Path,
    position: ProductionRoutePositionV1,
    local_participant: [u8; 32],
    reopen: bool,
) -> Result<EnrollmentContextV23, Error> {
    let root = validate_state_dir(state_dir).map_err(|_| Error::Context)?;
    let (name, mode) = if reopen {
        (
            PRODUCTION_REOPEN_CONFIG_FILE_V11,
            ProductionBootstrapModeV1::ReopenExisting,
        )
    } else {
        (
            PRODUCTION_CREATE_CONFIG_FILE_V11,
            ProductionBootstrapModeV1::Create,
        )
    };
    let config = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &public_bytes(
            &resource(&root, Path::new(name))?,
            MAX_PRODUCTION_BOOTSTRAP_BYTES_V1,
        )?,
        mode,
    )
    .map_err(|_| Error::Context)?;
    let pins = config.pins();
    let bytes = |role, bound| public_bytes(&resource(&root, config.relative_path(role))?, bound);
    let authorities = ProductionAuthorityBundleV1::decode_canonical(&bytes(
        ProductionPathRoleV1::RegistryAuthorities,
        MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1 as u64,
    )?)
    .map_err(|_| Error::Context)?;
    let secp = SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1);
    authorities
        .registry
        .validate_with_context(&secp)
        .map_err(|_| Error::Context)?;
    if authorities
        .registry
        .authority_set_digest()
        .map_err(|_| Error::Context)?
        != pins.registry_authority_set_digest
    {
        return Err(Error::Context);
    }
    let registry_path = resource(
        &root,
        config.relative_path(ProductionPathRoleV1::RegistryStore),
    )?;
    let store = RegistryStoreV1::open_existing(&registry_path).map_err(|_| Error::Context)?;
    let registry = if reopen {
        store.load_pinned(
            pins.registry_manifest_digest,
            &authorities.registry,
            &secp,
            pins.network_id,
        )
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Context)?
            .as_secs();
        store.load_current(
            &authorities.registry,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: now,
                expected_network_id: pins.network_id,
                minimum_epoch: pins.registry_minimum_epoch,
            },
        )
    }
    .map_err(|_| Error::Context)?
    .ok_or(Error::Context)?;
    if registry.manifest_digest() != pins.registry_manifest_digest
        || registry.epoch() < pins.registry_minimum_epoch
    {
        return Err(Error::Context);
    }
    let up = SettlementTermsV1::decode(&bytes(
        ProductionPathRoleV1::UpstreamTerms,
        MAX_TERMS_ARTIFACT_BYTES_V1,
    )?)
    .map_err(|_| Error::Context)?;
    let down = SettlementTermsV1::decode(&bytes(
        ProductionPathRoleV1::DownstreamTerms,
        MAX_TERMS_ARTIFACT_BYTES_V1,
    )?)
    .map_err(|_| Error::Context)?;
    if up.terms_hash().map_err(|_| Error::Context)? != pins.upstream_terms_digest
        || down.terms_hash().map_err(|_| Error::Context)? != pins.downstream_terms_digest
        || route_scope_digest(&up, &down).map_err(|_| Error::Context)? != pins.route_scope_digest
    {
        return Err(Error::Context);
    }
    let roster = ProductionRelayRosterBundleV1::decode_canonical(&bytes(
        ProductionPathRoleV1::RelayRoster,
        PRODUCTION_ROSTER_BUNDLE_BYTES_V1 as u64,
    )?)
    .map_err(|_| Error::Context)?;
    if roster.bundle_digest().map_err(|_| Error::Context)? != pins.relay_binding_digest
        || roster.network_id != pins.network_id
        || roster.route_id != pins.route_id
    {
        return Err(Error::Context);
    }
    validate_roster_terms(&roster, &up, &down, &secp).map_err(|_| Error::Context)?;
    let participants = ProductionParticipantBindingBundleV1::decode_canonical(&bytes(
        ProductionPathRoleV1::ParticipantBindings,
        MAX_PRODUCTION_PARTICIPANT_BUNDLE_SOLANA_ACCOUNTS_BYTES_V25 as u64,
    )?)
    .map_err(|_| Error::Context)?;
    if participants.bundle_digest().map_err(|_| Error::Context)? != pins.participant_bindings_digest
        || participants.route_id != pins.route_id
    {
        return Err(Error::Context);
    }
    let index = match position {
        ProductionRoutePositionV1::Upstream => 0,
        ProductionRoutePositionV1::Downstream => 1,
    };
    let terms = [&up, &down][index];
    let descriptor = &config.universal_v11().ok_or(Error::Context)?.legs[index];
    if descriptor.family != ProductionChainFamilyV11::Xmr
        || descriptor.chain_id != terms.counterparty_leg.chain_id.0
        || descriptor.settlement_id != terms.settlement_id.0
        || descriptor.session_id != terms.session_id.0
    {
        return Err(Error::Context);
    }
    let chain = registry
        .resolve_chain(terms.counterparty_leg.chain_id)
        .ok_or(Error::Context)?;
    let deployment = chain
        .monero_deployment_capability()
        .map_err(|_| Error::Context)?;
    let dom = registry
        .resolve_dom()
        .map_err(|_| Error::Context)?
        .deployment();
    if terms.counterparty_leg.asset_id != deployment.profile().native_asset
        || terms.counterparty_leg.finality != deployment.profile().finality
        || terms.dom_leg.chain_id != dom.chain_id
        || terms.dom_leg.asset_id != dom.native_asset
        || terms.dom_leg.finality != dom.finality
        || terms.dom_leg.adapter_profile_hash
            != route_time_anchor::resolved_dom_profile_digest_v1(&registry)
                .map_err(|_| Error::Context)?
    {
        return Err(Error::Context);
    }
    let legs: Vec<_> = participants
        .monero_legs
        .iter()
        .filter(|leg| leg.position == position)
        .collect();
    let [leg] = legs.as_slice() else {
        return Err(Error::Context);
    };
    let ChainKindV1::Monero { network } = chain.profile().kind else {
        return Err(Error::Context);
    };
    if network as u8 != leg.profile.network as u8 || leg.refund.is_some() {
        return Err(Error::Context);
    }
    let setup = xmr_setup_profile::validate_setup_for_chain_profile_v24(
        terms,
        &leg.profile,
        leg.binding.clone(),
        deployment.profile(),
    )
    .map_err(|_| Error::Context)?;
    let enrollment = leg
        .native_enrollment
        .as_ref()
        .ok_or(Error::Context)?
        .authenticate(terms, &setup)
        .map_err(|_| Error::Context)?;
    let participant = ParticipantId(local_participant);
    if local_participant == [0; 32]
        || !terms.roster.contains(&participant)
        || terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
    {
        return Err(Error::Context);
    }
    let role = if participant == terms.counterparty_leg.beneficiary {
        XmrLocalShareRoleV11::ClaimReceiver
    } else if participant == terms.counterparty_leg.refund_to {
        XmrLocalShareRoleV11::RefundReceiver
    } else {
        return Err(Error::Context);
    };
    Ok(EnrollmentContextV23 {
        enrollment,
        terms: terms.clone(),
        public_enrollment: leg
            .native_enrollment
            .as_ref()
            .ok_or(Error::Context)?
            .clone(),
        role,
        network_id: pins.network_id,
        route_id: pins.route_id,
        registry_digest: pins.registry_manifest_digest,
        participant_digest: pins.participant_bindings_digest,
        session_id: terms.session_id.0,
    })
}
