//! Differential tests through genuinely signed, resolved registry capabilities.
//! No raw deployment or caller-selected digest is promoted to an authority.
mod common;

use btc_crypto::SecpContext;
use deployment_registry::{
    AuthoritySetV1, DomNetworkV1, DomRuntimeIdentityV1, RegistryManifestV1, RegistrySignatureV1,
    RegistryValidationPolicyV1, ResolvedRegistryV1, SignedRegistryV1,
};
use dom_consensus::derive_chain_id;
use dom_core::configured_genesis_hash_for_network_magic;
use kaystra_core::types::{AssetId, ChainId};
use route_time_anchor::{
    resolved_dom_deployment_profile_digest_v25, resolved_dom_profile_digest_v1,
};
use std::error::Error;

const REGISTRY_KEYS_V25: [[u8; 32]; 3] = [[0x03; 32], [0x04; 32], [0x05; 32]];

fn signed(
    manifest: &RegistryManifestV1,
) -> Result<(SignedRegistryV1, AuthoritySetV1, SecpContext), Box<dyn Error>> {
    let secp = SecpContext::new(&[0x73; 32]);
    let keys = REGISTRY_KEYS_V25
        .iter()
        .enumerate()
        .map(|(index, key)| {
            secp.sign_bip340(key, &[0x41; 32], &[0x51 + index as u8; 32])
                .map(|(_, public)| public)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authorities = AuthoritySetV1::new(2, keys)?;
    let signatures = common::sign_digest(
        &secp,
        &REGISTRY_KEYS_V25,
        &manifest.manifest_digest()?,
        0x74,
    )
    .into_iter()
    .map(|signature| RegistrySignatureV1 {
        signer_index: signature.signer_index,
        signature: signature.signature,
    })
    .collect();
    Ok((
        SignedRegistryV1::new(manifest, signatures)?,
        authorities,
        secp,
    ))
}

fn validation(manifest: &RegistryManifestV1) -> RegistryValidationPolicyV1 {
    RegistryValidationPolicyV1 {
        now_seconds: common::EVIDENCE_TIME,
        expected_network_id: manifest.network_id,
        minimum_epoch: 7,
    }
}

fn authenticate(manifest: &RegistryManifestV1) -> Result<ResolvedRegistryV1, Box<dyn Error>> {
    let (signed, authorities, secp) = signed(manifest)?;
    Ok(signed.verify(&authorities, &secp, validation(manifest))?)
}

fn change_network(manifest: &mut RegistryManifestV1, network: DomNetworkV1) {
    let old_chain = manifest.dom.chain_id;
    let magic = network.canonical_magic();
    let genesis = configured_genesis_hash_for_network_magic(magic).unwrap();
    manifest.dom.chain_id = ChainId(*derive_chain_id(magic, &genesis).as_bytes());
    manifest.dom.genesis_hash = *genesis.as_bytes();
    manifest.dom.runtime_identity = DomRuntimeIdentityV1::pinned(network);
    for asset in &mut manifest.assets {
        if asset.chain_id == old_chain {
            asset.chain_id = manifest.dom.chain_id;
        }
    }
    manifest
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
}

#[test]
fn resolved_dom_deployment_matches_original_profile_on_all_authenticated_networks_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    let mut observed = Vec::new();
    for network in [
        DomNetworkV1::Regtest,
        DomNetworkV1::Testnet,
        DomNetworkV1::Mainnet,
    ] {
        let mut manifest = fixture.registry.manifest().clone();
        change_network(&mut manifest, network);
        let registry = authenticate(&manifest)?;
        let deployment = registry.resolve_dom()?;
        let original = resolved_dom_profile_digest_v1(&registry)?;
        assert_eq!(
            resolved_dom_deployment_profile_digest_v25(deployment)?,
            original
        );
        assert_eq!(deployment.deployment(), manifest.dom);
        assert_eq!(deployment.registry_digest(), registry.manifest_digest());
        observed.push(original);
    }
    assert_ne!(observed[0], observed[1]);
    assert_ne!(observed[0], observed[2]);
    assert_ne!(observed[1], observed[2]);
    Ok(())
}

#[test]
fn every_independently_mutable_dom_profile_field_changes_both_authenticated_digests_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    let baseline = resolved_dom_profile_digest_v1(&fixture.registry)?;
    // The remaining two of the twelve fields (chain/genesis) are coupled by
    // authenticated runtime identity and are covered by the network test above.
    for field in 0..10 {
        let mut manifest = fixture.registry.manifest().clone();
        match field {
            0 => manifest.dom.consensus_rules_digest[0] ^= 1,
            1 => manifest.dom.scriptless_api_version += 1,
            2 => manifest.dom.timing.min_block_seconds += 1,
            3 => manifest.dom.timing.max_block_seconds += 1,
            4 => manifest.dom.timing.max_reorg_seconds += 1,
            5 => manifest.dom.timing.observation_seconds += 1,
            6 => manifest.dom.timing.broadcast_seconds += 1,
            7 => manifest.dom.finality.min_confirmations += 1,
            8 => manifest.dom.finality.max_reorg_depth += 1,
            9 => {
                let previous = manifest.dom.native_asset;
                let dom_chain = manifest.dom.chain_id;
                manifest.dom.native_asset = AssetId([0x71; 32]);
                let binding = manifest
                    .assets
                    .iter_mut()
                    .find(|asset| asset.chain_id == dom_chain && asset.asset_id == previous)
                    .unwrap();
                binding.asset_id = manifest.dom.native_asset;
                manifest
                    .assets
                    .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
            }
            _ => unreachable!(),
        }
        let registry = authenticate(&manifest)?;
        let from_registry = resolved_dom_profile_digest_v1(&registry)?;
        let from_deployment = resolved_dom_deployment_profile_digest_v25(registry.resolve_dom()?)?;
        assert_eq!(from_deployment, from_registry, "field {field}");
        assert_ne!(
            from_deployment, baseline,
            "field {field} is part of the profile"
        );
    }
    Ok(())
}

#[test]
fn isolated_chain_genesis_and_runtime_changes_cannot_mint_resolved_dom_capability_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    for field in 0..5 {
        let mut manifest = fixture.registry.manifest().clone();
        match field {
            0 => manifest.dom.chain_id.0[0] ^= 1,
            1 => manifest.dom.genesis_hash[0] ^= 1,
            2 => manifest.dom.runtime_identity.network_magic ^= 1,
            3 => manifest.dom.runtime_identity.protocol_version += 1,
            4 => {
                manifest
                    .dom
                    .runtime_identity
                    .range_proof_serialization_version ^= 1
            }
            _ => unreachable!(),
        }
        // Re-signing an incoherent deployment cannot bypass the registry's
        // native identity validator; neither public profile API receives it.
        assert!(authenticate(&manifest).is_err(), "field {field}");
    }
    Ok(())
}

#[test]
fn dom_adapter_profile_remains_distinct_from_consensus_and_registry_domains_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    let resolved = fixture.registry.resolve_dom()?;
    let profile = resolved_dom_deployment_profile_digest_v25(resolved)?;
    assert_eq!(profile, fixture.upstream.dom_leg.adapter_profile_hash);
    assert_eq!(profile, fixture.downstream.dom_leg.adapter_profile_hash);
    assert_ne!(profile, resolved.deployment().consensus_rules_digest);
    assert_ne!(profile, resolved.registry_digest());
    assert_ne!(profile, resolved.native_asset_binding_digest());

    let mut manifest = fixture.registry.manifest().clone();
    manifest.dom.consensus_rules_digest = profile;
    let changed = authenticate(&manifest)?;
    let changed_profile = resolved_dom_deployment_profile_digest_v25(changed.resolve_dom()?)?;
    assert_eq!(changed_profile, resolved_dom_profile_digest_v1(&changed)?);
    assert_ne!(changed_profile, profile);
    assert_ne!(
        changed_profile,
        changed.manifest().dom.consensus_rules_digest
    );
    Ok(())
}

#[test]
fn registry_provenance_remains_separate_from_the_unchanged_twelve_field_dom_profile_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    let old = fixture.registry.resolve_dom()?;
    let mut manifest = fixture.registry.manifest().clone();
    manifest.epoch += 1;
    let registry = authenticate(&manifest)?;
    let new = registry.resolve_dom()?;
    assert_ne!(old.registry_digest(), new.registry_digest());
    assert_ne!(old.registry_epoch(), new.registry_epoch());
    assert_eq!(old.deployment(), new.deployment());
    assert_eq!(
        resolved_dom_deployment_profile_digest_v25(old)?,
        resolved_dom_deployment_profile_digest_v25(new)?,
    );
    assert_eq!(
        resolved_dom_profile_digest_v1(&fixture.registry)?,
        resolved_dom_profile_digest_v1(&registry)?,
    );
    Ok(())
}

#[test]
fn changed_dom_profile_with_old_registry_signatures_cannot_issue_typed_capability_v25(
) -> Result<(), Box<dyn Error>> {
    let fixture = common::fixture();
    let mut manifest = fixture.registry.manifest().clone();
    let (original, authorities, secp) = signed(&manifest)?;
    manifest.dom.timing.broadcast_seconds += 1;
    let substituted = SignedRegistryV1::new(&manifest, original.signatures().to_vec())?;
    assert!(substituted
        .verify(&authorities, &secp, validation(&manifest))
        .is_err());
    // The same changed profile is admissible only when authenticated anew.
    let resolved = authenticate(&manifest)?;
    assert_eq!(
        resolved_dom_profile_digest_v1(&resolved)?,
        resolved_dom_deployment_profile_digest_v25(resolved.resolve_dom()?)?,
    );
    Ok(())
}
