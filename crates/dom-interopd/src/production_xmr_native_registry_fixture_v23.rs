//! Explicit offline deployment profiles, checked by the real registry validator.
use adapter_btc::timelock::ChainTimingBoundsV1;
use chain_profile::{ChainKindV1, ChainProfileV1, MoneroNetworkV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, ChainDeploymentV1, MoneroDeploymentV1,
    RegistryChainProfileV1, RegistryManifestV1,
};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{AssetId, ChainId, TimelockSpec},
};

pub(crate) fn configure(
    manifest: &mut RegistryManifestV1,
    terms: [&mut SettlementTermsV1; 2],
) -> Result<(), Box<dyn std::error::Error>> {
    configure_network(manifest, terms, xmr_setup_profile::XmrNetwork::Stagenet)
}

pub(crate) fn configure_network(
    manifest: &mut RegistryManifestV1,
    terms: [&mut SettlementTermsV1; 2],
    selected: xmr_setup_profile::XmrNetwork,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = chain_for_network_v24(selected, terms[0].counterparty_leg.finality)?;
    let chain = entry.profile.chain_id;
    let asset = entry.profile.native_asset;
    let finality = entry.profile.finality;
    let digest = entry.profile.profile_digest()?;
    manifest.chains = vec![entry];
    manifest
        .assets
        .retain(|entry| entry.chain_id == manifest.dom.chain_id);
    manifest.assets.push(AssetBindingV1 {
        chain_id: chain,
        asset_id: asset,
        decimals: 12,
        representation: AssetRepresentationV1::Native,
    });
    manifest
        .assets
        .sort_by_key(|entry| (entry.chain_id.0, entry.asset_id.0));
    for terms in terms {
        terms.counterparty_leg.chain_id = chain;
        terms.counterparty_leg.asset_id = asset;
        terms.counterparty_leg.finality = finality;
        terms.counterparty_leg.mechanism =
            kaystra_core::types::LockMechanism::CrossCurveSharedSpend;
        terms.counterparty_leg.adapter_profile_hash = digest;
        terms.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 100_000 };
    }
    manifest.validate()?;
    Ok(())
}

/// The exact public profile used by this fixture's registry producer, not a
/// digest supplied by the terms. Reopening never changes these chain facts.
pub(crate) fn profile_for_terms_v24(
    terms: &SettlementTermsV1,
    operational: &xmr_setup_profile::XmrAdapterProfileV1,
) -> Result<ChainProfileV1, Box<dyn std::error::Error>> {
    let profile =
        chain_for_network_v24(operational.network, terms.counterparty_leg.finality)?.profile;
    xmr_setup_profile::require_chain_profile_v24(terms, operational, &profile)?;
    Ok(profile)
}

pub(crate) fn validate_setup_v24(
    terms: &SettlementTermsV1,
    operational: &xmr_setup_profile::XmrAdapterProfileV1,
    binding: xmr_setup_profile::XmrSetupBindingV1,
) -> Result<xmr_setup_profile::ValidatedXmrSetup, Box<dyn std::error::Error>> {
    Ok(xmr_setup_profile::validate_setup_for_chain_profile_v24(
        terms,
        operational,
        binding,
        &profile_for_terms_v24(terms, operational)?,
    )?)
}

fn chain_for_network_v24(
    selected: xmr_setup_profile::XmrNetwork,
    finality: kaystra_core::types::FinalityPolicyV1,
) -> Result<RegistryChainProfileV1, Box<dyn std::error::Error>> {
    let (network, genesis_hex, chain_domain) = match selected {
        xmr_setup_profile::XmrNetwork::Mainnet => (
            MoneroNetworkV1::Mainnet,
            "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
            "DOM/NativeXmrComponentFixture/MoneroMainnetChain/V23",
        ),
        xmr_setup_profile::XmrNetwork::Stagenet => (
            MoneroNetworkV1::Stagenet,
            "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb",
            "DOM/NativeXmrComponentFixture/MoneroStagenetChain/V23",
        ),
        _ => return Err("unsupported explicit offline network".into()),
    };
    let genesis: [u8; 32] = hex::decode(genesis_hex)?
        .try_into()
        .map_err(|_| "Monero genesis length")?;
    let chain = ChainId(*dom_crypto::blake2b_256_tagged(chain_domain, &genesis).as_bytes());
    let asset = AssetId(
        *dom_crypto::blake2b_256_tagged(
            "DOM/NativeXmrComponentFixture/MoneroNativeAsset/V23",
            &chain.0,
        )
        .as_bytes(),
    );
    Ok(RegistryChainProfileV1 {
        profile: ChainProfileV1 {
            chain_id: chain,
            kind: ChainKindV1::Monero { network },
            timing: ChainTimingBoundsV1 {
                min_block_seconds: 60,
                max_block_seconds: 180,
                max_reorg_seconds: 1080,
                observation_seconds: 5,
                broadcast_seconds: 5,
            },
            finality,
            native_asset: asset,
            allowed_assets: vec![],
        },
        deployment: ChainDeploymentV1::Monero(MoneroDeploymentV1 {
            genesis_hash: genesis,
            max_fee_piconero: 3,
        }),
    })
}

#[test]
fn registry_terms_pin_chain_profile_without_reinterpreting_operational_hash_v24() {
    let fixture = crate::route_time_test_common::fixture();
    for network in [
        xmr_setup_profile::XmrNetwork::Mainnet,
        xmr_setup_profile::XmrNetwork::Stagenet,
    ] {
        let mut manifest = fixture.registry.manifest().clone();
        let mut terms = [fixture.upstream.clone(), fixture.downstream.clone()];
        let [up, down] = &mut terms;
        configure_network(&mut manifest, [up, down], network).unwrap();
        let operational = xmr_setup_profile::XmrAdapterProfileV1::new(network, 3, 2).unwrap();
        let digest = manifest.chains[0].profile.profile_digest().unwrap();
        assert_ne!(digest, operational.profile_hash());
        for terms in &mut terms {
            assert_eq!(terms.counterparty_leg.adapter_profile_hash, digest);
            let before = terms.terms_hash().unwrap();
            assert_eq!(
                profile_for_terms_v24(terms, &operational).unwrap(),
                manifest.chains[0].profile
            );
            assert_eq!(terms.terms_hash().unwrap(), before);
            terms.counterparty_leg.adapter_profile_hash = operational.profile_hash();
            assert!(profile_for_terms_v24(terms, &operational).is_err());
        }
    }
}
