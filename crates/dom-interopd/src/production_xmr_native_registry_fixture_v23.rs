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
    let finality = terms[0].counterparty_leg.finality;
    manifest.chains = vec![RegistryChainProfileV1 {
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
    }];
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
        terms.counterparty_leg.deadline = TimelockSpec::BlockHeight { value: 100_000 };
    }
    manifest.validate()?;
    Ok(())
}
