use super::*;
use chain_profile::{ChainKindV1, ChainProfileV1, MoneroNetworkV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, ChainDeploymentV1, MoneroDeploymentV1,
    RegistryChainProfileV1, RegistrySignatureV1, RegistryValidationPolicyV1, SignedRegistryV1,
};
use kaystra_core::types::{AssetId, ChainId, LockMechanism, TimelockSpec};

fn fixture() -> Result<
    (
        deployment_registry::ResolvedRegistryV1,
        kaystra_core::terms::SettlementTermsV1,
        kaystra_core::terms::SettlementTermsV1,
    ),
    Box<dyn std::error::Error>,
> {
    let (old, mut upstream, mut downstream) = common::mainnet_registry_and_terms();
    let mut manifest = old.manifest().clone();
    let chain_id = ChainId([0x61; 32]);
    let asset_id = AssetId([0x62; 32]);
    let profile = ChainProfileV1 {
        chain_id,
        native_asset: asset_id,
        allowed_assets: vec![],
        kind: ChainKindV1::Monero {
            network: MoneroNetworkV1::Mainnet,
        },
        timing: adapter_btc::timelock::ChainTimingBoundsV1 {
            min_block_seconds: 60,
            max_block_seconds: 180,
            max_reorg_seconds: 600,
            observation_seconds: 30,
            broadcast_seconds: 30,
        },
        finality: manifest.dom.finality,
    };
    let profile_digest = profile.profile_digest()?;
    // Ratified Monero genesis; registry validation rejects any substitution.
    let genesis_hash =
        hex::decode("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3")?
            .try_into()
            .map_err(|_| "genesis length")?;
    manifest.chains = vec![RegistryChainProfileV1 {
        profile: profile.clone(),
        deployment: ChainDeploymentV1::Monero(MoneroDeploymentV1 {
            genesis_hash,
            max_fee_piconero: 1_000_000_000,
        }),
    }];
    manifest
        .assets
        .retain(|asset| asset.chain_id == manifest.dom.chain_id);
    manifest.assets.push(AssetBindingV1 {
        chain_id,
        asset_id,
        decimals: 12,
        representation: AssetRepresentationV1::Native,
    });
    // The manifest's canonical encoding requires the asset bindings to be
    // strictly increasing by (chain_id, asset_id). The DOM chain id is derived
    // from the network magic and genesis, so where this appended XMR binding
    // falls relative to it is not something the fixture can assume.
    manifest
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    let secp = btc_crypto::SecpContext::new(&[0x67; 32]);
    let keys = [[3; 32], [4; 32], [5; 32]];
    let authorities = common::authority_set(&secp, &keys);
    let signatures = common::sign_digest(&secp, &keys, &manifest.manifest_digest()?, 0x50)
        .into_iter()
        .map(|s| RegistrySignatureV1 {
            signer_index: s.signer_index,
            signature: s.signature,
        })
        .collect();
    let registry = SignedRegistryV1::new(&manifest, signatures)?.verify(
        &authorities,
        &secp,
        RegistryValidationPolicyV1 {
            now_seconds: EVIDENCE_TIME,
            expected_network_id: REGISTRY_NETWORK,
            minimum_epoch: 7,
        },
    )?;
    for (terms, height) in [(&mut upstream, 40_000), (&mut downstream, 20_000)] {
        let leg = &mut terms.counterparty_leg;
        leg.chain_id = chain_id;
        leg.asset_id = asset_id;
        leg.mechanism = LockMechanism::CrossCurveSharedSpend;
        leg.deadline = TimelockSpec::BlockHeight { value: height };
        leg.finality = profile.finality;
        leg.adapter_profile_hash = profile_digest;
    }
    Ok((registry, upstream, downstream))
}

#[test]
fn native_clock_is_role_scoped_but_one_chain_observation() -> Result<(), Box<dyn std::error::Error>>
{
    let (registry, upstream, downstream) = fixture()?;
    let policy = RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &registry,
        &upstream,
        &downstream,
        common::limits(),
    )?;
    assert!(policy.is_dom_xmr_mainnet_v23());
    let bytes = policy.canonical_bytes()?;
    assert_eq!(&bytes[10..12], &[0, 1]);
    assert_eq!(RouteTimePolicyV2::decode(&bytes)?, policy);
    let mut observations = common::checkpoints(&policy, 0, 0);
    observations[2] = observations[1];
    observations[2].role = route_time_anchor::CheckpointRoleV2::DownstreamCounterparty;
    let evidence = route_time_anchor::RouteTimeEvidenceV2::new(
        &policy,
        1,
        EVIDENCE_TIME,
        EVIDENCE_TIME + 120,
        observations,
    )?;
    assert_eq!(evidence.policy_digest(), policy.policy_digest()?);
    for mutation in 0..4 {
        let mut altered = observations;
        match mutation {
            0 => altered[2].anchor_hash[0] ^= 1,
            1 => altered[2].time_upper_seconds += 1,
            2 => altered[2].canonical_tip_height += 1,
            _ => altered[2].canonicality_evidence_digest[0] ^= 1,
        }
        assert!(route_time_anchor::RouteTimeEvidenceV2::new(
            &policy,
            1,
            EVIDENCE_TIME,
            EVIDENCE_TIME + 120,
            altered
        )
        .is_err());
    }
    let mut limits = common::limits();
    limits.counterparty_margin_seconds = 1;
    assert!(RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &registry,
        &upstream,
        &downstream,
        limits
    )
    .is_err());
    let mut timestamp = downstream.clone();
    timestamp.counterparty_leg.deadline = TimelockSpec::TimestampSeconds { value: 20_000 };
    assert!(RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &registry,
        &upstream,
        &timestamp,
        common::limits()
    )
    .is_err());
    let mut wrong_asset = downstream;
    wrong_asset.counterparty_leg.asset_id = AssetId([0x63; 32]);
    assert!(RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &registry,
        &upstream,
        &wrong_asset,
        common::limits()
    )
    .is_err());
    Ok(())
}
