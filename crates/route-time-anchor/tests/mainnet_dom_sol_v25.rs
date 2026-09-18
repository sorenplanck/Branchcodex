//! Off-chain mainnet DOM / Solana timing profile regression coverage. Public
//! checkpoint fixtures exercise validation only; they are not canonical-chain
//! evidence, funding, or an activation of any Solana cluster.
mod common;
#[path = "mainnet_dom_sol_v25/ladder.rs"]
mod ladder;

use adapter_btc::timelock::ChainTimingBoundsV1;
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1, MoneroNetworkV1, SolanaNetworkV1};
use common::{EVIDENCE_TIME, REGISTRY_NETWORK};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, MoneroDeploymentV1,
    RegistryChainProfileV1, RegistrySignatureV1, RegistryValidationPolicyV1, ResolvedRegistryV1,
    SignedRegistryV1, SolanaDeploymentV1,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, Digest32, FinalityPolicyV1, LegTermsV1, LockMechanism, TimelockSpec,
};
use route_time_anchor::{
    CanonicalTimeCheckpointV2, CheckpointRoleV2, ClockKindV2, RouteTimeAnchorErrorV2,
    RouteTimeEvidenceV2, RouteTimePolicyV2, RouteTimeProfileV2,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const MONERO_CHAIN: ChainId = ChainId([0x61; 32]);
const MONERO_ASSET: AssetId = AssetId([0x62; 32]);
const SOL_CHAIN: ChainId = ChainId([0x71; 32]);
const SOL_ASSET: AssetId = AssetId([0x72; 32]);
const SOL_DEVNET_CHAIN: ChainId = ChainId([0x73; 32]);
const SOL_DEVNET_ASSET: AssetId = AssetId([0x74; 32]);
const SOL_GENESIS: Digest32 = [0x53; 32];
const SOL_DEVNET_GENESIS: Digest32 = [0x54; 32];
/// Stand-in for the operational `SolanaAdapterProfileV1::profile_hash()`:
/// nonzero, but a different domain from the registry chain-profile digest.
const OPERATIONAL_ADAPTER_HASH: Digest32 = [0x5a; 32];
const SOL_DOWNSTREAM_DEADLINE: u64 = 1_100_000;
/// The tightest safe upstream deadline: downstream + both drift bands + the
/// signed counterparty margin of `common::limits()`.
const SOL_UPSTREAM_DEADLINE: u64 = SOL_DOWNSTREAM_DEADLINE + 2 * 3_600 + 2_100_000;
/// Same bounds as the daemon's local-validator registry fixture.
const SOL_TIMING: ChainTimingBoundsV1 = ChainTimingBoundsV1 {
    min_block_seconds: 1,
    max_block_seconds: 2,
    max_reorg_seconds: 128,
    observation_seconds: 5,
    broadcast_seconds: 5,
};
const SOL_FINALITY: FinalityPolicyV1 = FinalityPolicyV1 {
    min_confirmations: 1,
    max_reorg_depth: 32,
};

struct SolFixture {
    registry: ResolvedRegistryV1,
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
}

fn authority_set(secp: &SecpContext, secrets: &[[u8; 32]]) -> TestResult<AuthoritySetV1> {
    let mut keys = Vec::with_capacity(secrets.len());
    for (index, secret) in secrets.iter().enumerate() {
        let aux = [0x42 + u8::try_from(index)?; 32];
        keys.push(secp.sign_bip340(secret, &[0x41; 32], &aux)?.1);
    }
    Ok(AuthoritySetV1::new(2, keys)?)
}

fn sol_chain(
    chain_id: ChainId,
    native_asset: AssetId,
    network: SolanaNetworkV1,
    genesis_hash: Digest32,
) -> RegistryChainProfileV1 {
    RegistryChainProfileV1 {
        profile: ChainProfileV1 {
            chain_id,
            native_asset,
            allowed_assets: vec![],
            kind: ChainKindV1::Solana {
                network,
                escrow_program: [0x51; 32],
                program_data_hash: [0x52; 32],
            },
            timing: SOL_TIMING,
            finality: SOL_FINALITY,
        },
        deployment: ChainDeploymentV1::Solana(SolanaDeploymentV1 {
            genesis_hash,
            max_fee_lamports: 10_000,
        }),
    }
}

fn sol_leg(
    leg: &mut LegTermsV1,
    chain_id: ChainId,
    asset_id: AssetId,
    profile_digest: Digest32,
    deadline: u64,
) {
    leg.chain_id = chain_id;
    leg.asset_id = asset_id;
    leg.mechanism = LockMechanism::CrossCurveConditionLock;
    leg.deadline = TimelockSpec::TimestampSeconds { value: deadline };
    leg.finality = SOL_FINALITY;
    leg.adapter_profile_hash = profile_digest;
}

fn profile_digest(registry: &ResolvedRegistryV1, chain_id: ChainId) -> TestResult<Digest32> {
    Ok(registry
        .resolve_chain(chain_id)
        .ok_or("chain absent from registry")?
        .profile()
        .profile_digest()?)
}

/// Re-signs `base` with one Monero mainnet chain and two Solana chains, and
/// points both counterparty legs at the same local-validator Solana chain.
fn sol_fixture(
    (base, mut upstream, mut downstream): (
        ResolvedRegistryV1,
        SettlementTermsV1,
        SettlementTermsV1,
    ),
) -> TestResult<SolFixture> {
    let mut manifest = base.manifest().clone();
    // Ratified Monero genesis; registry validation rejects any substitution.
    let monero_genesis: Digest32 =
        hex::decode("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3")?
            .try_into()
            .map_err(|_| "genesis length")?;
    manifest.chains = vec![
        RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: MONERO_CHAIN,
                native_asset: MONERO_ASSET,
                allowed_assets: vec![],
                kind: ChainKindV1::Monero {
                    network: MoneroNetworkV1::Mainnet,
                },
                timing: ChainTimingBoundsV1 {
                    min_block_seconds: 60,
                    max_block_seconds: 180,
                    max_reorg_seconds: 600,
                    observation_seconds: 30,
                    broadcast_seconds: 30,
                },
                finality: manifest.dom.finality,
            },
            deployment: ChainDeploymentV1::Monero(MoneroDeploymentV1 {
                genesis_hash: monero_genesis,
                max_fee_piconero: 1_000_000_000,
            }),
        },
        sol_chain(
            SOL_CHAIN,
            SOL_ASSET,
            SolanaNetworkV1::LocalValidator,
            SOL_GENESIS,
        ),
        sol_chain(
            SOL_DEVNET_CHAIN,
            SOL_DEVNET_ASSET,
            SolanaNetworkV1::Devnet,
            SOL_DEVNET_GENESIS,
        ),
    ];
    manifest
        .assets
        .retain(|asset| asset.chain_id == manifest.dom.chain_id);
    for (chain_id, asset_id, decimals) in [
        (MONERO_CHAIN, MONERO_ASSET, 12),
        (SOL_CHAIN, SOL_ASSET, 9),
        (SOL_DEVNET_CHAIN, SOL_DEVNET_ASSET, 9),
    ] {
        manifest.assets.push(AssetBindingV1 {
            chain_id,
            asset_id,
            decimals,
            representation: AssetRepresentationV1::Native,
        });
    }
    manifest
        .assets
        .sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    let secp = SecpContext::new(&[0x67; 32]);
    let keys = [[3; 32], [4; 32], [5; 32]];
    let authorities = authority_set(&secp, &keys)?;
    let signatures = common::sign_digest(&secp, &keys, &manifest.manifest_digest()?, 0x50)
        .into_iter()
        .map(|signature| RegistrySignatureV1 {
            signer_index: signature.signer_index,
            signature: signature.signature,
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
    let sol_digest = profile_digest(&registry, SOL_CHAIN)?;
    for (terms, deadline) in [
        (&mut upstream, SOL_UPSTREAM_DEADLINE),
        (&mut downstream, SOL_DOWNSTREAM_DEADLINE),
    ] {
        sol_leg(
            &mut terms.counterparty_leg,
            SOL_CHAIN,
            SOL_ASSET,
            sol_digest,
            deadline,
        );
    }
    Ok(SolFixture {
        registry,
        upstream,
        downstream,
    })
}

/// The same route shape moved onto the registry's Monero mainnet chain.
fn monero_terms(fixture: &SolFixture) -> TestResult<(SettlementTermsV1, SettlementTermsV1)> {
    let digest = profile_digest(&fixture.registry, MONERO_CHAIN)?;
    let finality = fixture.registry.manifest().dom.finality;
    let mut upstream = fixture.upstream.clone();
    let mut downstream = fixture.downstream.clone();
    for (terms, height) in [(&mut upstream, 40_000), (&mut downstream, 20_000)] {
        let leg = &mut terms.counterparty_leg;
        leg.chain_id = MONERO_CHAIN;
        leg.asset_id = MONERO_ASSET;
        leg.mechanism = LockMechanism::CrossCurveSharedSpend;
        leg.deadline = TimelockSpec::BlockHeight { value: height };
        leg.finality = finality;
        leg.adapter_profile_hash = digest;
    }
    Ok((upstream, downstream))
}

fn sol_policy(fixture: &SolFixture) -> Result<RouteTimePolicyV2, RouteTimeAnchorErrorV2> {
    RouteTimePolicyV2::from_registry_dom_sol_v25(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        common::limits(),
    )
}

fn sol_policy_with_downstream(
    fixture: &SolFixture,
    mutate: impl FnOnce(&mut LegTermsV1),
) -> Result<RouteTimePolicyV2, RouteTimeAnchorErrorV2> {
    let mut downstream = fixture.downstream.clone();
    mutate(&mut downstream.counterparty_leg);
    RouteTimePolicyV2::from_registry_dom_sol_v25(
        &fixture.registry,
        &fixture.upstream,
        &downstream,
        common::limits(),
    )
}

/// One Solana observation serves both role-scoped counterparty positions.
fn shared_checkpoints(policy: &RouteTimePolicyV2) -> [CanonicalTimeCheckpointV2; 3] {
    let mut observations = common::checkpoints(policy, 0, 0);
    observations[2] = observations[1];
    observations[2].role = CheckpointRoleV2::DownstreamCounterparty;
    observations
}

#[test]
fn dom_sol_profile_has_its_own_tag_and_one_shared_solana_observation() -> TestResult<()> {
    let fixture = sol_fixture(common::mainnet_registry_and_terms())?;
    let policy = sol_policy(&fixture)?;
    assert!(policy.is_dom_sol_mainnet_v25());
    assert!(!policy.is_dom_xmr_mainnet_v23());
    assert_eq!(policy.profile(), RouteTimeProfileV2::DomSolMainnetV25);
    assert_eq!(RouteTimeProfileV2::Generic.tag(), 0);
    assert_eq!(RouteTimeProfileV2::DomXmrMainnetV23.tag(), 1);
    assert_eq!(RouteTimeProfileV2::DomSolMainnetV25.tag(), 2);
    let bytes = policy.canonical_bytes()?;
    assert_eq!(&bytes[10..12], &[0, 2]);
    assert_eq!(RouteTimePolicyV2::decode(&bytes)?, policy);

    let sol_digest = profile_digest(&fixture.registry, SOL_CHAIN)?;
    let bindings = policy.checkpoint_bindings();
    for (binding, role) in bindings[1..].iter().zip([
        CheckpointRoleV2::UpstreamCounterparty,
        CheckpointRoleV2::DownstreamCounterparty,
    ]) {
        assert_eq!(binding.role(), role);
        assert_eq!(binding.clock_kind(), ClockKindV2::Solana);
        assert_eq!(binding.chain_id(), SOL_CHAIN);
        assert_eq!(binding.genesis_hash(), SOL_GENESIS);
        assert_eq!(binding.profile_digest(), sol_digest);
        assert_ne!(binding.profile_digest(), OPERATIONAL_ADAPTER_HASH);
        assert_eq!(binding.timing(), SOL_TIMING);
        assert_eq!(binding.finality(), SOL_FINALITY);
    }

    // Distinct commitments from the legacy and DOM/XMR variants.
    let (xmr_upstream, xmr_downstream) = monero_terms(&fixture)?;
    let xmr = RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &fixture.registry,
        &xmr_upstream,
        &xmr_downstream,
        common::limits(),
    )?;
    let xmr_bytes = xmr.canonical_bytes()?;
    assert_eq!(&xmr_bytes[10..12], &[0, 1]);
    let legacy = common::fixture().policy;
    let legacy_bytes = legacy.canonical_bytes()?;
    assert_eq!(&legacy_bytes[10..12], &[0, 0]);
    assert_ne!(policy.policy_digest()?, xmr.policy_digest()?);
    assert_ne!(policy.policy_digest()?, legacy.policy_digest()?);

    // No tag reinterprets another profile's bindings.
    for tag in [0, 1] {
        let mut retagged = bytes.clone();
        retagged[11] = tag;
        assert_eq!(
            RouteTimePolicyV2::decode(&retagged),
            Err(RouteTimeAnchorErrorV2::InvalidPolicy)
        );
    }
    for mut other in [xmr_bytes, legacy_bytes] {
        other[11] = 2;
        assert_eq!(
            RouteTimePolicyV2::decode(&other),
            Err(RouteTimeAnchorErrorV2::InvalidPolicy)
        );
    }
    let mut unknown = bytes.clone();
    unknown[11] = 3;
    assert_eq!(
        RouteTimePolicyV2::decode(&unknown),
        Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    );
    let mut wide = bytes;
    wide[10] = 1;
    assert_eq!(
        RouteTimePolicyV2::decode(&wide),
        Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    );

    let observations = shared_checkpoints(&policy);
    let evidence = RouteTimeEvidenceV2::new(
        &policy,
        1,
        EVIDENCE_TIME,
        EVIDENCE_TIME + 120,
        observations,
    )?;
    assert_eq!(evidence.policy_digest(), policy.policy_digest()?);
    assert_eq!(
        RouteTimeEvidenceV2::decode(&evidence.canonical_bytes()?)?,
        evidence
    );
    // Two different observations for the one chain are refused.
    assert!(RouteTimeEvidenceV2::new(
        &policy,
        1,
        EVIDENCE_TIME,
        EVIDENCE_TIME + 120,
        common::checkpoints(&policy, 0, 0),
    )
    .is_err());
    for mutation in 0..6 {
        let mut altered = observations;
        match mutation {
            0 => altered[2].anchor_hash[0] ^= 1,
            1 => altered[2].anchor_height += 1,
            2 => altered[2].time_upper_seconds += 1,
            3 => altered[2].canonical_tip_height += 1,
            4 => altered[2].canonicality_evidence_digest[0] ^= 1,
            _ => {
                // Shared but on the wrong clock.
                altered[1].clock_kind = ClockKindV2::EvmTimestamp;
                altered[2].clock_kind = ClockKindV2::EvmTimestamp;
            }
        }
        assert!(RouteTimeEvidenceV2::new(
            &policy,
            1,
            EVIDENCE_TIME,
            EVIDENCE_TIME + 120,
            altered,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn dom_sol_profile_refuses_every_other_shape() -> TestResult<()> {
    let fixture = sol_fixture(common::mainnet_registry_and_terms())?;
    let limits = common::limits();
    assert!(sol_policy(&fixture).is_ok());

    // DOM must be mainnet.
    let regtest = common::fixture();
    let regtest = sol_fixture((regtest.registry, regtest.upstream, regtest.downstream))?;
    assert_eq!(
        sol_policy(&regtest),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    assert_eq!(
        RouteTimePolicyV2::from_registry(
            &regtest.registry,
            &regtest.upstream,
            &regtest.downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );

    // Both counterparty legs on one Solana chain; any registry Solana network.
    let devnet_digest = profile_digest(&fixture.registry, SOL_DEVNET_CHAIN)?;
    let mut devnet_upstream = fixture.upstream.clone();
    sol_leg(
        &mut devnet_upstream.counterparty_leg,
        SOL_DEVNET_CHAIN,
        SOL_DEVNET_ASSET,
        devnet_digest,
        SOL_UPSTREAM_DEADLINE,
    );
    let mut devnet_downstream = fixture.downstream.clone();
    sol_leg(
        &mut devnet_downstream.counterparty_leg,
        SOL_DEVNET_CHAIN,
        SOL_DEVNET_ASSET,
        devnet_digest,
        SOL_DOWNSTREAM_DEADLINE,
    );
    assert!(RouteTimePolicyV2::from_registry_dom_sol_v25(
        &fixture.registry,
        &devnet_upstream,
        &devnet_downstream,
        limits
    )
    .is_ok());
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &fixture.registry,
            &fixture.upstream,
            &devnet_downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );

    // Only a timestamp deadline under the cross-curve condition lock.
    assert_eq!(
        sol_policy_with_downstream(&fixture, |leg| {
            leg.deadline = TimelockSpec::BlockHeight { value: 20_000 }
        }),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    assert_eq!(
        sol_policy_with_downstream(&fixture, |leg| {
            leg.deadline = TimelockSpec::BtcTime512s { value: 20 }
        }),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    for mechanism in [
        LockMechanism::ConditionLock,
        LockMechanism::CrossCurveSharedSpend,
        LockMechanism::SchnorrAdaptor,
    ] {
        assert_eq!(
            sol_policy_with_downstream(&fixture, |leg| leg.mechanism = mechanism),
            Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
        );
    }

    // Registry chain-profile digest only: the operational adapter hash, a
    // zero hash and a finality substitution are all refused.
    for hash in [OPERATIONAL_ADAPTER_HASH, [0; 32]] {
        assert_eq!(
            sol_policy_with_downstream(&fixture, |leg| leg.adapter_profile_hash = hash),
            Err(RouteTimeAnchorErrorV2::RegistryMismatch)
        );
    }
    let mut operational_upstream = fixture.upstream.clone();
    operational_upstream.counterparty_leg.adapter_profile_hash = OPERATIONAL_ADAPTER_HASH;
    let mut operational_downstream = fixture.downstream.clone();
    operational_downstream.counterparty_leg.adapter_profile_hash = OPERATIONAL_ADAPTER_HASH;
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &fixture.registry,
            &operational_upstream,
            &operational_downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::RegistryMismatch)
    );
    assert_eq!(
        sol_policy_with_downstream(&fixture, |leg| {
            leg.finality = FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 32,
            }
        }),
        Err(RouteTimeAnchorErrorV2::RegistryMismatch)
    );

    // The asset must resolve on that exact chain.
    for asset in [AssetId([0x75; 32]), MONERO_ASSET] {
        assert_eq!(
            sol_policy_with_downstream(&fixture, |leg| leg.asset_id = asset),
            Err(RouteTimeAnchorErrorV2::RegistryMismatch)
        );
    }

    // Monero and EVM/BTC terms are not Solana terms.
    let (xmr_upstream, xmr_downstream) = monero_terms(&fixture)?;
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &fixture.registry,
            &xmr_upstream,
            &xmr_downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    let (evm_registry, evm_upstream, btc_downstream) = common::mainnet_registry_and_terms();
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &evm_registry,
            &evm_upstream,
            &btc_downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    let mut evm_downstream = btc_downstream;
    evm_downstream.counterparty_leg = evm_upstream.counterparty_leg.clone();
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &evm_registry,
            &evm_upstream,
            &evm_downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );

    // The legacy and DOM/XMR constructors refuse the Solana mainnet terms.
    assert_eq!(
        RouteTimePolicyV2::from_registry(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_xmr_v23(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            limits
        ),
        Err(RouteTimeAnchorErrorV2::UnsupportedTopology)
    );

    // Signed margins are never relaxed below the registry floor.
    let mut short = limits;
    short.counterparty_margin_seconds = 1;
    assert_eq!(
        RouteTimePolicyV2::from_registry_dom_sol_v25(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            short
        ),
        Err(RouteTimeAnchorErrorV2::InvalidPolicy)
    );
    Ok(())
}
