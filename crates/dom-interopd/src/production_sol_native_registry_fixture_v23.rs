//! Explicit local-validator Solana deployment, checked by the real registry
//! validator. Genesis and program-data hash are live facts of the owned
//! validator, never constants: a reset ledger mints a new cluster identity.
use adapter_btc::timelock::ChainTimingBoundsV1;
use chain_profile::{ChainKindV1, ChainProfileV1, SolanaNetworkV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, ChainDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, SolanaDeploymentV1,
};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{AssetId, ChainId, FinalityPolicyV1, LockMechanism, TimelockSpec},
};
use solana_profile::{SolanaAdapterProfileV1, SolanaNetwork};
use solana_types::SolanaPubkey;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// `programs/dom-solana-escrow/program-id.txt`; the `.so` is deployed at it.
pub(crate) const NATIVE_SOL_PROGRAM_ID_V23: &str = "3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw";

/// Slot time is sub-second; one whole second is the smallest signed bound.
pub(crate) const NATIVE_SOL_TIMING_V23: ChainTimingBoundsV1 = ChainTimingBoundsV1 {
    min_block_seconds: 1,
    max_block_seconds: 2,
    max_reorg_seconds: 128,
    observation_seconds: 5,
    broadcast_seconds: 5,
};

/// Observations use the finalized commitment; depth 32 covers the reorg budget.
pub(crate) const NATIVE_SOL_FINALITY_V23: FinalityPolicyV1 = FinalityPolicyV1 {
    min_confirmations: 1,
    max_reorg_depth: 32,
};

pub(crate) const NATIVE_SOL_MAX_FEE_LAMPORTS_V23: u64 = 10_000;
pub(crate) const NATIVE_SOL_DECIMALS_V23: u8 = 9;

pub(crate) fn program_id_v23() -> Result<SolanaPubkey> {
    SolanaPubkey::from_base58(NATIVE_SOL_PROGRAM_ID_V23)
        .map_err(|_| "escrow program id is not canonical base58".into())
}

/// The daemon admits only `require_immutable_program == true`, on every
/// network including the local validator. One RPC node, quorum one.
pub(crate) fn adapter_profile_v23(program_id: SolanaPubkey) -> Result<SolanaAdapterProfileV1> {
    let profile =
        SolanaAdapterProfileV1::new_attested(SolanaNetwork::LocalValidator, program_id, 1, 1)
            .map_err(|_| "attested Solana adapter profile refused")?;
    if !profile.require_immutable_program {
        return Err("attested Solana adapter profile does not require immutability".into());
    }
    Ok(profile)
}

pub(crate) fn configure_network(
    manifest: &mut RegistryManifestV1,
    terms: [&mut SettlementTermsV1; 2],
    genesis_hash: [u8; 32],
    program_id: SolanaPubkey,
    program_data_hash: [u8; 32],
) -> Result<()> {
    if genesis_hash == [0; 32] || program_data_hash == [0; 32] || program_id.is_zero() {
        return Err("Solana registry facts must be observed and nonzero".into());
    }
    let entry = chain_v23(genesis_hash, program_id, program_data_hash);
    let chain = entry.profile.chain_id;
    let asset = entry.profile.native_asset;
    let registry_digest = entry
        .profile
        .profile_digest()
        .map_err(|_| "Solana registry chain profile digest refused")?;
    // The attested operational profile must still exist for this program; the
    // terms, however, pin the registry digest (see below).
    adapter_profile_v23(program_id)?;
    manifest.chains = vec![entry];
    manifest
        .assets
        .retain(|entry| entry.chain_id == manifest.dom.chain_id);
    manifest.assets.push(AssetBindingV1 {
        chain_id: chain,
        asset_id: asset,
        decimals: NATIVE_SOL_DECIMALS_V23,
        representation: AssetRepresentationV1::Native,
    });
    manifest
        .assets
        .sort_by_key(|entry| (entry.chain_id.0, entry.asset_id.0));
    for terms in terms {
        terms.counterparty_leg.chain_id = chain;
        terms.counterparty_leg.asset_id = asset;
        terms.counterparty_leg.finality = NATIVE_SOL_FINALITY_V23;
        terms.counterparty_leg.mechanism = LockMechanism::CrossCurveConditionLock;
        // The registry chain-profile digest, as the daemon admission, the
        // DOM-mainnet SOL time policy and `validate_setup_for_chain_profile_v25`
        // require. The operational adapter hash is a different domain and
        // stays inside the DLEQ context only.
        terms.counterparty_leg.adapter_profile_hash = registry_digest;
        // Replaced by the negotiated deadline plan before either signature.
        terms.counterparty_leg.deadline = TimelockSpec::TimestampSeconds {
            value: manifest.expires_at,
        };
    }
    manifest.validate()?;
    Ok(())
}

fn chain_v23(
    genesis_hash: [u8; 32],
    program_id: SolanaPubkey,
    program_data_hash: [u8; 32],
) -> RegistryChainProfileV1 {
    let chain = ChainId(
        *dom_crypto::blake2b_256_tagged(
            "DOM/NativeSolComponentFixture/SolanaLocalValidatorChain/V23",
            &genesis_hash,
        )
        .as_bytes(),
    );
    let asset = AssetId(
        *dom_crypto::blake2b_256_tagged(
            "DOM/NativeSolComponentFixture/SolanaNativeAsset/V23",
            &chain.0,
        )
        .as_bytes(),
    );
    RegistryChainProfileV1 {
        profile: ChainProfileV1 {
            chain_id: chain,
            kind: ChainKindV1::Solana {
                network: SolanaNetworkV1::LocalValidator,
                escrow_program: program_id.0,
                program_data_hash,
            },
            timing: NATIVE_SOL_TIMING_V23,
            finality: NATIVE_SOL_FINALITY_V23,
            native_asset: asset,
            allowed_assets: vec![],
        },
        deployment: ChainDeploymentV1::Solana(SolanaDeploymentV1 {
            genesis_hash,
            max_fee_lamports: NATIVE_SOL_MAX_FEE_LAMPORTS_V23,
        }),
    }
}

#[test]
fn local_validator_registry_pins_the_attested_adapter_profile_v25() -> Result<()> {
    let fixture = crate::route_time_test_common::fixture();
    let program = program_id_v23()?;
    let mut manifest = fixture.registry.manifest().clone();
    let mut terms = [fixture.upstream.clone(), fixture.downstream.clone()];
    let [up, down] = &mut terms;
    configure_network(&mut manifest, [up, down], [7; 32], program, [9; 32])?;
    let profile = adapter_profile_v23(program)?;
    assert!(profile.require_immutable_program);
    assert_eq!(manifest.chains.len(), 1);
    let registry_digest = manifest.chains[0]
        .profile
        .profile_digest()
        .map_err(|_| "registry digest")?;
    assert_ne!(registry_digest, profile.profile_hash());
    for terms in &terms {
        assert_eq!(terms.counterparty_leg.adapter_profile_hash, registry_digest);
        assert_eq!(
            terms.counterparty_leg.mechanism,
            LockMechanism::CrossCurveConditionLock
        );
    }
    let mut unobserved = fixture.registry.manifest().clone();
    let mut again = [fixture.upstream.clone(), fixture.downstream.clone()];
    let [up, down] = &mut again;
    assert!(configure_network(&mut unobserved, [up, down], [7; 32], program, [0; 32]).is_err());
    Ok(())
}
