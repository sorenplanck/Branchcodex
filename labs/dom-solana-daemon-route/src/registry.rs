//! The signed deployment registry for a route whose counterparty positions are
//! Solana, and the authority bundle the daemon authenticates it against.
//!
//! These are the first two artifacts of the bootstrap, and they are the two that
//! turn three pins from derived labels into measured digests: the manifest digest,
//! the registry authority-set digest, and the network id every other artifact is
//! bound to.
//!
//! # Why this duplicates a pattern that already exists
//!
//! `deploy-genconfig::provision_registry` already builds, signs, installs and
//! re-verifies a registry -- three BIP340 authority keypairs, owner-only secret
//! files, a 2-of-3 threshold. Its `manifest_from_mold` builds an EVM chain and a
//! Bitcoin chain from fixed fields and has no Solana path, so it cannot produce the
//! entry this route needs. Extending that function is the better long-term home for
//! this code and it is additive; it is also a shared crate, and the instruction
//! here is to use the shared crates rather than edit them. So the pattern is
//! reproduced, the duplication is stated, and moving it is a decision for the
//! operator rather than a change made quietly from a laboratory.
//!
//! # What the Solana entry carries
//!
//! Three facts the leg already measures on a live cluster, which is what makes the
//! registry entry checkable rather than declarative:
//!
//! * `escrow_program` -- the id `declare_id!` fixes and the program refuses to run
//!   under any other;
//! * `program_data_hash` -- the canonical `code_hash` over the program's code
//!   region, the same value `attest_immutable_program` demands and the leg binds
//!   into its setup;
//! * `genesis_hash` -- the cluster's own identity, which the leg uses as the
//!   counterparty chain id in its frozen terms.

use std::path::Path;

use adapter_btc::timelock::ChainTimingBoundsV1;
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, RegistryChainProfileV1, RegistryManifestV1,
    RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1, SignedRegistryV1,
    SolanaDeploymentV1,
};
use dom_consensus::derive_chain_id;
use dom_core::{configured_genesis_hash_for_network_magic, NETWORK_MAGIC_REGTEST};
use dom_interopd::ProductionAuthorityBundleV1;
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use sha2::{Digest, Sha256};

/// Everything about the Solana side of the registry entry that a caller measures
/// rather than chooses. On a live cluster all three come from the harness and the
/// attestation; nothing here invents them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolanaChainFactsV1 {
    /// The cluster's genesis hash, its identity.
    pub genesis_hash: [u8; 32],
    /// The escrow program id, as `declare_id!` fixes it.
    pub escrow_program: [u8; 32],
    /// The canonical code hash over the program's code region.
    pub program_data_hash: [u8; 32],
    /// Which Solana network the entry describes.
    pub network: chain_profile::SolanaNetworkV1,
    /// Fee ceiling the deployment accepts, in lamports.
    pub max_fee_lamports: u64,
}

/// What provisioning the registry establishes, and what the bootstrap pins take
/// from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionedSolanaRegistryV1 {
    pub network_id: [u8; 32],
    pub epoch: u64,
    /// `BLAKE2b-256(domain || canonical manifest bytes)`, the daemon's pin.
    pub manifest_digest: [u8; 32],
    /// Digest of the registry authority set, as the daemon derives it from the
    /// authority bundle rather than from the set it was handed.
    pub authority_set_digest: [u8; 32],
    pub dom_chain_id: [u8; 32],
    /// The DOM hub's native asset, as the manifest names it. The terms of both
    /// positions name this same asset on their DOM leg: a route whose terms named
    /// an asset the registry does not declare would be settling something the
    /// deployment does not know about.
    pub dom_asset_id: [u8; 32],
    pub solana_chain_id: [u8; 32],
    pub solana_asset_id: [u8; 32],
}

fn asset_id(domain: &[u8], seed: &[u8; 32]) -> AssetId {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(seed);
    AssetId(hasher.finalize().into())
}

/// Timing the DOM hub declares.
///
/// `ChainProfileV1::validate` refuses a profile whose seconds budget for a reorg
/// does not cover the depth its finality policy tolerates at the slowest admitted
/// block interval: `max_reorg_seconds >= max_reorg_depth * max_block_seconds`. With
/// a depth of 8 and a 20-second ceiling that floor is 160, so 240 clears it with
/// room instead of sitting on the boundary. The first version of this function
/// declared 200 seconds against a depth of 32 and was refused, which is the rule
/// working.
fn dom_timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 20,
        max_reorg_seconds: 240,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

/// Timing the Solana entry declares. A cluster produces blocks far faster than the
/// DOM chain, so its ceiling is 2 seconds and the same depth needs a much smaller
/// seconds budget: 32 * 2 = 64, cleared by 150.
fn solana_timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 2,
        max_reorg_seconds: 150,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

/// The DOM leg's finality, as both terms must declare it.
///
/// This is not a preference. `validate_composition_registry_parts` refuses a route
/// unless `terms.dom_leg.finality` equals the DOM deployment's finality exactly, for
/// both positions -- so this function is the single place the value exists, and the
/// terms provisioner reads it from here rather than restating it.
pub fn dom_finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 1,
        max_reorg_depth: 8,
    }
}

/// The Solana leg's finality, as both terms must declare it.
///
/// Same contract, one line further down the same function:
/// `terms.counterparty_leg.finality` must equal the resolved chain profile's
/// finality.
pub fn solana_finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 1,
        max_reorg_depth: 32,
    }
}

/// Three BIP340 authority sets, each 2-of-3 and each distinct: the bundle refuses
/// two sets that are equal, and it is right to -- one key set authorising both the
/// registry and the time evidence would collapse two independent authorities into
/// one.
fn authority_sets(
    secp: &SecpContext,
    digest: &[u8; 32],
) -> Result<([AuthoritySetV1; 3], Vec<RegistrySignatureV1>), String> {
    let mut sets = Vec::with_capacity(3);
    let mut registry_signatures = Vec::new();
    for (role, label) in [(0u8, "registry"), (1, "time-policy"), (2, "time-evidence")] {
        let mut keys = Vec::with_capacity(3);
        for index in 0u8..3 {
            let mut hasher = Sha256::new();
            hasher.update(b"DOM-SOLANA-DAEMON-ROUTE/AUTHORITY-SECRET/V1\0");
            hasher.update([role, index]);
            hasher.update(label.as_bytes());
            let secret: [u8; 32] = hasher.finalize().into();
            let mut aux = Sha256::new();
            aux.update(b"DOM-SOLANA-DAEMON-ROUTE/AUTHORITY-AUX/V1\0");
            aux.update([role, index]);
            let aux: [u8; 32] = aux.finalize().into();
            let (signature, xonly) = secp
                .sign_bip340(&secret, digest, &aux)
                .map_err(|error| format!("authority signature: {error:?}"))?;
            if role == 0 {
                registry_signatures.push(RegistrySignatureV1 {
                    signer_index: u16::from(index),
                    signature,
                });
            }
            keys.push(xonly);
        }
        sets.push(
            AuthoritySetV1::new(2, keys).map_err(|error| format!("authority set: {error:?}"))?,
        );
    }
    let sets: [AuthoritySetV1; 3] = sets
        .try_into()
        .map_err(|_| "three authority sets".to_owned())?;
    Ok((sets, registry_signatures))
}

/// Build the manifest for a DOM hub and one Solana chain.
///
/// Only the chains a route actually uses are declared. The daemon resolves a
/// position's chain by id, so a manifest naming chains no position references would
/// be describing a deployment this route does not have.
pub fn manifest(
    network_id: [u8; 32],
    epoch: u64,
    valid_from: u64,
    expires_at: u64,
    solana: &SolanaChainFactsV1,
) -> Result<RegistryManifestV1, String> {
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
        .map_err(|error| format!("canonical DOM regtest genesis: {error:?}"))?;
    let dom_chain = ChainId(*derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes());
    let dom_asset = asset_id(b"DOM-SOLANA-DAEMON-ROUTE/DOM-NATIVE/V1\0", &dom_chain.0);
    let solana_chain = ChainId(solana.genesis_hash);
    let solana_asset = asset_id(
        b"DOM-SOLANA-DAEMON-ROUTE/SOL-NATIVE/V1\0",
        &solana.genesis_hash,
    );
    let mut assets = vec![
        AssetBindingV1 {
            chain_id: dom_chain,
            asset_id: dom_asset,
            decimals: 9,
            representation: AssetRepresentationV1::Native,
        },
        AssetBindingV1 {
            chain_id: solana_chain,
            asset_id: solana_asset,
            decimals: 9,
            representation: AssetRepresentationV1::Native,
        },
    ];
    assets.sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
    Ok(RegistryManifestV1 {
        network_id,
        epoch,
        valid_from,
        expires_at,
        dom: DomDeploymentV1 {
            chain_id: dom_chain,
            genesis_hash: *genesis.as_bytes(),
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: *dom_crypto_consensus_digest(),
            scriptless_api_version: 1,
            timing: dom_timing(),
            finality: dom_finality(),
            native_asset: dom_asset,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: solana_chain,
                kind: ChainKindV1::Solana {
                    network: solana.network,
                    escrow_program: solana.escrow_program,
                    program_data_hash: solana.program_data_hash,
                },
                timing: solana_timing(),
                finality: solana_finality(),
                native_asset: solana_asset,
                allowed_assets: vec![],
            },
            deployment: ChainDeploymentV1::Solana(SolanaDeploymentV1 {
                genesis_hash: solana.genesis_hash,
                max_fee_lamports: solana.max_fee_lamports,
            }),
        }],
        assets,
    })
}

/// A stand-in for the consensus rules digest of this DOM build.
///
/// A real deployment pins the digest of the consensus rules its nodes run. This
/// laboratory route has no such measurement to offer, so it declares a constant and
/// says so here rather than passing a hash of something unrelated off as one.
fn dom_crypto_consensus_digest() -> &'static [u8; 32] {
    &[0x22; 32]
}

/// Build, sign, install and re-verify the registry; write the authority bundle
/// beside it.
///
/// `registry_relative` and `authorities_relative` are the layout's own path roles,
/// so the files land exactly where the manifest says they will.
pub fn provision(
    state_dir: &Path,
    registry_relative: &str,
    authorities_relative: &str,
    network_id: [u8; 32],
    epoch: u64,
    solana: &SolanaChainFactsV1,
) -> Result<ProvisionedSolanaRegistryV1, String> {
    let manifest = manifest(network_id, epoch, 1_000, 10_000, solana)?;
    manifest
        .validate()
        .map_err(|error| format!("manifest: {error:?}"))?;
    let digest = manifest
        .manifest_digest()
        .map_err(|error| format!("manifest digest: {error:?}"))?;

    let secp = SecpContext::new(&[0x5a; 32]);
    let ([registry_set, time_policy_set, time_evidence_set], signatures) =
        authority_sets(&secp, &digest)?;
    // Two of the three sign: the threshold is what the set declares, and installing
    // with all three would not exercise it.
    let signed = SignedRegistryV1::new(&manifest, signatures[..2].to_vec())
        .map_err(|error| format!("signed registry: {error:?}"))?;

    let policy = RegistryValidationPolicyV1 {
        now_seconds: 2_000,
        expected_network_id: network_id,
        minimum_epoch: epoch,
    };
    // The registry store refuses a parent directory that is not owner-only, and
    // `create_dir_all` would make one the runner's umask widened to 0o755.
    if let Some(parent) = state_dir.join(registry_relative).parent() {
        crate::owner_only::directory(parent)?;
    }
    let mut store = RegistryStoreV1::create(&state_dir.join(registry_relative))
        .map_err(|error| format!("registry store: {error:?}"))?;
    let (_outcome, resolved) = store
        .install(&signed, &registry_set, &secp, policy)
        .map_err(|error| format!("registry install: {error:?}"))?;
    if resolved.manifest_digest() != digest {
        return Err("the installed registry is not the manifest that was signed".to_owned());
    }

    let bundle = ProductionAuthorityBundleV1::new(
        registry_set.clone(),
        time_policy_set,
        time_evidence_set,
    )
    .map_err(|error| format!("authority bundle: {error:?}"))?;
    let authority_set_digest = bundle
        .registry()
        .authority_set_digest()
        .map_err(|error| format!("authority set digest: {error:?}"))?;
    let bytes = bundle
        .canonical_bytes()
        .map_err(|error| format!("authority bundle bytes: {error:?}"))?;
    crate::owner_only::write(&state_dir.join(authorities_relative), &bytes)?;

    let solana_chain = ChainId(solana.genesis_hash);
    Ok(ProvisionedSolanaRegistryV1 {
        network_id,
        epoch,
        manifest_digest: digest,
        authority_set_digest,
        dom_chain_id: manifest.dom.chain_id.0,
        dom_asset_id: manifest.dom.native_asset.0,
        solana_chain_id: solana_chain.0,
        solana_asset_id: manifest.chains[0].profile.native_asset.0,
    })
}
