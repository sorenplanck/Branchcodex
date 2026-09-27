//! The signed deployment registry for a route whose counterparty positions are
//! Solana, and the authority bundle the daemon authenticates it against.
//!
//! These are the first two artifacts of the bootstrap, and they are the two that
//! turn three pins from derived labels into measured digests: the manifest digest,
//! the registry authority-set digest, and the network id every other artifact is
//! bound to.
//!
//! # Two Solana entries, not one
//!
//! The manifest declares the DOM hub and TWO Solana clusters, because the route has
//! two counterparty positions and `RouteTimePolicyV2::from_registry` refuses a pair
//! that shares a chain id unless the mainnet DOM/XMR profile is selected. Passing one
//! cluster for both positions is refused here, by name, rather than left to surface
//! later as `InvalidPolicy` from a component that knows nothing about Solana.
//!
//! # What this module measures that it does not choose
//!
//! `dom_profile_digest` is the twelve-field DOM adapter-profile digest, taken from the
//! INSTALLED registry with `route_time_anchor::resolved_dom_profile_digest_v1`. Both
//! terms must carry exactly that value as their DOM leg's `adapter_profile_hash`, and
//! the route-time policy refuses them with `RegistryMismatch` otherwise. A leg
//! laboratory with no registry derives its own stable value instead; a route
//! provisioned against a daemon may not.
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
    /// First and last trusted second the manifest itself declares. The route-time
    /// policy's own window must sit inside this one, so a caller writing that
    /// artifact reads the bounds from here instead of restating them.
    pub valid_from_seconds: u64,
    pub expires_at_seconds: u64,
    pub dom_chain_id: [u8; 32],
    /// The DOM hub's native asset, as the manifest names it. The terms of both
    /// positions name this same asset on their DOM leg: a route whose terms named
    /// an asset the registry does not declare would be settling something the
    /// deployment does not know about.
    pub dom_asset_id: [u8; 32],
    /// The twelve-field DOM adapter-profile digest, measured from the INSTALLED
    /// registry with `resolved_dom_profile_digest_v1`.
    ///
    /// Not a formula this crate owns. Both terms must carry exactly this value as
    /// their DOM leg's `adapter_profile_hash`, and the route-time policy refuses them
    /// with `RegistryMismatch` otherwise -- so it is measured here, once, from the
    /// registry that was actually installed.
    pub dom_profile_digest: [u8; 32],
    /// The cluster the upstream position settles on, and its native asset.
    pub upstream_chain_id: [u8; 32],
    pub upstream_asset_id: [u8; 32],
    /// `ChainProfileV1::profile_digest()` of that cluster's entry, measured from the
    /// INSTALLED registry.
    ///
    /// This is the value the upstream terms' `counterparty_leg.adapter_profile_hash`
    /// must carry. `admission`, `route_time_anchor::counterparty_binding` and the
    /// ratified Monero boundary all compare that field with it.
    pub upstream_profile_digest: [u8; 32],
    /// The cluster the downstream position settles on, and its native asset.
    ///
    /// A DIFFERENT cluster from the upstream one, and not by preference:
    /// `RouteTimePolicyV2::from_registry` refuses a route whose two counterparty
    /// positions share a chain unless the DOM/XMR mainnet profile is selected. See
    /// the module documentation.
    pub downstream_chain_id: [u8; 32],
    pub downstream_asset_id: [u8; 32],
    /// The same digest for the downstream cluster's entry.
    pub downstream_profile_digest: [u8; 32],
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
        // Two, not twenty. The route ladder projects a height deadline as
        // `[time_lower + delta*min_block, time_upper + delta*max_block]`, so the spread
        // between the two bounds multiplies the width of that interval by delta -- and the
        // ladder then requires the upstream interval to start after the downstream one
        // ENDS, plus the hub margin. At twenty seconds a five-hour route needed the
        // upstream deadline three hundred thousand blocks out; at two it needs forty
        // thousand.
        //
        // This is a declared bound, not a measurement, and it is honest only for a chain
        // that produces blocks at or under two seconds -- which this laboratory's regtest
        // node does. A deployment whose blocks are slower must widen it AND space its legs
        // further apart, in that order.
        max_block_seconds: 2,
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
/// The three independent authorities a route needs, in the order the bundle takes
/// them. The label is part of the key derivation, so the roles cannot collide even
/// if the byte were ever reused.
pub(crate) const AUTHORITY_ROLES: [(u8, &str); 3] =
    [(0, "registry"), (1, "time-policy"), (2, "time-evidence")];
/// Index into [`AUTHORITY_ROLES`] for the route-time policy authority.
pub(crate) const TIME_POLICY_ROLE: usize = 1;
/// Index into [`AUTHORITY_ROLES`] for the route-time evidence authority.
pub(crate) const TIME_EVIDENCE_ROLE: usize = 2;
/// Signatures required of each 2-of-3 set.
pub(crate) const AUTHORITY_THRESHOLD: u16 = 2;
/// Members of each set.
pub(crate) const AUTHORITY_MEMBERS: u8 = 3;

/// One authority's secret scalar.
///
/// Derived, so a laboratory route has a reproducible authority set without a key
/// ceremony, and so the module that signs the time artifacts can reach the same keys
/// the registry set was built from without either module holding them. A real
/// deployment's authorities hold their own secrets and this function does not exist
/// for them -- which is the same distinction the terms provisioner draws about the
/// condition scalar.
pub(crate) fn authority_secret(role: u8, index: u8, label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-SOLANA-DAEMON-ROUTE/AUTHORITY-SECRET/V1\0");
    hasher.update([role, index]);
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

/// The auxiliary randomness for one authority's BIP340 signature.
pub(crate) fn authority_aux(role: u8, index: u8) -> [u8; 32] {
    let mut aux = Sha256::new();
    aux.update(b"DOM-SOLANA-DAEMON-ROUTE/AUTHORITY-AUX/V1\0");
    aux.update([role, index]);
    aux.finalize().into()
}

fn authority_sets(
    secp: &SecpContext,
    digest: &[u8; 32],
) -> Result<([AuthoritySetV1; 3], Vec<RegistrySignatureV1>), String> {
    let mut sets = Vec::with_capacity(3);
    let mut registry_signatures = Vec::new();
    for (role, label) in AUTHORITY_ROLES {
        let mut keys = Vec::with_capacity(usize::from(AUTHORITY_MEMBERS));
        for index in 0..AUTHORITY_MEMBERS {
            let secret = authority_secret(role, index, label);
            let (signature, xonly) = secp
                .sign_bip340(&secret, digest, &authority_aux(role, index))
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
            AuthoritySetV1::new(AUTHORITY_THRESHOLD, keys)
                .map_err(|error| format!("authority set: {error:?}"))?,
        );
    }
    let sets: [AuthoritySetV1; 3] = sets
        .try_into()
        .map_err(|_| "three authority sets".to_owned())?;
    Ok((sets, registry_signatures))
}

/// Build the manifest for a DOM hub and the two Solana clusters the route uses.
///
/// Only the chains a route actually uses are declared. The daemon resolves a
/// position's chain by id, so a manifest naming chains no position references would
/// be describing a deployment this route does not have.
///
/// Two Solana entries, not one, because the route has two counterparty positions and
/// they may not share a chain. The entries are emitted in ascending chain-id order,
/// which the manifest requires: a duplicate or out-of-order chain is refused as a
/// non-canonical encoding rather than sorted for the caller.
pub fn manifest(
    network_id: [u8; 32],
    epoch: u64,
    valid_from: u64,
    expires_at: u64,
    upstream: &SolanaChainFactsV1,
    downstream: &SolanaChainFactsV1,
) -> Result<RegistryManifestV1, String> {
    if upstream.genesis_hash == downstream.genesis_hash {
        return Err(
            "the two counterparty positions must settle on different clusters: \
             RouteTimePolicyV2::from_registry refuses a route whose counterparty legs \
             share a chain id unless the DOM/XMR mainnet profile is selected"
                .to_owned(),
        );
    }
    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)
        .map_err(|error| format!("canonical DOM regtest genesis: {error:?}"))?;
    let dom_chain = ChainId(*derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes());
    let dom_asset = asset_id(b"DOM-SOLANA-DAEMON-ROUTE/DOM-NATIVE/V1\0", &dom_chain.0);

    let mut assets = vec![AssetBindingV1 {
        chain_id: dom_chain,
        asset_id: dom_asset,
        decimals: 9,
        representation: AssetRepresentationV1::Native,
    }];
    let mut chains = Vec::with_capacity(2);
    for facts in [upstream, downstream] {
        let chain_id = ChainId(facts.genesis_hash);
        if chain_id == dom_chain {
            return Err("a counterparty cluster may not be the DOM hub's own chain".to_owned());
        }
        let native_asset = solana_asset_id(facts);
        assets.push(AssetBindingV1 {
            chain_id,
            asset_id: native_asset,
            decimals: 9,
            representation: AssetRepresentationV1::Native,
        });
        chains.push(RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id,
                kind: ChainKindV1::Solana {
                    network: facts.network,
                    escrow_program: facts.escrow_program,
                    program_data_hash: facts.program_data_hash,
                },
                timing: solana_timing(),
                finality: solana_finality(),
                native_asset,
                allowed_assets: vec![],
            },
            deployment: ChainDeploymentV1::Solana(SolanaDeploymentV1 {
                genesis_hash: facts.genesis_hash,
                max_fee_lamports: facts.max_fee_lamports,
            }),
        });
    }
    chains.sort_by_key(|entry| entry.profile.chain_id.0);
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
        chains,
        assets,
    })
}

/// The native asset id of one cluster.
///
/// Named by the cluster it is native to, because native SOL has no mint and a zero
/// mint would look like a token. Two clusters therefore name two different assets,
/// which is correct: they are not fungible with each other.
pub fn solana_asset_id(facts: &SolanaChainFactsV1) -> AssetId {
    asset_id(
        b"DOM-SOLANA-DAEMON-ROUTE/SOL-NATIVE/V1\0",
        &facts.genesis_hash,
    )
}

/// A stand-in for the consensus rules digest of this DOM build.
///
/// A real deployment pins the digest of the consensus rules its nodes run. This
/// laboratory route has no such measurement to offer, so it declares a constant and
/// says so here rather than passing a hash of something unrelated off as one.
fn dom_crypto_consensus_digest() -> &'static [u8; 32] {
    &[0x22; 32]
}

/// Everything the registry provisioner is given.
///
/// The clock matters and is therefore explicit. The manifest's validity window must
/// contain the route-time policy's window, the registry is validated at a stated
/// second, and the terms are scheduled from the same second -- so all of them come
/// from one caller-supplied `now` instead of three constants that could disagree.
#[derive(Clone, Copy, Debug)]
pub struct RegistryProvisioningInputV1<'a> {
    pub state_dir: &'a Path,
    /// The layout's own relative path for `ProductionPathRoleV1::RegistryStore`.
    pub registry_relative: &'a str,
    /// The layout's own relative path for `ProductionPathRoleV1::RegistryAuthorities`.
    pub authorities_relative: &'a str,
    pub network_id: [u8; 32],
    /// Registry epoch. The bootstrap's rollback floor is pinned to it, and a zero
    /// epoch is refused.
    pub epoch: u64,
    /// Trusted wall clock, seconds. The registry is validated at this second.
    pub now_seconds: u64,
    /// How far before and after `now_seconds` the manifest declares itself valid.
    pub valid_from_offset_seconds: u64,
    pub valid_until_offset_seconds: u64,
    /// The cluster the upstream position settles on -- the operation that BEGINS on
    /// Solana.
    pub upstream: &'a SolanaChainFactsV1,
    /// The cluster the downstream position settles on -- the operation that ENDS on
    /// Solana. A different cluster, as the route-time policy requires.
    pub downstream: &'a SolanaChainFactsV1,
}

/// Build, sign, install and re-verify the registry; write the authority bundle
/// beside it.
pub fn provision(
    input: &RegistryProvisioningInputV1<'_>,
) -> Result<ProvisionedSolanaRegistryV1, String> {
    let valid_from_seconds = input
        .now_seconds
        .checked_sub(input.valid_from_offset_seconds)
        .ok_or_else(|| "the manifest would be valid before the epoch".to_owned())?;
    let expires_at_seconds = input
        .now_seconds
        .checked_add(input.valid_until_offset_seconds)
        .ok_or_else(|| "the manifest validity window overflows".to_owned())?;

    let manifest = manifest(
        input.network_id,
        input.epoch,
        valid_from_seconds,
        expires_at_seconds,
        input.upstream,
        input.downstream,
    )?;
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
        now_seconds: input.now_seconds,
        expected_network_id: input.network_id,
        minimum_epoch: input.epoch,
    };
    // The registry store refuses a parent directory that is not owner-only, and
    // `create_dir_all` would make one the runner's umask widened to 0o755.
    if let Some(parent) = input.state_dir.join(input.registry_relative).parent() {
        crate::owner_only::directory(parent)?;
    }
    let mut store = RegistryStoreV1::create(&input.state_dir.join(input.registry_relative))
        .map_err(|error| format!("registry store: {error:?}"))?;
    let (_outcome, resolved) = store
        .install(&signed, &registry_set, &secp, policy)
        .map_err(|error| format!("registry install: {error:?}"))?;
    if resolved.manifest_digest() != digest {
        return Err("the installed registry is not the manifest that was signed".to_owned());
    }
    // Measured from the registry that was installed, not from the manifest that was
    // handed to the store: the route-time policy derives it from the resolved
    // registry, and that is the value the terms must carry.
    let dom_profile_digest = route_time_anchor::resolved_dom_profile_digest_v1(&resolved)
        .map_err(|error| format!("dom profile digest: {error:?}"))?;
    let chain_profile_digest = |facts: &SolanaChainFactsV1| -> Result<[u8; 32], String> {
        resolved
            .resolve_chain(ChainId(facts.genesis_hash))
            .ok_or_else(|| "the installed registry does not declare that cluster".to_owned())?
            .profile()
            .profile_digest()
            .map_err(|error| format!("chain profile digest: {error:?}"))
    };
    let upstream_profile_digest = chain_profile_digest(input.upstream)?;
    let downstream_profile_digest = chain_profile_digest(input.downstream)?;

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
    crate::owner_only::write(&input.state_dir.join(input.authorities_relative), &bytes)?;

    Ok(ProvisionedSolanaRegistryV1 {
        network_id: input.network_id,
        epoch: input.epoch,
        manifest_digest: digest,
        authority_set_digest,
        valid_from_seconds,
        expires_at_seconds,
        dom_chain_id: manifest.dom.chain_id.0,
        dom_asset_id: manifest.dom.native_asset.0,
        dom_profile_digest,
        upstream_chain_id: input.upstream.genesis_hash,
        upstream_asset_id: solana_asset_id(input.upstream).0,
        upstream_profile_digest,
        downstream_chain_id: input.downstream.genesis_hash,
        downstream_asset_id: solana_asset_id(input.downstream).0,
        downstream_profile_digest,
    })
}
