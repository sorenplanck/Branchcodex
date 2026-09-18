//! Fresh signed time evidence from the owned local DOM snapshot and Solana
//! validator. RPC canonicality is an explicitly trusted boundary, not a PoW or
//! Tower-BFT audit. One SOL observation serves both same-chain positions.
use super::{NativeSolColdStartV23, SolanaTestValidatorOwnerV23};
use crate::production_node::ProductionNodeConfigV1;
use blake2::digest::{Update, VariableOutput};
use btc_crypto::SecpContext;
use deployment_registry::{RegistryManifestV1, RegistryStoreV1, RegistryValidationPolicyV1};
use dom_scriptless_chain_adapter::{BearerTokenV1, DomHttpChainAdapterV1, ScriptlessScanCursorV1};
use route_time_anchor::*;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_HISTORY: u64 = 4096;

pub(crate) struct SolColdStartSignedTimeV23 {
    pub(crate) policy: SignedRouteTimePolicyV2,
    pub(crate) evidence: SignedRouteTimeEvidenceV2,
    pub(crate) observed_at_seconds: u64,
}

impl SolColdStartSignedTimeV23 {
    /// Observes, signs, then runs the same durable signature/time/ladder
    /// verifier as admission. No verified capability escapes this producer.
    pub(crate) fn observe(
        cold: &NativeSolColdStartV23,
        node: &ProductionNodeConfigV1,
        mut bearer: Zeroizing<String>,
        validator: &SolanaTestValidatorOwnerV23,
        limits: RouteTimePolicyLimitsV2,
    ) -> Result<Self> {
        let identity = node.expected_identity();
        identity.validate()?;
        if identity.network != "mainnet"
            || cold
                .terms
                .iter()
                .any(|terms| terms.dom_leg.chain_id.0 != identity.chain_id)
        {
            return Err("time producer requires the exact DOM mainnet".into());
        }
        let address = node
            .endpoint()
            .as_str()
            .strip_prefix("http://")
            .ok_or("time producer local DOM scheme")?
            .trim_end_matches('/')
            .parse::<SocketAddr>()?;
        require_loopback(address)?;
        require_loopback(validator.address())?;
        let signed_registry = cold.signed_registry()?;
        let manifest = RegistryManifestV1::decode(signed_registry.manifest_bytes())?;
        let authorities = cold.authority_bundle()?;
        let secp = SecpContext::new(&[29; 32]);
        for (set, key) in [
            (authorities.registry(), [91; 32]),
            (authorities.time_policy(), [93; 32]),
            (authorities.time_evidence(), [94; 32]),
        ] {
            if set.threshold() != 1 || set.xonly_keys() != [secp.xonly_public_key(&key)?] {
                return Err("time fixture authority differs from ceremony".into());
            }
        }
        let root = tempfile::Builder::new()
            .prefix("native-sol-time-observation-")
            .tempdir_in(cold.root())?;
        let mut registry_store = RegistryStoreV1::create(&root.path().join("registry.sqlite"))?;
        let now = now_seconds()?;
        let registry_policy = RegistryValidationPolicyV1 {
            now_seconds: now,
            expected_network_id: manifest.network_id,
            minimum_epoch: manifest.epoch,
        };
        registry_store.install(
            &signed_registry,
            authorities.registry(),
            &secp,
            registry_policy,
        )?;
        let registry = registry_store
            .load_current(authorities.registry(), &secp, registry_policy)?
            .ok_or("time observation registry absent")?;
        // DOM mainnet with both counterparty legs on the same Solana cluster:
        // one chain observation serves both positions.
        let policy = RouteTimePolicyV2::from_registry_dom_sol_v25(
            &registry,
            &cold.terms[0],
            &cold.terms[1],
            limits,
        )?;
        let dom = DomHttpChainAdapterV1::new(
            node.endpoint().as_str(),
            identity,
            BearerTokenV1::new(std::mem::take(&mut *bearer))?,
            Duration::from_millis(node.connect_timeout_ms()),
            Duration::from_millis(node.request_timeout_ms()),
        )?;
        let bindings = policy.checkpoint_bindings();
        if bindings[0].genesis_hash() != node.expected_identity().genesis_hash
            || bindings[1].clock_kind() != ClockKindV2::Solana
            || bindings[2].clock_kind() != ClockKindV2::Solana
            || bindings[1].chain_id() != bindings[2].chain_id()
            || bindings[1].genesis_hash() != validator.genesis_hash()
            || bindings[2].genesis_hash() != validator.genesis_hash()
        {
            return Err("time producer changed the signed selected-chain profile".into());
        }
        let dom_observation = observe_dom(&dom, bindings[0], limits)?;
        let sol_observation = observe_solana(
            validator,
            if bindings[1].finality().min_confirmations >= bindings[2].finality().min_confirmations
            {
                bindings[1]
            } else {
                bindings[2]
            },
            limits,
        )?;
        let observed_at_seconds = now_seconds()?;
        let expiry = observed_at_seconds
            .checked_add(limits.max_evidence_age_seconds)
            .ok_or("time expiry overflow")?
            .min(limits.expires_at_seconds);
        let evidence = RouteTimeEvidenceV2::new(
            &policy,
            1,
            observed_at_seconds,
            expiry,
            [
                CanonicalTimeCheckpointV2::new(bindings[0], dom_observation),
                CanonicalTimeCheckpointV2::new(bindings[1], sol_observation),
                CanonicalTimeCheckpointV2::new(bindings[2], sol_observation),
            ],
        )?;
        let sign = |key, digest| -> Result<Vec<TimeAnchorSignatureV2>> {
            let (signature, _) = secp.sign_bip340(&key, &digest, &[37; 32])?;
            Ok(vec![TimeAnchorSignatureV2 {
                signer_index: 0,
                signature,
            }])
        };
        let signed_policy =
            SignedRouteTimePolicyV2::new(&policy, sign([93; 32], policy.policy_digest()?)?)?;
        let signed_evidence = SignedRouteTimeEvidenceV2::new(
            &evidence,
            sign([94; 32], evidence.evidence_digest()?)?,
        )?;
        let config = RouteTimeAnchorStoreConfigV2::new(
            &registry,
            &cold.terms[0],
            &cold.terms[1],
            authorities.time_policy(),
            authorities.time_evidence(),
            &secp,
        )?;
        let mut time =
            DurableRouteTimeAnchorStoreV2::create(&root.path().join("time.sqlite"), config)?;
        let policy_context = RouteTimePolicyVerificationContextV2::new(
            authorities.time_policy(),
            &secp,
            &registry,
            &cold.terms[0],
            &cold.terms[1],
        );
        let evidence_context = RouteTimeEvidenceVerificationContextV2::new(
            policy_context,
            authorities.time_evidence(),
        );
        let verified_at = now_seconds()?;
        time.install_policy(&signed_policy, policy_context, verified_at)?;
        time.install_evidence(&signed_evidence, evidence_context, verified_at)?;
        time.prove_route_ladder(evidence_context, verified_at)?;
        drop(time);
        drop(registry_store);
        Ok(Self {
            policy: signed_policy,
            evidence: signed_evidence,
            observed_at_seconds,
        })
    }
}

fn require_loopback(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("time observer requires numeric loopback endpoints".into());
    }
    Ok(())
}

/// Same complete genesis-to-tip DOM walk as the XMR campaign observer.
fn observe_dom(
    client: &DomHttpChainAdapterV1,
    binding: CheckpointBindingV2,
    limits: RouteTimePolicyLimitsV2,
) -> Result<CanonicalCheckpointObservationV2> {
    let mut cursor = ScriptlessScanCursorV1::genesis();
    let mut blocks = Vec::new();
    let mut tip = None;
    loop {
        let page = client.scan_page(cursor, 64)?;
        let identity = (page.identity.tip_height, page.identity.tip_hash);
        if identity.0 == 0
            || identity.0 > MAX_HISTORY
            || tip.is_some_and(|previous| previous != identity)
        {
            return Err("DOM time snapshot empty, changed, or oversized".into());
        }
        tip = Some(identity);
        if page.blocks.is_empty() {
            return Err("DOM time walk made no progress".into());
        }
        blocks.extend(page.blocks);
        cursor = page.next_cursor;
        if page.reached_snapshot_tip {
            break;
        }
        if cursor.next_height > MAX_HISTORY {
            return Err("DOM time scan bound".into());
        }
    }
    let (tip_height, tip_hash) = tip.ok_or("DOM time tip absent")?;
    if blocks.len() < 2
        || blocks.first().map(|block| block.block_hash) != Some(binding.genesis_hash())
        || blocks.last().map(|block| (block.height, block.block_hash))
            != Some((tip_height, tip_hash))
    {
        return Err("DOM time walk does not reach the pinned genesis and tip".into());
    }
    let tip_page = client.scan_page(
        ScriptlessScanCursorV1 {
            next_height: tip_height,
            anchor_hash: Some(blocks[blocks.len() - 2].block_hash),
        },
        1,
    )?;
    if tip_page.identity.tip_height != tip_height || tip_page.identity.tip_hash != tip_hash {
        return Err("DOM time tip changed after observation".into());
    }
    let anchor_height = anchor_height(tip_height, binding)?;
    let anchor = blocks
        .iter()
        .find(|block| block.height == anchor_height)
        .ok_or("DOM time anchor absent")?;
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(b"DOM-INTEROP/TIME/DOM-RPC-WALK/V23\0");
    hash.update(&binding.chain_id().0);
    for block in &blocks {
        hash.update(&block.height.to_be_bytes());
        hash.update(&block.block_hash);
        hash.update(&block.previous_block_hash);
        hash.update(&(u32::try_from(block.canonical_header_bytes.len())?).to_be_bytes());
        hash.update(&block.canonical_header_bytes);
    }
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)?;
    observation(
        anchor_height,
        anchor.block_hash,
        anchor.previous_block_hash,
        anchor.timestamp,
        tip_height,
        tip_hash,
        digest,
        limits,
    )
}

/// The finalized commitment is the confirmation: the SOL profile demands one
/// confirmation, so anchor and tip are the same produced finalized block.
fn observe_solana(
    validator: &SolanaTestValidatorOwnerV23,
    binding: CheckpointBindingV2,
    limits: RouteTimePolicyLimitsV2,
) -> Result<CanonicalCheckpointObservationV2> {
    if binding.finality().min_confirmations != 1
        || binding.genesis_hash() != validator.genesis_hash()
    {
        return Err("SOL time observer requires the finalized one-confirmation profile".into());
    }
    let (slot, block_hash, parent_hash, block_time) = validator.finalized_block_v25()?;
    let (reread_slot, _) = validator.finalized_anchor_v25()?;
    if slot == 0 || reread_slot < slot || block_time == 0 {
        return Err("SOL finalized anchor rolled back or is genesis".into());
    }
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(b"DOM-INTEROP/TIME/SOL-RPC-ANCHOR/V25\0");
    hash.update(&binding.chain_id().0);
    hash.update(&binding.genesis_hash());
    hash.update(&slot.to_be_bytes());
    hash.update(&block_hash);
    hash.update(&parent_hash);
    hash.update(&block_time.to_be_bytes());
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)?;
    observation(
        slot,
        block_hash,
        parent_hash,
        block_time,
        slot,
        block_hash,
        digest,
        limits,
    )
}

fn anchor_height(tip: u64, binding: CheckpointBindingV2) -> Result<u64> {
    let depth = u64::from(binding.finality().min_confirmations)
        .checked_sub(1)
        .ok_or("zero time confirmations")?;
    let anchor = tip
        .checked_sub(depth)
        .ok_or("insufficient time confirmations")?;
    if anchor == 0 {
        return Err("genesis is not a time anchor".into());
    }
    Ok(anchor)
}

#[allow(clippy::too_many_arguments)]
fn observation(
    height: u64,
    hash: [u8; 32],
    parent: [u8; 32],
    timestamp: u64,
    tip: u64,
    tip_hash: [u8; 32],
    digest: [u8; 32],
    limits: RouteTimePolicyLimitsV2,
) -> Result<CanonicalCheckpointObservationV2> {
    // Use the entire signed uncertainty budget, not an exact wall-clock claim.
    let half = limits.max_anchor_interval_width_seconds / 2;
    let lower = timestamp
        .checked_sub(half)
        .ok_or("time interval underflow")?;
    let upper = timestamp
        .checked_add(half)
        .ok_or("time interval overflow")?;
    Ok(CanonicalCheckpointObservationV2::new(
        CanonicalAnchorObservationV2::new(height, hash, parent),
        CanonicalTimeRangeV2::new(lower, upper),
        CanonicalTipObservationV2::new(tip, tip_hash, digest),
    ))
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
