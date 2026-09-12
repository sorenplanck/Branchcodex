//! Fresh signed time evidence from the actual local DOM/XMR scenario RPCs.
//! RPC canonicality is an explicitly trusted boundary, not a PoW audit.
use super::xmr_graph_wallet_tests::native_observation_v23::{
    NativeDomSnapshotV23, RouteFundingOwnerV23,
};
use super::NativeXmrColdStartV23;
use crate::production_node::ProductionNodeConfigV1;
use btc_crypto::SecpContext;
use deployment_registry::{RegistryManifestV1, RegistryStoreV1, RegistryValidationPolicyV1};
use dom_scriptless_chain_adapter::{BearerTokenV1, DomHttpChainAdapterV1, ScriptlessScanCursorV1};
use route_time_anchor::*;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[path = "production_xmr_native_time_observations_v23_tests.rs"]
mod observations;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct ColdStartSignedTimeV23 {
    pub(crate) policy: SignedRouteTimePolicyV2,
    pub(crate) evidence: SignedRouteTimeEvidenceV2,
    pub(crate) observed_at_seconds: u64,
}

impl ColdStartSignedTimeV23 {
    /// Observes, signs, then runs the same durable signature/time/ladder
    /// verifier as admission. No verified capability escapes this producer.
    pub(crate) fn observe(
        cold: &NativeXmrColdStartV23,
        node: &ProductionNodeConfigV1,
        bearer: Zeroizing<String>,
        xmr_addresses: Vec<SocketAddr>,
        limits: RouteTimePolicyLimitsV2,
    ) -> Result<Self> {
        Self::observe_mode_v24(cold, node, bearer, xmr_addresses, limits, None)
    }

    fn observe_mode_v24(
        cold: &NativeXmrColdStartV23,
        node: &ProductionNodeConfigV1,
        mut bearer: Zeroizing<String>,
        xmr_addresses: Vec<SocketAddr>,
        limits: RouteTimePolicyLimitsV2,
        live_window: Option<(u64, u64)>,
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
        observations::require_loopback(address)?;
        let signed_registry = cold.signed_registry()?;
        let manifest = RegistryManifestV1::decode(signed_registry.manifest_bytes())?;
        let authorities = cold.authority_bundle()?;
        let secp = SecpContext::new(&[29; 32]);
        // These are the real private authority owners created by this fixture,
        // not accepted arbitrary signing keys or invented authority identifiers.
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
            .prefix("native-time-observation-")
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
        let policy = RouteTimePolicyV2::from_registry_dom_xmr_v23(
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
        let profile = cold.enrolled[0].profile();
        if profile.network != xmr_setup_profile::XmrNetwork::Mainnet
            || profile != cold.enrolled[1].profile()
            || xmr_addresses.len() != usize::from(profile.rpc_node_count)
            || cold.terms.iter().any(|terms| {
                crate::production_xmr_native_registry_fixture_v23::profile_for_terms_v24(
                    terms, profile,
                )
                .is_err()
            })
            || bindings[0].genesis_hash() != node.expected_identity().genesis_hash
            || bindings[1].chain_id() != bindings[2].chain_id()
            || bindings[1].genesis_hash() != bindings[2].genesis_hash()
        {
            return Err("time producer changed the signed selected-chain profile".into());
        }
        let dom_observation = match live_window {
            None => observations::dom(&dom, bindings[0], limits)?,
            Some((baseline, span)) => {
                observations::dom_live_window_v24(&dom, bindings[0], limits, baseline, span)?
            }
        };
        // A single agreed observation is projected into both roles. Same XMR
        // chain cannot acquire two contradictory clocks merely by position.
        let xmr_observation = observations::monero(
            &xmr_addresses,
            if bindings[1].finality().min_confirmations >= bindings[2].finality().min_confirmations
            {
                bindings[1]
            } else {
                bindings[2]
            },
            limits,
            cold.enrolled[0].profile().rpc_quorum,
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
                CanonicalTimeCheckpointV2::new(bindings[1], xmr_observation),
                CanonicalTimeCheckpointV2::new(bindings[2], xmr_observation),
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

impl NativeXmrColdStartV23 {
    /// Live test-only observation requires the enabled original snapshot owner,
    /// not an operator-supplied switch or a replacement node identity.
    pub(crate) fn observe_mainnet_time_live_v24(
        &self,
        node: &ProductionNodeConfigV1,
        bearer: Zeroizing<String>,
        funding: &RouteFundingOwnerV23,
        limits: RouteTimePolicyLimitsV2,
        baseline: &NativeDomSnapshotV23,
    ) -> Result<ColdStartSignedTimeV23> {
        if node.endpoint().as_str().trim_end_matches('/')
            != baseline.endpoint().trim_end_matches('/')
            || &node.expected_identity() != baseline.adapter().expected_identity()
        {
            return Err("live time observer differs from enabled snapshot owner".into());
        }
        let scope = baseline.live_window_scope_v24()?;
        let urls = funding
            .urls()
            .iter()
            .map(|url| -> Result<SocketAddr> {
                Ok(url
                    .strip_prefix("http://")
                    .ok_or("local XMR scheme")?
                    .parse()?)
            })
            .collect::<Result<Vec<_>>>()?;
        ColdStartSignedTimeV23::observe_mode_v24(self, node, bearer, urls, limits, Some(scope))
    }
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
