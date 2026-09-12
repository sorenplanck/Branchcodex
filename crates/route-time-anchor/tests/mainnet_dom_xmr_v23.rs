//! Off-chain timing profile regression coverage. Public checkpoint fixtures
//! exercise validation only; they are not canonical-chain evidence or funding.
mod common;
#[path = "mainnet_dom_xmr_v23/native.rs"]
mod native;

use common::{EVIDENCE_TIME, REGISTRY_NETWORK};
use rfq::v2::{NativeClockKindV2, NegotiationClockV2};
use route_time_anchor::{
    resolved_dom_profile_digest_v1, PreF6TimePolicyLimitsV2, PreF6TimePolicyV2,
    PreF6TimeScopeRequestV2, PreF6TimeScopeV2, RouteTimeAnchorErrorV2, RouteTimePolicyV2,
};

#[test]
fn legacy_codec_and_mainnet_refusal_remain_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = common::fixture();
    let bytes = fixture.policy.canonical_bytes()?;
    assert_eq!(&bytes[10..12], &[0, 0]);
    assert_eq!(RouteTimePolicyV2::decode(&bytes)?, fixture.policy);
    let mut unknown = bytes.clone();
    unknown[11] = 2;
    assert_eq!(
        RouteTimePolicyV2::decode(&unknown),
        Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    );
    let mut substituted = bytes;
    substituted[11] = 1;
    // Native marker cannot reinterpret an EVM/BTC policy as a shared XMR clock.
    assert!(RouteTimePolicyV2::decode(&substituted).is_err());
    let (registry, upstream, downstream) = common::mainnet_registry_and_terms();
    assert_eq!(
        RouteTimePolicyV2::from_registry(&registry, &upstream, &downstream, common::limits()),
        Err(RouteTimeAnchorErrorV2::MainnetDisabled)
    );
    assert!(RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &registry,
        &upstream,
        &downstream,
        common::limits()
    )
    .is_err());
    assert!(RouteTimePolicyV2::from_registry_dom_xmr_v23(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        common::limits()
    )
    .is_err());
    Ok(())
}

fn scope(
    registry: &deployment_registry::ResolvedRegistryV1,
) -> Result<PreF6TimeScopeV2, Box<dyn std::error::Error>> {
    Ok(PreF6TimeScopeV2::new(PreF6TimeScopeRequestV2 {
        network_id: REGISTRY_NETWORK,
        session_id: [0x71; 32],
        route_id: [0x72; 32],
        composition_id: [0x73; 32],
        rfq_id: [0x74; 32],
        profile_bundle_digest: [0x75; 32],
        negotiation_clock: NegotiationClockV2 {
            chain_id: registry.manifest().dom.chain_id,
            profile_digest: resolved_dom_profile_digest_v1(registry)?,
            authority_scope: [0x76; 32],
            kind: NativeClockKindV2::BlockHeight,
        },
        registry_digest: registry.manifest_digest(),
        registry_epoch: registry.epoch(),
    })?)
}

#[test]
fn native_pre_f6_requires_real_mainnet_registry_scope_without_changing_legacy(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, _, _) = common::mainnet_registry_and_terms();
    let limits = PreF6TimePolicyLimitsV2 {
        valid_from_seconds: 900_000,
        expires_at_seconds: 4_000_000,
        max_evidence_age_seconds: 300,
    };
    let native_scope = scope(&registry)?;
    assert_eq!(
        PreF6TimePolicyV2::from_registry(native_scope, &registry, limits),
        Err(RouteTimeAnchorErrorV2::MainnetDisabled)
    );
    let policy = PreF6TimePolicyV2::from_registry_dom_mainnet_v23(native_scope, &registry, limits)?;
    assert_eq!(&policy.canonical_bytes()?[..8], b"DOMPF6P3");
    assert_eq!(policy.genesis_hash(), registry.manifest().dom.genesis_hash);
    assert_eq!(policy.limits(), limits);
    let old = common::fixture();
    assert!(PreF6TimePolicyV2::from_registry_dom_mainnet_v23(
        scope(&old.registry)?,
        &old.registry,
        limits
    )
    .is_err());
    assert!(PreF6TimePolicyV2::from_registry_dom_mainnet_v23(
        scope(&old.registry)?,
        &registry,
        limits
    )
    .is_err());
    let legacy = PreF6TimePolicyV2::from_registry(scope(&old.registry)?, &old.registry, limits)?;
    assert_eq!(&legacy.canonical_bytes()?[..8], b"DOMPF6P2");
    assert_ne!(legacy.policy_digest()?, policy.policy_digest()?);
    let mut short = limits;
    short.expires_at_seconds = EVIDENCE_TIME;
    short.max_evidence_age_seconds = 301;
    assert!(
        PreF6TimePolicyV2::from_registry_dom_mainnet_v23(native_scope, &registry, short).is_err()
    );
    Ok(())
}
