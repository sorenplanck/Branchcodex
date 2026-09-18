//! Explicit off-chain timing profile for mainnet DOM with both counterparty
//! positions on one Solana chain; no chain activation or signing authority.
use super::*;

pub(super) fn require_mainnet_dom_sol_terms_v25(
    registry: &ResolvedRegistryV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<()> {
    if registry.manifest().dom.runtime_identity.network != DomNetworkV1::Mainnet
        || upstream.counterparty_leg.chain_id != downstream.counterparty_leg.chain_id
    {
        return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
    }
    for leg in [&upstream.counterparty_leg, &downstream.counterparty_leg] {
        registry
            .resolve_asset(leg.chain_id, leg.asset_id)
            .ok_or(RouteTimeAnchorErrorV2::RegistryMismatch)?;
        let binding = native_counterparty_binding_sol_v25(
            registry,
            leg,
            CheckpointRoleV2::UpstreamCounterparty,
        )?;
        if binding.clock_kind != ClockKindV2::Solana {
            return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
        }
    }
    Ok(())
}

pub(super) fn native_counterparty_binding_sol_v25(
    registry: &ResolvedRegistryV1,
    leg: &kaystra_core::types::LegTermsV1,
    role: CheckpointRoleV2,
) -> Result<CheckpointBindingV2> {
    let resolved = registry
        .resolve_chain(leg.chain_id)
        .ok_or(RouteTimeAnchorErrorV2::RegistryMismatch)?;
    let profile = resolved.profile();
    registry
        .resolve_asset(leg.chain_id, leg.asset_id)
        .ok_or(RouteTimeAnchorErrorV2::RegistryMismatch)?;
    let ChainDeploymentV1::Solana(deployment) = resolved.deployment() else {
        return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
    };
    if !matches!(profile.kind, ChainKindV1::Solana { .. })
        || leg.mechanism != LockMechanism::CrossCurveConditionLock
        || !matches!(leg.deadline, TimelockSpec::TimestampSeconds { .. })
    {
        return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
    }
    let profile_digest = profile
        .profile_digest()
        .map_err(|_| RouteTimeAnchorErrorV2::RegistryMismatch)?;
    // Unlike the XMR profile, the leg carries the REGISTRY chain-profile
    // digest, exactly as generic V2 and route admission require. The
    // operational Solana adapter-profile hash is a different domain and is
    // refused here rather than silently accepted as a temporal identity.
    if leg.adapter_profile_hash != profile_digest || leg.finality != profile.finality {
        return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
    }
    Ok(CheckpointBindingV2 {
        role,
        clock_kind: ClockKindV2::Solana,
        chain_id: profile.chain_id,
        genesis_hash: deployment.genesis_hash,
        profile_digest,
        timing: profile.timing,
        finality: profile.finality,
    })
}
