//! Explicit off-chain timing profile; no chain activation or signing authority.
use super::*;

pub(super) fn require_mainnet_dom_xmr_terms_v23(
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
        let binding =
            native_counterparty_binding_v23(registry, leg, CheckpointRoleV2::UpstreamCounterparty)?;
        let resolved = registry
            .resolve_chain(leg.chain_id)
            .ok_or(RouteTimeAnchorErrorV2::RegistryMismatch)?;
        if !matches!(
            resolved.profile().kind,
            ChainKindV1::Monero {
                network: chain_profile::MoneroNetworkV1::Mainnet
            }
        ) || binding.clock_kind != ClockKindV2::Monero
        {
            return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
        }
    }
    Ok(())
}

pub(super) fn native_counterparty_binding_v23(
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
    let ChainDeploymentV1::Monero(deployment) = resolved.deployment() else {
        return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
    };
    if !matches!(
        profile.kind,
        ChainKindV1::Monero {
            network: chain_profile::MoneroNetworkV1::Mainnet
        }
    ) || leg.finality != profile.finality
        || leg.mechanism != LockMechanism::CrossCurveSharedSpend
        || !matches!(leg.deadline, TimelockSpec::BlockHeight { .. })
        || leg.adapter_profile_hash == [0; 32]
    {
        return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
    }
    // The registry timing/deployment profile and the XMR sidecar adapter
    // profile are DIFFERENT domains. The latter stays in signed terms and is
    // checked by setup/admission, not converted into a temporal grant here.
    Ok(CheckpointBindingV2 {
        role,
        clock_kind: ClockKindV2::Monero,
        chain_id: profile.chain_id,
        genesis_hash: deployment.genesis_hash,
        profile_digest: profile
            .profile_digest()
            .map_err(|_| RouteTimeAnchorErrorV2::RegistryMismatch)?,
        timing: profile.timing,
        finality: profile.finality,
    })
}
