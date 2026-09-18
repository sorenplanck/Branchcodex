//! Deadline arithmetic for a NEW DOM↔SOL cold-start negotiation, never a
//! mutation of an admitted route. DOM stays a block height; the Solana leg is
//! a cluster timestamp whose verifier widens it by a symmetric drift band.
use super::*;

/// The verifier's own drift band, re-exported by `route_time_anchor`. The
/// negotiation keeps exactly that reserve, never a second copy of the value.
pub(super) const SOLANA_CLOCK_DRIFT_SECONDS_V25: u64 =
    route_time_anchor::SOLANA_CLOCK_DRIFT_SECONDS_V2;

pub(super) struct NativeSolDeadlinePlanV23 {
    dom: [u64; 2],
    sol: [u64; 2],
    maximum_dom_height: u64,
}

impl NativeSolDeadlinePlanV23 {
    pub(super) fn new(
        manifest: &deployment_registry::RegistryManifestV1,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        dom_baseline_tip: u64,
    ) -> ColdStartResult<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Self::at_v25(manifest, limits, dom_baseline_tip, now)
    }

    fn at_v25(
        manifest: &deployment_registry::RegistryManifestV1,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        dom_baseline_tip: u64,
        now: u64,
    ) -> ColdStartResult<Self> {
        let lifetime = limits
            .expires_at_seconds
            .checked_sub(limits.valid_from_seconds)
            .ok_or("cold-start policy lifetime order")?;
        let preparation_seconds = lifetime.min(limits.max_evidence_age_seconds);
        if preparation_seconds == 0 || preparation_seconds > 21_600 {
            return Err("cold-start preparation exceeds bounded six-hour campaign".into());
        }
        if dom_baseline_tip < 1003 || dom_baseline_tip > 4095 {
            return Err("cold-start planned DOM baseline height bound".into());
        }
        let sol = manifest
            .chains
            .iter()
            .find(|chain| {
                matches!(
                    chain.profile.kind,
                    chain_profile::ChainKindV1::Solana {
                        network: chain_profile::SolanaNetworkV1::LocalValidator,
                        ..
                    }
                )
            })
            .ok_or("cold-start local-validator timing profile absent")?
            .profile
            .timing;
        // The signed M.8 floor of the one SOL chain carried by both legs.
        let floor = adapter_btc::timelock::minimum_safety_margin_seconds(&sol, &sol)?;
        if limits.counterparty_margin_seconds < floor {
            return Err("negotiated counterparty margin is below the signed SOL M.8 floor".into());
        }
        // DOM: identical to the XMR negotiation (baseline anchor age, full
        // uncertainty interval, preparation horizon, hub margin, reserve).
        let dom_minimum = u64::from(manifest.dom.timing.min_block_seconds);
        if dom_minimum == 0 {
            return Err("invalid signed DOM minimum block time".into());
        }
        let anchor_age = u64::from(manifest.dom.finality.min_confirmations)
            .checked_sub(1)
            .and_then(|depth| {
                depth.checked_mul(
                    xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23::BASELINE_BLOCK_SECONDS_V24,
                )
            })
            .and_then(|age| age.checked_add(limits.max_anchor_interval_width_seconds / 2))
            .ok_or("DOM baseline anchor age overflow or zero finality")?;
        let preparation_blocks = anchor_age
            .checked_add(preparation_seconds)
            .ok_or("DOM preparation horizon overflow")?
            .checked_add(dom_minimum - 1)
            .ok_or("DOM baseline anchor ceiling overflow")?
            / dom_minimum;
        let down_dom = dom_baseline_tip
            .checked_add(preparation_blocks)
            .ok_or("DOM deadline overflow")?;
        let timing = manifest.dom.timing;
        let min_block_seconds = u64::from(timing.min_block_seconds);
        let max_block_seconds = u64::from(timing.max_block_seconds);
        if min_block_seconds == 0 || min_block_seconds > max_block_seconds {
            return Err("invalid signed block-time range".into());
        }
        let up_dom = down_dom
            .checked_mul(max_block_seconds)
            .and_then(|n| n.checked_add(limits.max_anchor_interval_width_seconds))
            .and_then(|n| n.checked_add(limits.hub_margin_seconds))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(min_block_seconds - 1))
            .ok_or("deadline conservative bound overflow")?
            / min_block_seconds;
        let up_dom = up_dom.max(down_dom.checked_add(1).ok_or("deadline order overflow")?);
        let maximum_dom_height = up_dom
            .checked_add(256)
            .ok_or("DOM campaign recovery reserve overflow")?;
        if maximum_dom_height
            > xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23::MAX_CAMPAIGN_HEIGHT_V24
        {
            return Err("DOM campaign exceeds bounded paginated history".into());
        }
        // SOL: the downstream refund instant must stay after the whole
        // preparation horizon even at the late edge of the drift band.
        let down_sol = now
            .checked_add(preparation_seconds)
            .and_then(|v| v.checked_add(SOLANA_CLOCK_DRIFT_SECONDS_V25))
            .and_then(|v| v.checked_add(limits.counterparty_margin_seconds))
            .ok_or("SOL downstream deadline overflow")?;
        // Upstream's earliest instant must follow downstream's latest instant
        // by the counterparty margin and the anchor uncertainty width.
        let up_sol = down_sol
            .checked_add(2 * SOLANA_CLOCK_DRIFT_SECONDS_V25)
            .and_then(|v| v.checked_add(limits.counterparty_margin_seconds))
            .and_then(|v| v.checked_add(limits.max_anchor_interval_width_seconds))
            .and_then(|v| v.checked_add(1))
            .ok_or("SOL upstream deadline overflow")?;
        if i64::try_from(up_sol).is_err() {
            return Err("SOL deadline exceeds the escrow refund timestamp range".into());
        }
        Ok(Self {
            dom: [up_dom, down_dom],
            sol: [up_sol, down_sol],
            maximum_dom_height,
        })
    }

    pub(super) fn maximum_dom_height_v24(&self) -> u64 {
        self.maximum_dom_height
    }

    pub(super) fn terms(&self, position: usize, terms: &mut SettlementTermsV1) {
        terms.dom_leg.deadline = kaystra_core::types::TimelockSpec::BlockHeight {
            value: self.dom[position],
        };
        terms.counterparty_leg.deadline = kaystra_core::types::TimelockSpec::TimestampSeconds {
            value: self.sol[position],
        };
    }
}

#[cfg(test)]
mod ladder_tests_v25 {
    use super::*;

    fn limits(margin: u64) -> route_time_anchor::RouteTimePolicyLimitsV2 {
        route_time_anchor::RouteTimePolicyLimitsV2 {
            valid_from_seconds: 1,
            expires_at_seconds: 21601,
            max_evidence_age_seconds: 21600,
            max_anchor_interval_width_seconds: 600,
            max_anchor_time_skew_seconds: 1800,
            max_future_skew_seconds: 600,
            max_upstream_funding_anchor_delay_seconds: 14400,
            max_downstream_funding_anchor_delay_seconds: 14400,
            hub_margin_seconds: 300,
            counterparty_margin_seconds: margin,
        }
    }

    #[test]
    fn sol_ladder_orders_upstream_after_downstream_drift_and_margin_v25() -> ColdStartResult<()> {
        use crate::production_sol_native_registry_fixture_v23 as registry_v23;
        let (registry, mut up, mut down) =
            crate::route_time_test_common::mainnet_registry_and_terms();
        let mut manifest = registry.manifest().clone();
        registry_v23::configure_network(
            &mut manifest,
            [&mut up, &mut down],
            [7; 32],
            registry_v23::program_id_v23()?,
            [9; 32],
        )?;
        let floor = adapter_btc::timelock::minimum_safety_margin_seconds(
            &registry_v23::NATIVE_SOL_TIMING_V23,
            &registry_v23::NATIVE_SOL_TIMING_V23,
        )?;
        let now = 1_900_000_000;
        let plan = NativeSolDeadlinePlanV23::at_v25(&manifest, limits(floor), 1003, now)?;
        let drift = SOLANA_CLOCK_DRIFT_SECONDS_V25;
        assert!(plan.sol[0] - drift > plan.sol[1] + drift + floor);
        assert!(plan.sol[1] - drift >= now + 21600);
        assert!(plan.dom[0] > plan.dom[1]);
        assert!(plan.maximum_dom_height >= plan.dom[0] + 256);
        if floor > 0 {
            assert!(NativeSolDeadlinePlanV23::at_v25(&manifest, limits(floor - 1), 1003, now).is_err());
        }
        let mut terms = up.clone();
        plan.terms(1, &mut terms);
        assert_eq!(
            terms.counterparty_leg.deadline,
            kaystra_core::types::TimelockSpec::TimestampSeconds { value: plan.sol[1] }
        );
        Ok(())
    }
}
