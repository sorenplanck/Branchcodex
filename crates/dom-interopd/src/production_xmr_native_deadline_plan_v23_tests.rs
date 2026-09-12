//! Deadline arithmetic for a NEW cold-start negotiation, never a mutation of
//! an admitted live route. Increase heights; keep compensation windows intact.
use super::*;

pub(super) struct NativeDeadlinePlanV23 {
    dom: [u64; 2],
    xmr: [u64; 2],
    live_maximum_height: Option<u64>,
}

#[cfg(test)]
mod live_bound_tests_v24 {
    use super::*;

    fn limits() -> route_time_anchor::RouteTimePolicyLimitsV2 {
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
            counterparty_margin_seconds: 300,
        }
    }

    #[test]
    fn live_window_reserves_full_ladder_without_changing_default() -> ColdStartResult<()> {
        let (registry, mut upstream, mut downstream) =
            crate::route_time_test_common::mainnet_registry_and_terms();
        let mut manifest = registry.manifest().clone();
        crate::production_xmr_native_registry_fixture_v23::configure_network(
            &mut manifest,
            [&mut upstream, &mut downstream],
            xmr_setup_profile::XmrNetwork::Mainnet,
        )?;
        let original = NativeDeadlinePlanV23::new(&manifest, limits(), 1003)?;
        let live = NativeDeadlinePlanV23::new_live_v24(&manifest, limits(), 1003)?;
        assert_eq!(original.dom, [3107, 1103]);
        assert_eq!(live.dom, [4707, 1903]);
        assert_eq!(live.xmr, original.xmr);
        assert_eq!(original.live_maximum_height, None);
        assert_eq!(live.live_maximum_height, Some(5098));
        assert!(live.dom[0] + 256 <= live.live_maximum_height.unwrap());
        Ok(())
    }

    #[test]
    fn unsupported_live_budget_is_refused_not_clamped() {
        let mut policy = limits();
        assert!(NativeDeadlinePlanV23::validate_live_limits_v24(policy, 1003).is_ok());
        policy.max_anchor_interval_width_seconds = 1000;
        assert!(NativeDeadlinePlanV23::validate_live_limits_v24(policy, 1003).is_err());
        policy.max_anchor_interval_width_seconds = u64::MAX;
        assert!(NativeDeadlinePlanV23::validate_live_limits_v24(policy, 1003).is_err());
        assert!(NativeDeadlinePlanV23::validate_live_limits_v24(limits(), 0).is_err());
    }
}
impl NativeDeadlinePlanV23 {
    pub(super) fn new(
        manifest: &deployment_registry::RegistryManifestV1,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        dom_baseline_tip: u64,
    ) -> ColdStartResult<Self> {
        if dom_baseline_tip < 1003 || dom_baseline_tip > 4095 {
            return Err("cold-start planned DOM baseline height bound".into());
        }
        let xmr = manifest
            .chains
            .iter()
            .find(|chain| {
                matches!(
                    chain.profile.kind,
                    chain_profile::ChainKindV1::Monero {
                        network: chain_profile::MoneroNetworkV1::Mainnet
                    }
                )
            })
            .ok_or("cold-start mainnet timing profile absent")?
            .profile
            .timing;
        let down_dom = dom_baseline_tip
            .checked_add(100)
            .ok_or("DOM deadline overflow")?;
        // The route helper's common immutable ledger currently ends at 200.
        // Keep the full former 100000-block horizon, rather than shortening it.
        let down_xmr = 200u64.checked_add(100_000).ok_or("XMR deadline overflow")?;
        let upper = |down: u64,
                     timing: adapter_btc::timelock::ChainTimingBoundsV1,
                     margin: u64|
         -> ColdStartResult<u64> {
            let min_block_seconds = u64::from(timing.min_block_seconds);
            let max_block_seconds = u64::from(timing.max_block_seconds);
            if min_block_seconds == 0 || min_block_seconds > max_block_seconds {
                return Err("invalid signed block-time range".into());
            }
            let numerator = down
                .checked_mul(max_block_seconds)
                .and_then(|n| n.checked_add(limits.max_anchor_interval_width_seconds))
                .and_then(|n| n.checked_add(margin))
                .and_then(|n| n.checked_add(1))
                .ok_or("deadline conservative bound overflow")?;
            let value = numerator
                .checked_add(min_block_seconds - 1)
                .ok_or("deadline ceiling overflow")?
                / min_block_seconds;
            Ok(value.max(down.checked_add(1).ok_or("deadline order overflow")?))
        };
        Ok(Self {
            dom: [
                upper(down_dom, manifest.dom.timing, limits.hub_margin_seconds)?,
                down_dom,
            ],
            xmr: [
                upper(down_xmr, xmr, limits.counterparty_margin_seconds)?,
                down_xmr,
            ],
            live_maximum_height: None,
        })
    }
    /// Separate initial negotiation for the supplemental live harness. The
    /// original +100 constructor and every existing caller are unchanged.
    pub(super) fn new_live_v24(
        manifest: &deployment_registry::RegistryManifestV1,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        baseline: u64,
    ) -> ColdStartResult<Self> {
        Self::validate_live_limits_v24(limits, baseline)?;
        let mut plan = Self::new(manifest, limits, baseline)?;
        let timing = manifest.dom.timing;
        if timing.min_block_seconds != 1
            || timing.max_block_seconds != 2
            || manifest.dom.finality.min_confirmations == 0
            || manifest.dom.finality.min_confirmations > 64
        {
            return Err("live DOM timing/finality does not match bounded negotiation".into());
        }
        let downstream = baseline
            .checked_add(900)
            .ok_or("live DOM horizon overflow")?;
        let upstream = downstream
            .checked_mul(2)
            .and_then(|v| v.checked_add(limits.max_anchor_interval_width_seconds))
            .and_then(|v| v.checked_add(limits.hub_margin_seconds))
            .and_then(|v| v.checked_add(1))
            .ok_or("live DOM ladder overflow")?;
        plan.dom = [upstream, downstream];
        plan.live_maximum_height = Some(baseline.checked_add(4095).ok_or("live window overflow")?);
        Ok(plan)
    }
    pub(super) fn validate_live_limits_v24(
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        baseline: u64,
    ) -> ColdStartResult<()> {
        if baseline != 1003 {
            return Err("live baseline must be the original mature native inventory".into());
        }
        let upstream = baseline
            .checked_add(900)
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(limits.max_anchor_interval_width_seconds))
            .and_then(|v| v.checked_add(limits.hub_margin_seconds))
            .and_then(|v| v.checked_add(1))
            .ok_or("live ladder overflow")?;
        // Reserve the whole allowed compensation span (128), finality (64),
        // and another 64 blocks for inclusion/reconciliation. Never truncate.
        if upstream
            .checked_add(256)
            .ok_or("live recovery reserve overflow")?
            > baseline.checked_add(4095).ok_or("live history overflow")?
        {
            return Err(
                "live negotiation cannot contain preparation and recovery within 4096 blocks"
                    .into(),
            );
        }
        Ok(())
    }
    pub(super) fn terms(&self, position: usize, terms: &mut SettlementTermsV1) {
        terms.dom_leg.deadline = kaystra_core::types::TimelockSpec::BlockHeight {
            value: self.dom[position],
        };
        terms.counterparty_leg.deadline = kaystra_core::types::TimelockSpec::BlockHeight {
            value: self.xmr[position],
        };
    }
    pub(super) fn compensation(
        &self,
        position: usize,
        policy: &mut xmr_refund_policy::compensation::XmrCompensationPolicyV11,
    ) -> ColdStartResult<()> {
        let span = policy
            .compensation_height
            .checked_sub(policy.cancel_height)
            .ok_or("cold compensation window order")?;
        if let Some(maximum) = self.live_maximum_height {
            if span > 128
                || policy.collateral_confirmations > 64
                || self.dom[position]
                    .checked_add(span)
                    .and_then(|v| v.checked_add(128))
                    .is_none_or(|height| height > maximum)
            {
                return Err("live compensation/finality exceeds negotiated history window".into());
            }
        }
        if self.dom[position] < policy.cancel_height {
            return Err("cold negotiation cannot shorten availability".into());
        }
        policy.cancel_height = self.dom[position];
        policy.compensation_height = policy
            .cancel_height
            .checked_add(span)
            .ok_or("cold compensation height overflow")?;
        Ok(())
    }
}
