//! Deadline arithmetic for a NEW cold-start negotiation, never a mutation of
//! an admitted live route. Increase heights; keep compensation windows intact.
use super::*;

pub(super) struct NativeDeadlinePlanV23 {
    dom: [u64; 2],
    xmr: [u64; 2],
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
        })
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
