//! One fresh encrypted DOM wallet per actor, backed by mature local-chain
//! outputs. No XMR compensation policy exists on this route, so no payout
//! openings are seeded. No Contracts grant, reservation or T is created here.
use super::NativeSolColdStartV23;
use crate::production_config::ProductionPathRoleV1;
use dom_scriptless_chain_adapter::ScriptlessScanCursorV1;
use dom_wallet2::{Network, WalletV2State};
use std::os::unix::fs::PermissionsExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

impl NativeSolColdStartV23 {
    pub(crate) fn prepare_dom_wallet_v25(
        &self,
        actor: usize,
        resources: &super::NativeSolDaemonResourcesV23,
        snapshot: &super::xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23,
        passphrase: &[u8],
    ) -> Result<()> {
        let local = self.actor_id(actor)?;
        if resources.state_dir() != self.actor_work(actor)? {
            return Err("native wallet actor ownership mismatch".into());
        }
        let adapter = snapshot.adapter();
        let identity = adapter.expected_identity();
        if identity.network != "mainnet"
            || self
                .terms
                .iter()
                .any(|terms| terms.dom_leg.chain_id.0 != identity.chain_id)
        {
            return Err("native wallet requires exact DOM Mainnet identity".into());
        }
        // Slots 0/1 fund the two DOM legs at heights 1/2; slot 2 is the
        // independent solver collateral at height 3 (same baseline as XMR).
        let page = adapter.scan_page(ScriptlessScanCursorV1::genesis(), 4)?;
        let tip = page.identity.tip_height;
        if tip < dom_core::COINBASE_MATURITY + 3 {
            return Err("native wallet baseline coinbases are immature".into());
        }
        let require_observed_mature = |output: &dom_wallet2::StoredOutput| -> Result<()> {
            let block = output.origin_block.ok_or("native wallet missing origin")?;
            if !output.is_coinbase
                || tip
                    .checked_sub(block.height)
                    .is_none_or(|age| age < dom_core::COINBASE_MATURITY)
                || !page.blocks.iter().any(|observed| {
                    observed.height == block.height && observed.block_hash == block.hash
                })
            {
                return Err("native wallet output does not match the observed mature baseline".into());
            }
            Ok(())
        };
        let mut state = WalletV2State::new(Network::Mainnet, identity.chain_id);
        state.meta.last_reconciled_tip = tip;
        for (position, terms) in self.terms.iter().enumerate() {
            // The DOM leg funder is its refund recipient in the frozen terms.
            if local == terms.dom_leg.refund_to.0 {
                let output = snapshot.take_baseline_wallet_input_v23(position)?;
                require_observed_mature(&output)?;
                state.outputs.insert(output)?;
            }
        }
        let rosters = self.roster_bundle()?;
        let solver = rosters.legs()[0]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .ok_or("native wallet solver role")?
            .participant_id;
        if local == solver.0 {
            let output = snapshot.take_solver_baseline_input_v23()?;
            require_observed_mature(&output)?;
            state.outputs.insert(output)?;
        }
        let path = resources
            .state_dir()
            .join(resources.paths().get(ProductionPathRoleV1::DomWallet));
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("native wallet destination already exists or is unavailable".into()),
        }
        let passphrase = std::str::from_utf8(passphrase)?;
        if passphrase.is_empty() {
            return Err("native wallet empty passphrase".into());
        }
        dom_wallet2::save_wallet_state(&state, &path, passphrase)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::File::open(&path)?.sync_all()?;
        std::fs::File::open(resources.state_dir())?.sync_all()?;
        Ok(())
    }
}
