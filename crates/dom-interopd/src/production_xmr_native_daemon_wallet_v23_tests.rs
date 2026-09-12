//! One fresh encrypted wallet per actor, backed by mature local-chain outputs.
//! No Contracts grant, reservation, graph signature, T or U is created here.
use super::NativeXmrColdStartV23;
use crate::production_config::ProductionPathRoleV1;
use dom_actuator::DomXmrPayoutKindV22 as Payout;
use dom_crypto::{pedersen::Commitment, BlindingFactor};
use dom_scriptless_chain_adapter::ScriptlessScanCursorV1;
use dom_wallet2::{Network, OutputOrigin, StoredOutput, WalletV2State};
use std::os::unix::fs::PermissionsExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

impl NativeXmrColdStartV23 {
    pub(crate) fn prepare_dom_wallet_v23(
        &self,
        actor: usize,
        resources: &super::NativeXmrDaemonResourcesV23,
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
        // This call verifies the real projection served by the local backend,
        // including the frozen genesis identity. The backend's private output
        // owner below moves each coinbase into at most one actor wallet.
        let page = adapter.scan_page(ScriptlessScanCursorV1::genesis(), 3)?;
        let tip = page.identity.tip_height;
        if tip < dom_core::COINBASE_MATURITY + 3 {
            return Err("native wallet baseline coinbases are immature".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut state = WalletV2State::new(Network::Mainnet, identity.chain_id);
        state.meta.last_reconciled_tip = tip;
        for (position, terms) in self.terms.iter().enumerate() {
            let encoded = self.compensation_policy(position)?;
            let policy =
                xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(&encoded)?;
            let policy = policy.validate_for(terms)?;
            let funds = local == policy.policy().dom_funder;
            let payouts = if funds {
                [Payout::ClaimChange, Payout::Refund]
            } else {
                [Payout::ClaimPrincipal, Payout::Compensation]
            };
            for payout in payouts {
                let (_, commitment, value) = payout.policy_payout(&policy);
                let tag = match payout {
                    Payout::ClaimPrincipal => 11,
                    Payout::ClaimChange => 12,
                    Payout::Refund => 13,
                    Payout::Compensation => 14,
                } + 16 * u8::try_from(position)?;
                let blind = BlindingFactor::from_bytes([tag; 32])?;
                if Commitment::commit(value, &blind).as_bytes() != &commitment {
                    return Err(
                        "native wallet payout opening differs from negotiated policy".into(),
                    );
                }
                // Unconfirmed payout openings are not funding inputs.
                state.outputs.insert(StoredOutput::new_unconfirmed(
                    commitment,
                    value,
                    *blind.as_bytes(),
                    OutputOrigin::ReceiveSlate,
                    false,
                    None,
                    now,
                ))?;
            }
            if funds {
                let output = snapshot.take_baseline_wallet_input_v23(position)?;
                let block = output.origin_block.ok_or("native wallet missing origin")?;
                if !output.is_coinbase
                    || tip
                        .checked_sub(block.height)
                        .is_none_or(|age| age < dom_core::COINBASE_MATURITY)
                    || !page.blocks.iter().any(|observed| {
                        observed.height == block.height && observed.block_hash == block.hash
                    })
                {
                    return Err(
                        "native wallet output does not match the observed mature baseline".into(),
                    );
                }
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
            let block = output.origin_block.ok_or("solver baseline origin")?;
            if !output.is_coinbase
                || tip
                    .checked_sub(block.height)
                    .is_none_or(|age| age < dom_core::COINBASE_MATURITY)
                || !page.blocks.iter().any(|observed| {
                    observed.height == block.height && observed.block_hash == block.hash
                })
            {
                return Err("solver funding differs from observed mature coinbase".into());
            }
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
