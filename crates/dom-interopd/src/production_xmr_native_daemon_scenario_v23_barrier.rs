//! Correlate real retained DOM bytes with immutable public Contracts records.
//! These parsers observe the daemon; they never open a signing Store or grant F7.
use super::*;
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionPathRoleV1,
    ProductionUniversalLegV11, PRODUCTION_CREATE_CONFIG_FILE_V11,
};
use dom_scriptless_store::{SessionPhaseV1, SessionRecordV1};
use kaystra_core::{terms::SettlementTermsV1, types::TimelockSpec};
use std::{collections::BTreeSet, io::Read, path::Path};

pub(super) struct NativeBarrierV23 {
    terms: [SettlementTermsV1; 2],
    external_funding: [[u8; 32]; 2],
    recovery_legs: Option<[RecoveryLegV23; 2]>,
    dom_advanced_to: u64,
    pub(super) xmr: XmrLedgerPumpV23,
}

impl NativeBarrierV23 {
    pub(super) fn arm(startup: &NativeMainnetStartupV23) -> Result<Self> {
        let plan = startup.planning(0)?;
        let terms = [
            plan.composition().upstream().clone(),
            plan.composition().downstream().clone(),
        ];
        let external_funding = [LegIdV1::Upstream, LegIdV1::Downstream]
            .map(|leg| plan.monero_session(leg).setup().funding_tx_hash());
        let xmr = XmrLedgerPumpV23::new(startup)?;
        startup.arm_dom_submission_barrier_v23()?;
        Ok(Self {
            terms,
            external_funding,
            recovery_legs: None,
            dom_advanced_to: 0,
            xmr,
        })
    }
}

pub(super) struct XmrLedgerPumpV23 {
    confirmations: u64,
    last_poll: Option<Instant>,
}

impl XmrLedgerPumpV23 {
    pub(super) fn new(startup: &NativeMainnetStartupV23) -> Result<Self> {
        let composition = startup.planning(0)?.composition();
        let confirmations = u64::from(
            composition
                .upstream()
                .counterparty_leg
                .finality
                .min_confirmations
                .max(
                    composition
                        .downstream()
                        .counterparty_leg
                        .finality
                        .min_confirmations,
                ),
        );
        if confirmations == 0 || confirmations > 4096 {
            return Err("scenario XMR finality bound".into());
        }
        Ok(Self {
            confirmations,
            last_poll: None,
        })
    }

    pub(super) fn pump(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        snapshots: &[&RouteSnapshotV1],
    ) -> Result<()> {
        if self
            .last_poll
            .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return Ok(());
        }
        self.last_poll = Some(Instant::now());
        let mut expected = Vec::new();
        for snapshot in snapshots {
            for actor in 0..2 {
                let coordinator = CoordinatorObserverV23::new(running.state_dir(actor)?)?;
                for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
                    for kind in [
                        ActionKindV1::Funding,
                        ActionKindV1::Claim,
                        ActionKindV1::Refund,
                    ] {
                        if let Some(action) = coordinator.poll(snapshot, leg, kind)? {
                            if action.xmr_dispatched {
                                expected.push(action);
                            }
                        }
                    }
                }
            }
        }
        let history = running.xmr_history_status_v23()?;
        let pool = history.pool_tx_hashes;
        if pool.len() > 32
            || pool.iter().any(|hash| *hash == [0; 32])
            || pool.iter().copied().collect::<BTreeSet<_>>().len() != pool.len()
        {
            return Err("scenario XMR pool bound or duplicate identity".into());
        }
        // A valid pool transaction with no durable scoped intent is NOT
        // confirmed. A later poll may find the committed intent; otherwise the
        // scenario times out, rather than confirming arbitrary pool contents.
        let include: Vec<_> = pool
            .into_iter()
            .filter(|hash| expected.iter().any(|action| action.matches_xmr(*hash)))
            .collect();
        if include.is_empty() {
            return Ok(());
        }
        let target = history
            .tip_height
            .checked_add(self.confirmations)
            .ok_or("scenario XMR height overflow")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        running.advance_xmr_history_v23(target, now, &include)?;
        Ok(())
    }

    fn advance_deadline(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        deadline: u64,
    ) -> Result<()> {
        let target = deadline
            .checked_add(self.confirmations)
            .ok_or("scenario deadline overflow")?;
        let history = running.xmr_history_status_v23()?;
        if target <= history.tip_height {
            return Ok(());
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        running.advance_xmr_history_v23(target, now, &[])?;
        self.last_poll = None;
        Ok(())
    }
}

impl FundingBarrierControlV23 for NativeBarrierV23 {
    fn wait_public_refund_v24(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
        timeout: Duration,
    ) -> Result<[u8; 32]> {
        require_unbuilt_refund_v24(snapshot, boundary)?;
        let position = if boundary.leg == LegIdV1::Upstream {
            0
        } else {
            1
        };
        let terms = &self.terms[position];
        let policy = self.recovery_legs.ok_or("recovery policies absent")?[position];
        let proposal = retained_public_proposal_v24(running, boundary, snapshot, terms)?;
        let started = Instant::now();
        loop {
            if running.processes[boundary.survivor].is_some() {
                return Err("XMR signer must remain stopped during public U observation".into());
            }
            running.require_running(1 - boundary.survivor)?;
            // No XMR pump here: there can be no survivor refund candidate yet.
            if !running.xmr_pool_v23()?.is_empty() {
                return Err("unexpected XMR candidate while only DOM U owner is running".into());
            }
            if let Some((identity, tip, blocks)) = running.public_dom_history_v24()? {
                if let Some(hash) = public_refund_in_history_v24(
                    &identity, &tip, &blocks, &proposal, boundary, policy,
                )? {
                    return Ok(hash);
                }
            }
            if started.elapsed() >= timeout {
                return Err("DOM U owner alone did not publish original final refund".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_retained_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        timeout: Duration,
    ) -> Result<FundingBoundaryV23> {
        let configs = [
            config(running.state_dir(0)?)?,
            config(running.state_dir(1)?)?,
        ];
        let mut recovery_legs = Vec::with_capacity(2);
        for position in 0..2 {
            let mut selected_policy = None;
            let mut funder = None;
            for actor in 0..2 {
                let fields = configs[actor]
                    .universal_v11()
                    .ok_or("scenario V11 legs absent")?;
                let value = leg_parameters(running.state_dir(actor)?, &fields.legs[position])?;
                let local: [u8; 32] =
                    serde_json::from_value(value["local_participant_id"].clone())?;
                let bytes: Vec<u8> = serde_json::from_value(value["compensation_policy"].clone())?;
                let policy =
                    xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(&bytes)?;
                policy.validate_for(&self.terms[position])?;
                if policy.to_bytes()? != bytes {
                    return Err("noncanonical recovery policy".into());
                }
                if let Some(previous) = &selected_policy {
                    if previous != &bytes {
                        return Err("actors disagree on signed recovery policy".into());
                    }
                }
                selected_policy = Some(bytes);
                if local == self.terms[position].counterparty_leg.refund_to.0 {
                    if funder.replace(actor).is_some() {
                        return Err("two actors claim one XMR funding owner".into());
                    }
                } else if local != self.terms[position].dom_leg.refund_to.0 {
                    return Err("recovery actor is absent from negotiated participant roles".into());
                }
            }
            let policy = xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(
                &selected_policy.ok_or("signed recovery policy absent")?,
            )?;
            let TimelockSpec::BlockHeight {
                value: xmr_deadline,
            } = self.terms[position].counterparty_leg.deadline
            else {
                return Err("native XMR recovery requires negotiated height deadline".into());
            };
            recovery_legs.push(RecoveryLegV23 {
                funder: funder.ok_or("XMR funding owner absent")?,
                cancel_height: policy.cancel_height,
                compensation_height: policy.compensation_height,
                bounded_compensation: policy.bounded_availability_v23.is_some(),
                reveal_safety_blocks: policy.reveal_safety_blocks,
                dom_confirmations: u64::from(
                    self.terms[position].dom_leg.finality.min_confirmations,
                ),
                xmr_deadline,
            });
        }
        self.recovery_legs = Some(
            recovery_legs
                .try_into()
                .map_err(|_| "two recovery policies required")?,
        );
        let mut route_observers = super::observers(running)?;
        let start = Instant::now();
        loop {
            for actor in 0..2 {
                running.require_running(actor)?;
                if let Some(snapshot) = route_observers[actor].poll()? {
                    if snapshot.aborted_unfunded
                        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
                    {
                        return Err(
                            "native funding barrier observed abort or premature secret exposure"
                                .into(),
                        );
                    }
                }
            }
            // DOM Funding signing requires the authenticated custody/readiness
            // votes, not XMR inclusion. Conversely XMR submission requires the
            // actual finalized DOM collateral. Never confirm XMR here to make
            // progress: doing so would conceal a DOM-first ordering deadlock.
            let history = running.xmr_history_status_v23()?;
            if self.external_funding.iter().any(|id| {
                history.pool_tx_hashes.contains(id)
                    || history
                        .transactions
                        .iter()
                        .any(|transaction| transaction.tx_hash == *id)
            }) {
                return Err("route XMR funding preceded the retained DOM funding boundary".into());
            }
            let pending = running.pending_dom_submissions_v23()?;
            for (hash, transaction) in &pending {
                if dom_scriptless_chain_adapter::canonical_transaction_hash_v1(transaction)?
                    != *hash
                {
                    return Err("pending DOM bytes differ from their canonical identity".into());
                }
                let mut matched = BTreeSet::new();
                for position in 0..2 {
                    let role = if position == 0 {
                        ProductionPathRoleV1::UpstreamContracts
                    } else {
                        ProductionPathRoleV1::DownstreamContracts
                    };
                    for actor in 0..2 {
                        let path = running
                            .state_dir(actor)?
                            .join(configs[actor].relative_path(role))
                            .join("session-artifacts")
                            .join(format!(
                                "{}.f7-v12-funding",
                                hex::encode(self.terms[position].session_id.0)
                            ));
                        let bytes = match read_optional(&path, 2 * 1024 * 1024)? {
                            Some(bytes) => bytes,
                            None => continue,
                        };
                        if committed_funding(&bytes, &self.terms[position])?
                            == transaction.as_slice()
                        {
                            matched.insert(position);
                        }
                    }
                }
                if matched.len() > 1 {
                    return Err("DOM funding is ambiguously attributed to two sessions".into());
                }
                if let Some(position) = matched.into_iter().next() {
                    // A unilateral route must stop before downstream funding
                    // becomes admissible (the reducer requires upstream Final).
                    // Pending DOM hash order must not select downstream first.
                    if position != 0 {
                        continue;
                    }
                    let survivor = self
                        .recovery_legs
                        .as_ref()
                        .ok_or("recovery policies absent")?[position]
                        .funder;
                    let Some(snapshot) = route_observers[survivor].poll()? else {
                        continue;
                    };
                    let Some(action) = CoordinatorObserverV23::new(running.state_dir(survivor)?)?
                        .poll(&snapshot, LegIdV1::Upstream, ActionKindV1::Funding)?
                    else {
                        continue;
                    };
                    if !action.matches_xmr(self.external_funding[position])
                        || action.dom_id != *hash
                    {
                        return Err(
                            "funding boundary differs from its canonical coordinator children"
                                .into(),
                        );
                    }
                    return Ok(FundingBoundaryV23 {
                        survivor,
                        leg: if position == 0 {
                            LegIdV1::Upstream
                        } else {
                            LegIdV1::Downstream
                        },
                        funding_transaction_id: self.external_funding[position],
                        funding_aggregate_id: action.aggregate_id,
                        dom_collateral_transaction_id: *hash,
                    });
                }
            }
            if start.elapsed() >= timeout {
                return Err("no pending DOM funding matched an actual Contracts commit".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn release_retained_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
    ) -> Result<()> {
        if !running
            .pending_dom_submissions_v23()?
            .iter()
            .any(|(id, _)| *id == boundary.dom_collateral_transaction_id)
        {
            return Err("retained native funding disappeared before inclusion".into());
        }
        running.release_dom_submissions_v23()
    }

    fn advance_recovery(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()> {
        let target = compensation_recovery_target_v23(
            snapshot,
            boundary.survivor,
            &self.funding_aggregates(running, snapshot, boundary.survivor)?,
            self.recovery_legs
                .as_ref()
                .ok_or("signed recovery policies absent")?,
            self.native_final_funding(running)?,
        )?;
        let Some((dom, xmr)) = target else {
            return Ok(());
        };
        // Repeat from fresh durable snapshots: a subsequently funded second
        // leg must not inherit the first leg's shorter horizon. Advancing local
        // synthetic history is not a policy rewrite or real mainnet mining.
        if dom > self.dom_advanced_to {
            running.advance_dom_height_v23(dom)?;
            self.dom_advanced_to = dom;
        }
        self.xmr.advance_deadline(running, xmr)
    }

    fn pump_expected_xmr(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()> {
        self.xmr.pump(running, &[snapshot])
    }

    fn advance_refund_window(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()> {
        let position = if boundary.leg == LegIdV1::Upstream {
            0
        } else {
            1
        };
        let policy = self
            .recovery_legs
            .as_ref()
            .ok_or("signed refund policy absent")?[position];
        require_refund_window_v23(
            snapshot,
            boundary,
            policy,
            self.native_final_funding(running)?[position],
        )?;
        if policy.cancel_height > self.dom_advanced_to {
            running.advance_dom_height_v23(policy.cancel_height)?;
            self.dom_advanced_to = policy.cancel_height;
        }
        self.xmr.advance_deadline(running, policy.xmr_deadline)
    }

    fn confirm_stopped_funding(
        &mut self,
        running: &mut NativeXmrRunningColdStartV23,
        boundary: &FundingBoundaryV23,
        snapshot: &RouteSnapshotV1,
    ) -> Result<()> {
        if boundary.leg != LegIdV1::Upstream
            || snapshot.downstream.has_open_funds()
            || snapshot.upstream.funding.progress() != ActionProgressV1::Committed
            || snapshot
                .upstream
                .funding
                .effect()
                .and_then(|effect| effect.expected_transaction_id)
                != Some(boundary.funding_aggregate_id)
        {
            return Err(
                "stopped funding confirmation requires its exact durable upstream broadcast".into(),
            );
        }
        let action = CoordinatorObserverV23::new(running.state_dir(boundary.survivor)?)?
            .replay_stopped(snapshot, boundary.leg, ActionKindV1::Funding)?
            .ok_or("stopped native funding plan absent")?;
        if !action.xmr_dispatched
            || !action.matches_xmr(boundary.funding_transaction_id)
            || action.dom_id != boundary.dom_collateral_transaction_id
        {
            return Err("stopped native funding identities differ from durable coordinator".into());
        }
        self.xmr.last_poll = None;
        self.xmr.pump(running, &[snapshot])?;
        if !self.native_final_funding(running)?[0] {
            return Err("stopped upstream funding lacks actual native history finality".into());
        }
        Ok(())
    }
}

impl NativeBarrierV23 {
    fn funding_aggregates(
        &self,
        running: &NativeXmrRunningColdStartV23,
        snapshot: &RouteSnapshotV1,
        actor: usize,
    ) -> Result<[[u8; 32]; 2]> {
        let observer = CoordinatorObserverV23::new(running.state_dir(actor)?)?;
        let mut aggregates = [[0; 32]; 2];
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            if let Some(action) = observer.poll(snapshot, leg, ActionKindV1::Funding)? {
                if !action.matches_xmr(self.external_funding[index]) {
                    return Err("coordinator XMR funding differs from negotiated candidate".into());
                }
                aggregates[index] = action.aggregate_id;
            }
        }
        Ok(aggregates)
    }
    fn native_final_funding(
        &self,
        running: &mut NativeXmrRunningColdStartV23,
    ) -> Result<[bool; 2]> {
        let history = running.xmr_history_status_v23()?;
        Ok(self.external_funding.map(|id| {
            history.transactions.iter().any(|transaction| {
                transaction.tx_hash == id
                    && transaction.block_height > 0
                    && history
                        .tip_height
                        .checked_sub(transaction.block_height)
                        .and_then(|depth| depth.checked_add(1))
                        .is_some_and(|depth| depth >= self.xmr.confirmations)
            })
        }))
    }
}

#[derive(Clone, Copy)]
struct RecoveryLegV23 {
    funder: usize,
    cancel_height: u64,
    compensation_height: u64,
    bounded_compensation: bool,
    reveal_safety_blocks: u64,
    dom_confirmations: u64,
    xmr_deadline: u64,
}

fn require_refund_window_v23(
    snapshot: &RouteSnapshotV1,
    boundary: &FundingBoundaryV23,
    policy: RecoveryLegV23,
    native_final: bool,
) -> Result<()> {
    let leg = selected(snapshot, boundary.leg);
    let other = selected(
        snapshot,
        if boundary.leg == LegIdV1::Upstream {
            LegIdV1::Downstream
        } else {
            LegIdV1::Upstream
        },
    );
    if snapshot.aborted_unfunded
        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
        || policy.funder != boundary.survivor
        || other.has_open_funds()
        || !native_final
        || leg.funding.progress() == ActionProgressV1::NotPrepared
        || leg
            .funding
            .effect()
            .and_then(|effect| effect.expected_transaction_id)
            != Some(boundary.funding_aggregate_id)
        || leg.claim.progress() != ActionProgressV1::NotPrepared
        || leg.dom_compensation_v12.is_some()
        || policy.dom_confirmations == 0
        || policy.reveal_safety_blocks == 0
        || policy
            .dom_confirmations
            .checked_mul(2)
            .and_then(|blocks| policy.cancel_height.checked_add(blocks))
            .and_then(|height| height.checked_add(policy.reveal_safety_blocks))
            .is_none_or(|height| height >= policy.compensation_height)
    {
        return Err(
            "refund requires actual unilateral funding and the original safe U window".into(),
        );
    }
    Ok(())
}

fn compensation_recovery_target_v23(
    snapshot: &RouteSnapshotV1,
    survivor: usize,
    funding: &[[u8; 32]; 2],
    policies: &[RecoveryLegV23; 2],
    native_final: [bool; 2],
) -> Result<Option<(u64, u64)>> {
    if survivor > 1
        || snapshot.aborted_unfunded
        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
    {
        return Err("invalid noncooperative recovery observation".into());
    }
    let mut target: Option<(u64, u64)> = None;
    for (position, leg) in [&snapshot.upstream, &snapshot.downstream]
        .into_iter()
        .enumerate()
    {
        if !leg.has_open_funds()
            || !native_final[position]
            || leg.funding.progress() == ActionProgressV1::NotPrepared
        {
            continue;
        }
        if funding[position] == [0; 32]
            || leg
                .funding
                .effect()
                .and_then(|effect| effect.expected_transaction_id)
                != Some(funding[position])
        {
            return Err("durable funding does not match the negotiated XMR candidate".into());
        }
        let policy = policies[position];
        if policy.funder != survivor {
            // This owner may reveal its private DOM refund U, but cannot sign
            // the absent XMR funder's sweep. Advancing more blocks cannot mint
            // that role. Keep the both-legs/no-open-funds success gate intact.
            return Err("another funded XMR leg requires the absent refund owner; deadline advancement cannot close it".into());
        }
        if !policy.bounded_compensation
            || policy.cancel_height >= policy.compensation_height
            || policy.compensation_height >= 4096
            || policy.xmr_deadline > 1_000_000
        {
            return Err("signed compensation policy unsupported by bounded local history".into());
        }
        let (dom, xmr) = target.unwrap_or((0, 0));
        target = Some((
            dom.max(policy.compensation_height),
            xmr.max(policy.xmr_deadline),
        ));
    }
    Ok(target)
}

fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let file = super::observer::owned_file(path)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("scenario public artifact bound".into());
    }
    Ok(Some(bytes))
}

/// Equality evidence only: no private file bytes or digests leave this process.
/// Both before/after inventories are taken with the owning daemon reaped.
type StoppedStateInventoryV24 = Vec<(std::path::PathBuf, [u8; 32])>;

pub(super) fn stopped_inventory_v24(root: &Path) -> Result<StoppedStateInventoryV24> {
    use std::os::unix::fs::FileTypeExt;
    let mut pending = vec![root.to_path_buf()];
    let mut result = Vec::new();
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        if result.len() + pending.len() > 8192 {
            return Err("stopped-state inventory count bound".into());
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("stopped-state inventory refuses links".into());
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
            result.push((path.strip_prefix(root)?.to_path_buf(), [0; 32]));
        } else if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or("inventory size overflow")?;
            if total > 512 * 1024 * 1024 || metadata.len() > 64 * 1024 * 1024 {
                return Err("stopped-state inventory byte bound".into());
            }
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            super::observer::owned_file(&path)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != metadata.len() {
                return Err("stopped-state file changed during inventory".into());
            }
            result.push((
                path.strip_prefix(root)?.to_path_buf(),
                *dom_crypto::blake2b_256(&bytes).as_bytes(),
            ));
        } else if metadata.file_type().is_socket() {
            result.push((path.strip_prefix(root)?.to_path_buf(), [1; 32]));
        } else {
            return Err("stopped-state inventory special file refused".into());
        }
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(result)
}

fn retained_public_proposal_v24(
    running: &NativeXmrRunningColdStartV23,
    boundary: &FundingBoundaryV23,
    snapshot: &RouteSnapshotV1,
    terms: &SettlementTermsV1,
) -> Result<[u8; 704]> {
    let role = if boundary.leg == LegIdV1::Upstream {
        ProductionPathRoleV1::UpstreamContracts
    } else {
        ProductionPathRoleV1::DownstreamContracts
    };
    let position = if boundary.leg == LegIdV1::Upstream {
        0
    } else {
        1
    };
    let mut agreed = None;
    for actor in 0..2 {
        let state = running.state_dir(actor)?;
        let config = config(state)?;
        let path = state
            .join(config.relative_path(role))
            .join("session-rosters")
            .join(format!(
                "{}.xmr-graph-pin-v23",
                hex::encode(terms.session_id.0)
            ));
        let pin = read_optional(&path, 808)?.ok_or("original public graph pin absent")?;
        let proposal = decode_public_pin_v24(&pin)?;
        let fields = config
            .universal_v11()
            .ok_or("original universal legs absent")?;
        let parameters = leg_parameters(state, &fields.legs[position])?;
        let bytes: Vec<u8> = serde_json::from_value(parameters["compensation_policy"].clone())?;
        let policy = xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(&bytes)?;
        policy.validate_for(terms)?;
        if proposal[40..72] != snapshot.route_id
            || proposal[72..104] != terms.session_id.0
            || proposal[104..136] != terms.terms_hash()?
            || proposal[136..168] != terms.roster[0].0
            || proposal[168..200] != terms.roster[1].0
            || proposal[672..704] != policy.policy_hash()?
            || proposal[624..632] != policy.cancel_height.to_le_bytes()
            || proposal[632..640] != policy.compensation_height.to_le_bytes()
            || proposal[640..648] != policy.reveal_safety_blocks.to_le_bytes()
            || agreed
                .as_ref()
                .is_some_and(|previous| previous != &proposal)
        {
            return Err(
                "original graph pin disagrees with route, actors or negotiated policy".into(),
            );
        }
        agreed = Some(proposal);
    }
    agreed.ok_or_else(|| "public graph agreement absent".into())
}

fn decode_public_pin_v24(pin: &[u8]) -> Result<[u8; 704]> {
    if pin.len() != 808
        || &pin[..8] != b"DXGPIN23"
        || &pin[8..16] != b"DXGP22\0\x01"
        || dom_crypto::blake2b_256_tagged("DOM:local-xmr-graph-pin:v23", &pin[..776]).as_bytes()
            != &pin[776..]
        || pin[712..744] == [0; 32]
        || pin[744..776] == [0; 32]
    {
        return Err("public graph pin framing/integrity".into());
    }
    // This is only a scope pin, NOT an authenticated graph or authority token.
    Ok(pin[8..712].try_into()?)
}

/// Independent public observation against the original funded graph. The
/// accessor supplies only the actual native-validated local ledger, not caller
/// invented transactions. Full header linkage and exact native bytes are still
/// checked here. No scalar is extracted and no production token is minted.
fn public_refund_in_history_v24(
    identity: &dom_scriptless_chain_adapter::ExpectedDomIdentityV1,
    tip: &serde_json::Value,
    blocks: &[serde_json::Value],
    proposal: &[u8; 704],
    boundary: &FundingBoundaryV23,
    policy: RecoveryLegV23,
) -> Result<Option<[u8; 32]>> {
    use dom_serialization::{DomDeserialize, DomSerialize};
    let hash = |value: &serde_json::Value| -> Result<[u8; 32]> {
        Ok(hex::decode(value.as_str().ok_or("public hash absent")?)?
            .try_into()
            .map_err(|_| "public hash length")?)
    };
    identity.validate()?;
    let height = tip["tip_height"].as_u64().ok_or("public tip height")?;
    if height >= 4096
        || blocks.len() != usize::try_from(height + 1)?
        || proposal[8..40] != identity.chain_id
        || hash(&tip["chain_id"])? != identity.chain_id
        || hash(&tip["genesis_hash"])? != identity.genesis_hash
        || tip["network"].as_str() != Some(identity.network.as_str())
        || tip["protocol_version"].as_u64() != Some(u64::from(identity.protocol_version))
        || tip["range_proof_serialization_version"].as_u64()
            != Some(u64::from(identity.range_proof_serialization_version))
        || tip["network_magic"].as_u64() != Some(u64::from(identity.network_magic))
        || policy.dom_confirmations == 0
    {
        return Err("public history graph/chain/bound mismatch".into());
    }
    let mut previous = [0; 32];
    let mut events = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, block) in blocks.iter().enumerate() {
        let h = index as u64;
        let bytes = hex::decode(
            block["canonical_header_bytes"]
                .as_str()
                .ok_or("public header absent")?,
        )?;
        let header = dom_consensus::BlockHeader::from_bytes(&bytes)?;
        let id =
            *dom_chain::canonical_header_identifier(identity.network_magic, &bytes)?.as_bytes();
        if header.to_bytes()? != bytes
            || header.height.0 != h
            || header.prev_hash.as_bytes() != &previous
            || hash(&block["previous_block_hash"])? != previous
            || block["timestamp"].as_u64() != Some(header.timestamp.0)
            || block["height"].as_u64() != Some(h)
            || hash(&block["block_hash"])? != id
            || hash(&block["canonical_marker"])? != id
            || (h == 0 && id != identity.genesis_hash)
        {
            return Err("public history ancestry or canonical header mismatch".into());
        }
        previous = id;
        for (position, tx) in block["transactions"]
            .as_array()
            .ok_or("public transactions absent")?
            .iter()
            .enumerate()
        {
            let bytes = hex::decode(
                tx["canonical_bytes"]
                    .as_str()
                    .ok_or("public transaction absent")?,
            )?;
            let transaction = dom_consensus::Transaction::from_bytes(&bytes)?;
            let txid = dom_scriptless_chain_adapter::canonical_transaction_hash_v1(&bytes)?;
            if !seen.insert(txid)
                || txid != hash(&tx["tx_hash"])?
                || tx["block_height"].as_u64() != Some(h)
                || hash(&tx["block_hash"])? != id
                || tx["transaction_index"].as_u64() != Some(position as u64)
            {
                return Err("public transaction duplicate/location mismatch".into());
            }
            let template = dom_adaptor::canonical_template_v1(&transaction)?.1;
            // Native proposal template order: funding, claim, cancel, refund, compensation.
            let stage =
                (0..5).find(|stage| proposal[266 + stage * 32..298 + stage * 32] == template);
            if let Some(stage) = stage {
                events.push((stage, h, txid));
            }
            // No unknown transaction may spend C or D, even if a pinned refund
            // exists elsewhere. The native ledger already rejects double spends.
            for input in &transaction.inputs {
                if (input.commitment.as_bytes() == &proposal[426..459]
                    || input.commitment.as_bytes() == &proposal[459..492])
                    && !matches!(stage, Some(1..=4))
                {
                    return Err("unrecognized spend of original graph".into());
                }
            }
        }
    }
    if previous != hash(&tip["tip_hash"])? {
        return Err("public history tip mismatch".into());
    }
    require_public_refund_edges_v24(&events, height, boundary, policy)
}

fn require_public_refund_edges_v24(
    events: &[(usize, u64, [u8; 32])],
    height: u64,
    boundary: &FundingBoundaryV23,
    policy: RecoveryLegV23,
) -> Result<Option<[u8; 32]>> {
    if policy.dom_confirmations == 0
        || events
            .iter()
            .any(|event| event.1 > height || event.2 == [0; 32])
    {
        return Err("public graph event outside observed chain/policy".into());
    }
    let funding: Vec<_> = events.iter().filter(|event| event.0 == 0).collect();
    if funding.len() != 1 || funding[0].2 != boundary.dom_collateral_transaction_id {
        return Err("public history does not contain the original exact DOM collateral".into());
    }
    if events.iter().any(|event| event.0 == 1 || event.0 == 4) {
        return Err("original graph was claimed or compensated instead of revealing U".into());
    }
    let cancel: Vec<_> = events.iter().filter(|event| event.0 == 2).collect();
    let refund: Vec<_> = events.iter().filter(|event| event.0 == 3).collect();
    if cancel.len() > 1 || refund.len() > 1 {
        return Err("duplicate original graph edge".into());
    }
    let (Some(cancel), Some(refund)) = (cancel.first(), refund.first()) else {
        return Ok(None);
    };
    if funding[0].1 >= cancel.1
        || cancel.1 >= refund.1
        || cancel.1 < policy.cancel_height
        || refund.1 >= policy.compensation_height
        || refund.2 == boundary.dom_collateral_transaction_id
    {
        return Err("original graph refund order/window mismatch".into());
    }
    if height - refund.1 + 1 < policy.dom_confirmations {
        return Ok(None);
    }
    Ok(Some(refund.2))
}

fn config(state: &Path) -> Result<ProductionBootstrapConfigV1> {
    let bytes = read_optional(&state.join(PRODUCTION_CREATE_CONFIG_FILE_V11), 65536)?
        .ok_or("scenario config absent")?;
    Ok(ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
        &bytes,
        ProductionBootstrapModeV1::Create,
    )?)
}

fn leg_parameters(state: &Path, leg: &ProductionUniversalLegV11) -> Result<serde_json::Value> {
    let bytes = read_optional(&state.join(&leg.authority_bundle), 1024 * 1024)?
        .ok_or("scenario leg absent")?;
    if ProductionUniversalLegV11::bundle_digest(&bytes)? != leg.authority_bundle_digest {
        return Err("scenario leg digest differs from manifest".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value["family"] != "XMR_ENROLLMENT_V23" {
        return Err("scenario leg family mismatch".into());
    }
    Ok(value["parameters"].clone())
}

fn committed_funding<'a>(bytes: &'a [u8], terms: &SettlementTermsV1) -> Result<&'a [u8]> {
    if bytes.len() < 120
        || bytes.len() > 2 * 1024 * 1024
        || &bytes[..8] != b"DOMFFC12"
        || dom_crypto::blake2b_256_tagged(
            "DOM-INTEROP/F7-FUNDING-COMMIT/V12\0",
            &bytes[..bytes.len() - 32],
        )
        .as_bytes()
            != &bytes[bytes.len() - 32..]
        || bytes[8..40] == [0; 32]
        || bytes[40..72] == [0; 32]
        || u64::from_le_bytes(bytes[72..80].try_into()?) == 0
    {
        return Err("scenario native funding commit integrity mismatch".into());
    }
    let mut cursor = 80;
    let funding = blob(bytes, &mut cursor)?;
    let successor = SessionRecordV1::from_bytes(blob(bytes, &mut cursor)?)?;
    if cursor + 32 != bytes.len()
        || successor.session_id() != terms.session_id.0
        || successor.terms_hash() != terms.terms_hash()?
        || successor.phase() != SessionPhaseV1::FundingBroadcast
        || !successor.irreversible().funding_authorized
        || successor.irreversible().adaptor_secret_exposed
    {
        return Err("scenario native funding commit session or phase mismatch".into());
    }
    Ok(funding)
}

fn blob<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let header = cursor.checked_add(4).ok_or("scenario blob overflow")?;
    let length = u32::from_le_bytes(
        bytes
            .get(*cursor..header)
            .ok_or("scenario blob header")?
            .try_into()?,
    ) as usize;
    let end = header
        .checked_add(length)
        .ok_or("scenario blob length overflow")?;
    if end > bytes.len().saturating_sub(32) {
        return Err("scenario blob exceeds committed payload".into());
    }
    *cursor = end;
    Ok(&bytes[header..end])
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    use route_executor::{ActionStateV1, EffectReferenceV1};

    #[test]
    fn public_pin_parser_refuses_checksum_truncation_and_zero_proof() -> Result<()> {
        // Framing fixture only; the parser does not mint graph authority.
        let mut pin = vec![1u8; 808];
        pin[..8].copy_from_slice(b"DXGPIN23");
        pin[8..16].copy_from_slice(b"DXGP22\0\x01");
        let checksum =
            *dom_crypto::blake2b_256_tagged("DOM:local-xmr-graph-pin:v23", &pin[..776]).as_bytes();
        pin[776..].copy_from_slice(&checksum);
        assert_eq!(decode_public_pin_v24(&pin)?.as_slice(), &pin[8..712]);
        assert!(decode_public_pin_v24(&pin[..807]).is_err());
        let mut trailing = pin.clone();
        trailing.push(0);
        assert!(decode_public_pin_v24(&trailing).is_err());
        pin[300] ^= 1;
        assert!(decode_public_pin_v24(&pin).is_err());
        pin[712..744].fill(0);
        let checksum =
            *dom_crypto::blake2b_256_tagged("DOM:local-xmr-graph-pin:v23", &pin[..776]).as_bytes();
        pin[776..].copy_from_slice(&checksum);
        assert!(decode_public_pin_v24(&pin).is_err());
        Ok(())
    }

    #[test]
    fn public_u_handoff_requires_original_refund_depth_and_order() -> Result<()> {
        let boundary = FundingBoundaryV23 {
            survivor: 0,
            leg: LegIdV1::Upstream,
            funding_transaction_id: [9; 32],
            funding_aggregate_id: [19; 32],
            dom_collateral_transaction_id: [10; 32],
        };
        let policy = policies()[0];
        let events = [(0, 100, [10; 32]), (2, 2001, [11; 32]), (3, 2004, [12; 32])];
        assert_eq!(
            require_public_refund_edges_v24(&events, 2005, &boundary, policy)?,
            None
        );
        assert_eq!(
            require_public_refund_edges_v24(&events, 2006, &boundary, policy)?,
            Some([12; 32])
        );
        assert_eq!(
            require_public_refund_edges_v24(&events[..2], 2006, &boundary, policy)?,
            None
        );
        for mutation in [
            [(0, 100, [13; 32]), events[1], events[2]],
            [events[0], (2, 1999, [11; 32]), events[2]],
            [events[0], (2, 2005, [11; 32]), events[2]],
            [events[0], events[1], (3, 2030, [12; 32])],
            [events[0], events[1], (4, 2004, [12; 32])],
        ] {
            assert!(require_public_refund_edges_v24(&mutation, 2032, &boundary, policy).is_err());
        }
        let mut duplicate = events.to_vec();
        duplicate.push(events[2]);
        assert!(require_public_refund_edges_v24(&duplicate, 2006, &boundary, policy).is_err());
        assert!(require_public_refund_edges_v24(&events, 2003, &boundary, policy).is_err());
        Ok(())
    }

    #[test]
    fn stopped_inventory_refuses_links_instead_of_following_private_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::os::unix::fs::symlink("/not/a/scenario/file", root.path().join("link"))?;
        assert!(stopped_inventory_v24(root.path()).is_err());
        Ok(())
    }

    fn final_funding(id: [u8; 32]) -> ActionStateV1 {
        ActionStateV1::Final {
            effect: EffectReferenceV1 {
                effect_id: [1; 32],
                fencing_epoch: 1,
                semantic_digest: [2; 32],
                contains_route_secret: false,
                expected_transaction_id: Some(id),
            },
            transaction_id: id,
            evidence_digest: [3; 32],
        }
    }

    fn policies() -> [RecoveryLegV23; 2] {
        [
            RecoveryLegV23 {
                funder: 0,
                cancel_height: 2000,
                compensation_height: 2030,
                bounded_compensation: true,
                reveal_safety_blocks: 10,
                dom_confirmations: 3,
                xmr_deadline: 300_700,
            },
            RecoveryLegV23 {
                funder: 0,
                cancel_height: 1100,
                compensation_height: 1130,
                bounded_compensation: true,
                reveal_safety_blocks: 10,
                dom_confirmations: 3,
                xmr_deadline: 100_200,
            },
        ]
    }

    #[test]
    fn later_funded_longer_leg_extends_recovery_to_its_original_signed_horizon() -> Result<()> {
        let funding = [[9; 32], [10; 32]];
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        snapshot.downstream.funding = final_funding(funding[1]);
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [true; 2])?,
            Some((1130, 100_200))
        );
        snapshot.upstream.funding = final_funding(funding[0]);
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [true; 2])?,
            Some((2030, 300_700))
        );
        Ok(())
    }

    #[test]
    fn untouched_and_unconfirmed_legs_cannot_be_promoted_to_funding_by_clock_control() -> Result<()>
    {
        let funding = [[9; 32], [10; 32]];
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [false; 2])?,
            None
        );
        let ActionStateV1::Final { effect, .. } = final_funding(funding[0]) else {
            unreachable!()
        };
        snapshot.upstream.funding = ActionStateV1::Committed(effect);
        assert!(snapshot.has_open_funds());
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [false; 2])?,
            None
        );
        assert_eq!(
            snapshot.upstream.funding.progress(),
            ActionProgressV1::Committed
        );
        Ok(())
    }

    #[test]
    fn absent_other_funder_is_a_real_authority_blocker_not_a_closed_route() -> Result<()> {
        let funding = [[9; 32], [10; 32]];
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        snapshot.upstream.funding = final_funding(funding[0]);
        snapshot.downstream.funding = final_funding(funding[1]);
        let mut negotiated = policies();
        negotiated[1].funder = 1;
        assert!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &negotiated, [true; 2])
                .is_err()
        );
        assert!(snapshot.upstream.has_open_funds());
        assert!(snapshot.downstream.has_open_funds());
        Ok(())
    }

    #[test]
    fn compensation_schedule_rejects_wrong_funding_or_unnegotiated_availability() -> Result<()> {
        let funding = [[9; 32], [10; 32]];
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        snapshot.upstream.funding = final_funding([11; 32]);
        assert!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [true; 2])
                .is_err()
        );
        snapshot.upstream.funding = final_funding(funding[0]);
        let mut negotiated = policies();
        negotiated[0].bounded_compensation = false;
        assert!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &negotiated, [true; 2])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn offline_native_finality_can_age_history_without_fabricating_route_final() -> Result<()> {
        let funding = [[9; 32], [10; 32]];
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        let ActionStateV1::Final { effect, .. } = final_funding(funding[0]) else {
            unreachable!()
        };
        snapshot.upstream.funding = ActionStateV1::Committed(effect);
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [false; 2])?,
            None
        );
        assert_eq!(
            compensation_recovery_target_v23(&snapshot, 0, &funding, &policies(), [true, false])?,
            Some((2030, 300_700))
        );
        assert_eq!(
            snapshot.upstream.funding.progress(),
            ActionProgressV1::Committed
        );
        assert_eq!(
            snapshot.downstream.funding.progress(),
            ActionProgressV1::NotPrepared
        );
        Ok(())
    }

    #[test]
    fn refund_window_requires_native_funding_and_preserves_signed_reveal_safety() -> Result<()> {
        let mut snapshot = RouteSnapshotV1::new([4; 32])?;
        let boundary = FundingBoundaryV23 {
            survivor: 0,
            leg: LegIdV1::Upstream,
            funding_transaction_id: [9; 32],
            funding_aggregate_id: [19; 32],
            dom_collateral_transaction_id: [10; 32],
        };
        snapshot.upstream.funding = final_funding(boundary.funding_aggregate_id);
        let policy = policies()[0];
        assert!(require_refund_window_v23(&snapshot, &boundary, policy, true).is_ok());
        assert!(require_refund_window_v23(&snapshot, &boundary, policy, false).is_err());
        let mut short = policy;
        short.compensation_height =
            short.cancel_height + 2 * short.dom_confirmations + short.reveal_safety_blocks;
        assert!(require_refund_window_v23(&snapshot, &boundary, short, true).is_err());
        snapshot.downstream.funding = final_funding([11; 32]);
        assert!(require_refund_window_v23(&snapshot, &boundary, policy, true).is_err());
        Ok(())
    }
}
