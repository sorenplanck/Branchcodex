//! Continuation of the SAME noncooperative round, not another ceremony. The
//! peer receives the original refund through real DSC1/Relay after a cold
//! sidecar restart with its encrypted signing plan retired recoverably.
//! Public Ready bytes are observations here; only the daemon authenticates
//! their MAC, native U, quorum, input, rings and payout before import.
use super::*;
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionPathRoleV1,
    PRODUCTION_CREATE_CONFIG_FILE_V11,
};
use dom_scriptless_store::{
    BudgetPolicyV1, ContractsSessionStoreV1, SessionTransportIdentityReferenceV1,
};
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use xmr_live_sidecar_api::{BuildSweepResponseV2, LocalRefundBuildResponseV24};
use xmr_remote_sweep_wire::{RemoteSweepActionV23, RemoteSweepRequestV23, RemoteSweepResponseV23};

type Build = LocalRefundBuildResponseV24<BuildSweepResponseV2>;
const CACHE_DIRECTORY: &str = "local-refund-build-proofs-v24";
const MAX_READY: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    scope: Vec<u8>,
    response: Build,
    tag: [u8; 32],
}

struct RetiredPlan {
    root: PathBuf,
    plan: PathBuf,
    retired: PathBuf,
    dev: u64,
    ino: u64,
    plan_digest: [u8; 32],
    inventory: BTreeMap<String, [u8; 32]>,
    response: Build,
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let held = observer::owned_file(path)?;
    let before = held.metadata()?;
    let mut bytes = Vec::new();
    held.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if bytes.len() > maximum || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("publication artifact changed inode or exceeded bound".into());
    }
    Ok(bytes)
}

fn owned_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err("publication cache directory is not private and owned".into());
    }
    Ok(())
}

fn inventory(path: &Path) -> Result<BTreeMap<String, [u8; 32]>> {
    owned_directory(path)?;
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        if files.len() >= 64 {
            return Err("publication cache inventory exceeded bound".into());
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 cache artifact")?;
        let bytes = read(&entry.path(), MAX_READY)?;
        files.insert(name, *dom_crypto::blake2b_256(&bytes).as_bytes());
    }
    Ok(files)
}

impl RetiredPlan {
    fn retire(
        cache: &Path,
        snapshot: &RouteSnapshotV1,
        leg: LegIdV1,
        native: NativeActionV23,
        funding_hash: [u8; 32],
        refund_hash: [u8; 32],
    ) -> Result<Self> {
        owned_directory(cache)?;
        let root = cache.join(CACHE_DIRECTORY);
        let effect = snapshot
            .leg(leg)
            .refund
            .effect()
            .ok_or("original refund effect absent")?;
        let nonce = hex::encode(effect.effect_id);
        let plan = root.join(format!("{nonce}.plan"));
        let ready: Ready =
            serde_json::from_slice(&read(&root.join(format!("{nonce}.ready")), MAX_READY)?)?;
        let context = ready.response.validate_framing()?;
        ready.response.sweep.validate_for(&effect.effect_id)?;
        let request = &ready.response.public_scope.request;
        if ready.scope != ready.response.public_scope.canonical_bytes()?
            || ready.tag == [0; 32]
            || request.route != snapshot.route_id
            || request.effect_id != effect.effect_id
            || request.fencing_epoch != effect.fencing_epoch
            || request.semantic_digest != effect.semantic_digest
            || request.funding_tx_hash != funding_hash
            || ready.response.sweep.tx_hash != refund_hash
            || !native.matches_xmr(refund_hash)
            || context.sweep_tx != refund_hash
            || read(&root.join(format!("{nonce}.scope")), 32)? != ready.response.cache_request_hash
            || read(&root.join(format!("{nonce}.issued")), 32)?.len() != 32
        {
            return Err("Ready differs from original native refund/effect".into());
        }
        let mut inventory = inventory(&root)?;
        let plan_digest = inventory
            .remove(&format!("{nonce}.plan"))
            .ok_or("original private plan absent")?;
        let meta = observer::owned_file(&plan)?.metadata()?;
        let parent = cache.parent().ok_or("cache has no owned parent")?;
        owned_directory(parent)?;
        let retired = parent.join(format!("retired-local-refund-v24-{nonce}.plan"));
        // Atomic no-overwrite rename of one exact validated ciphertext. No
        // secret/share deletion; evidence remains recoverable outside lookup.
        let source_directory = fs::File::open(&root)?;
        let target_directory = fs::File::open(parent)?;
        rustix::fs::renameat_with(
            &source_directory,
            plan.file_name().ok_or("plan file name absent")?,
            &target_directory,
            retired.file_name().ok_or("retired plan file name absent")?,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        fs::File::open(&root)?.sync_all()?;
        fs::File::open(parent)?.sync_all()?;
        let checkpoint = Self {
            root,
            plan,
            retired,
            dev: meta.dev(),
            ino: meta.ino(),
            plan_digest,
            inventory,
            response: ready.response,
        };
        checkpoint.require_unchanged(cache)?;
        Ok(checkpoint)
    }

    fn require_unchanged(&self, cache: &Path) -> Result<()> {
        if cache.join(CACHE_DIRECTORY) != self.root || inventory(&self.root)? != self.inventory {
            return Err("LOAD recreated a plan or changed original Ready/cache records".into());
        }
        match fs::symlink_metadata(&self.plan) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("private local plan was recreated".into()),
        }
        let held = observer::owned_file(&self.retired)?;
        let meta = held.metadata()?;
        if (meta.dev(), meta.ino()) != (self.dev, self.ino)
            || *dom_crypto::blake2b_256(&read(&self.retired, 256 * 1024 + 64)?).as_bytes()
                != self.plan_digest
        {
            return Err("retired private plan evidence changed".into());
        }
        Ok(())
    }
}

struct Actor {
    config: ProductionBootstrapConfigV1,
    state: PathBuf,
    position: usize,
    chain: dom_adaptor::TrustedChainIdV1,
}
impl Actor {
    fn new(state: &Path, position: usize, chain: dom_adaptor::TrustedChainIdV1) -> Result<Self> {
        let config = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &read(&state.join(PRODUCTION_CREATE_CONFIG_FILE_V11), 65536)?,
            ProductionBootstrapModeV1::Create,
        )?;
        Ok(Self {
            config,
            state: state.to_owned(),
            position,
            chain,
        })
    }
    fn session(&self) -> Result<[u8; 32]> {
        Ok(self
            .config
            .universal_v11()
            .ok_or("universal legs absent")?
            .legs[self.position]
            .session_id)
    }
    fn open_stopped(&self) -> Result<ContractsSessionStoreV1> {
        let role = if self.position == 0 {
            ProductionPathRoleV1::UpstreamContracts
        } else {
            ProductionPathRoleV1::DownstreamContracts
        };
        let path = self.state.join(self.config.relative_path(role));
        let budget = BudgetPolicyV1::from_bytes(&read(
            &self.state.join(
                self.config
                    .contracts_budget_policy()
                    .ok_or("budget absent")?,
            ),
            1024 * 1024,
        )?)?;
        Ok(
            ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                Arc::new(cap_std::fs::Dir::from_std_file(fs::File::open(
                    path.parent().ok_or("contracts parent absent")?,
                )?)),
                path.file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("contracts name encoding")?,
                budget,
                self.chain,
            )?,
        )
    }
    fn retained_native_refund(&self, expected: &Build) -> Result<()> {
        let leg = &self
            .config
            .universal_v11()
            .ok_or("universal legs absent")?
            .legs[self.position];
        let store = xmr_actuator::XmrOperationStoreV1::open_existing_production(
            &self.state.join(&leg.actuator_store),
        )?;
        let locator = xmr_actuator::XmrOperationLocatorV1 {
            settlement_id: leg.settlement_id,
            kind: xmr_actuator::XmrOperationKindV1::Refund,
        };
        let view = store.view(locator)?;
        if view.tx_hash != expected.sweep.tx_hash
            || view.finality.is_none()
            || store.retained_transaction(locator)? != expected.sweep.raw_tx
        {
            return Err("native actuator did not retain the original final refund".into());
        }
        Ok(())
    }
    /// Read-only observation of the real durable sender. Store replay below
    /// subsequently proves sender-local authority and paired transcript state.
    fn pending_request(
        &self,
        refs: &[SessionTransportIdentityReferenceV1; 2],
        expected: &Build,
    ) -> Result<Option<SignedMessageV1>> {
        let role = if self.position == 0 {
            ProductionPathRoleV1::UpstreamRelaySender
        } else {
            ProductionPathRoleV1::DownstreamRelaySender
        };
        let path = self
            .state
            .join(self.config.relative_path(role))
            .join("route-sender-v1.sqlite3");
        let held = observer::owned_file(&path)?;
        let meta = held.metadata()?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(500))?;
        let after = fs::symlink_metadata(&path)?;
        if (meta.dev(), meta.ino()) != (after.dev(), after.ino()) {
            return Err("sender inode changed".into());
        }
        let transaction = connection.unchecked_transaction()?;
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM route_application", [], |r| r.get(0))?;
        if count > 4096 {
            return Err("sender observation exceeded bound".into());
        }
        let mut statement = transaction.prepare("SELECT CASE WHEN length(signed_dsc1) BETWEEN 1 AND 524501 THEN signed_dsc1 ELSE NULL END FROM route_application")?;
        let mut result = None;
        for row in statement.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            let message = SignedMessageV1::decode_exact(&row?)?;
            let unsigned = message.unsigned();
            if unsigned.kind() != MessageTypeV1::XmrRemoteSweepRequestV23 {
                continue;
            }
            if unsigned.session_id() != &self.session()?
                || unsigned.chain_id() != self.chain.as_bytes()
            {
                return Err("sender refund request has foreign session/chain".into());
            }
            let identity = refs
                .iter()
                .find(|r| r.participant_id() == unsigned.sender_id())
                .ok_or("request signer outside retained roster")?;
            message.verify_identity(identity.schnorr_public_key())?;
            let request = RemoteSweepRequestV23::decode_exact(unsigned.payload())?;
            require_same_economics(&request, expected)?;
            if result.replace(message).is_some() {
                return Err("multiple inner refund requests in one session".into());
            }
        }
        Ok(result)
    }
}

fn require_same_economics(request: &RemoteSweepRequestV23, expected: &Build) -> Result<()> {
    let original = &expected.public_scope.request;
    if request.action != RemoteSweepActionV23::Refund
        || request.route_id != original.route
        || request.session_id != original.session
        || request.settlement_id != original.settlement_id
        || request.terms_digest != original.terms
        || request.network_genesis != original.network_genesis
        || request.funding_tx_hash != original.funding_tx_hash
        || request.funding_output_index != expected.public_scope.output_index
        || request.funding_block_height != expected.public_scope.funding_height
        || request.funded_amount_piconero != original.funded_amount
        || request.destination != original.destination
        || request.max_fee_piconero != original.max_fee
    {
        return Err("remote request changed original refund economics".into());
    }
    // Actor-local effect/epoch/semantic intentionally differ; daemon checks
    // every remaining common composition/profile/deployment/source pin.
    Ok(())
}

/// Both daemons must already be reaped. No Store may be opened concurrently
/// with its daemon; live observations are separate read-only SQLite readers.
pub(super) fn prove_after_restart(
    running: &mut NativeXmrRunningColdStartV23,
    binary: &NativeDaemonBinaryV23,
    boundary: &FundingBoundaryV23,
    owner_snapshot: &RouteSnapshotV1,
    original: NativeActionV23,
    refund_hash: [u8; 32],
) -> Result<()> {
    let position = match boundary.leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    };
    let owner = boundary.survivor;
    let requester = owner ^ 1;
    // Obtain the already-running native ledger identity, never manufacture a
    // trusted chain from a mutable Store file or copy an actor's Store.
    let identity = running
        .public_dom_history_v24()?
        .ok_or("native DOM history absent")?
        .0;
    identity.validate()?;
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        identity.network_magic,
        &dom_core::Hash256::from_bytes(identity.genesis_hash),
    );
    if chain.as_bytes() != &identity.chain_id {
        return Err("native DOM chain mismatch".into());
    }
    let actors = [
        Actor::new(running.state_dir(0)?, position, chain)?,
        Actor::new(running.state_dir(1)?, position, chain)?,
    ];
    if actors[0].session()? != actors[1].session()? {
        return Err("publication actors have different sessions".into());
    }
    let references = {
        let a = actors[0].open_stopped()?;
        let b = actors[1].open_stopped()?;
        let refs = a.transport_identity_references(actors[0].session()?)?;
        if refs != b.transport_identity_references(actors[1].session()?)? {
            return Err("actor identity scopes differ".into());
        }
        let signer_store = if owner == 0 { &a } else { &b };
        if signer_store
            .resume_completed_xmr_remote_sweep_response_for_local_signer(actors[owner].session()?)?
            .is_some()
        {
            return Err("refund response already existed before public LOAD restart proof".into());
        }
        refs
    };
    let checkpoint = running.with_stopped_sidecar_v24(position, owner, |cache| {
        RetiredPlan::retire(
            cache,
            owner_snapshot,
            boundary.leg,
            original,
            boundary.funding_transaction_id,
            refund_hash,
        )
    })?;
    actors[owner].retained_native_refund(&checkpoint.response)?;
    running.restart_actor(requester, binary, NativeDaemonModeV23::Reopen)?;
    let start = Instant::now();
    let signed_request = loop {
        if let Some(request) =
            actors[requester].pending_request(&references, &checkpoint.response)?
        {
            break request;
        }
        if running.poll_actor_v23(requester)?.is_some() {
            return Err("requester exited without a durable authentic 0x19".into());
        }
        if start.elapsed() >= PHASE_TIMEOUT {
            return Err("requester did not retain authentic 0x19 before owner reopen".into());
        }
        thread::sleep(Duration::from_millis(100));
    };
    // Requester's real public request is durable before terminal owner opens.
    // Neither a grant nor a callback-provided accepted envelope is injected.
    running.restart_actor(owner, binary, NativeDaemonModeV23::Reopen)?;
    let mut observers = observers(running)?;
    let mut reaped = [false; 2];
    let start = Instant::now();
    loop {
        for actor in 0..2 {
            if !reaped[actor] {
                if let Some(status) = running.poll_actor_v23(actor)? {
                    if !status.success() {
                        return Err("publication daemon exited unsuccessfully".into());
                    }
                    running.reap_successful_actor_v23(actor)?;
                    reaped[actor] = true;
                }
            }
        }
        let snapshot = observers[requester].poll()?;
        let complete = snapshot.as_ref().is_some_and(|s| {
            !s.has_open_funds()
                && s.leg(boundary.leg).refund.progress() == ActionProgressV1::Final
                && s.leg(boundary.leg).claim.progress() == ActionProgressV1::NotPrepared
        });
        if complete {
            // This scenario intentionally funds only one leg. The idle leg
            // cannot make the route globally terminal, so a successful
            // publication does not imply natural daemon exit. Once the
            // requester has durably observed the exact final refund, stop the
            // remaining harness-owned children before opening their stores.
            for actor in 0..2 {
                if !reaped[actor] {
                    running.crash_actor(actor)?;
                    reaped[actor] = true;
                }
            }
            break;
        }
        if reaped[requester] && !complete {
            return Err("requester exited without observing final original refund".into());
        }
        if start.elapsed() >= PHASE_TIMEOUT {
            return Err("public LOAD/Relay refund continuation expired".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let session = actors[requester].session()?;
    let requester_store = actors[requester].open_stopped()?;
    let owner_store = actors[owner].open_stopped()?;
    let request = requester_store
        .resume_xmr_remote_sweep_request_for_local_requester(session)?
        .ok_or("original requester 0x19 absent after replay")?;
    if request.message_digest() != signed_request.digest()
        || request.payload() != signed_request.unsigned().payload()
    {
        return Err("requester changed original signed inner request across delivery".into());
    }
    let accepted = owner_store.resume_xmr_remote_sweep_request_exact(
        session,
        *request.requester_id(),
        request.payload(),
    )?;
    if accepted.message_digest() != request.message_digest() {
        return Err("owner accepted another inner request".into());
    }
    let response = requester_store.resume_xmr_remote_sweep_response_for_request(
        session,
        *request.signer_id(),
        *request.message_digest(),
    )?;
    let local_response = owner_store.resume_xmr_remote_sweep_response_for_request(
        session,
        *request.signer_id(),
        *request.message_digest(),
    )?;
    if response.response_message_digest() != local_response.response_message_digest()
        || response.payload() != local_response.payload()
    {
        return Err("paired 0x1a bytes differ across original Stores".into());
    }
    let wire = RemoteSweepResponseV23::decode_exact(response.payload())?;
    wire.validate_for_authenticated_request(
        &RemoteSweepRequestV23::decode_exact(request.payload())?,
        *request.message_digest(),
    )?;
    if wire.transaction_hash() != refund_hash
        || wire.raw_transaction() != checkpoint.response.sweep.raw_tx
    {
        return Err("published response is not the refund built without the peer".into());
    }
    drop((requester_store, owner_store));
    for actor in 0..2 {
        let replay = observers[actor].replay_stopped()?;
        let action = CoordinatorObserverV23::new(running.state_dir(actor)?)?
            .replay_stopped(&replay, boundary.leg, ActionKindV1::Refund)?
            .ok_or("native refund plan missing after public delivery")?;
        if !action.xmr_final || !action.matches_xmr(refund_hash) || action.dom_id != original.dom_id
        {
            return Err("publication changed original native XMR/DOM exit identities".into());
        }
        if actor == owner && action != original {
            return Err("terminal owner changed original refund aggregate".into());
        }
        actors[actor].retained_native_refund(&checkpoint.response)?;
    }
    running
        .with_stopped_sidecar_v24(position, owner, |cache| checkpoint.require_unchanged(cache))?;
    eprintln!("native real daemon: original refund 0x19/0x1a retained by both actors after cold public LOAD; private plan retired recoverably, no BUILD possible");
    Ok(())
}
