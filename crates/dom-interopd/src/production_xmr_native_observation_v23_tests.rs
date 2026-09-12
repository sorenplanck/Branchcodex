//! Explicit offline process/observer fixture, not network funding evidence.
use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
#[path = "production_xmr_native_refund_fixture_v23_tests.rs"]
mod refund_fixture_v23;

#[path = "production_xmr_native_claim_capture_v23_tests.rs"]
mod claim_capture;
#[path = "production_xmr_native_dom_snapshot_v23_tests.rs"]
mod dom_snapshot;
pub(crate) use dom_snapshot::Snapshot as NativeDomSnapshotV23;
#[path = "production_xmr_native_peer_sidecar_v23_tests.rs"]
mod peer_sidecar_v23;
pub(crate) use peer_sidecar_v23::PeerSidecarOwnerV23;
#[path = "production_xmr_native_route_funding_owner_v23_tests.rs"]
mod route_funding_v23;
pub(crate) use route_funding_v23::{
    NativeMainnetXmrInventorySourceV23, RouteFundingOwnerV23, NATIVE_XMR_INVENTORY_DESCRIPTOR_V23,
};

type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;
const MAX_ENVELOPE: usize = 4 * 1024 * 1024;

/// Exercise the exact GPL helper/address/parser/socket boundary before any
/// expensive native graph. Both networks use only the helper's loopback ledger.
#[test]
fn native_offline_funding_preflight_v23() -> Result<()> {
    let config = Configuration::require()?;
    let mut scalar = [0; 32];
    scalar[0] = 7;
    let spend = xmr_crypto::XmrSpendShare::from_canonical_bytes(scalar)?.public_share()?;
    for network_tag in [1, 2] {
        // The independent sweep-fee parser requires principal above the fee.
        let mut owner =
            config.start_selected_v23(spend, 1_000_000, 10_000, network_tag, None, [0x79; 32])?;
        owner.require_alive()?;
        assert_ne!(owner.hash(), [0; 32]);
    }
    Ok(())
}

pub(crate) struct Configuration {
    helper: PathBuf,
    sidecar: PathBuf,
}
pub(crate) struct FundingOwner {
    helper: ProcessOwner,
    sidecar: ProcessOwner,
    _root: tempfile::TempDir,
    pub(super) port: BlockingUdsSidecarPort,
    envelope: Envelope,
    verified_hash: [u8; 32],
}
struct ProcessOwner {
    child: Child,
    input: Option<ChildStdin>,
}
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = input.write_all(b"STOP\n");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        // Only the exact child this owner spawned; never a pidfile/process name.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    scope: String,
    combined_spend_public_key: String,
    view_public_key: String,
    amount_piconero: u64,
    destination: String,
    funding_tx_hash: String,
    canonical_transaction: String,
    daemon_urls: Vec<String>,
}

fn executable(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = PathBuf::from(std::env::var_os(name).ok_or("explicit offline executable missing")?);
    let meta = std::fs::symlink_metadata(&path)?;
    if !path.is_absolute()
        || std::fs::canonicalize(&path)? != path
        || !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o022 != 0
        || meta.mode() & 0o111 == 0
    {
        return Err("offline executable must be owner-controlled, canonical and executable".into());
    }
    Ok(path)
}
impl Configuration {
    /// Called before expensive C/D; absence is an error, not #[ignore]/skip.
    pub(crate) fn require() -> Result<Self> {
        Ok(Self {
            helper: executable("DOM_XMR_OFFLINE_FUNDING_HELPER_V23")?,
            sidecar: executable("DOM_XMR_REAL_SIDECAR_V23")?,
        })
    }
    pub(super) fn start(&self, spend: [u8; 32], amount: u64, max_fee: u64) -> Result<FundingOwner> {
        // XmrSetupProfile tags Stagenet as 2 (3 is Testnet). Keep this
        // fixture's public address encoding aligned with the profile used by
        // the native graph rather than relying on the helper's old tag.
        self.start_selected_v23(spend, amount, max_fee, 2, None, [0x79; 32])
    }

    pub(crate) fn start_mainnet_at_v23(
        &self,
        spend: [u8; 32],
        amount: u64,
        max_fee: u64,
        parent: &Path,
        auth: [u8; 32],
    ) -> Result<FundingOwner> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(parent)?;
        if auth == [0; 32]
            || !parent.is_absolute()
            || std::fs::canonicalize(parent)? != parent
            || !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.mode() & 0o077 != 0
            || meta.uid() != rustix::process::getuid().as_raw()
        {
            return Err(
                "mainnet offline sidecar requires original private parent and credential".into(),
            );
        }
        self.start_selected_v23(spend, amount, max_fee, 1, Some(parent), auth)
    }

    fn start_selected_v23(
        &self,
        spend: [u8; 32],
        amount: u64,
        max_fee: u64,
        network_tag: u8,
        parent: Option<&Path>,
        auth: [u8; 32],
    ) -> Result<FundingOwner> {
        let child = Command::new(&self.helper)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Preserve helper diagnostics in CI: a startup failure is part of
            // the integration boundary and must not be reduced to a generic
            // unavailable error after the expensive signing graph completed.
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut helper = ProcessOwner { child, input: None };
        helper.input = Some(helper.child.stdin.take().ok_or("missing helper stdin")?);
        let stdout = helper.child.stdout.take().ok_or("missing helper stdout")?;
        let input = helper
            .input
            .as_mut()
            .ok_or("missing retained helper stdin")?;
        let request = serde_json::json!({"schema":"DOM-XMR-OFFLINE-FUNDING-REQUEST-V23", "network_tag":network_tag, "combined_spend_public_key":hex::encode(spend),"amount_piconero":amount,"max_fee_piconero":max_fee});
        serde_json::to_writer(&mut *input, &request)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let (send, receive) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut data = Vec::new();
            let result = BufReader::new(stdout)
                .take((MAX_ENVELOPE + 1) as u64)
                .read_until(b'\n', &mut data)
                .map(|_| data)
                .map_err(|_| "helper envelope read failed");
            let _ = send.send(result);
        });
        let data = match receive.recv_timeout(Duration::from_secs(120)) {
            Ok(result) => result?,
            Err(_) => {
                let _ = helper.child.kill();
                let _ = reader.join();
                return Err("offline generator timeout".into());
            }
        };
        reader
            .join()
            .map_err(|_| "offline generator reader panicked")?;
        if data.len() > MAX_ENVELOPE || data.last() != Some(&b'\n') {
            return Err("offline envelope bound/framing".into());
        }
        let envelope: Envelope = serde_json::from_slice(&data)?;
        let mut view = [0; 32];
        view[0] = 13;
        let view_public = xmr_crypto::XmrSpendShare::from_canonical_bytes(view)?.public_share()?;
        if envelope.schema != "DOM-XMR-OFFLINE-FUNDING-V23"
            || envelope.scope != "local-component-only-no-chain-funding"
            || envelope.combined_spend_public_key != hex::encode(spend)
            || envelope.view_public_key != hex::encode(view_public)
            || envelope.amount_piconero != amount
            || envelope.destination.is_empty()
            || envelope.destination.len() > 128
            || envelope.daemon_urls.len() != 2
            || envelope.daemon_urls[0] == envelope.daemon_urls[1]
        {
            return Err("offline funding envelope scope mismatch".into());
        }
        for url in &envelope.daemon_urls {
            let address: std::net::SocketAddr = url
                .strip_prefix("http://")
                .ok_or("offline URL scheme")?
                .parse()?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err("nonlocal offline RPC".into());
            }
        }
        let tx_hash: [u8; 32] = hex::decode(&envelope.funding_tx_hash)?
            .try_into()
            .map_err(|_| "funding hash width")?;
        let bytes = hex::decode(&envelope.canonical_transaction)?;
        let verified = xmr_raw_tx_verify::verify_exact_raw_transaction(&bytes, tx_hash)?;
        // Independent MIT recipient/amount verification in addition to GPL scan.
        // The bound is the fee cap frozen in this scenario before native C/D.
        let paid = xmr_raw_tx_verify::verify_exact_raw_funding_v12(
            &bytes, tx_hash, spend, &view, amount, max_fee,
        )?;
        // Exercise fee parsing against genuinely signed modern raw bytes.
        // This funding transaction is NOT claimed to be the subsequent sweep;
        // the check proves the independent parser reads its actual RingCT fee.
        let bounded = xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
            &bytes, tx_hash, amount, max_fee,
        )?;
        assert_eq!(bounded.fee_piconero(), paid.fee_piconero());
        assert_eq!(bounded.sweep().transaction.tx_hash, tx_hash);
        assert!(matches!(
            xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
                &bytes,
                tx_hash,
                amount,
                paid.fee_piconero() - 1,
            ),
            Err(xmr_raw_tx_verify::SweepFeeErrorV23::Fee)
        ));
        let mut substituted_hash = tx_hash;
        substituted_hash[0] ^= 1;
        assert!(matches!(
            xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23(
                &bytes,
                substituted_hash,
                amount,
                max_fee,
            ),
            Err(xmr_raw_tx_verify::SweepFeeErrorV23::Raw(
                xmr_raw_tx_verify::RawTxError::HashMismatch
            ))
        ));
        if paid.transaction().tx_hash != verified.tx_hash
            || envelope.destination
                != xmr_raw_tx_verify::standard_funding_address_v12(network_tag, spend, &view)?
        {
            return Err("offline funding destination/hash mismatch".into());
        }
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::Builder::new()
            .prefix("xmr-v23-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent.unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR"))))?;
        let socket = directory.path().join("sidecar.sock");
        let child = Command::new(&self.sidecar)
            .env_clear()
            .env("DOM_XMR_SIDECAR_LISTEN", "127.0.0.1:0")
            .env("DOM_XMR_MONEROD_URL", &envelope.daemon_urls[0])
            .env("DOM_XMR_SIDECAR_AUTH_HEX", hex::encode(auth))
            .env("DOM_XMR_SIDECAR_CACHE_DIR", directory.path().join("cache"))
            .env("DOM_XMR_SIDECAR_UDS", &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut sidecar = ProcessOwner { child, input: None };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            if let Some(status) = sidecar.child.try_wait()? {
                return Err(format!("real sidecar exited before readiness: {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("real sidecar readiness timeout".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let port = BlockingUdsSidecarPort::with_timeout(
            socket,
            xmr_sidecar_auth::SidecarAuthKey::new(auth)?,
            Duration::from_secs(30),
        )?;
        Ok(FundingOwner {
            helper,
            sidecar,
            _root: directory,
            port,
            envelope,
            verified_hash: verified.tx_hash,
        })
    }
}
impl FundingOwner {
    pub(crate) fn raw_funding_v23(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(hex::decode(
            &self.envelope.canonical_transaction,
        )?))
    }
    pub(crate) fn sidecar_socket_v23(&self) -> PathBuf {
        self._root.path().join("sidecar.sock")
    }
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.verified_hash
    }
    pub(crate) fn destination(&self) -> String {
        self.envelope.destination.clone()
    }
    pub(crate) fn urls(&self) -> &[String] {
        &self.envelope.daemon_urls
    }
    pub(crate) fn require_alive(&mut self) -> Result<()> {
        if self.helper.child.try_wait()?.is_some() || self.sidecar.child.try_wait()?.is_some() {
            return Err("offline observation process exited".into());
        }
        Ok(())
    }
}

pub(super) fn run_claim(
    signed: crate::production_noise_relay::SignedNativeGraphFixtureV23,
    native: native_custody_v23::NativeXmrCustodyFixtureV23,
    work: [&Path; 2],
    funding: &mut FundingOwner,
) -> Result<()> {
    let plan_path = work[0]
        .parent()
        .ok_or("fixture parent missing")?
        .join("alice-plan.json");
    let plan: Plan = serde_json::from_slice(&std::fs::read(plan_path)?)?;
    let secp = SecpContext::new(&[13; 32]);
    let _authenticated = load_context(&plan, &secp, true)?;
    let authorities = ProductionAuthorityBundleV1::decode_canonical(&bounded_owner_read(
        &plan.authority_bundle_file,
        65536,
    )?)?;
    let registry = RegistryStoreV1::open_existing(&plan.registry_store)?
        .load_pinned(
            plan.registry_manifest_digest,
            authorities.registry(),
            &secp,
            plan.network_id,
        )?
        .ok_or("pinned fixture registry missing")?;
    let session = signed.wallets[0].0.session_id();
    let gate = signed.stores[0].resume_f7_funding_gate_v12(signed.chain, session)?;
    let request = signed.stores[0].f7_anchor_request_binding_v12(&gate, signed.chain)?;
    let deployment = registry
        .resolve_chain(request.role().terms().counterparty_leg.chain_id)
        .ok_or("Monero deployment missing")?
        .monero_deployment_capability()?;
    let committed = signed.stores[0].resume_f7_committed_funding_v12(&gate)?;
    let chain = signed.chain;
    let prior_tip = signed.stores[0].load_session(session)?.chain().tip_height;
    let funding_height = prior_tip.checked_add(1).ok_or("funding height overflow")?;
    let claim_previous_tip = prior_tip
        .checked_add(u64::from(
            request
                .role()
                .terms()
                .dom_leg
                .finality
                .min_confirmations
                .max(
                    signed.produced[0]
                        .economic()
                        .policy()
                        .policy()
                        .collateral_confirmations,
                ),
        ))
        .ok_or("Claim location overflow")?;
    let funding_bytes = committed.canonical_bytes().to_vec();
    let snapshot = dom_snapshot::Snapshot::start(
        registry.resolve_dom()?,
        committed.canonical_bytes(),
        signed.stores[0].load_session(session)?.chain().tip_height,
        request
            .role()
            .terms()
            .dom_leg
            .finality
            .min_confirmations
            .max(
                signed.produced[0]
                    .economic()
                    .policy()
                    .policy()
                    .collateral_confirmations,
            ),
    )?;
    let refund_sweep = refund_fixture_v23::recover_on_private_fork(
        &signed,
        &native,
        work,
        funding,
        registry.resolve_dom()?,
        &funding_bytes,
        funding_height,
    )?;
    let claim_bindings = [signed.wallets[0].0, signed.wallets[1].0];
    let funding_owner = std::cell::RefCell::new(funding);
    let mut built_sweep = None;
    native_funding_v23::native_claim_v23::claim_after_observed_funding(
        signed,
        work,
        &native,
        claim_capture::capture,
        |store, actor, participant, exact| {
            let facts = store
                .f7_claim_receiver_facts_v15(chain, session, participant)?
                .ok_or("receiver lacks accepted native 0x0f facts")?;
            let claim_snapshot = dom_snapshot::Snapshot::start_with_prior(
                registry.resolve_dom()?,
                exact,
                claim_previous_tip,
                facts.minimum_confirmations(),
                Some((&funding_bytes, funding_height)),
            )?;
            let runtime = claim_snapshot.runtime()?;
            // Synthetic location/header ancestry is explicitly NOT PoW or a
            // network payment. Signature/template/scanner checks are real.
            let observed = match store.resume_f7_claim_observation_v15(chain, session)? {
                Some(observed) => observed,
                None => {
                    let observation = runtime
                        .find_f7_final_claim_v15(&facts)?
                        .ok_or("exact captured Claim not found by real DOM scanner")?;
                    store.persist_f7_claim_observation_v15(
                        chain,
                        store.load_session(session)?.revision(),
                        observation,
                    )?
                }
            };
            assert_eq!(
                observed.tx_hash(),
                dom_scriptless_chain_adapter::canonical_transaction_hash_v1(exact)?
            );
            let revealed = runtime.consume_observed_f7_claim_v15(&facts, &observed)?;
            native.verify_extracted_claim_destination_v23(actor, revealed)?;
            if built_sweep.is_none() {
                let mut funding = funding_owner.try_borrow_mut()?;
                funding.require_alive()?;
                // Build only after the durable, freshly scanned DOM Claim.
                // The immutable loopback Monero ledger supplies real block/
                // transaction/decoy bytes; no submission or receipt is emulated.
                let nonce =
                    *dom_crypto::blake2b_256_tagged("DOM/Fixture/NativeClaimSweep/V23\0", &session)
                        .as_bytes();
                let sweep = native.build_observed_claim_sweep_v23(
                    actor,
                    store,
                    claim_bindings[actor],
                    chain,
                    &runtime,
                    &mut funding.port,
                    nonce,
                )?;
                assert!(!sweep.raw_transaction.is_empty());
                assert_ne!(sweep.tx_hash, [0; 32]);
                assert_ne!(sweep.key_image, [0; 32]);
                built_sweep = Some(sweep);
            }
            drop(runtime);
            claim_snapshot.finish()?;
            Ok(())
        },
        |actor, request, produced| {
            let mut funding = funding_owner.try_borrow_mut()?;
            funding.require_alive()?;
            let daemon_urls = funding.envelope.daemon_urls.clone();
            native.observe_claim_anchors_v23(
                actor,
                snapshot.adapter(),
                request,
                produced,
                &deployment,
                &daemon_urls,
                &mut funding.port,
            )
        },
    )?;
    let claim_sweep = built_sweep.ok_or("real sidecar Claim sweep must be built")?;
    // Alternate histories spend the same exact funding output, not two
    // unrelated balances. Identical key images also make their mutual
    // exclusion explicit: this scenario does not claim both exits can pay.
    assert_eq!(claim_sweep.key_image, refund_sweep.key_image);
    assert_ne!(claim_sweep.tx_hash, refund_sweep.tx_hash);
    assert_ne!(claim_sweep.raw_transaction, refund_sweep.raw_transaction);
    snapshot.finish()?;
    Ok(())
}
