//! Simulated read-only DOM snapshots containing actual native Funding/Claim bytes.
//! Headers/coinbase projections model a trusted RPC boundary, not mined blocks.
use dom_scriptless_chain_adapter::{BearerTokenV1, DomHttpChainAdapterV1, ExpectedDomIdentityV1};
use dom_serialization::{DomDeserialize, DomSerialize};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
#[path = "production_xmr_native_dom_baseline_coinbase_v23_tests.rs"]
mod baseline_coinbase_v23;
#[path = "production_xmr_native_dom_genesis_v23_tests.rs"]
mod genesis_v23;
#[path = "production_xmr_native_dom_snapshot_page_v23_tests.rs"]
mod page_v23;
#[path = "production_xmr_native_dom_recovery_capture_v23_tests.rs"]
mod recovery_capture_v23;
use page_v23::scan_response;
#[path = "production_xmr_native_dom_evolving_v23_tests.rs"]
mod evolving_v23;
#[path = "production_xmr_native_dom_history_v24_tests.rs"]
mod history_v24;
#[path = "production_xmr_native_dom_http_v24_tests.rs"]
mod http_v24;
#[path = "production_xmr_native_dom_ledger_v23_tests.rs"]
mod ledger_v23;
#[path = "production_xmr_native_dom_window_v24_tests.rs"]
mod window_v24;
pub(crate) use history_v24::PublicDomHistoryPagesV24;
type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;
type PublicDomHistoryV24 = (ExpectedDomIdentityV1, Value, PublicDomHistoryPagesV24);

pub(crate) struct Snapshot {
    adapter: DomHttpChainAdapterV1,
    endpoint: String,
    stop: Arc<AtomicBool>,
    submissions: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    baseline_wallet_inputs: std::sync::Mutex<[Option<dom_wallet2::StoredOutput>; 3]>,
    live: Option<Arc<std::sync::Mutex<evolving_v23::EvolvingDomV23>>>,
    worker: Option<thread::JoinHandle<core::result::Result<(), String>>>,
}
impl Snapshot {
    pub(crate) const MAX_CAMPAIGN_HEIGHT_V24: u64 = 65_535;
    /// Shared only by the local snapshot producer and its deadline regression.
    /// This is the simulated history spacing, not a registry timing override.
    pub(crate) const BASELINE_BLOCK_SECONDS_V24: u64 = 60;

    pub(crate) fn baseline_timestamp_v24(tip: u64, observed_at: u64, height: u64) -> Result<u64> {
        if height > tip {
            return Err("snapshot timestamp height exceeds tip".into());
        }
        let age = tip
            .checked_sub(height)
            .and_then(|blocks| blocks.checked_mul(Self::BASELINE_BLOCK_SECONDS_V24))
            .ok_or("snapshot clock overflow")?;
        observed_at
            .checked_sub(age)
            .ok_or_else(|| "snapshot clock before baseline".into())
    }

    /// A read-only pre-C/D chain with native coinbase proofs and no contract
    /// transactions. It cannot grant wallet funding or consensus admission.
    pub(crate) fn start_baseline_v23(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        tip: u64,
    ) -> Result<Self> {
        if tip == 0 || tip > 128 {
            return Err("bounded non-genesis DOM baseline required".into());
        }
        Self::start_transactions_v23(deployment, &[], tip)
    }
    pub(super) fn start(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        funding: &[u8],
        previous_tip: u64,
        confirmations: u32,
    ) -> Result<Self> {
        Self::start_with_prior(deployment, funding, previous_tip, confirmations, None)
    }
    pub(super) fn start_with_prior(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        funding: &[u8],
        previous_tip: u64,
        confirmations: u32,
        prior: Option<(&[u8], u64)>,
    ) -> Result<Self> {
        let height = previous_tip
            .checked_add(1)
            .ok_or("snapshot height overflow")?;
        let tip = previous_tip
            .checked_add(u64::from(confirmations))
            .ok_or("snapshot tip overflow")?;
        if confirmations == 0 {
            return Err("snapshot finality required".into());
        }
        let mut transactions = Vec::new();
        if let Some(prior) = prior {
            transactions.push(prior);
        }
        transactions.push((funding, height));
        Self::start_transactions_v23(deployment, &transactions, tip)
    }

    /// Fixture-only canonical transaction projections, not mined consensus blocks.
    pub(super) fn start_transactions_v23(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        entries: &[(&[u8], u64)],
        tip: u64,
    ) -> Result<Self> {
        Self::start_transactions_with_bearers_v23(
            deployment,
            entries,
            tip,
            vec![zeroize::Zeroizing::new(
                "offline-dom-snapshot-v23".to_owned(),
            )],
        )
    }

    /// Private local daemon credentials; never accepts a live-network endpoint.
    pub(crate) fn start_baseline_for_daemons_v23(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        tip: u64,
        bearer_tokens: [zeroize::Zeroizing<String>; 2],
    ) -> Result<Self> {
        if tip < dom_core::COINBASE_MATURITY + 3
            || tip >= 4096
            || bearer_tokens[0] == bearer_tokens[1]
        {
            return Err("native daemon baseline scope or credentials".into());
        }
        Self::start_transactions_with_bearers_v23(deployment, &[], tip, Vec::from(bearer_tokens))
    }

    fn start_transactions_with_bearers_v23(
        deployment: deployment_registry::ResolvedDomDeploymentV1,
        entries: &[(&[u8], u64)],
        tip: u64,
        bearer_tokens: Vec<zeroize::Zeroizing<String>>,
    ) -> Result<Self> {
        if bearer_tokens.is_empty() || bearer_tokens.len() > 2 {
            return Err("bounded baseline credential owners required".into());
        }
        for token in &bearer_tokens {
            drop(BearerTokenV1::new(token.to_string())?);
        }
        let deployment = deployment.deployment();
        if bearer_tokens.len() == 2
            && (deployment.runtime_identity.network.label() != "mainnet"
                || deployment.finality.min_confirmations == 0
                || deployment.finality.min_confirmations > 64)
        {
            return Err("native local finality scope".into());
        }
        let identity = ExpectedDomIdentityV1 {
            network: deployment.runtime_identity.network.label().into(),
            network_magic: deployment.runtime_identity.network_magic,
            chain_id: deployment.chain_id.0,
            genesis_hash: deployment.genesis_hash,
            protocol_version: deployment.runtime_identity.protocol_version,
            range_proof_serialization_version: deployment
                .runtime_identity
                .range_proof_serialization_version,
        };
        if entries.len() > 4 || tip >= 4096 {
            return Err("bounded fixture snapshot required".into());
        }
        let mut parsed = Vec::with_capacity(entries.len());
        let mut last = None;
        for &(bytes, height) in entries {
            let tx = dom_consensus::Transaction::from_bytes(bytes)?;
            if tx.to_bytes()? != bytes
                || tx.outputs.is_empty()
                || tx.kernels.is_empty()
                || height == 0
                || height > tip
                || last.is_some_and(|previous| height <= previous)
            {
                return Err("canonical ordered snapshot transaction required".into());
            }
            parsed.push((
                tx,
                bytes,
                height,
                hex::encode(dom_crypto::blake2b_256(bytes).as_bytes()),
            ));
            last = Some(height);
        }
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // Retain the original whole-history underflow check, including genesis.
        Self::baseline_timestamp_v24(tip, observed_at, 0)?;
        let mut previous = [0u8; 32];
        let mut blocks = Vec::new();
        let mut live_ledger = if bearer_tokens.len() == 2 {
            Some(ledger_v23::NativeDomLedgerV23::new(identity.chain_id)?)
        } else {
            None
        };
        for height in 0..=tip {
            if height == 0 {
                blocks.push(genesis_v23::projection(&identity)?);
                previous = identity.genesis_hash;
                continue;
            }
            let timestamp = Self::baseline_timestamp_v24(tip, observed_at, height)?;
            let coinbase = if let Some((coinbase_transaction, ..)) = parsed.first() {
                json!({
                    "output_commitment":hex::encode(coinbase_transaction.outputs[0].commitment.as_bytes()),
                    "explicit_value":1,"kernel_excess":hex::encode(coinbase_transaction.kernels[0].excess.as_bytes()),
                    "kernel_features":1,"kernel_excess_signature":hex::encode(coinbase_transaction.kernels[0].excess_signature),
                    "offset":hex::encode([0;32]),"output_proof_envelope":hex::encode(coinbase_transaction.outputs[0].range_proof_bytes()?)
                })
            } else {
                let (validated, projection) =
                    baseline_coinbase_v23::material_v23(&identity.chain_id, height, 0)?;
                if let Some(ledger) = live_ledger.as_mut() {
                    ledger.seed_coinbase(height, &validated)?;
                }
                projection
            };
            // Encode and roundtrip through the consensus codec; this constructs
            // test headers only, without changing or claiming PoW/consensus.
            let mut header = Vec::new();
            header.extend_from_slice(&identity.protocol_version.to_le_bytes());
            header.extend_from_slice(&height.to_le_bytes());
            header.extend_from_slice(&previous);
            header.extend_from_slice(&timestamp.to_le_bytes());
            header.extend_from_slice(&[0x51; 32]);
            header.extend_from_slice(&[0x52; 32]);
            header.extend_from_slice(&[0x53; 32]);
            header.extend_from_slice(&[0; 32]);
            header.extend_from_slice(&0x207fffffu32.to_le_bytes());
            header.extend_from_slice(&[0; 32]);
            header.extend_from_slice(&0u64.to_le_bytes());
            header.extend_from_slice(&[0; 32]);
            let decoded = dom_consensus::BlockHeader::from_bytes(&header)?;
            if decoded.to_bytes()? != header {
                return Err("snapshot header codec mismatch".into());
            }
            let hash = *dom_crypto::blake2b_256(&header).as_bytes();
            let hash_hex = hex::encode(hash);
            let entry = parsed.iter().find(|entry| entry.2 == height);
            let transactions = if let Some((transaction, funding, _, transaction_hash)) = entry {
                let outputs = transaction.outputs.iter().enumerate().map(|(index, output)| -> Result<Value> {
                    let capsule = output.recovery_capsule()?;
                    Ok(json!({"commitment":hex::encode(output.commitment.as_bytes()),
                        "range_proof":hex::encode(output.range_proof_bytes()?),
                        "recovery_capsule":capsule.as_ref().map(|c|hex::encode(c.as_bytes())).unwrap_or_default(),
                        "recovery_version":capsule.as_ref().map_or(0, |c|c.version()),
                        "is_coinbase":false,"block_height":height,"block_hash":hash_hex,
                        "output_position":index + 1}))
                }).collect::<Result<Vec<_>>>()?;
                vec![
                    json!({"block_height":height,"block_hash":hash_hex,"transaction_index":0,
                    "tx_hash":transaction_hash,"canonical_bytes":hex::encode(funding),
                    "inputs":transaction.inputs.iter().map(|i|json!({"spent_commitment":hex::encode(i.commitment.as_bytes())})).collect::<Vec<_>>(),
                    "outputs":outputs,
                    "kernels":transaction.kernels.iter().map(|k|json!({"excess":hex::encode(k.excess.as_bytes()),
                        "features":k.features,"fee":k.fee.noms(),"lock_height":k.lock_height,
                        "excess_signature":hex::encode(k.excess_signature)})).collect::<Vec<_>>(),
                    "offset":hex::encode(transaction.offset)}),
                ]
            } else {
                vec![]
            };
            let fees = if let Some((transaction, ..)) = entry {
                transaction
                    .kernels
                    .iter()
                    .try_fold(0u64, |sum, k| sum.checked_add(k.fee.noms()))
                    .ok_or("fee overflow")?
            } else {
                0
            };
            // Coinbase is an unrelated node projection, not an output available
            // to either wallet. Native signed transaction bytes alone are treated as evidence.
            blocks.push(json!({"height":height,"block_hash":hash_hex,"previous_block_hash":hex::encode(previous),
                "canonical_header_bytes":hex::encode(header),"timestamp":timestamp,"canonical_marker":hash_hex,
                "transactions":transactions,"coinbase":coinbase,
                "total_fees_noms":fees,"protocol_version":identity.protocol_version,
                "range_proof_serialization_version":identity.range_proof_serialization_version}));
            previous = hash;
        }
        let mut baseline_wallet_inputs = [None, None, None];
        if entries.is_empty() && tip >= dom_core::COINBASE_MATURITY + 3 {
            for (position, slot) in baseline_wallet_inputs.iter_mut().enumerate() {
                let height = u64::try_from(position)? + 1;
                let block = &blocks[usize::try_from(height)?];
                let hash: [u8; 32] =
                    hex::decode(block["block_hash"].as_str().ok_or("baseline block hash")?)?
                        .try_into()
                        .map_err(|_| "baseline block hash length")?;
                let output = baseline_coinbase_v23::wallet_output_v23(
                    &identity.chain_id,
                    height,
                    hash,
                    observed_at,
                )?;
                if block["coinbase"]["output_commitment"].as_str()
                    != Some(hex::encode(output.commitment).as_str())
                {
                    return Err("baseline wallet opening differs from served coinbase".into());
                }
                *slot = Some(output);
            }
        }
        let identity_json = json!({"network":identity.network,"network_magic":identity.network_magic,
            "chain_id":hex::encode(identity.chain_id),"genesis_hash":hex::encode(identity.genesis_hash),
            "protocol_version":identity.protocol_version,
            "range_proof_serialization_version":identity.range_proof_serialization_version,
            "coinbase_maturity":dom_core::COINBASE_MATURITY,"tip_height":tip,"tip_hash":hex::encode(previous)});
        let live = live_ledger.map(|ledger| {
            Arc::new(std::sync::Mutex::new(evolving_v23::EvolvingDomV23::new(
                ledger,
                identity.clone(),
                identity_json.clone(),
                blocks.clone(),
                deployment.finality.min_confirmations,
            )))
        });
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let adapter = DomHttpChainAdapterV1::new(
            &endpoint,
            identity,
            BearerTokenV1::new(bearer_tokens[0].to_string())?,
            Duration::from_secs(2),
            Duration::from_secs(5),
        )?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let submissions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = Arc::clone(&submissions);
        let retained_live = live.clone();
        let worker = thread::spawn(move || -> core::result::Result<(), String> {
            let mut requests = 0usize;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        if !peer.ip().is_loopback() {
                            return Err("nonlocal snapshot peer".into());
                        }
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .map_err(|e| e.to_string())?;
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .map_err(|e| e.to_string())?;
                        let connection = (|| -> Result<()> {
                            let header = http_v24::read_header_v24(&mut stream)?;
                            let header_end = header
                                .windows(4)
                                .position(|part| part == b"\r\n\r\n")
                                .ok_or("HTTP header terminator")?;
                            let head = std::str::from_utf8(&header[..header_end])
                                .map_err(|_| "snapshot HTTP encoding")?;
                            let auth: Vec<_> = head
                                .lines()
                                .filter_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("authorization")
                                        .then_some(value.trim())
                                })
                                .collect();
                            let authorized = auth.len() == 1
                                && auth[0].strip_prefix("Bearer ").is_some_and(|candidate| {
                                    bearer_tokens
                                        .iter()
                                        .any(|expected| candidate == expected.as_str())
                                });
                            if !authorized {
                                http_v24::socket_io_v24(stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))?;
                                return Ok(());
                            }
                            if header.starts_with(b"POST /tx/submit HTTP/1.1\r\n") {
                                if let Some(live) = &live {
                                    return evolving_v23::submit_http_v23(
                                        &mut stream,
                                        &header,
                                        live,
                                    );
                                }
                                let bytes =
                                    recovery_capture_v23::capture_submission(&mut stream, &header)
                                        .map_err(|e| e.to_string())?;
                                let mut captured = captured.lock().map_err(|_| "capture lock")?;
                                if captured.len() >= 4 {
                                    return Err("capture count bound".into());
                                }
                                captured.push(bytes);
                                return Ok(());
                            }
                            let header =
                                String::from_utf8(header).map_err(|_| "snapshot HTTP encoding")?;
                            let first = header.lines().next().ok_or("snapshot request missing")?;
                            if !authorized || !first.starts_with("GET /chain/scan/scriptless/v1?") {
                                http_v24::socket_io_v24(stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))?;
                                return Ok(());
                            }
                            requests += 1;
                            if requests > 65_536 {
                                return Err("snapshot call bound".into());
                            }
                            let response = if let Some(live) = &live {
                                let state = live.lock().map_err(|_| "evolving ledger lock")?;
                                state.scan_response(first)
                            } else {
                                scan_response(first, &identity_json, &blocks)
                            }?;
                            http_v24::write_json_v24(&mut stream, "200 OK", &response)
                        })();
                        http_v24::finish_connection_v24(connection)
                            .map_err(|error| error.to_string())?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok(())
        });
        Ok(Self {
            adapter,
            endpoint,
            stop,
            submissions,
            baseline_wallet_inputs: std::sync::Mutex::new(baseline_wallet_inputs),
            live: retained_live,
            worker: Some(worker),
        })
    }
    /// Controls are direct handles owned by this local scenario, not RPC methods
    /// or a credential that can change a live chain or the negotiated deadlines.
    pub(crate) fn arm_submission_barrier_v23(&self) -> Result<()> {
        self.live
            .as_ref()
            .ok_or("immutable DOM snapshot has no submission barrier")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .arm_submission_barrier()
    }

    pub(crate) fn pending_submissions_v23(&self) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        Ok(self
            .live
            .as_ref()
            .ok_or("immutable DOM snapshot has no pending ledger")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .pending_transactions())
    }

    pub(crate) fn release_submissions_v23(&self) -> Result<()> {
        self.live
            .as_ref()
            .ok_or("immutable DOM snapshot has no pending ledger")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .release_submissions()
    }

    /// Atomic read of the public local ledger, never a signing/finality token.
    /// Only native-validated admissions populate this evolving history.
    /// In explicit live-window mode the first entry is the original baseline
    /// anchor, not genesis; heights are absolute, never vector indices. RPC
    /// pagination still exposes the separately retained complete baseline.
    pub(crate) fn public_history_v24(&self) -> Result<Option<PublicDomHistoryV24>> {
        let live = match self
            .live
            .as_ref()
            .ok_or("mutable native ledger required")?
            .try_lock()
        {
            Ok(live) => live,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("native ledger poisoned".into())
            }
        };
        if live.blocks().is_empty() || live.blocks().len() > 4096 {
            return Err("native public history bound".into());
        }
        Ok(Some((
            self.adapter.expected_identity().clone(),
            live.identity_json()?.clone(),
            live.public_history_pages_v24()?,
        )))
    }

    pub(crate) fn confirm_retained_funding_v25(
        &self,
        hash: &[u8; 32],
        confirmations: u32,
    ) -> Result<()> {
        let mut state = self
            .live
            .as_ref()
            .ok_or("mutable DOM ledger required")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?;
        if let Some(target) = state.funding_confirmation_target_v25(hash, confirmations)? {
            state.advance_to_height(target)?;
        }
        Ok(())
    }

    pub(crate) fn advance_to_height_v23(&self, target: u64) -> Result<()> {
        let live = self
            .live
            .as_ref()
            .ok_or("immutable DOM snapshot cannot advance")?;
        let mut admitted = false;
        loop {
            let mut state = live.lock().map_err(|_| "local DOM ledger poisoned")?;
            let tip = state.identity_json()?["tip_height"]
                .as_u64()
                .ok_or("local tip")?;
            let maximum = state.maximum_height_v24()?;
            if (!admitted && target < tip) || target > maximum || tip > maximum {
                return Err("local history advance outside original negotiated bound".into());
            }
            if tip >= target {
                return Ok(());
            }
            admitted = true;
            // One small atomic page per lock/transaction. RPC observers can
            // progress between batches; neither all headers nor their proofs
            // are generated or fsynced as one giant uninterruptible campaign.
            state.advance_to_height(
                target.min(tip.checked_add(8).ok_or("history batch overflow")?),
            )?;
            drop(state);
            std::thread::yield_now();
        }
    }

    pub(crate) fn enable_campaign_history_v24(
        &self,
        baseline: u64,
        maximum: u64,
        parent: &std::path::Path,
    ) -> Result<()> {
        self.live
            .as_ref()
            .ok_or("campaign history requires mutable native ledger")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .enable_campaign_history_v24(baseline, maximum, parent)
    }

    pub(crate) fn maximum_history_height_v24(&self) -> Result<u64> {
        self.live
            .as_ref()
            .ok_or("mutable native ledger required")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .maximum_height_v24()
    }

    /// Explicit local-scenario opt-in: preserve the complete baseline, then
    /// retain at most 4096 evolving entries including its exact anchor. Neither
    /// the native ledger nor any absolute block height is reset or rewritten.
    pub(crate) fn enable_live_window_v24(
        &self,
        baseline_tip: u64,
        maximum_span: u64,
    ) -> Result<()> {
        self.live
            .as_ref()
            .ok_or("immutable snapshot cannot enable live window")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .enable_live_window_v24(baseline_tip, maximum_span)
    }

    pub(crate) fn live_window_scope_v24(&self) -> Result<(u64, u64)> {
        self.live
            .as_ref()
            .ok_or("immutable snapshot has no live window")?
            .lock()
            .map_err(|_| "local DOM ledger poisoned")?
            .live_window_scope_v24()
    }

    /// Move a baseline output once, without cloning a funded wallet or store.
    pub(crate) fn take_baseline_wallet_input_v23(
        &self,
        position: usize,
    ) -> Result<dom_wallet2::StoredOutput> {
        if position > 1 {
            return Err("baseline route position".into());
        }
        self.take_baseline_input_slot_v23(position)
    }

    pub(crate) fn take_solver_baseline_input_v23(&self) -> Result<dom_wallet2::StoredOutput> {
        self.take_baseline_input_slot_v23(2)
    }

    fn take_baseline_input_slot_v23(&self, position: usize) -> Result<dom_wallet2::StoredOutput> {
        self.baseline_wallet_inputs
            .lock()
            .map_err(|_| "baseline wallet ownership lock")?
            .get_mut(position)
            .ok_or("baseline wallet position")?
            .take()
            .ok_or_else(|| "baseline wallet input absent or already transferred".into())
    }

    pub(super) fn take_submission_v23(&self, expected_hash: [u8; 32]) -> Result<Vec<u8>> {
        let mut submissions = self
            .submissions
            .lock()
            .map_err(|_| "snapshot capture lock")?;
        if submissions.len() != 1 {
            return Err("one actual recovery submission required".into());
        }
        let bytes = submissions.remove(0);
        if dom_scriptless_chain_adapter::canonical_transaction_hash_v1(&bytes)? != expected_hash {
            return Err("captured recovery identity mismatch".into());
        }
        Ok(bytes)
    }
    pub(super) fn runtime(&self) -> Result<adapter_dom_real::RealDomRpcRuntimeV1> {
        let adapter = DomHttpChainAdapterV1::new(
            &self.endpoint,
            self.adapter.expected_identity().clone(),
            BearerTokenV1::new("offline-dom-snapshot-v23".into())?,
            Duration::from_secs(2),
            Duration::from_secs(5),
        )?;
        Ok(adapter_dom_real::RealDomRpcRuntimeV1::new(adapter, 64)?)
    }
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(crate) fn adapter(&self) -> &DomHttpChainAdapterV1 {
        &self.adapter
    }
    pub(super) fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| "snapshot worker panic")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        }
        Ok(())
    }
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
