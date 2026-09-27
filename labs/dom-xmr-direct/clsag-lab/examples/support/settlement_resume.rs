//! Fresh settlement recovery worker. Receives only root + operation ID + action;
//! reconstructs records and queries owned native nodes itself. The parent is
//! still the node host/fixture miner, not a source of interpreted observations.
//! Stable tip checks detect visible races, not ABA reorgs or a dishonest node.
use dom_consensus::{Transaction as DomTransaction, ValidationContext};
use dom_core::{BlockHeight, Timestamp};
use dom_serialization::{DomDeserialize, DomSerialize};
use dxp1_clsag_lab::{
    claim_resume::{digest, MAX_RECORD_BYTES},
    counterpart_delivery::{CounterpartDelivery, DeliveryAction, DeliveryBinding, Observation},
    native::XmrClaimEnvelope,
    native_dom::DomClaimOffer,
    operation_checkpoint::{ClaimManifest, OperationCheckpoint},
};
use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};
use monero_wallet::transaction::Transaction as XmrTransaction;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
fn ensure(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason)
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure(
        text.len() <= MAX_RECORD_BYTES * 2 && text.len().is_multiple_of(2),
        "hex length",
    )?;
    ensure(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "hex encoding",
    )?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "hex encoding"))
        .collect()
}
fn hash(value: &Value) -> Result<[u8; 32]> {
    unhex(value.as_str().ok_or("missing hash")?)?
        .try_into()
        .map_err(|_| "hash length")
}
fn number(value: &Value) -> Result<u64> {
    value.as_u64().ok_or("missing number")
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| "missing record")?
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| "record read")?;
    ensure(data.len() <= MAX_RECORD_BYTES, "record too large")?;
    Ok(data)
}

#[derive(Default)]
struct RpcMetrics {
    public_read_attempts: Cell<u64>,
    authenticated_read_attempts: Cell<u64>,
    submit_attempts: Cell<u64>,
    throttle_retries: Cell<u64>,
    wait_requested_ms: Cell<u64>,
    wait_elapsed_ms: Cell<u64>,
}
struct MeasuredWait<'a> {
    started: Instant,
    elapsed_ms: &'a Cell<u64>,
}
impl Drop for MeasuredWait<'_> {
    fn drop(&mut self) {
        self.elapsed_ms.set(
            self.elapsed_ms.get().saturating_add(
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ),
        );
    }
}
impl RpcMetrics {
    fn value(&self) -> Value {
        json!({"public_read_attempts":self.public_read_attempts.get(),
            "authenticated_read_attempts":self.authenticated_read_attempts.get(),
            "submit_attempts":self.submit_attempts.get(),"throttle_retries":self.throttle_retries.get(),
            "wait_requested_ms":self.wait_requested_ms.get(),"wait_elapsed_ms":self.wait_elapsed_ms.get()})
    }
    fn log(&self) {
        eprintln!(
            "recovery_rpc_metrics: {}",
            json!({"pid":std::process::id(),"dom_rpc":self.value()})
        );
    }
}

// Integer Retry-After or native tower_governor's floor-rounded seconds. Reject
// malformed/duplicate/conflicting-unbounded hints; never retry a POST here.
fn throttle_delay(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let mut seconds = None;
    for (name, floor_rounded) in [("retry-after", false), ("x-ratelimit-after", true)] {
        if headers.get_all(name).iter().count() > 1 {
            return None;
        }
        if let Some(value) = headers.get(name) {
            let text = value.to_str().ok()?;
            if text.is_empty() || !text.bytes().all(|v| v.is_ascii_digit()) {
                return None;
            }
            let mut wait = text.parse::<u64>().ok()?;
            if floor_rounded {
                wait = wait.checked_add(1)?;
            }
            wait = wait.max(1);
            if wait > 2 {
                return None;
            }
            seconds = Some(seconds.map_or(wait, |prior: u64| prior.max(wait)));
        }
    }
    seconds.map(Duration::from_secs)
}

struct DomRpc<'a> {
    client: reqwest::Client,
    base: String,
    token: String,
    metrics: &'a RpcMetrics,
}
impl DomRpc<'_> {
    async fn request(
        &self,
        method: reqwest::Method,
        route: &str,
        body: Option<Value>,
        allow_missing: bool,
    ) -> Result<Option<Value>> {
        let mut request = self
            .client
            .request(method.clone(), format!("{}{route}", self.base))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = loop {
            let counter = if method != reqwest::Method::GET {
                &self.metrics.submit_attempts
            } else if route.starts_with("/tx/") || route.starts_with("/chain/scan/") {
                &self.metrics.authenticated_read_attempts
            } else {
                &self.metrics.public_read_attempts
            };
            counter.set(counter.get().saturating_add(1));
            let response = request
                .try_clone()
                .ok_or("DOM request not repeatable")?
                .send()
                .await
                .map_err(|_| "DOM RPC unavailable")?;
            if method == reqwest::Method::GET
                && response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                if let Some(wait) = throttle_delay(response.headers()) {
                    let millis =
                        u64::try_from(wait.as_millis()).map_err(|_| "DOM throttle wait")?;
                    let requested = self.metrics.wait_requested_ms.get().saturating_add(millis);
                    // Shared by ALL reads of this worker, not renewed per route.
                    // Outer recovery timeout and original operation clock remain.
                    if requested <= 2000 {
                        self.metrics.wait_requested_ms.set(requested);
                        self.metrics
                            .throttle_retries
                            .set(self.metrics.throttle_retries.get() + 1);
                        drop(response);
                        let _measurement = MeasuredWait {
                            started: Instant::now(),
                            elapsed_ms: &self.metrics.wait_elapsed_ms,
                        };
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                }
            }
            break response;
        };
        let missing = response.status() == reqwest::StatusCode::NOT_FOUND;
        if !response.status().is_success() && !(missing && allow_missing) {
            // No bearer token or response body is logged. Keep enough native
            // diagnostics to distinguish throttling from canonicality errors.
            eprintln!(
                "DOM recovery RPC status={} route={route}",
                response.status()
            );
        }
        ensure(
            response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS,
            "DOM RPC rate limited",
        )?;
        ensure(
            response.status().is_success() || (missing && allow_missing),
            "DOM RPC status",
        )?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "DOM RPC body")? {
            ensure(
                bytes.len().saturating_add(chunk.len()) <= 4 * 1024 * 1024,
                "DOM RPC response limit",
            )?;
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "DOM RPC JSON")?;
        if missing {
            ensure(value["found"] == false, "DOM missing response malformed")?;
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
    async fn get(&self, route: &str) -> Result<Value> {
        self.request(reqwest::Method::GET, route, None, false)
            .await?
            .ok_or("DOM missing response")
    }
    async fn optional(&self, route: &str) -> Result<Option<Value>> {
        self.request(reqwest::Method::GET, route, None, true).await
    }
    async fn submit(&self, payload: &[u8]) -> Result<()> {
        let result = self
            .request(
                reqwest::Method::POST,
                "/tx/submit",
                Some(json!({"tx_hex":hex(payload)})),
                false,
            )
            .await?
            .ok_or("DOM admission response missing")?;
        ensure(
            result["accepted"] == true
                && result["tx_hash"] == hex(dom_crypto::blake2b_256(payload).as_bytes()),
            "DOM native admission rejected or mismatched",
        )
    }
    async fn identity(&self, checkpoint: &OperationCheckpoint) -> Result<Value> {
        let v = self.get("/chain/identity").await?;
        ensure(
            v["network"] == "regtest"
                && v["network_magic"] == format!("{:08x}", dom_core::NETWORK_MAGIC_REGTEST)
                && hash(&v["chain_id"])? == checkpoint.dom_chain
                && hash(&v["genesis_hash"])? == checkpoint.dom_genesis,
            "DOM chain identity mismatch",
        )?;
        number(&v["tip_height"])?;
        hash(&v["tip_hash"])?;
        Ok(v)
    }
    async fn observe(
        &self,
        tx: &DomTransaction,
        identity: &Value,
        inspect_unspent: bool,
    ) -> Result<(Observation, bool)> {
        let raw = tx.to_bytes().map_err(|_| "DOM encoding")?;
        let tx_hash = hex(dom_crypto::blake2b_256(&raw).as_bytes());
        let found = self.get(&format!("/tx/{tx_hash}")).await?;
        let index_missing = found["found"] == false;
        let (height, block, parent_hint) = if index_missing {
            // The admission identity index is optional/retained for a bounded
            // period. A miss does not prove absence. Locate by the native kernel
            // index, then require the EXACT transaction in the full scan below.
            let excess = hex(tx.kernels[0].excess.as_bytes());
            let Some(kernel) = self.optional(&format!("/kernel/{excess}")).await? else {
                if !inspect_unspent {
                    return Ok((Observation::Unknown, true));
                }
                // This lab adapter runs with the owned fixture miner paused.
                // Native UTXO evidence is required; a tx-index miss is not enough.
                for input in &tx.inputs {
                    let commitment = hex(input.commitment.as_bytes());
                    let Some(utxo) = self.optional(&format!("/utxo/{commitment}")).await? else {
                        return Ok((Observation::Unknown, true));
                    };
                    if !dom_unspent_matches(&utxo, &commitment, number(&identity["tip_height"])?) {
                        return Ok((Observation::Unknown, true));
                    }
                }
                // A visible pool change must cancel this observation. A race
                // after these reads is still decided by native admission.
                ensure(
                    self.get(&format!("/tx/{tx_hash}")).await?["found"] == false,
                    "DOM transaction appeared during absence check",
                )?;
                return Ok((Observation::AbsentAndUnspent, true));
            };
            ensure(
                kernel["found"] == true && kernel["excess"] == excess,
                "DOM kernel lookup",
            )?;
            let block = hash(&kernel["block_hash"])?;
            let header = self.get(&format!("/block/{}", hex(&block))).await?;
            ensure(hash(&header["hash"])? == block, "DOM kernel block mismatch")?;
            (
                number(&header["height"])?,
                block,
                Some(hash(&header["prev_hash"])?),
            )
        } else {
            ensure(
                found["found"] == true && found["tx_hash"] == tx_hash,
                "DOM transaction mismatch",
            )?;
            if found.get("confirmed").is_none() {
                return Ok((Observation::InPool, false));
            }
            ensure(found["confirmed"] == true, "DOM confirmation flag")?;
            (
                number(&found["block_height"])?,
                hash(&found["block_hash"])?,
                None,
            )
        };
        ensure(
            height > 0 && height <= number(&identity["tip_height"])?,
            "DOM inclusion height",
        )?;
        let anchor_hash = if let Some(parent) = parent_hint {
            // Merely a hint until the native scan validates this anchor under
            // the same chain lock as the canonical block and transaction body.
            parent
        } else {
            let anchor = self.get(&format!("/block/{}", height - 1)).await?;
            ensure(
                number(&anchor["height"])? == height - 1,
                "DOM anchor height",
            )?;
            hash(&anchor["hash"])?
        };
        let scan = self.get(&format!("/chain/scan/scriptless/v1?from={height}&to={height}&expected_network_magic={}&expected_chain_id={}&anchor_hash={}",
            dom_core::NETWORK_MAGIC_REGTEST,identity["chain_id"].as_str().ok_or("DOM chain")?,hex(&anchor_hash))).await?;
        verify_dom_inclusion(&scan, identity, &raw, height, block, anchor_hash)?;
        // The native full scan checks canonicality, anchor, exact body and tip
        // under ONE chain lock. A second /block read adds no stronger snapshot.
        // The caller still rechecks both tips after this observation and fsync.
        Ok((Observation::Included { block, height }, index_missing))
    }
}

fn verify_dom_inclusion(
    scan: &Value,
    identity: &Value,
    raw: &[u8],
    height: u64,
    block: [u8; 32],
    anchor_hash: [u8; 32],
) -> Result<()> {
    ensure(
        height > 0 && height <= number(&identity["tip_height"])?,
        "DOM inclusion height",
    )?;
    let tx_hash = hex(dom_crypto::blake2b_256(raw).as_bytes());
    ensure(
        scan["schema_version"] == 1
            && scan["status"] == "ok"
            && scan["canonical"] == true
            && scan["requested_from"] == height
            && scan["requested_to"] == height
            && scan["served_from"] == height
            && scan["served_to"] == height
            && scan["request_anchor"]["height"] == height - 1
            && hash(&scan["request_anchor"]["block_hash"])? == anchor_hash,
        "DOM incomplete scan",
    )?;
    for key in [
        "chain_id",
        "genesis_hash",
        "network",
        "tip_height",
        "tip_hash",
    ] {
        ensure(
            scan["identity"][key] == identity[key],
            "DOM scan snapshot changed",
        )?;
    }
    ensure(
        scan["identity"]["network_magic"] == dom_core::NETWORK_MAGIC_REGTEST,
        "DOM scan network",
    )?;
    let blocks = scan["blocks"].as_array().ok_or("DOM scan blocks")?;
    ensure(blocks.len() == 1, "DOM scan block count")?;
    let scanned = &blocks[0];
    ensure(
        number(&scanned["height"])? == height
            && hash(&scanned["block_hash"])? == block
            && hash(&scanned["previous_block_hash"])? == anchor_hash,
        "DOM scan location",
    )?;
    let transactions = scanned["transactions"]
        .as_array()
        .ok_or("DOM scan transactions")?;
    let matches: Vec<_> = transactions
        .iter()
        .filter(|v| v["tx_hash"] == tx_hash)
        .collect();
    ensure(matches.len() == 1, "DOM exact transaction missing")?;
    let exact = matches[0];
    ensure(
        number(&exact["block_height"])? == height
            && hash(&exact["block_hash"])? == block
            && unhex(
                exact["canonical_bytes"]
                    .as_str()
                    .ok_or("DOM native bytes")?,
            )? == raw,
        "DOM native body mismatch",
    )?;
    Ok(())
}

#[derive(Default)]
struct SendProgress {
    attempted: Cell<bool>,
    acknowledged: Cell<bool>,
    dom_rpc: RpcMetrics,
}

fn is_send(action: &str) -> bool {
    matches!(
        action,
        "send" | "send-crash-before-rpc" | "send-crash-after-admission"
    )
}
fn dom_unspent_matches(utxo: &Value, commitment: &str, tip: u64) -> bool {
    utxo["found"] == true
        && utxo["commitment"] == commitment
        && utxo["is_mature"] == true
        && utxo["is_coinbase"] == false
        && utxo["block_height"]
            .as_u64()
            .is_some_and(|height| height <= tip)
}
fn local_rpc_response(info: &Value) -> bool {
    info.get("untrusted")
        .is_none_or(|value| value == &Value::Bool(false))
}
fn xmr_exactly_missing(info: &Value, tx_hash: &str) -> bool {
    info["status"] == "OK"
        && info["missed_tx"] == json!([tx_hash])
        && (info["txs"].is_null() || info["txs"].as_array().is_some_and(Vec::is_empty))
        && local_rpc_response(info)
}
fn xmr_key_image_unspent(spent: &Value) -> bool {
    spent["status"] == "OK" && spent["spent_status"] == json!([0]) && local_rpc_response(spent)
}

async fn recover(
    root: &Path,
    operation: [u8; 32],
    action: &str,
    progress: &SendProgress,
) -> Result<Value> {
    let inspect_unspent = is_send(action) || action == "inspect-delivery";
    let checkpoint =
        OperationCheckpoint::decode(&read(&root.join("operation.checkpoint"))?, operation)
            .ok_or("operation checkpoint invalid")?;
    let records = root.join("claim-resume");
    let manifest = ClaimManifest::decode(&read(&records.join("manifest.record"))?, &checkpoint)
        .ok_or("original manifest invalid")?;
    let xmr = XmrClaimEnvelope::from_resume_bytes(
        &read(&records.join("xmr.record"))?,
        manifest.xmr_record,
        &mut OsRng,
    )
    .map_err(|_| "XMR envelope invalid")?;
    let dom =
        DomClaimOffer::from_resume_bytes(&read(&records.join("dom.record"))?, manifest.dom_record)
            .map_err(|_| "DOM envelope invalid")?;
    // Persisted before the original release, not supplied after inclusion.
    let first = read(&root.join("initial-claim.tx"))?;
    let policy = manifest
        .original_release_policy(&first)
        .ok_or("original release policy invalid")?;
    let gate = dxp1_clsag_lab::release_journal::InitialClaimJournal::open(
        &root.join("initial-claim.wal"),
        policy,
    )
    .map_err(|_| "initial exposure journal invalid")?;
    ensure(
        gate.state().map_err(|_| "initial exposure state")?
            == dxp1_clsag_lab::release_journal::ReleaseState::ExposurePossible,
        "initial exposure missing",
    )?;
    drop(gate);
    let dom_rpc = DomRpc {
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "DOM RPC client")?,
        base: format!("http://127.0.0.1:{}", checkpoint.dom_port),
        token: hex(&checkpoint.dom_token),
        metrics: &progress.dom_rpc,
    };
    let identity = dom_rpc.identity(&checkpoint).await?;
    let context = ValidationContext {
        chain_id: checkpoint.dom_chain,
        current_height: BlockHeight(number(&identity["tip_height"])?),
        now: Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock")?
                .as_secs(),
        ),
    };
    let rpc = SimpleRequestTransport::with_custom_timeout(
        format!("http://127.0.0.1:{}", checkpoint.xmr_port),
        Duration::from_secs(2),
    )
    .await
    .map_err(|_| "XMR RPC unavailable")?;
    let info: Value = serde_json::from_str(
        &rpc.json_rpc_call("get_info", None, 16384)
            .await
            .map_err(|_| "XMR identity unavailable")?,
    )
    .map_err(|_| "XMR identity JSON")?;
    ensure(
        info["offline"] == true && info["nettype"] == "fakechain",
        "XMR fixture identity",
    )?;
    ensure(
        rpc.block_by_number(0)
            .await
            .map_err(|_| "XMR genesis unavailable")?
            .hash()
            == checkpoint.xmr_genesis,
        "XMR genesis mismatch",
    )?;
    let xmr_tip_height = rpc
        .latest_block_number()
        .await
        .map_err(|_| "XMR tip unavailable")?;
    let xmr_tip = rpc
        .block_by_number(xmr_tip_height)
        .await
        .map_err(|_| "XMR tip block unavailable")?
        .hash();
    let observe_xmr = async |tx: &XmrTransaction, inspect_unspent: bool| -> Result<Observation> {
        let tx_hash = hex(&tx.hash());
        let info: Value = serde_json::from_str(
            &rpc.rpc_call(
                "get_transactions",
                Some(json!({"txs_hashes":[tx_hash]}).to_string()),
                MAX_RECORD_BYTES,
            )
            .await
            .map_err(|_| "XMR transaction unavailable")?,
        )
        .map_err(|_| "XMR transaction JSON")?;
        let Some(txs) = info["txs"].as_array().filter(|txs| txs.len() == 1) else {
            if !inspect_unspent || !xmr_exactly_missing(&info, &tx_hash) {
                return Ok(Observation::Unknown);
            }
            ensure(tx.prefix().inputs.len() == 1, "XMR unexpected input count")?;
            let monero_wallet::transaction::Input::ToKey { key_image, .. } = &tx.prefix().inputs[0]
            else {
                return Err("XMR native key image missing");
            };
            let spent: Value = serde_json::from_str(
                &rpc.rpc_call(
                    "is_key_image_spent",
                    Some(json!({"key_images":[hex(&key_image.to_bytes())]}).to_string()),
                    16384,
                )
                .await
                .map_err(|_| "XMR spentness unavailable")?,
            )
            .map_err(|_| "XMR spentness JSON")?;
            if xmr_key_image_unspent(&spent) {
                return Ok(Observation::AbsentAndUnspent);
            }
            return Ok(Observation::Unknown);
        };
        ensure(txs[0]["tx_hash"] == tx_hash, "XMR transaction identity")?;
        let native = rpc
            .transactions(&[tx.hash()])
            .await
            .map_err(|_| "XMR native bytes unavailable")?;
        ensure(
            native.len() == 1 && native[0].serialize() == tx.serialize(),
            "XMR native body mismatch",
        )?;
        if txs[0]["in_pool"].as_bool().ok_or("XMR pool flag")? {
            return Ok(Observation::InPool);
        }
        let height = number(&txs[0]["block_height"])?;
        ensure(height <= xmr_tip_height as u64, "XMR inclusion height")?;
        let block = rpc
            .block_by_number(usize::try_from(height).map_err(|_| "XMR height overflow")?)
            .await
            .map_err(|_| "XMR inclusion block unavailable")?;
        ensure(
            block.transactions.contains(&tx.hash()),
            "XMR canonical inclusion missing",
        )?;
        Ok(Observation::Included {
            block: block.hash(),
            height,
        })
    };
    let stable_tips = async || -> Result<()> {
        ensure(
            dom_rpc.identity(&checkpoint).await? == identity,
            "DOM tip changed during recovery",
        )?;
        ensure(
            rpc.latest_block_number()
                .await
                .map_err(|_| "XMR final tip unavailable")?
                == xmr_tip_height
                && rpc
                    .block_by_number(xmr_tip_height)
                    .await
                    .map_err(|_| "XMR final tip block unavailable")?
                    .hash()
                    == xmr_tip,
            "XMR tip changed during recovery",
        )
    };
    let (first_observation, mut dom_index_missing, witness) = if manifest.dom_first {
        let tx = decode_dom(&first)?;
        let mut secret = dom
            .extract(&tx, &context)
            .map_err(|_| "DOM first claim verification")?;
        secret.reverse();
        let witness = Zeroizing::new(
            Option::<curve25519_dalek::scalar::Scalar>::from(
                curve25519_dalek::scalar::Scalar::from_canonical_bytes(*secret),
            )
            .ok_or("noncanonical extracted witness")?,
        );
        let (observed, missing) = dom_rpc.observe(&tx, &identity, false).await?;
        (observed, missing, witness)
    } else {
        let tx = decode_xmr(&first)?;
        let witness = xmr
            .extract(&tx, &mut OsRng)
            .map_err(|_| "XMR first claim verification")?;
        (observe_xmr(&tx, false).await?, false, witness)
    };
    let Observation::Included { block, height } = first_observation else {
        return Err("first payment not canonical");
    };
    stable_tips().await?;
    let binding = DeliveryBinding {
        manifest: checkpoint.manifest,
        first_claim: digest(&first),
        first_block: block,
        first_height: height,
        target_chain: if manifest.dom_first {
            checkpoint.xmr_genesis
        } else {
            checkpoint.dom_chain
        },
    };
    let path = root.join("counterpart-delivery.wal");
    let exists = path.try_exists().map_err(|_| "delivery journal lookup")?;
    if action == "crash-before-obligation" {
        ensure(!exists, "crash fixture already has obligation")?;
        // Actual process exit after native inclusion verification, before ANY
        // post-inclusion artifact/obligation is created. Nodes remain in host.
        progress.dom_rpc.log();
        std::process::exit(75);
    }
    let mut created = false;
    let mut journal = if exists {
        // The EXACT first transaction was just reverified in the canonical
        // chain. A new inclusion location changes the observation, not the
        // operation or the already-created economic obligation.
        CounterpartDelivery::open_for_payment(&path, binding.payment())
            .map_err(|_| "delivery journal invalid or binding changed")?
    } else {
        ensure(
            action == "reconstruct",
            "missing obligation requires reconstruction",
        )?;
        // Only complete the fixed approved adaptor after native first payment.
        // Existing journals never take this path: no replacement or new nonce.
        let payload = if manifest.dom_first {
            xmr.complete(&witness, &mut OsRng)
                .map_err(|_| "XMR counterpart completion")?
                .serialize()
        } else {
            let mut bytes = Zeroizing::new(witness.to_bytes());
            bytes.reverse();
            dom.complete(
                &dom_scriptless_primitives::SecretScalar::from_be_bytes(*bytes)
                    .map_err(|_| "DOM witness")?,
                &context,
            )
            .map_err(|_| "DOM counterpart completion")?
            .to_bytes()
            .map_err(|_| "DOM counterpart encoding")?
        };
        stable_tips().await?;
        let journal = CounterpartDelivery::create(&path, binding, &payload)
            .map_err(|_| "obligation creation failed")?;
        created = true;
        journal
    };
    // Also validate a pre-existing journal against the approved envelope and
    // first payment. A checksum alone is never payment authorization.
    let mut target_observation = if manifest.dom_first {
        let tx = decode_xmr(journal.payload())?;
        let extracted = xmr
            .extract(&tx, &mut OsRng)
            .map_err(|_| "stored XMR counterpart verification")?;
        ensure(*extracted == *witness, "counterpart witness mismatch")?;
        if action == "observe" || inspect_unspent {
            observe_xmr(&tx, inspect_unspent).await?
        } else {
            Observation::Unknown
        }
    } else {
        let tx = decode_dom(journal.payload())?;
        let mut extracted = dom
            .extract(&tx, &context)
            .map_err(|_| "stored DOM counterpart verification")?;
        extracted.reverse();
        ensure(
            *extracted == witness.to_bytes(),
            "counterpart witness mismatch",
        )?;
        if action == "observe" || inspect_unspent {
            let (observed, missing) = dom_rpc.observe(&tx, &identity, inspect_unspent).await?;
            dom_index_missing |= missing;
            observed
        } else {
            Observation::Unknown
        }
    };
    drop(witness);
    stable_tips().await?;
    let mut exposed = journal
        .possibly_exposed()
        .map_err(|_| "delivery journal state")?;
    let decision = if action == "reconstruct" {
        // Reconstruction never restores privacy or grants send permission.
        // An exposed existing obligation still requires fresh reconciliation.
        if exposed {
            "Reconcile".to_string()
        } else {
            "CounterpartPrepared".to_string()
        }
    } else {
        ensure(exposed || inspect_unspent, "journal not yet exposed")?;
        let mut decision = journal
            .reconcile(
                binding.target_chain,
                journal.payload_digest(),
                target_observation,
            )
            .map_err(|_| "delivery reconciliation")?;
        ensure(
            matches!(
                decision,
                DeliveryAction::Reconcile
                    | DeliveryAction::MonitorPool
                    | DeliveryAction::MonitorInclusion
                    | DeliveryAction::RetryExactBytes
            ),
            "unexpected retry permission",
        )?;
        if decision == DeliveryAction::RetryExactBytes && is_send(action) {
            let frozen = journal
                .prepare_attempt(
                    binding.target_chain,
                    journal.payload_digest(),
                    target_observation,
                )
                .map_err(|_| "durable exposure failed")?
                .to_vec();
            exposed = true;
            if action == "send-crash-before-rpc" {
                progress.dom_rpc.log();
                std::process::exit(77);
            }
            // Account for storage latency by querying again after fsync. These
            // are owned, offline nodes, with their fixture miner idle here;
            // sequential RPCs are not a hostile-node atomic snapshot proof.
            stable_tips().await?;
            target_observation = if manifest.dom_first {
                observe_xmr(&decode_xmr(&frozen)?, true).await?
            } else {
                dom_rpc
                    .observe(&decode_dom(&frozen)?, &identity, true)
                    .await?
                    .0
            };
            stable_tips().await?;
            decision = journal
                .reconcile(binding.target_chain, digest(&frozen), target_observation)
                .map_err(|_| "post-fsync reconciliation")?;
            if decision == DeliveryAction::RetryExactBytes {
                progress.attempted.set(true);
                if manifest.dom_first {
                    let reply:Value=serde_json::from_str(&rpc.rpc_call("send_raw_transaction",
                        Some(json!({"tx_as_hex":hex(&frozen),"do_not_relay":true,"do_sanity_checks":false}).to_string()),16384)
                        .await.map_err(|_| "XMR submission result unknown")?).map_err(|_| "XMR admission JSON")?;
                    ensure(reply["status"] == "OK", "XMR native admission rejected")?;
                } else {
                    dom_rpc.submit(&frozen).await?;
                }
                progress.acknowledged.set(true);
                // Native RPC replied successfully. Exit before returning any
                // result to the supervisor or persisting an admission receipt.
                // This is lost process state, NOT a dropped native RPC reply.
                if action == "send-crash-after-admission" {
                    progress.dom_rpc.log();
                    std::process::exit(76);
                }
                "Submitted".to_string()
            } else {
                format!("{decision:?}")
            }
        } else {
            format!("{decision:?}")
        }
    };
    let original_binding = journal.binding();
    Ok(
        json!({"action":decision,"journal_verified":true,"first_payment_verified_from_native_rpc":true,
        "native_rpc_queries_performed":true,"dom_tx_index_missing_kernel_scan_used":dom_index_missing,
        "operation_checkpoint_loaded":true,"original_disclosed_at":manifest.disclosed_at,
        "original_earliest_adversarial":manifest.earliest_adversarial,"original_latest_honest":manifest.latest_honest,
        "first_block":hex(&block),"first_height":height,"target_observation":format!("{target_observation:?}"),
        "original_first_block":hex(&original_binding.first_block),"original_first_height":original_binding.first_height,
        "first_payment_reincluded":original_binding.first_block != block || original_binding.first_height != height,
        "obligation_created":created,"fixed_adaptor_completed":created,"possibly_exposed":exposed,
        "post_inclusion_claim_files_used":false,"initial_exposure_journal_verified":true}),
    )
}

fn decode_dom(bytes: &[u8]) -> Result<DomTransaction> {
    let tx = DomTransaction::from_bytes(bytes).map_err(|_| "DOM native decoding")?;
    ensure(
        tx.to_bytes().map_err(|_| "DOM native encoding")? == bytes,
        "DOM noncanonical transaction",
    )?;
    Ok(tx)
}
fn decode_xmr(bytes: &[u8]) -> Result<XmrTransaction> {
    let mut input = bytes;
    let tx = XmrTransaction::read(&mut input).map_err(|_| "XMR native decoding")?;
    ensure(
        input.is_empty() && tx.serialize() == bytes,
        "XMR noncanonical transaction",
    )?;
    Ok(tx)
}

pub async fn worker(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let root = PathBuf::from(args.next().expect("checkpoint root"));
    let operation: [u8; 32] = unhex(&args.next().expect("operation ID").into_string().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let action = args.next().expect("recovery action").into_string().unwrap();
    assert!(matches!(
        action.as_str(),
        "observe"
            | "reconstruct"
            | "crash-before-obligation"
            | "inspect-delivery"
            | "send"
            | "send-crash-before-rpc"
            | "send-crash-after-admission"
    ));
    assert!(args.next().is_none());
    let progress = SendProgress::default();
    let mut result = match tokio::time::timeout(
        Duration::from_secs(10),
        recover(&root, operation, &action, &progress),
    )
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(reason)) => {
            json!({"action":"Reconcile","reason":reason,"journal_verified":false})
        }
        Err(_) => {
            json!({"action":"Reconcile","reason":"recovery deadline","journal_verified":false})
        }
    };
    result["pid"] = json!(std::process::id());
    // An error after creation may leave a durable obligation. Do not claim
    // that completion did not happen when the operation's result is unknown.
    result["signature_created"] = if action != "reconstruct" {
        json!(false)
    } else {
        result
            .get("fixed_adaptor_completed")
            .cloned()
            .unwrap_or(Value::Null)
    };
    result["new_signing_round_or_nonce"] = json!(false);
    result["transaction_sent"] = if progress.acknowledged.get() {
        json!(true)
    } else if progress.attempted.get() {
        Value::Null
    } else {
        json!(false)
    };
    result["transaction_send_attempted"] = json!(progress.attempted.get());
    result["native_admission_ack_received"] = json!(progress.acknowledged.get());
    result["dom_rpc"] = progress.dom_rpc.value();
    progress.dom_rpc.log();
    println!("{}", serde_json::to_string(&result).unwrap());
}

struct OwnedWorker(Child);
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub async fn observe_in_fresh_process(root: &Path, operation: [u8; 32]) -> Value {
    let mut observation = run_worker(root, operation, "observe", 0).await;
    if observation["action"] == "MonitorPool" {
        let before = read(&root.join("counterpart-delivery.wal")).unwrap();
        let reconstructed = run_worker(root, operation, "reconstruct", 0).await;
        assert_eq!(reconstructed["action"], "Reconcile", "{reconstructed}");
        assert_eq!(reconstructed["possibly_exposed"], true);
        assert_eq!(reconstructed["signature_created"], false);
        assert_eq!(reconstructed["obligation_created"], false);
        assert_eq!(
            read(&root.join("counterpart-delivery.wal")).unwrap(),
            before
        );
        observation["reconstruction_after_exposure"] = reconstructed;
    }
    observation
}

pub async fn assert_pending_first_cannot_create_obligation(
    root: &Path,
    operation: [u8; 32],
) -> Value {
    assert!(!root.join("counterpart-delivery.wal").exists());
    let result = run_worker(root, operation, "reconstruct", 0).await;
    assert_eq!(result["action"], "Reconcile", "{result}");
    assert_eq!(result["reason"], "first payment not canonical", "{result}");
    assert!(!root.join("counterpart-delivery.wal").exists());
    result
}

/// The worker decides and performs both native RPC sends. The host supplies
/// no tx bytes, binding, chain interpretation, RPC endpoint or credential.
pub async fn native_send_after_restart(root: &Path, operation: [u8; 32]) -> Value {
    let began = Instant::now();
    let before_send = run_worker(root, operation, "send-crash-before-rpc", 77).await;
    let exposed_bytes = read(&root.join("counterpart-delivery.wal")).unwrap();
    let absent = run_worker(root, operation, "inspect-delivery", 0).await;
    assert_eq!(absent["action"], "RetryExactBytes", "{absent}");
    assert_eq!(absent["target_observation"], "AbsentAndUnspent");
    assert_eq!(absent["possibly_exposed"], true);
    assert_eq!(absent["transaction_send_attempted"], false);
    let admitted = run_worker(root, operation, "send-crash-after-admission", 76).await;
    assert_eq!(
        read(&root.join("counterpart-delivery.wal")).unwrap(),
        exposed_bytes
    );
    json!({"counterpart_sender_exit":76,"counterpart_sender_pid":admitted["pid"],
        "counterpart_delivery_seconds":began.elapsed().as_secs_f64(),
        "counterpart_native_send_workers":[before_send,absent,admitted],
        "counterpart_native_rpc_send_by_restored_worker":true,
        "counterpart_sender_receives_native_ack_before_exit":true,
        "counterpart_native_admission_result_not_returned_to_parent":true,
        "counterpart_host_forwards_payload":false,
        "counterpart_bytes_fsynced_before_send":true,"counterpart_exposure_fsynced_before_send":true,
        "counterpart_signature_recreated_after_send":false,"counterpart_pending_retry_dispatched":false,
        "full_coordinator_restart_exercised":false})
}

/// Request delivery again in pool/block/unavailable states. The restarted
/// coordinator must decide from RPCs and must not send in these cases.
pub async fn retry_absent_counterpart_in_fresh_process(root: &Path, operation: [u8; 32]) -> Value {
    let before = read(&root.join("counterpart-delivery.wal")).unwrap();
    let inspection = run_worker(root, operation, "inspect-delivery", 0).await;
    assert_eq!(inspection["action"], "RetryExactBytes", "{inspection}");
    assert_eq!(inspection["target_observation"], "AbsentAndUnspent");
    assert_eq!(inspection["possibly_exposed"], true);
    assert_eq!(inspection["transaction_send_attempted"], false);
    let sent = run_worker(root, operation, "send", 0).await;
    assert_eq!(sent["action"], "Submitted", "{sent}");
    assert_eq!(sent["transaction_send_attempted"], true);
    assert_eq!(sent["native_admission_ack_received"], true);
    assert_eq!(sent["signature_created"], false);
    assert_eq!(
        read(&root.join("counterpart-delivery.wal")).unwrap(),
        before
    );
    json!({"inspection":inspection,"sender":sent})
}

pub async fn expose_before_first_detachment(root: &Path, operation: [u8; 32]) -> Value {
    run_worker(root, operation, "send-crash-before-rpc", 77).await
}

pub async fn assert_noncanonical_first_preserves_obligation(
    root: &Path,
    operation: [u8; 32],
) -> Value {
    let path = root.join("counterpart-delivery.wal");
    let before = read(&path).unwrap();
    let mut results = Vec::new();
    for action in ["send", "reconstruct"] {
        let result = run_worker(root, operation, action, 0).await;
        assert_eq!(result["action"], "Reconcile", "{result}");
        assert_eq!(result["reason"], "first payment not canonical", "{result}");
        assert_eq!(result["transaction_send_attempted"], false);
        assert_eq!(read(&path).unwrap(), before);
        results.push(result);
    }
    json!(results)
}

pub async fn assert_first_reincluded(
    root: &Path,
    operation: [u8; 32],
    original_block: [u8; 32],
    original_height: u64,
    current_block: [u8; 32],
    current_height: u64,
) -> Value {
    let path = root.join("counterpart-delivery.wal");
    let before = read(&path).unwrap();
    let result = run_worker(root, operation, "reconstruct", 0).await;
    assert_eq!(result["action"], "Reconcile", "{result}");
    assert_eq!(result["journal_verified"], true);
    assert_eq!(result["first_payment_reincluded"], true);
    assert_eq!(result["original_first_block"], hex(&original_block));
    assert_eq!(result["original_first_height"], original_height);
    assert_eq!(result["first_block"], hex(&current_block));
    assert_eq!(result["first_height"], current_height);
    assert_eq!(result["possibly_exposed"], true);
    assert_eq!(result["obligation_created"], false);
    assert_eq!(result["signature_created"], false);
    assert_eq!(result["transaction_send_attempted"], false);
    assert_eq!(read(&path).unwrap(), before);
    result
}

pub async fn assert_native_send_suppressed(
    root: &Path,
    operation: [u8; 32],
    expected: &str,
) -> Value {
    let before = read(&root.join("counterpart-delivery.wal")).unwrap();
    let result = run_worker(root, operation, "send", 0).await;
    assert_eq!(result["action"], expected, "{result}");
    assert_eq!(result["transaction_send_attempted"], false, "{result}");
    assert_eq!(result["signature_created"], false);
    assert_eq!(
        read(&root.join("counterpart-delivery.wal")).unwrap(),
        before
    );
    result
}

async fn run_worker(root: &Path, operation: [u8; 32], action: &str, expected_exit: i32) -> Value {
    let began = Instant::now();
    let mut child = OwnedWorker(
        Command::new(std::env::current_exe().unwrap())
            .arg("--settlement-resume-worker")
            .arg(root)
            .arg(hex(&operation))
            .arg(action)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let exit_code = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status.code();
        }
        assert!(
            began.elapsed() < Duration::from_secs(15),
            "owned recovery worker timeout"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let mut bytes = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .take(8193)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8192);
    assert_eq!(
        exit_code,
        Some(expected_exit),
        "worker {action}: {}",
        String::from_utf8_lossy(&bytes)
    );
    if matches!(expected_exit, 75..=77) {
        assert!(bytes.is_empty());
        return json!({"pid":pid,"exit_code":expected_exit,"seconds":began.elapsed().as_secs_f64()});
    }
    let mut result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["pid"], pid);
    result["seconds"] = json!(began.elapsed().as_secs_f64());
    result
}

/// Host test expectations are used only to check the resulting durable journal;
/// none of this binding or an interpreted chain observation enters the worker.
pub async fn crash_then_reconstruct(
    root: &Path,
    operation: [u8; 32],
    expected: DeliveryBinding,
) -> (Vec<u8>, Value) {
    let started = Instant::now();
    let path = root.join("counterpart-delivery.wal");
    assert!(!path.exists());
    for name in ["observed.tx", "counterpart.tx"] {
        assert!(!root.join("claim-resume").join(name).exists());
    }
    let crash = run_worker(root, operation, "crash-before-obligation", 75).await;
    assert!(!path.exists());
    let created = run_worker(root, operation, "reconstruct", 0).await;
    assert_eq!(created["action"], "CounterpartPrepared", "{created}");
    assert_eq!(created["obligation_created"], true);
    assert_eq!(created["initial_exposure_journal_verified"], true);
    let journal = CounterpartDelivery::open(&path, expected).unwrap();
    assert!(!journal.possibly_exposed().unwrap());
    let payload = journal.payload().to_vec();
    drop(journal);
    let before = read(&path).unwrap();
    let reused = run_worker(root, operation, "reconstruct", 0).await;
    assert_eq!(reused["action"], "CounterpartPrepared", "{reused}");
    assert_eq!(reused["obligation_created"], false);
    assert_eq!(reused["signature_created"], false);
    assert_eq!(read(&path).unwrap(), before);
    for name in ["observed.tx", "counterpart.tx"] {
        assert!(!root.join("claim-resume").join(name).exists());
    }
    let evidence = json!({
        "claim_worker_crash_exit":75,"claim_worker_restart_exit":0,
        "claim_worker_pids":[crash["pid"],created["pid"],reused["pid"]],
        "claim_worker_seconds":started.elapsed().as_secs_f64(),
        "claim_records_synced_before_initial_claim":true,"initial_claim_bytes_synced_before_publication":true,
        "worker_receives_original_witness":false,"worker_receives_signing_keys_or_nonces":false,
        "worker_queries_chain_independently":true,"post_inclusion_claim_files_used":false,
        "obligation_reconstructed_after_exit_before_journal_creation":true,
        "existing_obligation_reused_without_signature_recreation":true,
        "claim_reconstruction_workers":[crash,created,reused],"full_executor_restart_exercised":false
    });
    (payload, evidence)
}

#[cfg(test)]
mod native_observation_tests {
    use super::*;

    #[test]
    fn coherent_dom_scan_rejects_stale_tip_parent_partial_range_and_changed_native_body() {
        let raw = b"approved native bytes";
        let block = [3; 32];
        let parent = [2; 32];
        let identity = json!({"network":"regtest","chain_id":hex(&[5;32]),"genesis_hash":hex(&[6;32]),"tip_height":9,"tip_hash":hex(&[9;32])});
        let mut scan_identity = identity.clone();
        scan_identity["network_magic"] = json!(dom_core::NETWORK_MAGIC_REGTEST);
        let valid = json!({"schema_version":1,"status":"ok","canonical":true,
            "requested_from":7,"requested_to":7,"served_from":7,"served_to":7,
            "request_anchor":{"height":6,"block_hash":hex(&parent)},"identity":scan_identity,
            "blocks":[{"height":7,"block_hash":hex(&block),"previous_block_hash":hex(&parent),
            "transactions":[{"tx_hash":hex(dom_crypto::blake2b_256(raw).as_bytes()),
                "block_height":7,"block_hash":hex(&block),"canonical_bytes":hex(raw)}]}]});
        assert!(verify_dom_inclusion(&valid, &identity, raw, 7, block, parent).is_ok());
        for (pointer, replacement) in [
            ("/canonical", json!(false)),
            ("/served_to", Value::Null),
            ("/requested_from", json!(6)),
            ("/identity/tip_hash", json!(hex(&[8; 32]))),
            ("/identity/genesis_hash", json!(hex(&[8; 32]))),
            ("/identity/network_magic", json!(0)),
            ("/request_anchor/block_hash", json!(hex(&[8; 32]))),
            ("/blocks/0/previous_block_hash", json!(hex(&[8; 32]))),
            ("/blocks/0/block_hash", json!(hex(&[8; 32]))),
            (
                "/blocks/0/transactions/0/canonical_bytes",
                json!(hex(b"changed native bytes")),
            ),
            ("/blocks/0/transactions/0/block_height", json!(8)),
            ("/blocks/0/transactions", json!([])),
            ("/blocks", json!([])),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                verify_dom_inclusion(&changed, &identity, raw, 7, block, parent).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn throttle_hint_requires_bounded_unambiguous_integer_delay() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        assert!(throttle_delay(&headers).is_none());
        headers.insert("x-ratelimit-after", HeaderValue::from_static("0"));
        assert_eq!(throttle_delay(&headers), Some(Duration::from_secs(1)));
        headers.insert("retry-after", HeaderValue::from_static("2"));
        assert_eq!(throttle_delay(&headers), Some(Duration::from_secs(2)));
        for invalid in ["3", "-1", "1.5", "forever", "18446744073709551615"] {
            headers.insert("retry-after", HeaderValue::from_str(invalid).unwrap());
            assert!(throttle_delay(&headers).is_none());
        }
        headers.remove("retry-after");
        headers.append("x-ratelimit-after", HeaderValue::from_static("0"));
        assert!(throttle_delay(&headers).is_none());
    }

    // Small owned HTTP server: assertions exercise the real reqwest transport,
    // including request count/method, rather than a fabricated Observation.
    fn scripted_http(
        replies: Vec<(&'static str, &'static str, &'static str)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for (status, headers, body) in replies {
                let until = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "expected HTTP request not received");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 1024];
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0 && request.len() + n <= 16384);
                    request.extend_from_slice(&chunk[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let text = std::str::from_utf8(&request[..end]).unwrap();
                        let length = text
                            .lines()
                            .filter_map(|s| s.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            lines.push(text.lines().next().unwrap().to_string());
                            break;
                        }
                    }
                }
                write!(stream, "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).unwrap();
            }
            lines
        });
        (base, worker)
    }
    fn test_rpc(base: String, metrics: &RpcMetrics) -> DomRpc<'_> {
        DomRpc {
            base,
            token: "disposable-test-token".into(),
            metrics,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn throttled_read_repeats_read_and_counts_wait_before_using_fresh_response() {
        let (base, server) = scripted_http(vec![
            (
                "429 Too Many Requests",
                "x-ratelimit-after: 0\r\n",
                "limited",
            ),
            ("200 OK", "", "{\"found\":false}"),
        ]);
        let metrics = RpcMetrics::default();
        let rpc = test_rpc(base, &metrics);
        assert_eq!(rpc.get("/tx/test").await.unwrap(), json!({"found":false}));
        assert_eq!(
            server.join().unwrap(),
            ["GET /tx/test HTTP/1.1", "GET /tx/test HTTP/1.1"]
        );
        assert_eq!(metrics.authenticated_read_attempts.get(), 2);
        assert_eq!(metrics.throttle_retries.get(), 1);
        assert_eq!(metrics.wait_requested_ms.get(), 1000);
        assert!(metrics.wait_elapsed_ms.get() >= 1000);
        assert_eq!(metrics.submit_attempts.get(), 0);
    }

    #[tokio::test]
    async fn throttle_budget_is_shared_across_routes_and_exhaustion_never_submits() {
        let limited = (
            "429 Too Many Requests",
            "x-ratelimit-after: 0\r\n",
            "limited",
        );
        let ok = ("200 OK", "", "{}");
        let (base, server) = scripted_http(vec![limited, ok, limited, ok, limited]);
        let metrics = RpcMetrics::default();
        let rpc = test_rpc(base, &metrics);
        rpc.get("/chain/identity").await.unwrap();
        rpc.get("/block/6").await.unwrap();
        assert_eq!(
            rpc.get("/block/7").await.unwrap_err(),
            "DOM RPC rate limited"
        );
        assert_eq!(server.join().unwrap().len(), 5);
        assert_eq!(metrics.public_read_attempts.get(), 5);
        assert_eq!(metrics.throttle_retries.get(), 2);
        assert_eq!(metrics.wait_requested_ms.get(), 2000);
        assert_eq!(metrics.submit_attempts.get(), 0);
    }

    #[tokio::test]
    async fn cancelling_recovery_during_throttle_counts_partial_wait_without_retry() {
        let (base, server) = scripted_http(vec![(
            "429 Too Many Requests",
            "x-ratelimit-after: 0\r\n",
            "limited",
        )]);
        let metrics = RpcMetrics::default();
        let rpc = test_rpc(base, &metrics);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rpc.get("/chain/identity"))
                .await
                .is_err()
        );
        assert_eq!(server.join().unwrap(), ["GET /chain/identity HTTP/1.1"]);
        assert_eq!(metrics.public_read_attempts.get(), 1);
        assert_eq!(metrics.wait_requested_ms.get(), 1000);
        assert!(metrics.wait_elapsed_ms.get() > 0);
        assert_eq!(metrics.submit_attempts.get(), 0);
    }

    #[tokio::test]
    async fn post_or_unbounded_throttle_or_other_status_is_never_automatically_repeated() {
        for (method, status, headers) in [
            (
                reqwest::Method::POST,
                "429 Too Many Requests",
                "x-ratelimit-after: 0\r\n",
            ),
            (
                reqwest::Method::GET,
                "429 Too Many Requests",
                "Retry-After: 3600\r\n",
            ),
            (
                reqwest::Method::GET,
                "503 Service Unavailable",
                "Retry-After: 1\r\n",
            ),
        ] {
            let (base, server) = scripted_http(vec![(status, headers, "busy")]);
            let metrics = RpcMetrics::default();
            assert!(test_rpc(base, &metrics)
                .request(method.clone(), "/tx/submit", Some(json!({})), false)
                .await
                .is_err());
            assert_eq!(
                server.join().unwrap(),
                [format!("{method} /tx/submit HTTP/1.1")]
            );
            assert_eq!(metrics.throttle_retries.get(), 0);
            assert_eq!(metrics.wait_requested_ms.get(), 0);
        }
    }

    #[test]
    fn dom_missing_tx_needs_exact_mature_native_input_at_observed_tip() {
        let valid = json!({"found":true,"commitment":"expected","is_mature":true,"is_coinbase":false,"block_height":7});
        assert!(dom_unspent_matches(&valid, "expected", 7));
        assert!(!dom_unspent_matches(&json!({"found":false}), "expected", 7));
        for (field, value) in [
            ("commitment", json!("other")),
            ("is_mature", json!(false)),
            ("is_coinbase", json!(true)),
            ("block_height", json!(8)),
            ("found", json!(false)),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(!dom_unspent_matches(&changed, "expected", 7), "{field}");
        }
    }

    #[test]
    fn xmr_absence_requires_exact_missed_id_without_partial_or_untrusted_results() {
        let valid = json!({"status":"OK","missed_tx":["expected"],"txs":[],"untrusted":false});
        assert!(xmr_exactly_missing(&valid, "expected"));
        for (field, value) in [
            ("status", json!("BUSY")),
            ("missed_tx", json!(["other"])),
            ("missed_tx", json!([])),
            ("txs", json!([{"tx_hash":"expected"}])),
            ("txs", json!({})),
            ("untrusted", json!(true)),
            ("untrusted", json!("false")),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(!xmr_exactly_missing(&changed, "expected"), "{field}");
        }
    }

    #[test]
    fn spent_or_pending_key_image_and_incomplete_rpc_never_authorize_send() {
        assert!(xmr_key_image_unspent(
            &json!({"status":"OK","spent_status":[0]})
        ));
        for result in [
            json!({"spent_status":[0]}),
            json!({"status":"BUSY","spent_status":[0]}),
            json!({"status":"OK","spent_status":[1]}),
            json!({"status":"OK","spent_status":[2]}),
            json!({"status":"OK","spent_status":[]}),
            json!({"status":"OK","spent_status":[0,0]}),
            json!({"status":"OK","spent_status":[0],"untrusted":true}),
        ] {
            assert!(!xmr_key_image_unspent(&result), "{result}");
        }
    }
}
