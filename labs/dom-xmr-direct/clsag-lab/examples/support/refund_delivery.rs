//! Private-abandonment refund delivery on owned offline nodes only. A pinned
//! job, exclusive RecoveryOnly gate and frozen signature are required. Native
//! observations come from the worker's RPC, never the supervisor's report.
//! Trusted local storage/node and no undetected ABA reorg are assumptions.
use super::refund_recovery_worker::{read_private, write_private, Job};
use dxp1_clsag_lab::{
    counterpart_delivery::Observation,
    native::PreparedClaim,
    preparation_gate::{PreparationBinding, PreparationGate},
};
use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};
use monero_wallet::transaction::{Input, Transaction};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const MAGIC: &[u8] = b"DXP1/owned-refund-network/v1\0";
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Network {
    pub port: u16,
    pub genesis: [u8; 32],
    pub anchor_height: u64,
    pub anchor: [u8; 32],
}
impl Network {
    pub fn persist(&self, root: &Path) -> [u8; 32] {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.port.to_le_bytes());
        bytes.extend(self.genesis);
        bytes.extend(self.anchor_height.to_le_bytes());
        bytes.extend(self.anchor);
        write_private(&root.join("refund-network.record"), &bytes);
        Sha256::digest(bytes).into()
    }
    fn load(root: &Path, expected: [u8; 32]) -> Self {
        let bytes = read_private(&root.join("refund-network.record"));
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&*bytes)), expected);
        let raw = bytes.strip_prefix(MAGIC).unwrap();
        assert_eq!(raw.len(), 74);
        let value = Self {
            port: u16::from_le_bytes(raw[..2].try_into().unwrap()),
            genesis: raw[2..34].try_into().unwrap(),
            anchor_height: u64::from_le_bytes(raw[34..42].try_into().unwrap()),
            anchor: raw[42..].try_into().unwrap(),
        };
        assert_ne!(value.port, 0);
        assert_ne!(value.genesis, [0; 32]);
        assert_ne!(value.anchor, [0; 32]);
        value
    }
}

fn local_ok(value: &Value) -> bool {
    value["status"] == "OK" && value["untrusted"] == false
}
fn exactly_missing(value: &Value, hash: &str) -> bool {
    local_ok(value)
        && value["missed_tx"] == json!([hash])
        && (value["txs"].is_null() || value["txs"].as_array().is_some_and(Vec::is_empty))
}
fn unspent(value: &Value) -> bool {
    local_ok(value) && value["spent_status"] == json!([0])
}
fn send_allowed(observation: Observation, received: u64, latest: u64, now: u64) -> bool {
    observation == Observation::AbsentAndUnspent && received <= now && now <= latest
}
async fn request(rpc: &MoneroDaemon<SimpleRequestTransport>, method: &str, args: Value) -> Value {
    serde_json::from_str(
        &rpc.rpc_call(method, Some(args.to_string()), 2 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}
async fn tip(rpc: &MoneroDaemon<SimpleRequestTransport>) -> (usize, [u8; 32]) {
    let height = rpc.latest_block_number().await.unwrap();
    (height, rpc.block_by_number(height).await.unwrap().hash())
}
async fn observe(
    rpc: &MoneroDaemon<SimpleRequestTransport>,
    tx: &Transaction,
    height: usize,
) -> Observation {
    let hash = hex(&tx.hash());
    let info = request(rpc, "get_transactions", json!({"txs_hashes":[hash]})).await;
    assert!(
        local_ok(&info),
        "untrusted or malformed transaction response"
    );
    let Some(txs) = info["txs"].as_array().filter(|v| v.len() == 1) else {
        if !exactly_missing(&info, &hash) {
            return Observation::Unknown;
        }
        let [Input::ToKey { key_image, .. }] = tx.prefix().inputs.as_slice() else {
            panic!("input");
        };
        let spent = request(
            rpc,
            "is_key_image_spent",
            json!({"key_images":[hex(&key_image.to_bytes())]}),
        )
        .await;
        return if unspent(&spent) {
            Observation::AbsentAndUnspent
        } else {
            Observation::Unknown
        };
    };
    assert_eq!(txs[0]["tx_hash"], hash);
    assert!(info["missed_tx"].is_null() || info["missed_tx"] == json!([]));
    let native = rpc.transactions(&[tx.hash()]).await.unwrap();
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].serialize(), tx.serialize());
    if txs[0]["in_pool"].as_bool().unwrap() {
        return Observation::InPool;
    }
    let included = txs[0]["block_height"].as_u64().unwrap();
    assert!(included <= height as u64);
    let block = rpc
        .block_by_number(usize::try_from(included).unwrap())
        .await
        .unwrap();
    assert!(block.transactions.contains(&tx.hash()));
    Observation::Included {
        block: block.hash(),
        height: included,
    }
}
async fn check_ring(
    rpc: &MoneroDaemon<SimpleRequestTransport>,
    tx: &Transaction,
    prepared: &PreparedClaim,
    height: usize,
) {
    let [Input::ToKey { key_offsets, .. }] = tx.prefix().inputs.as_slice() else {
        panic!("input");
    };
    let mut index = 0u64;
    let outputs: Vec<_> = key_offsets
        .iter()
        .map(|offset| {
            index = index.checked_add(*offset).unwrap();
            json!({"amount":0,"index":index})
        })
        .collect();
    let data = request(rpc, "get_outs", json!({"outputs":outputs,"get_txid":false})).await;
    assert!(local_ok(&data));
    let outs = data["outs"].as_array().unwrap();
    assert_eq!(outs.len(), prepared.context().ring.len());
    for (out, pair) in outs.iter().zip(prepared.context().ring) {
        assert_eq!(out["key"], hex(&pair[0].compress().to_bytes()));
        assert_eq!(out["mask"], hex(&pair[1].compress().to_bytes()));
        assert_eq!(out["unlocked"], true);
        assert!(out["height"].as_u64().unwrap() <= height as u64);
    }
}

async fn deliver(root: &Path, expected: [u8; 32], action: &str) -> Value {
    assert!(matches!(
        action,
        "send" | "send-crash-before-rpc" | "send-crash-after-ack" | "inspect"
    ));
    let job = Job::load(root, expected);
    let mut gate = PreparationGate::open(
        &root.join("preparation.wal"),
        PreparationBinding {
            capsule_link: job.link,
            received: job.received,
        },
    )
    .unwrap();
    gate.claim_recovery(expected)
        .expect("private refund not authorized");
    let network = Network::load(root, job.network);
    let prepared = job.prepared();
    let bytes = read_private(&root.join("refund-signed.tx"));
    let mut input = bytes.as_slice();
    let tx = Transaction::read(&mut input).unwrap();
    assert!(input.is_empty());
    assert_eq!(tx.serialize(), *bytes);
    prepared.verify_final(&tx, &mut OsRng).unwrap();
    let rpc = SimpleRequestTransport::with_custom_timeout(
        format!("http://127.0.0.1:{}", network.port),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let info: Value =
        serde_json::from_str(&rpc.json_rpc_call("get_info", None, 16384).await.unwrap()).unwrap();
    assert!(local_ok(&info) && info["offline"] == true && info["nettype"] == "fakechain");
    assert_eq!(
        rpc.block_by_number(0).await.unwrap().hash(),
        network.genesis
    );
    let initial_tip = tip(&rpc).await;
    assert!(network.anchor_height <= initial_tip.0 as u64);
    assert_eq!(
        rpc.block_by_number(usize::try_from(network.anchor_height).unwrap())
            .await
            .unwrap()
            .hash(),
        network.anchor
    );
    check_ring(&rpc, &tx, &prepared, initial_tip.0).await;
    let observation = observe(&rpc, &tx, initial_tip.0).await;
    assert_eq!(
        tip(&rpc).await,
        initial_tip,
        "tip changed during refund observation"
    );
    let mut submitted = false;
    if action != "inspect"
        && send_allowed(observation, job.received, job.latest, super::unix_seconds())
    {
        // Fsync exact intent BEFORE any POST. Existence is not evidence of ACK.
        // An interrupted/partial file is never repaired or silently replaced.
        let mut intent = b"DXP1/private-refund-send/v1\0".to_vec();
        intent.extend(expected);
        intent.extend(Sha256::digest(&*bytes));
        let path = root.join("refund-send.intent");
        if path.try_exists().unwrap() {
            assert_eq!(*read_private(&path), intent);
        } else {
            write_private(&path, &intent);
        }
        if action == "send-crash-before-rpc" {
            std::process::exit(80);
        }
        let again = observe(&rpc, &tx, initial_tip.0).await;
        assert_eq!(
            tip(&rpc).await,
            initial_tip,
            "tip changed before refund send"
        );
        assert!(
            send_allowed(again, job.received, job.latest, super::unix_seconds()),
            "refund no longer sendable"
        );
        // Single POST per process; ambiguous network errors require a fresh
        // native reconciliation, never a blind HTTP retry or a new signature.
        let result = request(
            &rpc,
            "send_raw_transaction",
            json!({"tx_as_hex":hex(&bytes),"do_not_relay":true,"do_sanity_checks":false}),
        )
        .await;
        assert_eq!(result["status"], "OK");
        submitted = true;
        if action == "send-crash-after-ack" {
            std::process::exit(81);
        }
    }
    let result = json!({"pid":std::process::id(),"observation":format!("{observation:?}"),"submitted":submitted,
        "original_deadline":job.latest,"transaction":hex(&tx.hash()),"signed_bytes_sha256":hex(&Sha256::digest(&*bytes)),
        "anchor_checked":true,"native_ring_checked":true,"worker_has_no_signing_keys":true});
    drop(gate);
    result
}
pub async fn worker(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let root = PathBuf::from(args.next().unwrap());
    let raw = args.next().unwrap().into_string().unwrap();
    assert_eq!(raw.len(), 64);
    let expected = std::array::from_fn(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).unwrap());
    assert_eq!(hex(&expected), raw);
    let action = args.next().unwrap().into_string().unwrap();
    assert!(args.next().is_none());
    let report = tokio::time::timeout(Duration::from_secs(8), deliver(&root, expected, &action))
        .await
        .expect("refund delivery observation timeout");
    println!("{}", report);
}
pub fn run(root: &Path, expected: [u8; 32], action: &str) -> Value {
    let mut child = super::ManagedDaemon(
        Command::new(std::env::current_exe().unwrap())
            .arg("--xmr-refund-delivery-worker")
            .arg(root)
            .arg(hex(&expected))
            .arg(action)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    use std::io::Read;
    let mut text = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    let status = child.0.wait().unwrap();
    if matches!(action, "send-crash-before-rpc" | "send-crash-after-ack") {
        let expected_exit = if action == "send-crash-before-rpc" {
            80
        } else {
            81
        };
        assert_eq!(status.code(), Some(expected_exit));
        json!({"pid":pid,"exit_code":expected_exit})
    } else {
        assert!(status.success(), "refund delivery worker failed");
        let result: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(result["pid"], pid);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_or_conflicting_native_observation_never_authorizes_send() {
        let hash = hex(&[1; 32]);
        let missing = json!({"status":"OK","untrusted":false,"missed_tx":[hash]});
        assert!(exactly_missing(&missing, &hash));
        for (key, value) in [
            ("untrusted", json!(true)),
            ("status", json!("BUSY")),
            ("missed_tx", json!([])),
            ("txs", json!([{}])),
        ] {
            let mut bad = missing.clone();
            bad[key] = value;
            assert!(!exactly_missing(&bad, &hash));
        }
        for statuses in [json!([1]), json!([2]), json!([]), json!([0, 0])] {
            assert!(!unspent(
                &json!({"status":"OK","untrusted":false,"spent_status":statuses})
            ));
        }
        assert!(!unspent(&json!({"status":"OK","spent_status":[0]})));
        assert!(unspent(
            &json!({"status":"OK","untrusted":false,"spent_status":[0]})
        ));
        for state in [
            Observation::Unknown,
            Observation::InPool,
            Observation::Included {
                block: [1; 32],
                height: 1,
            },
        ] {
            assert!(!send_allowed(state, 100, 200, 150));
        }
        assert!(send_allowed(Observation::AbsentAndUnspent, 100, 200, 200));
        for now in [99, 201, u64::MAX] {
            assert!(!send_allowed(Observation::AbsentAndUnspent, 100, 200, now));
        }
    }
    #[test]
    fn network_checkpoint_is_pinned_to_original_job() {
        let root = std::env::temp_dir().join(format!("dxp1-refund-network-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let value = Network {
            port: 1234,
            genesis: [1; 32],
            anchor_height: 200,
            anchor: [2; 32],
        };
        let digest = value.persist(&root);
        assert_eq!(Network::load(&root, digest).anchor_height, 200);
        let path = root.join("refund-network.record");
        let bytes = read_private(&path);
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            std::fs::write(&path, &*changed).unwrap();
            assert!(std::panic::catch_unwind(|| Network::load(&root, digest)).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
