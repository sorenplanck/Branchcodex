//! Starts its OWN offline regtest daemon with an empty config and fresh data.
//! No RPC URL is accepted. All coins are created by local generateblocks calls.
//! The first observed claim unlocks its funded counterpart, in either direction.
//! Setup is centralized; recovery modes are isolated experiments, not an SLA.

#[path = "support/claim_resume_bridge.rs"]
mod claim_resume_bridge;
#[path = "support/counterpart_delivery_bridge.rs"]
mod counterpart_delivery_bridge;
#[path = "support/direct_recovery_bridge.rs"]
mod direct_recovery_bridge;
#[path = "support/dom_regtest.rs"]
mod dom_regtest;
#[path = "support/recovery_bridge.rs"]
mod recovery_bridge;
#[path = "support/settlement_resume.rs"]
mod settlement_resume;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dom_scriptless_primitives::SecretScalar;
use dom_serialization::{DomDeserialize, DomSerialize};
use dxp1_clsag_lab::{
    counterpart_delivery::{DeliveryAction, DeliveryBinding, Observation},
    dom_recovery::{DomRecoveryLink, DomRecoveryMaterial},
    dom_reserve::{ReserveIntent, ReserveShare},
    joint::{JointParticipant, JointPlan},
    native::{ClaimTerms, PreparedClaim},
    recovery::RecoveryError,
    release_journal::{claim_digest, InitialClaimJournal, ReleasePolicy, ReleaseState},
    time_bounds::{
        AssumedClaimDelays, AssumedDirectRecoveryCosts, AssumedXmrRecoveryWindow,
        InitialClaimOrder, TimingError,
    },
    xmr_recovery::{
        XmrDirectRecoveryLink, XmrDirectRecoveryMaterial, XmrRecoveryLink, XmrRecoveryMaterial,
        XmrRecoveryRoster,
    },
    PreSignature, Statement,
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};
use monero_wallet::{
    address::Network,
    ed25519::{Point, Scalar as MoneroScalar},
    ringct::RctType,
    send::{Change, SignableTransaction},
    OutputWithDecoys, Scanner, ViewPair,
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use xmr_dleq_sigma::{prove, verify, CrossCurveSecret252};
use zeroize::Zeroizing;

struct ManagedDaemon(Child);
impl Drop for ManagedDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fresh_secret() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
}

enum Mode {
    XmrFirst,
    DomFirst,
    HeightXmrFirst,
    HeightDomFirst,
    DirectPair {
        bridge: PathBuf,
        outcome: PairOutcome,
    },
    XmrDirectRecovery {
        bridge: PathBuf,
        squarings: u64,
    },
    XmrRecovery {
        bridge: PathBuf,
        count: u16,
        bad_first: bool,
    },
    EarlyDomRefund {
        bridge: PathBuf,
        count: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairOutcome {
    XmrFirst,
    DomFirst,
    XmrFirstResume,
    DomFirstResume,
    XmrFirstAckLoss,
    DomFirstAckLoss,
    XmrFirstNativeSend,
    DomFirstNativeSend,
    DomFirstXmrDetach,
    XmrFirstReinclude,
    XmrFirstNativeReplay,
    Abandon,
    ClaimWins,
    RefundWins,
    LateClaimLeakAudit,
}

impl PairOutcome {
    fn resumes(self) -> bool {
        matches!(
            self,
            Self::XmrFirstResume
                | Self::DomFirstResume
                | Self::XmrFirstAckLoss
                | Self::DomFirstAckLoss
                | Self::XmrFirstNativeSend
                | Self::DomFirstNativeSend
                | Self::DomFirstXmrDetach
                | Self::XmrFirstReinclude
                | Self::XmrFirstNativeReplay
        )
    }
    fn loses_ack(self) -> bool {
        // Lost result may be in the bridge or in the native sender's process.
        matches!(
            self,
            Self::XmrFirstAckLoss
                | Self::DomFirstAckLoss
                | Self::XmrFirstNativeSend
                | Self::DomFirstNativeSend
                | Self::DomFirstXmrDetach
                | Self::XmrFirstReinclude
                | Self::XmrFirstNativeReplay
        )
    }
    fn native_send(self) -> bool {
        matches!(
            self,
            Self::XmrFirstNativeSend
                | Self::DomFirstNativeSend
                | Self::DomFirstXmrDetach
                | Self::XmrFirstReinclude
                | Self::XmrFirstNativeReplay
        )
    }
    fn races(self) -> bool {
        matches!(
            self,
            Self::ClaimWins | Self::RefundWins | Self::LateClaimLeakAudit
        )
    }
}

const LAB_CLAIM_DELAYS: AssumedClaimDelays = AssumedClaimDelays {
    xmr_resolution_secs: 1,
    observation_secs: 1,
    dom_resolution_secs: 1,
};

// Only the remaining participant's share is retained after the cooperative
// signing round. The other share must come from the verified public capsule.
struct RaceReserve {
    input: OutputWithDecoys,
    image: curve25519_dalek::edwards::EdwardsPoint,
    local_key: ThresholdKeys<Ed25519>,
    offset: Scalar,
}

struct RecoveredRefund {
    prepared: PreparedClaim,
    transaction: monero_wallet::transaction::Transaction,
    change: ViewPair,
    evidence: serde_json::Value,
}

async fn recover_race_refund(
    reserve: RaceReserve,
    recovery: (
        XmrRecoveryRoster,
        XmrDirectRecoveryLink,
        direct_recovery_bridge::DirectPublicCapsule,
    ),
    owner: &(Zeroizing<MoneroScalar>, ViewPair),
    fee: monero_wallet::interface::FeeRate,
    amount: u64,
) -> RecoveredRefund {
    let started = Instant::now();
    let (roster, link, capsule) = recovery;
    let binding = capsule.binding();
    let (opening, mut evidence) = tokio::task::spawn_blocking(move || capsule.open())
        .await
        .unwrap();
    let remote_id = Participant::new(2).unwrap();
    assert!(link
        .recover_after_opening(
            &roster,
            remote_id,
            binding,
            Zeroizing::new(*opening + Scalar::ONE)
        )
        .is_err());
    let restored = link
        .recover_after_opening(&roster, remote_id, binding, opening)
        .unwrap();
    let restored = restored.offset(reserve.offset);
    assert_eq!(restored.group_key(), reserve.local_key.group_key());
    evidence["recovery_verification_seconds"] = json!(started.elapsed().as_secs_f64());
    evidence["original_peer_share_dropped"] = json!(true);
    evidence["forged_recovery_share_rejected"] = json!(true);
    let change = ViewPair::new(
        Point::from((*owner.0).into() * G),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    let prepared = PreparedClaim::new(
        reserve.input,
        reserve.image,
        ClaimTerms {
            recipient: owner.1.legacy_address(Network::Mainnet),
            amount,
            change: change.clone(),
            fee_rate: fee,
            max_fee: 1_000_000_000_000,
        },
        fresh_secret(),
        Sha256::digest(link.binding()).into(),
        &mut OsRng,
    )
    .unwrap();
    let witness = Zeroizing::new(Scalar::random(&mut OsRng));
    let statement = Statement::prove(prepared.context(), &witness, &mut OsRng).unwrap();
    let pre = presign(
        &prepared,
        statement,
        [reserve.local_key, restored],
        [95; 32],
    );
    let transaction = prepared.complete(&pre, &witness, &mut OsRng).unwrap();
    prepared.verify_final(&transaction, &mut OsRng).unwrap();
    RecoveredRefund {
        prepared,
        transaction,
        change,
        evidence,
    }
}

struct PairState {
    dom: dom_regtest::FundedDom,
    window: AssumedXmrRecoveryWindow,
    ready_by: dom_core::Timestamp,
    preparation_seconds: f64,
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// This exercises the durable initial-exposure gate, not restart of the whole
// signing/recovery executor. All original secret material remains ephemeral.
async fn journaled_initial_send<T, F: std::future::Future<Output = T>>(
    root: &Path,
    operation: [u8; 32],
    window: &AssumedXmrRecoveryWindow,
    order: InitialClaimOrder,
    payload: &[u8],
    send: impl FnOnce() -> F,
) -> T {
    // The journal requires a durable containing directory. This fresh regtest
    // directory is never reused by a different operation.
    fs::File::open(root.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
    let path = root.join("initial-claim.wal");
    // Exact discovery material is durable BEFORE any possible network release.
    // The original policy below pins these bytes. A missing/corrupt journal on
    // restart is not permission to publish or manufacture an exposure event.
    claim_resume_bridge::write_new(&root.join("initial-claim.tx"), payload);
    let policy = ReleasePolicy::new(
        operation,
        window,
        order,
        LAB_CLAIM_DELAYS,
        claim_digest(payload),
    )
    .unwrap();
    let journal =
        InitialClaimJournal::create(&path, policy.clone(), dom_core::Timestamp(unix_seconds()))
            .unwrap();
    drop(journal);
    let mut journal = InitialClaimJournal::open(&path, policy.clone()).unwrap();
    assert_eq!(journal.state().unwrap(), ReleaseState::Private);
    let result = journal
        .release_once(payload, || dom_core::Timestamp(unix_seconds()), send)
        .await
        .expect("durable initial claim release refused; reconcile before any retry");
    drop(journal);
    let journal = InitialClaimJournal::open(&path, policy).unwrap();
    assert_eq!(journal.state().unwrap(), ReleaseState::ExposurePossible);
    result
}

struct RefundEvidence {
    binding: [u8; 64],
    seconds: f64,
    details: serde_json::Value,
}

fn presign(
    prepared: &PreparedClaim,
    statement: Statement,
    keys: [ThresholdKeys<Ed25519>; 2],
    session: [u8; 32],
) -> PreSignature {
    let plan = JointPlan::new(
        prepared.context().clone(),
        statement,
        session,
        prepared.offsets().to_vec(),
    )
    .unwrap();
    let [(a, ma), (b, mb)]: [_; 2] = keys
        .into_iter()
        .map(|keys| {
            JointParticipant::new(plan.clone(), prepared.input_opening(), keys)
                .unwrap()
                .preprocess(&mut OsRng)
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let (a, sa) = a.sign(&mb).unwrap();
    let (b, sb) = b.sign(&ma).unwrap();
    let pre = a.complete(&sb).unwrap();
    assert_eq!(pre, b.complete(&sa).unwrap());
    pre
}

async fn exercise(binary: PathBuf, mode: Mode) {
    let pair_outcome = match &mode {
        Mode::DirectPair { outcome, .. } => Some(*outcome),
        _ => None,
    };
    let dom_first = matches!(&mode, Mode::DomFirst | Mode::HeightDomFirst)
        || matches!(
            pair_outcome,
            Some(
                PairOutcome::DomFirst
                    | PairOutcome::DomFirstResume
                    | PairOutcome::DomFirstAckLoss
                    | PairOutcome::DomFirstNativeSend
                    | PairOutcome::DomFirstXmrDetach
            )
        );
    let resume_worker = pair_outcome.is_some_and(PairOutcome::resumes);
    let loses_ack = pair_outcome.is_some_and(PairOutcome::loses_ack);
    let native_send = pair_outcome.is_some_and(PairOutcome::native_send);
    let height_refund =
        matches!(&mode, Mode::HeightXmrFirst | Mode::HeightDomFirst) || pair_outcome.is_some();
    const DOM_REFUND_HEIGHT: u64 = 12;
    let (xmr_recovery_config, early_dom_config, direct_recovery_config) = match mode {
        Mode::XmrRecovery {
            bridge,
            count,
            bad_first,
        } => (Some((bridge, count, bad_first)), None, None),
        Mode::EarlyDomRefund { bridge, count } => (None, Some((bridge, count)), None),
        Mode::XmrDirectRecovery { bridge, squarings } => (None, None, Some((bridge, squarings))),
        Mode::DirectPair { bridge, .. } => (None, None, Some((bridge, 10_000_000))),
        _ => (None, None, None),
    };
    let whole = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!(
            "regtest-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir(&root).expect("fresh experiment directory");
    // Persist completed phases even when the outer timeout prevents a final
    // report. Only public measurements go here, never keys or capsule bodies.
    let checkpoint = |phase: &str, evidence: serde_json::Value| {
        if let Some(outcome) = pair_outcome {
            let event = json!({
                "phase":phase, "outcome":format!("{outcome:?}"),
                "elapsed_seconds":whole.elapsed().as_secs_f64(),
                "unix_seconds":unix_seconds(), "evidence":evidence,
            });
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("phases.jsonl"))
                .unwrap();
            writeln!(file, "{event}").unwrap();
            println!("phase: {event}");
        }
    };
    checkpoint("started", json!({"atomic_swap":false}));
    let config = root.join("empty.conf");
    fs::write(&config, "").unwrap();
    let rpc_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let p2p_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let log = fs::File::create(root.join("daemon.stdout.log")).unwrap();
    let mut daemon = ManagedDaemon(
        Command::new(binary)
            .arg("--config-file")
            .arg(config)
            .arg("--data-dir")
            .arg(root.join("chain"))
            .arg("--log-file")
            .arg(root.join("daemon.log"))
            .args([
                "--regtest",
                "--offline",
                "--no-zmq",
                "--no-igd",
                "--hide-my-port",
                "--disable-dns-checkpoints",
                "--check-updates",
                "disabled",
                "--fixed-difficulty",
                "1",
                "--max-concurrency",
                "2",
                "--prep-blocks-threads",
                "1",
                "--non-interactive",
                "--rpc-bind-ip",
                "127.0.0.1",
                "--p2p-bind-ip",
                "127.0.0.1",
                "--rpc-ssl",
                "disabled",
            ])
            .arg("--rpc-bind-port")
            .arg(rpc_port.to_string())
            .arg("--p2p-bind-port")
            .arg(p2p_port.to_string())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start owned regtest daemon"),
    );
    println!("isolated regtest artifacts: {}", root.display());
    let url = format!("http://127.0.0.1:{rpc_port}");
    let rpc = loop {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "owned daemon exited; inspect logs"
        );
        if let Ok(rpc) =
            SimpleRequestTransport::with_custom_timeout(url.clone(), Duration::from_secs(30)).await
        {
            break rpc;
        }
        assert!(
            whole.elapsed() < Duration::from_secs(30),
            "daemon startup timeout"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let info: serde_json::Value =
        serde_json::from_str(&rpc.json_rpc_call("get_info", None, 16384).await.unwrap()).unwrap();
    assert_eq!(info["offline"], true);
    assert_eq!(info["nettype"], "fakechain");
    let xmr_chain = if loses_ack {
        Some(rpc.block_by_number(0).await.unwrap().hash())
    } else {
        None
    };
    let observe_xmr = async |transaction: &monero_wallet::transaction::Transaction| {
        let hash: String = transaction
            .hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let response = rpc
            .rpc_call(
                "get_transactions",
                Some(json!({"txs_hashes":[hash]}).to_string()),
                65536,
            )
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        if response["txs"].as_array().is_some_and(|txs| txs.len() == 1) {
            assert_eq!(response["txs"][0]["tx_hash"], hash);
            assert_eq!(response["txs"][0]["in_pool"], true);
            Observation::InPool
        } else {
            assert_eq!(response["missed_tx"], json!([hash]));
            let monero_wallet::transaction::Input::ToKey { key_image, .. } =
                &transaction.prefix().inputs[0]
            else {
                panic!("native input")
            };
            let image: String = key_image
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let spent = rpc
                .rpc_call(
                    "is_key_image_spent",
                    Some(json!({"key_images":[image]}).to_string()),
                    16384,
                )
                .await
                .unwrap();
            let spent: serde_json::Value = serde_json::from_str(&spent).unwrap();
            assert_eq!(spent["spent_status"], json!([0]));
            Observation::AbsentAndUnspent
        }
    };
    // Keep test transactions in the local, mineable pool. A normal relay would
    // enter Dandelion's local/stem phase, which cannot propagate without peers.
    // All consensus validation remains enabled in send_raw_transaction.
    let publish_local = async |transaction: &monero_wallet::transaction::Transaction| {
        let tx_as_hex: String = transaction
            .serialize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let result = rpc
            .rpc_call(
                "send_raw_transaction",
                Some(
                    json!({
                        "tx_as_hex": tx_as_hex, "do_not_relay": true, "do_sanity_checks": false,
                    })
                    .to_string(),
                ),
                16384,
            )
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            result["status"], "OK",
            "local daemon rejected transaction: {result}"
        );
    };
    let reject_spent = async |transaction: &monero_wallet::transaction::Transaction| {
        let tx_as_hex: String = transaction
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let result = rpc
            .rpc_call(
                "send_raw_transaction",
                Some(
                    json!({
                        "tx_as_hex":tx_as_hex, "do_not_relay":true, "do_sanity_checks":false,
                    })
                    .to_string(),
                ),
                16384,
            )
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_ne!(
            result["status"], "OK",
            "conflicting spend accepted: {result}"
        );
        assert_eq!(
            result["double_spend"], true,
            "expected spent key image rejection: {result}"
        );
        result
    };
    assert_eq!(
        rpc.latest_block_number().await.unwrap(),
        0,
        "must own a fresh chain"
    );

    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let shares = [
        Zeroizing::new(Scalar::random(&mut OsRng)),
        Zeroizing::new(Scalar::random(&mut OsRng)),
    ];
    let roster = HashMap::from([
        (ids[0], GroupPoint(*shares[0] * G)),
        (ids[1], GroupPoint(*shares[1] * G)),
    ]);
    let keys: [ThresholdKeys<Ed25519>; 2] = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| {
            ThresholdKeys::new(
                ThresholdParams::new(2, 2, ids[i]).unwrap(),
                Interpolation::Constant(vec![Scalar::ONE; 2]),
                share,
                roster.clone(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let reserve_view = ViewPair::new(
        Point::from(keys[0].group_key().0),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    // Regtest uses mainnet address bytes; the daemon is offline FAKECHAIN.
    let reserve_address = reserve_view.legacy_address(Network::Mainnet);
    let recipient_spend = Zeroizing::new(MoneroScalar::random(&mut OsRng));
    let recipient_view = ViewPair::new(
        Point::from((*recipient_spend).into() * G),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    // Test-chain bootstrap only. The direct experiment creates the owner's
    // spendable balance BEFORE disclosing a capsule, then funds the shared
    // reserve through a native transaction only AFTER public verification.
    // Both stages remain in the end-to-end timer.
    let mine_fixture = async |address: &monero_wallet::address::MoneroAddress| {
        let mining = Instant::now();
        loop {
            let probe = rpc.rpc_call("json_rpc", Some(json!({"jsonrpc":"2.0", "id":0,
                "method":"generateblocks", "params":{"wallet_address":address.to_string(), "amount_of_blocks":1}
            }).to_string()), 16384).await.unwrap();
            let probe: serde_json::Value = serde_json::from_str(&probe).unwrap();
            if probe["result"]["status"] == "BUSY" {
                assert!(
                    mining.elapsed() < Duration::from_secs(30),
                    "regtest core remained BUSY"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            assert!(
                probe.get("error").is_none(),
                "regtest mining RPC failed: {probe}"
            );
            assert_eq!(probe["result"]["status"], "OK", "{probe}");
            assert_eq!(probe["result"]["blocks"].as_array().unwrap().len(), 1);
            break;
        }
        let (blocks, height) = rpc.generate_blocks(address, 139).await.unwrap();
        let seconds = mining.elapsed().as_secs_f64();
        println!("generated 140 test blocks in {seconds:.3}s");
        (blocks, height, seconds)
    };
    let direct_funding_source = if direct_recovery_config.is_some() {
        let started = Instant::now();
        let spend = Zeroizing::new(MoneroScalar::random(&mut OsRng));
        let view = ViewPair::new(
            Point::from((*spend).into() * G),
            Zeroizing::new(MoneroScalar::random(&mut OsRng)),
        )
        .unwrap();
        let address = view.legacy_address(Network::Mainnet);
        let (blocks, height, _) = mine_fixture(&address).await;
        let block = rpc.scannable_block(blocks[0]).await.unwrap();
        assert_eq!(block.block.header.hardfork_version, 16);
        // No shared reserve coin exists at this stage.
        assert!(Scanner::new(reserve_view.clone())
            .scan(block.clone())
            .unwrap()
            .not_additionally_locked()
            .is_empty());
        let mut outputs = Scanner::new(view.clone())
            .scan(block)
            .unwrap()
            .additional_timelock_satisfied_by(height, 0);
        assert_eq!(outputs.len(), 1);
        let input = OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, outputs.remove(0))
            .await
            .unwrap();
        let fee = rpc
            .fee_rate(FeePriority::Normal, 1_000_000_000)
            .await
            .unwrap();
        Some((spend, view, input, fee, started.elapsed().as_secs_f64()))
    } else {
        None
    };
    // Distinct economic roles: the XMR owner gets refund/change; the buyer
    // gets only the agreed XMR payment on successful completion.
    let direct_owner_wallet = direct_funding_source
        .as_ref()
        .map(|(spend, view, _, _, _)| (spend.clone(), view.clone()));
    let (recipient_spend, recipient_view) = if pair_outcome == Some(PairOutcome::Abandon) {
        direct_owner_wallet.as_ref().unwrap().clone()
    } else {
        (recipient_spend, recipient_view)
    };
    let recipient_address = recipient_view.legacy_address(Network::Mainnet);
    let prepared_pair_dom = if pair_outcome.is_some() {
        let started = Instant::now();
        let prepared = dom_regtest::FundedDom::prepare_unfunded(&root.join("dom")).await;
        Some((prepared, started.elapsed().as_secs_f64()))
    } else {
        None
    };
    checkpoint(
        "individual_balances_prepared",
        json!({"shared_reserves_funded":false}),
    );
    let capsule_start = Instant::now();
    let recovery = if let Some((bridge, count, bad_first)) = xmr_recovery_config {
        let mut reservation = Sha256::new();
        reservation.update(b"DXP1/XMR-recovery/owned-offline-fakechain/v1");
        reservation.update(*fresh_secret());
        reservation.update(reserve_address.to_string().as_bytes());
        let roster = XmrRecoveryRoster::new(
            reservation.finalize().into(),
            ids.map(|id| keys[0].original_verification_share(id).0),
        )
        .unwrap();
        let mut material =
            XmrRecoveryMaterial::create(&keys[1], &roster, count, &mut OsRng).unwrap();
        if bad_first {
            // The ciphertext and range proof honestly encrypt this scalar;
            // it alone contradicts the unchanged Feldman polynomial.
            material.puzzle_shares[0].scalar += Scalar::ONE;
        }
        let mut preparation_attempts = 0;
        let capsule = loop {
            preparation_attempts += 1;
            match recovery_bridge::PublicCapsule::try_prepare(
                &bridge,
                &material.plan,
                Zeroizing::new(material.puzzle_shares.clone()),
            ) {
                Ok(capsule) => break capsule,
                Err(RecoveryError::Share) if bad_first && preparation_attempts < 16 => {
                    println!("audit: bad scalar selected for opening; offer rejected before funding; generating fresh offer");
                }
                Err(error) => panic!("capsule preparation rejected: {error:?}"),
            }
        };
        if bad_first {
            assert_eq!(capsule.challenge.delayed_indexes()[0], 1);
        }
        let link = XmrRecoveryLink::new(
            &roster,
            ids[1],
            &material.plan,
            &capsule.challenge,
            &capsule.window,
        )
        .unwrap();
        drop(material);
        println!("XMR capsule verified; producer exited; funding shared test reserve");
        Some((
            roster,
            link,
            capsule,
            count,
            bad_first,
            preparation_attempts,
        ))
    } else {
        None
    };
    let mut direct_recovery = direct_recovery_config.map(|(bridge, squarings)| {
        let mut reservation = Sha256::new();
        reservation.update(b"DXP1/XMR-direct-recovery/owned-offline-fakechain/v0");
        reservation.update(*fresh_secret());
        reservation.update(reserve_address.to_string().as_bytes());
        let roster = XmrRecoveryRoster::new(reservation.finalize().into(),
            ids.map(|id| keys[0].original_verification_share(id).0)).unwrap();
        let material = XmrDirectRecoveryMaterial::create(&keys[1], &roster).unwrap();
        let capsule = if squarings == 200_000 {
            direct_recovery_bridge::DirectPublicCapsule::prepare(&bridge, material)
        } else {
            direct_recovery_bridge::DirectPublicCapsule::prepare_with_work(&bridge, material, squarings)
        };
        let link = XmrDirectRecoveryLink::new(&roster, ids[1], capsule.context(), capsule.public_key(), capsule.binding()).unwrap();
        println!("Direct XMR capsule verified; producer exited; funding isolated test reserve (no timing admission)");
        (roster, link, capsule)
    });
    let capsule_seconds = capsule_start.elapsed().as_secs_f64();
    checkpoint(
        "capsule_verified",
        json!({"capsule_seconds":capsule_seconds}),
    );
    let mut paired = if pair_outcome.is_some() {
        let (_, link, capsule) = direct_recovery.as_ref().unwrap();
        let disclosed = capsule.received_unix_seconds();
        // EXPLICIT CONDITIONAL LAB FIXTURE, not security bounds established
        // by benchmarks. Complete-frame receipt is not first disclosure.
        let ready_by = dom_core::Timestamp(
            disclosed
                .checked_add(if dom_first { 26 } else { 28 })
                .unwrap(),
        );
        let window = AssumedXmrRecoveryWindow::from_direct_costs(
            link,
            dom_core::Timestamp(disclosed),
            30,
            dom_core::Timestamp(disclosed.checked_add(35).unwrap()),
            AssumedDirectRecoveryCosts {
                opening_and_check_secs: 60,
                overhead_secs: 5,
            },
        )
        .unwrap();
        let started = Instant::now();
        let (prepared, preparation_seconds) = prepared_pair_dom.unwrap();
        let dom = dom_regtest::FundedDom::fund_with_recovery_window(
            prepared, &window, ready_by, dom_first,
        )
        .await;
        dom.assert_height_refund_locked().await;
        assert!(
            unix_seconds() < ready_by.0,
            "conditional test preparation budget exhausted before XMR deposit"
        );
        Some(PairState {
            dom,
            window,
            ready_by,
            preparation_seconds: preparation_seconds + started.elapsed().as_secs_f64(),
        })
    } else {
        None
    };
    if let Some(state) = &paired {
        checkpoint(
            "dom_reserve_funded",
            json!({
                "height":state.dom.funding_height,
                "refund_height":state.dom.height_refund_height(),
                "timing":state.dom.height_refund_timing(),
            }),
        );
    }
    let (output, height, preparation_seconds, funding_evidence) =
        if let Some((spend, view, input, fee, source_seconds)) = direct_funding_source {
            assert!(
                direct_recovery.is_some(),
                "public capsule must precede reserve funding"
            );
            let started = Instant::now();
            let source_address = view.legacy_address(Network::Mainnet);
            const DEPOSIT: u64 = 5_000_000_000_000;
            let tx = SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                fresh_secret(),
                vec![input],
                vec![(reserve_address, DEPOSIT)],
                Change::new(view, None),
                vec![],
                fee,
            )
            .unwrap()
            .sign(&mut OsRng, &spend)
            .unwrap();
            publish_local(&tx).await;
            let (blocks, _) = rpc.generate_blocks(&source_address, 1).await.unwrap();
            let block = rpc.scannable_block(blocks[0]).await.unwrap();
            assert!(block.block.transactions.contains(&tx.hash()));
            let mut outputs = Scanner::new(reserve_view.clone())
                .scan(block)
                .unwrap()
                .not_additionally_locked();
            assert_eq!(outputs.len(), 1);
            let output = outputs.remove(0);
            assert_eq!(output.commitment().amount, DEPOSIT);
            // Real consensus maturity remains in the measured interval. Blocks
            // are generated on demand ONLY on this isolated fakechain.
            let (_, height) = rpc.generate_blocks(&source_address, 10).await.unwrap();
            let deposit_seconds = started.elapsed().as_secs_f64();
            let evidence = json!({
                "owner_balance_prepared_before_capsule":true,
                "owner_balance_preparation_seconds":source_seconds,
                "reserve_funded_by_native_transfer":true,
                "reserve_funding_transaction_included":true,
                "reserve_funding_after_public_verification":true,
                "reserve_funding_and_maturity_seconds":deposit_seconds,
                "reserve_maturity_blocks_mined":10,
            });
            (
                output,
                height,
                source_seconds + deposit_seconds,
                Some(evidence),
            )
        } else {
            let (blocks, height, seconds) = mine_fixture(&reserve_address).await;
            let block = rpc.scannable_block(blocks[0]).await.unwrap();
            assert_eq!(block.block.header.hardfork_version, 16);
            let mut outputs = Scanner::new(reserve_view.clone())
                .scan(block)
                .unwrap()
                .additional_timelock_satisfied_by(height, 0);
            assert_eq!(outputs.len(), 1);
            (outputs.remove(0), height, seconds, None)
        };
    let reserve_amount = output.commitment().amount;
    checkpoint("xmr_reserve_funded_and_mature", json!({"height":height}));
    let offset = output.key_offset().into();
    let mut paired_height_miner = None;
    let (keys, recovery_evidence) = if let Some((
        roster,
        link,
        capsule,
        count,
        bad_first,
        preparation_attempts,
    )) = recovery
    {
        let [local, remote] = keys;
        drop(remote);
        let recovery_start = Instant::now();
        let (delayed, solve_evidence) = capsule.solve().expect("no valid delayed share remained");
        if bad_first {
            assert_eq!(solve_evidence.rejected_indexes, [1]);
            assert_eq!(solve_evidence.attempted_indexes.len(), 2);
        } else {
            assert!(solve_evidence.rejected_indexes.is_empty());
        }
        let mut forged = delayed.clone();
        forged.scalar += Scalar::ONE;
        assert!(link.recover_after_opening(&roster, ids[1], forged).is_err());
        let recovered = link
            .recover_after_opening(&roster, ids[1], delayed)
            .unwrap();
        let recovery_seconds = recovery_start.elapsed().as_secs_f64();
        (
            [local, recovered],
            Some(RefundEvidence {
                binding: link.binding(),
                seconds: recovery_seconds,
                details: json!({
                    "recovery_backend":"cut-and-choose",
                    "participants":count,"threshold":count/2+1,"opened":count/2,"squarings":200000,
                    "forged_delayed_share_rejected":true,
                    "public_solve_seconds":solve_evidence.sequential_solve_seconds,
                    "bad_first_delayed_puzzle_injected":bad_first,"capsule_generation_attempts":preparation_attempts,
                    "public_solve_attempted_indexes":solve_evidence.attempted_indexes,
                    "public_solve_rejected_indexes":solve_evidence.rejected_indexes,
                    "recovery_session_seconds":solve_evidence.verification_and_solve_seconds,
                    "public_offer_verifications":solve_evidence.public_offer_verifications,
                    "public_offer_verification_seconds":solve_evidence.public_verification_seconds,
                    "setup_verification_seconds":solve_evidence.setup_verification_seconds,
                    "setup_verified_before_offer":solve_evidence.setup_verified_before_offer,
                    "public_offer_verified_before_funding":solve_evidence.public_offer_verified_before_funding,
                    "public_verifier_started_before_offer":true,
                }),
            }),
        )
    } else if let Some((roster, link, capsule)) =
        if pair_outcome.is_none() || pair_outcome == Some(PairOutcome::Abandon) {
            direct_recovery.take()
        } else {
            None
        }
    {
        if let Some(state) = paired.as_mut() {
            assert!(
                unix_seconds() <= state.ready_by.0,
                "conditional test ready budget exhausted"
            );
            state.dom.discard_reserve_signing_material();
            state.dom.assert_height_refund_locked().await;
            paired_height_miner = Some(state.dom.start_refund_height_mining());
        }
        let [local, remote] = keys;
        drop(remote);
        let recovery_start = Instant::now();
        let binding = capsule.binding();
        checkpoint("xmr_recovery_started", json!({}));
        let (opening, mut details) = if paired_height_miner.is_some() {
            // A chain keeps progressing while a participant recovers XMR.
            // Blocking IPC must not freeze the fixture's native DOM miner.
            tokio::task::spawn_blocking(move || capsule.open())
                .await
                .unwrap()
        } else {
            capsule.open()
        };
        assert!(link
            .recover_after_opening(
                &roster,
                ids[1],
                binding,
                Zeroizing::new(*opening + Scalar::ONE)
            )
            .is_err());
        let recovered = link
            .recover_after_opening(&roster, ids[1], binding, opening)
            .unwrap();
        checkpoint(
            "xmr_recovery_verified",
            json!({"recovery_seconds":recovery_start.elapsed().as_secs_f64()}),
        );
        if let Some(state) = &paired {
            assert!(
                unix_seconds() <= state.window.latest_honest().0,
                "conditional recovery budget exceeded"
            );
            let dom_height = state.dom.context().await.current_height.0;
            assert!(
                dom_height > state.dom.funding_height,
                "native DOM chain did not progress during recovery"
            );
            details["dom_height_at_xmr_recovery_completion"] = json!(dom_height);
        }
        details["recovery_backend"] = json!("experimental-direct-dlog");
        details["puzzles"] = json!(1);
        details["proof_rounds"] = json!(256);
        details["forged_recovery_share_rejected"] = json!(true);
        details["public_offer_verified_before_funding"] = json!(true);
        (
            [local, recovered],
            Some(RefundEvidence {
                binding: link.binding(),
                seconds: recovery_start.elapsed().as_secs_f64(),
                details,
            }),
        )
    } else {
        (keys, None)
    };
    let keys = keys.map(|key| key.offset(offset));
    assert_eq!(keys[0].group_key().0, output.key().into());
    let h = Point::biased_hash(output.key().compress().to_bytes()).into();
    let image = keys
        .iter()
        .map(|key| h * **key.view(ids.to_vec()).unwrap().secret_share())
        .sum();
    let input = OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, output)
        .await
        .unwrap();
    // A fresh fakechain has a different emission/fee regime from today's
    // mainnet. Keep explicit caps in test-coin units and record the actual fee.
    let fee_rate = rpc
        .fee_rate(FeePriority::Normal, 1_000_000_000)
        .await
        .unwrap();
    const AMOUNT: u64 = 1_000_000_000_000;
    if let Some(RefundEvidence {
        binding: recovery_binding,
        seconds: recovery_seconds,
        details,
    }) = recovery_evidence
    {
        let refund_start = Instant::now();
        // Both destinations belong to the simulated remaining participant.
        // Use distinct view keys so the restrictive native builder has two
        // distinct addresses, while all refunded value leaves the shared key.
        let refund_change = ViewPair::new(
            Point::from((*recipient_spend).into() * G),
            Zeroizing::new(MoneroScalar::random(&mut OsRng)),
        )
        .unwrap();
        let prepared = PreparedClaim::new(
            input,
            image,
            ClaimTerms {
                recipient: recipient_address,
                amount: AMOUNT,
                change: refund_change.clone(),
                fee_rate,
                max_fee: 1_000_000_000_000,
            },
            fresh_secret(),
            Sha256::digest(recovery_binding).into(),
            &mut OsRng,
        )
        .unwrap();
        let witness = Zeroizing::new(Scalar::random(&mut OsRng));
        let statement = Statement::prove(prepared.context(), &witness, &mut OsRng).unwrap();
        let pre = presign(&prepared, statement, keys, [93; 32]);
        let tx = prepared.complete(&pre, &witness, &mut OsRng).unwrap();
        publish_local(&tx).await;
        let (refund_blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        let block = rpc.scannable_block(refund_blocks[0]).await.unwrap();
        assert!(block.block.transactions.contains(&tx.hash()));
        let xmr_refund_observed_unix = unix_seconds();
        if let Some(state) = &paired {
            let latest_resolution = state.window.latest_honest().0.checked_add(1).unwrap();
            assert!(
                xmr_refund_observed_unix <= latest_resolution,
                "XMR refund missed the conditional latest resolution boundary"
            );
            checkpoint(
                "xmr_refund_included_before_conditional_deadline",
                json!({
                    "refund_observed_unix":xmr_refund_observed_unix,
                    "conditional_latest_resolution_unix":latest_resolution,
                }),
            );
        }
        let observed = rpc.transactions(&[tx.hash()]).await.unwrap().remove(0);
        prepared.verify_final(&observed, &mut OsRng).unwrap();
        let mut received = Scanner::new(recipient_view.clone())
            .scan(block)
            .unwrap()
            .not_additionally_locked();
        let change = Scanner::new(refund_change)
            .scan(rpc.scannable_block(refund_blocks[0]).await.unwrap())
            .unwrap()
            .not_additionally_locked();
        assert_eq!(received.len(), 1);
        assert_eq!(change.len(), 1);
        received.extend(change);
        let refunded_amount: u64 = received
            .iter()
            .map(|output| output.commitment().amount)
            .sum();
        assert_eq!(refunded_amount, reserve_amount - prepared.fee());
        let refund_inclusion_seconds = refund_start.elapsed().as_secs_f64();
        let (_, height) = rpc.generate_blocks(&reserve_address, 10).await.unwrap();
        let mut inputs = Vec::new();
        for output in received {
            inputs.push(
                OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, output)
                    .await
                    .unwrap(),
            );
        }
        let onward = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            fresh_secret(),
            inputs,
            vec![(reserve_address, AMOUNT / 2)],
            Change::new(recipient_view, None),
            vec![],
            fee_rate,
        )
        .unwrap()
        .sign(&mut OsRng, &recipient_spend)
        .unwrap();
        publish_local(&onward).await;
        let (last, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        assert!(rpc
            .scannable_block(last[0])
            .await
            .unwrap()
            .block
            .transactions
            .contains(&onward.hash()));
        let mut report = json!({
            "experiment":"XMR reserve refund after peer abandonment and public puzzle solve",
            "network":"owned offline regtest", "atomic_swap":false,"bitcoin_involved":false,"dom_leg_exercised":false,
            "setup_centralized":true,"minimum_adversarial_delay_proven":false,"mainnet_latency_measurement":false,
            "public_solver_after_producer_exit":true,"original_peer_share_dropped":true,
            "aggregate_spend_key_reconstructed":false,"stealth_output_offset_applied_after_recovery":true,
            "xmr_reserve_funded":true,"xmr_refund_included":true,
            "all_refund_outputs_onward_spent":true,"refund_outputs":2,"refund_amount_atomic":refunded_amount,
            "reserve_amount_atomic":reserve_amount,"refund_fee_atomic":prepared.fee(),
            "capsule_preparation_verification_seconds":capsule_seconds,"preparation_blocks":140,
            "preparation_seconds":preparation_seconds,
            "honest_latest_recovery_bound_proven":false,
            "timing_admission_used":false,"safe_bilateral_window_proven":false,
            "recovery_verification_seconds":recovery_seconds,"refund_through_local_inclusion_seconds":refund_inclusion_seconds,
            "recipient_maturity_blocks_mined":10,"total_seconds":whole.elapsed().as_secs_f64(),
        });
        report
            .as_object_mut()
            .unwrap()
            .extend(details.as_object().unwrap().clone());
        if let Some(evidence) = funding_evidence {
            report
                .as_object_mut()
                .unwrap()
                .extend(evidence.as_object().unwrap().clone());
        }
        if let Some(state) = paired.take() {
            assert_eq!(pair_outcome, Some(PairOutcome::Abandon));
            let before = state.dom.height_refund_transaction().to_bytes().unwrap();
            checkpoint(
                "xmr_refund_outputs_spent",
                json!({
                    "dom_height":state.dom.context().await.current_height.0,
                    "dom_refund_height":state.dom.height_refund_height(),
                }),
            );
            // Publish and observe the XMR refund first. Waiting for DOM's
            // refund height before that would consume the safety margin.
            paired_height_miner.take().unwrap().wait().await;
            let (refund_height, onward_height) = state.dom.include_height_refund_and_spend().await;
            checkpoint(
                "dom_refund_output_spent",
                json!({"refund_height":refund_height,"onward_height":onward_height}),
            );
            assert_eq!(
                before,
                state.dom.height_refund_transaction().to_bytes().unwrap()
            );
            report.as_object_mut().unwrap().extend(
                state
                    .dom
                    .height_refund_timing()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone(),
            );
            report["experiment"] = json!(
                "direct DOM/XMR abandonment after both native deposits, before adaptor delivery"
            );
            report["dom_leg_exercised"] = json!(true);
            report["dom_refund_height"] = json!(state.dom.height_refund_height());
            report["dom_refund_included_height"] = json!(refund_height);
            report["dom_refund_onward_height"] = json!(onward_height);
            report["dom_refund_signed_before_funding"] = json!(true);
            report["dom_original_signing_material_dropped"] = json!(true);
            report["dom_refund_bytes_unchanged"] = json!(true);
            report["dom_preparation_seconds"] = json!(state.preparation_seconds);
            report["dom_post_bootstrap_walletless_regtest_mining"] = json!(true);
            report["dom_mining_progressed_during_xmr_recovery"] = json!(true);
            report["xmr_refund_paid_to_original_funding_owner"] = json!(true);
            report["xmr_refund_observed_unix"] = json!(xmr_refund_observed_unix);
            report["xmr_refund_preceded_conditional_latest_resolution"] = json!(true);
            report["conditional_lab_timing_checks_used"] = json!(true);
            report["authenticated_first_disclosure_clock"] = json!(false);
            report["total_seconds"] = json!(whole.elapsed().as_secs_f64());
        }
        fs::write(
            root.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    let dom_preparation = Instant::now();
    let paired_preparation_seconds = paired.as_ref().map(|state| state.preparation_seconds);
    let paired_ready_by = paired.as_ref().map(|state| state.ready_by);
    let paired_earliest_recovery = paired
        .as_ref()
        .map(|state| state.window.earliest_adversarial());
    let mut paired_release_window = None;
    let (mut dom, early_refund) = if let Some(state) = paired.take() {
        paired_release_window = Some(state.window);
        (state.dom, None)
    } else if let Some((bridge, count)) = early_dom_config {
        let chain = *dom_consensus::derive_chain_id(
            dom_wallet::Network::Regtest.magic(),
            &dom_core::Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        )
        .as_bytes();
        let shares = [
            ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
            ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
        ];
        let intent = ReserveIntent::new(
            dom_regtest::RESERVE_VALUE,
            chain,
            *fresh_secret(),
            [94; 32],
            shares.each_ref().map(|share| share.public_key()),
        )
        .unwrap();
        let proofs = [
            shares[0].prove(&intent, 0).unwrap(),
            shares[1].prove(&intent, 1).unwrap(),
        ];
        let reserve = intent.authorize(proofs).unwrap();
        let mut material =
            DomRecoveryMaterial::create(&shares[1], &reserve, 1, count, &mut OsRng).unwrap();
        let capsule = recovery_bridge::PublicCapsule::prepare(
            &bridge,
            &material.plan,
            Zeroizing::new(std::mem::take(&mut material.puzzle_shares)),
        );
        let link = DomRecoveryLink::new(
            &reserve,
            1,
            &material.plan,
            &material.cross_curve,
            &capsule.challenge,
            &capsule.window,
        )
        .unwrap();
        drop(material);
        let capsule_seconds = dom_preparation.elapsed().as_secs_f64();
        // Adversary starts solving as soon as the public capsule is available.
        // No stolen trapdoor or original peer scalar is sent to the solver.
        let early_start = Instant::now();
        let (delayed, solve_evidence) = capsule.solve().expect("no valid delayed share remained");
        let recovered = link.recover_after_opening(&reserve, 1, delayed).unwrap();
        let early_seconds = early_start.elapsed().as_secs_f64();
        println!("audit: public recovery already available BEFORE DOM funding");
        let dom = dom_regtest::FundedDom::new_prepared(&root.join("dom"), shares, reserve).await;
        let report = json!({"experiment":"early DOM recovery defeats unguarded direct claim composition",
            "network":"owned offline regtest","atomic_swap":false,"bitcoin_involved":false,
            "counterexample_reproduced":false,"mainnet_latency_measurement":false,
            "setup_centralized":true,"minimum_adversarial_delay_proven":false,
            "public_recovery_before_dom_funding":true,"public_solver_after_producer_exit":true,
            "uses_original_peer_share_for_refund":false,"uses_rsa_trapdoor_for_solve":false,
            "models_honest_xmr_counter_refund_scheduler":false,
            "participants":count,"threshold":count/2+1,"opened":count/2,"squarings":200000,
            "capsule_preparation_verification_seconds":capsule_seconds,
            "early_recovery_verification_seconds":early_seconds,"public_solve_seconds":solve_evidence.sequential_solve_seconds,
            "public_solve_attempted_indexes":solve_evidence.attempted_indexes,
            "public_solve_rejected_indexes":solve_evidence.rejected_indexes,
            "recovery_session_seconds":solve_evidence.verification_and_solve_seconds,
            "public_offer_verifications":solve_evidence.public_offer_verifications,
            "public_offer_verification_seconds":solve_evidence.public_verification_seconds,
            "setup_verification_seconds":solve_evidence.setup_verification_seconds,
            "setup_verified_before_offer":solve_evidence.setup_verified_before_offer,
            "public_offer_verified_before_funding":solve_evidence.public_offer_verified_before_funding,
            "public_verifier_started_before_offer":true,
            "dom_funding_height":dom.funding_height});
        (dom, Some((recovered, report)))
    } else {
        let dom = if height_refund {
            let dom = dom_regtest::FundedDom::new_with_height_refund(
                &root.join("dom"),
                DOM_REFUND_HEIGHT,
            )
            .await;
            dom.assert_height_refund_locked().await;
            dom
        } else {
            dom_regtest::FundedDom::new(&root.join("dom")).await
        };
        (dom, None)
    };
    let dom_preparation_seconds =
        paired_preparation_seconds.unwrap_or_else(|| dom_preparation.elapsed().as_secs_f64());
    let claim_start = Instant::now();
    let shared = CrossCurveSecret252::generate(&mut OsRng);
    let cross_curve_proof = prove(&shared, &mut OsRng).unwrap();
    verify(&cross_curve_proof).unwrap();
    let mut binding = Sha256::new();
    binding.update(b"DXP1/direct-dom-xmr-regtest/v1");
    binding.update(dom.claim.binding().unwrap());
    binding.update(cross_curve_proof.claim.secp_compressed);
    binding.update(cross_curve_proof.claim.ed_compressed);
    if let Some((roster, link, capsule)) = &direct_recovery {
        assert_eq!(roster.spend_key() + offset * G, keys[0].group_key().0);
        binding.update(b"DXP1/direct-pair-recovery-and-refund/v0");
        binding.update(link.binding());
        binding.update(Sha256::digest(
            dom.height_refund_transaction().to_bytes().unwrap(),
        ));
        assert_eq!(capsule.context(), roster.recovery_domain(ids[1]).unwrap());
    }
    let mut race_reserve = pair_outcome
        .filter(|outcome| outcome.races())
        .map(|_| RaceReserve {
            input: input.clone(),
            image,
            local_key: keys[0].clone(),
            offset,
        });
    let prepared = PreparedClaim::new(
        input,
        image,
        ClaimTerms {
            recipient: recipient_address,
            amount: AMOUNT,
            change: if pair_outcome.is_some() {
                direct_owner_wallet.as_ref().unwrap().1.clone()
            } else {
                reserve_view
            },
            fee_rate,
            max_fee: 1_000_000_000_000,
        },
        fresh_secret(),
        binding.finalize().into(),
        &mut OsRng,
    )
    .unwrap();
    // The XMR context already commits to the unsigned DOM body. Bind the DOM
    // signers in turn to the native XMR transaction hash before releasing shares.
    let mut dom_binding = Sha256::new();
    dom_binding.update(b"DXP1/DOM-joint/counterpart-xmr/v1");
    dom_binding.update(prepared.context().route_binding);
    dom_binding.update(prepared.context().message);
    let joint_operation_binding = dom_binding.finalize().into();
    let mut dom_offer = dom.offer(
        &cross_curve_proof.claim.secp_compressed,
        joint_operation_binding,
    );
    let witness = Zeroizing::new(
        Option::<Scalar>::from(Scalar::from_canonical_bytes(
            shared.xmr_share_little_endian(),
        ))
        .unwrap(),
    );
    let statement = Statement::prove(prepared.context(), &witness, &mut OsRng).unwrap();
    assert_eq!(
        statement.t_g.compress().to_bytes(),
        cross_curve_proof.claim.ed_compressed
    );
    let pre = presign(&prepared, statement, keys, [44; 32]);
    let mut prepared = prepared.into_claim_envelope(pre).unwrap();
    let resume_artifacts = resume_worker.then(|| {
        claim_resume_bridge::ResumeArtifacts::persist(
            &root,
            &prepared,
            &dom_offer,
            joint_operation_binding,
            paired_release_window.as_ref().unwrap(),
            dom_first,
            LAB_CLAIM_DELAYS,
        )
    });
    let mut resume_evidence = None;
    let mut resumed_xmr_transaction = None;
    let mut resumed_dom_transaction = None;
    let mut first_claim_reference = None;
    let mut pending_delivery = None;
    let mut settlement_observations = Vec::new();
    let mut native_send_probes = Vec::new();
    let mut xmr_detach_evidence = None;
    let mut first_reinclusion_evidence = None;
    let mut initial_replay_without_history_probe = None;
    let mut initial_pending_probe = None;
    let mut settlement_rpc = if loses_ack {
        let mut token = [0; 32];
        OsRng.fill_bytes(&mut token);
        let server = dom.start_owned_rpc(settlement_resume::hex(&token)).await;
        let checkpoint = dxp1_clsag_lab::operation_checkpoint::OperationCheckpoint {
            operation: joint_operation_binding,
            manifest: resume_artifacts.as_ref().unwrap().manifest_digest(),
            dom_chain: *dom.claim.chain(),
            dom_genesis: dom.canonical_hash(0),
            xmr_genesis: xmr_chain.unwrap(),
            dom_port: server.port,
            xmr_port: rpc_port,
            dom_token: token,
        };
        claim_resume_bridge::write_new(
            &root.join("operation.checkpoint"),
            &checkpoint.encode().unwrap(),
        );
        Some(server)
    } else {
        None
    };
    let paired_offer_elapsed = direct_recovery.as_ref().map(|(_, _, capsule)| {
        capsule.preparation_report()["offer_received_elapsed_seconds"]
            .as_f64()
            .unwrap()
    });
    if let Some(ready_by) = paired_ready_by {
        assert!(
            unix_seconds() <= ready_by.0,
            "conditional timing fixture expired before releasing paired offers"
        );
    }
    checkpoint(
        "paired_offers_ready",
        json!({"capsule_receipt_elapsed_seconds":paired_offer_elapsed}),
    );
    let claims_preparation_seconds = claim_start.elapsed().as_secs_f64();
    if height_refund {
        dom.discard_reserve_signing_material();
    }
    if matches!(
        pair_outcome,
        Some(PairOutcome::RefundWins | PairOutcome::LateClaimLeakAudit)
    ) {
        let audit = pair_outcome == Some(PairOutcome::LateClaimLeakAudit);
        let window = paired_release_window.as_ref().unwrap();
        // This completed claim remains PRIVATE to its sender until the later
        // explicitly marked exposure. Both adaptors have already been delivered.
        let stale_claim = prepared.complete(&witness, &mut OsRng).unwrap();
        drop(witness);
        drop(shared);
        let owner = direct_owner_wallet.as_ref().unwrap();
        let miner = if audit {
            None
        } else {
            Some(dom.start_refund_height_mining())
        };
        checkpoint(
            "post_offer_recovery_started",
            json!({"negative_control":audit}),
        );
        let refund = recover_race_refund(
            race_reserve.take().unwrap(),
            direct_recovery.take().unwrap(),
            owner,
            fee_rate,
            AMOUNT,
        )
        .await;
        assert!(unix_seconds() <= window.latest_honest().0);
        assert_eq!(prepared.context().image, refund.prepared.context().image);
        assert_ne!(stale_claim.hash(), refund.transaction.hash());
        publish_local(&refund.transaction).await;
        let (blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        let block = rpc.scannable_block(blocks[0]).await.unwrap();
        assert!(block
            .block
            .transactions
            .contains(&refund.transaction.hash()));
        assert!(!block.block.transactions.contains(&stale_claim.hash()));
        let observed = rpc
            .transactions(&[refund.transaction.hash()])
            .await
            .unwrap()
            .remove(0);
        refund.prepared.verify_final(&observed, &mut OsRng).unwrap();
        let refund_observed_unix = unix_seconds();
        assert!(refund_observed_unix <= window.latest_honest().0.checked_add(1).unwrap());
        let refused = window.check_initial_claim_release(
            dom_core::Timestamp(unix_seconds()),
            InitialClaimOrder::XmrFirst,
            LAB_CLAIM_DELAYS,
        );
        assert_eq!(refused, Err(TimingError::InitiationWindowExhausted));
        checkpoint(
            "post_offer_refund_won",
            json!({
                "late_initial_claim_refused":true, "negative_control_bypasses_refusal":audit,
                "refund_observed_unix":refund_observed_unix,
            }),
        );
        assert!(
            Scanner::new(recipient_view.clone())
                .scan(block.clone())
                .unwrap()
                .not_additionally_locked()
                .is_empty(),
            "buyer must not receive XMR after refund wins"
        );
        let mut outputs = Scanner::new(owner.1.clone())
            .scan(block.clone())
            .unwrap()
            .not_additionally_locked();
        let mut change = Scanner::new(refund.change.clone())
            .scan(block)
            .unwrap()
            .not_additionally_locked();
        assert_eq!(outputs.len(), 1);
        assert_eq!(change.len(), 1);
        outputs.append(&mut change);
        assert_eq!(
            outputs.iter().map(|o| o.commitment().amount).sum::<u64>(),
            reserve_amount - refund.prepared.fee()
        );
        let (_, height) = rpc.generate_blocks(&reserve_address, 10).await.unwrap();
        let mut refund_inputs = vec![];
        for output in outputs {
            refund_inputs.push(
                OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, output)
                    .await
                    .unwrap(),
            );
        }
        let onward = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            fresh_secret(),
            refund_inputs,
            vec![(reserve_address, AMOUNT / 2)],
            Change::new(owner.1.clone(), None),
            vec![],
            fee_rate,
        )
        .unwrap()
        .sign(&mut OsRng, &owner.0)
        .unwrap();
        publish_local(&onward).await;
        let (blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        assert!(rpc
            .scannable_block(blocks[0])
            .await
            .unwrap()
            .block
            .transactions
            .contains(&onward.hash()));

        let (dom_refund_height, dom_onward_height, dom_claim_height, rejection) = if audit {
            // Deliberately violate the sender's refusal: disclose the losing
            // claim bytes to the peer. Rejection by monerod cannot erase them.
            // This does NOT claim that a private rejected RPC is auto-relayed.
            dom.assert_height_refund_locked().await;
            let rejection = reject_spent(&stale_claim).await;
            let leaked = monero_wallet::transaction::Transaction::read(
                &mut stale_claim.serialize().as_slice(),
            )
            .unwrap();
            let mut extracted =
                Zeroizing::new(prepared.extract(&leaked, &mut OsRng).unwrap().to_bytes());
            extracted.reverse();
            let secret = SecretScalar::from_be_bytes(*extracted).unwrap();
            let stolen_dom = dom_offer.complete(&secret, &dom.context().await).unwrap();
            let (_, height) = dom.include(&stolen_dom).await;
            let onward = dom.spend_claim_output().await;
            checkpoint(
                "late_claim_exposure_lost_dom",
                json!({"dom_claim_height":height,"dom_onward_height":onward}),
            );
            (None, onward, Some(height), rejection)
        } else {
            // No initial claim bytes leave the honest sender after refusal.
            // Only after BOTH refunds do we expose a replay as a negative test.
            miner.unwrap().wait().await;
            let (height, onward) = dom.include_height_refund_and_spend().await;
            checkpoint(
                "both_refunds_completed_before_late_claim_replay",
                json!({"dom_refund_height":height,"dom_onward_height":onward}),
            );
            let rejection = reject_spent(&stale_claim).await;
            let mut extracted = Zeroizing::new(
                prepared
                    .extract(&stale_claim, &mut OsRng)
                    .unwrap()
                    .to_bytes(),
            );
            extracted.reverse();
            let replay = dom_offer
                .complete(
                    &SecretScalar::from_be_bytes(*extracted).unwrap(),
                    &dom.context().await,
                )
                .unwrap();
            dom.assert_spent_rejection(&replay).await;
            (Some(height), onward, None, rejection)
        };
        let mut report = json!({
            "experiment":if audit {"negative control: a peer extracts from a late losing XMR claim and takes DOM after refunding XMR"}
                else {"XMR refund wins after adaptor delivery; late initial claim refused before exposure; both owners recover"},
            "network":"owned offline regtest", "atomic_swap":false,"bitcoin_involved":false,
            "mainnet_latency_measurement":false,"setup_centralized":true,"safe_bilateral_window_proven":false,
            "authenticated_first_disclosure_clock":false,"conditional_lab_timing_checks_used":true,
            "adaptor_claims_delivered_before_recovery":true,"dom_original_signing_material_dropped":true,
            "same_xmr_key_image_for_claim_and_refund":true,"xmr_refund_included":true,
            "xmr_refund_paid_to_original_funding_owner":true,"all_refund_outputs_onward_spent":true,
            "xmr_buyer_received_payment":false,"late_initial_claim_check_refused":true,
            "late_initial_claim_refusal_deliberately_bypassed":audit,
            "late_claim_exposed_before_dom_refund":audit,"losing_xmr_claim_rejected_as_spent":true,
            "monerod_losing_claim_response":rejection,
            "counterexample_reproduced":audit,"dom_original_owner_recovered":!audit,
            "dom_claim_included":audit,"dom_claim_height":dom_claim_height,
            "dom_refund_height":dom.height_refund_height(),"dom_refund_included_height":dom_refund_height,
            "dom_onward_height":dom_onward_height,"dom_onward_spend_included":true,
            "dom_claim_after_refund_rejected":!audit,
            "capsule_preparation_verification_seconds":capsule_seconds,
            "dom_preparation_seconds":dom_preparation_seconds,
            "offers_ready_elapsed_since_capsule_receipt_seconds":paired_offer_elapsed,
            "xmr_refund_observed_unix":refund_observed_unix,"total_seconds":whole.elapsed().as_secs_f64(),
        });
        report
            .as_object_mut()
            .unwrap()
            .extend(refund.evidence.as_object().unwrap().clone());
        report.as_object_mut().unwrap().extend(
            dom.height_refund_timing()
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
        report
            .as_object_mut()
            .unwrap()
            .extend(funding_evidence.unwrap().as_object().unwrap().clone());
        fs::write(
            root.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    let early_attack = if let Some((recovered, mut report)) = early_refund {
        // Both valid adaptor claims have already been delivered. A refunds DOM
        // first, then uses its retained XMR claim. There is deliberately no
        // safe-deadline admission policy or competing XMR refund in this audit.
        dom.abandon_peer();
        let (refund, onward) = dom.refund_after_recovery(recovered).await;
        report["dom_refund_height"] = json!(refund);
        report["dom_refund_onward_height"] = json!(onward);
        report["dom_refund_onward_spent"] = json!(true);
        Some(report)
    } else {
        None
    };
    // In the inverse direction discard the original witness before observing
    // DOM. XMR completion must use only extraction from the included DOM body.
    let mut included_dom = None;
    let mut dom_completion_seconds = 0.0;
    let xmr_witness = if dom_first {
        if let Some(window) = &paired_release_window {
            window
                .check_initial_claim_release(
                    dom_core::Timestamp(unix_seconds()),
                    InitialClaimOrder::DomFirst,
                    LAB_CLAIM_DELAYS,
                )
                .expect("initial DOM claim release expired");
        }
        let dom_start = Instant::now();
        let mut bytes = Zeroizing::new(witness.to_bytes());
        bytes.reverse();
        let final_dom = dom_offer
            .complete(
                &SecretScalar::from_be_bytes(*bytes).unwrap(),
                &dom.context().await,
            )
            .unwrap();
        let decoded_dom =
            dom_consensus::Transaction::from_bytes(&final_dom.to_bytes().unwrap()).unwrap();
        dom_consensus::validate_transaction(&decoded_dom, &dom.context().await).unwrap();
        drop(bytes);
        drop(witness);
        drop(shared);
        dom_completion_seconds = dom_start.elapsed().as_secs_f64();
        if let Some(window) = &paired_release_window {
            window
                .check_initial_claim_release(
                    dom_core::Timestamp(unix_seconds()),
                    InitialClaimOrder::DomFirst,
                    LAB_CLAIM_DELAYS,
                )
                .expect("initial DOM publication expired");
        }
        let (observed_dom, height) = if loses_ack {
            journaled_initial_send(
                &root,
                joint_operation_binding,
                paired_release_window.as_ref().unwrap(),
                InitialClaimOrder::DomFirst,
                &decoded_dom.to_bytes().unwrap(),
                || async {
                    dom.submit_without_mining(&decoded_dom);
                },
            )
            .await;
            initial_pending_probe = Some(
                settlement_resume::assert_pending_first_cannot_create_obligation(
                    &root,
                    joint_operation_binding,
                )
                .await,
            );
            dom.include_submitted(&decoded_dom).await
        } else if let Some(window) = &paired_release_window {
            journaled_initial_send(
                &root,
                joint_operation_binding,
                window,
                InitialClaimOrder::DomFirst,
                &decoded_dom.to_bytes().unwrap(),
                || dom.include(&decoded_dom),
            )
            .await
        } else {
            dom.include(&decoded_dom).await
        };
        if let Some(artifacts) = &resume_artifacts {
            // No original signing preparation, witness or live offer object is
            // passed into either new process. Nodes remain owned by this parent.
            drop((prepared, dom_offer));
            let (raw, evidence) = if loses_ack {
                settlement_resume::crash_then_reconstruct(
                    &root,
                    joint_operation_binding,
                    DeliveryBinding {
                        manifest: artifacts.manifest_digest(),
                        first_claim: dxp1_clsag_lab::claim_resume::digest(
                            &observed_dom.to_bytes().unwrap(),
                        ),
                        first_block: dom.canonical_hash(height),
                        first_height: height,
                        target_chain: xmr_chain.unwrap(),
                    },
                )
                .await
            } else {
                artifacts.crash_then_complete(
                    true,
                    &observed_dom.to_bytes().unwrap(),
                    &dom.context().await,
                )
            };
            (prepared, dom_offer) = artifacts.load();
            let mut input = raw.as_slice();
            let tx = monero_wallet::transaction::Transaction::read(&mut input).unwrap();
            assert!(input.is_empty());
            assert_eq!(tx.serialize(), raw);
            prepared.verify_final(&tx, &mut OsRng).unwrap();
            resumed_xmr_transaction = Some(tx);
            resume_evidence = Some(evidence);
            first_claim_reference = Some((
                dxp1_clsag_lab::claim_resume::digest(&observed_dom.to_bytes().unwrap()),
                dom.canonical_hash(height),
                height,
            ));
            checkpoint("claim_worker_restored_after_dom_payment", json!({}));
        }
        let mut extracted = dom_offer
            .extract(&observed_dom, &dom.context().await)
            .unwrap();
        extracted.reverse();
        let recovered = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(*extracted)).unwrap(),
        );
        assert_eq!(
            (*recovered * G).compress().to_bytes(),
            cross_curve_proof.claim.ed_compressed
        );
        included_dom = Some(height);
        recovered
    } else {
        drop(shared);
        witness
    };
    if !dom_first {
        if let Some(window) = &paired_release_window {
            window
                .check_initial_claim_release(
                    dom_core::Timestamp(unix_seconds()),
                    InitialClaimOrder::XmrFirst,
                    LAB_CLAIM_DELAYS,
                )
                .expect("initial XMR claim release expired");
        }
    }
    let tx = resumed_xmr_transaction
        .unwrap_or_else(|| prepared.complete(&xmr_witness, &mut OsRng).unwrap());
    let xmr_transaction_ready_seconds = claim_start.elapsed().as_secs_f64();
    if !dom_first {
        if let Some(window) = &paired_release_window {
            window
                .check_initial_claim_release(
                    dom_core::Timestamp(unix_seconds()),
                    InitialClaimOrder::XmrFirst,
                    LAB_CLAIM_DELAYS,
                )
                .expect("initial XMR publication expired");
        }
    }
    if !dom_first {
        if let Some(window) = &paired_release_window {
            journaled_initial_send(
                &root,
                joint_operation_binding,
                window,
                InitialClaimOrder::XmrFirst,
                &tx.serialize(),
                || publish_local(&tx),
            )
            .await;
        } else {
            publish_local(&tx).await;
        }
    } else {
        // This is an owed counterpart after canonical DOM payment, NOT a new
        // initial release. Do not apply the initial gate to this obligation.
        if loses_ack {
            assert_eq!(observe_xmr(&tx).await, Observation::AbsentAndUnspent);
            let (first_claim, first_block, first_height) = first_claim_reference.unwrap();
            let binding = DeliveryBinding {
                manifest: resume_artifacts.as_ref().unwrap().manifest_digest(),
                first_claim,
                first_block,
                first_height,
                target_chain: xmr_chain.unwrap(),
            };
            let delivery = if native_send {
                let evidence =
                    settlement_resume::native_send_after_restart(&root, joint_operation_binding)
                        .await;
                counterpart_delivery_bridge::PendingDelivery::track_native_sender(
                    &root,
                    binding,
                    &tx.serialize(),
                    evidence,
                )
            } else {
                counterpart_delivery_bridge::send_without_reply(
                    &root,
                    binding,
                    &tx.serialize(),
                    || publish_local(&tx),
                )
                .await
            };
            delivery.reconcile(observe_xmr(&tx).await, DeliveryAction::MonitorPool);
            let resumed =
                settlement_resume::observe_in_fresh_process(&root, joint_operation_binding).await;
            assert_eq!(resumed["action"], "MonitorPool", "{resumed}");
            settlement_observations.push(resumed);
            if native_send {
                native_send_probes.push(
                    settlement_resume::assert_native_send_suppressed(
                        &root,
                        joint_operation_binding,
                        "MonitorPool",
                    )
                    .await,
                );
            }
            pending_delivery = Some(delivery);
        } else {
            publish_local(&tx).await;
        }
    }
    let xmr_witness = if resume_worker {
        drop(xmr_witness);
        None
    } else {
        Some(xmr_witness)
    };
    if loses_ack && !dom_first {
        initial_pending_probe = Some(
            settlement_resume::assert_pending_first_cannot_create_obligation(
                &root,
                joint_operation_binding,
            )
            .await,
        );
    }
    if pair_outcome == Some(PairOutcome::XmrFirstNativeReplay) {
        initial_replay_without_history_probe = Some(
            settlement_resume::assert_exposure_alone_cannot_replay_first(
                &root,
                joint_operation_binding,
            )
            .await,
        );
    }
    let (claim_blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
    let mut block = rpc.scannable_block(claim_blocks[0]).await.unwrap();
    assert!(
        block.block.transactions.contains(&tx.hash()),
        "claim must be included"
    );
    let xmr_claim_observed_unix = unix_seconds();
    if let Some(earliest) = paired_earliest_recovery {
        assert!(
            xmr_claim_observed_unix < earliest.0,
            "XMR claim missed the conditional earliest recovery boundary"
        );
        checkpoint(
            "xmr_claim_included_before_conditional_recovery",
            json!({
                "claim_observed_unix":xmr_claim_observed_unix,
                "conditional_earliest_recovery_unix":earliest.0,
            }),
        );
    }
    let observed = rpc.transactions(&[tx.hash()]).await.unwrap().remove(0);
    if loses_ack {
        let height = rpc.latest_block_number().await.unwrap();
        assert_eq!(
            rpc.block_by_number(height).await.unwrap().hash(),
            claim_blocks[0]
        );
        if dom_first {
            pending_delivery.as_ref().unwrap().reconcile(
                Observation::Included {
                    block: claim_blocks[0],
                    height: height as u64,
                },
                DeliveryAction::MonitorInclusion,
            );
            let resumed =
                settlement_resume::observe_in_fresh_process(&root, joint_operation_binding).await;
            assert_eq!(resumed["action"], "MonitorInclusion", "{resumed}");
            settlement_observations.push(resumed);
            if native_send {
                native_send_probes.push(
                    settlement_resume::assert_native_send_suppressed(
                        &root,
                        joint_operation_binding,
                        "MonitorInclusion",
                    )
                    .await,
                );
            }
        } else {
            first_claim_reference = Some((
                dxp1_clsag_lab::claim_resume::digest(&observed.serialize()),
                claim_blocks[0],
                height as u64,
            ));
        }
    }
    if pair_outcome == Some(PairOutcome::DomFirstXmrDetach) {
        // Mutate only the fresh owned fakechain. Native detachment exercises
        // actual consensus storage/pool state, not a fabricated observation.
        // This is not yet a competing-peer fork-choice/reorg experiment.
        let began = Instant::now();
        let before_height = rpc.latest_block_number().await.unwrap();
        let old_hash = block.block.hash();
        assert_eq!(
            rpc.block_by_number(before_height).await.unwrap().hash(),
            old_hash
        );
        let frozen = fs::read(root.join("counterpart-delivery.wal")).unwrap();
        checkpoint(
            "xmr_detach_started",
            json!({"original_height":before_height}),
        );
        let popped: serde_json::Value = serde_json::from_str(
            &rpc.rpc_call("pop_blocks", Some(json!({"nblocks":1}).to_string()), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(popped["status"], "OK", "{popped}");
        checkpoint("xmr_block_detached", json!({"native_reply":popped}));
        assert_eq!(rpc.latest_block_number().await.unwrap() + 1, before_height);
        let in_pool = settlement_resume::assert_native_send_suppressed(
            &root,
            joint_operation_binding,
            "MonitorPool",
        )
        .await;
        let flushed: serde_json::Value = serde_json::from_str(
            &rpc.json_rpc_call(
                "flush_txpool",
                Some(json!({"txids":[settlement_resume::hex(&tx.hash())]}).to_string()),
                16384,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(flushed["status"], "OK", "{flushed}");
        checkpoint("xmr_detached_claim_removed_from_pool", json!({}));
        // Replace the removed block WITHOUT the claim; reinclusion must occur
        // at another height/hash, avoiding an identical regenerated block.
        let (empty_blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        assert!(!rpc
            .block_by_number(before_height)
            .await
            .unwrap()
            .transactions
            .contains(&tx.hash()));
        assert_ne!(empty_blocks[0], old_hash);
        let retransmitted = settlement_resume::retry_absent_counterpart_in_fresh_process(
            &root,
            joint_operation_binding,
        )
        .await;
        assert_eq!(
            rpc.transactions(&[tx.hash()]).await.unwrap()[0].serialize(),
            tx.serialize()
        );
        let (replacement, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        block = rpc.scannable_block(replacement[0]).await.unwrap();
        assert!(block.block.transactions.contains(&tx.hash()));
        assert_ne!(block.block.hash(), old_hash);
        checkpoint("xmr_detached_claim_remined", json!({}));
        let reincluded = settlement_resume::assert_native_send_suppressed(
            &root,
            joint_operation_binding,
            "MonitorInclusion",
        )
        .await;
        assert_eq!(
            fs::read(root.join("counterpart-delivery.wal")).unwrap(),
            frozen
        );
        let recovered_at = unix_seconds();
        assert!(
            recovered_at < paired_earliest_recovery.unwrap().0,
            "detachment recovery exceeded the ORIGINAL conditional recovery boundary"
        );
        let evidence = json!({
            "native_detachment":true,"competing_peer_reorg":false,
            "removed_block":settlement_resume::hex(&old_hash),
            "replacement_empty_block":settlement_resume::hex(&empty_blocks[0]),
            "reinclusion_block":settlement_resume::hex(&replacement[0]),
            "original_height":before_height,
            "reinclusion_height":rpc.latest_block_number().await.unwrap(),
            "pool_after_detach":in_pool,"absent_retry":retransmitted,
            "reincluded":reincluded,"journal_unchanged":true,
            "same_native_transaction":true,"recovered_at_unix":recovered_at,
            "original_conditional_earliest_recovery_unix":paired_earliest_recovery.unwrap().0,
            "seconds":began.elapsed().as_secs_f64()
        });
        checkpoint(
            "xmr_counterpart_reincluded_after_native_detachment",
            evidence.clone(),
        );
        xmr_detach_evidence = Some(evidence);
    }
    if !dom_first {
        if let Some(artifacts) = &resume_artifacts {
            drop((prepared, dom_offer));
            let (raw, evidence) = if loses_ack {
                let (first_claim, first_block, first_height) = first_claim_reference.unwrap();
                settlement_resume::crash_then_reconstruct(
                    &root,
                    joint_operation_binding,
                    DeliveryBinding {
                        manifest: artifacts.manifest_digest(),
                        first_claim,
                        first_block,
                        first_height,
                        target_chain: *dom.claim.chain(),
                    },
                )
                .await
            } else {
                artifacts.crash_then_complete(false, &observed.serialize(), &dom.context().await)
            };
            (prepared, dom_offer) = artifacts.load();
            let tx = dom_consensus::Transaction::from_bytes(&raw).unwrap();
            assert_eq!(tx.to_bytes().unwrap(), raw);
            dom_offer.validate(&tx, &dom.context().await).unwrap();
            resumed_dom_transaction = Some(tx);
            resume_evidence = Some(evidence);
            checkpoint("claim_worker_restored_after_xmr_payment", json!({}));
        }
    }
    if matches!(
        pair_outcome,
        Some(PairOutcome::XmrFirstReinclude | PairOutcome::XmrFirstNativeReplay)
    ) {
        let native_first_replay = pair_outcome == Some(PairOutcome::XmrFirstNativeReplay);
        let began = Instant::now();
        let old_height = rpc.latest_block_number().await.unwrap();
        let old_block = block.block.hash();
        assert_eq!(
            rpc.block_by_number(old_height).await.unwrap().hash(),
            old_block
        );
        let crashed =
            settlement_resume::expose_before_first_detachment(&root, joint_operation_binding).await;
        let record_paths = [
            root.join("counterpart-delivery.wal"),
            root.join("initial-claim.wal"),
            root.join("initial-claim.tx"),
            root.join("claim-resume/manifest.record"),
        ];
        let frozen: Vec<_> = record_paths.iter().map(|p| fs::read(p).unwrap()).collect();
        checkpoint("first_xmr_detachment_started", json!({"height":old_height}));
        let popped: serde_json::Value = serde_json::from_str(
            &rpc.rpc_call("pop_blocks", Some(json!({"nblocks":1}).to_string()), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(popped["status"], "OK");
        assert_eq!(rpc.latest_block_number().await.unwrap() + 1, old_height);
        assert_eq!(observe_xmr(&tx).await, Observation::InPool);
        let first_pool_monitor = if native_first_replay {
            Some(
                settlement_resume::assert_first_replay_suppressed(
                    &root,
                    joint_operation_binding,
                    "MonitorFirstPool",
                )
                .await,
            )
        } else {
            None
        };
        let in_pool = settlement_resume::assert_noncanonical_first_preserves_obligation(
            &root,
            joint_operation_binding,
        )
        .await;
        let flushed: serde_json::Value = serde_json::from_str(
            &rpc.json_rpc_call(
                "flush_txpool",
                Some(json!({"txids":[settlement_resume::hex(&tx.hash())]}).to_string()),
                16384,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(flushed["status"], "OK");
        assert_eq!(observe_xmr(&tx).await, Observation::AbsentAndUnspent);
        let absent = settlement_resume::assert_noncanonical_first_preserves_obligation(
            &root,
            joint_operation_binding,
        )
        .await;
        checkpoint(
            "first_xmr_noncanonical_obligation_preserved",
            json!({"pool":in_pool,"absent":absent}),
        );
        let (empty, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        assert_ne!(empty[0], old_block);
        assert!(!rpc
            .block_by_number(old_height)
            .await
            .unwrap()
            .transactions
            .contains(&tx.hash()));
        assert_eq!(
            fs::read(root.join("initial-claim.tx")).unwrap(),
            tx.serialize()
        );
        let first_replay = if native_first_replay {
            Some(
                settlement_resume::replay_first_after_restart(&root, joint_operation_binding).await,
            )
        } else {
            // Historical fixture path retained as its own explicit mode.
            publish_local(&tx).await;
            None
        };
        assert_eq!(
            rpc.transactions(&[tx.hash()]).await.unwrap()[0].serialize(),
            tx.serialize()
        );
        let (reincluded_blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        block = rpc.scannable_block(reincluded_blocks[0]).await.unwrap();
        assert!(block.block.transactions.contains(&tx.hash()));
        let new_height = rpc.latest_block_number().await.unwrap();
        assert_eq!(new_height, old_height + 1);
        assert_ne!(reincluded_blocks[0], old_block);
        let first_inclusion_monitor = if native_first_replay {
            Some(
                settlement_resume::assert_first_replay_suppressed(
                    &root,
                    joint_operation_binding,
                    "MonitorFirstInclusion",
                )
                .await,
            )
        } else {
            None
        };
        let restored = settlement_resume::assert_first_reincluded(
            &root,
            joint_operation_binding,
            old_block,
            old_height as u64,
            reincluded_blocks[0],
            new_height as u64,
        )
        .await;
        for (path, bytes) in record_paths.iter().zip(&frozen) {
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
        let included_at = unix_seconds();
        assert!(
            included_at < paired_earliest_recovery.unwrap().0,
            "first reinclusion missed ORIGINAL conditional recovery boundary"
        );
        let evidence = json!({
            "native_detachment":true,"competing_peer_reorg":false,
            "first_transaction_rebroadcast_by_fixture":!native_first_replay,
            "native_first_replay":first_replay,"first_pool_monitor":first_pool_monitor,
            "first_inclusion_monitor":first_inclusion_monitor,
            "counterpart_exposure_before_detachment":crashed,
            "pool_reconciliation":in_pool,"absent_reconciliation":absent,
            "restored":restored,"original_block":settlement_resume::hex(&old_block),
            "original_height":old_height,"new_block":settlement_resume::hex(&reincluded_blocks[0]),
            "new_height":new_height,"original_records_unchanged":true,
            "included_at_unix":included_at,"original_conditional_earliest_recovery_unix":paired_earliest_recovery.unwrap().0,
            "seconds":began.elapsed().as_secs_f64()
        });
        checkpoint("first_xmr_reincluded_obligation_restored", evidence.clone());
        first_reinclusion_evidence = Some(evidence);
    }
    prepared.verify_final(&observed, &mut OsRng).unwrap();
    let recovered = prepared.extract(&observed, &mut OsRng).unwrap();
    if let Some(witness) = &xmr_witness {
        assert_eq!(*recovered, **witness);
    }
    assert_eq!(
        (*recovered * G).compress().to_bytes(),
        cross_curve_proof.claim.ed_compressed
    );
    drop(xmr_witness);
    let mut owner_change = if pair_outcome.is_some() {
        let (_, view) = direct_owner_wallet.as_ref().unwrap();
        let outputs = Scanner::new(view.clone())
            .scan(block.clone())
            .unwrap()
            .not_additionally_locked();
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0].commitment().amount,
            reserve_amount - AMOUNT - prepared.fee()
        );
        outputs
    } else {
        vec![]
    };
    let mut recipient_scanner = Scanner::new(recipient_view.clone());
    let mut received = recipient_scanner
        .scan(block)
        .unwrap()
        .not_additionally_locked();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].commitment().amount, AMOUNT);
    let claim_inclusion_seconds = claim_start.elapsed().as_secs_f64();
    let dom_claim_height = if let Some(height) = included_dom {
        Some(height)
    } else {
        let dom_start = Instant::now();
        let mut to_dom = Zeroizing::new(recovered.to_bytes());
        to_dom.reverse();
        let final_dom = if let Some(tx) = resumed_dom_transaction {
            tx
        } else {
            dom_offer
                .complete(
                    &SecretScalar::from_be_bytes(*to_dom).unwrap(),
                    &dom.context().await,
                )
                .unwrap()
        };
        let decoded_dom =
            dom_consensus::Transaction::from_bytes(&final_dom.to_bytes().unwrap()).unwrap();
        dom_consensus::validate_transaction(&decoded_dom, &dom.context().await).unwrap();
        assert_eq!(
            *dom_offer
                .extract(&decoded_dom, &dom.context().await)
                .unwrap(),
            *to_dom
        );
        dom_completion_seconds = dom_start.elapsed().as_secs_f64();
        if early_attack.is_some() {
            dom.assert_spent_rejection(&decoded_dom).await;
            None
        } else {
            let (observed_dom, height) = if loses_ack {
                dom.assert_absent_and_unspent(&decoded_dom);
                let (first_claim, first_block, first_height) = first_claim_reference.unwrap();
                let binding = DeliveryBinding {
                    manifest: resume_artifacts.as_ref().unwrap().manifest_digest(),
                    first_claim,
                    first_block,
                    first_height,
                    target_chain: *dom.claim.chain(),
                };
                let delivery = if native_send {
                    let evidence = settlement_resume::native_send_after_restart(
                        &root,
                        joint_operation_binding,
                    )
                    .await;
                    counterpart_delivery_bridge::PendingDelivery::track_native_sender(
                        &root,
                        binding,
                        &decoded_dom.to_bytes().unwrap(),
                        evidence,
                    )
                } else {
                    counterpart_delivery_bridge::send_without_reply(
                        &root,
                        binding,
                        &decoded_dom.to_bytes().unwrap(),
                        || async {
                            dom.submit_without_mining(&decoded_dom);
                        },
                    )
                    .await
                };
                dom.assert_in_pool(&decoded_dom);
                delivery.reconcile(Observation::InPool, DeliveryAction::MonitorPool);
                let resumed =
                    settlement_resume::observe_in_fresh_process(&root, joint_operation_binding)
                        .await;
                assert_eq!(resumed["action"], "MonitorPool", "{resumed}");
                settlement_observations.push(resumed);
                if native_send {
                    native_send_probes.push(
                        settlement_resume::assert_native_send_suppressed(
                            &root,
                            joint_operation_binding,
                            "MonitorPool",
                        )
                        .await,
                    );
                }
                let (observed, height) = dom.include_submitted(&decoded_dom).await;
                delivery.reconcile(
                    Observation::Included {
                        block: dom.canonical_hash(height),
                        height,
                    },
                    DeliveryAction::MonitorInclusion,
                );
                let resumed =
                    settlement_resume::observe_in_fresh_process(&root, joint_operation_binding)
                        .await;
                assert_eq!(resumed["action"], "MonitorInclusion", "{resumed}");
                settlement_observations.push(resumed);
                if native_send {
                    native_send_probes.push(
                        settlement_resume::assert_native_send_suppressed(
                            &root,
                            joint_operation_binding,
                            "MonitorInclusion",
                        )
                        .await,
                    );
                }
                pending_delivery = Some(delivery);
                (observed, height)
            } else {
                dom.include(&decoded_dom).await
            };
            assert_eq!(
                *dom_offer
                    .extract(&observed_dom, &dom.context().await)
                    .unwrap(),
                *to_dom
            );
            Some(height)
        }
    };
    let direct_claims_inclusion_seconds = claim_start.elapsed().as_secs_f64();
    let claims_included_total_seconds = whole.elapsed().as_secs_f64();
    checkpoint(
        "both_claims_included",
        json!({"dom_claim_height":dom_claim_height}),
    );
    if let Some(server) = &mut settlement_rpc {
        // A new process must not reuse an earlier successful observation when
        // an actual required native endpoint is unavailable.
        server.stop().await;
        let resumed =
            settlement_resume::observe_in_fresh_process(&root, joint_operation_binding).await;
        assert_eq!(resumed["action"], "Reconcile", "{resumed}");
        assert_eq!(resumed["reason"], "DOM RPC unavailable", "{resumed}");
        settlement_observations.push(resumed);
        if native_send {
            native_send_probes.push(
                settlement_resume::assert_native_send_suppressed(
                    &root,
                    joint_operation_binding,
                    "Reconcile",
                )
                .await,
            );
        }
    }
    let dom_onward_height = if dom_claim_height.is_some() {
        Some(if height_refund {
            dom.spend_claim_output().await
        } else {
            dom.prove_onward_spend_and_reject_double_spend().await
        })
    } else {
        None
    };

    // A received output still needs its mandatory age. Mine it explicitly,
    // then prove that the recipient can actually spend the resulting output.
    let (_, height) = rpc.generate_blocks(&reserve_address, 10).await.unwrap();
    let next_input = OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, received.remove(0))
        .await
        .unwrap();
    let onward = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        fresh_secret(),
        vec![next_input],
        vec![(reserve_address, AMOUNT / 2)],
        Change::new(recipient_view, None),
        vec![],
        fee_rate,
    )
    .unwrap()
    .sign(&mut OsRng, &recipient_spend)
    .unwrap();
    publish_local(&onward).await;
    let (last, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
    assert!(rpc
        .scannable_block(last[0])
        .await
        .unwrap()
        .block
        .transactions
        .contains(&onward.hash()));
    if pair_outcome.is_some() {
        let (spend, view) = direct_owner_wallet.as_ref().unwrap();
        let height = rpc.latest_block_number().await.unwrap();
        let input = OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, owner_change.remove(0))
            .await
            .unwrap();
        let change = ViewPair::new(
            Point::from((**spend).into() * G),
            Zeroizing::new(MoneroScalar::random(&mut OsRng)),
        )
        .unwrap();
        let tx = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            fresh_secret(),
            vec![input],
            vec![(view.legacy_address(Network::Mainnet), AMOUNT / 2)],
            Change::new(change, None),
            vec![],
            fee_rate,
        )
        .unwrap()
        .sign(&mut OsRng, spend)
        .unwrap();
        publish_local(&tx).await;
        let (blocks, _) = rpc.generate_blocks(&reserve_address, 1).await.unwrap();
        assert!(rpc
            .scannable_block(blocks[0])
            .await
            .unwrap()
            .block
            .transactions
            .contains(&tx.hash()));
    }
    if let Some(mut report) = early_attack {
        assert!(dom_claim_height.is_none() && dom_onward_height.is_none());
        report["counterexample_reproduced"] = json!(true);
        report["adaptor_claims_delivered_before_refund"] = json!(true);
        report["xmr_payment_included"] = json!(true);
        report["xmr_payment_onward_spent"] = json!(true);
        report["xmr_received_atomic"] = json!(AMOUNT);
        report["valid_dom_claim_rejected_as_spent"] = json!(true);
        report["dom_payee_received_claim_output"] = json!(false);
        report["recipient_maturity_blocks_mined"] = json!(10);
        report["total_seconds"] = json!(whole.elapsed().as_secs_f64());
        fs::write(
            root.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    let mut claim_won_race = None;
    let mut race_miner = None;
    if pair_outcome == Some(PairOutcome::ClaimWins) {
        race_miner = Some(dom.start_refund_height_mining());
        checkpoint("claim_won_recovery_started", json!({}));
        let refund = recover_race_refund(
            race_reserve.take().unwrap(),
            direct_recovery.take().unwrap(),
            direct_owner_wallet.as_ref().unwrap(),
            fee_rate,
            AMOUNT,
        )
        .await;
        assert_eq!(prepared.context().image, refund.prepared.context().image);
        let rejection = reject_spent(&refund.transaction).await;
        let mut evidence = refund.evidence;
        evidence["valid_recovered_xmr_refund_rejected_as_spent"] = json!(true);
        evidence["monerod_losing_refund_response"] = rejection;
        claim_won_race = Some(evidence);
        checkpoint("recovered_refund_lost_to_included_claim", json!({}));
    }
    if height_refund {
        checkpoint(
            "onward_spends_included",
            json!({
                "dom_height":dom.context().await.current_height.0,
                "dom_refund_height":dom.height_refund_height(),
            }),
        );
        if let Some(miner) = race_miner {
            miner.wait().await;
        } else {
            dom.mine_to_refund_height().await;
        }
        dom.assert_spent_rejection(&dom.height_refund_transaction())
            .await;
        checkpoint(
            "late_dom_refund_rejected",
            json!({"height":dom.context().await.current_height.0}),
        );
    }
    let mut report = json!({
        "experiment": "DXP1 observed first claim directly completes funded counterpart", "network": "owned offline regtest",
        "atomic_swap": false, "mainnet_latency_measurement": false,
        "flow": if dom_first { "DOM -> XMR" } else { "XMR -> DOM" }, "bitcoin_involved": false,
        "dom_input_funded": true, "dom_consensus_validated": true,
        "dom_claim_included": true, "dom_funding_height": dom.funding_height,
        "dom_claim_height": dom_claim_height, "dom_onward_height": dom_onward_height,
        "dom_onward_spend_included": true, "dom_conflicting_spend_rejected": true,
        "dom_preparation_seconds": dom_preparation_seconds,
        "dom_regtest_fast_pow": true, "dom_regtest_coinbase_maturity": dom_core::REGTEST_COINBASE_MATURITY,
        "setup_centralized": true, "recovery_exercised": false,
        "dom_claim_two_party_signing": true, "dom_kernel_secret_reconstructed": false,
        "dom_reserve_shared": true, "dom_reserve_opening_reconstructed": false,
        "dom_reserve_range_proof_mpc": true, "dom_single_share_claims_rejected": true,
        "direct_claims_through_local_inclusion_seconds": direct_claims_inclusion_seconds,
        "claims_included_total_seconds":claims_included_total_seconds,
        "counterpart_secret_source": if dom_first {
            "extracted from exact DOM transaction fetched from canonical block in owned node"
        } else {
            "extracted from exact XMR transaction fetched from owned monerod"
        },
        "dom_first_original_witness_dropped_before_observation": dom_first,
        "dom_completion_seconds": dom_completion_seconds,
        "preparation_blocks": 140, "preparation_seconds": preparation_seconds,
        "claims_preparation_seconds": claims_preparation_seconds,
        "xmr_transaction_ready_seconds": xmr_transaction_ready_seconds,
        "xmr_claim_through_local_inclusion_seconds": claim_inclusion_seconds,
        "recipient_maturity_blocks_mined": 10, "recipient_onward_spend_included": true,
        "amount_atomic": AMOUNT, "fee_atomic": prepared.fee(), "total_seconds": whole.elapsed().as_secs_f64(),
    });
    report["dom_height_refund_prepared_before_funding"] = json!(height_refund);
    report["dom_original_signing_material_dropped"] = json!(height_refund);
    report["dom_refund_after_claim_rejected"] = json!(height_refund);
    report["dom_refund_height"] = json!(if height_refund {
        Some(dom.height_refund_height())
    } else {
        None
    });
    report["dom_reserve_share_capsule_exists"] = json!(false);
    if let Some(delivery) = pending_delivery {
        report
            .as_object_mut()
            .unwrap()
            .extend(delivery.evidence.as_object().unwrap().clone());
        report["counterpart_reconciled_from_native_pool_and_block_after_sender_exit"] = json!(true);
        report["settlement_observers"] = json!(settlement_observations);
        report["native_send_suppression_probes"] = json!(native_send_probes);
        report["xmr_native_detachment"] = json!(xmr_detach_evidence);
        report["first_payment_native_reinclusion"] = json!(first_reinclusion_evidence);
        report["initial_replay_without_history_probe"] =
            json!(initial_replay_without_history_probe);
        report["initial_pending_reconstruction_probe"] = json!(initial_pending_probe);
        report["settlement_observer_receives_parent_chain_interpretation"] = json!(false);
        report["operation_checkpoint_synced_before_initial_release"] = json!(true);
        report["settlement_observer_queries_native_nodes_independently"] = json!(true);
        report["parent_remains_native_node_host_and_fixture_miner"] = json!(true);
    }
    if let Some(evidence) = resume_evidence {
        report
            .as_object_mut()
            .unwrap()
            .extend(evidence.as_object().unwrap().clone());
        report["claim_worker_restart_exercised"] = json!(true);
    }
    if pair_outcome.is_some() {
        if let Some((_, _, capsule)) = direct_recovery {
            report
                .as_object_mut()
                .unwrap()
                .extend(capsule.cancel().as_object().unwrap().clone());
        }
        report.as_object_mut().unwrap().extend(
            dom.height_refund_timing()
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
        report
            .as_object_mut()
            .unwrap()
            .extend(funding_evidence.unwrap().as_object().unwrap().clone());
        report["experiment"] = json!("direct DOM/XMR claims with verified direct XMR capsule and conditional native DOM refund height");
        report["capsule_preparation_verification_seconds"] = json!(capsule_seconds);
        report["offers_ready_elapsed_since_capsule_receipt_seconds"] = json!(paired_offer_elapsed);
        report["claims_bind_exact_recovery_and_dom_refund"] = json!(true);
        report["xmr_claim_observed_unix"] = json!(xmr_claim_observed_unix);
        report["xmr_claim_preceded_conditional_earliest_recovery"] = json!(true);
        report["initial_claim_release_checked_before_publication"] = json!(true);
        report["initial_claim_exposure_fsynced_before_publication"] = json!(true);
        report["initial_claim_journal_reopened_before_and_after_send"] = json!(true);
        report["full_executor_restart_exercised"] = json!(false);
        report["dom_post_bootstrap_walletless_regtest_mining"] = json!(true);
        report["xmr_change_paid_to_original_funding_owner"] = json!(true);
        report["xmr_owner_change_amount_atomic"] = json!(reserve_amount - AMOUNT - prepared.fee());
        report["xmr_owner_change_onward_spent"] = json!(true);
        report["conditional_lab_timing_checks_used"] = json!(true);
        report["authenticated_first_disclosure_clock"] = json!(false);
        report["safe_bilateral_window_proven"] = json!(false);
        report["total_seconds"] = json!(whole.elapsed().as_secs_f64());
        if let Some(evidence) = claim_won_race {
            report
                .as_object_mut()
                .unwrap()
                .extend(evidence.as_object().unwrap().clone());
            report["experiment"] = json!("both cooperative claims win; public recovery produces a valid XMR refund which monerod rejects as spent");
            report["recovery_exercised"] = json!(true);
            report["adaptor_claims_delivered_before_recovery"] = json!(true);
        }
    }
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--settlement-resume-worker")
    {
        args.next();
        settlement_resume::worker(args).await;
        return;
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--counterpart-delivery-worker")
    {
        args.next();
        counterpart_delivery_bridge::worker(args);
        return;
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--claim-resume-worker")
    {
        args.next();
        claim_resume_bridge::worker(args);
        return;
    }
    let binary = args
        .next()
        .map(PathBuf::from)
        .expect("usage: regtest_claim /absolute/path/to/monerod [xmr-first|dom-first|height-xmr-first|height-dom-first|(xmr-recovery|xmr-recovery-bad-first|early-dom-refund) /absolute/bridge count]");
    let mode = match args.next() {
        None => Mode::XmrFirst,
        Some(arg) if arg == "xmr-first" => Mode::XmrFirst,
        Some(arg) if arg == "dom-first" => Mode::DomFirst,
        Some(arg) if arg == "height-xmr-first" => Mode::HeightXmrFirst,
        Some(arg) if arg == "height-dom-first" => Mode::HeightDomFirst,
        Some(arg)
            if arg == "direct-pair-xmr-first"
                || arg == "direct-pair-dom-first"
                || arg == "direct-pair-xmr-first-resume"
                || arg == "direct-pair-dom-first-resume"
                || arg == "direct-pair-xmr-first-ack-loss"
                || arg == "direct-pair-dom-first-ack-loss"
                || arg == "direct-pair-xmr-first-native-send"
                || arg == "direct-pair-dom-first-native-send"
                || arg == "direct-pair-dom-first-xmr-detach"
                || arg == "direct-pair-xmr-first-reinclude"
                || arg == "direct-pair-xmr-first-native-replay"
                || arg == "direct-pair-abandon"
                || arg == "direct-pair-claim-wins"
                || arg == "direct-pair-refund-wins"
                || arg == "direct-pair-late-claim-audit" =>
        {
            let bridge = PathBuf::from(args.next().expect("absolute direct bridge path required"));
            assert!(bridge.is_absolute() && bridge.is_file());
            let outcome = if arg == "direct-pair-xmr-first-native-replay" {
                PairOutcome::XmrFirstNativeReplay
            } else if arg == "direct-pair-xmr-first-reinclude" {
                PairOutcome::XmrFirstReinclude
            } else if arg == "direct-pair-dom-first-xmr-detach" {
                PairOutcome::DomFirstXmrDetach
            } else if arg == "direct-pair-xmr-first-native-send" {
                PairOutcome::XmrFirstNativeSend
            } else if arg == "direct-pair-dom-first-native-send" {
                PairOutcome::DomFirstNativeSend
            } else if arg == "direct-pair-xmr-first-ack-loss" {
                PairOutcome::XmrFirstAckLoss
            } else if arg == "direct-pair-dom-first-ack-loss" {
                PairOutcome::DomFirstAckLoss
            } else if arg == "direct-pair-xmr-first-resume" {
                PairOutcome::XmrFirstResume
            } else if arg == "direct-pair-dom-first-resume" {
                PairOutcome::DomFirstResume
            } else if arg == "direct-pair-xmr-first" {
                PairOutcome::XmrFirst
            } else if arg == "direct-pair-dom-first" {
                PairOutcome::DomFirst
            } else if arg == "direct-pair-claim-wins" {
                PairOutcome::ClaimWins
            } else if arg == "direct-pair-refund-wins" {
                PairOutcome::RefundWins
            } else if arg == "direct-pair-late-claim-audit" {
                PairOutcome::LateClaimLeakAudit
            } else {
                PairOutcome::Abandon
            };
            Mode::DirectPair { bridge, outcome }
        }
        Some(arg) if arg == "xmr-direct-recovery" => {
            let bridge = PathBuf::from(args.next().expect("absolute direct bridge path required"));
            assert!(bridge.is_absolute() && bridge.is_file());
            let squarings = args
                .next()
                .map(|arg| arg.into_string().unwrap().parse().unwrap())
                .unwrap_or(200_000);
            assert!(
                matches!(squarings, 200_000 | 10_000_000),
                "unsupported direct lab profile"
            );
            Mode::XmrDirectRecovery { bridge, squarings }
        }
        Some(arg)
            if arg == "xmr-recovery"
                || arg == "xmr-recovery-bad-first"
                || arg == "early-dom-refund" =>
        {
            let bridge = PathBuf::from(args.next().expect("absolute bridge path required"));
            assert!(bridge.is_absolute() && bridge.is_file());
            let count = args
                .next()
                .map(|arg| arg.into_string().unwrap().parse().unwrap())
                .unwrap_or(198);
            assert!([6, 132, 166, 198].contains(&count));
            if arg == "early-dom-refund" {
                Mode::EarlyDomRefund { bridge, count }
            } else {
                Mode::XmrRecovery {
                    bridge,
                    count,
                    bad_first: arg == "xmr-recovery-bad-first",
                }
            }
        }
        Some(_) => panic!("unknown regtest experiment mode"),
    };
    assert!(args.next().is_none(), "unexpected argument");
    assert!(
        binary.is_absolute() && binary.is_file(),
        "specify a local daemon binary"
    );
    tokio::time::timeout(Duration::from_secs(240), exercise(binary, mode))
        .await
        .expect("regtest exceeded 240 seconds");
}
