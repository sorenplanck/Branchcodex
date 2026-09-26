//! Owns a fresh in-process DOM node with no network listeners or peer tasks.
//! Coins are mined and spent through the node's normal admission/miner paths.
//! Key preparation here is centralized and disposable, not secure swap setup.
// Shared by cooperative and abandonment examples, which use different methods.
#![allow(dead_code)]

use dom_consensus::{
    Block, Transaction, TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN,
};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    PublicKey, SecretKey,
};
use dom_node::{node::DomNode, node_handle::NodeHandleImpl};
use dom_rpc::{NodeHandle, SpendRequest};
use dom_scriptless_primitives::scriptless_add_public_points;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet::{Bip39Seed, Network, WalletDir};
use dxp1_clsag_lab::{
    dom_joint::{DomSigner, DomSigningIntent},
    dom_reserve::{ReserveIntent, ReserveShare, VerifiedReserve},
    native_dom::{DomClaimOffer, PreparedDomClaim},
    time_bounds::{
        AssumedClaimDelays, AssumedDomAnchor, AssumedXmrRecoveryWindow, DomClockNetwork,
    },
};
use rand_core::{OsRng, RngCore};
use std::{
    fs,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const RESERVE_VALUE: u64 = 100_000_000;
pub const CLAIM_FEE: u64 = 1_000_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// This helper owns only a regtest node. Pace every block near the future
// boundary, including the refund and its onward spend after reaching height.
async fn mine_with_native_clock(node: &Arc<DomNode>) -> u64 {
    loop {
        let parent_timestamp = {
            let chain = node.chain.lock().await;
            let bytes = chain
                .store
                .get_block_header(chain.tip_hash.as_bytes())
                .unwrap()
                .unwrap();
            dom_consensus::BlockHeader::from_bytes(&bytes)
                .unwrap()
                .timestamp
                .0
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if parent_timestamp < now + DomClockNetwork::Regtest.future_tolerance() {
            return dom_node::miner::mine_one_block(node.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn assert_native_refund_locked(
    node: &Arc<DomNode>,
    transaction: &Transaction,
    chain_id: [u8; 32],
    not_before: u64,
) {
    let context = ValidationContext {
        chain_id,
        current_height: node.chain.lock().await.tip_height,
        now: Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
    };
    assert!(context.current_height.0 < not_before);
    dom_consensus::validate_kernel_signatures(transaction, &context.chain_id).unwrap();
    assert!(matches!(
        dom_consensus::validate_transaction(transaction, &context),
        Err(DomError::TemporarilyInvalid(_))
    ));
    let rejected = NodeHandleImpl(node.clone())
        .submit_tx(transaction.to_bytes().unwrap())
        .expect_err("node must reject premature refund");
    assert!(
        rejected.to_string().contains("kernel locked until height"),
        "{rejected}"
    );
}

async fn mine_until_refund_height(
    node: &Arc<DomNode>,
    transaction: &Transaction,
    chain_id: [u8; 32],
    height: u64,
) {
    let started = Instant::now();
    while node.chain.lock().await.tip_height.0 < height {
        assert_native_refund_locked(node, transaction, chain_id, height).await;
        let mined = mine_with_native_clock(node).await;
        if mined % 16 == 0 || mined == height {
            println!(
                "DOM refund-height progress: {mined}/{height}, {:.3}s",
                started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(node.chain.lock().await.tip_height.0, height);
}

/// Owns the only background miner for this fixture. It submits no refund;
/// the caller must await completion before mining another DOM transaction.
pub struct RefundHeightMiner(tokio::task::JoinHandle<()>);
impl RefundHeightMiner {
    pub async fn wait(mut self) {
        (&mut self.0).await.expect("owned DOM height miner failed");
    }
}
impl Drop for RefundHeightMiner {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn prepare(
    input_blind: &BlindingFactor,
    value: u64,
    output_blind: &BlindingFactor,
    chain: [u8; 32],
) -> (PreparedDomClaim, [SecretKey; 2]) {
    // Each contribution can be calculated locally. Only their public points
    // are added; no complete kernel signing scalar is constructed here.
    // The disposable funding fixture still knows the input/output openings.
    let offsets = [BlindingFactor::random(), BlindingFactor::random()];
    let offset = offsets[1].sub_nonzero(&offsets[0]).unwrap();
    let shares = [
        offsets[0].sub_nonzero(input_blind).unwrap(),
        output_blind.sub_nonzero(&offsets[1]).unwrap(),
    ];
    let keys = shares
        .each_ref()
        .map(|s| SecretKey::from_bytes(s.as_bytes()).unwrap());
    let (proof, commitment) =
        dom_crypto::range_proof_prove_bytes(value - CLAIM_FEE, output_blind).unwrap();
    let claim = assemble(
        Commitment::commit(value, input_blind),
        TransactionOutput {
            commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
            proof,
        },
        offset,
        &keys,
        chain,
    );
    (claim, keys)
}

fn assemble(
    input: Commitment,
    output: TransactionOutput,
    offset: BlindingFactor,
    keys: &[SecretKey; 2],
    chain: [u8; 32],
) -> PreparedDomClaim {
    let excess = scriptless_add_public_points(&keys.each_ref().map(|k| k.public_key())).unwrap();
    let tx = Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![output],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(CLAIM_FEE).unwrap(),
            lock_height: 0,
            excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes()).unwrap(),
            excess_signature: [0; 65],
        }],
        offset: *offset.as_bytes(),
    };
    PreparedDomClaim::new(tx, chain).unwrap()
}

fn prepare_shared_claim(
    shares: &[ReserveShare; 2],
    reserve: &Commitment,
    recipient: &BlindingFactor,
    chain: [u8; 32],
) -> (PreparedDomClaim, [SecretKey; 2]) {
    let masks = [BlindingFactor::random(), BlindingFactor::random()];
    let offset = masks[1].sub_nonzero(&masks[0]).unwrap();
    let recipient_mask = recipient.sub_nonzero(&masks[1]).unwrap();
    let keys = [
        shares[0].debit_key(&masks[0]).unwrap(),
        shares[1].debit_key(&recipient_mask).unwrap(),
    ];
    let (proof, point) =
        dom_crypto::range_proof_prove_bytes(RESERVE_VALUE - CLAIM_FEE, recipient).unwrap();
    let output = TransactionOutput {
        commitment: Commitment::from_compressed_bytes(&point).unwrap(),
        proof,
    };
    (
        assemble(reserve.clone(), output, offset, &keys, chain),
        keys,
    )
}

fn joint_offer(
    claim: PreparedDomClaim,
    keys: [SecretKey; 2],
    adaptor: PublicKey,
    route: [u8; 32],
) -> DomClaimOffer {
    let mut session = [0; 32];
    OsRng.fill_bytes(&mut session);
    let intent = DomSigningIntent::new(
        claim,
        adaptor,
        keys.each_ref().map(|k| k.public_key()),
        session,
        route,
    )
    .unwrap();
    let proofs = [
        intent.prove_share(0, &keys[0]).unwrap(),
        intent.prove_share(1, &keys[1]).unwrap(),
    ];
    let plan = intent.authorize(proofs).unwrap();
    let [(a, ma), (b, mb)]: [_; 2] = keys
        .into_iter()
        .enumerate()
        .map(|(i, key)| {
            DomSigner::new(plan.clone(), i as u8, key)
                .unwrap()
                .preprocess(&mut OsRng)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let (a, sa) = a.sign(&mb).unwrap();
    let (b, sb) = b.sign(&ma).unwrap();
    let offer = a.complete(&sb).unwrap();
    b.complete(&sa).unwrap();
    offer
}

// Local single-owner controls only: no untrusted peer or exposed nonce round.
fn sign_control(claim: &PreparedDomClaim, keys: [SecretKey; 2]) -> Transaction {
    let nonces = [BlindingFactor::random(), BlindingFactor::random()]
        .map(|n| SecretKey::from_bytes(n.as_bytes()).unwrap());
    let aggregate =
        scriptless_add_public_points(&nonces.each_ref().map(|n| n.public_key())).unwrap();
    let partials = keys
        .iter()
        .zip(&nonces)
        .map(|(key, nonce)| {
            dom_crypto::schnorr_partial_sign(
                key,
                nonce,
                &aggregate,
                claim.key(),
                claim.chain(),
                claim.message(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut tx = claim.unsigned_transaction().clone();
    tx.kernels[0].excess_signature = dom_crypto::schnorr_aggregate_sigs(&partials, &aggregate)
        .unwrap()
        .to_bytes();
    tx
}

pub struct FundedDom {
    node: Arc<DomNode>,
    pub claim: PreparedDomClaim,
    keys: Option<[SecretKey; 2]>,
    reserve_shares: Option<[ReserveShare; 2]>,
    recovery_local: Option<ReserveShare>,
    reserve_plan: VerifiedReserve,
    reserve: Commitment,
    recipient_blinding: BlindingFactor,
    pub funding_height: u64,
    height_refund: Option<HeightRefund>,
}

struct HeightRefund {
    transaction: Transaction,
    recipient: BlindingFactor,
    not_before: u64,
    timing: Option<serde_json::Value>,
}

enum RefundSchedule<'a> {
    Height(u64),
    Conditional {
        window: &'a AssumedXmrRecoveryWindow,
        ready_by: Timestamp,
        dom_first: bool,
    },
}

/// Ordinary staging funds and unsigned shared funding. No final funding
/// signature or shared reserve output has been released by this preparation.
pub struct UnfundedDom {
    node: Arc<DomNode>,
    plan: VerifiedReserve,
    reserve_shares: [ReserveShare; 2],
    shared_funding: PreparedDomClaim,
    funding_keys: [SecretKey; 2],
}

impl FundedDom {
    pub async fn new(root: &Path) -> Self {
        Self::create(root, None, None).await
    }
    pub async fn new_with_height_refund(root: &Path, not_before: u64) -> Self {
        Self::create(root, None, Some(RefundSchedule::Height(not_before))).await
    }
    pub async fn fund_with_recovery_window(
        prepared: UnfundedDom,
        window: &AssumedXmrRecoveryWindow,
        ready_by: Timestamp,
        dom_first: bool,
    ) -> Self {
        Self::finish(
            prepared,
            Some(RefundSchedule::Conditional {
                window,
                ready_by,
                dom_first,
            }),
        )
        .await
    }
    pub async fn prepare_unfunded(root: &Path) -> UnfundedDom {
        let mut prepared = Self::prepare(root, None).await;
        // The wallet has already created the ordinary staging coin. All swap
        // outputs below are controlled by the explicit participant material,
        // not this bootstrap wallet. Use the node's native walletless regtest
        // miner for later blocks: their coinbase rewards are intentionally
        // unspendable, while transaction/PoW/timestamp validation is unchanged.
        // Otherwise each irrelevant reward repeats encrypted-wallet KDF and
        // persistence work throughout the conservative refund-height test.
        let node = Arc::get_mut(&mut prepared.node).expect("sole owned regtest node");
        assert_eq!(node.config.network, dom_config::Network::Regtest);
        assert!(node.wallet.take().is_some());
        prepared
    }
    pub async fn new_prepared(
        root: &Path,
        shares: [ReserveShare; 2],
        plan: VerifiedReserve,
    ) -> Self {
        Self::create(root, Some((shares, plan)), None).await
    }
    async fn create(
        root: &Path,
        supplied: Option<([ReserveShare; 2], VerifiedReserve)>,
        refund_height: Option<RefundSchedule<'_>>,
    ) -> Self {
        let prepared = Self::prepare(root, supplied).await;
        Self::finish(prepared, refund_height).await
    }

    async fn prepare(
        root: &Path,
        supplied: Option<([ReserveShare; 2], VerifiedReserve)>,
    ) -> UnfundedDom {
        fs::create_dir(root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        // This switch is honored only on regtest. No production validation is
        // bypassed; PoW and maturity are the node's explicit regtest profile.
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let wallet_path = root.join("wallet");
        let mut password_bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(&mut *password_bytes);
        let password = Zeroizing::new(hex(&*password_bytes));
        let seed = Bip39Seed::generate_new().unwrap();
        drop(
            WalletDir::create_from_seed(
                &wallet_path,
                &password,
                Network::Regtest,
                &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
                &seed,
            )
            .unwrap(),
        );
        let mut config = dom_config::NodeConfig::regtest();
        config.data_dir = root.join("chain").to_string_lossy().into_owned();
        config.wallet_path = Some(wallet_path.to_string_lossy().into_owned());
        config.wallet_password = Some(password.to_string());
        config.mine = false;
        config.miner_threads = 1;
        config.min_outbound = 0;
        config.disable_dns_seeds = true;
        config.p2p_listen_addr = "127.0.0.1:0".into();
        let node = Arc::new(DomNode::init_with_map_size(config, 64 << 20).unwrap());
        // Do not call node.run(): this experiment needs no networking tasks.
        dom_node::miner::create_genesis_block(node.clone())
            .await
            .unwrap();
        for _ in 0..3 {
            dom_node::miner::mine_one_block(node.clone()).await.unwrap();
        }
        let chain_id = *node
            .wallet
            .as_ref()
            .unwrap()
            .lock()
            .await
            .wallet()
            .chain_id();
        // First create an ordinary owned staging coin through the wallet API.
        // Its opening is not an opening of the later two-party reserve.
        let reserve_blinding = BlindingFactor::random();
        let reserve = Commitment::commit(RESERVE_VALUE + CLAIM_FEE, &reserve_blinding);
        let handle = NodeHandleImpl(node.clone());
        assert_eq!(handle.network(), "regtest");
        let funding_id = handle
            .wallet_spend(SpendRequest {
                recipient_commitment: hex(reserve.as_bytes()),
                recipient_blinding: hex(reserve_blinding.as_bytes()),
                amount_noms: RESERVE_VALUE + CLAIM_FEE,
                fee_noms: CLAIM_FEE,
            })
            .unwrap();
        assert!(handle.get_mempool_tx(&funding_id).is_some());
        let funding = node
            .mempool
            .lock()
            .await
            .get_tx(&funding_id)
            .unwrap()
            .tx
            .clone();
        let funding_height = dom_node::miner::mine_one_block(node.clone()).await.unwrap();
        let utxo = handle
            .get_utxo(reserve.as_bytes())
            .expect("mined reserve UTXO");
        assert_eq!(utxo.block_height, funding_height);
        assert!(utxo.is_mature && !utxo.is_coinbase);
        // wallet_spend does not populate submit_tx's admission identity map.
        // Verify its exact body in the canonical block and its kernel index.
        let funding_hash = handle.get_block_hash_at_height(funding_height).unwrap();
        let funding_block = Block::from_bytes(
            &node
                .chain
                .lock()
                .await
                .store
                .get_block_body(&funding_hash)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(funding_block.transactions.contains(&funding));
        assert_eq!(
            handle.get_kernel_block(funding.kernels[0].excess.as_bytes()),
            Some(funding_hash)
        );
        let (reserve_shares, plan) = if let Some((shares, plan)) = supplied {
            assert_eq!(plan.chain(), chain_id);
            assert_eq!(plan.value(), RESERVE_VALUE);
            for (i, share) in shares.iter().enumerate() {
                assert_eq!(
                    share.public_key().to_compressed_bytes(),
                    plan.share_key(i as u8).unwrap().to_compressed_bytes()
                );
            }
            (shares, plan)
        } else {
            let reserve_shares = [
                ReserveShare::generate(&mut OsRng).unwrap(),
                ReserveShare::generate(&mut OsRng).unwrap(),
            ];
            let mut session = [0; 32];
            OsRng.fill_bytes(&mut session);
            let intent = ReserveIntent::new(
                RESERVE_VALUE,
                chain_id,
                session,
                [47; 32],
                reserve_shares.each_ref().map(|s| s.public_key()),
            )
            .unwrap();
            let proofs = [
                reserve_shares[0].prove(&intent, 0).unwrap(),
                reserve_shares[1].prove(&intent, 1).unwrap(),
            ];
            let plan = intent.authorize(proofs).unwrap();
            (reserve_shares, plan)
        };
        let mut seed = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(&mut *seed);
        let (a, ma) = reserve_shares[0]
            .begin_proof(plan.clone(), 0, &seed, &mut OsRng)
            .unwrap();
        let (b, mb) = reserve_shares[1]
            .begin_proof(plan.clone(), 1, &seed, &mut OsRng)
            .unwrap();
        drop(seed);
        let (a, sa) = a.respond(&mb).unwrap();
        let (b, sb) = b.respond(&ma).unwrap();
        let proof = a.complete(sb).unwrap();
        assert_eq!(proof, b.complete(sa).unwrap());
        let offset = BlindingFactor::random();
        let keys = [
            reserve_shares[0]
                .funding_key(Some(&reserve_blinding), Some(&offset))
                .unwrap(),
            reserve_shares[1].funding_key(None, None).unwrap(),
        ];
        let shared_funding = assemble(
            reserve,
            TransactionOutput {
                commitment: plan.commitment().clone(),
                proof,
            },
            offset,
            &keys,
            chain_id,
        );
        drop(reserve_blinding);
        assert!(handle.get_utxo(plan.commitment().as_bytes()).is_none());
        UnfundedDom {
            node,
            plan,
            reserve_shares,
            shared_funding,
            funding_keys: keys,
        }
    }

    async fn finish(prepared: UnfundedDom, refund_height: Option<RefundSchedule<'_>>) -> Self {
        let UnfundedDom {
            node,
            plan,
            reserve_shares,
            shared_funding,
            funding_keys: keys,
        } = prepared;
        let chain_id = plan.chain();
        let handle = NodeHandleImpl(node.clone());
        assert!(handle.get_utxo(plan.commitment().as_bytes()).is_none());
        // Refresh an ordinary chain anchor after potentially long capsule
        // preparation; no shared funds or refund are published by this block.
        // Otherwise an old timestamp yields an unnecessarily distant height.
        if matches!(&refund_height, Some(RefundSchedule::Conditional { .. })) {
            dom_node::miner::mine_one_block(node.clone()).await.unwrap();
        }
        let (funding_height, funding_hash, anchor_timestamp) = {
            let chain = node.chain.lock().await;
            let bytes = chain
                .store
                .get_block_header(chain.tip_hash.as_bytes())
                .unwrap()
                .unwrap();
            let header = dom_consensus::BlockHeader::from_bytes(&bytes).unwrap();
            (
                chain.tip_height.0,
                *chain.tip_hash.as_bytes(),
                header.timestamp,
            )
        };
        let public_witness =
            dom_scriptless_primitives::SecretScalar::from_be_bytes([1; 32]).unwrap();
        let offer = joint_offer(
            shared_funding,
            keys,
            public_witness.public_key().unwrap(),
            plan.binding(),
        );
        let context = ValidationContext {
            chain_id,
            current_height: node.chain.lock().await.tip_height,
            now: Timestamp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        };
        let funding_tx = offer.complete(&public_witness, &context).unwrap();
        // Prepare the exact refund BEFORE the shared reserve is funded. DOM
        // commitments are known now; no global XMR ring index is needed here.
        // This variant never releases or capsules a DOM reserve key share.
        let height_refund = refund_height.map(|schedule| {
            let (not_before, timing) = match schedule {
                RefundSchedule::Height(height) => (height, None),
                RefundSchedule::Conditional { window, ready_by, dom_first } => {
                    // The exact canonical tip anchors the native inequality
                    // before publishing the shared funding transaction.
                    let anchor = AssumedDomAnchor::new(BlockHeight(funding_height), anchor_timestamp);
                    let calculate = if dom_first {
                        AssumedXmrRecoveryWindow::required_dom_refund_height_for_dom_first
                    } else { AssumedXmrRecoveryWindow::required_dom_refund_height };
                    let height = calculate(window,
                        &anchor, DomClockNetwork::Regtest, 0, ready_by,
                        AssumedClaimDelays { xmr_resolution_secs:1, observation_secs:1, dom_resolution_secs:1 },
                    ).unwrap();
                    let earliest = anchor.earliest_refund_time(height, DomClockNetwork::Regtest, 0).unwrap();
                    assert!(earliest.0 > window.latest_honest().0 + 3);
                    (height.0, Some(serde_json::json!({
                        "dom_timing_anchor_height":funding_height,
                        "dom_timing_anchor_timestamp":anchor_timestamp.0,
                        "dom_timing_anchor_hash":hex(&funding_hash),
                        "dom_refund_conditional_earliest_unix":earliest.0,
                        "xmr_conditional_latest_recovery_unix":window.latest_honest().0,
                        "xmr_conditional_earliest_adversarial_unix":window.earliest_adversarial().0,
                        "conditional_offers_ready_by_unix":ready_by.0,
                        "conditional_first_claim_order":if dom_first { "DOM-first" } else { "XMR-first" },
                        "conditional_validator_clock_ahead_seconds":0,
                        "conditional_resolution_seconds_each":1,
                        "conditional_observation_seconds":1,
                        "timing_capsule_link_binding":hex(&window.capsule_binding()),
                        "timing_bounds_proven":false,
                    })))
                }
            };
            assert!(not_before > context.current_height.0 + 1);
            let recipient = BlindingFactor::random();
            let (plain, refund_keys) =
                prepare_shared_claim(&reserve_shares, plan.commitment(), &recipient, chain_id);
            let mut unsigned = plain.unsigned_transaction().clone();
            unsigned.kernels[0].features = KERNEL_FEAT_HEIGHT_LOCKED;
            unsigned.kernels[0].lock_height = not_before;
            let refund =
                PreparedDomClaim::new_height_locked_refund(unsigned, chain_id, not_before).unwrap();
            let refund_offer = joint_offer(
                refund,
                refund_keys,
                public_witness.public_key().unwrap(),
                plan.binding(),
            );
            // Future context is for OFF-CHAIN signature verification only.
            // The node always validates against its own current height.
            let future = ValidationContext {
                chain_id,
                current_height: BlockHeight(not_before),
                now: context.now,
            };
            let transaction = refund_offer.complete(&public_witness, &future).unwrap();
            assert!(matches!(
                dom_consensus::validate_transaction(&transaction, &context),
                Err(DomError::TemporarilyInvalid(_))
            ));
            HeightRefund {
                transaction,
                recipient,
                not_before,
                timing,
            }
        });
        let (_, funding_height) = Self::include_on_node(&node, &funding_tx).await;
        let reserve = plan.commitment().clone();
        let recipient_blinding = BlindingFactor::random();
        let (claim, keys) =
            prepare_shared_claim(&reserve_shares, &reserve, &recipient_blinding, chain_id);
        // A native claim signed with either one contribution alone is invalid.
        for key in &keys {
            let mut unilateral = claim.unsigned_transaction().clone();
            unilateral.kernels[0].excess_signature =
                dom_crypto::schnorr_sign(key, claim.message(), &chain_id)
                    .unwrap()
                    .to_bytes();
            assert!(dom_consensus::validate_transaction(&unilateral, &context).is_err());
            assert!(handle.submit_tx(unilateral.to_bytes().unwrap()).is_err());
        }
        assert!(handle.get_utxo(reserve.as_bytes()).is_some());
        Self {
            node,
            claim,
            keys: Some(keys),
            reserve_shares: Some(reserve_shares),
            recovery_local: None,
            reserve_plan: plan,
            reserve,
            recipient_blinding,
            funding_height,
            height_refund,
        }
    }

    pub async fn context(&self) -> ValidationContext {
        ValidationContext {
            chain_id: *self.claim.chain(),
            current_height: self.node.chain.lock().await.tip_height,
            now: Timestamp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        }
    }

    pub fn discard_reserve_signing_material(&mut self) {
        self.keys.take();
        self.reserve_shares.take();
        self.recovery_local.take();
    }

    pub fn height_refund_transaction(&self) -> Transaction {
        self.height_refund
            .as_ref()
            .expect("height refund prepared")
            .transaction
            .clone()
    }

    pub fn height_refund_height(&self) -> u64 {
        self.height_refund
            .as_ref()
            .expect("height refund prepared")
            .not_before
    }

    pub fn height_refund_timing(&self) -> Option<serde_json::Value> {
        self.height_refund
            .as_ref()
            .and_then(|refund| refund.timing.clone())
    }

    pub async fn assert_height_refund_locked(&self) {
        let refund = self.height_refund.as_ref().expect("height refund prepared");
        assert_native_refund_locked(
            &self.node,
            &refund.transaction,
            *self.claim.chain(),
            refund.not_before,
        )
        .await;
    }

    pub async fn mine_to_refund_height(&self) {
        let refund = self.height_refund.as_ref().expect("height refund prepared");
        mine_until_refund_height(
            &self.node,
            &refund.transaction,
            *self.claim.chain(),
            refund.not_before,
        )
        .await;
    }

    pub fn start_refund_height_mining(&self) -> RefundHeightMiner {
        let node = self.node.clone();
        let transaction = self.height_refund_transaction();
        let height = self.height_refund_height();
        let chain_id = *self.claim.chain();
        RefundHeightMiner(tokio::spawn(async move {
            mine_until_refund_height(&node, &transaction, chain_id, height).await;
        }))
    }

    pub async fn include_height_refund_and_spend(&self) -> (u64, u64) {
        let refund = self.height_refund.as_ref().expect("height refund prepared");
        assert!(self.context().await.current_height.0 >= refund.not_before);
        let (_, height) = self.include(&refund.transaction).await;
        let (onward, keys) = prepare(
            &refund.recipient,
            RESERVE_VALUE - CLAIM_FEE,
            &BlindingFactor::random(),
            *self.claim.chain(),
        );
        let (_, next) = self.include(&sign_control(&onward, keys)).await;
        (height, next)
    }

    /// Drop the simulated peer's original share AND both prepared claim keys.
    /// A subsequent refund must use a share obtained from the public capsule.
    pub fn abandon_peer(&mut self) {
        let [local, remote] = self.reserve_shares.take().expect("live reserve shares");
        drop(remote);
        self.keys.take();
        self.recovery_local = Some(local);
    }

    pub async fn refund_after_recovery(&mut self, recovered: ReserveShare) -> (u64, u64) {
        assert_eq!(
            recovered.public_key().to_compressed_bytes(),
            self.reserve_plan
                .share_key(1)
                .unwrap()
                .to_compressed_bytes()
        );
        let local = self
            .recovery_local
            .take()
            .expect("peer must be abandoned first");
        let destination = BlindingFactor::random();
        let (refund, keys) = prepare_shared_claim(
            &[local, recovered],
            &self.reserve,
            &destination,
            *self.claim.chain(),
        );
        let refund = sign_control(&refund, keys);
        let (_, height) = self.include(&refund).await;
        let (onward, keys) = prepare(
            &destination,
            RESERVE_VALUE - CLAIM_FEE,
            &BlindingFactor::random(),
            *self.claim.chain(),
        );
        let (_, next) = self.include(&sign_control(&onward, keys)).await;
        (height, next)
    }

    pub fn offer(&mut self, adaptor: &[u8; 33], route: [u8; 32]) -> DomClaimOffer {
        let adaptor = PublicKey::from_compressed_bytes(adaptor).unwrap();
        let keys = self.keys.take().expect("one-use DOM claim shares");
        joint_offer(self.claim.clone(), keys, adaptor, route)
    }

    pub async fn include(&self, tx: &Transaction) -> (Transaction, u64) {
        Self::include_on_node(&self.node, tx).await
    }

    /// A cryptographically valid claim must still lose to a confirmed refund.
    pub async fn assert_spent_rejection(&self, tx: &Transaction) {
        dom_consensus::validate_transaction(tx, &self.context().await).unwrap();
        let rejection = NodeHandleImpl(self.node.clone())
            .submit_tx(tx.to_bytes().unwrap())
            .expect_err("spent reserve must be rejected");
        assert!(
            rejection
                .to_string()
                .contains("input commitment not found in canonical UTXO set"),
            "unexpected rejection: {rejection}"
        );
    }

    async fn include_on_node(node: &Arc<DomNode>, tx: &Transaction) -> (Transaction, u64) {
        let handle = NodeHandleImpl(node.clone());
        let admission = handle.submit_tx(tx.to_bytes().unwrap()).unwrap();
        assert_eq!(admission.state, dom_rpc::TxAdmissionState::New);
        assert!(handle.get_mempool_tx(&admission.tx_hash).is_some());
        let height = mine_with_native_clock(node).await;
        let chain = node.chain.lock().await;
        let tip = *chain.tip_hash.as_bytes();
        let bytes = chain
            .store
            .get_block_body(&tip)
            .unwrap()
            .expect("canonical DOM block");
        let block = Block::from_bytes(&bytes).unwrap();
        let observed = block
            .transactions
            .iter()
            .find(|candidate| *candidate == tx)
            .expect("exact included DOM transaction")
            .clone();
        assert_eq!(chain.store.get_hash_at_height(height).unwrap(), Some(tip));
        drop(chain);
        assert_eq!(
            handle.get_kernel_block(tx.kernels[0].excess.as_bytes()),
            Some(tip)
        );
        assert!(handle
            .get_utxo(tx.inputs[0].commitment.as_bytes())
            .is_none());
        let output = handle
            .get_utxo(tx.outputs[0].commitment.as_bytes())
            .expect("claim output UTXO");
        assert_eq!(output.block_height, height);
        assert!(output.is_mature && !output.is_coinbase);
        assert_eq!(
            handle.submit_tx(tx.to_bytes().unwrap()).unwrap().state,
            dom_rpc::TxAdmissionState::Confirmed
        );
        (observed, height)
    }

    pub async fn prove_onward_spend_and_reject_double_spend(&self) -> u64 {
        let chain = *self.claim.chain();
        // A different, correctly signed transaction cannot spend the now-used
        // reserve. Exact already-confirmed replay is separately idempotent.
        let (conflict, keys) = prepare_shared_claim(
            self.reserve_shares
                .as_ref()
                .expect("cooperative shares present"),
            &self.reserve,
            &BlindingFactor::random(),
            chain,
        );
        let conflict_tx = sign_control(&conflict, keys);
        dom_consensus::validate_transaction(&conflict_tx, &self.context().await).unwrap();
        let rejection = NodeHandleImpl(self.node.clone())
            .submit_tx(conflict_tx.to_bytes().unwrap())
            .expect_err("spent reserve must be rejected");
        assert!(
            rejection
                .to_string()
                .contains("input commitment not found in canonical UTXO set"),
            "unexpected rejection: {rejection}"
        );
        self.spend_claim_output().await
    }

    pub async fn spend_claim_output(&self) -> u64 {
        let (onward, keys) = prepare(
            &self.recipient_blinding,
            RESERVE_VALUE - CLAIM_FEE,
            &BlindingFactor::random(),
            *self.claim.chain(),
        );
        let onward_tx = sign_control(&onward, keys);
        self.include(&onward_tx).await.1
    }
}
