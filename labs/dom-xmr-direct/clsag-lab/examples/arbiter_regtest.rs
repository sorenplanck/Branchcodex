//! Funded DXA1 DOM↔XMR experiment using one isolated DOM Regtest node and one
//! isolated `monerod --regtest`. Bitcoin is not part of this flow. Mining is
//! requested on demand, so elapsed time is evidence for this test fixture and
//! is not a production-network latency guarantee.

use std::{
    env, fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use dom_consensus::{
    swap_arbiter_intent, Block, SwapArbiterContract, SwapArbiterPath, Transaction,
    TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_PLAIN, KERNEL_FEAT_SWAP_CLAIM,
    KERNEL_FEAT_SWAP_PUNISH, KERNEL_FEAT_SWAP_REFUND, TAG_KERNEL_MSG,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign, SecretKey,
};
use dom_node::{node::DomNode, node_handle::NodeHandleImpl};
use dom_rpc::{NodeHandle, SpendRequest, TxAdmissionState};
use dom_scriptless_primitives::{scriptless_add_public_points, SecretScalar};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet::{Bip39Seed, Network, WalletDir};
use dxp1_clsag_lab::{
    arbiter_pair::VerifiedArbiterSharesV1,
    arbiter_session::{ArbiterSessionBinding, ArbiterSessionJournal},
    claim_resume::digest,
    dom_joint::{DomCommitment, DomSigner, DomSigningIntent},
    native_dom::{DomClaimOffer, PreparedDomClaim},
};
use monero_simple_request_rpc::{prelude::*, SimpleRequestTransport};
use monero_wallet::{
    address::Network as XmrNetwork,
    ed25519::{Point, Scalar as MoneroScalar},
    interface::FeePriority,
    ringct::RctType,
    send::{Change, SignableTransaction},
    OutputWithDecoys, Scanner, ViewPair,
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use xmr_dleq_sigma::{
    prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use zeroize::Zeroizing;

const SETTLEMENT_ID: [u8; 32] = [0x72; 32];
const CONTEXT_HASH: [u8; 32] = [0x73; 32];
const ARBITER_VALUE: u64 = 100_000_000;
const FEE: u64 = 1_000_000;

struct ManagedDaemon(Child);

impl Drop for ManagedDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Claim,
    Refund,
    Punish,
}

impl Outcome {
    fn parse(value: &str) -> Self {
        match value {
            "claim" => Self::Claim,
            "refund" => Self::Refund,
            "punish" => Self::Punish,
            _ => panic!("outcome must be claim, refund, or punish"),
        }
    }

    fn path(self) -> SwapArbiterPath {
        match self {
            Self::Claim => SwapArbiterPath::Claim,
            Self::Refund => SwapArbiterPath::Refund,
            Self::Punish => SwapArbiterPath::Punish,
        }
    }
}

fn fresh_secret() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn kernel_message(feature: u8, fee: u64, lock_height: u64) -> [u8; 32] {
    let mut bytes = vec![feature];
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &bytes).as_bytes()
}

async fn mine(node: &Arc<DomNode>) -> u64 {
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
        if parent_timestamp < now + 7200 {
            return dom_node::miner::mine_one_block(node.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dom-xmr-arbiter-node-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn node() -> (TestDir, Arc<DomNode>, [u8; 32]) {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let root = TestDir::new();
    let wallet_path = root.0.join("wallet");
    WalletDir::create_from_seed(
        &wallet_path,
        "arbiter-node-test",
        Network::Regtest,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        &Bip39Seed::generate_new().unwrap(),
    )
    .unwrap();
    let mut config = dom_config::NodeConfig::regtest();
    config.data_dir = root.0.join("chain").to_string_lossy().into_owned();
    config.wallet_path = Some(wallet_path.to_string_lossy().into_owned());
    config.wallet_password = Some("arbiter-node-test".into());
    config.mine = false;
    config.miner_threads = 1;
    config.min_outbound = 0;
    config.disable_dns_seeds = true;
    config.p2p_listen_addr = "127.0.0.1:0".into();
    let node = Arc::new(DomNode::init_with_map_size(config, 64 << 20).unwrap());
    dom_node::miner::create_genesis_block(node.clone())
        .await
        .unwrap();
    for _ in 0..3 {
        mine(&node).await;
    }
    let chain_id = *node
        .wallet
        .as_ref()
        .unwrap()
        .lock()
        .await
        .wallet()
        .chain_id();
    (root, node, chain_id)
}

struct Branch {
    unsigned: Transaction,
    prepared: PreparedDomClaim,
    keys: [SecretKey; 2],
}

fn branch(
    input: Commitment,
    input_blinding: &BlindingFactor,
    chain_id: [u8; 32],
    feature: u8,
    boundary: u64,
    scalars: [u8; 2],
) -> Branch {
    let scalar = |last| {
        let mut bytes = [0u8; 32];
        bytes[31] = last;
        BlindingFactor::from_bytes(bytes).unwrap()
    };
    let blindings = scalars.map(scalar);
    let output_blinding = input_blinding
        .add(&blindings[0])
        .unwrap()
        .add(&blindings[1])
        .unwrap();
    let (proof, commitment) =
        dom_crypto::range_proof_prove_bytes(ARBITER_VALUE - FEE, &output_blinding).unwrap();
    let keys = blindings
        .each_ref()
        .map(|blinding| SecretKey::from_bytes(blinding.as_bytes()).unwrap());
    let excess = scriptless_add_public_points(&keys.each_ref().map(SecretKey::public_key)).unwrap();
    let unsigned = Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![TransactionOutput {
            commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: feature,
            fee: Amount::from_noms(FEE).unwrap(),
            lock_height: boundary,
            excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes()).unwrap(),
            excess_signature: [0; 65],
        }],
        offset: [0; 32],
    };
    let prepared = PreparedDomClaim::new_swap_arbiter_path(unsigned.clone(), chain_id).unwrap();
    Branch {
        unsigned,
        prepared,
        keys,
    }
}

fn offer(branch: &Branch, adaptor: dom_crypto::PublicKey, session: u8) -> DomClaimOffer {
    let intent = DomSigningIntent::new(
        branch.prepared.clone(),
        adaptor,
        branch.keys.each_ref().map(SecretKey::public_key),
        [session; 32],
        CONTEXT_HASH,
    )
    .unwrap();
    let proofs = [
        intent.prove_share(0, &branch.keys[0]).unwrap(),
        intent.prove_share(1, &branch.keys[1]).unwrap(),
    ];
    let plan = intent.authorize(proofs).unwrap();
    let rounds: Vec<_> = branch
        .keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            DomSigner::new(plan.clone(), index as u8, key.clone())
                .unwrap()
                .preprocess(&mut OsRng)
                .unwrap()
        })
        .collect();
    let commitments: [DomCommitment; 2] = [rounds[0].1.clone(), rounds[1].1.clone()];
    let [first, second]: [_; 2] = rounds.try_into().ok().unwrap();
    let (first, first_response) = first.0.sign(&commitments[1]).unwrap();
    let (second, second_response) = second.0.sign(&commitments[0]).unwrap();
    let result = first.complete(&second_response).unwrap();
    second.complete(&first_response).unwrap();
    result
}

fn signed_funding(
    staging: Commitment,
    staging_blinding: &BlindingFactor,
    arbiter_blinding: &BlindingFactor,
    arbiter_output: TransactionOutput,
    chain_id: &[u8; 32],
) -> Transaction {
    let kernel_blinding = arbiter_blinding.sub_nonzero(staging_blinding).unwrap();
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let signature = schnorr_sign(
        &secret,
        &kernel_message(KERNEL_FEAT_PLAIN, FEE, 0),
        chain_id,
    )
    .unwrap();
    Transaction {
        inputs: vec![TransactionInput {
            commitment: staging,
        }],
        outputs: vec![arbiter_output],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(FEE).unwrap(),
            lock_height: 0,
            excess: Commitment::commit(0, &kernel_blinding),
            excess_signature: signature.to_bytes(),
        }],
        offset: [0; 32],
    }
}

struct FundedArbiter {
    _root: TestDir,
    node: Arc<DomNode>,
    chain_id: [u8; 32],
    shares: VerifiedArbiterSharesV1,
    dom_owner: CrossCurveSecret252,
    xmr_owner: CrossCurveSecret252,
    claim: Branch,
    refund: Branch,
    punish: Branch,
    refund_offer: DomClaimOffer,
    punish_offer: DomClaimOffer,
    claim_until: u64,
    refund_until: u64,
    session_binding: ArbiterSessionBinding,
    journal: ArbiterSessionJournal,
}

fn validation_context(chain_id: [u8; 32], height: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id,
        now: Timestamp(u64::MAX),
    }
}

async fn observed_transaction(
    setup: &FundedArbiter,
    height: u64,
    expected: &Transaction,
) -> Transaction {
    let handle = NodeHandleImpl(setup.node.clone());
    let block_hash = handle.get_block_hash_at_height(height).unwrap();
    let block = Block::from_bytes(
        &setup
            .node
            .chain
            .lock()
            .await
            .store
            .get_block_body(&block_hash)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    block
        .transactions
        .into_iter()
        .find(|candidate| candidate == expected)
        .unwrap()
}

async fn funded_arbiter() -> FundedArbiter {
    let (root, node, chain_id) = node().await;
    let handle = NodeHandleImpl(node.clone());

    let staging_blinding = BlindingFactor::random();
    let staging = Commitment::commit(ARBITER_VALUE + FEE, &staging_blinding);
    let staging_id = handle
        .wallet_spend(SpendRequest {
            recipient_commitment: hex(staging.as_bytes()),
            recipient_blinding: hex(staging_blinding.as_bytes()),
            amount_noms: ARBITER_VALUE + FEE,
            fee_noms: FEE,
        })
        .unwrap();
    assert!(handle.get_mempool_tx(&staging_id).is_some());
    let staging_height = mine(&node).await;
    assert!(handle.get_utxo(staging.as_bytes()).is_some());

    let dom_owner = CrossCurveSecret252::generate(&mut OsRng);
    let xmr_owner = CrossCurveSecret252::generate(&mut OsRng);
    let dom_proof = prove_bound(
        &dom_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_REFUND_SHARE,
        &mut OsRng,
    )
    .unwrap();
    let xmr_proof = prove_bound(
        &xmr_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_SHARED_SPEND,
        &mut OsRng,
    )
    .unwrap();
    let shares =
        VerifiedArbiterSharesV1::new(SETTLEMENT_ID, CONTEXT_HASH, &dom_proof, &xmr_proof).unwrap();

    let arbiter_blinding = BlindingFactor::random();
    let arbiter = Commitment::commit(ARBITER_VALUE, &arbiter_blinding);
    let claim_until = staging_height + 2;
    let refund_until = claim_until + 1;
    let claim = branch(
        arbiter.clone(),
        &arbiter_blinding,
        chain_id,
        KERNEL_FEAT_SWAP_CLAIM,
        claim_until,
        [21, 22],
    );
    let refund = branch(
        arbiter.clone(),
        &arbiter_blinding,
        chain_id,
        KERNEL_FEAT_SWAP_REFUND,
        claim_until + 1,
        [23, 24],
    );
    let punish = branch(
        arbiter,
        &arbiter_blinding,
        chain_id,
        KERNEL_FEAT_SWAP_PUNISH,
        refund_until + 1,
        [25, 26],
    );
    let restore = |name: &str, offer: DomClaimOffer| {
        let bytes = offer.to_swap_arbiter_resume_bytes().unwrap();
        let path = root.0.join(name);
        fs::write(&path, &bytes).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
        let restored = fs::read(path).unwrap();
        DomClaimOffer::from_swap_arbiter_resume_bytes(&restored, digest(&bytes)).unwrap()
    };
    let refund_offer = restore(
        "refund.offer",
        offer(
            &refund,
            shares.adaptor_point(SwapArbiterPath::Refund).unwrap(),
            82,
        ),
    );
    let punish_offer = restore(
        "punish.offer",
        offer(
            &punish,
            shares.adaptor_point(SwapArbiterPath::Punish).unwrap(),
            83,
        ),
    );
    fs::File::open(&root.0).unwrap().sync_all().unwrap();
    let contract = SwapArbiterContract::new(
        claim_until,
        refund_until,
        swap_arbiter_intent(&claim.unsigned).unwrap(),
        swap_arbiter_intent(&refund.unsigned).unwrap(),
        swap_arbiter_intent(&punish.unsigned).unwrap(),
    )
    .unwrap();
    let session_binding =
        ArbiterSessionBinding::new(chain_id, &contract, &shares, &refund_offer, &punish_offer)
            .unwrap();
    let mut journal =
        ArbiterSessionJournal::create(&root.0.join("arbiter-session.wal"), session_binding.clone())
            .unwrap();
    let contract_bytes = contract.to_bytes();
    let (proof, commitment) = dom_crypto::range_proof_prove_bytes_with_extra_commit(
        ARBITER_VALUE,
        &arbiter_blinding,
        &contract_bytes,
    )
    .unwrap();
    let arbiter_output = TransactionOutput::with_swap_arbiter(
        Commitment::from_compressed_bytes(&commitment).unwrap(),
        proof,
        &contract,
    )
    .unwrap();
    let funding = signed_funding(
        staging,
        &staging_blinding,
        &arbiter_blinding,
        arbiter_output,
        &chain_id,
    );
    let funding_admission = handle.submit_tx(funding.to_bytes().unwrap()).unwrap();
    assert_eq!(funding_admission.state, TxAdmissionState::New);
    let funding_height = mine(&node).await;
    assert_eq!(funding_height, staging_height + 1);
    assert!(handle
        .get_utxo(claim.unsigned.inputs[0].commitment.as_bytes())
        .is_some());
    journal
        .record_dom_funding(funding_admission.tx_hash, funding_height)
        .unwrap();

    FundedArbiter {
        _root: root,
        node,
        chain_id,
        shares,
        dom_owner,
        xmr_owner,
        claim,
        refund,
        punish,
        refund_offer,
        punish_offer,
        claim_until,
        refund_until,
        session_binding,
        journal,
    }
}

async fn exercise(monerod: PathBuf, outcome: Outcome) {
    let started = Instant::now();
    let mut setup = funded_arbiter().await;
    let handle = NodeHandleImpl(setup.node.clone());

    let dom_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        setup.dom_owner.xmr_share_little_endian(),
    ))
    .unwrap();
    let xmr_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        setup.xmr_owner.xmr_share_little_endian(),
    ))
    .unwrap();
    let joint_spend = dom_share + xmr_share;
    let verified_joint = CompressedEdwardsY(setup.shares.joint_xmr_spend_key().unwrap())
        .decompress()
        .unwrap();
    assert_eq!(verified_joint, joint_spend * ED25519_BASEPOINT_POINT);
    let reserve_view = ViewPair::new(
        Point::from(verified_joint),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    let reserve_address = reserve_view.legacy_address(XmrNetwork::Mainnet);

    let config = setup._root.0.join("monerod-empty.conf");
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
    let log = fs::File::create(setup._root.0.join("monerod.stdout.log")).unwrap();
    let mut daemon = ManagedDaemon(
        Command::new(monerod)
            .arg("--config-file")
            .arg(config)
            .arg("--data-dir")
            .arg(setup._root.0.join("monero-chain"))
            .arg("--log-file")
            .arg(setup._root.0.join("monerod.log"))
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
            .unwrap(),
    );
    let startup = Instant::now();
    let url = format!("http://127.0.0.1:{rpc_port}");
    let rpc = loop {
        assert!(daemon.0.try_wait().unwrap().is_none(), "monerod exited");
        if let Ok(rpc) =
            SimpleRequestTransport::with_custom_timeout(url.clone(), Duration::from_secs(30)).await
        {
            break rpc;
        }
        assert!(startup.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let info: serde_json::Value =
        serde_json::from_str(&rpc.json_rpc_call("get_info", None, 16384).await.unwrap()).unwrap();
    assert_eq!(info["offline"], true);
    assert_eq!(info["nettype"], "fakechain");

    let mining = Instant::now();
    loop {
        let response = rpc
            .rpc_call(
                "json_rpc",
                Some(
                    json!({"jsonrpc":"2.0", "id":0, "method":"generateblocks",
                        "params":{"wallet_address":reserve_address.to_string(), "amount_of_blocks":1}})
                    .to_string(),
                ),
                16384,
            )
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        if response["result"]["status"] == "BUSY" {
            assert!(mining.elapsed() < Duration::from_secs(30));
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["status"], "OK", "{response}");
        break;
    }
    let (_, height) = rpc.generate_blocks(&reserve_address, 139).await.unwrap();
    let first_hash = rpc.block_by_number(1).await.unwrap().hash();
    let funding_block = rpc.scannable_block(first_hash).await.unwrap();
    assert_eq!(funding_block.block.header.hardfork_version, 16);
    let mut outputs = Scanner::new(reserve_view.clone())
        .scan(funding_block)
        .unwrap()
        .additional_timelock_satisfied_by(height, 0);
    assert_eq!(outputs.len(), 1);
    let reserve_output = outputs.remove(0);
    let reserve_amount = reserve_output.commitment().amount;
    let xmr_output_id = reserve_output.key().compress().to_bytes();
    setup
        .journal
        .record_xmr_ready(xmr_output_id, height.try_into().unwrap())
        .unwrap();
    let session_path = setup._root.0.join("arbiter-session.wal");
    drop(setup.journal);
    setup.journal =
        ArbiterSessionJournal::open(&session_path, setup.session_binding.clone()).unwrap();
    let active_settlement = Instant::now();
    let input = OutputWithDecoys::new(&mut OsRng, &rpc, 16, height, reserve_output)
        .await
        .unwrap();
    let fee = rpc
        .fee_rate(FeePriority::Normal, 1_000_000_000)
        .await
        .unwrap();

    // This is the Ready transition. The claim offer does not exist while the
    // XMR reserve is absent or immature. Recovery offers were already durable
    // before DOM funding, so refusal at Ready can still terminate safely.
    let claim_offer = offer(
        &setup.claim,
        setup.shares.adaptor_point(SwapArbiterPath::Claim).unwrap(),
        81,
    );
    let claim_bytes = claim_offer.to_swap_arbiter_resume_bytes().unwrap();
    let claim_path = setup._root.0.join("claim.offer");
    fs::write(&claim_path, &claim_bytes).unwrap();
    fs::File::open(&claim_path).unwrap().sync_all().unwrap();
    fs::File::open(&setup._root.0).unwrap().sync_all().unwrap();
    let claim_offer = DomClaimOffer::from_swap_arbiter_resume_bytes(
        &fs::read(claim_path).unwrap(),
        digest(&claim_bytes),
    )
    .unwrap();
    setup.journal.record_claim_ready(&claim_offer).unwrap();
    drop(setup.journal);
    setup.journal =
        ArbiterSessionJournal::open(&session_path, setup.session_binding.clone()).unwrap();

    let (branch, offer, secret, settlement_height) = match outcome {
        Outcome::Claim => (
            &setup.claim,
            &claim_offer,
            &setup.xmr_owner,
            setup.claim_until,
        ),
        Outcome::Refund => {
            assert_eq!(mine(&setup.node).await, setup.claim_until);
            (
                &setup.refund,
                &setup.refund_offer,
                &setup.dom_owner,
                setup.claim_until + 1,
            )
        }
        Outcome::Punish => {
            assert_eq!(mine(&setup.node).await, setup.claim_until);
            assert_eq!(mine(&setup.node).await, setup.refund_until);
            (
                &setup.punish,
                &setup.punish_offer,
                &setup.xmr_owner,
                setup.refund_until + 1,
            )
        }
    };
    let settlement = offer
        .complete(
            &SecretScalar::from_be_bytes(secret.dom_secret_big_endian()).unwrap(),
            &validation_context(setup.chain_id, settlement_height),
        )
        .unwrap();
    let settlement_admission = handle.submit_tx(settlement.to_bytes().unwrap()).unwrap();
    assert_eq!(settlement_admission.state, TxAdmissionState::New);
    assert_eq!(mine(&setup.node).await, settlement_height);
    let observed = observed_transaction(&setup, settlement_height, &settlement).await;
    let durable_dom_id = setup
        .journal
        .record_dom_settlement(&observed, settlement_height)
        .unwrap();
    assert_eq!(durable_dom_id, settlement_admission.tx_hash);
    let opening = offer
        .extract(
            &observed,
            &validation_context(setup.chain_id, settlement_height),
        )
        .unwrap();
    let recovered = setup
        .shares
        .xmr_share_from_dom_opening(outcome.path(), *opening)
        .unwrap();
    let recovered = Option::<Scalar>::from(Scalar::from_canonical_bytes(*recovered)).unwrap();
    let local = match outcome {
        Outcome::Refund => xmr_share,
        Outcome::Claim | Outcome::Punish => dom_share,
    };
    let reconstructed = local + recovered;
    assert_eq!(
        reconstructed * ED25519_BASEPOINT_POINT,
        joint_spend * ED25519_BASEPOINT_POINT
    );

    let recipient_spend = Zeroizing::new(MoneroScalar::random(&mut OsRng));
    let recipient_view = ViewPair::new(
        Point::from((*recipient_spend).into() * ED25519_BASEPOINT_POINT),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    let recipient_address = recipient_view.legacy_address(XmrNetwork::Mainnet);
    let recipient_role = match outcome {
        Outcome::Refund => "xmr_owner",
        Outcome::Claim | Outcome::Punish => "dom_owner",
    };
    let payment = reserve_amount / 2;
    let xmr_transaction = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        fresh_secret(),
        vec![input],
        vec![(recipient_address, payment)],
        Change::new(reserve_view, None),
        vec![],
        fee,
    )
    .unwrap()
    .sign(
        &mut OsRng,
        &Zeroizing::new(MoneroScalar::from(reconstructed)),
    )
    .unwrap();
    let tx_as_hex: String = xmr_transaction
        .serialize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let response = rpc
        .rpc_call(
            "send_raw_transaction",
            Some(
                json!({"tx_as_hex":tx_as_hex, "do_not_relay":true, "do_sanity_checks":false})
                    .to_string(),
            ),
            16384,
        )
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["status"], "OK", "{response}");
    let (blocks, _) = rpc.generate_blocks(&recipient_address, 1).await.unwrap();
    let payment_block = rpc.scannable_block(blocks[0]).await.unwrap();
    assert!(payment_block
        .block
        .transactions
        .contains(&xmr_transaction.hash()));
    let received = Scanner::new(recipient_view)
        .scan(payment_block)
        .unwrap()
        .not_additionally_locked();
    assert!(received
        .iter()
        .any(|output| output.commitment().amount == payment));
    let xmr_transaction_id: [u8; 32] = xmr_transaction.hash().as_ref().try_into().unwrap();
    setup
        .journal
        .record_xmr_settlement(xmr_transaction_id)
        .unwrap();
    let durable_state = setup.journal.state().unwrap();
    assert_eq!(durable_state.dom_settlement.unwrap().path, outcome.path());
    assert_eq!(durable_state.xmr_settlement, Some(xmr_transaction_id));
    assert!(handle
        .get_utxo(branch.unsigned.inputs[0].commitment.as_bytes())
        .is_none());
    let active_settlement_seconds = active_settlement.elapsed().as_secs_f64();
    assert!(
        active_settlement.elapsed() <= Duration::from_secs(180),
        "ready-to-complete settlement exceeded three minutes"
    );

    println!(
        "{}",
        json!({
            "experiment":"DXA1 DOM-XMR daemon end-to-end",
            "outcome":format!("{outcome:?}").to_lowercase(),
            "dom_node":true,
            "monerod":true,
            "bitcoin_involved":false,
            "recovery_offers_persisted_before_dom_funding":true,
            "claim_offer_persisted_after_xmr_ready":true,
            "durable_ordering_journal_complete":true,
            "dom_settlement_height":settlement_height,
            "xmr_reserve_amount":reserve_amount,
            "xmr_payment_amount":payment,
            "xmr_recipient_role":recipient_role,
            "xmr_default_lock_window_blocks":monero_wallet::DEFAULT_LOCK_WINDOW,
            "prepared_mature_reserve_required_for_three_minute_target":true,
            "ready_to_complete_seconds":active_settlement_seconds,
            "total_seconds":started.elapsed().as_secs_f64(),
        })
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = env::args_os().skip(1);
    let monerod = PathBuf::from(
        args.next()
            .expect("usage: arbiter_regtest MONEROD claim|refund|punish"),
    );
    let outcome = args
        .next()
        .and_then(|value| value.into_string().ok())
        .map(|value| Outcome::parse(&value))
        .expect("usage: arbiter_regtest MONEROD claim|refund|punish");
    assert!(args.next().is_none(), "too many arguments");
    tokio::time::timeout(Duration::from_secs(180), exercise(monerod, outcome))
        .await
        .expect("arbiter regtest exceeded 180 seconds");
}
