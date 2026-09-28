use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
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
    dom_joint::{DomCommitment, DomSigner, DomSigningIntent},
    native_dom::{DomClaimOffer, PreparedDomClaim},
};
use rand_core::OsRng;
use xmr_dleq_sigma::{
    prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};

const SETTLEMENT_ID: [u8; 32] = [0x72; 32];
const CONTEXT_HASH: [u8; 32] = [0x73; 32];
const ARBITER_VALUE: u64 = 100_000_000;
const FEE: u64 = 1_000_000;

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
    claim_until: u64,
    refund_until: u64,
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

fn assert_reconstructs_joint_xmr_key(
    setup: &FundedArbiter,
    path: SwapArbiterPath,
    extracted: [u8; 32],
) {
    let recovered = setup
        .shares
        .xmr_share_from_dom_opening(path, extracted)
        .unwrap();
    let recovered = Option::<Scalar>::from(Scalar::from_canonical_bytes(*recovered)).unwrap();
    let (local, expected) = match path {
        SwapArbiterPath::Refund => (
            setup.xmr_owner.xmr_share_little_endian(),
            setup.dom_owner.xmr_share_little_endian(),
        ),
        SwapArbiterPath::Claim | SwapArbiterPath::Punish => (
            setup.dom_owner.xmr_share_little_endian(),
            setup.xmr_owner.xmr_share_little_endian(),
        ),
    };
    let local = Option::<Scalar>::from(Scalar::from_canonical_bytes(local)).unwrap();
    let expected = Option::<Scalar>::from(Scalar::from_canonical_bytes(expected)).unwrap();
    assert_eq!(
        (local + recovered) * ED25519_BASEPOINT_POINT,
        (local + expected) * ED25519_BASEPOINT_POINT
    );
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
    let contract = SwapArbiterContract::new(
        claim_until,
        refund_until,
        swap_arbiter_intent(&claim.unsigned).unwrap(),
        swap_arbiter_intent(&refund.unsigned).unwrap(),
        swap_arbiter_intent(&punish.unsigned).unwrap(),
    )
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
    assert_eq!(
        handle.submit_tx(funding.to_bytes().unwrap()).unwrap().state,
        TxAdmissionState::New
    );
    let funding_height = mine(&node).await;
    assert_eq!(funding_height, staging_height + 1);
    assert!(handle
        .get_utxo(claim.unsigned.inputs[0].commitment.as_bytes())
        .is_some());

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
        claim_until,
        refund_until,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn node_funds_and_settles_claim_from_the_consensus_arbiter() {
    let setup = funded_arbiter().await;
    let handle = NodeHandleImpl(setup.node.clone());

    let refund_tx = offer(
        &setup.refund,
        setup.shares.adaptor_point(SwapArbiterPath::Refund).unwrap(),
        82,
    )
    .complete(
        &SecretScalar::from_be_bytes(setup.dom_owner.dom_secret_big_endian()).unwrap(),
        &validation_context(setup.chain_id, setup.claim_until + 1),
    )
    .unwrap();
    let punish_tx = offer(
        &setup.punish,
        setup.shares.adaptor_point(SwapArbiterPath::Punish).unwrap(),
        83,
    )
    .complete(
        &SecretScalar::from_be_bytes(setup.xmr_owner.dom_secret_big_endian()).unwrap(),
        &validation_context(setup.chain_id, setup.refund_until + 1),
    )
    .unwrap();
    assert!(handle.submit_tx(refund_tx.to_bytes().unwrap()).is_err());
    assert!(handle.submit_tx(punish_tx.to_bytes().unwrap()).is_err());

    let claim_offer = offer(
        &setup.claim,
        setup.shares.adaptor_point(SwapArbiterPath::Claim).unwrap(),
        81,
    );
    let claim_tx = claim_offer
        .complete(
            &SecretScalar::from_be_bytes(setup.xmr_owner.dom_secret_big_endian()).unwrap(),
            &validation_context(setup.chain_id, setup.claim_until),
        )
        .unwrap();
    assert_eq!(
        handle
            .submit_tx(claim_tx.to_bytes().unwrap())
            .unwrap()
            .state,
        TxAdmissionState::New
    );
    let claim_height = mine(&setup.node).await;
    assert_eq!(claim_height, setup.claim_until);
    let observed = observed_transaction(&setup, claim_height, &claim_tx).await;
    let extracted = claim_offer
        .extract(&observed, &validation_context(setup.chain_id, claim_height))
        .unwrap();
    assert_reconstructs_joint_xmr_key(&setup, SwapArbiterPath::Claim, *extracted);
    assert!(handle
        .get_utxo(claim_tx.inputs[0].commitment.as_bytes())
        .is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn node_opens_refund_only_after_claim_window() {
    let setup = funded_arbiter().await;
    let handle = NodeHandleImpl(setup.node.clone());
    let refund_offer = offer(
        &setup.refund,
        setup.shares.adaptor_point(SwapArbiterPath::Refund).unwrap(),
        84,
    );
    let refund_tx = refund_offer
        .complete(
            &SecretScalar::from_be_bytes(setup.dom_owner.dom_secret_big_endian()).unwrap(),
            &validation_context(setup.chain_id, setup.claim_until + 1),
        )
        .unwrap();

    assert!(handle.submit_tx(refund_tx.to_bytes().unwrap()).is_err());
    assert_eq!(mine(&setup.node).await, setup.claim_until);
    assert_eq!(
        handle
            .submit_tx(refund_tx.to_bytes().unwrap())
            .unwrap()
            .state,
        TxAdmissionState::New
    );
    let refund_height = mine(&setup.node).await;
    assert_eq!(refund_height, setup.claim_until + 1);
    let observed = observed_transaction(&setup, refund_height, &refund_tx).await;
    let extracted = refund_offer
        .extract(
            &observed,
            &validation_context(setup.chain_id, refund_height),
        )
        .unwrap();
    assert_reconstructs_joint_xmr_key(&setup, SwapArbiterPath::Refund, *extracted);
    assert!(handle
        .get_utxo(refund_tx.inputs[0].commitment.as_bytes())
        .is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn node_opens_punish_only_after_refund_window() {
    let setup = funded_arbiter().await;
    let handle = NodeHandleImpl(setup.node.clone());
    let punish_offer = offer(
        &setup.punish,
        setup.shares.adaptor_point(SwapArbiterPath::Punish).unwrap(),
        85,
    );
    let punish_tx = punish_offer
        .complete(
            &SecretScalar::from_be_bytes(setup.xmr_owner.dom_secret_big_endian()).unwrap(),
            &validation_context(setup.chain_id, setup.refund_until + 1),
        )
        .unwrap();

    assert!(handle.submit_tx(punish_tx.to_bytes().unwrap()).is_err());
    assert_eq!(mine(&setup.node).await, setup.claim_until);
    assert!(handle.submit_tx(punish_tx.to_bytes().unwrap()).is_err());
    assert_eq!(mine(&setup.node).await, setup.refund_until);
    assert_eq!(
        handle
            .submit_tx(punish_tx.to_bytes().unwrap())
            .unwrap()
            .state,
        TxAdmissionState::New
    );
    let punish_height = mine(&setup.node).await;
    assert_eq!(punish_height, setup.refund_until + 1);
    let observed = observed_transaction(&setup, punish_height, &punish_tx).await;
    let extracted = punish_offer
        .extract(
            &observed,
            &validation_context(setup.chain_id, punish_height),
        )
        .unwrap();
    assert_reconstructs_joint_xmr_key(&setup, SwapArbiterPath::Punish, *extracted);
    assert!(handle
        .get_utxo(punish_tx.inputs[0].commitment.as_bytes())
        .is_none());
}
