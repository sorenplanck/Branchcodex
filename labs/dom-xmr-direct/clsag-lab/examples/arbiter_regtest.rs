//! Funded DXA1 DOM↔XMR experiment using one isolated DOM Regtest node and one
//! isolated `monerod --regtest`. Bitcoin is not part of this flow. Mining is
//! requested on demand, so elapsed time is evidence for this test fixture and
//! is not a production-network latency guarantee.

use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};
use dom_consensus::{
    swap_arbiter_intent, Block, SwapArbiterContract, SwapArbiterPath, Transaction,
    TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::{
    hash::blake2b_256_tagged,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign, SecretKey,
};
use dom_node::{node::DomNode, node_handle::NodeHandleImpl};
use dom_rpc::{NodeHandle, SpendRequest, TxAdmissionState};
use dom_scriptless_primitives::scriptless_add_public_points;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet::{Bip39Seed, Network, WalletDir};
use dxp1_clsag_lab::{
    arbiter_pair::VerifiedArbiterSharesV1,
    arbiter_session::{ArbiterSessionBinding, ArbiterSessionJournal},
    claim_resume::digest,
    dom_reserve::ReserveIntent,
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
use sha2::{Digest, Sha256};
use xmr_dleq_sigma::BoundCrossCurveProofV1;
use zeroize::Zeroizing;

const SETTLEMENT_ID: [u8; 32] = [0x72; 32];
const CONTEXT_HASH: [u8; 32] = [0x73; 32];
const ARBITER_VALUE: u64 = 100_000_000;
const FEE: u64 = 1_000_000;
const MIN_DOM_CONFIRMATIONS: u64 = 2;

struct ManagedDaemon(Child);

impl Drop for ManagedDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone)]
struct NoiseEndpoints {
    server_key_path: PathBuf,
    client_key_path: PathBuf,
    server_public: [u8; 32],
    client_public: [u8; 32],
}

struct PartyProcess {
    binary: PathBuf,
    proxy_binary: PathBuf,
    role: String,
    chain_id: [u8; 32],
    state_path: PathBuf,
    noise: NoiseEndpoints,
    server: Child,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Drop for PartyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

impl PartyProcess {
    fn transport_session(chain_id: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"DXA1/participant-transport/v1");
        hash.update(SETTLEMENT_ID);
        hash.update(CONTEXT_HASH);
        hash.update(chain_id);
        hash.finalize().into()
    }

    fn identity(proxy_binary: &Path, path: &Path) -> [u8; 32] {
        let output = Command::new(proxy_binary)
            .arg("identity")
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Noise identity failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixed_hex(String::from_utf8(output.stdout).unwrap().trim())
    }

    fn launch(
        binary: &Path,
        proxy_binary: &Path,
        role: &str,
        chain_id: [u8; 32],
        state_path: &Path,
        noise: &NoiseEndpoints,
    ) -> (
        Child,
        Child,
        ChildStdin,
        BufReader<ChildStdout>,
        BoundCrossCurveProofV1,
        bool,
    ) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let address = format!("127.0.0.1:{port}");
        let session = Self::transport_session(chain_id);
        let mut server = Command::new(proxy_binary)
            .arg("server")
            .arg(binary)
            .arg(role)
            .arg(hex(&SETTLEMENT_ID))
            .arg(hex(&CONTEXT_HASH))
            .arg(hex(&chain_id))
            .arg(state_path)
            .arg(&address)
            .arg(&noise.server_key_path)
            .arg(hex(&noise.client_public))
            .arg(hex(&session))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut server_output = BufReader::new(server.stdout.take().unwrap());
        let mut listening = String::new();
        assert_ne!(
            server_output.read_line(&mut listening).unwrap(),
            0,
            "party proxy server exited early"
        );
        assert_eq!(listening.trim(), address);

        let mut child = Command::new(proxy_binary)
            .arg("client")
            .arg(&address)
            .arg(&noise.client_key_path)
            .arg(hex(&noise.server_public))
            .arg(hex(&chain_id))
            .arg(hex(&session))
            .arg(dom_core::NETWORK_MAGIC_REGTEST.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "party exited early"
        );
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["ok"], true);
        assert_eq!(ready["role"], role);
        let proof = serde_json::from_value(ready["proof"].clone()).unwrap();
        let restored = ready["restored"].as_bool().unwrap();
        (server, child, input, output, proof, restored)
    }

    fn spawn(
        binary: &Path,
        role: &str,
        chain_id: [u8; 32],
        state_path: PathBuf,
    ) -> (Self, BoundCrossCurveProofV1, bool) {
        let proxy_binary = binary.with_file_name("arbiter_party_proxy");
        assert!(proxy_binary.is_file(), "arbiter_party_proxy missing");
        let server_key_path = state_path.with_extension("server-noise");
        let client_key_path = state_path.with_extension("client-noise");
        let noise = NoiseEndpoints {
            server_public: Self::identity(&proxy_binary, &server_key_path),
            client_public: Self::identity(&proxy_binary, &client_key_path),
            server_key_path,
            client_key_path,
        };
        let (server, child, input, output, proof, restored) =
            Self::launch(binary, &proxy_binary, role, chain_id, &state_path, &noise);
        (
            Self {
                binary: binary.to_owned(),
                proxy_binary,
                role: role.to_owned(),
                chain_id,
                state_path,
                noise,
                server,
                child,
                input,
                output,
            },
            proof,
            restored,
        )
    }

    fn restart(&mut self) -> (BoundCrossCurveProofV1, bool) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.server.kill().unwrap();
        self.server.wait().unwrap();
        let (server, child, input, output, proof, restored) = Self::launch(
            &self.binary,
            &self.proxy_binary,
            &self.role,
            self.chain_id,
            &self.state_path,
            &self.noise,
        );
        self.server = server;
        self.child = child;
        self.input = input;
        self.output = output;
        (proof, restored)
    }

    fn exchange(&mut self, request: serde_json::Value) -> serde_json::Value {
        serde_json::to_writer(&mut self.input, &request).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "party exited before response"
        );
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, request: serde_json::Value) -> serde_json::Value {
        let response = self.exchange(request);
        assert_eq!(response["ok"], true, "party rejected request: {response}");
        response["value"].clone()
    }

    fn bind_peer(&mut self, proof: &BoundCrossCurveProofV1) -> [u8; 32] {
        let value = self.request(json!({"op":"bind-peer","proof":proof}));
        fixed_hex(value["joint_xmr_key"].as_str().unwrap())
    }

    fn authorize_dom(&mut self, contract: &SwapArbiterContract, offer: &DomClaimOffer) {
        let offer_bytes = offer.to_swap_arbiter_resume_bytes().unwrap();
        let value = self.request(json!({
            "op":"authorize-dom",
            "contract":hex(&contract.to_bytes()),
            "offer":hex(&offer_bytes),
        }));
        assert_eq!(
            fixed_hex::<32>(value["offer_digest"].as_str().unwrap()),
            digest(&offer_bytes)
        );
    }

    fn complete_dom(&mut self, offer: &DomClaimOffer, height: u64) -> Transaction {
        let bytes = offer.to_swap_arbiter_resume_bytes().unwrap();
        let value = self.request(json!({
            "op":"complete-dom",
            "offer":hex(&bytes),
            "height":height,
        }));
        Transaction::from_bytes(&decode_hex(value["transaction"].as_str().unwrap())).unwrap()
    }

    fn rejects_dom(&mut self, offer: &DomClaimOffer, height: u64) -> bool {
        let bytes = offer.to_swap_arbiter_resume_bytes().unwrap();
        !self
            .exchange(json!({
                "op":"complete-dom",
                "offer":hex(&bytes),
                "height":height,
            }))
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    fn sign_xmr(
        &mut self,
        signable: &SignableTransaction,
        opening: [u8; 32],
        path: SwapArbiterPath,
    ) -> (String, [u8; 32]) {
        let path = match path {
            SwapArbiterPath::Claim => "claim",
            SwapArbiterPath::Refund => "refund",
            SwapArbiterPath::Punish => "punish",
        };
        let value = self.request(json!({
            "op":"sign-xmr",
            "path":path,
            "opening":hex(&opening),
            "signable":hex(&signable.serialize()),
        }));
        (
            value["transaction"].as_str().unwrap().to_owned(),
            fixed_hex(value["transaction_id"].as_str().unwrap()),
        )
    }

    fn rejects_xmr(
        &mut self,
        signable: &SignableTransaction,
        opening: [u8; 32],
        path: SwapArbiterPath,
    ) -> bool {
        let path = match path {
            SwapArbiterPath::Claim => "claim",
            SwapArbiterPath::Refund => "refund",
            SwapArbiterPath::Punish => "punish",
        };
        !self
            .exchange(json!({
                "op":"sign-xmr",
                "path":path,
                "opening":hex(&opening),
                "signable":hex(&signable.serialize()),
            }))
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    fn rejects_dom_presign(
        &mut self,
        branch: &Branch,
        adaptor: &dom_crypto::PublicKey,
        path: SwapArbiterPath,
        session: u8,
    ) -> bool {
        !self
            .exchange(json!({
                "op":"dom-possession",
                "path":path_name(path),
                "transaction":hex(&branch.unsigned.to_bytes().unwrap()),
                "adaptor":hex(&adaptor.to_compressed_bytes()),
                "kernel_keys":[
                    hex(&branch.kernel_keys[0].to_compressed_bytes()),
                    hex(&branch.kernel_keys[1].to_compressed_bytes()),
                ],
                "session":hex(&[session;32]),
                "route":hex(&CONTEXT_HASH),
            }))
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Claim,
    Refund,
    Punish,
    ReorgGuard,
}

impl Outcome {
    fn parse(value: &str) -> Self {
        match value {
            "claim" => Self::Claim,
            "refund" => Self::Refund,
            "punish" => Self::Punish,
            "reorg-guard" => Self::ReorgGuard,
            _ => panic!("outcome must be claim, refund, punish, or reorg-guard"),
        }
    }

    fn path(self) -> SwapArbiterPath {
        match self {
            Self::Claim | Self::ReorgGuard => SwapArbiterPath::Claim,
            Self::Refund => SwapArbiterPath::Refund,
            Self::Punish => SwapArbiterPath::Punish,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Refund => "refund",
            Self::Punish => "punish",
            Self::ReorgGuard => "reorg-guard",
        }
    }
}

fn path_name(path: SwapArbiterPath) -> &'static str {
    match path {
        SwapArbiterPath::Claim => "claim",
        SwapArbiterPath::Refund => "refund",
        SwapArbiterPath::Punish => "punish",
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

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("party returned invalid hex"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
    decode_hex(value).try_into().ok().unwrap()
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

async fn canonical_block(node: &Arc<DomNode>, height: u64) -> Block {
    let handle = NodeHandleImpl(node.clone());
    let block_hash = handle.get_block_hash_at_height(height).unwrap();
    let bytes = node
        .chain
        .lock()
        .await
        .store
        .get_block_body(&block_hash)
        .unwrap()
        .unwrap();
    Block::from_bytes(&bytes).unwrap()
}

fn validation_now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200,
    )
}

async fn shadow_node(
    root: &Path,
    source: &Arc<DomNode>,
    through_height: u64,
    expected_chain_id: [u8; 32],
) -> Arc<DomNode> {
    let wallet_path = root.join("shadow-wallet");
    WalletDir::create_from_seed(
        &wallet_path,
        "arbiter-shadow-test",
        Network::Regtest,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        &Bip39Seed::generate_new().unwrap(),
    )
    .unwrap();
    let mut config = dom_config::NodeConfig::regtest();
    config.data_dir = root.join("shadow-chain").to_string_lossy().into_owned();
    config.wallet_path = Some(wallet_path.to_string_lossy().into_owned());
    config.wallet_password = Some("arbiter-shadow-test".into());
    config.mine = false;
    config.miner_threads = 1;
    config.min_outbound = 0;
    config.disable_dns_seeds = true;
    config.p2p_listen_addr = "127.0.0.1:0".into();
    let shadow = Arc::new(DomNode::init_with_map_size(config, 64 << 20).unwrap());
    dom_node::miner::create_genesis_block(shadow.clone())
        .await
        .unwrap();
    let shadow_chain_id = *shadow
        .wallet
        .as_ref()
        .unwrap()
        .lock()
        .await
        .wallet()
        .chain_id();
    assert_eq!(shadow_chain_id, expected_chain_id);
    for height in 1..=through_height {
        let block = canonical_block(source, height).await;
        let result = shadow
            .chain
            .lock()
            .await
            .connect_block(&block, validation_now())
            .unwrap();
        assert!(matches!(result, dom_chain::ConnectResult::BestChain));
    }
    let source_tip = NodeHandleImpl(source.clone())
        .get_block_hash_at_height(through_height)
        .unwrap();
    let shadow_tip = NodeHandleImpl(shadow.clone())
        .get_block_hash_at_height(through_height)
        .unwrap();
    assert_eq!(source_tip, shadow_tip);
    shadow
}

struct Branch {
    unsigned: Transaction,
    kernel_keys: [dom_crypto::PublicKey; 2],
}

fn branch(
    input: Commitment,
    input_blinding: &BlindingFactor,
    chain_id: [u8; 32],
    boundary: u64,
    path: SwapArbiterPath,
    dom_owner: &mut PartyProcess,
    xmr_owner: &mut PartyProcess,
) -> Branch {
    let feature = match path {
        SwapArbiterPath::Claim => dom_core::KERNEL_FEAT_SWAP_CLAIM,
        SwapArbiterPath::Refund => dom_core::KERNEL_FEAT_SWAP_REFUND,
        SwapArbiterPath::Punish => dom_core::KERNEL_FEAT_SWAP_PUNISH,
    };
    let configure = |party: &mut PartyProcess, input: Option<&BlindingFactor>| {
        let mut request = json!({"op":"configure-branch","path":path_name(path)});
        if let Some(input) = input {
            request["input_blinding"] = json!(hex(input.as_bytes()));
        }
        let value = party.request(request);
        (
            dom_crypto::PublicKey::from_compressed_bytes(&fixed_hex::<33>(
                value["kernel_key"].as_str().unwrap(),
            ))
            .unwrap(),
            dom_crypto::PublicKey::from_compressed_bytes(&fixed_hex::<33>(
                value["output_share_key"].as_str().unwrap(),
            ))
            .unwrap(),
        )
    };
    let (dom_kernel, dom_output) = configure(dom_owner, Some(input_blinding));
    let (xmr_kernel, xmr_output) = configure(xmr_owner, None);
    let kernel_keys = [dom_kernel, xmr_kernel];
    let output_keys = [dom_output, xmr_output];
    let reserve_session = [feature; 32];
    let reserve_intent = ReserveIntent::new(
        ARBITER_VALUE - FEE,
        chain_id,
        reserve_session,
        CONTEXT_HASH,
        output_keys.clone(),
    )
    .unwrap();
    let reserve_request = || {
        json!({
            "path":path_name(path),
            "value":ARBITER_VALUE-FEE,
            "session":hex(&reserve_session),
            "terms":hex(&CONTEXT_HASH),
            "output_share_keys":[
                hex(&output_keys[0].to_compressed_bytes()),
                hex(&output_keys[1].to_compressed_bytes()),
            ],
        })
    };
    let mut request = reserve_request();
    request["op"] = json!("reserve-possession");
    let dom_possession = dom_owner.request(request)["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut request = reserve_request();
    request["op"] = json!("reserve-possession");
    let xmr_possession = xmr_owner.request(request)["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let possession = [dom_possession, xmr_possession];
    let mut common_seed = [0; 32];
    OsRng.fill_bytes(&mut common_seed);
    let round_one_request = || {
        let mut request = reserve_request();
        request["op"] = json!("reserve-round-one");
        request["proofs"] = json!(possession);
        request["common_seed"] = json!(hex(&common_seed));
        request
    };
    let round_one = [
        dom_owner.request(round_one_request()),
        xmr_owner.request(round_one_request()),
    ];
    let round_two_request = |peer: &serde_json::Value| {
        json!({
            "op":"reserve-round-two",
            "path":path_name(path),
            "plan":peer["plan"],
            "index":peer["index"],
            "t_one":peer["t_one"],
            "t_two":peer["t_two"],
        })
    };
    let dom_response = dom_owner.request(round_two_request(&round_one[1]));
    let xmr_response = xmr_owner.request(round_two_request(&round_one[0]));
    let complete_request = |peer: &serde_json::Value| {
        json!({
            "op":"reserve-complete",
            "path":path_name(path),
            "round":peer["round"],
            "index":peer["index"],
            "scalar":peer["scalar"],
        })
    };
    let dom_proof = dom_owner.request(complete_request(&xmr_response));
    let xmr_proof = xmr_owner.request(complete_request(&dom_response));
    assert_eq!(dom_proof, xmr_proof);
    let proof = decode_hex(dom_proof["range_proof"].as_str().unwrap());
    let commitment = reserve_intent.commitment().clone();
    let excess = scriptless_add_public_points(&kernel_keys).unwrap();
    let unsigned = Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![TransactionOutput { commitment, proof }],
        kernels: vec![TransactionKernel {
            features: feature,
            fee: Amount::from_noms(FEE).unwrap(),
            lock_height: boundary,
            excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes()).unwrap(),
            excess_signature: [0; 65],
        }],
        offset: [0; 32],
    };
    PreparedDomClaim::new_swap_arbiter_path(unsigned.clone(), chain_id).unwrap();
    Branch {
        unsigned,
        kernel_keys,
    }
}

fn offer(
    branch: &Branch,
    adaptor: dom_crypto::PublicKey,
    session: u8,
    path: SwapArbiterPath,
    dom_owner: &mut PartyProcess,
    xmr_owner: &mut PartyProcess,
) -> DomClaimOffer {
    let transaction = hex(&branch.unsigned.to_bytes().unwrap());
    let base = || {
        json!({
            "path":path_name(path),
            "transaction":transaction,
            "adaptor":hex(&adaptor.to_compressed_bytes()),
            "kernel_keys":[
                hex(&branch.kernel_keys[0].to_compressed_bytes()),
                hex(&branch.kernel_keys[1].to_compressed_bytes()),
            ],
            "session":hex(&[session;32]),
            "route":hex(&CONTEXT_HASH),
        })
    };
    let mut request = base();
    request["op"] = json!("dom-possession");
    let dom_possession = dom_owner.request(request)["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut request = base();
    request["op"] = json!("dom-possession");
    let xmr_possession = xmr_owner.request(request)["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let possession = [dom_possession, xmr_possession];
    let round_one_request = || {
        let mut request = base();
        request["op"] = json!("dom-round-one");
        request["proofs"] = json!(possession);
        request
    };
    let round_one = [
        dom_owner.request(round_one_request()),
        xmr_owner.request(round_one_request()),
    ];
    let round_two_request = |peer: &serde_json::Value| {
        json!({
            "op":"dom-round-two",
            "path":path_name(path),
            "plan":peer["plan"],
            "signer":peer["signer"],
            "nonces":peer["nonces"],
        })
    };
    let dom_response = dom_owner.request(round_two_request(&round_one[1]));
    let xmr_response = xmr_owner.request(round_two_request(&round_one[0]));
    let complete_request = |peer: &serde_json::Value| {
        json!({
            "op":"dom-presign-complete",
            "path":path_name(path),
            "round":peer["round"],
            "signer":peer["signer"],
            "scalar":peer["scalar"],
        })
    };
    let dom_offer = dom_owner.request(complete_request(&xmr_response));
    let xmr_offer = xmr_owner.request(complete_request(&dom_response));
    assert_eq!(dom_offer, xmr_offer);
    let bytes = decode_hex(dom_offer["offer"].as_str().unwrap());
    DomClaimOffer::from_swap_arbiter_resume_bytes(&bytes, digest(&bytes)).unwrap()
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
    shadow: Option<Arc<DomNode>>,
    chain_id: [u8; 32],
    contract: SwapArbiterContract,
    shares: VerifiedArbiterSharesV1,
    dom_owner: PartyProcess,
    xmr_owner: PartyProcess,
    claim: Branch,
    refund: Branch,
    punish: Branch,
    refund_offer: DomClaimOffer,
    punish_offer: DomClaimOffer,
    refund_replacement_offer: DomClaimOffer,
    punish_replacement_offer: DomClaimOffer,
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
    let block = canonical_block(&setup.node, height).await;
    block
        .transactions
        .into_iter()
        .find(|candidate| candidate == expected)
        .unwrap()
}

async fn funded_arbiter(party_binary: &Path, create_shadow: bool) -> FundedArbiter {
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

    let (mut dom_owner, dom_proof, dom_restored) = PartyProcess::spawn(
        party_binary,
        "dom-owner",
        chain_id,
        root.0.join("dom-owner.state"),
    );
    let (mut xmr_owner, xmr_proof, xmr_restored) = PartyProcess::spawn(
        party_binary,
        "xmr-owner",
        chain_id,
        root.0.join("xmr-owner.state"),
    );
    assert!(!dom_restored && !xmr_restored);
    let shares =
        VerifiedArbiterSharesV1::new(SETTLEMENT_ID, CONTEXT_HASH, &dom_proof, &xmr_proof).unwrap();
    let dom_joint = dom_owner.bind_peer(&xmr_proof);
    let xmr_joint = xmr_owner.bind_peer(&dom_proof);
    assert_eq!(dom_joint, xmr_joint);
    assert_eq!(dom_joint, shares.joint_xmr_spend_key().unwrap());

    let arbiter_blinding = BlindingFactor::random();
    let arbiter = Commitment::commit(ARBITER_VALUE, &arbiter_blinding);
    let claim_until = staging_height + 2;
    let refund_until = claim_until + 1;
    let claim = branch(
        arbiter.clone(),
        &arbiter_blinding,
        chain_id,
        claim_until,
        SwapArbiterPath::Claim,
        &mut dom_owner,
        &mut xmr_owner,
    );
    let refund = branch(
        arbiter.clone(),
        &arbiter_blinding,
        chain_id,
        claim_until + 1,
        SwapArbiterPath::Refund,
        &mut dom_owner,
        &mut xmr_owner,
    );
    let punish = branch(
        arbiter,
        &arbiter_blinding,
        chain_id,
        refund_until + 1,
        SwapArbiterPath::Punish,
        &mut dom_owner,
        &mut xmr_owner,
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
            SwapArbiterPath::Refund,
            &mut dom_owner,
            &mut xmr_owner,
        ),
    );
    let punish_offer = restore(
        "punish.offer",
        offer(
            &punish,
            shares.adaptor_point(SwapArbiterPath::Punish).unwrap(),
            83,
            SwapArbiterPath::Punish,
            &mut dom_owner,
            &mut xmr_owner,
        ),
    );
    let refund_replacement_offer = offer(
        &refund,
        shares.adaptor_point(SwapArbiterPath::Refund).unwrap(),
        92,
        SwapArbiterPath::Refund,
        &mut dom_owner,
        &mut xmr_owner,
    );
    let punish_replacement_offer = offer(
        &punish,
        shares.adaptor_point(SwapArbiterPath::Punish).unwrap(),
        93,
        SwapArbiterPath::Punish,
        &mut dom_owner,
        &mut xmr_owner,
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
    dom_owner.authorize_dom(&contract, &refund_offer);
    xmr_owner.authorize_dom(&contract, &punish_offer);
    let session_binding = ArbiterSessionBinding::new(
        chain_id,
        &contract,
        &shares,
        &refund_offer,
        &punish_offer,
        1,
        MIN_DOM_CONFIRMATIONS,
    )
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
    let shadow = if create_shadow {
        Some(shadow_node(&root.0, &node, funding_height, chain_id).await)
    } else {
        None
    };

    FundedArbiter {
        _root: root,
        node,
        shadow,
        chain_id,
        contract,
        shares,
        dom_owner,
        xmr_owner,
        claim,
        refund,
        punish,
        refund_offer,
        punish_offer,
        refund_replacement_offer,
        punish_replacement_offer,
        claim_until,
        refund_until,
        session_binding,
        journal,
    }
}

async fn exercise(monerod: PathBuf, party_binary: PathBuf, outcome: Outcome) {
    let started = Instant::now();
    let mut setup = funded_arbiter(&party_binary, outcome == Outcome::ReorgGuard).await;
    let handle = NodeHandleImpl(setup.node.clone());

    let verified_joint = CompressedEdwardsY(setup.shares.joint_xmr_spend_key().unwrap())
        .decompress()
        .unwrap();
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
        SwapArbiterPath::Claim,
        &mut setup.dom_owner,
        &mut setup.xmr_owner,
    );
    let claim_replacement_offer = offer(
        &setup.claim,
        setup.shares.adaptor_point(SwapArbiterPath::Claim).unwrap(),
        91,
        SwapArbiterPath::Claim,
        &mut setup.dom_owner,
        &mut setup.xmr_owner,
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
    setup.xmr_owner.authorize_dom(&setup.contract, &claim_offer);
    setup.journal.record_claim_ready(&claim_offer).unwrap();
    drop(setup.journal);
    setup.journal =
        ArbiterSessionJournal::open(&session_path, setup.session_binding.clone()).unwrap();

    let (dom_restart_proof, dom_restored) = setup.dom_owner.restart();
    let (xmr_restart_proof, xmr_restored) = setup.xmr_owner.restart();
    assert!(dom_restored && xmr_restored);
    let restarted_shares = VerifiedArbiterSharesV1::new(
        SETTLEMENT_ID,
        CONTEXT_HASH,
        &dom_restart_proof,
        &xmr_restart_proof,
    )
    .unwrap();
    assert_eq!(
        restarted_shares.joint_xmr_spend_key().unwrap(),
        setup.shares.joint_xmr_spend_key().unwrap()
    );
    for path in [
        SwapArbiterPath::Claim,
        SwapArbiterPath::Refund,
        SwapArbiterPath::Punish,
    ] {
        assert_eq!(
            restarted_shares
                .adaptor_point(path)
                .unwrap()
                .to_compressed_bytes(),
            setup
                .shares
                .adaptor_point(path)
                .unwrap()
                .to_compressed_bytes()
        );
    }
    assert_eq!(
        setup.dom_owner.bind_peer(&xmr_restart_proof),
        setup.shares.joint_xmr_spend_key().unwrap()
    );
    assert_eq!(
        setup.xmr_owner.bind_peer(&dom_restart_proof),
        setup.shares.joint_xmr_spend_key().unwrap()
    );
    let claim_adaptor = setup.shares.adaptor_point(SwapArbiterPath::Claim).unwrap();
    assert!(setup.dom_owner.rejects_dom_presign(
        &setup.claim,
        &claim_adaptor,
        SwapArbiterPath::Claim,
        81,
    ));
    assert!(setup.xmr_owner.rejects_dom_presign(
        &setup.claim,
        &claim_adaptor,
        SwapArbiterPath::Claim,
        81,
    ));
    setup
        .dom_owner
        .authorize_dom(&setup.contract, &setup.refund_offer);
    setup
        .xmr_owner
        .authorize_dom(&setup.contract, &setup.punish_offer);
    setup.xmr_owner.authorize_dom(&setup.contract, &claim_offer);

    let (branch, selected_offer, replacement_offer, settlement_height) = match outcome {
        Outcome::Claim | Outcome::ReorgGuard => (
            &setup.claim,
            &claim_offer,
            &claim_replacement_offer,
            setup.claim_until,
        ),
        Outcome::Refund => {
            assert_eq!(mine(&setup.node).await, setup.claim_until);
            (
                &setup.refund,
                &setup.refund_offer,
                &setup.refund_replacement_offer,
                setup.claim_until + 1,
            )
        }
        Outcome::Punish => {
            assert_eq!(mine(&setup.node).await, setup.claim_until);
            assert_eq!(mine(&setup.node).await, setup.refund_until);
            (
                &setup.punish,
                &setup.punish_offer,
                &setup.punish_replacement_offer,
                setup.refund_until + 1,
            )
        }
    };
    let settlement = match outcome {
        Outcome::Refund => {
            assert!(setup
                .xmr_owner
                .rejects_dom(selected_offer, settlement_height));
            assert!(setup
                .dom_owner
                .rejects_dom(replacement_offer, settlement_height));
            setup
                .dom_owner
                .complete_dom(selected_offer, settlement_height)
        }
        Outcome::Claim | Outcome::Punish | Outcome::ReorgGuard => {
            assert!(setup
                .dom_owner
                .rejects_dom(selected_offer, settlement_height));
            assert!(setup
                .xmr_owner
                .rejects_dom(replacement_offer, settlement_height));
            setup
                .xmr_owner
                .complete_dom(selected_offer, settlement_height)
        }
    };
    let released_dom_id = setup
        .journal
        .record_dom_release(&settlement, settlement_height)
        .unwrap();
    let settlement_admission = handle.submit_tx(settlement.to_bytes().unwrap()).unwrap();
    assert_eq!(settlement_admission.state, TxAdmissionState::New);
    assert_eq!(mine(&setup.node).await, settlement_height);
    let observed = observed_transaction(&setup, settlement_height, &settlement).await;
    let durable_dom_id = setup
        .journal
        .record_dom_settlement(&observed, settlement_height)
        .unwrap();
    assert_eq!(released_dom_id, settlement_admission.tx_hash);
    assert_eq!(durable_dom_id, settlement_admission.tx_hash);
    assert!(setup.journal.record_xmr_settlement([1; 32]).is_err());
    let finality_height = mine(&setup.node).await;
    assert_eq!(
        finality_height,
        settlement_height + MIN_DOM_CONFIRMATIONS - 1
    );
    let settlement_block_hash = handle.get_block_hash_at_height(settlement_height).unwrap();
    let finality_tip_hash = handle.get_block_hash_at_height(finality_height).unwrap();
    assert_eq!(
        observed_transaction(&setup, settlement_height, &settlement).await,
        settlement
    );
    let dom_confirmation_depth = setup
        .journal
        .record_dom_finality(
            &observed,
            settlement_height,
            settlement_block_hash,
            finality_height,
            finality_tip_hash,
        )
        .unwrap();
    assert_eq!(dom_confirmation_depth, MIN_DOM_CONFIRMATIONS);

    if outcome == Outcome::ReorgGuard {
        let shadow = setup.shadow.as_ref().unwrap().clone();
        for expected_height in settlement_height..=settlement_height + 2 {
            assert_eq!(mine(&shadow).await, expected_height);
        }
        let mut reorg_promoted = false;
        for height in settlement_height..=settlement_height + 2 {
            let alternate = canonical_block(&shadow, height).await;
            let result = setup
                .node
                .chain
                .lock()
                .await
                .connect_block(&alternate, validation_now())
                .unwrap();
            reorg_promoted |= matches!(result, dom_chain::ConnectResult::Reorg(_));
        }
        assert!(reorg_promoted);
        let canonical_height = handle.chain_height();
        assert_eq!(canonical_height, settlement_height + 2);
        let changed_block_hash = handle.get_block_hash_at_height(settlement_height).unwrap();
        let changed_tip_hash = handle.get_block_hash_at_height(canonical_height).unwrap();
        assert_ne!(changed_block_hash, settlement_block_hash);
        let changed_block = canonical_block(&setup.node, settlement_height).await;
        assert!(!changed_block
            .transactions
            .iter()
            .any(|candidate| candidate == &settlement));
        assert!(setup
            .journal
            .verify_dom_canonicality(
                &observed,
                settlement_height,
                changed_block_hash,
                canonical_height,
                changed_tip_hash,
            )
            .is_err());
        let active_seconds = active_settlement.elapsed().as_secs_f64();
        assert!(active_settlement.elapsed() <= Duration::from_secs(180));
        println!(
            "{}",
            json!({
                "experiment":"DXA1 DOM-XMR daemon end-to-end",
                "outcome":outcome.label(),
                "dom_node":true,
                "monerod":true,
                "bitcoin_involved":false,
                "authenticated_noise_transport":true,
                "distributed_dom_presigning":true,
                "collaborative_dom_range_proofs":true,
                "coordinator_never_receives_dom_signing_keys":true,
                "participant_restart_restored_bound_shares":true,
                "dom_finality_recorded_before_reorg":true,
                "dom_reorg_promoted":true,
                "dom_settlement_removed_by_reorg":true,
                "dom_canonicality_recheck_rejected_reorg":true,
                "xmr_signing_requested":false,
                "xmr_transaction_submitted":false,
                "dom_min_confirmations":MIN_DOM_CONFIRMATIONS,
                "dom_confirmation_depth_before_reorg":dom_confirmation_depth,
                "competing_tip_height":canonical_height,
                "ready_to_reorg_rejection_seconds":active_seconds,
                "total_seconds":started.elapsed().as_secs_f64(),
                "prepared_mature_reserve_required_for_three_minute_target":true,
                "xmr_default_lock_window_blocks":monero_wallet::DEFAULT_LOCK_WINDOW,
            })
        );
        return;
    }
    drop(setup.journal);
    setup.journal =
        ArbiterSessionJournal::open(&session_path, setup.session_binding.clone()).unwrap();
    let opening = selected_offer
        .extract(
            &observed,
            &validation_context(setup.chain_id, settlement_height),
        )
        .unwrap();

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
        Outcome::ReorgGuard => unreachable!(),
    };
    let payment = reserve_amount / 2;
    let signable_xmr_transaction = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        fresh_secret(),
        vec![input],
        vec![(recipient_address, payment)],
        Change::new(reserve_view, None),
        vec![],
        fee,
    )
    .unwrap();
    let recheck_tip_height = handle.chain_height();
    let recheck_block_hash = handle.get_block_hash_at_height(settlement_height).unwrap();
    let recheck_tip_hash = handle.get_block_hash_at_height(recheck_tip_height).unwrap();
    let rechecked_settlement = observed_transaction(&setup, settlement_height, &settlement).await;
    let recheck_depth = setup
        .journal
        .verify_dom_canonicality(
            &rechecked_settlement,
            settlement_height,
            recheck_block_hash,
            recheck_tip_height,
            recheck_tip_hash,
        )
        .unwrap();
    let (tx_as_hex, xmr_transaction_id) = match outcome {
        Outcome::Refund => {
            assert!(setup.dom_owner.rejects_xmr(
                &signable_xmr_transaction,
                *opening,
                outcome.path(),
            ));
            setup
                .xmr_owner
                .sign_xmr(&signable_xmr_transaction, *opening, outcome.path())
        }
        Outcome::Claim | Outcome::Punish => {
            assert!(setup.xmr_owner.rejects_xmr(
                &signable_xmr_transaction,
                *opening,
                outcome.path(),
            ));
            setup
                .dom_owner
                .sign_xmr(&signable_xmr_transaction, *opening, outcome.path())
        }
        Outcome::ReorgGuard => unreachable!(),
    };
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
        .iter()
        .any(|transaction| transaction.as_ref() == xmr_transaction_id));
    let received = Scanner::new(recipient_view)
        .scan(payment_block)
        .unwrap()
        .not_additionally_locked();
    assert!(received
        .iter()
        .any(|output| output.commitment().amount == payment));
    setup
        .journal
        .record_xmr_settlement(xmr_transaction_id)
        .unwrap();
    let durable_state = setup.journal.state().unwrap();
    assert_eq!(durable_state.dom_settlement.unwrap().path, outcome.path());
    assert_eq!(
        durable_state.dom_finality.unwrap().confirmation_depth,
        MIN_DOM_CONFIRMATIONS
    );
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
            "outcome":outcome.label(),
            "dom_node":true,
            "monerod":true,
            "bitcoin_involved":false,
            "recovery_offers_persisted_before_dom_funding":true,
            "claim_offer_persisted_after_xmr_ready":true,
            "durable_ordering_journal_complete":true,
            "dom_release_recorded_before_submit":true,
            "dom_finality_recorded_before_xmr_submit":true,
            "private_xmr_shares_held_by_separate_processes":true,
            "distributed_dom_presigning":true,
            "collaborative_dom_range_proofs":true,
            "coordinator_never_receives_dom_signing_keys":true,
            "post_restart_dom_presigning_rejected":true,
            "authenticated_noise_transport":true,
            "noise_peer_identity_pinned":true,
            "transport_session_bound":true,
            "wrong_role_operations_rejected":true,
            "unauthorized_dom_offer_rejected":true,
            "participant_restart_restored_bound_shares":true,
            "dom_min_confirmations":MIN_DOM_CONFIRMATIONS,
            "dom_confirmation_depth":dom_confirmation_depth,
            "dom_pre_xmr_recheck_depth":recheck_depth,
            "dom_canonicality_rechecked_before_xmr_signing":true,
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
            .expect("usage: arbiter_regtest MONEROD claim|refund|punish|reorg-guard"),
    );
    let outcome = args
        .next()
        .and_then(|value| value.into_string().ok())
        .map(|value| Outcome::parse(&value))
        .expect("usage: arbiter_regtest MONEROD claim|refund|punish|reorg-guard");
    assert!(args.next().is_none(), "too many arguments");
    let party_binary = std::env::current_exe()
        .unwrap()
        .with_file_name("arbiter_party");
    assert!(
        party_binary.is_file(),
        "arbiter_party sibling binary missing"
    );
    tokio::time::timeout(
        Duration::from_secs(180),
        exercise(monerod, party_binary, outcome),
    )
    .await
    .expect("arbiter regtest exceeded 180 seconds");
}
