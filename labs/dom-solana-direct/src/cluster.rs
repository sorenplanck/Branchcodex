//! Delivery to, and observation of, a real Solana cluster.
//!
//! Nothing here knows about swaps. It signs exactly the message
//! `solana-transaction-builder` produced, submits it, and reports what the node
//! says happened. Two properties are deliberate:
//!
//! * a transaction is never declared successful because it was accepted for
//!   propagation: `confirm` waits for a signature status and fails on a status
//!   whose `failed` flag is set;
//! * the cluster's own clock is read from the `Clock` sysvar, which is the exact
//!   value the escrow program compares `refund_after_unix` against, rather than
//!   this host's clock, which the program never sees.
//!
//! The keypair loader reads the 64-byte array `solana-keygen` writes. It is the
//! only way a key enters this lab, so the funded roles a harness creates are the
//! only roles that can pay a fee.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use solana_rpc::{HttpSolanaRpc, RpcError, SolanaRpc};
use solana_rpc_pool::SolanaRpcPool;
use solana_transaction_builder::{
    assemble_signed_transaction, build_legacy_message, TransactionBuildError,
};
use solana_types::{
    Commitment, SolanaAccountSnapshot, SolanaHash, SolanaInstruction, SolanaPubkey, SolanaSignature,
    SolanaSignatureStatus,
};
use std::{
    path::Path,
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// `SysvarC1ock11111111111111111111111111111111`, the account holding the
/// cluster clock the runtime hands to a program.
pub const CLOCK_SYSVAR_BASE58: &str = "SysvarC1ock11111111111111111111111111111111";

/// Byte offset of `unix_timestamp` inside the bincode-encoded `Clock`:
/// slot(u64) + epoch_start_timestamp(i64) + epoch(u64) + leader_schedule_epoch(u64).
const CLOCK_UNIX_TIMESTAMP_OFFSET: usize = 32;
const CLOCK_LEN: usize = 40;

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("Solana RPC: {0}")]
    Rpc(#[from] RpcError),
    /// A refused transaction, in the program's own words.
    ///
    /// `solana-rpc` maps every JSON-RPC error to one opaque variant, so a
    /// refusal arrives as `Rpc(Remote)` with the reason discarded -- which says
    /// nothing at all about why the runtime said no. When a submission fails the
    /// harness re-asks the node to simulate the same bytes and reports what it
    /// answers, so a refusal names itself instead of needing another run to
    /// investigate.
    #[error("the cluster refused the transaction: {err}\nprogram logs:\n{logs}")]
    Refused { err: String, logs: String },
    #[error("transaction assembly: {0}")]
    Build(#[from] TransactionBuildError),
    #[error("no keypair was supplied for a required signer")]
    MissingSigner,
    #[error("the keypair file is not a 64-byte solana-keygen array")]
    MalformedKeypair,
    #[error("the cluster clock sysvar is absent or malformed")]
    MalformedClock,
    #[error("the account {0} does not exist on this cluster")]
    MissingAccount(String),
    #[error("the transaction was still unconfirmed after {0:?}")]
    ConfirmationTimedOut(Duration),
    #[error("the cluster rejected the transaction")]
    Rejected,
    #[error("the transaction the cluster was expected to reject succeeded")]
    UnexpectedSuccess,
    #[error("the cluster clock did not reach {0} within {1:?}")]
    ClockTimedOut(i64, Duration),
    #[error("an RPC quorum of {0} cannot be formed from {1} node(s)")]
    QuorumUnavailable(usize, usize),
    #[error("the cluster finalized no slot within {0:?}")]
    NoFinalizedSlot(Duration),
}

/// An Ed25519 keypair loaded from a `solana-keygen` file.
pub struct KeypairV1 {
    signing: SigningKey,
    public: SolanaPubkey,
}

impl core::fmt::Debug for KeypairV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeypairV1")
            .field("public", &self.public)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl KeypairV1 {
    /// Read the JSON byte array `solana-keygen new --outfile` writes: 64
    /// numbers, the 32-byte seed followed by the 32-byte public key. The public
    /// half is recomputed from the seed and the file's copy must agree, so a
    /// truncated or edited file is refused instead of producing a key whose
    /// signatures nothing accepts.
    pub fn load_solana_keygen_json(path: &Path) -> Result<Self, ClusterError> {
        let text = std::fs::read_to_string(path).map_err(|_| ClusterError::MalformedKeypair)?;
        let values: Vec<i64> =
            serde_json::from_str(&text).map_err(|_| ClusterError::MalformedKeypair)?;
        if values.len() != 64 {
            return Err(ClusterError::MalformedKeypair);
        }
        let mut bytes = Zeroizing::new([0u8; 64]);
        for (slot, value) in bytes.iter_mut().zip(&values) {
            *slot = u8::try_from(*value).map_err(|_| ClusterError::MalformedKeypair)?;
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        let signing = SigningKey::from_bytes(&seed);
        let public = SolanaPubkey(signing.verifying_key().to_bytes());
        if public.0 != bytes[32..] {
            return Err(ClusterError::MalformedKeypair);
        }
        Ok(Self { signing, public })
    }

    pub fn public(&self) -> SolanaPubkey {
        self.public
    }

    fn sign(&self, message: &[u8]) -> SolanaSignature {
        SolanaSignature(self.signing.sign(message).to_bytes())
    }
}

/// A connection to one cluster, pinned to the genesis hash it reported when the
/// connection was opened.
pub struct ClusterSessionV1 {
    rpc: HttpSolanaRpc,
    /// Kept so a refusal can be explained through the same endpoint.
    url: String,
    genesis: SolanaHash,
    commitment: Commitment,
}

impl ClusterSessionV1 {
    /// Open the connection and read the genesis hash. A caller that already
    /// knows which cluster it intends to talk to compares the two and refuses a
    /// mismatch; nothing here can do that for it.
    pub fn connect(url: &str, max_signed_transaction_bytes: usize) -> Result<Self, ClusterError> {
        let rpc = HttpSolanaRpc::new(url, max_signed_transaction_bytes)?;
        let genesis = rpc.genesis_hash()?;
        Ok(Self {
            rpc,
            url: url.to_string(),
            genesis,
            commitment: Commitment::Confirmed,
        })
    }

    pub fn genesis(&self) -> SolanaHash {
        self.genesis
    }

    pub fn rpc(&self) -> &HttpSolanaRpc {
        &self.rpc
    }

    pub fn with_commitment(mut self, commitment: Commitment) -> Self {
        self.commitment = commitment;
        self
    }

    /// Sign and submit. Every signer the message requires must be present among
    /// `fee_payer` and `cosigners`, or this refuses before touching the network.
    pub fn submit(
        &self,
        instructions: &[SolanaInstruction],
        fee_payer: &KeypairV1,
        cosigners: &[&KeypairV1],
    ) -> Result<SolanaSignature, ClusterError> {
        let (blockhash, _last_valid) = self.rpc.get_latest_blockhash_with_validity()?;
        let plan = build_legacy_message(fee_payer.public, blockhash, instructions)?;
        let mut signatures = Vec::with_capacity(plan.signer_keys.len());
        for signer in &plan.signer_keys {
            let keypair = if *signer == fee_payer.public {
                fee_payer
            } else {
                *cosigners
                    .iter()
                    .find(|candidate| candidate.public == *signer)
                    .ok_or(ClusterError::MissingSigner)?
            };
            signatures.push((*signer, keypair.sign(&plan.message)));
        }
        let raw = assemble_signed_transaction(&plan, &signatures)?;
        match self.rpc.send_transaction(&raw) {
            Ok(signature) => Ok(signature),
            Err(RpcError::Remote) => Err(self.explain_refusal(&raw)),
            Err(other) => Err(other.into()),
        }
    }

    /// Ask the node to simulate exactly the bytes it just refused, and turn its
    /// answer into an error that names the cause. Failing to obtain an
    /// explanation is itself reported rather than swallowed: the transaction was
    /// still refused, and that fact must not be lost because the second call
    /// also failed.
    fn explain_refusal(&self, raw: &[u8]) -> ClusterError {
        let encoded = BASE64.encode(raw);
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "simulateTransaction",
            "params": [encoded, {"encoding": "base64", "sigVerify": false, "commitment": "processed"}],
        });
        let answer = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .ok()
            .and_then(|client| client.post(&self.url).json(&body).send().ok())
            .and_then(|response| response.text().ok());
        let Some(text) = answer else {
            return ClusterError::Refused {
                err: "refused, and the node did not answer a simulation of the same bytes"
                    .to_string(),
                logs: String::new(),
            };
        };
        let parsed: Option<Value> = serde_json::from_str(&text).ok();
        let (err, logs) = match parsed.as_ref().and_then(|value| value.get("result")) {
            Some(result) => (
                result
                    .get("err")
                    .map(|err| err.to_string())
                    .unwrap_or_else(|| "none reported by the simulation".to_string()),
                result
                    .get("logs")
                    .and_then(Value::as_array)
                    .map(|lines| {
                        lines
                            .iter()
                            .filter_map(Value::as_str)
                            .map(|line| format!("  {line}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default(),
            ),
            // No `result` at all: report the node's raw answer, bounded, rather
            // than an empty explanation.
            None => (text.chars().take(2000).collect::<String>(), String::new()),
        };
        ClusterError::Refused { err, logs }
    }

    /// Wait for a status. A status whose `failed` flag is set is an error: the
    /// transaction landed and the program refused it, which is not success.
    pub fn confirm(
        &self,
        signature: SolanaSignature,
        timeout: Duration,
    ) -> Result<SolanaSignatureStatus, ClusterError> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.rpc.get_signature_status(signature)? {
                if status.failed {
                    return Err(ClusterError::Rejected);
                }
                return Ok(status);
            }
            if started.elapsed() >= timeout {
                return Err(ClusterError::ConfirmationTimedOut(timeout));
            }
            sleep(Duration::from_millis(400));
        }
    }

    /// Submit and confirm in one step.
    pub fn execute(
        &self,
        instructions: &[SolanaInstruction],
        fee_payer: &KeypairV1,
        cosigners: &[&KeypairV1],
        timeout: Duration,
    ) -> Result<SolanaSignature, ClusterError> {
        let signature = self.submit(instructions, fee_payer, cosigners)?;
        self.confirm(signature, timeout)?;
        Ok(signature)
    }

    /// Assert that the cluster refuses something. Preflight may reject at
    /// submission and the runtime may reject after inclusion, so both count as
    /// the expected refusal and only success is an error.
    pub fn expect_refusal(
        &self,
        instructions: &[SolanaInstruction],
        fee_payer: &KeypairV1,
        cosigners: &[&KeypairV1],
        timeout: Duration,
    ) -> Result<(), ClusterError> {
        match self.submit(instructions, fee_payer, cosigners) {
            Err(ClusterError::Refused { .. }) | Err(ClusterError::Rpc(_)) => Ok(()),
            Err(other) => Err(other),
            Ok(signature) => match self.confirm(signature, timeout) {
                Err(ClusterError::Rejected) => Ok(()),
                Err(other) => Err(other),
                Ok(_) => Err(ClusterError::UnexpectedSuccess),
            },
        }
    }

    pub fn account(&self, key: SolanaPubkey) -> Result<Option<SolanaAccountSnapshot>, ClusterError> {
        Ok(self.rpc.get_account(key, self.commitment)?)
    }

    /// Account data, refusing an absent account rather than returning an empty
    /// buffer that a decoder would then misread.
    pub fn account_data(&self, key: SolanaPubkey) -> Result<Vec<u8>, ClusterError> {
        self.account(key)?
            .map(|snapshot| snapshot.data)
            .ok_or_else(|| ClusterError::MissingAccount(key.to_base58()))
    }

    pub fn lamports(&self, key: SolanaPubkey) -> Result<u64, ClusterError> {
        Ok(self
            .account(key)?
            .map(|snapshot| snapshot.lamports)
            .unwrap_or(0))
    }

    /// A quorum view over this cluster's nodes.
    ///
    /// The profile declares how many nodes a leg reads through and how many must
    /// agree; reading through one node while the profile says otherwise would
    /// make the declared policy decorative. This harness has one validator, so
    /// the honest configuration is one node with a quorum of one -- the machinery
    /// is exercised, the redundancy is not, and a real deployment lists several.
    pub fn quorum_pool(
        &self,
        node_count: usize,
        quorum: usize,
    ) -> Result<SolanaRpcPool<HttpSolanaRpc>, ClusterError> {
        if quorum == 0 || quorum > node_count {
            return Err(ClusterError::QuorumUnavailable(quorum, node_count));
        }
        let shared = Arc::new(self.rpc.clone());
        let nodes = (0..node_count).map(|_| Arc::clone(&shared)).collect();
        SolanaRpcPool::new(nodes, quorum)
            .map_err(|_| ClusterError::QuorumUnavailable(quorum, node_count))
    }

    /// Block until the cluster has finalized at least one slot.
    ///
    /// Attestation reads at `Commitment::Finalized`, and a validator that has
    /// just started has finalized nothing: asking too early is not a missing
    /// program, it is an early question.
    pub fn wait_for_finalized_slot(&self, timeout: Duration) -> Result<u64, ClusterError> {
        let started = Instant::now();
        loop {
            if let Ok(slot) = self.rpc.get_slot(Commitment::Finalized) {
                if slot > 0 {
                    return Ok(slot);
                }
            }
            if started.elapsed() >= timeout {
                return Err(ClusterError::NoFinalizedSlot(timeout));
            }
            sleep(Duration::from_millis(500));
        }
    }

    /// The cluster clock, as the runtime would hand it to a program.
    pub fn cluster_unix_time(&self) -> Result<i64, ClusterError> {
        let key =
            SolanaPubkey::from_base58(CLOCK_SYSVAR_BASE58).map_err(|_| ClusterError::MalformedClock)?;
        let data = self
            .account(key)?
            .map(|snapshot| snapshot.data)
            .ok_or(ClusterError::MalformedClock)?;
        if data.len() < CLOCK_LEN {
            return Err(ClusterError::MalformedClock);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[CLOCK_UNIX_TIMESTAMP_OFFSET..CLOCK_UNIX_TIMESTAMP_OFFSET + 8]);
        Ok(i64::from_le_bytes(bytes))
    }

    /// Block until the cluster clock passes `deadline`. The escrow's refund is
    /// gated on this exact value, so waiting on anything else would be waiting
    /// on the wrong clock.
    pub fn wait_for_cluster_time(
        &self,
        deadline: i64,
        timeout: Duration,
    ) -> Result<i64, ClusterError> {
        let started = Instant::now();
        loop {
            let now = self.cluster_unix_time()?;
            if now >= deadline {
                return Ok(now);
            }
            if started.elapsed() >= timeout {
                return Err(ClusterError::ClockTimedOut(deadline, timeout));
            }
            sleep(Duration::from_millis(500));
        }
    }
}
