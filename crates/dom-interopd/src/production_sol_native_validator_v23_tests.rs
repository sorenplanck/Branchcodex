//! Owned local `solana-test-validator`, never a public cluster. The binary and
//! the escrow program are explicit dependencies: absence is an error, not skip.
//! RPC canonicality is a trusted local boundary, not a consensus audit.
use solana_rpc::{HttpSolanaRpc, SolanaRpc};
use solana_rpc_pool::SolanaRpcPool;
use solana_types::{Commitment, SolanaPubkey, BPF_LOADER_UPGRADEABLE_ID};
use std::{
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(180);
const FINALITY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RPC_RESPONSE: usize = 4 * 1024 * 1024;

pub(crate) struct SolanaTestValidatorOwnerV23 {
    child: Option<Child>,
    address: SocketAddr,
    genesis_hash: [u8; 32],
    program_id: SolanaPubkey,
    program_data_hash: [u8; 32],
    /// Removed only after Drop killed and reaped the whole process group.
    _ledger: tempfile::TempDir,
}

impl SolanaTestValidatorOwnerV23 {
    /// Do not call until the implementation-writing phase is complete: this
    /// spawns the real validator from `DOM_SOL_TEST_VALIDATOR_V23` and deploys
    /// `DOM_SOL_ESCROW_PROGRAM_V23` immutably (upgrade authority `none`).
    pub(crate) fn from_environment(program_id: SolanaPubkey) -> Result<Self> {
        let validator = explicit_dependency("DOM_SOL_TEST_VALIDATOR_V23", true)?;
        let program = explicit_dependency("DOM_SOL_ESCROW_PROGRAM_V23", false)?;
        if program_id.is_zero() {
            return Err("escrow program id must be nonzero".into());
        }
        // Private TMPDIR supplied by the runner; never the shared /tmp root.
        let ledger = tempfile::Builder::new()
            .prefix("sol-ledger-")
            .tempdir()?;
        std::fs::set_permissions(ledger.path(), std::fs::Permissions::from_mode(0o700))?;
        let rpc = reserve_loopback_port()?;
        let faucet = reserve_loopback_port()?;
        // The validator's websocket listens on rpc+1. A taken port is a
        // failure, never a silent retry on a different endpoint.
        drop(TcpListener::bind(SocketAddr::from((
            [127, 0, 0, 1],
            rpc.port().checked_add(1).ok_or("websocket port overflow")?,
        )))?);
        if faucet.port() == rpc.port() + 1 {
            return Err("faucet port collides with the validator websocket".into());
        }
        let log = File::options()
            .write(true)
            .create_new(true)
            .open(ledger.path().join("validator.log"))?;
        std::fs::set_permissions(
            ledger.path().join("validator.log"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        let mut command = Command::new(&validator);
        {
            use std::os::unix::process::CommandExt;
            command
                .env_clear()
                .env("HOME", ledger.path())
                .env("PATH", "/usr/bin:/bin")
                .env("RUST_BACKTRACE", "0")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(log))
                .arg("--reset")
                .arg("--ledger")
                .arg(ledger.path().join("ledger"))
                .arg("--bind-address")
                .arg("127.0.0.1")
                .arg("--rpc-port")
                .arg(rpc.port().to_string())
                .arg("--faucet-port")
                .arg(faucet.port().to_string())
                .arg("--upgradeable-program")
                .arg(program_id.to_base58())
                .arg(&program)
                .arg("none")
                .arg("--quiet");
        }
        let child = command
            .spawn()
            .map_err(|_| "solana-test-validator could not start")?;
        let mut owner = Self {
            child: Some(child),
            address: rpc,
            genesis_hash: [0; 32],
            program_id,
            program_data_hash: [0; 32],
            _ledger: ledger,
        };
        owner.genesis_hash = owner.wait_genesis()?;
        owner.program_data_hash = owner.wait_immutable_program()?;
        eprintln!(
            "native SOL validator: genesis and immutable escrow program attested at {}",
            owner.endpoint()
        );
        Ok(owner)
    }

    pub(crate) fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }
    pub(crate) fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }
    pub(crate) fn program_id(&self) -> SolanaPubkey {
        self.program_id
    }
    pub(crate) fn program_data_hash(&self) -> [u8; 32] {
        self.program_data_hash
    }

    pub(crate) fn rpc(&self) -> Result<HttpSolanaRpc> {
        Ok(HttpSolanaRpc::new(self.endpoint(), 1232).map_err(|_| "validator RPC client")?)
    }

    pub(crate) fn pool(&self) -> Result<SolanaRpcPool<HttpSolanaRpc>> {
        Ok(SolanaRpcPool::new(vec![Arc::new(self.rpc()?)], 1)
            .map_err(|_| "validator RPC pool")?)
    }

    /// The scenario checks this instead of pumping a ledger: the validator
    /// produces its own slots, and an exited validator is a hard failure.
    pub(crate) fn require_alive(&mut self) -> Result<()> {
        let child = self.child.as_mut().ok_or("validator already reaped")?;
        if child.try_wait()?.is_some() {
            return Err("solana-test-validator exited during the scenario".into());
        }
        Ok(())
    }

    /// Local faucet transfer, then wait for the finalized balance. The target
    /// is absolute, so a concurrent credit cannot satisfy a missing airdrop.
    pub(crate) fn airdrop(&mut self, account: SolanaPubkey, lamports: u64) -> Result<()> {
        if account.is_zero() || lamports == 0 {
            return Err("airdrop account and amount must be nonzero".into());
        }
        let before = self.balance(account)?;
        let target = before
            .checked_add(lamports)
            .ok_or("airdrop balance overflow")?;
        let signature = json_rpc(
            self.address,
            "requestAirdrop",
            serde_json::json!([account.to_base58(), lamports, {"commitment": "finalized"}]),
        )?;
        signature
            .as_str()
            .ok_or("airdrop returned no signature")?;
        let start = Instant::now();
        while self.balance(account)? < target {
            self.require_alive()?;
            if start.elapsed() >= FINALITY_TIMEOUT {
                return Err("airdrop did not reach finalized balance".into());
            }
            thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    pub(crate) fn balance(&self, account: SolanaPubkey) -> Result<u64> {
        let value = json_rpc(
            self.address,
            "getBalance",
            serde_json::json!([account.to_base58(), {"commitment": "finalized"}]),
        )?;
        value
            .get("value")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "finalized balance response".into())
    }

    /// Finalized slot and blockhash of the nearest produced block at or below
    /// the finalized tip. Skipped slots have no block; the walk is bounded.
    pub(crate) fn finalized_anchor_v25(&self) -> Result<(u64, [u8; 32])> {
        let block = self.finalized_block_v25()?;
        Ok((block.0, block.1))
    }

    /// (slot, blockhash, previous blockhash, block time) of that same block.
    pub(crate) fn finalized_block_v25(&self) -> Result<(u64, [u8; 32], [u8; 32], u64)> {
        let tip = json_rpc(
            self.address,
            "getSlot",
            serde_json::json!([{"commitment": "finalized"}]),
        )?
        .as_u64()
        .ok_or("finalized slot response")?;
        let mut slot = tip;
        loop {
            if slot == 0 || tip - slot > 64 {
                return Err("no produced finalized Solana block near the tip".into());
            }
            let block = json_rpc(
                self.address,
                "getBlock",
                serde_json::json!([slot, {
                    "commitment": "finalized", "transactionDetails": "none",
                    "rewards": false, "maxSupportedTransactionVersion": 0
                }]),
            );
            match block {
                Ok(block) if !block.is_null() => {
                    let hash = |field: &str| -> Result<[u8; 32]> {
                        let text = block
                            .get(field)
                            .and_then(serde_json::Value::as_str)
                            .ok_or("Solana block hash field absent")?;
                        Ok(solana_types::SolanaHash::from_base58(text)
                            .map_err(|_| "Solana block hash encoding")?
                            .0)
                    };
                    let time = block
                        .get("blockTime")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or("Solana block time absent")?;
                    return Ok((slot, hash("blockhash")?, hash("previousBlockhash")?, time));
                }
                _ => slot -= 1,
            }
        }
    }

    fn wait_genesis(&mut self) -> Result<[u8; 32]> {
        let rpc = self.rpc()?;
        let start = Instant::now();
        loop {
            self.require_alive()?;
            if let Ok(hash) = rpc.genesis_hash() {
                if hash.0 != [0; 32] {
                    return Ok(hash.0);
                }
            }
            if start.elapsed() >= STARTUP_TIMEOUT {
                return Err("solana-test-validator never served its genesis hash".into());
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    /// Read the finalized ProgramData account and hash it exactly as the
    /// production attestation does, then run that attestation itself.
    fn wait_immutable_program(&mut self) -> Result<[u8; 32]> {
        use solana_program_attestation::{
            attest_immutable_program, code_hash, PROGRAM_DATA_METADATA_LEN, PROGRAM_METADATA_LEN,
        };
        let rpc = self.rpc()?;
        let start = Instant::now();
        let program = loop {
            self.require_alive()?;
            if let Ok(Some(account)) = rpc.get_account(self.program_id, Commitment::Finalized) {
                break account;
            }
            if start.elapsed() >= STARTUP_TIMEOUT {
                return Err("escrow program never finalized on the validator".into());
            }
            thread::sleep(Duration::from_millis(250));
        };
        if !program.executable
            || program.owner != BPF_LOADER_UPGRADEABLE_ID
            || program.data.len() < PROGRAM_METADATA_LEN
        {
            return Err("escrow program is not an upgradeable-loader program".into());
        }
        let address = SolanaPubkey(program.data[4..36].try_into()?);
        let data = rpc
            .get_account(address, Commitment::Finalized)
            .map_err(|_| "ProgramData account unavailable")?
            .ok_or("ProgramData account absent")?;
        if data.data.len() <= PROGRAM_DATA_METADATA_LEN {
            return Err("ProgramData account has no code".into());
        }
        let hash = code_hash(&data.data[PROGRAM_DATA_METADATA_LEN..]);
        // The refusal carries its variant and the loader metadata it judged,
        // so a validator-version layout difference is diagnosable from logs.
        attest_immutable_program(&self.pool()?, self.program_id, hash).map_err(|error| {
            format!(
                "deployed escrow program fails production attestation: {error:?}; \
                 program[0..36]={} programdata[0..{}]={}",
                hex::encode(&program.data[..PROGRAM_METADATA_LEN.min(program.data.len())]),
                PROGRAM_DATA_METADATA_LEN,
                hex::encode(&data.data[..PROGRAM_DATA_METADATA_LEN]),
            )
        })?;
        Ok(hash)
    }
}

impl Drop for SolanaTestValidatorOwnerV23 {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(None) = child.try_wait() {
            // Only this owner's own process group; never a name or pidfile.
            if let Some(pid) = i32::try_from(child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = child.kill();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

/// Minimal HTTP/1.1 JSON-RPC over numeric loopback only. Used for faucet,
/// balance and block-time reads the production `SolanaRpc` trait lacks.
pub(crate) fn json_rpc(
    address: SocketAddr,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("validator JSON-RPC requires a numeric loopback endpoint".into());
    }
    let body = serde_json::to_vec(
        &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
    )?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;
    let mut response = Vec::new();
    Read::by_ref(&mut stream)
        .take(MAX_RPC_RESPONSE as u64 + 1)
        .read_to_end(&mut response)?;
    if response.len() > MAX_RPC_RESPONSE {
        return Err("validator JSON-RPC response bound".into());
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("validator HTTP header terminator")?;
    let head = std::str::from_utf8(&response[..split])?.to_ascii_lowercase();
    if !head.starts_with("http/1.1 200") && !head.starts_with("http/1.0 200") {
        return Err("validator HTTP status refused".into());
    }
    let raw = &response[split + 4..];
    let payload = if head.contains("transfer-encoding: chunked") {
        dechunk(raw)?
    } else {
        raw.to_vec()
    };
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    if value.get("error").is_some() {
        return Err("validator JSON-RPC refused the request".into());
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| "validator JSON-RPC result absent".into())
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line = raw
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("chunk size terminator")?;
        let size_text = std::str::from_utf8(&raw[..line])?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)?;
        raw = &raw[line + 2..];
        if size == 0 {
            return Ok(output);
        }
        if raw.len() < size + 2 || output.len() + size > MAX_RPC_RESPONSE {
            return Err("chunked validator response truncated or oversized".into());
        }
        output.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn reserve_loopback_port() -> Result<SocketAddr> {
    // Released immediately before the validator binds; a race is a failure.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

/// Absolute, canonical (no symlink), owner-controlled regular file. The
/// validator must be executable; the `.so` is data and needs no X bit.
fn explicit_dependency(name: &str, executable: bool) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(name).ok_or_else(|| format!("{name} is required"))?,
    );
    let meta = std::fs::symlink_metadata(&path)?;
    let euid = rustix::process::geteuid().as_raw();
    if !path.is_absolute()
        || std::fs::canonicalize(&path)? != path
        || !meta.is_file()
        || (meta.uid() != euid && meta.uid() != 0)
        || meta.mode() & 0o022 != 0
        || (executable && meta.mode() & 0o111 == 0)
        || meta.len() == 0
    {
        return Err(format!("{name} must be a canonical owner-controlled file").into());
    }
    require_trusted_ancestors(&path)?;
    Ok(path)
}

fn require_trusted_ancestors(path: &Path) -> Result<()> {
    let euid = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors().skip(1) {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if !meta.is_dir() || (meta.uid() != euid && meta.uid() != 0) || meta.mode() & 0o022 != 0 {
            return Err("explicit dependency ancestor is writable by another owner".into());
        }
    }
    Ok(())
}

#[test]
fn chunked_validator_responses_are_bounded_and_exact_v25() -> Result<()> {
    assert_eq!(dechunk(b"4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n")?, b"{\"a\":1}");
    assert!(dechunk(b"9\r\nshort\r\n").is_err());
    assert!(dechunk(b"zz\r\n").is_err());
    Ok(())
}
