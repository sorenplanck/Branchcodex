//! Noise-authenticated TCP bridge for one isolated `arbiter_party` process.
//!
//! Server mode keeps the private party state on its host. Client mode exposes
//! the same newline JSON interface used by the regtest coordinator, while every
//! line crosses a peer-pinned, chain- and session-bound Noise connection.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use dom_core::NETWORK_MAGIC_REGTEST;
use dom_wire::handshake::{derive_static_pubkey, generate_static_keypair};
use dxp1_clsag_lab::swap_transport::SwapNoiseChannel;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8] = b"DXA1/noise-static/v1\0";
const KEY_BYTES: usize = KEY_MAGIC.len() + 32 + 32;

fn transport_session(
    settlement_id: [u8; 32],
    context_hash: [u8; 32],
    chain_id: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DXA1/participant-transport/v1");
    hash.update(settlement_id);
    hash.update(context_hash);
    hash.update(chain_id);
    hash.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err("wrong hex length".into());
    }
    let mut result = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("invalid hex"),
        };
        result[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(result)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| io::Error::other("key path has no parent"))?,
    )?
    .sync_all()
}

fn load_or_create_key(path: &Path) -> io::Result<(File, Zeroizing<[u8; 32]>, [u8; 32])> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.try_lock()
                .map_err(|_| io::Error::other("Noise identity is locked"))?;
            let (secret, public) = generate_static_keypair();
            let secret = Zeroizing::new(secret);
            let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_BYTES));
            bytes.extend(KEY_MAGIC);
            bytes.extend_from_slice(&*secret);
            let checksum = Sha256::digest(&*bytes);
            bytes.extend(checksum);
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_parent(path)?;
            Ok((file, secret, public))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(io::Error::other("unsafe Noise identity file"));
            }
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            file.try_lock()
                .map_err(|_| io::Error::other("Noise identity is locked"))?;
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file)
                .take((KEY_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            let secret_end = KEY_MAGIC.len() + 32;
            if bytes.len() != KEY_BYTES
                || &bytes[..KEY_MAGIC.len()] != KEY_MAGIC
                || bytes[secret_end..] != Sha256::digest(&bytes[..secret_end])[..]
            {
                return Err(io::Error::other("corrupt Noise identity file"));
            }
            let secret = Zeroizing::new(
                bytes[KEY_MAGIC.len()..secret_end]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid Noise private key"))?,
            );
            let public = derive_static_pubkey(&secret);
            Ok((file, secret, public))
        }
        Err(error) => Err(error),
    }
}

struct ManagedParty(Child);

impl Drop for ManagedParty {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn serve_connection(
    channel: &mut SwapNoiseChannel,
    party_binary: &str,
    party_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut party = ManagedParty(
        Command::new(party_binary)
            .args(party_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let mut party_input = party.0.stdin.take().ok_or("party stdin missing")?;
    let mut party_output = BufReader::new(party.0.stdout.take().ok_or("party stdout missing")?);
    let mut ready = String::new();
    if party_output.read_line(&mut ready)? == 0 {
        return Err("party exited before readiness".into());
    }
    channel.send(ready.trim_end().as_bytes()).await?;

    loop {
        let request = match channel.receive().await {
            Ok(request) => request,
            Err(_) => return Ok(()),
        };
        if request.contains(&b'\n') || request.contains(&b'\r') {
            return Err("embedded newline in party request".into());
        }
        party_input.write_all(&request)?;
        party_input.write_all(b"\n")?;
        party_input.flush()?;
        let mut response = String::new();
        if party_output.read_line(&mut response)? == 0 {
            return Err("party exited before response".into());
        }
        channel.send(response.trim_end().as_bytes()).await?;
    }
}

async fn server(args: Vec<String>, persistent: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 10 {
        return Err("server requires party, role, settlement, context, chain, state, listen, Noise state, expected peer and session".into());
    }
    let party_binary = &args[0];
    let chain_id = fixed_hex::<32>(&args[4])?;
    let listen = &args[6];
    let noise_path = PathBuf::from(&args[7]);
    let expected_peer = fixed_hex::<32>(&args[8])?;
    let session = fixed_hex::<32>(&args[9])?;
    let (_key_file, noise_secret, _) = load_or_create_key(&noise_path)?;

    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("{}", listener.local_addr()?);
    io::stdout().flush()?;
    loop {
        let accepted = SwapNoiseChannel::accept(
            &listener,
            &noise_secret,
            expected_peer,
            NETWORK_MAGIC_REGTEST,
            chain_id,
            session,
        )
        .await;
        let mut channel = match accepted {
            Ok(channel) => channel,
            Err(error) if persistent => {
                eprintln!("rejected participant connection: {error}");
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        serve_connection(&mut channel, party_binary, &args[1..6]).await?;
        if !persistent {
            break;
        }
    }
    Ok(())
}

async fn client(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 6 {
        return Err(
            "client requires address, Noise state, expected peer, chain and session".into(),
        );
    }
    let address = args[0].parse()?;
    let noise_path = PathBuf::from(&args[1]);
    let expected_peer = fixed_hex::<32>(&args[2])?;
    let chain_id = fixed_hex::<32>(&args[3])?;
    let session = fixed_hex::<32>(&args[4])?;
    let network_magic: u32 = args[5].parse()?;
    let (_key_file, noise_secret, _) = load_or_create_key(&noise_path)?;
    let mut channel = SwapNoiseChannel::connect(
        address,
        &noise_secret,
        expected_peer,
        network_magic,
        chain_id,
        session,
    )
    .await?;

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&channel.receive().await?)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        channel.send(line.as_bytes()).await?;
        stdout.write_all(&channel.receive().await?)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("missing mode")?;
    let args: Vec<_> = args.collect();
    match mode.as_str() {
        "regtest-bootstrap" => {
            if args.len() != 2 {
                return Err("regtest-bootstrap requires settlement and context hashes".into());
            }
            let settlement_id = fixed_hex::<32>(&args[0])?;
            let context_hash = fixed_hex::<32>(&args[1])?;
            let genesis = dom_core::Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST);
            let chain_id =
                *dom_consensus::derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis).as_bytes();
            println!(
                "{}",
                serde_json::json!({
                    "settlement_id":hex(&settlement_id),
                    "context_hash":hex(&context_hash),
                    "chain_id":hex(&chain_id),
                    "session":hex(&transport_session(settlement_id, context_hash, chain_id)),
                    "network_magic":NETWORK_MAGIC_REGTEST,
                })
            );
            Ok(())
        }
        "identity" => {
            if args.len() != 1 {
                return Err("identity requires one state path".into());
            }
            let (_file, _secret, public) = load_or_create_key(Path::new(&args[0]))?;
            println!("{}", hex(&public));
            Ok(())
        }
        "server" => server(args, false).await,
        "server-persistent" => server(args, true).await,
        "client" => client(args).await,
        _ => Err(
            "mode must be regtest-bootstrap, identity, server, server-persistent or client".into(),
        ),
    }
}
