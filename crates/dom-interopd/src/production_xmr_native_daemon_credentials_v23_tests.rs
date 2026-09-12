//! Independent credential owners for two real XMR-only daemon processes.
//! These are process/database credentials, never T/U or recovered share bytes.
use rand::RngCore;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeXmrDaemonCredentialsV23 {
    stdin: [Zeroizing<Vec<u8>>; 2],
    pub(crate) bearer: [Zeroizing<Vec<u8>>; 2],
    pub(crate) wallet_passphrases: [Zeroizing<Vec<u8>>; 2],
    pub(crate) sidecar_auth: [[Zeroizing<[u8; 32]>; 2]; 2],
    pub(crate) hsm_auth: [[[Zeroizing<[u8; 32]>; 2]; 2]; 2],
}

impl NativeXmrDaemonCredentialsV23 {
    /// Return four independent master keys for first enrollment. Their only
    /// second representation is the corresponding actor's private V4 input.
    /// No database is inspected and no enrolled secret is exported.
    pub(crate) fn create() -> Result<(Self, [[Zeroizing<[u8; 32]>; 2]; 2])> {
        let mut generated = Vec::<Zeroizing<[u8; 32]>>::new();
        let mut key = || loop {
            let mut value = Zeroizing::new([0; 32]);
            rand::thread_rng().fill_bytes(value.as_mut());
            if *value != [0; 32] && generated.iter().all(|old| **old != *value) {
                generated.push(Zeroizing::new(*value));
                break value;
            }
        };
        let master_keys = std::array::from_fn(|_| std::array::from_fn(|_| key()));
        let sidecar_auth = std::array::from_fn(|_| std::array::from_fn(|_| key()));
        let hsm_auth =
            std::array::from_fn(|_| std::array::from_fn(|_| std::array::from_fn(|_| key())));
        let bearer = std::array::from_fn(|_| encoded(&key()));
        let wallet_passphrases = std::array::from_fn(|_| encoded(&key()));
        let mut stdin = std::array::from_fn(|_| Zeroizing::new(Vec::new()));
        for actor in 0..2 {
            let out = &mut stdin[actor];
            out.extend_from_slice(b"DOM-INTEROPD-SECRETS-V4");
            line(out, &bearer[actor]);
            // Exact Relay credentials of the genuine two-party ceremony.
            line(out, &encoded(&[21 + 2 * actor as u8; 32]));
            line(out, &encoded(&[22 + 2 * actor as u8; 32]));
            line(out, b"test-passphrase-v13");
            line(out, &wallet_passphrases[actor]);
            line(out, &encoded(&key()));
            line(out, &encoded(&key()));
            for position in 0..2 {
                line(
                    out,
                    if position == 0 {
                        b"upstream_family=XMR"
                    } else {
                        b"downstream_family=XMR"
                    },
                );
                line(out, &encoded(&master_keys[position][actor]));
                line(out, &encoded(&sidecar_auth[position][actor]));
            }
            for position in 0..2 {
                line(
                    out,
                    if position == 0 {
                        b"upstream_f6_hsm_credentials=2"
                    } else {
                        b"downstream_f6_hsm_credentials=2"
                    },
                );
                for credential in &hsm_auth[position][actor] {
                    line(out, &encoded(credential));
                }
            }
            // The same parser used by `run`, including all pairwise-reuse
            // checks, authenticates the stream shape before it leaves owner.
            crate::production_node::ProductionSecretsV4::read(out.as_slice())?
                .into_parts([crate::production_config::ProductionChainFamilyV11::Xmr; 2])?;
        }
        drop(key);
        drop(generated);
        Ok((
            Self {
                stdin,
                bearer,
                wallet_passphrases,
                sidecar_auth,
                hsm_auth,
            },
            master_keys,
        ))
    }

    /// Explicit credential copy for a create/reopen attempt; retained bytes
    /// remain in zeroizing memory owned by the scenario, never written to disk.
    pub(crate) fn stdin_for(&self, actor: usize) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            self.stdin
                .get(actor)
                .ok_or("native credential actor")?
                .to_vec(),
        ))
    }
}

fn encoded(bytes: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let alphabet = b"0123456789abcdef";
    let mut output = Zeroizing::new(Vec::with_capacity(64));
    for byte in bytes {
        output.push(alphabet[usize::from(byte >> 4)]);
        output.push(alphabet[usize::from(byte & 15)]);
    }
    output
}

fn line(output: &mut Vec<u8>, value: &[u8]) {
    output.push(b'\n');
    output.extend_from_slice(value);
}
