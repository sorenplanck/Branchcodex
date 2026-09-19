//! Independent credential owners for two real DOM↔SOL daemon processes.
//! Process/database credentials and scoped Ed25519 seeds, never the route secret.
use rand::RngCore;
use solana_types::SolanaPubkey;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The fixture-generated Solana accounts. Only these have a seed.
pub(crate) struct NativeSolLegKeysV23 {
    funder_seeds: [Zeroizing<[u8; 32]>; 2],
    /// V25: the escrow pays a real recipient account, bound to the
    /// beneficiary participant by a dual-signed account proof.
    recipient_seeds: [Zeroizing<[u8; 32]>; 2],
}

impl NativeSolLegKeysV23 {
    /// One distinct funder and one distinct recipient account per position:
    /// V4 refuses any reused key.
    pub(crate) fn generate() -> Result<Self> {
        let mut seeds: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(4);
        while seeds.len() < 4 {
            let candidate = seed();
            if seeds.iter().all(|old| **old != *candidate) {
                seeds.push(candidate);
            }
        }
        let mut seeds = seeds.into_iter();
        let mut next = || seeds.next().ok_or("SOL leg seed count");
        Ok(Self {
            funder_seeds: [next()?, next()?],
            recipient_seeds: [next()?, next()?],
        })
    }

    pub(crate) fn funder(&self, position: usize) -> Result<SolanaPubkey> {
        Ok(public_key(
            self.funder_seeds.get(position).ok_or("funder position")?,
        ))
    }

    pub(crate) fn recipient(&self, position: usize) -> Result<SolanaPubkey> {
        Ok(public_key(
            self.recipient_seeds
                .get(position)
                .ok_or("recipient position")?,
        ))
    }

    /// A seed exists only for an account this fixture generated on that
    /// position. A participant identity is a Blake2b digest with no Ed25519
    /// seed, so it is refused here rather than papered over.
    pub(crate) fn seed_for(
        &self,
        position: usize,
        account: SolanaPubkey,
    ) -> Result<Zeroizing<[u8; 32]>> {
        for seed in [
            self.funder_seeds.get(position).ok_or("seed position")?,
            self.recipient_seeds.get(position).ok_or("seed position")?,
        ] {
            if public_key(seed) == account {
                return Ok(Zeroizing::new(**seed));
            }
        }
        Err("no fixture Ed25519 seed derives this Solana account on this position".into())
    }
}

pub(crate) struct NativeSolDaemonCredentialsV23 {
    stdin: [Zeroizing<Vec<u8>>; 2],
    pub(crate) bearer: [Zeroizing<Vec<u8>>; 2],
    pub(crate) wallet_passphrases: [Zeroizing<Vec<u8>>; 2],
    pub(crate) hsm_auth: [[[Zeroizing<[u8; 32]>; 2]; 2]; 2],
    /// Position, then actor: the seed of that actor's LOCAL role account.
    local_seeds: [[Zeroizing<[u8; 32]>; 2]; 2],
}

impl NativeSolDaemonCredentialsV23 {
    /// `local_accounts[position][actor]` is the Ed25519 account of the role
    /// that actor holds on that position (funder or recipient).
    pub(crate) fn create(
        keys: &NativeSolLegKeysV23,
        local_accounts: [[SolanaPubkey; 2]; 2],
    ) -> Result<Self> {
        let mut seeds = Vec::with_capacity(4);
        for (position, accounts) in local_accounts.iter().enumerate() {
            if accounts[0] == accounts[1] {
                return Err("both actors cannot hold the same Solana role account".into());
            }
            for account in accounts {
                seeds.push(keys.seed_for(position, *account)?);
            }
        }
        let mut seeds = seeds.into_iter();
        let mut next = || seeds.next().ok_or("SOL seed count");
        let local_seeds = [[next()?, next()?], [next()?, next()?]];
        let mut generated: Vec<Zeroizing<[u8; 32]>> = local_seeds
            .iter()
            .flatten()
            .map(|seed| Zeroizing::new(**seed))
            .collect();
        for (index, seed) in generated.iter().enumerate() {
            if generated[..index].iter().any(|old| **old == **seed) {
                return Err("SOL local seeds must be pairwise distinct".into());
            }
        }
        let mut key = || loop {
            let mut value = Zeroizing::new([0; 32]);
            rand::thread_rng().fill_bytes(value.as_mut());
            if *value != [0; 32] && generated.iter().all(|old| **old != *value) {
                generated.push(Zeroizing::new(*value));
                break value;
            }
        };
        let peer_auth: [[Zeroizing<[u8; 32]>; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| key()));
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
                        b"upstream_family=SOL"
                    } else {
                        b"downstream_family=SOL"
                    },
                );
                // SOL: the local signing seed, then the independent peer field.
                line(out, &encoded(&local_seeds[position][actor]));
                line(out, &encoded(&peer_auth[position][actor]));
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
                .into_parts([crate::production_config::ProductionChainFamilyV11::Sol; 2])?;
        }
        drop(key);
        drop(generated);
        Ok(Self {
            stdin,
            bearer,
            wallet_passphrases,
            hsm_auth,
            local_seeds,
        })
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

    /// The seed of `actor`'s own local role account on `position`; it signs
    /// that account's V25 binding proof during planning.
    pub(crate) fn local_seed(
        &self,
        position: usize,
        actor: usize,
    ) -> Result<Zeroizing<[u8; 32]>> {
        Ok(self
            .local_seeds
            .get(position)
            .ok_or("native credential position")?
            .get(actor)
            .ok_or("native credential actor")?
            .clone())
    }

    /// The seed a test peer socket of `actor` serves: the OTHER actor's local
    /// role on that position. Test-only duplication of the counterpart's key.
    pub(crate) fn served_peer_seed(
        &self,
        position: usize,
        actor: usize,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if actor > 1 {
            return Err("native credential actor".into());
        }
        Ok(self
            .local_seeds
            .get(position)
            .ok_or("native credential position")?[1 - actor]
            .clone())
    }
}

fn seed() -> Zeroizing<[u8; 32]> {
    loop {
        let mut value = Zeroizing::new([0; 32]);
        rand::thread_rng().fill_bytes(value.as_mut());
        if *value != [0; 32] {
            return value;
        }
    }
}

fn public_key(seed: &[u8; 32]) -> SolanaPubkey {
    SolanaPubkey(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
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

#[test]
fn only_fixture_generated_accounts_have_a_seed_v25() -> Result<()> {
    let keys = NativeSolLegKeysV23::generate()?;
    let funder = keys.funder(0)?;
    let recipient = keys.recipient(0)?;
    assert_ne!(funder, keys.funder(1)?);
    assert_ne!(recipient, keys.recipient(1)?);
    assert_ne!(funder, recipient);
    assert_eq!(public_key(&*keys.seed_for(0, funder)?), funder);
    assert_eq!(public_key(&*keys.seed_for(0, recipient)?), recipient);
    // An account is never valid on the other position, and a digest-shaped
    // ParticipantId has no seed at all.
    assert!(keys.seed_for(1, funder).is_err());
    assert!(keys.seed_for(1, recipient).is_err());
    assert!(keys.seed_for(0, SolanaPubkey([0xb1; 32])).is_err());
    Ok(())
}
