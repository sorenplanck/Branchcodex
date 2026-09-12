//! Exact-setup Solana signing. No generic transfer, close or arbitrary program
//! instruction can reach the local key or the scoped Unix signer peer.
use crate::production_child_solana::ScopedSolanaSignerV1;
use crate::production_inputs::AuthenticatedSolanaSessionBindingsV1;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use ed25519_dalek::{Signer, SigningKey};
use settlement_coordinator::{ChildAuthorityRefusalV1 as Error, SettlementActionV1};
use solana_escrow_wire::EscrowInstructionV1;
use solana_profile::{SolanaAssetV1, ValidatedSolanaSetup};
use solana_transaction_builder::{
    assemble_signed_transaction, build_legacy_message, LegacyMessagePlan,
};
use solana_types::{SolanaHash, SolanaInstruction, SolanaPubkey, SolanaSignature};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_MESSAGE: usize = 1_232 - 65;
const REQUEST: &[u8; 8] = b"DOMSLSQ7";
const RESPONSE: &[u8; 8] = b"DOMSLSA7";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductionSolanaSignerRoleV7 {
    Funder,
    Beneficiary,
}

/// Explicit legacy SPL accounts. Their owners and mint are enforced by the
/// escrow program. Keys are fixed when the daemon binds the session and never
/// chosen by a signer response. Native SOL accepts no token account keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductionSolanaTokenAccountsV7 {
    pub(crate) source: SolanaPubkey,
    pub(crate) recipient: SolanaPubkey,
    pub(crate) refund: SolanaPubkey,
}

pub(crate) fn validate_token_accounts_v7(
    setup: &ValidatedSolanaSetup,
    accounts: Option<ProductionSolanaTokenAccountsV7>,
) -> Result<(), Error> {
    match (setup.asset(), accounts) {
        (SolanaAssetV1::NativeSol, None) => Ok(()),
        (SolanaAssetV1::LegacySpl { .. }, Some(a))
            if !a.source.is_zero()
                && !a.recipient.is_zero()
                && !a.refund.is_zero()
                && ![a.source, a.recipient, a.refund].contains(&setup.vault_pda()) =>
        {
            Ok(())
        }
        _ => Err(Error::Conflict),
    }
}

pub(crate) fn instructions_v7(
    setup: &ValidatedSolanaSetup,
    accounts: Option<ProductionSolanaTokenAccountsV7>,
    action: SettlementActionV1,
    secret: Option<[u8; 32]>,
) -> Result<Vec<SolanaInstruction>, Error> {
    validate_token_accounts_v7(setup, accounts)?;
    match (action, secret) {
        (SettlementActionV1::Funding, None) => Ok(vec![
            solana_program_client::initialize(setup),
            solana_program_client::fund(setup, accounts.map(|a| a.source))
                .map_err(|_| Error::Conflict)?,
        ]),
        (SettlementActionV1::Refund, None) => Ok(vec![solana_program_client::refund(
            setup,
            accounts.map(|a| a.refund),
        )
        .map_err(|_| Error::Conflict)?]),
        (SettlementActionV1::Claim, Some(secret)) => {
            xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar(secret, &setup.claim())
                .map_err(|_| Error::Conflict)?;
            Ok(vec![solana_program_client::claim(
                setup,
                secret,
                accounts.map(|a| a.recipient),
            )
            .map_err(|_| Error::Conflict)?])
        }
        _ => Err(Error::Conflict),
    }
}

/// Constructed only from authenticated session inputs; no codec can create it.
pub(crate) struct ProductionSolanaSignerBindingV7 {
    setup: ValidatedSolanaSetup,
    accounts: Option<ProductionSolanaTokenAccountsV7>,
    role: ProductionSolanaSignerRoleV7,
    account: SolanaPubkey,
    digest: [u8; 32],
}

impl ProductionSolanaSignerBindingV7 {
    pub(crate) fn authenticate(
        session: &AuthenticatedSolanaSessionBindingsV1,
        role: ProductionSolanaSignerRoleV7,
        accounts: Option<ProductionSolanaTokenAccountsV7>,
    ) -> Result<Self, Error> {
        let setup = session.setup();
        validate_token_accounts_v7(setup, accounts)?;
        let account = match role {
            ProductionSolanaSignerRoleV7::Funder => setup.funder(),
            ProductionSolanaSignerRoleV7::Beneficiary => setup.recipient(),
        };
        let mut parts = vec![
            session.route_id(),
            session.session_id(),
            session.terms_digest(),
            session.deployment().registry_digest(),
            session.deployment().deployment().genesis_hash,
            setup.binding_hash(),
            account.0,
        ];
        if parts.contains(&[0; 32]) {
            return Err(Error::Conflict);
        }
        parts.push(
            [match role {
                ProductionSolanaSignerRoleV7::Funder => 1,
                ProductionSolanaSignerRoleV7::Beneficiary => 2,
            }; 32],
        );
        if let Some(a) = accounts {
            parts.extend([a.source.0, a.recipient.0, a.refund.0]);
        }
        let digest = hash(b"DOM-INTEROP/SOLANA-SIGNER/V7\0", &parts.concat())?;
        Ok(Self {
            setup: setup.clone(),
            accounts,
            role,
            account,
            digest,
        })
    }

    fn validate_message(&self, message: &[u8]) -> Result<LegacyMessagePlan, Error> {
        let (hash, data) = message_shape(message)?;
        let (action, secret) = match data.as_slice() {
            [initialize, fund] if self.role == ProductionSolanaSignerRoleV7::Funder => {
                if !matches!(
                    EscrowInstructionV1::decode(initialize),
                    Ok(EscrowInstructionV1::InitializeNative(_))
                        | Ok(EscrowInstructionV1::InitializeSpl(_))
                ) || !matches!(
                    EscrowInstructionV1::decode(fund),
                    Ok(EscrowInstructionV1::Fund)
                ) {
                    return Err(Error::Conflict);
                }
                (SettlementActionV1::Funding, None)
            }
            [terminal] => match (self.role, EscrowInstructionV1::decode(terminal)) {
                (ProductionSolanaSignerRoleV7::Funder, Ok(EscrowInstructionV1::Refund)) => {
                    (SettlementActionV1::Refund, None)
                }
                (
                    ProductionSolanaSignerRoleV7::Beneficiary,
                    Ok(EscrowInstructionV1::Claim { revealed_secret_be }),
                ) => (SettlementActionV1::Claim, Some(revealed_secret_be)),
                _ => return Err(Error::Conflict),
            },
            _ => return Err(Error::Conflict),
        };
        let instructions = instructions_v7(&self.setup, self.accounts, action, secret)?;
        let plan =
            build_legacy_message(self.account, hash, &instructions).map_err(|_| Error::Conflict)?;
        if plan.signer_keys != [self.account] || plan.message != message {
            return Err(Error::Conflict);
        }
        Ok(plan)
    }
}

pub(crate) struct ProductionSolanaLocalSignerV7 {
    binding: ProductionSolanaSignerBindingV7,
    key: SigningKey,
}
impl ProductionSolanaLocalSignerV7 {
    pub(crate) fn new(
        binding: ProductionSolanaSignerBindingV7,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, Error> {
        if *seed == [0; 32] {
            return Err(Error::Conflict);
        }
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().to_bytes() != binding.account.0 {
            return Err(Error::Conflict);
        }
        Ok(Self { binding, key })
    }

    /// Serve one bounded request on an already authorized connected socket.
    /// A caller may loop on successful requests; any error requires reconnect.
    pub(crate) fn serve_once(
        &mut self,
        socket: &mut UnixStream,
        timeout: Duration,
    ) -> Result<(), Error> {
        let deadline = deadline(socket, timeout)?;
        let mut header = [0; 42];
        read(socket, &mut header, deadline)?;
        if &header[..8] != REQUEST || header[8..40] != self.binding.digest {
            return Err(Error::Conflict);
        }
        let length = usize::from(u16::from_be_bytes([header[40], header[41]]));
        if length == 0 || length > MAX_MESSAGE {
            return Err(Error::Conflict);
        }
        let mut message = Zeroizing::new(vec![0; length]);
        read(socket, &mut message, deadline)?;
        let signature = self.sign_message(&message)?;
        let message_hash = hash(b"DOM-INTEROP/SOLANA-SIGNING-MESSAGE/V7\0", &message)?;
        let mut response = Vec::with_capacity(136);
        response.extend_from_slice(RESPONSE);
        response.extend_from_slice(&self.binding.digest);
        response.extend_from_slice(&message_hash);
        response.extend_from_slice(&signature.0);
        write(socket, &response, deadline)
    }
}
impl ScopedSolanaSignerV1 for ProductionSolanaLocalSignerV7 {
    fn account(&self) -> SolanaPubkey {
        self.binding.account
    }
    fn sign_message(&mut self, message: &[u8]) -> Result<SolanaSignature, Error> {
        self.binding.validate_message(message)?;
        Ok(SolanaSignature(self.key.sign(message).to_bytes()))
    }
}

pub(crate) struct ProductionSolanaUnixSignerV7 {
    binding: ProductionSolanaSignerBindingV7,
    socket: UnixStream,
    timeout: Duration,
    failed: bool,
}
impl ProductionSolanaUnixSignerV7 {
    pub(crate) fn new(
        binding: ProductionSolanaSignerBindingV7,
        socket: UnixStream,
        timeout: Duration,
    ) -> Result<Self, Error> {
        deadline(&socket, timeout)?;
        Ok(Self {
            binding,
            socket,
            timeout,
            failed: false,
        })
    }
    fn exchange(
        &mut self,
        message: &[u8],
        plan: &LegacyMessagePlan,
    ) -> Result<SolanaSignature, Error> {
        let deadline = deadline(&self.socket, self.timeout)?;
        let mut request = Zeroizing::new(Vec::with_capacity(42 + message.len()));
        request.extend_from_slice(REQUEST);
        request.extend_from_slice(&self.binding.digest);
        request.extend_from_slice(&(message.len() as u16).to_be_bytes());
        request.extend_from_slice(message);
        write(&mut self.socket, &request, deadline)?;
        let mut response = [0; 136];
        read(&mut self.socket, &mut response, deadline)?;
        if &response[..8] != RESPONSE
            || response[8..40] != self.binding.digest
            || response[40..72] != hash(b"DOM-INTEROP/SOLANA-SIGNING-MESSAGE/V7\0", message)?
        {
            return Err(Error::Conflict);
        }
        let mut bytes = [0; 64];
        bytes.copy_from_slice(&response[72..]);
        let signature = SolanaSignature(bytes);
        assemble_signed_transaction(plan, &[(self.binding.account, signature)])
            .map_err(|_| Error::Conflict)?;
        Ok(signature)
    }
}
impl ScopedSolanaSignerV1 for ProductionSolanaUnixSignerV7 {
    fn account(&self) -> SolanaPubkey {
        self.binding.account
    }
    fn sign_message(&mut self, message: &[u8]) -> Result<SolanaSignature, Error> {
        if self.failed {
            return Err(Error::Unavailable);
        }
        let plan = self.binding.validate_message(message)?;
        let result = self.exchange(message, &plan);
        // An interrupted frame leaves the stream position ambiguous; it cannot
        // become a valid reply to a later operation on this connection.
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn hash(domain: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
    let mut h = Blake2bVar::new(32).map_err(|_| Error::Conflict)?;
    h.update(domain);
    h.update(&(data.len() as u64).to_be_bytes());
    h.update(data);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).map_err(|_| Error::Conflict)?;
    Ok(out)
}
fn deadline(socket: &UnixStream, timeout: Duration) -> Result<Instant, Error> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(Error::Conflict);
    }
    socket
        .set_nonblocking(false)
        .map_err(|_| Error::Unavailable)?;
    Instant::now().checked_add(timeout).ok_or(Error::Conflict)
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Error::Unavailable)
}
fn read(socket: &mut UnixStream, mut bytes: &mut [u8], end: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        socket
            .set_read_timeout(Some(remaining(end)?))
            .map_err(|_| Error::Unavailable)?;
        match socket.read(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Unavailable),
        }
    }
    remaining(end).map(|_| ())
}
fn write(socket: &mut UnixStream, mut bytes: &[u8], end: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        socket
            .set_write_timeout(Some(remaining(end)?))
            .map_err(|_| Error::Unavailable)?;
        match socket.write(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Unavailable),
        }
    }
    remaining(end).map(|_| ())
}

// Parse only the bounded legacy envelope. Rebuilding the *entire* message
// below is what authenticates account order, flags, indices and instruction
// bytes; parsed peer metadata is never trusted as a signing policy.
fn message_shape(message: &[u8]) -> Result<(SolanaHash, Vec<&[u8]>), Error> {
    if message.len() > MAX_MESSAGE || message.len() < 3 || message[0] != 1 || message[1] != 0 {
        return Err(Error::Conflict);
    }
    let mut cursor = Cursor {
        bytes: message,
        at: 3,
    };
    let count = cursor.short()?;
    if count == 0 || count > 256 {
        return Err(Error::Conflict);
    }
    cursor.take(count * 32)?;
    let mut hash = [0; 32];
    hash.copy_from_slice(cursor.take(32)?);
    if hash == [0; 32] {
        return Err(Error::Conflict);
    }
    let count = cursor.short()?;
    if count == 0 || count > 2 {
        return Err(Error::Conflict);
    }
    let mut data = Vec::with_capacity(count);
    for _ in 0..count {
        cursor.take(1)?;
        let accounts = cursor.short()?;
        cursor.take(accounts)?;
        let length = cursor.short()?;
        data.push(cursor.take(length)?);
    }
    if cursor.at != message.len() {
        return Err(Error::Conflict);
    }
    Ok((SolanaHash(hash), data))
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Conflict)?;
        let result = self.bytes.get(self.at..end).ok_or(Error::Conflict)?;
        self.at = end;
        Ok(result)
    }
    fn short(&mut self) -> Result<usize, Error> {
        let mut value = 0;
        for i in 0..3 {
            let byte = self.take(1)?[0];
            if i == 2 && byte > 3 {
                return Err(Error::Conflict);
            }
            value |= usize::from(byte & 127) << (7 * i);
            if byte & 128 == 0 {
                if i > 0 && byte == 0 {
                    return Err(Error::Conflict);
                }
                return Ok(value);
            }
        }
        Err(Error::Conflict)
    }
}

#[cfg(test)]
#[path = "tests/solana_signer_v7.rs"]
mod tests;
