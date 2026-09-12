//! Restartable participant exchange over the durable V3 signing operations.
//! The driver keeps no nonce counter or shadow journal. A retry starts at
//! phase one; the signing port must replay its retained nonce and partial.
use crate::{BitcoinActuatorErrorV1, BitcoinClaimMessageV3};

/// The two public exchanges in a participant-separated claim round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitcoinClaimExchangePhaseV6 {
    /// Exchange authenticated public nonces.
    Nonce = 1,
    /// Exchange authenticated transcript-bound partial signatures.
    Partial = 2,
}

/// Refusals remain separate from successful completion and never carry data.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinClaimDriverErrorV6 {
    /// The local authenticated signing authority refused the transition.
    #[error("Bitcoin claim signing transition refused")]
    Signing(#[source] BitcoinActuatorErrorV1),
    /// Delivery was interrupted; exact durable messages may be replayed.
    #[error("Bitcoin claim transport unavailable")]
    TransportUnavailable,
    /// The peer supplied a malformed, oversized or out-of-order envelope.
    #[error("Bitcoin claim transport envelope rejected")]
    EnvelopeRejected,
}

/// One local participant, with fresh local authorization at every operation.
/// Implementations must use durable nonce/partial replay and authenticate
/// peer frames before mutation; the transport supplies no signing authority.
pub trait BitcoinClaimSigningPortV6 {
    /// Move-only result issued after local verification and aggregation.
    type Completion;
    /// Persist or replay the same local public nonce.
    fn expose_nonce(&mut self) -> Result<BitcoinClaimMessageV3, BitcoinActuatorErrorV1>;
    /// Authenticate the peer nonce and persist or replay the local partial.
    fn produce_partial(
        &mut self,
        peer_nonce: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinActuatorErrorV1>;
    /// Authenticate both peer messages and aggregate through the local vault.
    fn complete(
        &mut self,
        peer_nonce: &BitcoinClaimMessageV3,
        peer_partial: &BitcoinClaimMessageV3,
    ) -> Result<Self::Completion, BitcoinActuatorErrorV1>;
}

/// Exchanges bounded public frames. It has no keys or refund capabilities.
pub trait BitcoinClaimTransportV6 {
    /// Sends the durable local frame, then obtains the peer frame for a phase.
    fn exchange(
        &mut self,
        phase: BitcoinClaimExchangePhaseV6,
        local: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinClaimDriverErrorV6>;
}

/// Drives an entire round. Returning an error does not clear durable signing
/// state or authorize funding. Reconnect and call again with the same session.
pub fn drive_bitcoin_claim_v6<S: BitcoinClaimSigningPortV6, T: BitcoinClaimTransportV6 + ?Sized>(
    signer: &mut S,
    transport: &mut T,
) -> Result<S::Completion, BitcoinClaimDriverErrorV6> {
    let nonce = signer
        .expose_nonce()
        .map_err(BitcoinClaimDriverErrorV6::Signing)?;
    let peer_nonce = transport.exchange(BitcoinClaimExchangePhaseV6::Nonce, &nonce)?;
    let partial = signer
        .produce_partial(&peer_nonce)
        .map_err(BitcoinClaimDriverErrorV6::Signing)?;
    let peer_partial = transport.exchange(BitcoinClaimExchangePhaseV6::Partial, &partial)?;
    signer
        .complete(&peer_nonce, &peer_partial)
        .map_err(BitcoinClaimDriverErrorV6::Signing)
}

/// Local duplex transport. This is a V6 envelope carrying V3 authenticated
/// messages, not a new DSC1/Relay message. Peer identity is checked by the
/// signing port against its pinned roster before signing-state mutation.
#[cfg(unix)]
pub struct UnixBitcoinClaimTransportV6 {
    stream: std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
    poisoned: bool,
}

#[cfg(unix)]
impl UnixBitcoinClaimTransportV6 {
    /// Uses an already connected socket and an absolute deadline per exchange.
    /// The timeout must be positive and at most 60 seconds.
    pub fn new(
        stream: std::os::unix::net::UnixStream,
        timeout: std::time::Duration,
    ) -> Result<Self, BitcoinClaimDriverErrorV6> {
        if timeout.is_zero() || timeout > std::time::Duration::from_secs(60) {
            return Err(BitcoinClaimDriverErrorV6::EnvelopeRejected);
        }
        stream
            .set_nonblocking(false)
            .map_err(|_| BitcoinClaimDriverErrorV6::TransportUnavailable)?;
        Ok(Self {
            stream,
            timeout,
            poisoned: false,
        })
    }

    fn remaining(
        deadline: std::time::Instant,
    ) -> Result<std::time::Duration, BitcoinClaimDriverErrorV6> {
        deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BitcoinClaimDriverErrorV6::TransportUnavailable)
    }

    fn write_deadline(
        &mut self,
        mut bytes: &[u8],
        deadline: std::time::Instant,
    ) -> Result<(), BitcoinClaimDriverErrorV6> {
        use std::io::Write;
        while !bytes.is_empty() {
            self.stream
                .set_write_timeout(Some(Self::remaining(deadline)?))
                .map_err(|_| BitcoinClaimDriverErrorV6::TransportUnavailable)?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(BitcoinClaimDriverErrorV6::TransportUnavailable),
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(BitcoinClaimDriverErrorV6::TransportUnavailable),
            }
        }
        Ok(())
    }

    fn read_deadline(
        &mut self,
        bytes: &mut [u8],
        deadline: std::time::Instant,
    ) -> Result<(), BitcoinClaimDriverErrorV6> {
        use std::io::Read;
        let mut offset = 0;
        while offset < bytes.len() {
            self.stream
                .set_read_timeout(Some(Self::remaining(deadline)?))
                .map_err(|_| BitcoinClaimDriverErrorV6::TransportUnavailable)?;
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) => return Err(BitcoinClaimDriverErrorV6::TransportUnavailable),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(BitcoinClaimDriverErrorV6::TransportUnavailable),
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl BitcoinClaimTransportV6 for UnixBitcoinClaimTransportV6 {
    fn exchange(
        &mut self,
        phase: BitcoinClaimExchangePhaseV6,
        local: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinClaimDriverErrorV6> {
        if self.poisoned {
            return Err(BitcoinClaimDriverErrorV6::TransportUnavailable);
        }
        let result = self.exchange_once(phase, local);
        if result.is_err() {
            // Partial delivery leaves the peer's framing position unknown.
            // Retained signer messages can be replayed only on a NEW stream.
            self.poisoned = true;
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
        result
    }
}

#[cfg(unix)]
impl UnixBitcoinClaimTransportV6 {
    fn exchange_once(
        &mut self,
        phase: BitcoinClaimExchangePhaseV6,
        local: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinClaimDriverErrorV6> {
        let bytes = local.to_bytes();
        if bytes[10] != phase as u8 {
            return Err(BitcoinClaimDriverErrorV6::EnvelopeRejected);
        }
        let deadline = std::time::Instant::now() + self.timeout;
        let mut header = [0u8; 12];
        header[..8].copy_from_slice(b"DOMBTCX6");
        header[8] = phase as u8;
        header[10..].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
        self.write_deadline(&header, deadline)?;
        self.write_deadline(&bytes, deadline)?;
        self.read_deadline(&mut header, deadline)?;
        let size = usize::from(u16::from_be_bytes([header[10], header[11]]));
        if &header[..8] != b"DOMBTCX6"
            || header[8] != phase as u8
            || header[9] != 0
            || size
                != if phase == BitcoinClaimExchangePhaseV6::Nonce {
                    270
                } else {
                    268
                }
        {
            return Err(BitcoinClaimDriverErrorV6::EnvelopeRejected);
        }
        let mut peer = vec![0; size];
        self.read_deadline(&mut peer, deadline)?;
        Self::remaining(deadline)?;
        if peer[10] != phase as u8 {
            return Err(BitcoinClaimDriverErrorV6::EnvelopeRejected);
        }
        BitcoinClaimMessageV3::from_bytes(&peer)
            .map_err(|_| BitcoinClaimDriverErrorV6::EnvelopeRejected)
    }
}
