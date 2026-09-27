//! Authenticated, session-bound transport for DXA1 participant messages.
//!
//! This uses the node's existing Noise XX handshake and pins the remote static
//! key. The DOM chain id and network magic are part of the Noise prologue. Each
//! plaintext also carries the exact swap session and a monotonic sequence.
//! A channel must be dropped after a send/receive error or cancellation.

use std::{net::SocketAddr, time::Duration};

use dom_core::DomError;
use dom_wire::handshake::{
    perform_handshake_initiator, perform_handshake_responder, read_framed, write_framed,
    NOISE_MAX_MSG,
};
use snow::TransportState;
use tokio::net::{TcpListener, TcpStream};

const ENVELOPE_MAGIC: &[u8; 8] = b"DXA1NET1";
const HEADER_BYTES: usize = ENVELOPE_MAGIC.len() + 32 + 8 + 4;
const CHUNK_BYTES: usize = NOISE_MAX_MSG - 16;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum application payload accepted by the participant channel.
pub const MAX_SWAP_MESSAGE_BYTES: usize = 1 << 20;

fn invalid(reason: impl Into<String>) -> DomError {
    DomError::Invalid(reason.into())
}

/// One authenticated Noise connection pinned to a participant identity.
pub struct SwapNoiseChannel {
    stream: TcpStream,
    transport: TransportState,
    peer_id: [u8; 32],
    session: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
}

impl SwapNoiseChannel {
    /// Connect and require the responder's exact Noise static public key.
    pub async fn connect(
        address: SocketAddr,
        local_static: &[u8; 32],
        expected_peer: [u8; 32],
        network_magic: u32,
        chain_id: [u8; 32],
        session: [u8; 32],
    ) -> Result<Self, DomError> {
        let mut stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| invalid("swap transport connect timeout"))?
            .map_err(|error| DomError::Internal(format!("swap transport connect: {error}")))?;
        let transport =
            perform_handshake_initiator(&mut stream, local_static, network_magic, &chain_id)
                .await?;
        Self::new(stream, transport, expected_peer, session)
    }

    /// Accept one connection and require the initiator's exact Noise identity.
    pub async fn accept(
        listener: &TcpListener,
        local_static: &[u8; 32],
        expected_peer: [u8; 32],
        network_magic: u32,
        chain_id: [u8; 32],
        session: [u8; 32],
    ) -> Result<Self, DomError> {
        let (mut stream, _) = tokio::time::timeout(IO_TIMEOUT, listener.accept())
            .await
            .map_err(|_| invalid("swap transport accept timeout"))?
            .map_err(|error| DomError::Internal(format!("swap transport accept: {error}")))?;
        let transport =
            perform_handshake_responder(&mut stream, local_static, network_magic, &chain_id)
                .await?;
        Self::new(stream, transport, expected_peer, session)
    }

    fn new(
        stream: TcpStream,
        transport: TransportState,
        expected_peer: [u8; 32],
        session: [u8; 32],
    ) -> Result<Self, DomError> {
        if session == [0; 32] {
            return Err(invalid("zero swap transport session"));
        }
        let peer_id: [u8; 32] = transport
            .get_remote_static()
            .ok_or_else(|| invalid("Noise peer has no static identity"))?
            .try_into()
            .map_err(|_| invalid("invalid Noise peer identity length"))?;
        if peer_id != expected_peer {
            return Err(invalid("unexpected swap participant identity"));
        }
        Ok(Self {
            stream,
            transport,
            peer_id,
            session,
            send_sequence: 0,
            receive_sequence: 0,
        })
    }

    /// Authenticated remote Noise static key checked at connection setup.
    pub fn peer_id(&self) -> [u8; 32] {
        self.peer_id
    }

    /// Encrypt and send one session-bound, ordered application message.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), DomError> {
        if payload.len() > MAX_SWAP_MESSAGE_BYTES {
            return Err(invalid("swap message exceeds maximum size"));
        }
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| invalid("swap message length does not fit u32"))?;
        let mut plaintext = Vec::with_capacity(HEADER_BYTES + payload.len());
        plaintext.extend_from_slice(ENVELOPE_MAGIC);
        plaintext.extend_from_slice(&self.session);
        plaintext.extend_from_slice(&self.send_sequence.to_le_bytes());
        plaintext.extend_from_slice(&payload_len.to_le_bytes());
        plaintext.extend_from_slice(payload);

        let total_len = u32::try_from(plaintext.len())
            .map_err(|_| invalid("swap envelope length does not fit u32"))?;
        let mut framed = Vec::with_capacity(4 + plaintext.len());
        framed.extend_from_slice(&total_len.to_le_bytes());
        framed.extend_from_slice(&plaintext);
        for chunk in framed.chunks(CHUNK_BYTES) {
            let mut ciphertext = vec![0; chunk.len() + 16];
            let written = self
                .transport
                .write_message(chunk, &mut ciphertext)
                .map_err(|error| DomError::Internal(format!("swap Noise encrypt: {error}")))?;
            tokio::time::timeout(
                IO_TIMEOUT,
                write_framed(&mut self.stream, &ciphertext[..written]),
            )
            .await
            .map_err(|_| invalid("swap transport write timeout"))??;
        }
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("swap send sequence exhausted"))?;
        Ok(())
    }

    /// Receive one message and reject a different session or sequence.
    pub async fn receive(&mut self) -> Result<Vec<u8>, DomError> {
        let maximum = HEADER_BYTES + MAX_SWAP_MESSAGE_BYTES;
        let mut plaintext = Vec::new();
        let mut expected_total = None;
        loop {
            let ciphertext = tokio::time::timeout(READ_IDLE_TIMEOUT, read_framed(&mut self.stream))
                .await
                .map_err(|_| invalid("swap transport read timeout"))??;
            let mut chunk = vec![0; ciphertext.len()];
            let length = self
                .transport
                .read_message(&ciphertext, &mut chunk)
                .map_err(|error| invalid(format!("swap Noise decrypt: {error}")))?;
            plaintext.extend_from_slice(&chunk[..length]);
            if expected_total.is_none() && plaintext.len() >= 4 {
                let total = u32::from_le_bytes(plaintext[..4].try_into().unwrap()) as usize;
                if total > maximum || total < HEADER_BYTES {
                    return Err(invalid("invalid swap envelope size"));
                }
                expected_total = Some(4 + total);
            }
            if plaintext.len() > maximum + 4 {
                return Err(invalid("swap envelope overrun"));
            }
            match expected_total {
                Some(expected) if plaintext.len() == expected => break,
                Some(expected) if plaintext.len() > expected => {
                    return Err(invalid("swap envelope crossed message boundary"));
                }
                _ => {}
            }
        }

        let envelope = &plaintext[4..];
        if &envelope[..8] != ENVELOPE_MAGIC {
            return Err(invalid("wrong swap envelope protocol"));
        }
        if envelope[8..40] != self.session {
            return Err(invalid("swap envelope belongs to another session"));
        }
        let sequence = u64::from_le_bytes(envelope[40..48].try_into().unwrap());
        if sequence != self.receive_sequence {
            return Err(invalid("unexpected swap message sequence"));
        }
        let payload_len = u32::from_le_bytes(envelope[48..52].try_into().unwrap()) as usize;
        if envelope.len() != HEADER_BYTES + payload_len {
            return Err(invalid("swap payload length mismatch"));
        }
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("swap receive sequence exhausted"))?;
        Ok(envelope[HEADER_BYTES..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::NETWORK_MAGIC_REGTEST;
    use dom_wire::handshake::generate_static_keypair;

    const CHAIN: [u8; 32] = [0x41; 32];
    const SESSION: [u8; 32] = [0x51; 32];

    async fn pair(
        initiator_session: [u8; 32],
        responder_session: [u8; 32],
    ) -> (SwapNoiseChannel, SwapNoiseChannel) {
        let (initiator_secret, initiator_public) = generate_static_keypair();
        let (responder_secret, responder_public) = generate_static_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            SwapNoiseChannel::accept(
                &listener,
                &responder_secret,
                initiator_public,
                NETWORK_MAGIC_REGTEST,
                CHAIN,
                responder_session,
            )
            .await
            .unwrap()
        });
        let initiator = SwapNoiseChannel::connect(
            address,
            &initiator_secret,
            responder_public,
            NETWORK_MAGIC_REGTEST,
            CHAIN,
            initiator_session,
        )
        .await
        .unwrap();
        (initiator, responder.await.unwrap())
    }

    #[tokio::test]
    async fn pinned_peers_exchange_fragmented_ordered_messages() {
        let (mut initiator, mut responder) = pair(SESSION, SESSION).await;
        let first = vec![0xA5; NOISE_MAX_MSG * 2];
        initiator.send(&first).await.unwrap();
        assert_eq!(responder.receive().await.unwrap(), first);
        responder.send(b"ack-0").await.unwrap();
        assert_eq!(initiator.receive().await.unwrap(), b"ack-0");
        initiator.send(b"request-1").await.unwrap();
        assert_eq!(responder.receive().await.unwrap(), b"request-1");
    }

    #[tokio::test]
    async fn different_session_is_rejected_after_authenticated_handshake() {
        let (mut initiator, mut responder) = pair(SESSION, [0x52; 32]).await;
        initiator.send(b"wrong session").await.unwrap();
        assert!(responder.receive().await.is_err());
    }

    #[tokio::test]
    async fn unexpected_static_identity_is_rejected() {
        let (initiator_secret, _) = generate_static_keypair();
        let (responder_secret, _) = generate_static_keypair();
        let (_, wrong_responder) = generate_static_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            perform_handshake_responder(
                &mut stream,
                &responder_secret,
                NETWORK_MAGIC_REGTEST,
                &CHAIN,
            )
            .await
            .unwrap();
        });
        let result = SwapNoiseChannel::connect(
            address,
            &initiator_secret,
            wrong_responder,
            NETWORK_MAGIC_REGTEST,
            CHAIN,
            SESSION,
        )
        .await;
        assert!(result.is_err());
        responder.await.unwrap();
    }
}
