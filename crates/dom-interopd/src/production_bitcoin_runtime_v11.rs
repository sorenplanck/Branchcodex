//! Root-owned participant transport for the same child-owned late M.8 driver.
//! Socket frames remain public and are authenticated by the native signer.
//! Transport unavailability never grants signing or converts a bad frame to
//! legitimate absence. A retry opens a new stream and replays durable frames.

use crate::production_bitcoin_claim_driver::BitcoinPostAnchorErrorV8;
use crate::production_universal_leg_authority::{connect_unix_bounded, existing_resource};
use btc_actuator::{
    BitcoinClaimDriverErrorV6, BitcoinClaimExchangePhaseV6, BitcoinClaimMessageV3,
    BitcoinClaimTransportV6, UnixBitcoinClaimTransportV6,
};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) struct ProductionBitcoinRuntimeTransportV11 {
    state_dir: PathBuf,
    relative_socket: String,
    timeout: Duration,
    connected: Option<UnixBitcoinClaimTransportV6>,
}

impl ProductionBitcoinRuntimeTransportV11 {
    /// The root has already authenticated the manifest and isolated its path.
    /// Opening remains lazy: a funding-only cycle never contacts a claim peer.
    pub(crate) fn new(state_dir: PathBuf, relative_socket: String, timeout: Duration) -> Self {
        Self {
            state_dir,
            relative_socket,
            timeout,
            connected: None,
        }
    }

    /// Each driver call replays nonce then partial on a fresh duplex stream.
    /// An interrupted previous call cannot leave a half-read envelope behind.
    pub(crate) fn start_attempt(&mut self) {
        self.connected = None;
    }
}

impl BitcoinClaimTransportV6 for ProductionBitcoinRuntimeTransportV11 {
    fn exchange(
        &mut self,
        phase: BitcoinClaimExchangePhaseV6,
        local: &BitcoinClaimMessageV3,
    ) -> Result<BitcoinClaimMessageV3, BitcoinClaimDriverErrorV6> {
        if self.connected.is_none() {
            if phase != BitcoinClaimExchangePhaseV6::Nonce {
                return Err(BitcoinClaimDriverErrorV6::EnvelopeRejected);
            }
            let map = |error| match error {
                settlement_coordinator::ChildAuthorityRefusalV1::Unavailable => {
                    BitcoinClaimDriverErrorV6::TransportUnavailable
                }
                _ => BitcoinClaimDriverErrorV6::EnvelopeRejected,
            };
            let path =
                existing_resource(&self.state_dir, &self.relative_socket, true).map_err(map)?;
            let stream = connect_unix_bounded(&path).map_err(map)?;
            self.connected = Some(UnixBitcoinClaimTransportV6::new(stream, self.timeout)?);
        }
        let result = self
            .connected
            .as_mut()
            .ok_or(BitcoinClaimDriverErrorV6::TransportUnavailable)?
            .exchange(phase, local);
        if result.is_err() {
            self.connected = None;
        }
        result
    }
}

/// Only explicit absence, insufficient depth, snapshot changes and transport
/// outages are retryable. Substitution, malformed RPC, bad signatures, wrong
/// ancestry or Store refusal stop signing rather than posing as "not yet".
pub(crate) fn retryable_post_anchor_v11(error: &BitcoinPostAnchorErrorV8) -> bool {
    use crate::production_f7_m8::ProductionF7M8ErrorV2 as Bridge;
    use adapter_btc_live::LiveBitcoinError as Btc;
    use f7_anchor_authority::F7AnchorAuthorityError as F7;
    matches!(
        error,
        BitcoinPostAnchorErrorV8::AwaitingClaimMaterialization
            | BitcoinPostAnchorErrorV8::Exchange(BitcoinClaimDriverErrorV6::TransportUnavailable)
            | BitcoinPostAnchorErrorV8::Funding(
                Btc::TransactionUnavailable | Btc::SnapshotChanged | Btc::InsufficientConfirmations
            )
            | BitcoinPostAnchorErrorV8::F7(Bridge::AnchorRefused(
                F7::InsufficientFinality
                    | F7::DomFundingAbsent
                    | F7::Dom(
                        dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
                    )
            ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_btc_live::LiveBitcoinError;
    #[test]
    fn absent_funding_retries_but_substituted_or_malformed_funding_stops() {
        for error in [
            LiveBitcoinError::TransactionUnavailable,
            LiveBitcoinError::SnapshotChanged,
            LiveBitcoinError::InsufficientConfirmations,
        ] {
            assert!(retryable_post_anchor_v11(
                &BitcoinPostAnchorErrorV8::Funding(error)
            ));
        }
        for error in [
            LiveBitcoinError::IdentityMismatch,
            LiveBitcoinError::FundingMismatch,
            LiveBitcoinError::InvalidRpcResponse,
            LiveBitcoinError::CorruptRecord,
            LiveBitcoinError::Rpc,
        ] {
            assert!(!retryable_post_anchor_v11(
                &BitcoinPostAnchorErrorV8::Funding(error)
            ));
        }
        assert!(!retryable_post_anchor_v11(
            &BitcoinPostAnchorErrorV8::Exchange(BitcoinClaimDriverErrorV6::EnvelopeRejected)
        ));
        assert!(!retryable_post_anchor_v11(&BitcoinPostAnchorErrorV8::Scope));
    }
}
