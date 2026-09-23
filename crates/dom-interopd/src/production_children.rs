//! Production composition of the counterparty settlement children.
//!
//! This module is the seam named by `CHILD_SOCKETS_DESIGN.md`: it takes the
//! authenticated route inputs, the provisioned durable actuator stores and
//! the operator's chain-endpoints artifact, and constructs the EVM, Bitcoin,
//! Solana and Monero children in their drive (non-materializing) form — one
//! child per authenticated counterparty leg, nothing for a face the route
//! did not admit, and a named refusal instead of a half-composed child.
//!
//! The DOM child is deliberately **not** composed here: its Contracts
//! authority requires the real Relay worker over a real `F6TransportPortV1`,
//! which remains in `MISSING_PRODUCTION_PARTS_V1`. Composing it over a
//! refusing transport would dress absence as presence.
//!
//! The Solana and Monero actuator stores are created lazily by their own
//! idempotent `open` during composition rather than under provisioning
//! journal stages. The journal's ordering audit requires a monotone stage
//! prefix, and the two stages that would have to precede these (F6, Relay)
//! cannot complete yet; the stores' own row-level fencing and write-once
//! custody make unjournaled creation safe, exactly as it is for the Bitcoin
//! prebroadcast store the external arming flow writes.

use std::path::Path;
use std::rc::Rc;

use adapter_btc_live::{
    BitcoinCoreRpcClientV1, BitcoinCoreRpcConfigV1, BitcoinPrebroadcastStoreV1,
    ReopenedBitcoinFundingV1,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use kaystra_core::types::Digest32;
use route_executor::LegIdV1;
use solana_actuator::{DurableSolanaActuatorV1, SolanaActuatorLeaseV1, SolanaOperationStoreV1};
use solana_rpc::HttpSolanaRpc;
use solana_rpc_pool::SolanaRpcPool;
use std::sync::Arc;
use xmr_actuator::{
    DurableXmrActuatorV1, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrObservationPortV1,
    XmrOperationStoreV1, XmrTxInclusionV1,
};
use xmr_rpc_broadcast_blocking::{BlockingMoneroBroadcaster, BlockingMoneroDaemonReaderV1};

use crate::production_child_btc::ProductionBitcoinFundingAuthorityV1;
use crate::production_child_router::{
    AuthenticatedBitcoinChildPortV1, AuthenticatedEvmChildPortV1, AuthenticatedSolanaChildPortV1,
    AuthenticatedXmrChildPortV1, ProductionSettlementChildRouterV1,
};
use crate::production_child_solana::{
    ProductionSolanaChildPortV1, SystemProductionSolanaChildClockV1,
};
use crate::production_child_xmr::{ProductionXmrChildPortV1, SystemProductionXmrChildClockV1};
use crate::production_config::{read_owner_file_bounded, ProductionConfigErrorV1};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_refund_arming::{
    production_bitcoin_refund_route_binding_v1, ProductionBitcoinRefundFaceV1,
    ProductionCounterpartyRefundFaceV1, ProductionEvmRefundFaceV1, ProductionSolanaRefundFaceV1,
    ProductionXmrRefundFaceV1,
};
use xmr_refund_policy::XmrRefundArtifactV1;

const ENDPOINTS_MAGIC_V1: &[u8; 8] = b"DOMCEND1";
const ENDPOINTS_VERSION_V1: u16 = 1;
/// Endpoints are operator configuration, not chain data; one artifact of
/// this size bounds sixteen URLs per quorum face with room to spare.
pub(crate) const MAX_CHAIN_ENDPOINTS_BYTES_V1: usize = 32 * 1024;
const MAX_ENDPOINT_URL_BYTES_V1: usize = 512;
const MAX_WALLET_NAME_BYTES_V1: usize = 64;
const MAX_SIGNET_CHALLENGE_BYTES_V1: usize = 128;
const MAX_QUORUM_NODES_V1: usize = 16;
const AUTHORITY_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/CHILDREN/AUTHORITY-ID/V1\0";

/// Composition refusals. Redacted: no variant carries a URL, a path or any
/// byte of the artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionChildCompositionErrorV1 {
    /// The chain-endpoints artifact is missing, oversize or non-canonical.
    #[error("chain-endpoints artifact refused")]
    Endpoints,
    /// The artifact's face set disagrees with the authenticated route legs.
    #[error("chain-endpoints faces do not match the admitted route")]
    FaceMismatch,
    /// A deployment capability or session the route needs was refused.
    #[error("counterparty deployment capability refused")]
    Capability,
    /// A durable store could not be opened or a lease could not be minted.
    #[error("counterparty durable authority unavailable")]
    Store,
    /// An RPC client could not be constructed from the artifact.
    #[error("counterparty RPC boundary refused")]
    Rpc,
    /// The Bitcoin external funding is not yet armed in the prebroadcast
    /// store, so the Bitcoin child cannot exist without inventing custody.
    #[error("Bitcoin external funding is not armed")]
    FundingNotArmed,
    /// A child constructor refused its authenticated inputs.
    #[error("counterparty child construction refused")]
    Child,
    /// The Monero leg carries no registered refund arm, so its refund face
    /// cannot exist without inventing one.
    #[error("Monero refund arm is not registered in the participant bundle")]
    RefundArmNotRegistered,
}

/// Endpoint set for one EVM face.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvmEndpointsV1 {
    pub(crate) url: String,
}

/// Endpoint set for one Bitcoin Core face. Credentials stay in Core's
/// owner-only cookie file; this artifact only references it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BitcoinEndpointsV1 {
    pub(crate) endpoint: String,
    pub(crate) wallet_name: String,
    pub(crate) cookie_file: String,
}

/// Endpoint set for one Solana quorum face.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SolanaEndpointsV1 {
    pub(crate) node_urls: Vec<String>,
    pub(crate) quorum: u16,
}

/// Endpoint set for one Monero quorum face. The first daemon is also the
/// exact-broadcast target; every daemon serves the observation quorum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MoneroEndpointsV1 {
    pub(crate) daemon_urls: Vec<String>,
    pub(crate) quorum: u16,
}

/// The operator's chain-endpoints artifact: which counterparty faces this
/// deployment can reach, and through what. Strictly canonical; faces are a
/// bitmask (bit 0 EVM, bit 1 Bitcoin, bit 2 Solana, bit 3 Monero) and the
/// sections follow in bit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductionChainEndpointsV1 {
    pub(crate) evm: Option<EvmEndpointsV1>,
    pub(crate) bitcoin: Option<BitcoinEndpointsV1>,
    pub(crate) solana: Option<SolanaEndpointsV1>,
    pub(crate) monero: Option<MoneroEndpointsV1>,
}

impl ProductionChainEndpointsV1 {
    /// Canonical reject-trailing encoding.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionChildCompositionErrorV1> {
        let mut faces: u16 = 0;
        if self.evm.is_some() {
            faces |= 1;
        }
        if self.bitcoin.is_some() {
            faces |= 2;
        }
        if self.solana.is_some() {
            faces |= 4;
        }
        if self.monero.is_some() {
            faces |= 8;
        }
        if faces == 0 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(ENDPOINTS_MAGIC_V1);
        bytes.extend_from_slice(&ENDPOINTS_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&faces.to_be_bytes());
        if let Some(evm) = &self.evm {
            put_bounded(&mut bytes, evm.url.as_bytes(), MAX_ENDPOINT_URL_BYTES_V1)?;
        }
        if let Some(bitcoin) = &self.bitcoin {
            put_bounded(
                &mut bytes,
                bitcoin.endpoint.as_bytes(),
                MAX_ENDPOINT_URL_BYTES_V1,
            )?;
            put_bounded(
                &mut bytes,
                bitcoin.wallet_name.as_bytes(),
                MAX_WALLET_NAME_BYTES_V1,
            )?;
            put_bounded(
                &mut bytes,
                bitcoin.cookie_file.as_bytes(),
                MAX_ENDPOINT_URL_BYTES_V1,
            )?;
        }
        if let Some(solana) = &self.solana {
            put_quorum_urls(&mut bytes, &solana.node_urls, solana.quorum)?;
        }
        if let Some(monero) = &self.monero {
            put_quorum_urls(&mut bytes, &monero.daemon_urls, monero.quorum)?;
        }
        if bytes.len() > MAX_CHAIN_ENDPOINTS_BYTES_V1 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        Ok(bytes)
    }

    /// Strict decode: exact magic, version, bit-ordered sections, no
    /// trailing bytes, and byte-identical re-encoding.
    pub(crate) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, ProductionChildCompositionErrorV1> {
        if bytes.len() > MAX_CHAIN_ENDPOINTS_BYTES_V1 || bytes.len() < 12 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(8)? != ENDPOINTS_MAGIC_V1 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        if cursor.u16()? != ENDPOINTS_VERSION_V1 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let faces = cursor.u16()?;
        if faces == 0 || faces > 0b1111 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let evm = if faces & 1 != 0 {
            Some(EvmEndpointsV1 {
                url: cursor.bounded_string(MAX_ENDPOINT_URL_BYTES_V1)?,
            })
        } else {
            None
        };
        let bitcoin = if faces & 2 != 0 {
            Some(BitcoinEndpointsV1 {
                endpoint: cursor.bounded_string(MAX_ENDPOINT_URL_BYTES_V1)?,
                wallet_name: cursor.bounded_string(MAX_WALLET_NAME_BYTES_V1)?,
                cookie_file: cursor.bounded_string(MAX_ENDPOINT_URL_BYTES_V1)?,
            })
        } else {
            None
        };
        let solana = if faces & 4 != 0 {
            let (node_urls, quorum) = cursor.quorum_urls()?;
            Some(SolanaEndpointsV1 { node_urls, quorum })
        } else {
            None
        };
        let monero = if faces & 8 != 0 {
            let (daemon_urls, quorum) = cursor.quorum_urls()?;
            Some(MoneroEndpointsV1 {
                daemon_urls,
                quorum,
            })
        } else {
            None
        };
        if cursor.at != bytes.len() {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let value = Self {
            evm,
            bitcoin,
            solana,
            monero,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        Ok(value)
    }
}

/// Loads and strictly decodes the artifact from an owner-only file.
pub(crate) fn load_production_chain_endpoints(
    path: &Path,
) -> Result<ProductionChainEndpointsV1, ProductionChildCompositionErrorV1> {
    let bytes = read_owner_file_bounded(
        path,
        MAX_CHAIN_ENDPOINTS_BYTES_V1 as u64,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Endpoints)?;
    ProductionChainEndpointsV1::decode_canonical(&bytes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProductionChildCompositionErrorV1> {
        let end = self
            .at
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProductionChildCompositionErrorV1::Endpoints)?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, ProductionChildCompositionErrorV1> {
        let slice = self.take(2)?;
        Ok(u16::from_be_bytes([slice[0], slice[1]]))
    }

    fn bounded_string(
        &mut self,
        bound: usize,
    ) -> Result<String, ProductionChildCompositionErrorV1> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > bound {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let slice = self.take(length)?;
        if !slice.is_ascii() {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        String::from_utf8(slice.to_vec()).map_err(|_| ProductionChildCompositionErrorV1::Endpoints)
    }

    fn quorum_urls(&mut self) -> Result<(Vec<String>, u16), ProductionChildCompositionErrorV1> {
        let count = usize::from(self.take(1)?[0]);
        if count == 0 || count > MAX_QUORUM_NODES_V1 {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        let mut urls = Vec::with_capacity(count);
        for _ in 0..count {
            urls.push(self.bounded_string(MAX_ENDPOINT_URL_BYTES_V1)?);
        }
        let quorum = self.u16()?;
        if quorum == 0 || usize::from(quorum) > count {
            return Err(ProductionChildCompositionErrorV1::Endpoints);
        }
        Ok((urls, quorum))
    }
}

fn put_bounded(
    bytes: &mut Vec<u8>,
    value: &[u8],
    bound: usize,
) -> Result<(), ProductionChildCompositionErrorV1> {
    if value.is_empty() || value.len() > bound || !value.is_ascii() {
        return Err(ProductionChildCompositionErrorV1::Endpoints);
    }
    let length =
        u16::try_from(value.len()).map_err(|_| ProductionChildCompositionErrorV1::Endpoints)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn put_quorum_urls(
    bytes: &mut Vec<u8>,
    urls: &[String],
    quorum: u16,
) -> Result<(), ProductionChildCompositionErrorV1> {
    if urls.is_empty() || urls.len() > MAX_QUORUM_NODES_V1 {
        return Err(ProductionChildCompositionErrorV1::Endpoints);
    }
    if quorum == 0 || usize::from(quorum) > urls.len() {
        return Err(ProductionChildCompositionErrorV1::Endpoints);
    }
    bytes.push(u8::try_from(urls.len()).map_err(|_| ProductionChildCompositionErrorV1::Endpoints)?);
    for url in urls {
        put_bounded(bytes, url.as_bytes(), MAX_ENDPOINT_URL_BYTES_V1)?;
    }
    bytes.extend_from_slice(&quorum.to_be_bytes());
    Ok(())
}

/// Quorum Monero observation boundary over independent loopback daemons.
///
/// An inclusion answer requires at least `quorum` daemons agreeing on the
/// exact `(height, block hash)`; confirmations are counted from the lowest
/// agreeing daemon height, the safe direction. Absence requires `quorum`
/// daemons that answered and all reported the txid unknown. A spent key
/// image at any answering daemon is reported as spent — the conservative
/// direction, since the actuator treats "spent" as inconclusive.
#[derive(Clone)]
pub(crate) struct QuorumXmrObservationPortV1 {
    readers: Vec<BlockingMoneroDaemonReaderV1>,
    quorum: usize,
    genesis: [u8; 32],
    /// Aggregate bound applied to the next trait observation. A scoped copy
    /// carries `None` so scoping never recurses.
    deadline_v26: Option<std::time::Instant>,
}

impl QuorumXmrObservationPortV1 {
    fn observation_scope_v24(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Self, XmrActuatorErrorV1> {
        require_observation_deadline_v24(deadline)?;
        let readers = self
            .readers
            .iter()
            .map(|reader| {
                require_observation_deadline_v24(deadline)?;
                reader
                    .with_observation_deadline_v24(deadline)
                    .map_err(|_| XmrActuatorErrorV1::ObservationUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        require_observation_deadline_v24(deadline)?;
        Ok(Self {
            readers,
            quorum: self.quorum,
            genesis: self.genesis,
            deadline_v26: None,
        })
    }

    /// Same original deadline for all voters and all nested RPCs. A timed-out
    /// operation cannot emit inclusion or manufacture absence.
    pub(crate) fn transaction_inclusion_with_deadline_v24(
        &self,
        tx_hash: [u8; 32],
        deadline: std::time::Instant,
    ) -> Result<Option<XmrTxInclusionV1>, XmrActuatorErrorV1> {
        let deadline = bounded_observation_deadline_v24(deadline)?;
        let mut bounded = self.observation_scope_v24(deadline)?;
        let result = bounded.transaction_inclusion(tx_hash);
        require_observation_deadline_v24(deadline)?;
        result
    }

    /// Read exact funding bytes without extending the public-LOAD lease.
    pub(crate) fn authenticated_funding_raw_with_deadline_v24(
        &self,
        tx_hash: [u8; 32],
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, XmrActuatorErrorV1> {
        let deadline = bounded_observation_deadline_v24(deadline)?;
        let bounded = self.observation_scope_v24(deadline)?;
        let result = bounded.authenticated_funding_raw_v23(tx_hash);
        require_observation_deadline_v24(deadline)?;
        result
    }

    /// Resolve all sixteen claimed ring members under the same original bound.
    pub(crate) fn authenticate_remote_ring_with_deadline_v24(
        &self,
        claimed: &[xmr_remote_sweep_wire::RemoteRingMemberV23],
        deadline: std::time::Instant,
    ) -> Result<Vec<xmr_raw_tx_verify::RingMemberEvidenceV23>, XmrActuatorErrorV1> {
        let deadline = bounded_observation_deadline_v24(deadline)?;
        let bounded = self.observation_scope_v24(deadline)?;
        let result = bounded.authenticate_remote_ring_v23(claimed);
        require_observation_deadline_v24(deadline)?;
        result
    }

    pub(crate) fn new(
        readers: Vec<BlockingMoneroDaemonReaderV1>,
        quorum: usize,
        genesis: [u8; 32],
    ) -> Result<Self, ProductionChildCompositionErrorV1> {
        if !crate::production_xmr_quorum::valid_quorum_v5(readers.len(), quorum)
            || genesis == [0; 32]
        {
            return Err(ProductionChildCompositionErrorV1::Rpc);
        }
        let mut ports = Vec::new();
        for reader in &readers {
            let port = reader
                .loopback_port_v5()
                .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
            if ports.contains(&port) {
                return Err(ProductionChildCompositionErrorV1::Rpc);
            }
            ports.push(port);
        }
        Ok(Self {
            readers,
            quorum,
            genesis,
            deadline_v26: None,
        })
    }

    /// Resolve and authenticate every member of one modern RingCT ring. The
    /// peer's response supplies indices only as claims: a strict majority of
    /// distinct genesis-bound loopback daemons must return the exact same
    /// keys and commitments, and all sixteen are compared byte-for-byte.
    pub(crate) fn authenticate_remote_ring_v23(
        &self,
        claimed: &[xmr_remote_sweep_wire::RemoteRingMemberV23],
    ) -> Result<Vec<xmr_raw_tx_verify::RingMemberEvidenceV23>, XmrActuatorErrorV1> {
        if claimed.len() != xmr_remote_sweep_wire::RING_MEMBERS_V23
            || claimed
                .windows(2)
                .any(|pair| pair[0].global_index >= pair[1].global_index)
        {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        let indices: Vec<u64> = claimed.iter().map(|member| member.global_index).collect();
        let genesis = self.genesis;
        let votes = std::thread::scope(|scope| {
            let workers: Vec<_> = self
                .readers
                .iter()
                .map(|reader| {
                    let indices = &indices;
                    scope.spawn(move || reader.ring_members_v23(indices, genesis))
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .unwrap_or(Err(xmr_spend_port::SpendPortError::Rejected))
                })
                .collect::<Vec<_>>()
        });
        let votes = crate::production_xmr_quorum::collect_checked_votes_v8(votes)?;
        let mut groups: Vec<(Vec<xmr_rpc_broadcast_blocking::MoneroRingMemberV23>, usize)> =
            Vec::new();
        for vote in votes.into_iter().flatten() {
            if let Some(group) = groups.iter_mut().find(|group| group.0 == vote) {
                group.1 += 1;
            } else {
                groups.push((vote, 1));
            }
        }
        let winners: Vec<_> = groups
            .into_iter()
            .filter(|(_, count)| *count >= self.quorum)
            .collect();
        let [(winner, _)] = winners.as_slice() else {
            return Err(XmrActuatorErrorV1::ObservationUnavailable);
        };
        if winner.len() != claimed.len()
            || winner.iter().zip(claimed).any(|(actual, expected)| {
                actual.global_index != expected.global_index
                    || actual.key != expected.key
                    || actual.commitment != expected.commitment
            })
        {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        Ok(winner
            .iter()
            .map(|member| xmr_raw_tx_verify::RingMemberEvidenceV23 {
                global_index: member.global_index,
                key: member.key,
                commitment: member.commitment,
            })
            .collect())
    }

    /// Fetch exact funding bytes from the same strict-majority, distinct-node
    /// Mainnet quorum. This is independent of the remote signer response.
    pub(crate) fn authenticated_funding_raw_v23(
        &self,
        funding_tx_hash: [u8; 32],
    ) -> Result<Vec<u8>, XmrActuatorErrorV1> {
        if funding_tx_hash == [0; 32] {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        let genesis = self.genesis;
        let votes = std::thread::scope(|scope| {
            let workers: Vec<_> = self
                .readers
                .iter()
                .map(|reader| {
                    scope.spawn(move || reader.transaction_raw_v23(funding_tx_hash, genesis))
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .unwrap_or(Err(xmr_spend_port::SpendPortError::Rejected))
                })
                .collect::<Vec<_>>()
        });
        let votes = crate::production_xmr_quorum::collect_checked_votes_v8(votes)?;
        let mut groups: Vec<(Vec<u8>, usize)> = Vec::new();
        for vote in votes.into_iter().flatten() {
            if let Some(group) = groups.iter_mut().find(|group| group.0 == vote) {
                group.1 += 1;
            } else {
                groups.push((vote, 1));
            }
        }
        let mut winners = groups
            .into_iter()
            .filter(|(_, count)| *count >= self.quorum);
        let (winner, _) = winners
            .next()
            .ok_or(XmrActuatorErrorV1::ObservationUnavailable)?;
        if winners.next().is_some() {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        Ok(winner)
    }
}

fn bounded_observation_deadline_v24(
    original: std::time::Instant,
) -> Result<std::time::Instant, XmrActuatorErrorV1> {
    require_observation_deadline_v24(original)?;
    let cap = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(60))
        .ok_or(XmrActuatorErrorV1::ObservationUnavailable)?;
    Ok(original.min(cap))
}

fn require_observation_deadline_v24(
    deadline: std::time::Instant,
) -> Result<(), XmrActuatorErrorV1> {
    if deadline <= std::time::Instant::now() {
        Err(XmrActuatorErrorV1::ObservationUnavailable)
    } else {
        Ok(())
    }
}

impl core::fmt::Debug for QuorumXmrObservationPortV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QuorumXmrObservationPortV1")
            .field("quorum", &self.quorum)
            .finish_non_exhaustive()
    }
}

impl XmrObservationPortV1 for QuorumXmrObservationPortV1 {
    fn set_observation_deadline_v26(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<(), XmrActuatorErrorV1> {
        require_observation_deadline_v24(deadline)?;
        self.deadline_v26 = Some(bounded_observation_deadline_v24(deadline)?);
        Ok(())
    }

    fn transaction_inclusion(
        &mut self,
        tx_hash: [u8; 32],
    ) -> Result<Option<XmrTxInclusionV1>, XmrActuatorErrorV1> {
        // One observation fans out over several daemon calls, each with its
        // own transport timeout; only an aggregate bound stops their sum from
        // outliving the caller's lease. A scoped copy carries no deadline of
        // its own, so this delegation cannot recurse.
        if let Some(deadline) = self.deadline_v26 {
            return self.transaction_inclusion_with_deadline_v24(tx_hash, deadline);
        }
        let genesis = self.genesis;
        let votes = std::thread::scope(|scope| {
            let workers: Vec<_> = self
                .readers
                .iter()
                .map(|reader| {
                    scope.spawn(move || reader.transaction_observation_v5(tx_hash, genesis))
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .unwrap_or(Err(xmr_spend_port::SpendPortError::Rejected))
                })
                .collect::<Vec<_>>()
        });
        let votes = crate::production_xmr_quorum::collect_checked_votes_v8(votes)?;
        crate::production_xmr_quorum::decide_inclusion_v5(&votes, self.quorum)
    }

    fn key_image_spent(&mut self, key_image: [u8; 32]) -> Result<bool, XmrActuatorErrorV1> {
        if let Some(deadline) = self.deadline_v26 {
            let mut bounded = self.observation_scope_v24(deadline)?;
            let result = bounded.key_image_spent(key_image);
            require_observation_deadline_v24(deadline)?;
            return result;
        }
        let genesis = self.genesis;
        let votes = std::thread::scope(|scope| {
            let workers: Vec<_> = self
                .readers
                .iter()
                .map(|reader| {
                    scope.spawn(move || reader.key_image_spent_on_chain_v5(key_image, genesis))
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .unwrap_or(Err(xmr_spend_port::SpendPortError::Rejected))
                })
                .collect::<Vec<_>>()
        });
        let votes = crate::production_xmr_quorum::collect_checked_votes_v8(votes)?;
        crate::production_xmr_quorum::decide_key_image_v5(&votes, self.quorum)
    }
}

fn authority_id_v1(
    route_id: Digest32,
    face_tag: u8,
) -> Result<Digest32, ProductionChildCompositionErrorV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    hasher.update(AUTHORITY_ID_DOMAIN_V1);
    hasher.update(&route_id);
    hasher.update(&[face_tag]);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    if out == [0u8; 32] {
        return Err(ProductionChildCompositionErrorV1::Store);
    }
    Ok(out)
}

/// The composed counterparty children, one per authenticated route face.
///
/// The DOM child and therefore the full
/// [`ProductionSettlementChildRouterV1`] are absent by design: they await
/// the real F6/Relay authorities. See the module documentation.
pub(crate) struct ProductionCounterpartyChildrenV1 {
    pub(crate) evm: Option<AuthenticatedEvmChildPortV1>,
    pub(crate) bitcoin: Option<AuthenticatedBitcoinChildPortV1>,
    pub(crate) solana: Option<AuthenticatedSolanaChildPortV1>,
    pub(crate) monero: Option<AuthenticatedXmrChildPortV1>,
    /// Per-leg counterparty refund faces, in [upstream, downstream] order,
    /// built from the same authorities as the children so exclusive stores
    /// are opened exactly once.
    pub(crate) refund_faces: [Option<ProductionCounterpartyRefundFaceV1>; 2],
}

impl core::fmt::Debug for ProductionCounterpartyChildrenV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionCounterpartyChildrenV1")
            .field("evm", &self.evm.is_some())
            .field("bitcoin", &self.bitcoin.is_some())
            .field("solana", &self.solana.is_some())
            .field("monero", &self.monero.is_some())
            .field(
                "refund_faces",
                &[
                    self.refund_faces[0].is_some(),
                    self.refund_faces[1].is_some(),
                ],
            )
            .finish()
    }
}

impl ProductionCounterpartyChildrenV1 {
    /// Assembles the full child router the moment a real DOM child exists.
    ///
    /// Kept here so the one remaining step is visible in the type system:
    /// everything but its first argument is already constructed.
    #[allow(dead_code)]
    pub(crate) fn into_router(
        self,
        dom: crate::production_child_router::AuthenticatedDomChildPortV1,
    ) -> Result<ProductionSettlementChildRouterV1, settlement_coordinator::ChildAuthorityRefusalV1>
    {
        ProductionSettlementChildRouterV1::new_with_all_counterparties(
            dom,
            self.evm,
            self.bitcoin,
            self.solana,
            self.monero,
        )
    }
}

/// Everything the composition needs, all of it already authenticated or
/// provisioned by the caller. No secret enters here: the EVM and Bitcoin
/// signing keys stay wherever they live, because drive-form children only
/// retransmit, observe and reconcile exact retained bytes.
pub(crate) struct ProductionCounterpartyCompositionRequestV1<'a> {
    pub(crate) inputs: &'a AuthenticatedProductionInputsV1,
    pub(crate) endpoints: &'a ProductionChainEndpointsV1,
    pub(crate) evm_actuator: Option<evm_actuator::DurableEvmActuatorV1>,
    pub(crate) bitcoin_actuator: Option<btc_actuator::DurableBitcoinActuatorV1>,
    pub(crate) bitcoin_prebroadcast_path: Option<&'a Path>,
    pub(crate) solana_store_path: Option<&'a Path>,
    pub(crate) xmr_store_path: Option<&'a Path>,
    /// Native enrollment requires the retained, revalidating Contracts owner.
    pub(crate) native_xmr_owner_v23:
        Option<&'a crate::production_relay_stage12::ProductionRelayStage12OwnerV1>,
    pub(crate) owner_id: Digest32,
    pub(crate) now_unix_ms: u64,
    pub(crate) actuator_lease_ms: u64,
    pub(crate) external_call_timeout_ms: u64,
}

/// Composes the counterparty children for exactly the authenticated legs.
///
/// The artifact's face set must equal the route's face set: an endpoint for
/// a face the route did not admit is refused rather than ignored, so a
/// deployment cannot quietly hold credentials it has no admitted use for.
pub(crate) fn compose_production_counterparty_children_v1(
    mut request: ProductionCounterpartyCompositionRequestV1<'_>,
) -> Result<ProductionCounterpartyChildrenV1, ProductionChildCompositionErrorV1> {
    let inputs = request.inputs;
    let route_id = inputs.admission().route_id();
    let mut children = ProductionCounterpartyChildrenV1 {
        evm: None,
        bitcoin: None,
        solana: None,
        monero: None,
        refund_faces: [None, None],
    };
    for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
        .into_iter()
        .enumerate()
    {
        if inputs.evm_session(leg).is_some() {
            if children.evm.is_some() {
                // One durable EVM child carries one settlement; a route with
                // two EVM legs needs a second store this layout does not
                // provision. Refused, never split silently.
                return Err(ProductionChildCompositionErrorV1::Capability);
            }
            let (child, face) = compose_evm_child(&mut request, leg)?;
            children.evm = Some(child);
            children.refund_faces[index] = Some(face);
        } else if inputs.bitcoin_session(leg).is_some() {
            if children.bitcoin.is_some() {
                return Err(ProductionChildCompositionErrorV1::Capability);
            }
            let (child, face) = compose_bitcoin_child(&mut request, leg)?;
            children.bitcoin = Some(child);
            children.refund_faces[index] = Some(face);
        } else if inputs.solana_session(leg).is_some() {
            if children.solana.is_some() {
                return Err(ProductionChildCompositionErrorV1::Capability);
            }
            let (child, face) = compose_solana_child(&mut request, leg, route_id)?;
            children.solana = Some(child);
            children.refund_faces[index] = Some(face);
        } else if inputs.monero_session(leg).is_some() {
            if children.monero.is_some() {
                return Err(ProductionChildCompositionErrorV1::Capability);
            }
            let (child, face) = compose_monero_child(&mut request, leg, route_id)?;
            children.monero = Some(child);
            children.refund_faces[index] = Some(face);
        } else {
            return Err(ProductionChildCompositionErrorV1::Capability);
        }
    }
    // Exact face binding: every configured endpoint face must have produced
    // a child, and every child a face. Extra credentials are a refusal.
    if request.endpoints.evm.is_some() != children.evm.is_some()
        || request.endpoints.bitcoin.is_some() != children.bitcoin.is_some()
        || request.endpoints.solana.is_some() != children.solana.is_some()
        || request.endpoints.monero.is_some() != children.monero.is_some()
    {
        return Err(ProductionChildCompositionErrorV1::FaceMismatch);
    }
    Ok(children)
}

/// Per-leg resource bundle. The two bundles must reference the same admitted
/// route but own independent actuators/paths; endpoints need not be identical
/// when both legs use the same family (for example two EVM networks).
pub(crate) struct ProductionCounterpartyCompositionRequestV4<'a> {
    pub(crate) upstream: ProductionCounterpartyCompositionRequestV1<'a>,
    pub(crate) downstream: ProductionCounterpartyCompositionRequestV1<'a>,
}

/// Both real drive-form children and their refund owners, preserved together.
/// This does not grant fresh signing or replace the root's readiness protocol.
pub(crate) struct ProductionCounterpartyChildrenV4 {
    upstream: crate::production_child_router::AuthenticatedCounterpartyChildPortV4,
    downstream: crate::production_child_router::AuthenticatedCounterpartyChildPortV4,
    refund_faces: [ProductionCounterpartyRefundFaceV1; 2],
}

impl ProductionCounterpartyChildrenV4 {
    #[expect(
        dead_code,
        reason = "V4 multi-leg factory awaits generalized root provisioning"
    )]
    pub(crate) fn into_router_and_refunds(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        dom: crate::production_child_router::AuthenticatedDomChildPortV1,
    ) -> Result<
        (
            ProductionSettlementChildRouterV1,
            [ProductionCounterpartyRefundFaceV1; 2],
        ),
        settlement_coordinator::ChildAuthorityRefusalV1,
    > {
        let router = ProductionSettlementChildRouterV1::new_for_route_v4(
            inputs,
            dom,
            self.upstream,
            self.downstream,
        )?;
        Ok((router, self.refund_faces))
    }
}

/// Open both selected chains, with all resource-shape checks before any RPC
/// or lease mutation. Reuses the real constructors, including quorum, signed
/// deployment, armed Bitcoin funding and Monero refund checks.
#[expect(
    dead_code,
    reason = "V4 multi-leg factory awaits generalized root provisioning"
)]
pub(crate) fn compose_production_counterparty_children_v4(
    mut request: ProductionCounterpartyCompositionRequestV4<'_>,
) -> Result<ProductionCounterpartyChildrenV4, ProductionChildCompositionErrorV1> {
    let topology = crate::production_route_topology::ProductionRouteTopologyV4::authenticate(
        request.upstream.inputs,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let other = crate::production_route_topology::ProductionRouteTopologyV4::authenticate(
        request.downstream.inputs,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    if topology != other {
        return Err(ProductionChildCompositionErrorV1::Capability);
    }
    require_leg_resources_v4(&request.upstream, topology.legs[0].face)?;
    require_leg_resources_v4(&request.downstream, topology.legs[1].face)?;
    let paths = [
        request.upstream.bitcoin_prebroadcast_path,
        request.upstream.solana_store_path,
        request.upstream.xmr_store_path,
        request.downstream.bitcoin_prebroadcast_path,
        request.downstream.solana_store_path,
        request.downstream.xmr_store_path,
    ];
    require_distinct_store_paths_v4(&paths)?;
    let (upstream, upstream_refund) = compose_one_leg_v4(&mut request.upstream, LegIdV1::Upstream)?;
    let (downstream, downstream_refund) =
        compose_one_leg_v4(&mut request.downstream, LegIdV1::Downstream)?;
    Ok(ProductionCounterpartyChildrenV4 {
        upstream,
        downstream,
        refund_faces: [upstream_refund, downstream_refund],
    })
}

fn require_distinct_store_paths_v4(
    paths: &[Option<&Path>],
) -> Result<(), ProductionChildCompositionErrorV1> {
    let mut identities = Vec::new();
    #[cfg(unix)]
    let mut inodes = Vec::new();
    for path in paths.iter().flatten() {
        // Existing hard links have different canonical names but one journal.
        // A dangling symlink is never a legitimate fresh-store destination.
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() && !path.exists() {
                    return Err(ProductionChildCompositionErrorV1::Store);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let meta = std::fs::metadata(path)
                        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
                    let identity = (meta.dev(), meta.ino());
                    if inodes.contains(&identity) {
                        return Err(ProductionChildCompositionErrorV1::Store);
                    }
                    inodes.push(identity);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProductionChildCompositionErrorV1::Store),
        }
        let identity = match path.canonicalize() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .ok_or(ProductionChildCompositionErrorV1::Store)?;
                let name = path
                    .file_name()
                    .ok_or(ProductionChildCompositionErrorV1::Store)?;
                parent
                    .canonicalize()
                    .map_err(|_| ProductionChildCompositionErrorV1::Store)?
                    .join(name)
            }
            Err(_) => return Err(ProductionChildCompositionErrorV1::Store),
        };
        if identities.contains(&identity) {
            return Err(ProductionChildCompositionErrorV1::Store);
        }
        identities.push(identity);
    }
    Ok(())
}

fn require_leg_resources_v4(
    request: &ProductionCounterpartyCompositionRequestV1<'_>,
    face: settlement_coordinator::SettlementFaceV1,
) -> Result<(), ProductionChildCompositionErrorV1> {
    use settlement_coordinator::SettlementFaceV1 as Face;
    let endpoints = request.endpoints;
    if request.owner_id == [0; 32]
        || request.now_unix_ms == 0
        || request.actuator_lease_ms == 0
        || request.external_call_timeout_ms == 0
        || request
            .now_unix_ms
            .checked_add(request.actuator_lease_ms)
            .is_none()
        || endpoints.evm.is_some() != (face == Face::Evm)
        || endpoints.bitcoin.is_some() != (face == Face::Bitcoin)
        || endpoints.solana.is_some() != (face == Face::Solana)
        || endpoints.monero.is_some() != (face == Face::Monero)
        || request.evm_actuator.is_some() != (face == Face::Evm)
        || request.bitcoin_actuator.is_some() != (face == Face::Bitcoin)
        || request.bitcoin_prebroadcast_path.is_some() != (face == Face::Bitcoin)
        || request.solana_store_path.is_some() != (face == Face::Solana)
        || request.xmr_store_path.is_some() != (face == Face::Monero)
    {
        return Err(ProductionChildCompositionErrorV1::FaceMismatch);
    }
    // Run the bounded canonical validator before constructing clients.
    endpoints.canonical_bytes()?;
    Ok(())
}

fn compose_one_leg_v4(
    request: &mut ProductionCounterpartyCompositionRequestV1<'_>,
    leg: LegIdV1,
) -> Result<
    (
        crate::production_child_router::AuthenticatedCounterpartyChildPortV4,
        ProductionCounterpartyRefundFaceV1,
    ),
    ProductionChildCompositionErrorV1,
> {
    use crate::production_child_router::AuthenticatedCounterpartyChildPortV4 as Port;
    // A settlement-specific namespace prevents same-family authorities from
    // sharing an id even if the public network/profile are identical.
    let authority_scope = leg_settlement_id(request.inputs, leg);
    if request.inputs.evm_session(leg).is_some() {
        let (port, refund) = compose_evm_child(request, leg)?;
        Ok((Port::Evm(port), refund))
    } else if request.inputs.bitcoin_session(leg).is_some() {
        let (port, refund) = compose_bitcoin_child(request, leg)?;
        Ok((Port::Bitcoin(port), refund))
    } else if request.inputs.solana_session(leg).is_some() {
        let (port, refund) = compose_solana_child(request, leg, authority_scope)?;
        Ok((Port::Solana(port), refund))
    } else if request.inputs.monero_session(leg).is_some() {
        let (port, refund) = compose_monero_child(request, leg, authority_scope)?;
        Ok((Port::Monero(port), refund))
    } else {
        Err(ProductionChildCompositionErrorV1::Capability)
    }
}

fn leg_settlement_id(inputs: &AuthenticatedProductionInputsV1, leg: LegIdV1) -> Digest32 {
    match leg {
        LegIdV1::Upstream => inputs.composition().upstream().settlement_id.0,
        LegIdV1::Downstream => inputs.composition().downstream().settlement_id.0,
    }
}

fn compose_evm_child(
    request: &mut ProductionCounterpartyCompositionRequestV1<'_>,
    leg: LegIdV1,
) -> Result<
    (
        AuthenticatedEvmChildPortV1,
        ProductionCounterpartyRefundFaceV1,
    ),
    ProductionChildCompositionErrorV1,
> {
    let inputs = request.inputs;
    let session = inputs
        .evm_session(leg)
        .ok_or(ProductionChildCompositionErrorV1::Capability)?;
    let deployment = inputs
        .admission()
        .evm_deployment_capability(leg, session)
        .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let endpoints = request
        .endpoints
        .evm
        .as_ref()
        .ok_or(ProductionChildCompositionErrorV1::FaceMismatch)?;
    let rpc = evm_actuator::HttpEvmRpcV1::new(&endpoints.url)
        .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let mut actuator = request
        .evm_actuator
        .take()
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let funder_lease = actuator
        .acquire_lease_for_role(
            &deployment,
            evm_actuator::EvmSignerRoleV1::Funder,
            request.owner_id,
            request.now_unix_ms,
            request.actuator_lease_ms,
        )
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?
        .lease();
    let beneficiary_lease = actuator
        .acquire_lease_for_role(
            &deployment,
            evm_actuator::EvmSignerRoleV1::Beneficiary,
            request.owner_id,
            request.now_unix_ms,
            request.actuator_lease_ms,
        )
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?
        .lease();
    let timeout_seconds = request.external_call_timeout_ms.div_ceil(1000).max(1);
    let face =
        ProductionEvmRefundFaceV1::connect(endpoints.url.clone(), timeout_seconds, deployment)
            .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    let port = crate::production_child_evm::ProductionEvmChildPortV1::new(
        actuator,
        rpc,
        deployment,
        funder_lease,
        beneficiary_lease,
        crate::production_child_evm::SystemProductionEvmChildClockV1,
        leg_settlement_id(inputs, leg),
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    Ok((
        ProductionSettlementChildRouterV1::authenticate_evm(port),
        ProductionCounterpartyRefundFaceV1::Evm(face),
    ))
}

fn compose_bitcoin_child(
    request: &mut ProductionCounterpartyCompositionRequestV1<'_>,
    leg: LegIdV1,
) -> Result<
    (
        AuthenticatedBitcoinChildPortV1,
        ProductionCounterpartyRefundFaceV1,
    ),
    ProductionChildCompositionErrorV1,
> {
    let inputs = request.inputs;
    let admission = inputs.admission();
    let deployment = admission
        .bitcoin_deployment_capability(leg)
        .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let endpoints = request
        .endpoints
        .bitcoin
        .as_ref()
        .ok_or(ProductionChildCompositionErrorV1::FaceMismatch)?;
    let expected_network = match deployment.profile().kind {
        chain_profile::ChainKindV1::Bitcoin { network } => match network {
            adapter_btc::types::BitcoinNetworkV1::Regtest => {
                adapter_btc_live::BitcoinCoreNetworkV1::Regtest
            }
            adapter_btc::types::BitcoinNetworkV1::PublicSignet => {
                adapter_btc_live::BitcoinCoreNetworkV1::PublicSignet
            }
            adapter_btc::types::BitcoinNetworkV1::CustomSignet => {
                adapter_btc_live::BitcoinCoreNetworkV1::CustomSignet
            }
        },
        _ => return Err(ProductionChildCompositionErrorV1::Capability),
    };
    let signet_challenge = deployment.deployment().signet_challenge.clone();
    let client = BitcoinCoreRpcClientV1::connect(BitcoinCoreRpcConfigV1 {
        endpoint: endpoints.endpoint.clone(),
        wallet_name: endpoints.wallet_name.clone(),
        cookie_file: std::path::PathBuf::from(&endpoints.cookie_file),
        expected_network,
        expected_genesis_hash: deployment.deployment().genesis_hash,
        expected_signet_challenge: (!signet_challenge.is_empty()).then_some(signet_challenge),
    })
    .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    client
        .require_chain_identity()
        .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let prebroadcast_path = request
        .bitcoin_prebroadcast_path
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let store = BitcoinPrebroadcastStoreV1::open_or_create(prebroadcast_path)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let route_binding = production_bitcoin_refund_route_binding_v1(
        admission.route_id(),
        inputs.composition(),
        leg,
        &deployment,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let armed = match store
        .reopen(&client, route_binding)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?
    {
        Some(ReopenedBitcoinFundingV1::Armed(armed)) => armed,
        Some(ReopenedBitcoinFundingV1::Prepared(_)) | None => {
            return Err(ProductionChildCompositionErrorV1::FundingNotArmed);
        }
    };
    let store = Rc::new(store);
    let client = Rc::new(client);
    let face = ProductionBitcoinRefundFaceV1::new(
        Rc::clone(&store),
        Rc::clone(&client),
        deployment.clone(),
        &armed,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    let funding = ProductionBitcoinFundingAuthorityV1::new(
        Rc::clone(&store),
        Rc::clone(&client),
        armed,
        admission,
        inputs.composition(),
        leg,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    let mut actuator = request
        .bitcoin_actuator
        .take()
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let lease = actuator
        .acquire_lease(request.now_unix_ms, request.actuator_lease_ms)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let rpc =
        btc_actuator::HttpBitcoinCoreRpcV1::connect(btc_actuator::HttpBitcoinCoreRpcConfigV1 {
            endpoint: endpoints.endpoint.clone(),
            cookie_path: std::path::PathBuf::from(&endpoints.cookie_file),
        })
        .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let port = crate::production_child_btc::ProductionBitcoinChildPortV1::new(
        actuator,
        rpc,
        lease,
        crate::production_child_btc::SystemProductionBitcoinChildClockV1,
        funding,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    Ok((
        ProductionSettlementChildRouterV1::authenticate_bitcoin(port),
        ProductionCounterpartyRefundFaceV1::Bitcoin(face),
    ))
}

fn compose_solana_child(
    request: &mut ProductionCounterpartyCompositionRequestV1<'_>,
    leg: LegIdV1,
    route_id: Digest32,
) -> Result<
    (
        AuthenticatedSolanaChildPortV1,
        ProductionCounterpartyRefundFaceV1,
    ),
    ProductionChildCompositionErrorV1,
> {
    let inputs = request.inputs;
    let session = inputs
        .solana_session(leg)
        .ok_or(ProductionChildCompositionErrorV1::Capability)?;
    let deployment = inputs
        .admission()
        .solana_deployment_capability(leg)
        .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let endpoints = request
        .endpoints
        .solana
        .as_ref()
        .ok_or(ProductionChildCompositionErrorV1::FaceMismatch)?;
    // The authenticated adapter profile governs the quorum shape; an
    // artifact that disagrees with what the frozen terms committed to is a
    // misconfiguration, never an override.
    let profile = session.profile();
    if endpoints.node_urls.len() != usize::from(profile.rpc_node_count)
        || endpoints.quorum != profile.rpc_quorum
    {
        return Err(ProductionChildCompositionErrorV1::FaceMismatch);
    }
    let max_signed = usize::try_from(profile.max_signed_transaction_bytes)
        .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let mut nodes = Vec::with_capacity(endpoints.node_urls.len());
    for url in &endpoints.node_urls {
        nodes.push(Arc::new(
            HttpSolanaRpc::new(url.clone(), max_signed)
                .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?,
        ));
    }
    let pool = SolanaRpcPool::new(nodes, usize::from(endpoints.quorum))
        .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let store_path = request
        .solana_store_path
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let store = SolanaOperationStoreV1::open(store_path)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let actuator = DurableSolanaActuatorV1::new(store);
    let genesis_hash = deployment.deployment().genesis_hash;
    let authority_id = authority_id_v1(route_id, 5)?;
    // The composition clock is the fence: every later composition under the
    // same owner takes over with a strictly higher epoch, which is exactly
    // what the actuator's stale-fence refusal wants.
    let lease_until = request
        .now_unix_ms
        .checked_add(request.actuator_lease_ms)
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let funder_lease = SolanaActuatorLeaseV1::new(
        authority_id,
        request.owner_id,
        genesis_hash,
        session.setup().binding().funder,
        request.now_unix_ms,
        lease_until,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let beneficiary_lease = SolanaActuatorLeaseV1::new(
        authority_id,
        request.owner_id,
        genesis_hash,
        session.setup().binding().recipient,
        request.now_unix_ms,
        lease_until,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let face = ProductionSolanaRefundFaceV1::new(
        pool.clone(),
        session.setup().clone(),
        deployment.clone(),
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    let port = ProductionSolanaChildPortV1::new(
        actuator,
        pool,
        deployment,
        session.setup().clone(),
        funder_lease,
        beneficiary_lease,
        SystemProductionSolanaChildClockV1,
    )
    .and_then(|port| port.bind_route_v7(inputs, leg))
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    Ok((
        ProductionSettlementChildRouterV1::authenticate_solana(port),
        ProductionCounterpartyRefundFaceV1::Solana(face),
    ))
}

fn compose_monero_child(
    request: &mut ProductionCounterpartyCompositionRequestV1<'_>,
    leg: LegIdV1,
    route_id: Digest32,
) -> Result<
    (
        AuthenticatedXmrChildPortV1,
        ProductionCounterpartyRefundFaceV1,
    ),
    ProductionChildCompositionErrorV1,
> {
    let inputs = request.inputs;
    // Authenticate before opening RPC clients or mutable journals.
    let refund_bundle = crate::production_xmr_compensation::resolve_xmr_refund_bundle_v23(
        inputs,
        leg,
        request.native_xmr_owner_v23,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::RefundArmNotRegistered)?;
    let session = inputs
        .monero_session(leg)
        .ok_or(ProductionChildCompositionErrorV1::Capability)?;
    let deployment = inputs
        .admission()
        .monero_deployment_capability(leg)
        .map_err(|_| ProductionChildCompositionErrorV1::Capability)?;
    let endpoints = request
        .endpoints
        .monero
        .as_ref()
        .ok_or(ProductionChildCompositionErrorV1::FaceMismatch)?;
    let profile = session.profile();
    if endpoints.daemon_urls.len() != usize::from(profile.rpc_node_count)
        || endpoints.quorum != profile.rpc_quorum
    {
        return Err(ProductionChildCompositionErrorV1::FaceMismatch);
    }
    let broadcast = BlockingMoneroBroadcaster::new_for_chain_v5(
        endpoints
            .daemon_urls
            .first()
            .ok_or(ProductionChildCompositionErrorV1::Rpc)?
            .clone(),
        deployment.deployment().genesis_hash,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?;
    let mut readers = Vec::with_capacity(endpoints.daemon_urls.len());
    for url in &endpoints.daemon_urls {
        readers.push(
            BlockingMoneroDaemonReaderV1::new(url.clone())
                .map_err(|_| ProductionChildCompositionErrorV1::Rpc)?,
        );
    }
    let observation = QuorumXmrObservationPortV1::new(
        readers,
        usize::from(endpoints.quorum),
        deployment.deployment().genesis_hash,
    )?;
    let store_path = request
        .xmr_store_path
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let store = XmrOperationStoreV1::open(store_path)
        .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let actuator = DurableXmrActuatorV1::new(store);
    let lease_until = request
        .now_unix_ms
        .checked_add(request.actuator_lease_ms)
        .ok_or(ProductionChildCompositionErrorV1::Store)?;
    let lease = XmrActuatorLeaseV1::new(
        authority_id_v1(route_id, 4)?,
        request.owner_id,
        deployment.deployment().genesis_hash,
        request.now_unix_ms,
        lease_until,
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Store)?;
    let terms = match leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let min_confirmations = u64::from(terms.counterparty_leg.finality.min_confirmations);
    let face = ProductionXmrRefundFaceV1::new(
        *session.profile(),
        session.setup().clone(),
        deployment.clone(),
        refund_bundle.proof.clone(),
        XmrRefundArtifactV1 {
            template_hash: refund_bundle.template_hash,
            adaptor_point_sec1: refund_bundle.adaptor_point_sec1,
            executor_profile_hash: refund_bundle.executor_profile_hash,
            deadline: refund_bundle.deadline,
        },
    )
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    let port = ProductionXmrChildPortV1::new(
        actuator,
        broadcast,
        observation,
        deployment,
        session.setup().clone(),
        lease,
        min_confirmations,
        SystemProductionXmrChildClockV1,
    )
    .and_then(|port| port.bind_route_v7(inputs, leg))
    .map_err(|_| ProductionChildCompositionErrorV1::Child)?;
    Ok((
        ProductionSettlementChildRouterV1::authenticate_monero(port),
        ProductionCounterpartyRefundFaceV1::Monero(face),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_observation_deadline_expiry_contacts_no_voter_v24(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listeners = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
            .collect::<Result<Vec<_>, _>>()?;
        let readers = listeners
            .iter()
            .map(|listener| {
                listener.set_nonblocking(true)?;
                let url = format!("http://{}", listener.local_addr()?);
                Ok(BlockingMoneroDaemonReaderV1::new(url)?)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let quorum = QuorumXmrObservationPortV1::new(readers, 2, [1; 32])?;
        let deadline = std::time::Instant::now();
        assert!(matches!(
            quorum.transaction_inclusion_with_deadline_v24([2; 32], deadline),
            Err(XmrActuatorErrorV1::ObservationUnavailable)
        ));
        assert!(matches!(
            quorum.authenticated_funding_raw_with_deadline_v24([2; 32], deadline),
            Err(XmrActuatorErrorV1::ObservationUnavailable)
        ));
        assert!(matches!(
            quorum.authenticate_remote_ring_with_deadline_v24(&[], deadline),
            Err(XmrActuatorErrorV1::ObservationUnavailable)
        ));
        for listener in listeners {
            assert_eq!(
                listener.accept().err().map(|error| error.kind()),
                Some(std::io::ErrorKind::WouldBlock)
            );
        }
        Ok(())
    }

    #[test]
    fn monero_v5_requires_majority_nonzero_genesis_and_distinct_endpoint_ports() {
        let readers = |urls: &[&str]| {
            urls.iter()
                .map(|url| BlockingMoneroDaemonReaderV1::new(*url).expect("local client"))
                .collect::<Vec<_>>()
        };
        let distinct = [
            "http://127.0.0.1:18081",
            "http://127.0.0.1:18082",
            "http://127.0.0.1:18083",
        ];
        assert!(QuorumXmrObservationPortV1::new(readers(&distinct), 2, [1; 32]).is_ok());
        assert!(QuorumXmrObservationPortV1::new(readers(&distinct), 1, [1; 32]).is_err());
        assert!(QuorumXmrObservationPortV1::new(readers(&distinct), 2, [0; 32]).is_err());
        for alias in [
            "http://localhost:18081",
            "http://[::1]:18081",
            "http://127.0.0.1:18081/",
        ] {
            assert!(
                QuorumXmrObservationPortV1::new(readers(&[distinct[0], alias]), 2, [1; 32])
                    .is_err()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn two_leg_store_preflight_rejects_path_symlink_and_hardlink_aliases() {
        use std::{
            fs,
            os::unix::fs::symlink,
            time::{SystemTime, UNIX_EPOCH},
        };
        let dir = std::env::temp_dir().join(format!(
            "dom-v4-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&dir).expect("private test directory");
        let first = dir.join("upstream.sqlite");
        let second = dir.join("downstream.sqlite");
        assert!(require_distinct_store_paths_v4(&[Some(&first), Some(&second)]).is_ok());
        assert!(require_distinct_store_paths_v4(&[Some(&first), Some(&first)]).is_err());
        fs::write(&first, b"journal").expect("journal");
        fs::hard_link(&first, &second).expect("hard link");
        assert!(require_distinct_store_paths_v4(&[Some(&first), Some(&second)]).is_err());
        fs::remove_file(&second).expect("remove alias");
        symlink(&first, &second).expect("symbolic link");
        assert!(require_distinct_store_paths_v4(&[Some(&first), Some(&second)]).is_err());
        fs::remove_file(&first).expect("make dangling link");
        assert!(require_distinct_store_paths_v4(&[Some(&second)]).is_err());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    fn full_artifact() -> ProductionChainEndpointsV1 {
        ProductionChainEndpointsV1 {
            evm: Some(EvmEndpointsV1 {
                url: "http://127.0.0.1:8545".to_string(),
            }),
            bitcoin: Some(BitcoinEndpointsV1 {
                endpoint: "http://127.0.0.1:18443/".to_string(),
                wallet_name: "route".to_string(),
                cookie_file: "/var/lib/bitcoin/regtest/.cookie".to_string(),
            }),
            solana: Some(SolanaEndpointsV1 {
                node_urls: vec![
                    "http://127.0.0.1:8899".to_string(),
                    "http://127.0.0.1:8901".to_string(),
                ],
                quorum: 2,
            }),
            monero: Some(MoneroEndpointsV1 {
                daemon_urls: vec![
                    "http://127.0.0.1:18081".to_string(),
                    "http://127.0.0.1:18082".to_string(),
                ],
                quorum: 2,
            }),
        }
    }

    #[test]
    fn chain_endpoints_round_trip_canonically_for_every_face_combination() {
        let full = full_artifact();
        let combinations = [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
            (true, true, false, false),
            (false, false, true, true),
            (true, true, true, true),
        ];
        for (evm, bitcoin, solana, monero) in combinations {
            let artifact = ProductionChainEndpointsV1 {
                evm: evm.then(|| full.evm.clone()).flatten(),
                bitcoin: bitcoin.then(|| full.bitcoin.clone()).flatten(),
                solana: solana.then(|| full.solana.clone()).flatten(),
                monero: monero.then(|| full.monero.clone()).flatten(),
            };
            let bytes = artifact.canonical_bytes().expect("encode");
            let decoded = ProductionChainEndpointsV1::decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, artifact);
            assert_eq!(decoded.canonical_bytes().expect("re-encode"), bytes);
        }
    }

    #[test]
    fn chain_endpoints_refuse_empty_trailing_and_tampered_bytes() {
        let empty = ProductionChainEndpointsV1 {
            evm: None,
            bitcoin: None,
            solana: None,
            monero: None,
        };
        assert!(empty.canonical_bytes().is_err());
        let bytes = full_artifact().canonical_bytes().expect("encode");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProductionChainEndpointsV1::decode_canonical(&trailing).is_err());
        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(ProductionChainEndpointsV1::decode_canonical(&truncated).is_err());
        // Claiming fewer faces than the bytes carry must refuse.
        let mut relabeled = bytes;
        relabeled[11] &= !0b1000;
        assert!(ProductionChainEndpointsV1::decode_canonical(&relabeled).is_err());
    }

    #[test]
    fn chain_endpoints_refuse_broken_quorums_and_oversize_fields() {
        let mut artifact = full_artifact();
        if let Some(solana) = &mut artifact.solana {
            solana.quorum = 3;
        }
        assert!(artifact.canonical_bytes().is_err());
        let mut artifact = full_artifact();
        if let Some(evm) = &mut artifact.evm {
            evm.url = "x".repeat(MAX_ENDPOINT_URL_BYTES_V1 + 1);
        }
        assert!(artifact.canonical_bytes().is_err());
        let mut artifact = full_artifact();
        if let Some(monero) = &mut artifact.monero {
            monero.daemon_urls.clear();
        }
        assert!(artifact.canonical_bytes().is_err());
    }

    #[test]
    fn authority_identity_is_domain_separated_per_face() {
        let route = [7; 32];
        let solana = authority_id_v1(route, 5).expect("solana authority");
        let monero = authority_id_v1(route, 4).expect("monero authority");
        assert_ne!(solana, monero);
        assert_ne!(solana, authority_id_v1([8; 32], 5).expect("other route"));
    }
}
