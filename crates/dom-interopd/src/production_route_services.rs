//! Position-bound live services. A service configuration grants no signing,
//! refund or F7 authority. Both positions are authenticated before RPC work.
use crate::production_chain_services::{
    bitcoin_network_identity, bounded_rpc_timeouts, validate_cookie_path, validate_endpoint_text,
    validate_wallet_name, ProductionChainClientsV1, ProductionChainServicesErrorV1 as Error,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_route_topology::ProductionRouteTopologyV4;
use deployment_registry::{
    ResolvedBitcoinDeploymentV1, ResolvedEvmDeploymentV1, ResolvedMoneroDeploymentV1,
    ResolvedSolanaDeploymentV1,
};
use route_executor::LegIdV1;
use serde::{Deserialize, Serialize};
use settlement_coordinator::SettlementFaceV1 as Face;
use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

pub(crate) const FILE_V8: &str = "production-route-services.v8.json";
const MAX_BYTES: usize = 131_072;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "family", deny_unknown_fields)]
pub(crate) enum ServiceV8 {
    #[serde(rename = "EVM")]
    Evm {
        endpoint: String,
        refund_timeout_seconds: u64,
    },
    #[serde(rename = "BTC")]
    Bitcoin {
        endpoint: String,
        wallet: String,
        cookie: PathBuf,
    },
    #[serde(rename = "SOL")]
    Solana { endpoints: Vec<String>, quorum: u16 },
    #[serde(rename = "XMR")]
    Monero { endpoints: Vec<String>, quorum: u16 },
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegServicesV8 {
    pub(crate) settlement_id: [u8; 32],
    pub(crate) chain_id: [u8; 32],
    pub(crate) service: ServiceV8,
}

/// Public local configuration, not an authority. The comparison against
/// authenticated admission happens in `bind`; a checksum cannot replace it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteServicesV8 {
    pub(crate) version: u16,
    pub(crate) route_id: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
    pub(crate) registry_digest: [u8; 32],
    pub(crate) legs: [LegServicesV8; 2],
}

impl ServiceV8 {
    fn face(&self) -> Face {
        match self {
            Self::Evm { .. } => Face::Evm,
            Self::Bitcoin { .. } => Face::Bitcoin,
            Self::Solana { .. } => Face::Solana,
            Self::Monero { .. } => Face::Monero,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Evm {
                endpoint,
                refund_timeout_seconds,
            } => {
                validate_endpoint_text(endpoint, Error::InvalidEvmEndpoint)?;
                if *refund_timeout_seconds == 0 || *refund_timeout_seconds > 300 {
                    return Err(Error::InvalidRuntimeTimeout);
                }
            }
            Self::Bitcoin {
                endpoint,
                wallet,
                cookie,
            } => {
                validate_endpoint_text(endpoint, Error::InvalidBitcoinEndpoint)?;
                validate_wallet_name(wallet)?;
                // File ownership is checked again immediately before connection.
                if !cookie.is_absolute()
                    || cookie.as_os_str().len() > 4096
                    || cookie.components().any(|c| {
                        !matches!(
                            c,
                            std::path::Component::RootDir | std::path::Component::Normal(_)
                        )
                    })
                {
                    return Err(Error::InvalidBitcoinCookie);
                }
            }
            Self::Solana { endpoints, quorum } | Self::Monero { endpoints, quorum } => {
                if !crate::production_xmr_quorum::valid_quorum_v5(
                    endpoints.len(),
                    usize::from(*quorum),
                ) {
                    return Err(Error::InvalidEncoding);
                }
                let mut seen = std::collections::BTreeSet::new();
                for endpoint in endpoints {
                    validate_endpoint_text(endpoint, Error::InvalidEncoding)?;
                    if !seen.insert(endpoint.trim_end_matches('/').to_ascii_lowercase()) {
                        return Err(Error::InvalidEncoding);
                    }
                }
            }
        }
        Ok(())
    }
}

impl RouteServicesV8 {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != 8
            || [self.route_id, self.composition_digest, self.registry_digest].contains(&[0; 32])
            || self.legs[0].settlement_id == self.legs[1].settlement_id
        {
            return Err(Error::InvalidEncoding);
        }
        for leg in &self.legs {
            if [leg.settlement_id, leg.chain_id].contains(&[0; 32]) {
                return Err(Error::InvalidEncoding);
            }
            leg.service.validate()?;
        }
        if self.legs[0].chain_id == self.legs[1].chain_id
            && self.legs[0].service.face() != self.legs[1].service.face()
        {
            return Err(Error::InvalidEncoding);
        }
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::InvalidEncoding)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_BYTES {
            return Err(Error::InvalidEncoding);
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)?;
        if value.canonical_bytes()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(value)
    }
    fn require_topology(&self, topology: &ProductionRouteTopologyV4) -> Result<(), Error> {
        self.canonical_bytes()?;
        topology.validate().map_err(|_| Error::InvalidEncoding)?;
        if self.route_id != topology.route_id
            || self.composition_digest != topology.composition_digest
            || self.registry_digest != topology.registry_digest
        {
            return Err(Error::InvalidEncoding);
        }
        for (actual, expected) in self.legs.iter().zip(topology.legs) {
            if actual.settlement_id != expected.settlement_id
                || actual.chain_id != expected.chain_id
                || actual.service.face() != expected.face
            {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok(())
    }
    pub(crate) fn bind(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        timeout_ms: u64,
    ) -> Result<SelectedServicesV8, Error> {
        let topology =
            ProductionRouteTopologyV4::authenticate(inputs).map_err(|_| Error::InvalidEncoding)?;
        self.require_topology(&topology)?;
        if timeout_ms == 0 || timeout_ms > 300_000 {
            return Err(Error::InvalidRuntimeTimeout);
        }
        let mut deployments = Vec::with_capacity(2);
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            let admission = inputs.admission();
            deployments.push(match &self.legs[index].service {
                ServiceV8::Evm {
                    refund_timeout_seconds,
                    ..
                } => {
                    bounded_rpc_timeouts(timeout_ms, *refund_timeout_seconds)?;
                    DeploymentV8::Evm(
                        admission
                            .evm_deployment_capability(
                                leg,
                                inputs.evm_session(leg).ok_or(Error::InvalidEncoding)?,
                            )
                            .map_err(|_| Error::InvalidEncoding)?,
                    )
                }
                ServiceV8::Bitcoin { .. } => DeploymentV8::Bitcoin(
                    admission
                        .bitcoin_deployment_capability(leg)
                        .map_err(|_| Error::InvalidEncoding)?,
                ),
                ServiceV8::Solana { endpoints, quorum } => {
                    let profile = inputs
                        .solana_session(leg)
                        .ok_or(Error::InvalidEncoding)?
                        .profile();
                    if endpoints.len() != usize::from(profile.rpc_node_count)
                        || *quorum != profile.rpc_quorum
                        || profile.max_signed_transaction_bytes == 0
                        || profile.max_signed_transaction_bytes > 1232
                    {
                        return Err(Error::InvalidSolanaEndpoints);
                    }
                    // These external clients have a fixed 30-second request bound.
                    if timeout_ms < 30_000 {
                        return Err(Error::InvalidRuntimeTimeout);
                    }
                    DeploymentV8::Solana(
                        admission
                            .solana_deployment_capability(leg)
                            .map_err(|_| Error::InvalidEncoding)?,
                        profile.max_signed_transaction_bytes as usize,
                    )
                }
                ServiceV8::Monero { endpoints, quorum } => {
                    let profile = inputs
                        .monero_session(leg)
                        .ok_or(Error::InvalidEncoding)?
                        .profile();
                    if endpoints.len() != usize::from(profile.rpc_node_count)
                        || *quorum != profile.rpc_quorum
                    {
                        return Err(Error::InvalidXmrEndpoints);
                    }
                    if timeout_ms < 30_000 {
                        return Err(Error::InvalidRuntimeTimeout);
                    }
                    DeploymentV8::Monero(
                        admission
                            .monero_deployment_capability(leg)
                            .map_err(|_| Error::InvalidEncoding)?,
                    )
                }
            });
        }
        let deployments = deployments.try_into().map_err(|_| Error::InvalidEncoding)?;
        Ok(SelectedServicesV8 {
            document: self,
            deployments,
            timeout_ms,
        })
    }
}

enum DeploymentV8 {
    Evm(ResolvedEvmDeploymentV1),
    Bitcoin(ResolvedBitcoinDeploymentV1),
    Solana(ResolvedSolanaDeploymentV1, usize),
    Monero(ResolvedMoneroDeploymentV1),
}

/// Neither the decoded document nor a caller's family tag can mint this type.
pub(crate) struct SelectedServicesV8 {
    document: RouteServicesV8,
    deployments: [DeploymentV8; 2],
    timeout_ms: u64,
}

#[allow(dead_code)] // Extended clients await the root's signer/F7 resource owners.
pub(crate) enum LegClientsV8 {
    Evm {
        rpc: evm_actuator::HttpEvmRpcV1,
        refund: crate::production_refund_arming::ProductionEvmRefundFaceV1,
    },
    Bitcoin {
        rpc: btc_actuator::HttpBitcoinCoreRpcV1,
        live: Rc<adapter_btc_live::BitcoinCoreRpcClientV1>,
    },
    Solana {
        pool: solana_rpc_pool::SolanaRpcPool<solana_rpc::HttpSolanaRpc>,
        deployment: ResolvedSolanaDeploymentV1,
    },
    Monero {
        broadcast: xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster,
        observation: crate::production_children::QuorumXmrObservationPortV1,
        deployment: ResolvedMoneroDeploymentV1,
    },
}

impl SelectedServicesV8 {
    pub(crate) fn xmr_funding_urls_v22(&self) -> [Option<Vec<String>>; 2] {
        std::array::from_fn(|index| match &self.document.legs[index].service {
            ServiceV8::Monero { endpoints, .. } => Some(endpoints.clone()),
            _ => None,
        })
    }

    /// Create observers only for admitted EVM/SOL positions. These are read-only
    /// clients; transaction identity is supplied later by the existing child.
    /// Native XMR instead mounts its observer from authenticated graph custody
    /// and the already-open sweep resources in Stage 12.
    pub(crate) fn f7_observer_plans_v20(
        &self,
        inputs: &AuthenticatedProductionInputsV1,
    ) -> Result<[Option<crate::production_contracts::ProductionF7ObserverPlanV20>; 2], Error> {
        use crate::production_contracts::ProductionF7ObserverPlanV20 as Plan;
        use f7_anchor_authority::families_v11::{
            EvmFundingAuthorityV11, SolanaFundingAuthorityV11,
        };
        let mut out = Vec::with_capacity(2);
        let timeout = self.timeout_ms.div_ceil(1_000).clamp(1, 120);
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            let terms = match leg {
                LegIdV1::Upstream => inputs.composition().upstream(),
                LegIdV1::Downstream => inputs.composition().downstream(),
            };
            let terms_hash = terms.terms_hash().map_err(|_| Error::InvalidEncoding)?;
            let plan = match (&self.document.legs[index].service, &self.deployments[index]) {
                (ServiceV8::Evm { endpoint, .. }, DeploymentV8::Evm(deployment)) => {
                    Some(Plan::Evm {
                        authority: EvmFundingAuthorityV11::new(
                            deployment, terms, endpoint, timeout,
                        )
                        .map_err(|_| Error::InvalidEvmEndpoint)?,
                        terms_hash,
                        // Reserve two bounded RPC calls in addition to the native
                        // F7 verifier's signed deadline/chain-window checks.
                        minimum_remaining_seconds: timeout * 2,
                    })
                }
                (ServiceV8::Solana { endpoints, .. }, DeploymentV8::Solana(deployment, _)) => {
                    let session = inputs.solana_session(leg).ok_or(Error::InvalidEncoding)?;
                    Some(Plan::Solana {
                        authority: SolanaFundingAuthorityV11::new(
                            deployment,
                            terms,
                            session.setup(),
                            session.profile().clone(),
                            endpoints,
                        )
                        .map_err(|_| Error::InvalidSolanaEndpoints)?,
                        terms_hash,
                    })
                }
                (ServiceV8::Bitcoin { .. }, DeploymentV8::Bitcoin(_))
                | (ServiceV8::Monero { .. }, DeploymentV8::Monero(_)) => None,
                _ => return Err(Error::InvalidEncoding),
            };
            out.push(plan);
        }
        out.try_into().map_err(|_| Error::InvalidEncoding)
    }

    /// Compatibility gate for the remaining V10 credential/F7 graph. It is
    /// deliberately after universal authentication and before live RPC work.
    pub(crate) fn legacy_deployments(
        &self,
    ) -> Result<(ResolvedEvmDeploymentV1, ResolvedBitcoinDeploymentV1), Error> {
        match &self.deployments {
            [DeploymentV8::Evm(evm), DeploymentV8::Bitcoin(btc)]
            | [DeploymentV8::Bitcoin(btc), DeploymentV8::Evm(evm)] => Ok((*evm, btc.clone())),
            _ => Err(Error::InvalidEncoding),
        }
    }
    pub(crate) fn into_clients(self) -> Result<[LegClientsV8; 2], Error> {
        // Preflight both cookie authorities before either Bitcoin connect.
        for leg in &self.document.legs {
            if let ServiceV8::Bitcoin { cookie, .. } = &leg.service {
                validate_cookie_path(cookie)?;
            }
        }
        let mut clients = Vec::with_capacity(2);
        for (leg, deployment) in self.document.legs.into_iter().zip(self.deployments) {
            clients.push(connect_leg(leg.service, deployment, self.timeout_ms)?);
        }
        clients.try_into().map_err(|_| Error::InvalidEncoding)
    }
    pub(crate) fn into_legacy_clients(self) -> Result<ProductionChainClientsV1, Error> {
        self.legacy_deployments()?;
        let [a, b] = self.into_clients()?;
        match (a, b) {
            (
                LegClientsV8::Evm {
                    rpc: evm,
                    refund: evm_refund,
                },
                LegClientsV8::Bitcoin {
                    rpc: bitcoin,
                    live: bitcoin_live,
                },
            )
            | (
                LegClientsV8::Bitcoin {
                    rpc: bitcoin,
                    live: bitcoin_live,
                },
                LegClientsV8::Evm {
                    rpc: evm,
                    refund: evm_refund,
                },
            ) => Ok(ProductionChainClientsV1 {
                evm,
                evm_refund,
                bitcoin,
                bitcoin_live,
            }),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

fn connect_leg(
    service: ServiceV8,
    deployment: DeploymentV8,
    timeout_ms: u64,
) -> Result<LegClientsV8, Error> {
    match (service, deployment) {
        (
            ServiceV8::Evm {
                endpoint,
                refund_timeout_seconds,
            },
            DeploymentV8::Evm(deployment),
        ) => {
            let (timeouts, _, _) = bounded_rpc_timeouts(timeout_ms, refund_timeout_seconds)?;
            let rpc = evm_actuator::HttpEvmRpcV1::new_with_timeouts(&endpoint, timeouts)
                .map_err(|_| Error::InvalidEvmEndpoint)?;
            let refund = crate::production_refund_arming::ProductionEvmRefundFaceV1::connect(
                endpoint,
                refund_timeout_seconds,
                deployment,
            )
            .map_err(|_| Error::InvalidEvmEndpoint)?;
            Ok(LegClientsV8::Evm { rpc, refund })
        }
        (
            ServiceV8::Bitcoin {
                endpoint,
                wallet,
                cookie,
            },
            DeploymentV8::Bitcoin(deployment),
        ) => {
            let duration = Duration::from_millis(timeout_ms);
            let rpc = btc_actuator::HttpBitcoinCoreRpcV1::connect_with_timeouts(
                btc_actuator::HttpBitcoinCoreRpcConfigV1 {
                    endpoint: endpoint.clone(),
                    cookie_path: cookie.clone(),
                },
                btc_actuator::HttpBitcoinCoreRpcTimeoutsV1::new(
                    Duration::from_secs(5).min(duration),
                    duration,
                )
                .map_err(|_| Error::InvalidRuntimeTimeout)?,
            )
            .map_err(|_| Error::InvalidBitcoinEndpoint)?;
            let (network, challenge) = bitcoin_network_identity(&deployment)?;
            let live = adapter_btc_live::BitcoinCoreRpcClientV1::connect_with_timeouts(
                adapter_btc_live::BitcoinCoreRpcConfigV1 {
                    endpoint,
                    wallet_name: wallet,
                    cookie_file: cookie,
                    expected_network: network,
                    expected_genesis_hash: deployment.deployment().genesis_hash,
                    expected_signet_challenge: challenge,
                },
                adapter_btc_live::BitcoinCoreRpcTimeoutsV1::new(
                    Duration::from_secs(5).min(duration),
                    duration,
                )
                .map_err(|_| Error::InvalidRuntimeTimeout)?,
            )
            .map_err(|_| Error::InvalidBitcoinEndpoint)?;
            Ok(LegClientsV8::Bitcoin {
                rpc,
                live: Rc::new(live),
            })
        }
        (ServiceV8::Solana { endpoints, quorum }, DeploymentV8::Solana(deployment, max_signed)) => {
            let nodes = endpoints
                .into_iter()
                .map(|url| {
                    solana_rpc::HttpSolanaRpc::new(url, max_signed)
                        .map(Arc::new)
                        .map_err(|_| Error::InvalidSolanaEndpoints)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let pool = solana_rpc_pool::SolanaRpcPool::new(nodes, usize::from(quorum))
                .map_err(|_| Error::InvalidSolanaEndpoints)?;
            Ok(LegClientsV8::Solana { pool, deployment })
        }
        (ServiceV8::Monero { endpoints, quorum }, DeploymentV8::Monero(deployment)) => {
            let genesis = deployment.deployment().genesis_hash;
            let broadcast =
                xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster::new_for_chain_v5(
                    endpoints.first().ok_or(Error::InvalidXmrEndpoints)?.clone(),
                    genesis,
                )
                .map_err(|_| Error::InvalidXmrEndpoints)?;
            let readers = endpoints
                .into_iter()
                .map(|url| {
                    xmr_rpc_broadcast_blocking::BlockingMoneroDaemonReaderV1::new(url)
                        .map_err(|_| Error::InvalidXmrEndpoints)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let observation = crate::production_children::QuorumXmrObservationPortV1::new(
                readers,
                usize::from(quorum),
                genesis,
            )
            .map_err(|_| Error::InvalidXmrEndpoints)?;
            Ok(LegClientsV8::Monero {
                broadcast,
                observation,
                deployment,
            })
        }
        _ => Err(Error::InvalidEncoding),
    }
}

pub(crate) fn load_selected_services_v8(
    state_dir: &Path,
    inputs: &AuthenticatedProductionInputsV1,
    timeout_ms: u64,
) -> Result<SelectedServicesV8, Error> {
    let directory =
        crate::production_config::validate_state_dir(state_dir).map_err(|_| Error::Unavailable)?;
    let path = directory.join(FILE_V8);
    let document = match std::fs::symlink_metadata(&path) {
        Ok(_) => RouteServicesV8::decode(
            &crate::production_config::read_owner_file_bounded(
                &path,
                MAX_BYTES as u64,
                crate::production_config::ProductionConfigErrorV1::InputArtifactUnavailable,
            )
            .map_err(|_| Error::Unavailable)?,
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let topology = ProductionRouteTopologyV4::authenticate(inputs)
                .map_err(|_| Error::InvalidEncoding)?;
            crate::production_chain_services::load_production_chain_services_v2(&directory)?
                .into_route_document_v8(&topology)?
        }
        Err(_) => return Err(Error::Unavailable),
    };
    document.bind(inputs, timeout_ms)
}

#[cfg(test)]
#[path = "tests/route_services_v8.rs"]
mod tests;
