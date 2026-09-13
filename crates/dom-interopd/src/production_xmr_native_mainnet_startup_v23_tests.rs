//! End-to-end ownership of the local Mainnet-profile startup preparation.
//! This runs no code at module initialization and never authorizes Relay IDs.
use super::*;
type PublicDomHistoryV24 = (
    dom_scriptless_chain_adapter::ExpectedDomIdentityV1,
    serde_json::Value,
    xmr_graph_wallet_tests::native_observation_v23::PublicDomHistoryPagesV24,
);
use crate::production_config::ProductionUniversalBootstrapFieldsV11;
use crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23;
use crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23;
use xmr_graph_wallet_tests::native_observation_v23::{
    Configuration, NativeDomSnapshotV23, NativeMainnetXmrInventorySourceV23, RouteFundingOwnerV23,
};

pub(crate) const MAINNET_BASELINE_TIP_V23: u64 = 1003;

/// Dependencies drop before the fixture that owns their private sockets/DBs.
pub(crate) struct NativeMainnetStartupV23 {
    prepared: Option<[(NativeXmrDaemonResourcesV23, NativeDaemonPlanningContextV23); 2]>,
    f6: Option<NativeF6ProvisionV23>,
    baseline: Option<NativeDomSnapshotV23>,
    funding: Option<RouteFundingOwnerV23>,
    inventory: Option<NativeMainnetXmrInventorySourceV23>,
    credentials: Option<NativeXmrDaemonCredentialsV23>,
    cold: Option<NativeXmrColdStartV23>,
}

/// Retained by the running-process owner until both actual children are reaped.
struct RunningDependenciesV23 {
    _f6: NativeF6ProvisionV23,
    _baseline: NativeDomSnapshotV23,
    _funding: RouteFundingOwnerV23,
    _inventory: NativeMainnetXmrInventorySourceV23,
    _credentials: NativeXmrDaemonCredentialsV23,
}

impl NativeMainnetStartupV23 {
    /// Freeze inclusion, not validation, before either daemon starts. The
    /// scenario can then remove a peer after an exact funding submission and
    /// before chain confirmation makes claim signing eligible.
    pub(crate) fn arm_dom_submission_barrier_v23(&self) -> ColdStartResult<()> {
        self.baseline
            .as_ref()
            .ok_or("startup DOM baseline absent")?
            .arm_submission_barrier_v23()
    }

    /// Connect the retained, independently provisioned actor identities to the
    /// actual binary. No third Relay database is invented for the second leg:
    /// both documents opt into the production shared-peer gate explicitly.
    /// Addresses are supplied by the local scenario, never resolved through DNS.
    pub(crate) fn export_and_launch_shared_peer_v23(
        self,
        binary: &NativeDaemonBinaryV23,
        addresses: [std::net::SocketAddr; 2],
        refund_arming_authority_epoch: u64,
    ) -> ColdStartResult<NativeXmrRunningColdStartV23> {
        use crate::production_config::{
            production_f6_authority_bundle_digest_v8, ProductionBootstrapModeV1,
            ProductionChainFamilyV11, ProductionF6PathRoleV8, ProductionUniversalLegV11,
            PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1,
        };
        use crate::production_relay_network_config::{
            ProductionRelayEndpointModeV1, ProductionRelayNetworkConfigV1,
            ProductionRelayNetworkLinkV1,
        };
        use relay::production::RelayDatabaseIdV1;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        if refund_arming_authority_epoch == 0
            || addresses[0] == addresses[1]
            || addresses
                .iter()
                .any(|address| !address.ip().is_loopback() || address.port() == 0)
        {
            return Err(
                "shared-peer startup requires two distinct local endpoints and an epoch".into(),
            );
        }
        let f6 = self.f6()?;
        let mut local_ids = Vec::with_capacity(2);
        for actor in 0..2 {
            let provision = &f6.actors[actor];
            let common = self.planning(actor)?.common_v6(
                ProductionBootstrapModeV1::Create,
                provision.bounds,
                provision.family.clone(),
                &provision.owners,
            )?;
            local_ids.push(RelayDatabaseIdV1::new(
                common
                    .relay_authority_pins_v6()
                    .ok_or("shared-peer local Relay owner")?
                    .relay_database_id,
            )?);
        }
        if local_ids[0] == local_ids[1]
            || self.planning(0)?.composition().binding_digest()
                != self.planning(1)?.composition().binding_digest()
            || self.planning(0)?.roster_bundle().bundle_digest()?
                != self.planning(1)?.roster_bundle().bundle_digest()?
        {
            return Err("shared-peer actors must own distinct databases for the same route".into());
        }
        let mut fields = Vec::with_capacity(2);
        let mut sidecars = Vec::with_capacity(2);
        for actor in 0..2 {
            let plan = self.planning(actor)?;
            let peer = local_ids[1 - actor];
            let mode = if actor == 0 {
                ProductionRelayEndpointModeV1::Listen
            } else {
                ProductionRelayEndpointModeV1::Connect
            };
            let network = ProductionRelayNetworkConfigV1::new_shared_peer_v23(
                ProductionRelayNetworkLinkV1::new(mode, addresses[0], peer)?,
                ProductionRelayNetworkLinkV1::new(mode, addresses[1], peer)?,
            )?;
            network.validate_local_database_id(local_ids[actor])?;
            sidecars.push(network.canonical_bytes()?);
            let legs = [
                route_executor::LegIdV1::Upstream,
                route_executor::LegIdV1::Downstream,
            ]
            .map(|leg| {
                let session = plan.monero_session(leg);
                let position = if leg == route_executor::LegIdV1::Upstream {
                    0
                } else {
                    1
                };
                ProductionUniversalLegV11 {
                    family: ProductionChainFamilyV11::Xmr,
                    settlement_id: session.setup().settlement_id(),
                    session_id: session.session_id(),
                    chain_id: session.deployment().profile().chain_id.0,
                    actuator_store: format!("daemon-xmr-{position}-actuator.sqlite"),
                    authority_bundle: format!("daemon-xmr-{position}-authority.json"),
                    // Resource export replaces this with its canonical encoder's digest
                    // before any configuration is validated or published.
                    authority_bundle_digest: [0; 32],
                }
            });
            fields.push(ProductionUniversalBootstrapFieldsV11 {
                f6_paths: ProductionF6PathRoleV8::ALL.map(|role| {
                    format!(
                        "daemon-{}",
                        role.key().strip_prefix("path_").unwrap_or(role.key())
                    )
                }),
                f6_authority_bundle_digest: production_f6_authority_bundle_digest_v8(
                    &f6.actors[actor].bundle,
                )?,
                refund_arming_authority_epoch,
                remote_relay_database_ids: [*peer.as_bytes(); 2],
                shared_relay_peer_v23: true,
                legs,
            });
        }
        // Complete both public encodings before publishing either. A partial
        // publication is retained on failure; never overwrite an old topology.
        let prepared = self.prepared.as_ref().ok_or("startup already consumed")?;
        for (actor, bytes) in sidecars.into_iter().enumerate() {
            let root = prepared[actor].0.state_dir();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(root.join(PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(root)?.sync_all()?;
        }
        self.export_and_launch(
            binary,
            fields
                .try_into()
                .map_err(|_| "two shared-peer exports required")?,
        )
    }

    /// Only invoke after implementation is complete: this starts local RPC/HSM
    /// helpers, but does not launch the daemon or move any live-chain funds.
    pub(crate) fn prepare(
        configuration: &Configuration,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        fee_cap: u64,
    ) -> ColdStartResult<Self> {
        Self::prepare_mode_v24(configuration, limits, fee_cap, false)
    }

    pub(crate) fn prepare_live_bounded_v24(
        configuration: &Configuration,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        fee_cap: u64,
    ) -> ColdStartResult<Self> {
        deadline_plan_v23::NativeDeadlinePlanV23::validate_live_limits_v24(
            limits,
            MAINNET_BASELINE_TIP_V23,
        )?;
        Self::prepare_mode_v24(configuration, limits, fee_cap, true)
    }

    fn prepare_mode_v24(
        configuration: &Configuration,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        fee_cap: u64,
        live: bool,
    ) -> ColdStartResult<Self> {
        eprintln!("native startup: preparing original enrollment and funding owners");
        let (credentials, master_keys) = NativeXmrDaemonCredentialsV23::create()?;
        let profile = xmr_setup_profile::XmrAdapterProfileV1::new(
            xmr_setup_profile::XmrNetwork::Mainnet,
            2,
            2,
        )?;
        let secrets = NativeXmrRouteSecretsV23::new(profile, fee_cap, master_keys)?;
        let (cold, mut funding) = NativeXmrColdStartV23::prepare_mainnet_funded_mode_v24(
            secrets,
            configuration,
            &credentials,
            limits,
            MAINNET_BASELINE_TIP_V23,
            live,
        )?;
        let inventory = funding.take_inventory_source_v23()?;
        eprintln!("native startup: enrollment and funding owners ready; preparing DOM baseline");
        let mut owner = Self {
            prepared: None,
            f6: None,
            baseline: None,
            funding: Some(funding),
            inventory: Some(inventory),
            credentials: Some(credentials),
            cold: Some(cold),
        };
        let cold = owner.cold.as_ref().ok_or("startup cold owner")?;
        let credentials = owner.credentials.as_ref().ok_or("startup credentials")?;
        owner.baseline =
            Some(cold.start_mainnet_baseline_v23(MAINNET_BASELINE_TIP_V23, credentials)?);
        let baseline = owner.baseline.as_ref().ok_or("startup baseline")?;
        if live {
            baseline.enable_live_window_v24(MAINNET_BASELINE_TIP_V23, 4095)?;
        } else {
            baseline.enable_campaign_history_v24(
                MAINNET_BASELINE_TIP_V23,
                cold.negotiated_dom_history_maximum_v24()?,
                cold.root(),
            )?;
        }
        let funding = owner.funding.as_ref().ok_or("startup funding owner")?;
        let inventory = owner
            .inventory
            .as_mut()
            .ok_or("startup XMR inventory owner")?;
        let nodes = [
            cold.mainnet_node_config_v23(baseline)?,
            cold.mainnet_node_config_v23(baseline)?,
        ];
        eprintln!("native startup: bounded DOM baseline ready; observing signed time");
        let time = if live {
            cold.observe_mainnet_time_live_v24(
                &nodes[0],
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
                funding,
                limits,
                baseline,
            )?
        } else {
            cold.observe_mainnet_time_v23(
                &nodes[0],
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
                funding,
                limits,
            )?
        };
        eprintln!("native startup: signed time ready; preparing actor resources and F6");
        let (prepared, f6) = cold.prepare_mainnet_f6_pair_v23(
            nodes,
            funding,
            &time,
            baseline,
            credentials,
            inventory,
        )?;
        owner.prepared = Some(prepared);
        owner.f6 = Some(f6);
        eprintln!("native startup: both actors and F6 observations ready; daemon not launched");
        Ok(owner)
    }

    /// Public authenticated inputs needed by the separate V11/Relay producer.
    /// No getter manufactures a peer database identity or changes a guard.
    pub(crate) fn planning(
        &self,
        actor: usize,
    ) -> ColdStartResult<&NativeDaemonPlanningContextV23> {
        Ok(&self
            .prepared
            .as_ref()
            .ok_or("startup already consumed")?
            .get(actor)
            .ok_or("startup actor")?
            .1)
    }
    pub(crate) fn f6(&self) -> ColdStartResult<&NativeF6ProvisionV23> {
        self.f6
            .as_ref()
            .ok_or_else(|| "startup F6 owner absent".into())
    }

    /// V11 fields must come from an authorized producer. Both existing export
    /// validation and the binary's numeric-loopback network guard remain intact.
    /// Invalid/shared remote IDs are not substituted, repaired or bypassed here.
    pub(crate) fn export_and_launch(
        mut self,
        binary: &NativeDaemonBinaryV23,
        fields: [ProductionUniversalBootstrapFieldsV11; 2],
    ) -> ColdStartResult<NativeXmrRunningColdStartV23> {
        let prepared = self.prepared.take().ok_or("startup already consumed")?;
        let f6 = self.f6.as_ref().ok_or("startup F6 absent")?;
        let credentials = self
            .credentials
            .as_ref()
            .ok_or("startup credentials absent")?;
        let mut exports = Vec::with_capacity(2);
        for (actor, ((resources, plan), fields)) in prepared.into_iter().zip(fields).enumerate() {
            let provision = &f6.actors[actor];
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            eprintln!(
                "native startup actor={actor}: exporting and authenticating production inputs"
            );
            exports.push(resources.export(
                plan,
                provision.family.clone(),
                provision.bounds,
                &provision.owners,
                fields,
                &provision.bundle,
                credentials.stdin_for(actor)?,
                now,
            )?);
            eprintln!("native startup actor={actor}: authenticated export ready");
        }
        let exports = exports.try_into().map_err(|_| "startup two exports")?;
        let dependencies = RunningDependenciesV23 {
            _f6: self.f6.take().ok_or("startup F6 absent")?,
            _baseline: self.baseline.take().ok_or("startup baseline absent")?,
            _funding: self.funding.take().ok_or("startup funding absent")?,
            _inventory: self.inventory.take().ok_or("startup inventory absent")?,
            _credentials: self
                .credentials
                .take()
                .ok_or("startup credentials absent")?,
        };
        eprintln!("native startup: both exports authenticated; launching actual daemons");
        self.cold
            .take()
            .ok_or("startup cold owner absent")?
            .launch_with_dependencies_v23(binary, exports, Some(Box::new(dependencies)))
    }
}

impl NativeXmrRunningColdStartV23 {
    fn mainnet_dependencies_mut_v23(&mut self) -> ColdStartResult<&mut RunningDependenciesV23> {
        self._dependencies
            .as_mut()
            .and_then(|owner| owner.downcast_mut::<RunningDependenciesV23>())
            .ok_or_else(|| "running daemon has no retained mainnet scenario dependencies".into())
    }

    pub(crate) fn xmr_history_status_v23(
        &mut self,
    ) -> ColdStartResult<xmr_graph_wallet_tests::native_observation_v23::NativeXmrHistoryStatusV23>
    {
        self.mainnet_dependencies_mut_v23()?
            ._funding
            .history_status_v23()
    }

    pub(crate) fn xmr_pool_v23(&mut self) -> ColdStartResult<Vec<[u8; 32]>> {
        Ok(self.xmr_history_status_v23()?.pool_tx_hashes)
    }

    /// Test-only, exact original helper restart. No live route writer may
    /// race the cache audit/retirement closure, and no private cache is copied.
    pub(crate) fn with_stopped_sidecar_v24<T>(
        &mut self,
        position: usize,
        actor: usize,
        operation: impl FnOnce(&Path) -> ColdStartResult<T>,
    ) -> ColdStartResult<T> {
        if position >= 2 || actor >= 2 || self.processes.iter().any(Option::is_some) {
            return Err(
                "sidecar cache operation requires two reaped original daemons and exact indices"
                    .into(),
            );
        }
        self.mainnet_dependencies_mut_v23()?
            ._funding
            .with_stopped_sidecar_v24(position, actor, operation)
    }

    /// Include only explicitly selected, cryptographically verified local pool
    /// transactions. The helper checks the complete contiguous history and ACK;
    /// no command is addressed to a live-network daemon.
    pub(crate) fn advance_xmr_history_v23(
        &mut self,
        height: u64,
        timestamp: u64,
        include: &[[u8; 32]],
    ) -> ColdStartResult<xmr_graph_wallet_tests::native_observation_v23::NativeXmrHistoryStatusV23>
    {
        self.mainnet_dependencies_mut_v23()?
            ._funding
            .advance_history_v23(height, timestamp, include)
    }

    fn mainnet_dependencies_v23(&self) -> ColdStartResult<&RunningDependenciesV23> {
        self._dependencies
            .as_ref()
            .and_then(|owner| owner.downcast_ref::<RunningDependenciesV23>())
            .ok_or_else(|| "running daemon has no retained mainnet scenario dependencies".into())
    }

    pub(crate) fn pending_dom_submissions_v23(&self) -> ColdStartResult<Vec<([u8; 32], Vec<u8>)>> {
        self.mainnet_dependencies_v23()?
            ._baseline
            .pending_submissions_v23()
    }

    pub(crate) fn public_dom_history_v24(&self) -> ColdStartResult<Option<PublicDomHistoryV24>> {
        self.mainnet_dependencies_v23()?
            ._baseline
            .public_history_v24()
    }

    pub(crate) fn maximum_dom_history_height_v24(&self) -> ColdStartResult<u64> {
        self.mainnet_dependencies_v23()?
            ._baseline
            .maximum_history_height_v24()
    }

    pub(crate) fn release_dom_submissions_v23(&self) -> ColdStartResult<()> {
        self.mainnet_dependencies_v23()?
            ._baseline
            .release_submissions_v23()
    }

    /// Append genuine validated coinbase/UTXO transitions to the controlled
    /// RPC ledger. The headers are still a simulation, not proof of mainnet PoW.
    pub(crate) fn advance_dom_height_v23(&self, target: u64) -> ColdStartResult<()> {
        self.mainnet_dependencies_v23()?
            ._baseline
            .advance_to_height_v23(target)
    }
}
