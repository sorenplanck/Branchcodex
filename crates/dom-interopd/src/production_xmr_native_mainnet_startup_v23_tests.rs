//! End-to-end ownership of the local Mainnet-profile startup preparation.
//! This runs no code at module initialization and never authorizes Relay IDs.
use super::*;
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
    /// Only invoke after implementation is complete: this starts local RPC/HSM
    /// helpers, but does not launch the daemon or move any live-chain funds.
    pub(crate) fn prepare(
        configuration: &Configuration,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        fee_cap: u64,
    ) -> ColdStartResult<Self> {
        let (credentials, master_keys) = NativeXmrDaemonCredentialsV23::create()?;
        let profile = xmr_setup_profile::XmrAdapterProfileV1::new(
            xmr_setup_profile::XmrNetwork::Mainnet,
            2,
            2,
        )?;
        let secrets = NativeXmrRouteSecretsV23::new(profile, fee_cap, master_keys)?;
        let (cold, mut funding) = NativeXmrColdStartV23::prepare_mainnet_funded_v23(
            secrets,
            configuration,
            &credentials,
            limits,
            MAINNET_BASELINE_TIP_V23,
        )?;
        let inventory = funding.take_inventory_source_v23()?;
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
        let funding = owner.funding.as_ref().ok_or("startup funding owner")?;
        let inventory = owner
            .inventory
            .as_mut()
            .ok_or("startup XMR inventory owner")?;
        let nodes = [
            cold.mainnet_node_config_v23(baseline)?,
            cold.mainnet_node_config_v23(baseline)?,
        ];
        let time = cold.observe_mainnet_time_v23(
            &nodes[0],
            zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
            funding,
            limits,
        )?;
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
        self.cold
            .take()
            .ok_or("startup cold owner absent")?
            .launch_with_dependencies_v23(binary, exports, Some(Box::new(dependencies)))
    }
}
