//! Concrete private resources for the real two-position daemon cold start.
//! Creates no Contracts/F6 authority, graph, wallet reservation or funding grant.
use super::NativeXmrColdStartV23;
use crate::production_config::*;
use crate::production_f6_factory::native_daemon_export_v23::ExportedNativeDaemonV23;
use crate::production_inputs::native_daemon_planning_v23::{
    NativeDaemonOwnerPinsV23, NativeDaemonPlanningContextV23,
};
use crate::production_node::ProductionNodeConfigV1;
use crate::production_route_services::{LegServicesV8, RouteServicesV8, ServiceV8};
use crate::production_universal_leg_authority::native_bundle_v23::{
    encode_native_xmr_bundle_from_plan_v23, NativeXmrBundleResourcesV23,
};
use rand::RngCore;
use route_executor::LegIdV1;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeXmrDaemonResourcesV23 {
    root: PathBuf,
    paths: ProductionPathReferencesV1,
    resources: [NativeXmrBundleResourcesV23; 2],
    policies: [xmr_refund_policy::compensation::XmrCompensationPolicyV11; 2],
    endpoints: [Vec<String>; 2],
}

impl NativeXmrDaemonResourcesV23 {
    /// Addresses come from already-bound local scenario servers; there is no
    /// hostname, externally reachable endpoint, or optional selected family.
    /// Sidecar sockets and the four enrollment DBs remain the original owners.
    pub(crate) fn prepare(
        cold: &NativeXmrColdStartV23,
        actor: usize,
        node: ProductionNodeConfigV1,
        daemon_addresses: [Vec<SocketAddr>; 2],
        sidecar_paths: [&Path; 2],
        private_funding: [Option<Zeroizing<Vec<u8>>>; 2],
    ) -> Result<Self> {
        let root = cold.actor_work(actor)?.to_path_buf();
        require_private_directory(&root)?;
        let identity = node.expected_identity();
        identity.validate()?;
        if node.network() != "mainnet"
            || cold
                .terms
                .iter()
                .any(|terms| terms.dom_leg.chain_id.0 != identity.chain_id)
        {
            return Err("cold-start requires the exact DOM mainnet identity".into());
        }
        let dom_address = node
            .endpoint()
            .as_str()
            .strip_prefix("http://")
            .ok_or("cold-start DOM endpoint scheme")?
            .trim_end_matches('/')
            .parse::<SocketAddr>()?;
        require_loopback(dom_address)?;
        let mut endpoints = [Vec::new(), Vec::new()];
        for (position, addresses) in daemon_addresses.into_iter().enumerate() {
            for address in addresses {
                require_loopback(address)?;
                let url = format!("http://{address}");
                if endpoints[position].contains(&url) {
                    return Err("cold-start duplicate XMR endpoint".into());
                }
                endpoints[position].push(url);
            }
        }
        let paths =
            ProductionPathReferencesV1::from_ordered(ProductionPathRoleV1::ALL.map(|role| {
                format!(
                    "daemon-{}",
                    role.key().strip_prefix("path_").unwrap_or(role.key())
                )
            }))?;
        let local = cold.actor_id(actor)?;
        let policies = [0, 1].map(|position| -> Result<_> {
            xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(
                &cold.compensation_policy(position)?,
            )
            .map_err(Into::into)
        });
        let [up_policy, down_policy] = policies;
        let policies = [up_policy?, down_policy?];
        let mut resources = Vec::with_capacity(2);
        for (position, raw) in private_funding.into_iter().enumerate() {
            let terms = &cold.terms[position];
            let setup = cold.enrolled[position].setup();
            let policy = policies[position].validate_for(terms)?;
            if policy.policy().bounded_availability_v23.is_none() {
                return Err("cold-start missing negotiated bounded availability".into());
            }
            let custody = &cold.custody_roots[position][actor];
            require_private_directory(custody)?;
            let secret_store =
                relative_existing(&root, &custody.join("native-xmr-secrets-v23.sqlite"), false)?;
            let nullifier_store = relative_existing(
                &root,
                &custody.join("native-xmr-nullifiers-v23.sqlite"),
                false,
            )?;
            let sidecar_socket = relative_existing(&root, sidecar_paths[position], true)?;
            if raw.is_some() != (local == terms.counterparty_leg.refund_to.0) {
                return Err("cold-start private funding assigned to wrong actor".into());
            }
            let fee = u64::try_from(terms.fee_limit.counterparty_max)?;
            let private_funding = match raw {
                Some(mut raw) => {
                    // Match the actual offline producer's fixture view key;
                    // this is not a spend share or an execution capability.
                    let mut view = Zeroizing::new([0; 32]);
                    view[0] = 13;
                    let candidate = xmr_rpc_broadcast_blocking::PreparedPrivateFundingV12::import(
                        std::mem::take(&mut *raw),
                        setup.funding_tx_hash(),
                        setup.combined_spend_public_key(),
                        &view,
                        setup.expected_amount_piconero(),
                        fee,
                    )?;
                    let name = format!("daemon-xmr-{position}-funding.raw");
                    candidate.with_raw(|bytes| publish(&root, &name, bytes))?;
                    Some((name, fee))
                }
                None => None,
            };
            let sealing_key_file = format!("daemon-xmr-{position}-recovery.key");
            let mut sealing_key = Zeroizing::new([0; 32]);
            rand::thread_rng().fill_bytes(&mut *sealing_key);
            if *sealing_key == [0; 32] {
                return Err("cold-start zero recovery sealing key".into());
            }
            publish(&root, &sealing_key_file, &*sealing_key)?;
            let mut custody_id = [0; 32];
            rand::thread_rng().fill_bytes(&mut custody_id);
            if custody_id == [0; 32] {
                return Err("cold-start zero custody id".into());
            }
            resources.push(NativeXmrBundleResourcesV23 {
                local_participant_id: local,
                secret_store,
                nullifier_store,
                sidecar_socket,
                sidecar_timeout_ms: 60_000,
                custody_directory: format!("daemon-xmr-{position}-graph-custody"),
                sealing_key_file,
                custody_id,
                private_funding,
            });
        }
        publish(
            &root,
            PRODUCTION_NODE_CONFIG_FILE_V1,
            &node.canonical_bytes()?,
        )?;
        Ok(Self {
            root,
            paths,
            policies,
            endpoints,
            resources: resources
                .try_into()
                .map_err(|_| "cold-start two resources")?,
        })
    }

    pub(crate) fn state_dir(&self) -> &Path {
        &self.root
    }
    pub(crate) fn paths(&self) -> ProductionPathReferencesV1 {
        self.paths.clone()
    }

    /// F6 economics/signers, wallet and relay owners are supplied by their
    /// actual producers. This method cannot invent these authorities.
    pub(crate) fn export(
        self,
        plan: NativeDaemonPlanningContextV23,
        family: ProductionFamilyInputsV6,
        bounds: ProductionRuntimeBoundsV1,
        owners: &NativeDaemonOwnerPinsV23,
        mut fields: ProductionUniversalBootstrapFieldsV11,
        f6_bundle: &[u8],
        stdin: Zeroizing<Vec<u8>>,
        now_seconds: u64,
    ) -> Result<ExportedNativeDaemonV23> {
        let services = RouteServicesV8 {
            version: 8,
            route_id: plan.admission().route_id(),
            composition_digest: plan.composition().binding_digest(),
            registry_digest: plan.resolved_registry().manifest_digest(),
            legs: [0, 1].map(|position| {
                let leg = if position == 0 {
                    LegIdV1::Upstream
                } else {
                    LegIdV1::Downstream
                };
                let session = plan.monero_session(leg);
                LegServicesV8 {
                    settlement_id: session.setup().settlement_id(),
                    chain_id: session.deployment().profile().chain_id.0,
                    service: ServiceV8::Monero {
                        endpoints: self.endpoints[position].clone(),
                        quorum: u16::from(session.profile().rpc_quorum),
                    },
                }
            }),
        };
        for (position, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            if self.endpoints[position].len()
                != usize::from(plan.monero_session(leg).profile().rpc_node_count)
            {
                return Err("cold-start XMR endpoint count differs from signed profile".into());
            }
            if plan.monero_session(leg).profile().network != xmr_setup_profile::XmrNetwork::Mainnet
            {
                return Err("cold-start requires XMR mainnet profile".into());
            }
        }
        publish(
            &self.root,
            crate::production_route_services::FILE_V8,
            &services.canonical_bytes()?,
        )?;
        let mut bundles = Vec::with_capacity(2);
        for (position, resource) in self.resources.into_iter().enumerate() {
            let leg = if position == 0 {
                LegIdV1::Upstream
            } else {
                LegIdV1::Downstream
            };
            let descriptor = ProductionUniversalLegV11 {
                family: ProductionChainFamilyV11::Xmr,
                settlement_id: plan.monero_session(leg).setup().settlement_id(),
                session_id: plan.monero_session(leg).session_id(),
                chain_id: plan.monero_session(leg).deployment().profile().chain_id.0,
                actuator_store: format!("daemon-xmr-{position}-actuator.sqlite"),
                authority_bundle: format!("daemon-xmr-{position}-authority.json"),
                // The canonical encoder computes this before any descriptor is used.
                authority_bundle_digest: [0; 32],
            };
            let (descriptor, bundle) = encode_native_xmr_bundle_from_plan_v23(
                &plan,
                leg,
                descriptor,
                &self.policies[position],
                resource,
            )?;
            fields.legs[position] = descriptor;
            bundles.push(bundle);
        }
        let common = [
            plan.common_v6(
                ProductionBootstrapModeV1::Create,
                bounds,
                family.clone(),
                owners,
            )?,
            plan.common_v6(
                ProductionBootstrapModeV1::ReopenExisting,
                bounds,
                family,
                owners,
            )?,
        ];
        plan.export_first(
            common,
            fields,
            f6_bundle,
            [&bundles[0], &bundles[1]],
            stdin,
            now_seconds,
        )
    }
}

fn require_loopback(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("cold-start endpoints must be numeric loopback and bound".into());
    }
    Ok(())
}

fn require_private_directory(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path)? != path
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err("cold-start directory is not an original private owner".into());
    }
    Ok(())
}

fn relative_existing(root: &Path, path: &Path, socket: bool) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("cold-start resource escaped state directory".into());
    }
    let mut parent = root.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        parent.push(part.as_os_str());
        require_private_directory(&parent)?;
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.mode() & 0o077 != 0
        || (socket && !meta.file_type().is_socket())
        || (!socket && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err("cold-start resource is not its private original".into());
    }
    Ok(relative
        .to_str()
        .ok_or("cold-start resource path encoding")?
        .to_owned())
}

fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    require_private_directory(root)?;
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err("cold-start published artifact must be a direct child".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
