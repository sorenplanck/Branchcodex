//! Concrete private resources for the real two-position DOM↔SOL cold start.
//! Creates no Contracts/F6 authority, wallet reservation or funding grant.
use super::{NativeSolColdStartV23, NativeSolDaemonCredentialsV23, NativeSolPeerSignerOwnerV23};
use crate::production_config::*;
use crate::production_f6_factory::native_daemon_export_v23::ExportedNativeDaemonV23;
use crate::production_inputs::native_daemon_planning_v23::{
    NativeDaemonOwnerPinsV23, NativeDaemonPlanningContextV23,
};
use crate::production_node::ProductionNodeConfigV1;
use crate::production_route_services::{LegServicesV8, RouteServicesV8, ServiceV8};
use crate::production_solana_signer::ProductionSolanaSignerRoleV7;
use route_executor::LegIdV1;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Must stay within `require_milliseconds(.., 60_000)` of the V11 decoder.
pub(crate) const SOL_PEER_TIMEOUT_MS_V25: u64 = 30_000;
/// The exact name `production_run_universal` reads for the LocalOrigin scalar.
pub(crate) const LOCAL_ORIGIN_FILE_V25: &str = "production-local-origin-secret.v21";
use crate::production_universal_leg_authority::{
    encode_solana_leg_authority_bundle_v25, ProductionLegBundleIdentityV22,
    ProductionSolanaLegBundleParametersV25, ProductionSolanaLegRoleV25 as SolanaLocalRoleV25,
};

pub(crate) struct NativeSolDaemonResourcesV23 {
    root: PathBuf,
    paths: ProductionPathReferencesV1,
    endpoints: [Vec<String>; 2],
    roles: [SolanaLocalRoleV25; 2],
    /// Listening before export and launch; moved to the running owner.
    peers: Vec<NativeSolPeerSignerOwnerV23>,
}

impl NativeSolDaemonResourcesV23 {
    /// The validator address comes from the owned local process; there is no
    /// hostname, public cluster, or optional selected family.
    pub(crate) fn prepare(
        cold: &NativeSolColdStartV23,
        actor: usize,
        node: ProductionNodeConfigV1,
        validator: SocketAddr,
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
        require_loopback(validator)?;
        let endpoint = format!("http://{validator}");
        let paths =
            ProductionPathReferencesV1::from_ordered(ProductionPathRoleV1::ALL.map(|role| {
                format!(
                    "daemon-{}",
                    role.key().strip_prefix("path_").unwrap_or(role.key())
                )
            }))?;
        let local = cold.actor_id(actor)?;
        let mut roles = Vec::with_capacity(2);
        for terms in &cold.terms {
            roles.push(if local == terms.counterparty_leg.refund_to.0 {
                SolanaLocalRoleV25::Funder
            } else if local == terms.counterparty_leg.beneficiary.0 {
                SolanaLocalRoleV25::Beneficiary
            } else {
                return Err("cold-start actor holds no SOL role on this position".into());
            });
        }
        publish(
            &root,
            PRODUCTION_NODE_CONFIG_FILE_V1,
            &node.canonical_bytes()?,
        )?;
        // Only the downstream DOM claim sender holds the LocalOrigin scalar.
        if local == cold.origin_actor_id_v25() {
            publish(&root, LOCAL_ORIGIN_FILE_V25, cold.origin_secret_v25().as_slice())?;
        }
        Ok(Self {
            root,
            paths,
            endpoints: [vec![endpoint.clone()], vec![endpoint]],
            roles: roles.try_into().map_err(|_| "cold-start two SOL roles")?,
            peers: Vec::new(),
        })
    }

    pub(crate) fn state_dir(&self) -> &Path {
        &self.root
    }
    pub(crate) fn paths(&self) -> ProductionPathReferencesV1 {
        self.paths.clone()
    }

    /// Requires both DLEQ-authenticated sessions, so it runs after planning
    /// and strictly before export: `bind_signers` connects at daemon startup.
    pub(crate) fn bind_peer_signers(
        &mut self,
        plan: &NativeDaemonPlanningContextV23,
        credentials: &NativeSolDaemonCredentialsV23,
        actor: usize,
    ) -> Result<()> {
        if !self.peers.is_empty() {
            return Err("SOL peer signers already bound".into());
        }
        for position in 0..2 {
            let served = match self.roles[position] {
                SolanaLocalRoleV25::Funder => ProductionSolanaSignerRoleV7::Beneficiary,
                SolanaLocalRoleV25::Beneficiary => ProductionSolanaSignerRoleV7::Funder,
            };
            let owner = NativeSolPeerSignerOwnerV23::bind(
                &self.root.join(peer_socket_name(position)),
                plan.solana_session(leg(position))?,
                served,
                credentials.served_peer_seed(position, actor)?,
                Duration::from_millis(SOL_PEER_TIMEOUT_MS_V25),
            )?;
            relative_existing(&self.root, owner.socket(), true)?;
            self.peers.push(owner);
        }
        Ok(())
    }

    /// F6 economics/signers, wallet and relay owners are supplied by their
    /// actual producers. This method cannot invent these authorities.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<(ExportedNativeDaemonV23, Vec<NativeSolPeerSignerOwnerV23>)> {
        let Self {
            root,
            paths: _,
            endpoints,
            roles,
            peers,
        } = self;
        if peers.len() != 2 {
            return Err("SOL peer signers must listen before export".into());
        }
        let mut services = Vec::with_capacity(2);
        for position in 0..2 {
            let session = plan.solana_session(leg(position))?;
            let profile = session.profile();
            if endpoints[position].len() != usize::from(profile.rpc_node_count)
                || !profile.require_immutable_program
                || profile.network != solana_profile::SolanaNetwork::LocalValidator
            {
                return Err("cold-start SOL endpoints differ from the attested profile".into());
            }
            services.push(LegServicesV8 {
                settlement_id: session.setup().settlement_id(),
                chain_id: session.deployment().profile().chain_id.0,
                service: ServiceV8::Solana {
                    endpoints: endpoints[position].clone(),
                    quorum: profile.rpc_quorum,
                },
            });
        }
        let services = RouteServicesV8 {
            version: 8,
            route_id: plan.admission().route_id(),
            composition_digest: plan.composition().binding_digest(),
            registry_digest: plan.resolved_registry().manifest_digest(),
            legs: services.try_into().map_err(|_| "cold-start two SOL services")?,
        };
        publish(
            &root,
            crate::production_route_services::FILE_V8,
            &services.canonical_bytes()?,
        )?;
        let mut bundles = Vec::with_capacity(2);
        for position in 0..2 {
            let session = plan.solana_session(leg(position))?;
            let terms = if position == 0 {
                plan.composition().upstream()
            } else {
                plan.composition().downstream()
            };
            let mut descriptor = ProductionUniversalLegV11 {
                family: ProductionChainFamilyV11::Sol,
                settlement_id: session.setup().settlement_id(),
                session_id: session.session_id(),
                chain_id: session.deployment().profile().chain_id.0,
                actuator_store: format!("daemon-sol-{position}-actuator.sqlite"),
                authority_bundle: format!("daemon-sol-{position}-authority.json"),
                authority_bundle_digest: [0; 32],
            };
            let bundle = encode_sol_authority_bundle_v25(
                &descriptor,
                terms.terms_hash()?,
                roles[position],
                &peer_socket_name(position),
            )?;
            descriptor.authority_bundle_digest = ProductionUniversalLegV11::bundle_digest(&bundle)?;
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
        let exported = plan.export_first(
            common,
            fields,
            f6_bundle,
            [&bundles[0], &bundles[1]],
            stdin,
            now_seconds,
        )?;
        Ok((exported, peers))
    }
}

fn leg(position: usize) -> LegIdV1 {
    if position == 0 {
        LegIdV1::Upstream
    } else {
        LegIdV1::Downstream
    }
}

fn peer_socket_name(position: usize) -> String {
    format!("sol-peer-{position}.sock")
}

/// Thin wrapper over the production writer, which builds the bytes from the
/// decoder's own `WireV11`. Native SOL admits no SPL token accounts.
fn encode_sol_authority_bundle_v25(
    descriptor: &ProductionUniversalLegV11,
    terms_hash: [u8; 32],
    role: SolanaLocalRoleV25,
    peer_socket: &str,
) -> Result<Vec<u8>> {
    if descriptor.family != ProductionChainFamilyV11::Sol
        || [descriptor.settlement_id, descriptor.session_id, descriptor.chain_id, terms_hash]
            .contains(&[0; 32])
    {
        return Err("SOL authority bundle identity must be exact and nonzero".into());
    }
    let bundle = encode_solana_leg_authority_bundle_v25(
        &ProductionLegBundleIdentityV22 {
            settlement_id: descriptor.settlement_id,
            session_id: descriptor.session_id,
            chain_id: descriptor.chain_id,
            terms_hash,
        },
        ProductionSolanaLegBundleParametersV25 {
            local_role: role,
            token_accounts: None,
            peer_socket: peer_socket.to_owned(),
            peer_timeout_ms: SOL_PEER_TIMEOUT_MS_V25,
        },
    )
    .map_err(|_| "SOL authority bundle refused by the production writer")?;
    Ok(bundle.bytes().to_vec())
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
    use std::os::unix::fs::FileTypeExt;
    let relative = path.strip_prefix(root)?;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("cold-start resource escaped state directory".into());
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

#[test]
fn sol_authority_bundle_has_the_decoder_field_order_v25() -> Result<()> {
    let descriptor = ProductionUniversalLegV11 {
        family: ProductionChainFamilyV11::Sol,
        settlement_id: [1; 32],
        session_id: [2; 32],
        chain_id: [3; 32],
        actuator_store: "daemon-sol-0-actuator.sqlite".into(),
        authority_bundle: "daemon-sol-0-authority.json".into(),
        authority_bundle_digest: [0; 32],
    };
    let bytes = encode_sol_authority_bundle_v25(
        &descriptor,
        [4; 32],
        SolanaLocalRoleV25::Funder,
        "sol-peer-0.sock",
    )?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.starts_with("{\"format\":\"DOM-INTEROPD-LEG-AUTHORITY-V11\",\"settlement_id\":[1,"));
    assert!(text.ends_with(
        "\"authority\":{\"family\":\"SOL\",\"parameters\":{\"local_role\":\"funder\",\
         \"token_accounts\":null,\"peer_socket\":\"sol-peer-0.sock\",\"peer_timeout_ms\":30000}}}"
    ));
    let mut xmr = descriptor.clone();
    xmr.family = ProductionChainFamilyV11::Xmr;
    assert!(encode_sol_authority_bundle_v25(&xmr, [4; 32], SolanaLocalRoleV25::Funder, "s").is_err());
    Ok(())
}
