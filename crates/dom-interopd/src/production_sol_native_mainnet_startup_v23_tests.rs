//! End-to-end ownership of the local DOM↔SOL startup preparation. This runs
//! no code at module initialization and never authorizes Relay identities.
use super::*;
use crate::production_config::ProductionUniversalBootstrapFieldsV11;
use crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23;
use crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23;
use xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23;

/// The same original mature native DOM inventory height as the XMR campaign.
pub(crate) const SOL_MAINNET_BASELINE_TIP_V25: u64 = 1003;
/// Each funder pays the initialize and fund transactions of its own position,
/// plus escrow rent; the grant stays far above that.
const FUNDER_AIRDROP_LAMPORTS_V25: u64 = 10_000_000_000;
/// The claim fee payer is the recipient account itself.
const RECIPIENT_AIRDROP_LAMPORTS_V25: u64 = 1_000_000_000;

/// Dependencies drop before the fixture that owns their private sockets/DBs.
pub(crate) struct NativeSolMainnetStartupV23 {
    prepared: Option<[(NativeSolDaemonResourcesV23, NativeDaemonPlanningContextV23); 2]>,
    f6: Option<NativeSolF6ProvisionV23>,
    baseline: Option<NativeDomSnapshotV23>,
    credentials: Option<NativeSolDaemonCredentialsV23>,
    cold: Option<NativeSolColdStartV23>,
    validator: Option<SolanaTestValidatorOwnerV23>,
}

/// Retained by the running-process owner until both actual children are
/// reaped. Peer signers stop first; the validator is killed last.
struct RunningSolDependenciesV23 {
    _peers: Vec<NativeSolPeerSignerOwnerV23>,
    _f6: NativeSolF6ProvisionV23,
    _baseline: NativeDomSnapshotV23,
    _credentials: NativeSolDaemonCredentialsV23,
    state_pdas: [SolanaPubkey; 2],
    validator: SolanaTestValidatorOwnerV23,
}

impl NativeSolMainnetStartupV23 {
    /// Only invoke after implementation is complete: this starts the local
    /// validator, DOM snapshot and HSM helpers, but launches no daemon.
    pub(crate) fn prepare(limits: route_time_anchor::RouteTimePolicyLimitsV2) -> ColdStartResult<Self> {
        eprintln!("native SOL startup: starting the owned local validator");
        let mut validator = SolanaTestValidatorOwnerV23::from_environment(
            crate::production_sol_native_registry_fixture_v23::program_id_v23()?,
        )?;
        let keys = NativeSolLegKeysV23::generate()?;
        for position in 0..2 {
            validator.airdrop(keys.funder(position)?, FUNDER_AIRDROP_LAMPORTS_V25)?;
        }
        eprintln!("native SOL startup: funders finalized; running the ceremony");
        let cold = NativeSolColdStartV23::prepare_v25(
            &validator,
            &keys,
            limits,
            SOL_MAINNET_BASELINE_TIP_V25,
        )?;
        // V25: each position pays a fixture-generated recipient account bound
        // to the beneficiary participant, never the participant digest.
        for position in 0..2 {
            validator.airdrop(keys.recipient(position)?, RECIPIENT_AIRDROP_LAMPORTS_V25)?;
        }
        let accounts = cold.local_role_accounts_v25(&keys)?;
        let credentials = NativeSolDaemonCredentialsV23::create(&keys, accounts)?;
        drop(keys);
        eprintln!("native SOL startup: ceremony and credentials ready; preparing DOM baseline");
        let mut owner = Self {
            prepared: None,
            f6: None,
            baseline: None,
            credentials: Some(credentials),
            cold: Some(cold),
            validator: Some(validator),
        };
        let cold = owner.cold.as_ref().ok_or("startup cold owner")?;
        let credentials = owner.credentials.as_ref().ok_or("startup credentials")?;
        owner.baseline =
            Some(cold.start_mainnet_baseline_v25(SOL_MAINNET_BASELINE_TIP_V25, credentials)?);
        let baseline = owner.baseline.as_ref().ok_or("startup baseline")?;
        baseline.enable_campaign_history_v24(
            SOL_MAINNET_BASELINE_TIP_V25,
            cold.negotiated_dom_history_maximum_v24(),
            cold.root(),
        )?;
        let nodes = [
            cold.mainnet_node_config_v25(baseline)?,
            cold.mainnet_node_config_v25(baseline)?,
        ];
        let validator = owner.validator.as_ref().ok_or("startup validator")?;
        eprintln!("native SOL startup: bounded DOM baseline ready; observing signed time");
        let time = SolColdStartSignedTimeV23::observe(
            cold,
            &nodes[0],
            zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
            validator,
            limits,
        )?;
        eprintln!("native SOL startup: signed time ready; preparing actor resources and F6");
        let (prepared, f6) =
            cold.prepare_mainnet_f6_pair_v25(nodes, validator, &time, baseline, credentials)?;
        owner.prepared = Some(prepared);
        owner.f6 = Some(f6);
        eprintln!("native SOL startup: both actors, peer signers and F6 ready; daemon not launched");
        Ok(owner)
    }

    fn planning(&self, actor: usize) -> ColdStartResult<&NativeDaemonPlanningContextV23> {
        Ok(&self
            .prepared
            .as_ref()
            .ok_or("startup already consumed")?
            .get(actor)
            .ok_or("startup actor")?
            .1)
    }

    /// Connect the retained, independently provisioned actor identities to the
    /// actual binary through the production shared-peer Relay gate. Addresses
    /// are supplied by the local scenario, never resolved through DNS.
    pub(crate) fn export_and_launch_shared_peer_v23(
        self,
        binary: &NativeDaemonBinaryV23,
        addresses: [std::net::SocketAddr; 2],
        refund_arming_authority_epoch: u64,
    ) -> ColdStartResult<NativeSolRunningColdStartV23> {
        use crate::production_config::{
            production_f6_authority_bundle_digest_v8, ProductionBootstrapModeV1,
            ProductionF6PathRoleV8, ProductionUniversalLegV11,
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
        let f6 = self.f6.as_ref().ok_or("startup F6 owner absent")?;
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
            let mut legs = Vec::with_capacity(2);
            for (position, leg) in [
                route_executor::LegIdV1::Upstream,
                route_executor::LegIdV1::Downstream,
            ]
            .into_iter()
            .enumerate()
            {
                let session = plan.solana_session(leg)?;
                legs.push(ProductionUniversalLegV11 {
                    family: ProductionChainFamilyV11::Sol,
                    settlement_id: session.setup().settlement_id(),
                    session_id: session.session_id(),
                    chain_id: session.deployment().profile().chain_id.0,
                    actuator_store: format!("daemon-sol-{position}-actuator.sqlite"),
                    authority_bundle: format!("daemon-sol-{position}-authority.json"),
                    // Resource export replaces this with its canonical encoder's
                    // digest before any configuration is validated or published.
                    authority_bundle_digest: [0; 32],
                });
            }
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
                legs: legs.try_into().map_err(|_| "shared-peer two SOL legs")?,
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

    /// V11 fields must come from an authorized producer. Both existing export
    /// validation and the binary's numeric-loopback network guard remain intact.
    fn export_and_launch(
        mut self,
        binary: &NativeDaemonBinaryV23,
        fields: [ProductionUniversalBootstrapFieldsV11; 2],
    ) -> ColdStartResult<NativeSolRunningColdStartV23> {
        let prepared = self.prepared.take().ok_or("startup already consumed")?;
        let f6 = self.f6.as_ref().ok_or("startup F6 absent")?;
        let credentials = self
            .credentials
            .as_ref()
            .ok_or("startup credentials absent")?;
        let mut exports = Vec::with_capacity(2);
        let mut peers = Vec::with_capacity(4);
        for (actor, ((resources, plan), fields)) in prepared.into_iter().zip(fields).enumerate() {
            let provision = &f6.actors[actor];
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            eprintln!(
                "native SOL startup actor={actor}: exporting and authenticating production inputs"
            );
            let (export, owned) = resources.export(
                plan,
                provision.family.clone(),
                provision.bounds,
                &provision.owners,
                fields,
                &provision.bundle,
                credentials.stdin_for(actor)?,
                now,
            )?;
            exports.push(export);
            peers.extend(owned);
            eprintln!("native SOL startup actor={actor}: authenticated export ready");
        }
        let exports = exports.try_into().map_err(|_| "startup two exports")?;
        let cold = self.cold.take().ok_or("startup cold owner absent")?;
        let state_pdas = [
            cold.participant_setups[0].binding.state_pda,
            cold.participant_setups[1].binding.state_pda,
        ];
        let dependencies = RunningSolDependenciesV23 {
            _peers: peers,
            _f6: self.f6.take().ok_or("startup F6 absent")?,
            _baseline: self.baseline.take().ok_or("startup baseline absent")?,
            _credentials: self
                .credentials
                .take()
                .ok_or("startup credentials absent")?,
            state_pdas,
            validator: self.validator.take().ok_or("startup validator absent")?,
        };
        eprintln!("native SOL startup: both exports authenticated; launching actual daemons");
        cold.launch_with_dependencies_v25(binary, exports, Some(Box::new(dependencies)))
    }
}

impl NativeSolColdStartV23 {
    pub(crate) fn start_mainnet_baseline_v25(
        &self,
        tip: u64,
        credentials: &NativeSolDaemonCredentialsV23,
    ) -> ColdStartResult<NativeDomSnapshotV23> {
        let signed = self.signed_registry()?;
        let manifest = deployment_registry::RegistryManifestV1::decode(signed.manifest_bytes())?;
        let authorities = self.authority_bundle()?;
        let registry = signed.verify(
            authorities.registry(),
            &SecpContext::new(&[29; 32]),
            deployment_registry::RegistryValidationPolicyV1 {
                now_seconds: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                expected_network_id: manifest.network_id,
                minimum_epoch: manifest.epoch,
            },
        )?;
        NativeDomSnapshotV23::start_baseline_for_daemons_v23(
            registry.resolve_dom()?,
            tip,
            [
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[0])?.to_owned()),
                zeroize::Zeroizing::new(std::str::from_utf8(&credentials.bearer[1])?.to_owned()),
            ],
        )
    }

    pub(crate) fn mainnet_node_config_v25(
        &self,
        baseline: &NativeDomSnapshotV23,
    ) -> ColdStartResult<crate::production_node::ProductionNodeConfigV1> {
        use crate::production_node::*;
        let identity = baseline.adapter().expected_identity();
        identity.validate()?;
        if identity.network != "mainnet"
            || self
                .terms
                .iter()
                .any(|terms| terms.dom_leg.chain_id.0 != identity.chain_id)
        {
            return Err("baseline does not belong to the cold mainnet route".into());
        }
        Ok(ProductionNodeConfigV1::from_parts(
            DomNodeEndpointV1::new(baseline.endpoint())?,
            ProductionNodeIdentityV1 {
                network: identity.network.clone(),
                network_magic: identity.network_magic,
                chain_id: identity.chain_id,
                genesis_hash: identity.genesis_hash,
                protocol_version: identity.protocol_version,
                range_proof_serialization_version: identity.range_proof_serialization_version,
            },
            ProductionNodeBoundsV1 {
                connect_timeout_ms: 2_000,
                request_timeout_ms: 5_000,
                history_limit: 4096,
            },
        )?)
    }

    /// Materialize only this actor's public resources, authenticate first
    /// admission from the shared signed observation, then start the peer
    /// signer sockets the daemon connects to during startup.
    pub(crate) fn prepare_mainnet_actor_v25(
        &self,
        actor: usize,
        node: crate::production_node::ProductionNodeConfigV1,
        validator: &SolanaTestValidatorOwnerV23,
        signed: &SolColdStartSignedTimeV23,
        baseline: &NativeDomSnapshotV23,
        credentials: &NativeSolDaemonCredentialsV23,
    ) -> ColdStartResult<(NativeSolDaemonResourcesV23, NativeDaemonPlanningContextV23)> {
        eprintln!("native SOL preparation actor={actor}: preparing scoped resources");
        let mut resources =
            NativeSolDaemonResourcesV23::prepare(self, actor, node, validator.address())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let planning = self.prepare_authenticated(
            actor,
            resources.state_dir(),
            resources.paths(),
            self.signed_registry()?,
            signed.policy.clone(),
            signed.evidence.clone(),
            now,
            credentials,
        )?;
        eprintln!("native SOL preparation actor={actor}: planning authenticated; binding peer signers");
        resources.bind_peer_signers(&planning, credentials, actor)?;
        self.prepare_dom_wallet_v25(
            actor,
            &resources,
            baseline,
            credentials
                .wallet_passphrases
                .get(actor)
                .ok_or("wallet actor")?,
        )?;
        eprintln!("native SOL preparation actor={actor}: observed DOM wallet ready");
        Ok((resources, planning))
    }

    /// `[position][actor]`: the funder account for the solver (the SOL refund
    /// recipient in the terms), the ParticipantId-pinned recipient otherwise.
    pub(crate) fn local_role_accounts_v25(
        &self,
        keys: &NativeSolLegKeysV23,
    ) -> ColdStartResult<[[SolanaPubkey; 2]; 2]> {
        let mut result = [[SolanaPubkey([0; 32]); 2]; 2];
        for (position, terms) in self.terms.iter().enumerate() {
            for (actor, account) in result[position].iter_mut().enumerate() {
                let local = self.actor_id(actor)?;
                *account = if local == terms.counterparty_leg.refund_to.0 {
                    keys.funder(position)?
                } else if local == terms.counterparty_leg.beneficiary.0 {
                    keys.recipient(position)?
                } else {
                    return Err("cold-start actor holds no SOL role".into());
                };
            }
        }
        Ok(result)
    }
}

impl NativeSolRunningColdStartV23 {
    fn sol_dependencies_v25(&self) -> ColdStartResult<&RunningSolDependenciesV23> {
        self._dependencies
            .as_ref()
            .and_then(|owner| owner.downcast_ref::<RunningSolDependenciesV23>())
            .ok_or_else(|| "running daemon has no retained SOL scenario dependencies".into())
    }

    fn sol_dependencies_mut_v25(&mut self) -> ColdStartResult<&mut RunningSolDependenciesV23> {
        self._dependencies
            .as_mut()
            .and_then(|owner| owner.downcast_mut::<RunningSolDependenciesV23>())
            .ok_or_else(|| "running daemon has no retained SOL scenario dependencies".into())
    }

    /// The validator produces its own slots; no ledger pump exists. An
    /// exited validator fails the scenario instead of stalling it.
    pub(crate) fn require_validator_alive_v25(&mut self) -> ColdStartResult<()> {
        self.sol_dependencies_mut_v25()?.validator.require_alive()
    }

    /// Finalized on-chain escrow state of both legs, decoded strictly from the
    /// program-owned state PDAs. Test evidence only, never an authority.
    pub(crate) fn escrow_states_v25(
        &self,
    ) -> ColdStartResult<[solana_escrow_wire::EscrowStateV1; 2]> {
        use solana_rpc::SolanaRpc;
        let dependencies = self.sol_dependencies_v25()?;
        let rpc = dependencies.validator.rpc()?;
        let mut states = Vec::with_capacity(2);
        for pda in dependencies.state_pdas {
            let account = rpc
                .get_account(pda, solana_types::Commitment::Finalized)
                .map_err(|_| "escrow state RPC unavailable")?
                .ok_or("escrow state account absent")?;
            if account.owner != dependencies.validator.program_id() {
                return Err("escrow state is not owned by the attested program".into());
            }
            states.push(
                solana_escrow_wire::EscrowStateV1::decode(&account.data)
                    .map_err(|_| "escrow state encoding refused")?,
            );
        }
        states
            .try_into()
            .map_err(|_| "two escrow states required".into())
    }
}
