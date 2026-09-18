//! DOM↔SOL ceremony and first-export preparation before the daemon produces
//! any C/D output. This never calls the component graph/wallet fixture: the
//! real daemon must create its own reservation and Contracts journals.
//! Order is mandatory: validator and funders, ceremony (the observed genesis
//! and program hash enter the signed manifest), DOM baseline, configs, signed
//! time, planning, peer signers, F6, export, launch.
use super::*;
use crate::production_config::ProductionChainFamilyV11;
use solana_types::SolanaPubkey;
use zeroize::Zeroizing;

#[path = "production_sol_native_daemon_scenario_v23_tests.rs"]
mod daemon_scenario_v23;
#[path = "production_sol_native_mainnet_startup_v23_tests.rs"]
mod mainnet_startup_v23;
pub(crate) use mainnet_startup_v23::NativeSolMainnetStartupV23;
#[path = "production_sol_native_validator_v23_tests.rs"]
mod validator_v23;
pub(crate) use validator_v23::SolanaTestValidatorOwnerV23;
#[path = "production_sol_native_peer_signer_v23_tests.rs"]
mod peer_signer_v23;
pub(crate) use peer_signer_v23::NativeSolPeerSignerOwnerV23;
#[path = "production_sol_native_deadline_plan_v23_tests.rs"]
mod deadline_plan_v23;
#[path = "production_sol_native_daemon_credentials_v23_tests.rs"]
mod daemon_credentials_v23;
pub(crate) use daemon_credentials_v23::{NativeSolDaemonCredentialsV23, NativeSolLegKeysV23};
#[path = "production_sol_native_daemon_resources_v23_tests.rs"]
mod daemon_resources_v23;
pub(crate) use daemon_resources_v23::NativeSolDaemonResourcesV23;
#[path = "production_sol_native_signed_time_v23_tests.rs"]
mod signed_time_v23;
pub(crate) use signed_time_v23::SolColdStartSignedTimeV23;
#[path = "production_sol_native_dom_wallet_v23_tests.rs"]
mod dom_wallet_v23;
#[path = "production_sol_native_daemon_f6_v23_tests.rs"]
mod daemon_f6_v23;
pub(crate) use daemon_f6_v23::NativeSolF6ProvisionV23;

type ColdStartResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

/// Both positions are Solana on the same owned local validator.
pub(crate) const SOL_FAMILIES_V25: [ProductionChainFamilyV11; 2] =
    [ProductionChainFamilyV11::Sol; 2];
/// 0.05 SOL per leg: above rent and fees, far below the local faucet grant.
pub(crate) const NATIVE_SOL_LEG_LAMPORTS_V25: u64 = 50_000_000;

/// Field order is deliberate: stop/reap both children before TempDir cleanup.
pub(crate) struct NativeSolRunningColdStartV23 {
    processes: [Option<crate::production_xmr_native_binary_v23_tests::NativeDaemonProcessV23>; 2],
    restart: [NativeSolRestartInputV23; 2],
    _dependencies: Option<Box<dyn std::any::Any>>,
    _fixture: Fixture,
}

struct NativeSolRestartInputV23 {
    state_dir: PathBuf,
    credentials: Zeroizing<Vec<u8>>,
    manifests: [Vec<u8>; 2],
}

impl NativeSolRestartInputV23 {
    fn read_manifests(state_dir: &Path) -> ColdStartResult<[Vec<u8>; 2]> {
        use crate::production_config::{
            read_owner_file_bounded, ProductionConfigErrorV1, PRODUCTION_CREATE_CONFIG_FILE_V11,
            PRODUCTION_REOPEN_CONFIG_FILE_V11,
        };
        let mut result = Vec::with_capacity(2);
        for name in [
            PRODUCTION_CREATE_CONFIG_FILE_V11,
            PRODUCTION_REOPEN_CONFIG_FILE_V11,
        ] {
            result.push(read_owner_file_bounded(
                &state_dir.join(name),
                262_144,
                ProductionConfigErrorV1::InputArtifactUnavailable,
            )?);
        }
        result
            .try_into()
            .map_err(|_| "two original manifests required".into())
    }
}

impl NativeSolRunningColdStartV23 {
    pub(crate) fn state_dir(&self, actor: usize) -> ColdStartResult<&Path> {
        Ok(&self
            .restart
            .get(actor)
            .ok_or("daemon actor index")?
            .state_dir)
    }

    pub(crate) fn poll_actor_v23(
        &mut self,
        actor: usize,
    ) -> ColdStartResult<Option<std::process::ExitStatus>> {
        self.processes
            .get_mut(actor)
            .ok_or("daemon actor index")?
            .as_mut()
            .ok_or("daemon actor is stopped")?
            .poll()
    }

    /// Reap a successful natural terminal exit, never substitute SIGTERM or
    /// SIGKILL for proof that the real daemon completed its own run function.
    pub(crate) fn reap_successful_actor_v23(&mut self, actor: usize) -> ColdStartResult<()> {
        match self.poll_actor_v23(actor)? {
            Some(status) if status.success() => {}
            Some(_) => return Err("real daemon exited unsuccessfully".into()),
            None => return Err("real daemon has not exited naturally".into()),
        }
        // stop() sees the already retained exit status and sends no signal.
        let status = self
            .processes
            .get_mut(actor)
            .ok_or("daemon actor index")?
            .take()
            .ok_or("daemon actor is stopped")?
            .stop()?;
        if !status.success() {
            return Err("reaped daemon status changed".into());
        }
        Ok(())
    }

    /// Keep success evidence only after the scenario explicitly reaped both
    /// daemon owners; archival never stops a live process as a side effect.
    pub(crate) fn retain_successful_fixture_v24(self) -> ColdStartResult<PathBuf> {
        if self.processes.iter().any(Option::is_some) {
            self.retain_failed_fixture_v23();
            return Err("successful fixture still has an unreaped daemon owner".into());
        }
        let Self {
            processes,
            restart,
            _dependencies,
            _fixture,
        } = self;
        drop(processes);
        drop(_dependencies);
        drop(restart);
        let retained = _fixture._root.keep();
        eprintln!(
            "native SOL real daemon: successful fixture retained at {}",
            retained.display()
        );
        Ok(retained)
    }

    /// Retain original synthetic Stores after failure, only after every owned
    /// process, peer signer and the validator are stopped and reaped.
    pub(crate) fn retain_failed_fixture_v23(self) -> PathBuf {
        let Self {
            processes,
            restart,
            _dependencies,
            _fixture,
        } = self;
        drop(processes);
        drop(_dependencies);
        drop(restart);
        let retained = _fixture._root.keep();
        eprintln!(
            "native SOL real daemon: failed fixture retained at {}",
            retained.display()
        );
        if let Some(marker) = std::env::var_os("DOM_SOL_FAILED_FIXTURE_MARKER_V23") {
            let marker = PathBuf::from(marker);
            let publish = (|| -> ColdStartResult<()> {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let parent = marker.parent().ok_or("fixture marker parent")?;
                if !marker.is_absolute() || std::fs::canonicalize(parent)? != parent {
                    return Err("fixture marker must have a canonical absolute parent".into());
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(&marker)?;
                writeln!(file, "{}", retained.display())?;
                file.sync_all()?;
                std::fs::File::open(parent)?.sync_all()?;
                Ok(())
            })();
            if publish.is_err() {
                eprintln!("native SOL real daemon: fixture kept; marker unavailable or already exists (not overwritten)");
            }
        }
        retained
    }

    /// Reopen is required after completion; the real binary, not this
    /// harness, validates that mode. No database or manifest is repaired.
    pub(crate) fn restart_actor(
        &mut self,
        actor: usize,
        binary: &crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23,
        mode: crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23,
    ) -> ColdStartResult<()> {
        let process = self.processes.get_mut(actor).ok_or("daemon actor index")?;
        if process.is_some() {
            return Err("daemon restart requires a reaped original process".into());
        }
        let retained = &self.restart[actor];
        if NativeSolRestartInputV23::read_manifests(&retained.state_dir)? != retained.manifests {
            return Err("daemon restart manifests differ from original export".into());
        }
        *process = Some(binary.launch_for_families_v25(
            &retained.state_dir,
            retained.credentials.clone(),
            mode,
            SOL_FAMILIES_V25,
        )?);
        Ok(())
    }
}

struct NativeSolLaunchGuardV23 {
    processes: Vec<crate::production_xmr_native_binary_v23_tests::NativeDaemonProcessV23>,
    dependencies: Option<Box<dyn std::any::Any>>,
    fixture: Fixture,
}

pub(crate) struct NativeSolColdStartV23 {
    fixture: Fixture,
    pub(crate) terms: [SettlementTermsV1; 2],
    plans: [Plan; 2],
    pub(crate) contracts_bootstrap: Vec<u8>,
    /// DLEQ-bound escrow setups, validated against the frozen terms here.
    pub(crate) participant_setups: [crate::production_inputs::ProductionSolanaLegSetupV1; 2],
    /// Big-endian DOM scalar for the LocalOrigin claim sender only.
    origin_secret: Zeroizing<[u8; 32]>,
    negotiated_dom_history_maximum_v24: u64,
}

impl NativeSolColdStartV23 {
    /// Real offline route producer over the owned validator's observed facts.
    /// The same cross-curve secret binds both same-T legs.
    pub(crate) fn prepare_v25(
        validator: &SolanaTestValidatorOwnerV23,
        keys: &NativeSolLegKeysV23,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        dom_baseline_tip: u64,
    ) -> ColdStartResult<Self> {
        use crate::production_sol_native_registry_fixture_v23 as registry_v23;
        let program_id = validator.program_id();
        let program_data_hash = validator.program_data_hash();
        let genesis = validator.genesis_hash();
        let profile = registry_v23::adapter_profile_v23(program_id)?;
        let secret = xmr_dleq_sigma::CrossCurveSecret252::generate(&mut rand::thread_rng());
        let adaptor_point = secret.public_claim()?.secp_compressed;
        let mut deadlines = None;
        let mut configured: ColdStartResult<()> = Err("registry configuration did not run".into());
        // The ordinary route topology: the solver owns T on the whole route,
        // as the composed role plan requires, and funds only the SOL position
        // it delivers; the user funds the position it gives.
        let fixture = fixture_with_route_topology_v25(false, true, |manifest, terms| {
            configured = (|| -> ColdStartResult<()> {
                let [up, down] = terms;
                // The initial local negotiation, not a lease refresh. Registry
                // and time policy must cover the same bounded campaign.
                manifest.valid_from = limits.valid_from_seconds;
                manifest.expires_at = limits.expires_at_seconds;
                registry_v23::configure_network(
                    manifest,
                    [&mut *up, &mut *down],
                    genesis,
                    program_id,
                    program_data_hash,
                )?;
                let plan =
                    deadline_plan_v23::NativeSolDeadlinePlanV23::new(manifest, limits, dom_baseline_tip)?;
                for (position, terms) in [up, down].into_iter().enumerate() {
                    terms.adaptor_point_sec1 = adaptor_point;
                    // LocalOrigin first exposure on the downstream DOM leg.
                    terms.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
                    terms.counterparty_leg.amount = u128::from(NATIVE_SOL_LEG_LAMPORTS_V25);
                    terms.fee_limit.counterparty_max =
                        u128::from(registry_v23::NATIVE_SOL_MAX_FEE_LAMPORTS_V23);
                    terms.fee_limit.dom_max = 1_000_000;
                    plan.terms(position, terms);
                }
                deadlines = Some(plan);
                Ok(())
            })();
        });
        configured?;
        let deadlines = deadlines.ok_or("SOL deadline plan absent")?;
        // Only the transport ceremony is completed here. In particular no C/D
        // proof, graph wallet, F6 grant or funding authorization is produced.
        let (fixture, contracts_bootstrap) = complete_fixture(fixture);
        let mut plans = Vec::with_capacity(2);
        for actor in 0..2 {
            plans.push(serde_json::from_slice::<Plan>(&std::fs::read(
                &fixture.plan[actor],
            )?)?);
        }
        let plans: [Plan; 2] = plans.try_into().map_err(|_| "cold-start two plans")?;
        let terms = [
            SettlementTermsV1::decode(&std::fs::read(&plans[0].terms_files[0])?)?,
            SettlementTermsV1::decode(&std::fs::read(&plans[0].terms_files[1])?)?,
        ];
        for position in 0..2 {
            if plans[0].terms_digests[position] != terms[position].terms_hash()?
                || plans[1].terms_digests[position] != terms[position].terms_hash()?
                || terms[position].adaptor_point_sec1 != adaptor_point
            {
                return Err("cold-start ceremony terms changed before setup".into());
            }
        }
        let actors = [plans[0].local_participant_id, plans[1].local_participant_id];
        let roster = ProductionRelayRosterBundleV1::decode_canonical(&std::fs::read(
            &plans[0].roster_file,
        )?)?;
        let solver = roster.legs()[0]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .ok_or("cold-start solver absent")?
            .participant_id;
        if !actors.contains(&solver.0)
            || roster.legs()[1]
                .members
                .iter()
                .find(|member| member.role == relay::SenderRoleV1::Solver)
                .map(|member| member.participant_id)
                != Some(solver)
        {
            return Err("cold-start solver roster mismatch".into());
        }
        use crate::production_inputs::ProductionRoutePositionV1::{Downstream, Upstream};
        // The signed registry of this ceremony names the chain profile whose
        // digest the terms pin; the V25 setup is validated against it.
        let signed_registry = SignedRegistryV1::decode(&std::fs::read(
            fixture._root.path().join("registry.signed.bin"),
        )?)?;
        let manifest =
            deployment_registry::RegistryManifestV1::decode(signed_registry.manifest_bytes())?;
        let funders = [
            terms[0].counterparty_leg.refund_to,
            terms[1].counterparty_leg.refund_to,
        ];
        let mut setups = Vec::with_capacity(2);
        for (position, route_position) in [Upstream, Downstream].into_iter().enumerate() {
            let terms = &terms[position];
            // Each position is funded by its own counterparty refund party:
            // the user funds the SOL it gives, the solver funds the SOL it
            // delivers. The solver funds exactly the downstream position.
            if terms.counterparty_leg.refund_to == terms.counterparty_leg.beneficiary
                || !actors.contains(&terms.counterparty_leg.refund_to.0)
                || funders[0] == funders[1]
                || (terms.counterparty_leg.refund_to == solver) != (position == 1)
            {
                return Err("cold-start SOL funders must alternate, solver downstream".into());
            }
            let registry_profile = &manifest
                .chains
                .iter()
                .find(|entry| entry.profile.chain_id == terms.counterparty_leg.chain_id)
                .ok_or("cold-start SOL chain absent from the signed registry")?
                .profile;
            let binding = solana_setup_binding_v25(
                &profile,
                terms,
                &secret,
                keys.funder(position)?,
                keys.recipient(position)?,
                program_data_hash,
                registry_profile,
            )?;
            setups.push(crate::production_inputs::ProductionSolanaLegSetupV1::new(
                route_position,
                profile,
                binding,
            )?);
        }
        Ok(Self {
            fixture,
            terms,
            plans,
            contracts_bootstrap,
            participant_setups: setups
                .try_into()
                .map_err(|_| "cold-start two SOL setups")?,
            origin_secret: Zeroizing::new(secret.dom_secret_big_endian()),
            negotiated_dom_history_maximum_v24: deadlines.maximum_dom_height_v24(),
        })
    }

    pub(crate) fn negotiated_dom_history_maximum_v24(&self) -> u64 {
        self.negotiated_dom_history_maximum_v24
    }

    /// The downstream DOM beneficiary sends the first-exposure DOM claim.
    pub(crate) fn origin_actor_id_v25(&self) -> [u8; 32] {
        self.terms[1].dom_leg.beneficiary.0
    }

    pub(crate) fn origin_secret_v25(&self) -> &Zeroizing<[u8; 32]> {
        &self.origin_secret
    }

    /// Re-authenticate signed observations; never import a time capability.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_authenticated(
        &self,
        actor: usize,
        state_dir: &Path,
        paths: crate::production_config::ProductionPathReferencesV1,
        signed_registry: deployment_registry::SignedRegistryV1,
        signed_policy: route_time_anchor::SignedRouteTimePolicyV2,
        signed_evidence: route_time_anchor::SignedRouteTimeEvidenceV2,
        now_seconds: u64,
        credentials: &NativeSolDaemonCredentialsV23,
    ) -> ColdStartResult<
        crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23,
    > {
        use crate::production_inputs::native_daemon_planning_v23::{
            NativeDaemonPlanningContextV23, NativeDaemonPlanningInputsV23,
            ParticipantFinisherV25,
        };
        let plan = self.plans.get(actor).ok_or("cold-start actor index")?;
        // Both actors must produce byte-identical proofs (the F6 record carries
        // their digests), so the validity window derives from the one signed
        // observation, never from each actor's own clock.
        let observed_at =
            route_time_anchor::RouteTimeEvidenceV2::decode(signed_evidence.evidence_bytes())
                .map_err(|_| "cold-start signed evidence does not decode")?
                .observed_at_seconds();
        let finish: ParticipantFinisherV25<'_> = Box::new(move |admission, registry| {
            let rosters = ProductionRelayRosterBundleV1::decode_canonical(&std::fs::read(
                &plan.roster_file,
            )?)?;
            let proofs = self.solana_account_proofs_v25(
                credentials,
                &rosters,
                admission,
                registry,
                observed_at,
            )?;
            Ok(
                crate::production_inputs::ProductionParticipantBindingBundleV1::new_with_solana_account_proofs_v25(
                    plan.route_id,
                    Vec::new(),
                    Vec::new(),
                    self.participant_setups.to_vec(),
                    Vec::new(),
                    proofs,
                )?,
            )
        });
        let authorities = ProductionAuthorityBundleV1::decode_canonical(&std::fs::read(
            &plan.authority_bundle_file,
        )?)?;
        let rosters =
            ProductionRelayRosterBundleV1::decode_canonical(&std::fs::read(&plan.roster_file)?)?;
        let participants =
            crate::production_inputs::ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
                plan.route_id, Vec::new(), Vec::new(),
                self.participant_setups.to_vec(),
                Vec::new(),
            )?;
        if deployment_registry::RegistryManifestV1::decode(signed_registry.manifest_bytes())?
            .manifest_digest()?
            != plan.registry_manifest_digest
        {
            return Err("cold-start changed ceremony registry".into());
        }
        NativeDaemonPlanningContextV23::prepare_for_families_with_participants_v25(
            state_dir,
            paths,
            NativeDaemonPlanningInputsV23 {
                signed_registry,
                authorities,
                terms: self.terms.clone(),
                signed_policy,
                signed_evidence,
                rosters,
                participants,
                contracts_bootstrap: self.contracts_bootstrap.clone(),
                route_id: plan.route_id,
                network_id: plan.network_id,
                minimum_registry_epoch: plan.minimum_registry_epoch,
                now_seconds,
            },
            SOL_FAMILIES_V25,
            finish,
        )
    }

    /// Test-only producer of both V25 Solana account proofs on each position:
    /// the role's Ed25519 account signs, and so does the participant's frozen
    /// Relay roster key. This fixture holds both actors' secrets; in a real
    /// deployment each participant signs only its own statement.
    fn solana_account_proofs_v25(
        &self,
        credentials: &NativeSolDaemonCredentialsV23,
        rosters: &ProductionRelayRosterBundleV1,
        admission: &crate::admission::AuthenticatedRouteAdmissionV1,
        registry: &deployment_registry::ResolvedRegistryV1,
        observed_at_seconds: u64,
    ) -> ColdStartResult<Vec<crate::production_inputs::ProductionSolanaLegAccountProofsV25>> {
        use crate::production_inputs::ProductionRoutePositionV1::{Downstream, Upstream};
        use ed25519_dalek::Signer;
        use participant_binding::{
            solana_account_binding_digest_v25, SolanaAccountBindingProofV25,
            SolanaAccountBindingStatementV25, SolanaBindingRoleV25,
        };
        let secp = SecpContext::new(&[0x5B; 32]);
        let mut result = Vec::with_capacity(2);
        for (position, (route_position, leg)) in [
            (Upstream, route_executor::LegIdV1::Upstream),
            (Downstream, route_executor::LegIdV1::Downstream),
        ]
        .into_iter()
        .enumerate()
        {
            let terms = &self.terms[position];
            let deployment = admission
                .solana_deployment_capability(leg)
                .map_err(|_| "cold-start SOL deployment capability refused")?;
            let escrow_program = match deployment.profile().kind {
                chain_profile::ChainKindV1::Solana { escrow_program, .. } => escrow_program,
                _ => return Err("cold-start SOL deployment is not a Solana chain".into()),
            };
            let roster = rosters
                .legs()
                .iter()
                .find(|candidate| candidate.position == route_position)
                .ok_or("cold-start SOL roster leg absent")?;
            let sign = |role: SolanaBindingRoleV25,
                        participant: ParticipantId|
             -> ColdStartResult<SolanaAccountBindingProofV25> {
                let actor = (0..2)
                    .find(|actor| self.plans[*actor].local_participant_id == participant.0)
                    .ok_or("cold-start SOL role participant is no actor")?;
                let relay_secret = self.relay_secret_v25(actor, position)?;
                let xonly = secp
                    .xonly_public_key(&relay_secret)
                    .map_err(|_| "cold-start relay key")?;
                if !roster
                    .members
                    .iter()
                    .any(|member| member.participant_id == participant && member.xonly_key == xonly)
                {
                    return Err("cold-start relay secret is not the frozen roster key".into());
                }
                let seed = credentials.local_seed(position, actor)?;
                let account = ed25519_dalek::SigningKey::from_bytes(&seed);
                let statement = SolanaAccountBindingStatementV25 {
                    network_id: registry.manifest().network_id,
                    registry_digest: registry.manifest_digest(),
                    route_id: admission.route_id(),
                    settlement_id: terms.settlement_id.0,
                    session_id: terms.session_id.0,
                    terms_digest: admission.frozen_bindings().terms_digest,
                    roster_snapshot: roster.roster_snapshot,
                    participant_id: participant,
                    participant_xonly_key: xonly,
                    account: account.verifying_key().to_bytes(),
                    position: route_position.solana_position(),
                    role,
                    issued_at: observed_at_seconds,
                    valid_until: observed_at_seconds.saturating_add(86_400),
                    genesis_hash: deployment.deployment().genesis_hash,
                    escrow_program,
                };
                let digest = solana_account_binding_digest_v25(&statement)
                    .map_err(|_| "cold-start SOL account binding digest")?;
                // Fixed auxiliary randomness keeps both actors' bytes identical.
                let (participant_signature, signed_key) = secp
                    .sign_bip340(&relay_secret, &digest, &[0x5A; 32])
                    .map_err(|_| "cold-start participant signature")?;
                if signed_key != xonly {
                    return Err("cold-start participant signed with another key".into());
                }
                Ok(SolanaAccountBindingProofV25::new(
                    statement,
                    account.sign(&digest).to_bytes(),
                    participant_signature,
                ))
            };
            let funder = sign(SolanaBindingRoleV25::Funder, terms.counterparty_leg.refund_to)?;
            let beneficiary = sign(
                SolanaBindingRoleV25::Beneficiary,
                terms.counterparty_leg.beneficiary,
            )?;
            result.push(
                crate::production_inputs::ProductionSolanaLegAccountProofsV25::new(
                    route_position,
                    funder,
                    beneficiary,
                )?,
            );
        }
        Ok(result)
    }

    /// The Relay secret the ceremony fixture issued to `actor` for `position`.
    fn relay_secret_v25(&self, actor: usize, position: usize) -> ColdStartResult<Zeroizing<[u8; 32]>> {
        let value: serde_json::Value = serde_json::from_slice(
            self.fixture
                .credentials
                .get(actor)
                .ok_or("cold-start actor index")?,
        )?;
        let field = if position == 0 {
            "upstream_relay_secret"
        } else {
            "downstream_relay_secret"
        };
        let bytes = hex::decode(value[field].as_str().ok_or("cold-start relay secret field")?)?;
        Ok(Zeroizing::new(
            bytes
                .try_into()
                .map_err(|_| "cold-start relay secret width")?,
        ))
    }

    /// Transfer the original databases to the actual processes, with no live
    /// parent SQLite handles. Call only after both exports passed the loader.
    pub(crate) fn launch_with_dependencies_v25(
        self,
        binary: &crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23,
        exports: [crate::production_f6_factory::native_daemon_export_v23::ExportedNativeDaemonV23;
            2],
        dependencies: Option<Box<dyn std::any::Any>>,
    ) -> ColdStartResult<NativeSolRunningColdStartV23> {
        use crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23;
        // Tuple field order keeps helpers ahead of TempDir cleanup on failure.
        let pending = (dependencies, self);
        let cold = &pending.1;
        for (actor, export) in exports.iter().enumerate() {
            if export.route_id != cold.plans[actor].route_id
                || export.config_digest == [0; 32]
                || !export.state_dir.starts_with(&cold.fixture.work[actor])
                || std::fs::canonicalize(&export.state_dir)? != export.state_dir
            {
                return Err("cold-start export actor ownership mismatch".into());
            }
        }
        if exports[0].state_dir == exports[1].state_dir {
            return Err("cold-start daemon state directories alias".into());
        }
        let (dependencies, cold) = pending;
        let Self { fixture, .. } = cold;
        let mut guard = NativeSolLaunchGuardV23 {
            processes: Vec::with_capacity(2),
            dependencies,
            fixture,
        };
        let mut restart = Vec::with_capacity(2);
        for export in &exports {
            restart.push(NativeSolRestartInputV23 {
                state_dir: export.state_dir.clone(),
                credentials: export.stdin_v4.clone(),
                manifests: NativeSolRestartInputV23::read_manifests(&export.state_dir)?,
            });
        }
        let [alice, bob] = exports;
        guard.processes.push(binary.launch_for_families_v25(
            &alice.state_dir,
            alice.stdin_v4,
            NativeDaemonModeV23::Create,
            SOL_FAMILIES_V25,
        )?);
        guard.processes.push(binary.launch_for_families_v25(
            &bob.state_dir,
            bob.stdin_v4,
            NativeDaemonModeV23::Create,
            SOL_FAMILIES_V25,
        )?);
        let processes: [crate::production_xmr_native_binary_v23_tests::NativeDaemonProcessV23; 2] =
            guard
                .processes
                .try_into()
                .map_err(|_| "two started daemons required")?;
        Ok(NativeSolRunningColdStartV23 {
            processes: processes.map(Some),
            restart: restart
                .try_into()
                .map_err(|_| "two retained restart inputs required")?,
            _dependencies: guard.dependencies,
            _fixture: guard.fixture,
        })
    }

    pub(crate) fn signed_registry(&self) -> ColdStartResult<SignedRegistryV1> {
        Ok(SignedRegistryV1::decode(&std::fs::read(
            self.root().join("registry.signed.bin"),
        )?)?)
    }

    pub(crate) fn authority_bundle(&self) -> ColdStartResult<ProductionAuthorityBundleV1> {
        Ok(ProductionAuthorityBundleV1::decode_canonical(
            &std::fs::read(&self.plans[0].authority_bundle_file)?,
        )?)
    }

    pub(crate) fn roster_bundle(&self) -> ColdStartResult<ProductionRelayRosterBundleV1> {
        Ok(ProductionRelayRosterBundleV1::decode_canonical(
            &std::fs::read(&self.plans[0].roster_file)?,
        )?)
    }

    pub(crate) fn actor_id(&self, actor: usize) -> ColdStartResult<[u8; 32]> {
        Ok(self
            .plans
            .get(actor)
            .ok_or("cold-start actor index")?
            .local_participant_id)
    }

    pub(crate) fn identity_store(&self, actor: usize) -> ColdStartResult<&Path> {
        Ok(&self
            .plans
            .get(actor)
            .ok_or("cold-start actor index")?
            .identity_store)
    }

    pub(crate) fn root(&self) -> &Path {
        self.fixture._root.path()
    }

    pub(crate) fn actor_work(&self, actor: usize) -> ColdStartResult<&Path> {
        self.fixture
            .work
            .get(actor)
            .map(PathBuf::as_path)
            .ok_or_else(|| "cold-start actor index".into())
    }
}

/// The two-phase `solana-session-init` construction without its setup store:
/// the proof binds the settlement and the pre-adaptor context (funder and
/// deadline included), PDAs are derived, and the V25 rule must accept it: the
/// escrow pays the real recipient account and refunds the funder account.
fn solana_setup_binding_v25(
    profile: &solana_profile::SolanaAdapterProfileV1,
    terms: &SettlementTermsV1,
    secret: &xmr_dleq_sigma::CrossCurveSecret252,
    funder: SolanaPubkey,
    recipient: SolanaPubkey,
    program_data_hash: [u8; 32],
    registry_profile: &chain_profile::ChainProfileV1,
) -> ColdStartResult<solana_profile::SolanaSetupBindingV1> {
    use solana_profile::{
        proof_context_from_terms, proof_context_hash, setup_id,
        validate_setup_for_chain_profile_v25, SolanaAssetV1, SolanaSetupAccountsV25,
        SolanaSetupBindingV1,
    };
    let asset = SolanaAssetV1::NativeSol;
    let context = proof_context_from_terms(terms, asset, funder)?;
    let context_hash = proof_context_hash(profile, &context)?;
    let dleq = xmr_dleq_sigma::prove_bound(
        secret,
        terms.settlement_id.0,
        context_hash,
        xmr_dleq_sigma::ROLE_SOLANA_CONDITION_LOCK,
        &mut rand::thread_rng(),
    )?;
    let pdas = solana_pda::derive_escrow_pdas(profile.program_id, terms.settlement_id.0)?;
    let kaystra_core::types::TimelockSpec::TimestampSeconds { value } =
        terms.counterparty_leg.deadline
    else {
        return Err("SOL counterparty deadline must be a cluster timestamp".into());
    };
    let mut binding = SolanaSetupBindingV1 {
        settlement_id: terms.settlement_id.0,
        terms_hash: terms.terms_hash()?,
        dleq,
        program_id: profile.program_id,
        state_pda: pdas.state,
        vault_pda: pdas.native_vault,
        vault_authority: pdas.vault_authority,
        state_bump: pdas.state_bump,
        vault_bump: pdas.native_vault_bump,
        authority_bump: pdas.vault_authority_bump,
        asset,
        funder,
        recipient,
        refund_recipient: funder,
        amount: u64::try_from(terms.counterparty_leg.amount)?,
        refund_after_unix: i64::try_from(value)?,
        program_data_hash,
        setup_id: [0; 32],
    };
    binding.setup_id = setup_id(&binding)?;
    validate_setup_for_chain_profile_v25(
        profile,
        terms,
        binding.clone(),
        registry_profile,
        SolanaSetupAccountsV25 {
            funder,
            recipient,
            refund_recipient: funder,
        },
    )?;
    Ok(binding)
}
