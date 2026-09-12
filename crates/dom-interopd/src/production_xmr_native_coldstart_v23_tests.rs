//! Ceremony and share enrollment before the daemon produces any C/D output.
//! This deliberately never calls the component graph/wallet fixture: the real
//! daemon must create its own reservation and Contracts journals from scratch.
use super::*;
#[path = "production_xmr_native_mainnet_startup_v23_tests.rs"]
mod mainnet_startup_v23;
pub(crate) use mainnet_startup_v23::{NativeMainnetStartupV23, MAINNET_BASELINE_TIP_V23};
#[path = "production_xmr_native_daemon_f6_v23_tests.rs"]
mod daemon_f6_v23;
pub(crate) use daemon_f6_v23::{
    NativeF6ProvisionV23, NativeF6XmrInventoryObservationV23, NativeF6XmrInventorySourceV23,
};
#[path = "production_xmr_native_daemon_resources_v23_tests.rs"]
mod daemon_resources_v23;
#[path = "production_xmr_native_daemon_wallet_v23_tests.rs"]
mod daemon_wallet_v23;
pub(crate) use daemon_resources_v23::NativeXmrDaemonResourcesV23;
#[path = "production_xmr_native_daemon_credentials_v23_tests.rs"]
mod daemon_credentials_v23;
pub(crate) use daemon_credentials_v23::NativeXmrDaemonCredentialsV23;
#[path = "production_xmr_native_deadline_plan_v23_tests.rs"]
mod deadline_plan_v23;
#[path = "production_xmr_native_mainnet_preparation_v23_tests.rs"]
mod mainnet_preparation_v23;
#[path = "production_xmr_native_signed_time_v23_tests.rs"]
mod signed_time_v23;
pub(crate) use signed_time_v23::ColdStartSignedTimeV23;
use xmr_graph_wallet_tests::native_custody_v23::{
    NativeXmrEnrolledFixtureV23, NativeXmrEnrollmentPlanV23, NativeXmrRouteSecretsV23,
};

type ColdStartResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

/// Field order is deliberate: stop/reap both children before TempDir cleanup.
pub(crate) struct NativeXmrRunningColdStartV23 {
    pub(crate) processes:
        [crate::production_xmr_native_binary_v23_tests::NativeDaemonProcessV23; 2],
    _dependencies: Option<Box<dyn std::any::Any>>,
    _fixture: Fixture,
}

struct NativeLaunchGuardV23 {
    processes: Vec<crate::production_xmr_native_binary_v23_tests::NativeDaemonProcessV23>,
    dependencies: Option<Box<dyn std::any::Any>>,
    fixture: Fixture,
}

pub(crate) struct NativeXmrColdStartV23 {
    fixture: Fixture,
    pub(crate) terms: [SettlementTermsV1; 2],
    plans: [Plan; 2],
    pub(crate) contracts_bootstrap: Vec<u8>,
    pub(crate) enrolled: [NativeXmrEnrolledFixtureV23; 2],
    /// Position, then actor. These are original private databases, never copies.
    pub(crate) custody_roots: [[PathBuf; 2]; 2],
    pub(crate) participant_setups: [crate::production_inputs::ProductionXmrLegSetupV1; 2],
}

impl NativeXmrColdStartV23 {
    /// Real offline route producer: one XMR history, original actor directories,
    /// two candidates and four independently credentialed sidecars.
    pub(crate) fn prepare_mainnet_funded_v23(
        secrets: NativeXmrRouteSecretsV23,
        configuration: &xmr_graph_wallet_tests::native_observation_v23::Configuration,
        credentials: &NativeXmrDaemonCredentialsV23,
        limits: route_time_anchor::RouteTimePolicyLimitsV2,
        dom_baseline_tip: u64,
    ) -> ColdStartResult<(
        Self,
        xmr_graph_wallet_tests::native_observation_v23::RouteFundingOwnerV23,
    )> {
        let (cold, mut owner) = Self::prepare_with_funding_and_time_v23(
            secrets,
            Some((limits, dom_baseline_tip)),
            |spends, terms, work, _actors, solver| {
                let owner = configuration.start_mainnet_route_v23(
                    spends,
                    [
                        u64::try_from(terms[0].counterparty_leg.amount)?,
                        u64::try_from(terms[1].counterparty_leg.amount)?,
                    ],
                    [
                        u64::try_from(terms[0].fee_limit.counterparty_max)?,
                        u64::try_from(terms[1].fee_limit.counterparty_max)?,
                    ],
                    work,
                    &credentials.sidecar_auth,
                    solver,
                )?;
                let plans = [
                    NativeXmrEnrollmentPlanV23 {
                        funding_tx_hash: owner.hash(0)?,
                        funding_destination: owner.destination(0)?,
                    },
                    NativeXmrEnrollmentPlanV23 {
                        funding_tx_hash: owner.hash(1)?,
                        funding_destination: owner.destination(1)?,
                    },
                ];
                Ok((plans, owner))
            },
        )?;
        let authority = owner.inventory_authority_id_v23()?;
        let actor = (0..2)
            .find(|actor| cold.actor_id(*actor).ok() == Some(authority))
            .ok_or("solver inventory custody actor absent")?;
        let network = cold.plans[0].network_id;
        let route = cold.plans[0].route_id;
        let sessions = [cold.terms[0].session_id.0, cold.terms[1].session_id.0];
        let terms = [cold.terms[0].terms_hash()?, cold.terms[1].terms_hash()?];
        let store_path = cold.custody_roots[0][actor].join("native-xmr-secrets-v23.sqlite");
        let descriptor_path = cold.actor_work(actor)?.join(
            xmr_graph_wallet_tests::native_observation_v23::NATIVE_XMR_INVENTORY_DESCRIPTOR_V23,
        );
        owner.persist_inventory_source_v23(
            network,
            route,
            sessions,
            terms,
            &descriptor_path,
            |record_id, binding, material| {
                cold.enrolled[0].persist_inventory_material_v23(
                    actor,
                    &store_path,
                    record_id,
                    binding,
                    material,
                )
            },
        )?;
        Ok((cold, owner))
    }
    /// `planned` must come from the offline funding producer's actual bytes.
    /// Enrollment records identity only; it is neither chain evidence nor F7.
    pub(crate) fn prepare(
        secrets: NativeXmrRouteSecretsV23,
        planned: [NativeXmrEnrollmentPlanV23; 2],
    ) -> ColdStartResult<Self> {
        Ok(Self::prepare_with_funding_v23(secrets, |_, _, _, _, _| Ok((planned, ())))?.0)
    }

    /// Retain original actor paths before publishing candidates/enrollment.
    pub(crate) fn prepare_with_funding_v23<T>(
        secrets: NativeXmrRouteSecretsV23,
        provision: impl FnOnce(
            [[u8; 32]; 2],
            &[SettlementTermsV1; 2],
            [&Path; 2],
            [[u8; 32]; 2],
            [u8; 32],
        ) -> ColdStartResult<([NativeXmrEnrollmentPlanV23; 2], T)>,
    ) -> ColdStartResult<(Self, T)> {
        Self::prepare_with_funding_and_time_v23(secrets, None, provision)
    }

    fn prepare_with_funding_and_time_v23<T>(
        secrets: NativeXmrRouteSecretsV23,
        time: Option<(route_time_anchor::RouteTimePolicyLimitsV2, u64)>,
        provision: impl FnOnce(
            [[u8; 32]; 2],
            &[SettlementTermsV1; 2],
            [&Path; 2],
            [[u8; 32]; 2],
            [u8; 32],
        ) -> ColdStartResult<([NativeXmrEnrollmentPlanV23; 2], T)>,
    ) -> ColdStartResult<(Self, T)> {
        let spends = [
            secrets.combined_spend_public_key(0)?,
            secrets.combined_spend_public_key(1)?,
        ];
        let mut deadlines = None;
        let fixture = fixture_with_registry_configuration_v23(true, |manifest, terms| {
            secrets.configure_registry(manifest, terms).unwrap();
            if let Some((limits, tip)) = time {
                deadlines = Some(
                    deadline_plan_v23::NativeDeadlinePlanV23::new(manifest, limits, tip).unwrap(),
                );
            }
        });
        let fixture = xmr_graph_wallet_tests::configure_wallet_fixture_with_policy_v23(
            fixture,
            true,
            |position, terms| {
                secrets.configure_terms(position, terms).unwrap();
                if let Some(plan) = &deadlines {
                    plan.terms(position, terms);
                }
            },
            |position, terms, policy| {
                if let Some(plan) = &deadlines {
                    plan.compensation(position, policy).unwrap();
                    // New fixture quote, frozen before either signature. Keep
                    // DOM principal and volatility reserve unchanged.
                    policy.xmr_principal_piconero =
                        u64::try_from(terms.counterparty_leg.amount).unwrap();
                    policy.quote_dom_numerator = policy.dom_principal_noms;
                    policy.quote_xmr_denominator = policy.xmr_principal_piconero;
                }
            },
        );
        // Only the transport ceremony is completed here. In particular no C/D
        // proof, graph wallet, F6 grant or funding authorization is produced.
        let (fixture, contracts_bootstrap) = complete_fixture(fixture);
        let plans: [Plan; 2] = [0, 1].map(|actor| {
            serde_json::from_slice(&std::fs::read(&fixture.plan[actor]).unwrap()).unwrap()
        });
        let terms = [0, 1].map(|position| {
            SettlementTermsV1::decode(&std::fs::read(&plans[0].terms_files[position]).unwrap())
                .unwrap()
        });
        for position in 0..2 {
            if plans[0].terms_digests[position] != terms[position].terms_hash()?
                || plans[1].terms_digests[position] != terms[position].terms_hash()?
            {
                return Err("cold-start ceremony terms changed before enrollment".into());
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
        let (planned, funding_owner) = provision(
            spends,
            &terms,
            [fixture.work[0].as_path(), fixture.work[1].as_path()],
            actors,
            solver.0,
        )?;
        let custody_roots: [[PathBuf; 2]; 2] = std::array::from_fn(|position| {
            std::array::from_fn(|actor| {
                fixture.work[actor].join(format!("cold-start-xmr-position-{position}"))
            })
        });
        for root in custody_roots.iter().flatten() {
            directory(root);
        }
        let enrolled = secrets.enroll(
            [&terms[0], &terms[1]],
            planned,
            [actors, actors],
            [
                [custody_roots[0][0].as_path(), custody_roots[0][1].as_path()],
                [custody_roots[1][0].as_path(), custody_roots[1][1].as_path()],
            ],
        )?;
        use crate::production_inputs::ProductionRoutePositionV1::{Downstream, Upstream};
        let participant_setups = [
            enrolled[0].participant_setup_v23(Upstream, &terms[0])?,
            enrolled[1].participant_setup_v23(Downstream, &terms[1])?,
        ];
        Ok((
            Self {
                fixture,
                terms,
                plans,
                contracts_bootstrap,
                enrolled,
                custody_roots,
                participant_setups,
            },
            funding_owner,
        ))
    }

    /// Re-authenticate signed observations; never import a time capability.
    pub(crate) fn prepare_authenticated(
        &self,
        actor: usize,
        state_dir: &Path,
        paths: crate::production_config::ProductionPathReferencesV1,
        signed_registry: deployment_registry::SignedRegistryV1,
        signed_policy: route_time_anchor::SignedRouteTimePolicyV2,
        signed_evidence: route_time_anchor::SignedRouteTimeEvidenceV2,
        now_seconds: u64,
    ) -> ColdStartResult<
        crate::production_inputs::native_daemon_planning_v23::NativeDaemonPlanningContextV23,
    > {
        use crate::production_inputs::native_daemon_planning_v23::{
            NativeDaemonPlanningContextV23, NativeDaemonPlanningInputsV23,
        };
        let plan = self.plans.get(actor).ok_or("cold-start actor index")?;
        let authorities = ProductionAuthorityBundleV1::decode_canonical(&std::fs::read(
            &plan.authority_bundle_file,
        )?)?;
        let rosters =
            ProductionRelayRosterBundleV1::decode_canonical(&std::fs::read(&plan.roster_file)?)?;
        let participants =
            crate::production_inputs::ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
                plan.route_id, Vec::new(), Vec::new(), Vec::new(),
                self.participant_setups.to_vec(),
            )?;
        if deployment_registry::RegistryManifestV1::decode(signed_registry.manifest_bytes())?
            .manifest_digest()?
            != plan.registry_manifest_digest
        {
            return Err("cold-start changed ceremony registry".into());
        }
        NativeDaemonPlanningContextV23::prepare(
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
        )
    }

    /// Transfer the original databases to the actual processes, with no live
    /// parent SQLite handles. Call only after writing is complete and both
    /// exports have passed the production loader and local-only runner guards.
    pub(crate) fn launch(
        self,
        binary: &crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23,
        exports: [crate::production_f6_factory::native_daemon_export_v23::ExportedNativeDaemonV23;
            2],
    ) -> ColdStartResult<NativeXmrRunningColdStartV23> {
        self.launch_with_dependencies_v23(binary, exports, None)
    }

    pub(crate) fn launch_with_dependencies_v23(
        self,
        binary: &crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23,
        exports: [crate::production_f6_factory::native_daemon_export_v23::ExportedNativeDaemonV23;
            2],
        dependencies: Option<Box<dyn std::any::Any>>,
    ) -> ColdStartResult<NativeXmrRunningColdStartV23> {
        use crate::production_xmr_native_binary_v23_tests::NativeDaemonModeV23;
        // Tuple field order keeps helpers ahead of TempDir cleanup on preflight failure.
        let pending = (dependencies, self);
        let cold = &pending.1;
        for (actor, export) in exports.iter().enumerate() {
            if export.route_id != cold.plans[actor].route_id
                || export.config_digest == [0; 32]
                || !export.state_dir.starts_with(&cold.fixture.work[actor])
                || std::fs::canonicalize(&export.state_dir)? != export.state_dir
                || cold
                    .custody_roots
                    .iter()
                    .flatten()
                    .any(|root| export.state_dir.starts_with(root) || root == &export.state_dir)
            {
                return Err("cold-start export actor ownership mismatch".into());
            }
        }
        if exports[0].state_dir == exports[1].state_dir {
            return Err("cold-start daemon state directories alias".into());
        }
        let (dependencies, cold) = pending;
        let Self {
            fixture, enrolled, ..
        } = cold;
        // This is the only transition from enrollment-owner to runtime-owner.
        // Every encrypted secret/nullifier connection closes before launch.
        drop(enrolled);
        let mut guard = NativeLaunchGuardV23 {
            processes: Vec::with_capacity(2),
            dependencies,
            fixture,
        };
        let [alice, bob] = exports;
        guard.processes.push(binary.launch(
            &alice.state_dir,
            alice.stdin_v4,
            NativeDaemonModeV23::Create,
        )?);
        guard.processes.push(binary.launch(
            &bob.state_dir,
            bob.stdin_v4,
            NativeDaemonModeV23::Create,
        )?);
        Ok(NativeXmrRunningColdStartV23 {
            processes: guard
                .processes
                .try_into()
                .map_err(|_| "two started daemons required")?,
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

    pub(crate) fn compensation_policy(&self, position: usize) -> ColdStartResult<Vec<u8>> {
        let paths = self.plans[0]
            .xmr_compensation_policy_files
            .as_ref()
            .ok_or("cold-start compensation policies absent")?;
        let path = paths
            .get(position)
            .and_then(Option::as_ref)
            .ok_or("cold-start compensation position")?;
        Ok(std::fs::read(path)?)
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
