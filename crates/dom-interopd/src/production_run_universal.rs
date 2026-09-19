//! Universal production entrypoint. Every external resource belongs to its
//! selected position; DOM/Contracts/Relay remain the common mandatory center.
//! No manifest family can substitute a signer or a chain-funding capability.
use super::*;
use crate::production_chain_signers::{
    provision_production_chain_signers_v6, ProductionChainSignerProvisioningRequestV6,
};
use crate::production_config::{
    load_production_bootstrap_v11, load_production_create_or_resume_bootstrap_v11,
    provisioning_binding_for_v11_bootstrap, universal_actuator_stage_v11,
    ProductionBitcoinPrebroadcastPinsV7, ProductionBootstrapModeV1, ProductionChainFamilyV11,
    ProductionUniversalLegV11,
};
use crate::production_node::{ProductionLegCredentialsV4, ProductionSecretsV4};
use crate::production_plan_source::{
    ProductionChainPublicSecretSourceV1, ProductionPublicSecretRequestV1,
    ProductionPublicSecretSourceV1,
};
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;
use crate::production_run::ProductionF6StageFailureV25;
use crate::production_route_services::{LegClientsV8, SelectedServicesV8};
use crate::production_universal_leg_authority::{
    ProductionUniversalEvmSignerPairV11, ProductionUniversalLegAuthorityV11,
    ProductionUniversalSolanaSignerPairV11, ProductionUniversalXmrAuthorityV11,
};
use evm_actuator::EvmRpcV1 as _;
use route_composer::{ComposedFinalClaimRolePlanV1, FinalClaimSecretSourceScopeV1};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Names which Stage-11 step refused. The refusal itself is unchanged: the
/// step tag is closed and carries no path, byte, credential or nested text.
const fn f6_step_v25(step: ProductionF6StageFailureV25) -> ProductionRunErrorV1 {
    ProductionRunErrorV1::F6AuthoritiesDetail(step)
}
#[cfg(test)]
#[path = "production_xmr_custody_startup_paths_v23_tests.rs"]
mod custody_startup_paths_v23;
#[path = "production_native_phase_ownership_v24.rs"]
mod native_phase_ownership_v24;

pub(super) fn run(
    options: &ProductionRunOptionsV1,
    secrets: ProductionSecretsV4,
) -> Result<(), ProductionRunErrorV1> {
    // Install the sole process signal consumer after the one blocking secret
    // read, but before any future Relay/RPC or actuator worker can be spawned.
    // Installing it before stdin would suppress the default SIGTERM action
    // while no runtime loop yet existed to observe the shutdown token. The
    // guard remains on this thread and restores the prior mask on every typed
    // return path.
    let (mut _run_control, shutdown) = SystemRouteRunControlV1::new();
    let mut _signal_bridge = ProductionSignalBridgeV1::install(shutdown)
        .map_err(|_| ProductionRunErrorV1::SignalBridge)?;

    let bootstrap = match options.mode {
        ProductionRunModeV1::Create => {
            load_production_create_or_resume_bootstrap_v11(&options.state_dir)
        }
        ProductionRunModeV1::ReopenExisting => load_production_bootstrap_v11(
            &options.state_dir,
            ProductionBootstrapModeV1::ReopenExisting,
        ),
    }
    // Carry the redacted class of check that refused. This is the manifest
    // load, which is where an operator assembling a state directory needs to
    // learn *what* was wrong; every variant is already free of paths,
    // endpoints and input bytes.
    .map_err(ProductionRunErrorV1::ConfigurationDetail)?;
    let families = bootstrap
        .config()
        .universal_v11()
        .ok_or(ProductionRunErrorV1::Configuration)?
        .families();
    let secrets = secrets
        .into_parts(families)
        .map_err(|_| ProductionRunErrorV1::Secrets)?;
    let crate::production_node::ProductionSecretPartsV4 {
        bearer,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        identity_passphrase,
        dom_wallet_passphrase,
        route_secret_seal_key,
        xmr_graph_vault_key_v23,
        refund_arming_credential,
        legs: credentials,
        f6_hsm: [upstream_f6_hsm_credentials, downstream_f6_hsm_credentials],
    } = secrets;
    let relay_network_config = bind_relay_network_v11(&bootstrap)?;
    let provisioning_binding = provisioning_binding_for_v11_bootstrap(&bootstrap)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let mut provisioning = match options.mode {
        ProductionRunModeV1::Create => {
            DurableProductionProvisioningJournalV1::open_or_create_after_absence_check(
                bootstrap.layout().state_dir(),
                provisioning_binding,
            )
        }
        ProductionRunModeV1::ReopenExisting => DurableProductionProvisioningJournalV1::open(
            bootstrap.layout().state_dir(),
            provisioning_binding,
        ),
    }
    .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::ReopenExisting {
        require_reopen_provisioning_prefix(&provisioning)?;
    }
    let trusted_now_seconds = trusted_now_seconds_v1()?;
    let mut inputs = match options.mode {
        ProductionRunModeV1::Create => load_authenticated_production_inputs_with_provisioning_v1(
            &bootstrap,
            trusted_now_seconds,
            &mut provisioning,
        ),
        ProductionRunModeV1::ReopenExisting => {
            load_authenticated_production_inputs_v1(&bootstrap, trusted_now_seconds)
        }
    }
    .map_err(|_| ProductionRunErrorV1::Inputs)?;
    bootstrap
        .require_universal_admission_v11(&inputs)
        .map_err(|_| ProductionRunErrorV1::Inputs)?;
    inputs
        .contracts_bootstrap()
        .ok_or(ProductionRunErrorV1::Inputs)?;
    inputs
        .audit_external_custody_only()
        .map_err(|_| ProductionRunErrorV1::RouteJournalPolicy)?;
    let runtime_bounds = bootstrap.config().bounds();
    let dom_deployment = inputs
        .admission()
        .dom_deployment_capability()
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let dom_node = load_production_node_config_v1(bootstrap.layout().state_dir())
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let dom_history_limit = dom_node.history_limit();
    let dom_chain_adapter = dom_node
        .into_dom_chain_adapter(
            bearer,
            dom_deployment.deployment(),
            runtime_bounds.external_call_timeout_ms,
        )
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let selected_services = crate::production_route_services::load_selected_services_v11(
        bootstrap.layout().state_dir(),
        &inputs,
        runtime_bounds.external_call_timeout_ms,
    )
    .map_err(|_| ProductionRunErrorV1::ChainServices)?;
    let mut claim_observers_v20 = selected_services
        .f7_observer_plans_v20(&inputs)
        .map_err(|_| ProductionRunErrorV1::ChainServices)?;
    let claim_faces_v20 = claim_observers_v20.each_ref().map(|plan| match plan {
        Some(crate::production_contracts::ProductionF7ObserverPlanV20::Evm { .. }) => {
            Some(settlement_coordinator::SettlementFaceV1::Evm)
        }
        Some(crate::production_contracts::ProductionF7ObserverPlanV20::Solana { .. }) => {
            Some(settlement_coordinator::SettlementFaceV1::Solana)
        }
        None => None,
    });
    let (mut selected, bitcoin_participant_secrets) =
        SelectedLegV11::prepare_pair(&bootstrap, &inputs, credentials, selected_services)?;
    let mut bitcoin_transports = selected.each_ref().map(|selected| match selected {
        SelectedLegV11::Bitcoin { bundle, .. } => Some(
            crate::production_bitcoin_runtime_v11::ProductionBitcoinRuntimeTransportV11::new(
                bootstrap.layout().state_dir().to_path_buf(),
                bundle.claim_peer_socket.clone(),
                Duration::from_millis(bundle.claim_exchange_timeout_ms),
            ),
        ),
        _ => None,
    });
    // Share the already-open selected Core clients with the DOM claim observer.
    let bitcoin_dom_clients_v22 = selected.each_ref().map(|leg| match leg {
        SelectedLegV11::Bitcoin { live, .. } => Some(Rc::clone(live)),
        _ => None,
    });
    let mut bitcoin_claim_installed_v22 = [false; 2];
    let state_capability = state_dir_capability(bootstrap.layout().state_dir())?;
    let vault_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RouteSecretVault)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::Create
        && vault_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_vault_create_prefix_absent(&state_capability)?;
    }
    let vault_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RouteSecretVault)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => vault_stage_before_begin,
    };
    let route_secret_retention = open_route_secret_retention(
        options.mode,
        vault_stage_before_begin,
        vault_stage,
        Arc::clone(&state_capability),
        route_secret_seal_key,
    )?;
    if options.mode == ProductionRunModeV1::Create
        && vault_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::RouteSecretVault)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if vault_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let coordinator_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::CoordinatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let coordinator_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::CoordinatorStore);
    if options.mode == ProductionRunModeV1::Create
        && coordinator_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_coordinator_create_prefix_absent(coordinator_path)?;
    }
    let coordinator_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::CoordinatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => coordinator_stage_before_begin,
    };
    let pins = bootstrap.config().pins();
    let now_unix_ms = trusted_now_seconds
        .checked_mul(1_000)
        .ok_or(ProductionRunErrorV1::CoordinatorStore)?;
    let coordinator = open_settlement_coordinator(
        options.mode,
        coordinator_stage_before_begin,
        coordinator_stage,
        coordinator_path,
        pins.coordinator_id,
        pins.coordinator_plan_authority_id,
        now_unix_ms,
    )?;
    if options.mode == ProductionRunModeV1::Create
        && coordinator_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::CoordinatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if coordinator_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let dom_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::DomActuatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let dom_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::DomActuatorStore);
    if options.mode == ProductionRunModeV1::Create
        && dom_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_dom_actuator_create_prefix_absent(dom_path)?;
    }
    let dom_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::DomActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => dom_stage_before_begin,
    };
    let mut dom_actuator_store =
        open_dom_actuator_store(options.mode, dom_stage_before_begin, dom_stage, dom_path)?;
    if options.mode == ProductionRunModeV1::Create
        && dom_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::DomActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if dom_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let (actuators, actuator_guards) = open_actuator_pair_v11(
        options.mode,
        &bootstrap,
        &mut provisioning,
        &selected,
        provisioning_binding,
    )?;
    let mut chain_signers =
        provision_production_chain_signers_v6(ProductionChainSignerProvisioningRequestV6 {
            bootstrap: &bootstrap,
            inputs: &inputs,
            journal: &mut provisioning,
            upstream_relay_signing_secret: &upstream_relay_signing_secret,
            downstream_relay_signing_secret: &downstream_relay_signing_secret,
            dom_wallet_passphrase,
            bitcoin_participant_secrets,
        })
        .map_err(|_| ProductionRunErrorV1::ChainSignerAuthorities)?;
    for external in &selected {
        external.require_local_participant(chain_signers.participant_id().0)?;
    }
    let inventory_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::SolverInventoryStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let inventory_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::SolverInventoryStore);
    if options.mode == ProductionRunModeV1::Create
        && inventory_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_solver_inventory_create_prefix_absent(inventory_path)?;
    }
    let inventory_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::SolverInventoryStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => inventory_stage_before_begin,
    };
    let solver_inventory = open_solver_inventory_store(
        options.mode,
        inventory_stage_before_begin,
        inventory_stage,
        inventory_path,
        pins.solver_inventory_binding_digest,
    )?;
    complete_provisioning_stage(
        options.mode,
        inventory_stage,
        ProductionProvisioningStageV1::SolverInventoryStore,
        &mut provisioning,
    )?;

    let contracts_trusted_chain =
        crate::production_contracts_session_bootstrap::authenticate_production_contracts_chain_v23(
            &dom_chain_adapter,
            inputs
                .contracts_bootstrap()
                .ok_or(ProductionRunErrorV1::ContractsStores)?,
        )
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let contracts_policy = load_contracts_budget_policy(&bootstrap)?;
    let xmr_graph_vault_provisioner_v23 = xmr_graph_vault_key_v23.mount(
        Arc::clone(&state_capability),
        contracts_policy.clone(),
        options.mode == ProductionRunModeV1::Create,
    );
    let upstream_contracts_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::UpstreamContracts);
    let downstream_contracts_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::DownstreamContracts);
    let upstream_contracts_root =
        contracts_root_name(bootstrap.layout().state_dir(), upstream_contracts_path)?;
    let downstream_contracts_root =
        contracts_root_name(bootstrap.layout().state_dir(), downstream_contracts_path)?;
    let contracts_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::ContractsStores)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::Create
        && contracts_stage_before_begin != ProductionProvisioningStageStateV1::Complete
    {
        preflight_contracts_store_pair(
            Arc::clone(&state_capability),
            upstream_contracts_root,
            downstream_contracts_root,
            &contracts_policy,
            provisioning_binding,
            contracts_stage_before_begin == ProductionProvisioningStageStateV1::Started,
            contracts_trusted_chain,
        )?;
    }
    let contracts_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::ContractsStores)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => contracts_stage_before_begin,
    };
    let contracts_stores = open_contracts_store_pair(ContractsStorePairRequestV1 {
        mode: options.mode,
        stage_before_begin: contracts_stage_before_begin,
        stage: contracts_stage,
        parent: Arc::clone(&state_capability),
        upstream_root: upstream_contracts_root,
        downstream_root: downstream_contracts_root,
        policy: contracts_policy,
        creation_binding: provisioning_binding,
        chain: contracts_trusted_chain,
    })?;
    let identity_store_path = bootstrap
        .layout()
        .contracts_transport_identity_store()
        .ok_or(ProductionRunErrorV1::ContractsStores)?;
    let authenticated_contracts_bootstrap = inputs
        .contracts_bootstrap()
        .ok_or(ProductionRunErrorV1::ContractsStores)?;
    let mut contracts_stage10_owner =
        bootstrap_production_contracts_sessions_v1(ProductionContractsSessionBootstrapRequestV1 {
            state_capability: Arc::clone(&state_capability),
            state_dir: bootstrap.layout().state_dir(),
            identity_store_path,
            bootstrap_artifact_path: bootstrap
                .layout()
                .contracts_bootstrap()
                .ok_or(ProductionRunErrorV1::ContractsStores)?,
            identity_passphrase,
            dom_chain_adapter,
            authenticated_bootstrap: authenticated_contracts_bootstrap,
            chain_signers: &chain_signers,
            upstream_store: contracts_stores.upstream,
            downstream_store: contracts_stores.downstream,
        })
        .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
    complete_provisioning_stage(
        options.mode,
        contracts_stage,
        ProductionProvisioningStageV1::ContractsStores,
        &mut provisioning,
    )?;

    // Stage 11 authenticates every immutable F6 input before publishing a
    // prefix. The bundle file was already digest-pinned by the V8 loader; this
    // second boundary verifies its threshold signatures and exact route scope.
    let f6_bundle_path = bootstrap
        .layout()
        .f6_path_v8(ProductionF6PathRoleV8::AuthorityBundleV7)
        .ok_or(f6_step_v25(ProductionF6StageFailureV25::BundlePath))?;
    let f6_bundle_bytes = read_owner_file_bounded(
        f6_bundle_path,
        MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::BundleRead))?;
    let f6_bundle = AuthenticatedProductionF6AuthorityBundleV7::decode_and_authenticate(
        &f6_bundle_bytes,
        &inputs,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::BundleDecode))?;
    let f6_solver = f6_bundle.solver();
    let native_xmr_inventory_max_age_seconds = f6_bundle.inventory_proof_max_age_seconds();
    let historical_f6_recovery_v24 = if options.mode == ProductionRunModeV1::ReopenExisting {
        let retained = inputs
            .historical_f6_recovery_v24()
            .map_err(|_| ProductionRunErrorV1::Inputs)?;
        match retained {
            Some(recovery) => Some(recovery),
            None => SelectedLegV11::recover_native_committed_funding_v24(
                &mut selected,
                &inputs,
                &coordinator,
                bootstrap.layout().state_dir(),
            )?,
        }
    } else {
        None
    };
    // This is the non-test production consumer of the durable XMR inventory
    // source. On the solver of the authenticated native XMR/XMR enrollment
    // profile, F6 cannot proceed when the descriptor, V4-backed Store row,
    // sidecar, raw quorum, finality or key-image absence disagree. Mixed
    // routes use the bound profile and do not consume this two-leg artifact.
    let (native_xmr_inventory_required, native_xmr_inventory) =
        if historical_f6_recovery_v24.is_some() {
            (false, None)
        } else {
            SelectedLegV11::observe_native_xmr_inventory_v23(
                &mut selected,
                &inputs,
                bootstrap.layout().state_dir(),
                f6_solver.0,
                native_xmr_inventory_max_age_seconds,
            )?
        };
    let f6_route = ProductionF6AuthenticatedRouteContextV7::from_authenticated(&inputs);
    let composition_owner = inputs.composition_owner();
    let route_id = inputs.admission().route_id();
    let funding_window_v23 = crate::production_timer::ProductionFundingWindowV23::new(route_id);
    let composition_digest = inputs.composition().binding_digest();
    let dom_chain_id = inputs.composition().upstream().dom_leg.chain_id;

    let f6_external_paths = ProductionF6ExternalPathsV7::new(
        bootstrap.layout().state_dir(),
        [
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamStatusStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamStatusStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamTimeStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamTimeStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamCandidateStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamCandidateStore)?
                .to_path_buf(),
        ],
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::ActivationPaths))?;
    let f6_external_prepared = ProductionF6ExternalPreparedBindingsV7::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
    let upstream_f6_prepared = ProductionF6PreparedBindingsV2::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
        SettlementPositionV2::Upstream,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
    let downstream_f6_prepared = ProductionF6PreparedBindingsV2::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
        SettlementPositionV2::Downstream,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
    let upstream_f6_paths = ProductionF6ActivationPathsV2::from_v4_layout(
        bootstrap.layout(),
        SettlementPositionV2::Upstream,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::ActivationPaths))?;
    let downstream_f6_paths = ProductionF6ActivationPathsV2::from_v4_layout(
        bootstrap.layout(),
        SettlementPositionV2::Downstream,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::ActivationPaths))?;

    // Only selected Bitcoin positions reopen a native prebroadcast owner.
    let mut bitcoin_owners = open_bitcoin_owners_v11(&bootstrap, &inputs, &selected)?;
    let f6_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::F6Authorities)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let f6_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::F6Authorities)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => f6_stage_before_begin,
    };
    require_f6_stage_open_state(options.mode, f6_stage)?;

    // A Started stage is an authenticated, idempotent creation prefix. The
    // retained V4 journals and the six V8 RFQ-late owners are prepared in one
    // fixed order and are never touched before the global begin record.
    if f6_stage == ProductionProvisioningStageStateV1::Started {
        upstream_f6_prepared
            .prepare_stage11(ProductionF6PathsV2 {
                binding_log: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamBindingLog,
                )?,
                receipt_store: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamReceiptStore,
                )?,
                candidate_book: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamCandidateBook,
                )?,
            })
            .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
        downstream_f6_prepared
            .prepare_stage11(ProductionF6PathsV2 {
                binding_log: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamBindingLog,
                )?,
                receipt_store: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamReceiptStore,
                )?,
                candidate_book: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamCandidateBook,
                )?,
            })
            .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
        f6_external_prepared
            .prepare_stage11(&f6_external_paths)
            .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Prefix))?;
    }

    // The wallet, not this root, selects the unique commitments. Both session
    // bindings and their one physical participant lease are durable, making a
    // crash anywhere in this pair exactly resumable.
    let (upstream_dom_payout, downstream_dom_payout, mut dom_lease) = authenticate_dom_f6_payouts(
        &inputs,
        contracts_stage10_owner.private_bootstrap_v13.as_mut(),
        &mut chain_signers,
        &mut dom_actuator_store,
        pins.process_owner_id,
        trusted_now_millis_v1()?,
        runtime_bounds.actuator_lease_ms,
    )?;
    let [upstream_payout, downstream_payout] = take_bitcoin_payouts_v11(&mut bitcoin_owners)?;
    let upstream_counterparty = ProductionF6CounterpartyTermsOwnerV7::from_authenticated(
        &inputs,
        LegIdV1::Upstream,
        upstream_payout,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::CounterpartyFace))?;
    let downstream_counterparty = ProductionF6CounterpartyTermsOwnerV7::from_authenticated(
        &inputs,
        LegIdV1::Downstream,
        downstream_payout,
    )
    .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::CounterpartyFace))?;
    let mut f6_pair_factory =
        ProductionF6PairAuthoritiesFactoryV7::new(ProductionF6PairFactoryRequestV7 {
            bundle: f6_bundle,
            route: f6_route,
            composition: composition_owner,
            paths: f6_external_paths,
            prepared: f6_external_prepared,
            inventory: solver_inventory,
            inventory_owner_id: pins.process_owner_id,
            inventory_lease_duration_ms: runtime_bounds.lease_duration_ms,
            native_xmr_inventory,
            native_xmr_inventory_required,
            terms: ProductionF6TermsOwnersV7 {
                upstream_dom: upstream_dom_payout,
                downstream_dom: downstream_dom_payout,
                upstream_counterparty,
                downstream_counterparty,
            },
            credentials: ProductionF6BondSignerCredentialsV7 {
                upstream: upstream_f6_hsm_credentials,
                downstream: downstream_f6_hsm_credentials,
            },
        })
        .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Factory))?;
    if let Some(recovery) = &historical_f6_recovery_v24 {
        f6_pair_factory = f6_pair_factory
            .with_historical_recovery_v24(recovery.clone())
            .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::HistoricalRecovery))?;
    }
    let f6_final_claim_plan = f6_pair_factory
        .take_final_claim_plan()
        .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::ClaimPlan))?;
    let route_store = inputs
        .take_route_store_for_f6()
        .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::RouteStore))?;
    let (upstream_f6_activation, downstream_f6_activation, f6_runtime_receiver) =
        ProductionF6PairActivationRequestV2 {
            route_store,
            route_id,
            composition_v2_digest: composition_digest,
            upstream: ProductionF6PairLegMaterialsV2::new(
                SettlementPositionV2::Upstream,
                f6_solver,
                dom_chain_id,
                upstream_f6_paths,
                upstream_f6_prepared,
            ),
            downstream: ProductionF6PairLegMaterialsV2::new(
                SettlementPositionV2::Downstream,
                f6_solver,
                dom_chain_id,
                downstream_f6_paths,
                downstream_f6_prepared,
            ),
            authority_factory: Box::new(f6_pair_factory),
        }
        .into_authorities()
        .map_err(|_| f6_step_v25(ProductionF6StageFailureV25::Activation))?;

    // Completion certifies that every move-only Stage-11 owner exists in this
    // process. It is deliberately after the one-shot RouteStore transfer and
    // pair split; a crash before here leaves Started and resumes every prefix.
    complete_provisioning_stage(
        options.mode,
        f6_stage,
        ProductionProvisioningStageV1::F6Authorities,
        &mut provisioning,
    )?;

    let relay_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RelayAuthorities)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let relay_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RelayAuthorities)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => relay_stage_before_begin,
    };
    let relay_stage12 = construct_production_relay_stage12_v1(ProductionRelayStage12RequestV1 {
        xmr_graph_vault_provisioner_v23,
        bootstrap: &bootstrap,
        inputs: &inputs,
        chain_signers: &chain_signers,
        contracts: contracts_stage10_owner,
        upstream_activation: upstream_f6_activation,
        downstream_activation: downstream_f6_activation,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        mode: match options.mode {
            ProductionRunModeV1::Create => ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionRunModeV1::ReopenExisting => ProductionRelayStage12ModeV1::ReopenExisting,
        },
        stage_before_begin: relay_stage_before_begin,
        stage: relay_stage,
    })
    .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;
    let relay_stage12 = relay_stage12
        .recover_production_f6_applied_history()
        .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;
    complete_provisioning_stage(
        options.mode,
        relay_stage,
        ProductionProvisioningStageV1::RelayAuthorities,
        &mut provisioning,
    )?;
    let relay_stage12_owner = relay_stage12
        .finish(&provisioning)
        .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;
    // ------------------------------------------------------------------
    // Activate the same Relay/F6 owners before asking for bilateral ready.
    // Child funding is still impossible: no child/router exists yet.
    //
    // The retained Stage-12 owner moves into the composite loop here; every
    // authority that needed `&mut` access to it was derived above. Socket and
    // exchange bounds come from the authenticated V10 external-call bound and
    // the Relay poll backoff, so no timing constant is invented. Activation is
    // bounded per invocation and re-entered until the exact pair receiver
    // releases the route Store, or shutdown is requested.
    // ------------------------------------------------------------------
    let external_call_bound = Duration::from_millis(runtime_bounds.external_call_timeout_ms);
    let relay_backoff = Duration::from_millis(runtime_bounds.relay_poll_backoff_ms);
    // The live services' RPC ceiling may be 30 seconds. The composite loop
    // separately caps connect/accept plus exchange at 30 seconds combined.
    let composite_call_bound = external_call_bound.min(Duration::from_secs(15));
    let composite_config = ProductionCompositeLoopConfigV1::new(
        composite_call_bound,
        composite_call_bound,
        composite_call_bound,
        relay_backoff,
        // Return between Relay rounds so retained DOM authority is renewed
        // while the counterparty is still negotiating F6.
        1,
    )
    .map_err(|error| ProductionRunErrorV1::CompositeLoopDetail(error.failure_v25()))?;
    let mut activation = ProductionCompositeActivationV1::new(
        relay_stage12_owner,
        f6_runtime_receiver,
        relay_network_config,
        composite_config,
    )
    .map_err(|error| ProductionRunErrorV1::CompositeLoopDetail(error.failure_v25()))?;
    let (mut relay_loop, route_store) = loop {
        dom_lease = dom_actuator_store
            .renew_lease(
                dom_lease,
                trusted_now_millis_v1()?,
                runtime_bounds.actuator_lease_ms,
            )
            .map_err(|_| ProductionRunErrorV1::DomActuatorStore)?;
        match activation.activate_bounded(&mut _run_control) {
            ProductionCompositeActivationExitV1::Ready { relay, route_store } => {
                break (relay, route_store);
            }
            ProductionCompositeActivationExitV1::RoundBudgetExhausted(again) => {
                activation = again;
            }
            ProductionCompositeActivationExitV1::Shutdown(_) => {
                // Shutdown before activation: no route lease was taken and no
                // effect was externalized by this process. The retained
                // stores are closed by drop in reverse construction order.
                return Ok(());
            }
            ProductionCompositeActivationExitV1::Failed { error, .. } => {
                return Err(ProductionRunErrorV1::CompositeLoopDetail(
                    error.failure_v25(),
                ));
            }
        }
    };

    // Public early/BP preparation can finish for XMR. Funding stays behind
    // the unchanged native compensation refusal, before any child is built.
    require_compensated_xmr_funding_authority_v11(&inputs)?;
    let bitcoin_readiness =
        load_bitcoin_readiness_v11(&inputs, &chain_signers, relay_loop.stage12_owner_mut_v11())?;
    let mut relay_stage12_owner = relay_loop.stage12_owner_mut_v11();

    // Stage 13 binds all four refund verifiers before any funding child can be
    // constructed. The authority epoch is the immutable V9 configuration pin;
    // it is deliberately distinct from the supervisor's dynamic route fence.
    let refund_authority_epoch = bootstrap
        .config()
        .refund_arming_authority_epoch_v9()
        .ok_or(ProductionRunErrorV1::Configuration)?;
    let deadline_timer =
        ProductionDeadlineTimerAuthorityV1::from_composition(route_id, inputs.composition())
            .map_err(|_| ProductionRunErrorV1::TimerAuthority)?;
    let height_deadlines_v23 =
        crate::production_timer::ProductionHeightDeadlineAuthorityV23::from_composition(
            route_id,
            inputs.composition(),
            inputs.admission().frozen_bindings().clone(),
        )
        .map_err(|_| ProductionRunErrorV1::TimerAuthority)?;
    let mut xmr_deadline_sources_v23 = Vec::new();
    for (position, selected_leg) in selected.iter().enumerate() {
        let (deployment, urls) = match selected_leg {
            SelectedLegV11::Monero {
                deployment,
                funding_daemon_urls_v22,
                ..
            }
            | SelectedLegV11::MoneroEnrollment {
                deployment,
                funding_daemon_urls_v22,
                ..
            } => (deployment, funding_daemon_urls_v22),
            _ => continue,
        };
        let leg = if position == 0 {
            LegIdV1::Upstream
        } else {
            LegIdV1::Downstream
        };
        let session = inputs
            .monero_session(leg)
            .ok_or(ProductionRunErrorV1::Inputs)?;
        xmr_deadline_sources_v23.push(
            crate::production_timer::ProductionXmrDeadlineSourceV23::new(
                leg,
                deployment.clone(),
                session.profile().clone(),
                urls.clone(),
            )
            .map_err(|_| ProductionRunErrorV1::TimerAuthority)?,
        );
    }
    let refund_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RefundArmingAuthority)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let refund_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RefundArmingAuthority)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => refund_stage_before_begin,
    };
    let upstream_dom_refund = relay_stage12_owner
        .dom_refund_face_for_selected_v23(
            LegIdV1::Upstream,
            ProductionDomRefundFaceScopeV1::new(
                inputs.admission(),
                inputs.composition(),
                LegIdV1::Upstream,
                pins.process_owner_id,
                refund_authority_epoch,
            )
            .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
            chain_signers.dom_binding(LegIdV1::Upstream),
        )
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let downstream_dom_refund = relay_stage12_owner
        .dom_refund_face_for_selected_v23(
            LegIdV1::Downstream,
            ProductionDomRefundFaceScopeV1::new(
                inputs.admission(),
                inputs.composition(),
                LegIdV1::Downstream,
                pins.process_owner_id,
                refund_authority_epoch,
            )
            .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
            chain_signers.dom_binding(LegIdV1::Downstream),
        )
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let upstream_public_source = selected[0].public_source(&inputs, LegIdV1::Upstream)?;
    let upstream_counterparty_refund = selected[0].refund_face(
        &inputs,
        LegIdV1::Upstream,
        bitcoin_owners[0].as_ref(),
        &relay_stage12_owner,
    )?;
    let downstream_counterparty_refund = selected[1].refund_face(
        &inputs,
        LegIdV1::Downstream,
        bitcoin_owners[1].as_ref(),
        &relay_stage12_owner,
    )?;
    let refund_sources = ProductionRefundArmingSourcesV1::new(
        inputs.admission(),
        inputs.composition(),
        pins.process_owner_id,
        refund_authority_epoch,
        ProductionRefundLegV1::new(upstream_dom_refund, upstream_counterparty_refund),
        ProductionRefundLegV1::new(downstream_dom_refund, downstream_counterparty_refund),
    )
    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let refund_path = bootstrap
        .layout()
        .refund_arming_database()
        .ok_or(ProductionRunErrorV1::RefundArmingAuthority)?;
    let refund_arming_authority = open_refund_arming_authority(
        options.mode,
        refund_stage_before_begin,
        refund_stage,
        refund_path,
        refund_arming_credential,
        refund_sources,
    )?;
    complete_provisioning_stage(
        options.mode,
        refund_stage,
        ProductionProvisioningStageV1::RefundArmingAuthority,
        &mut provisioning,
    )?;
    let (role_plan, upstream_source_scope, downstream_source_scope) =
        if f6_final_claim_plan.requires_native_templates() {
            let upstream = relay_stage12_owner
                .bound_xmr_setup_v23(LegIdV1::Upstream)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            let downstream = relay_stage12_owner
                .bound_xmr_setup_v23(LegIdV1::Downstream)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            f6_final_claim_plan.materialize_native(
                inputs.composition(),
                [
                    upstream
                        .native_refund_binding_v23()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    downstream
                        .native_refund_binding_v23()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                ],
            )
        } else if f6_final_claim_plan.requires_bootstrap_claim_templates_v25() {
            // DOMF6A25: the downstream LocalOrigin source commits the real
            // native DOM claim template, which exists only now that the
            // bilateral bootstrap completed. The V20 gate below rebinds it
            // against the same Store before any funding.
            // Recheck the authenticated account links at their point of use.
            // The A25 decoder checked them before the bundle was admitted;
            // retaining this boundary ensures a later caller cannot select a
            // template from a SOL setup while omitting the account authority
            // that binds the escrow's funder/refund and recipient accounts.
            let upstream_session = inputs
                .solana_session(LegIdV1::Upstream)
                .filter(|session| session.account_binding_v25().is_some())
                .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?;
            inputs
                .solana_session(LegIdV1::Downstream)
                .filter(|session| session.account_binding_v25().is_some())
                .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?;
            let upstream_setup = upstream_session.setup().binding_hash();
            let selected = relay_stage12_owner.leg_mut(LegIdV1::Downstream);
            let chain = selected.trusted_chain_id();
            let template = selected
                .contracts_mut()
                .bootstrap_claim_template_hash_v25(chain)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            f6_final_claim_plan.materialize_sol_v25(inputs.composition(), template, upstream_setup)
        } else {
            f6_final_claim_plan.into_parts()
        }
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    relay_stage12_owner
        .install_xmr_claim_context_v23(&role_plan, &upstream_source_scope, &downstream_source_scope)
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    // Build the selected plain-recovery F7 gate from native retained
    // bootstrap before children can request funding materialization.
    for (leg, position, terms, source) in [
        (
            LegIdV1::Upstream,
            dom_final_claim_binding::ComposedSettlementLegV1::Upstream,
            inputs.composition().upstream(),
            &upstream_source_scope,
        ),
        (
            LegIdV1::Downstream,
            dom_final_claim_binding::ComposedSettlementLegV1::Downstream,
            inputs.composition().downstream(),
            &downstream_source_scope,
        ),
    ] {
        if terms.policy_version == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17
            && matches!(
                terms.counterparty_leg.mechanism,
                kaystra_core::types::LockMechanism::ConditionLock
                    | kaystra_core::types::LockMechanism::CrossCurveConditionLock
            )
        {
            let selected = relay_stage12_owner.leg_mut(leg);
            let chain = selected.trusted_chain_id();
            selected
                .contracts_mut()
                .prepare_bootstrap_gate_v20(
                    chain,
                    &role_plan,
                    source,
                    position,
                    trusted_now_millis_v1()? / 1_000,
                )
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
        }
    }
    let dom_materialization_scope = ProductionDomMaterializationScopeV1::authenticate(
        &inputs,
        &role_plan,
        upstream_source_scope.clone(),
        downstream_source_scope.clone(),
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let upstream_dom_binding = chain_signers.dom_binding(LegIdV1::Upstream);
    let downstream_dom_binding = chain_signers.dom_binding(LegIdV1::Downstream);
    // The downstream local origin already exists in the signed composed
    // terms. Read that original scalar privately before any funding child is
    // opened. Receiver participants and recovery after exposure need no file.
    let origin_role = role_plan.entry(dom_final_claim_binding::ComposedSettlementLegV1::Downstream);
    let origin_terms = inputs.composition().downstream();
    if origin_terms.policy_version == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17
        && matches!(
            origin_terms.counterparty_leg.mechanism,
            kaystra_core::types::LockMechanism::ConditionLock
                | kaystra_core::types::LockMechanism::CrossCurveConditionLock
                | kaystra_core::types::LockMechanism::SchnorrAdaptor
        )
        && origin_role.dom_claim_sender_id().0
            == downstream_dom_binding.participant().participant_id()
        && origin_role.secret_source()
            == dom_final_claim_binding::FinalClaimSecretSourceV1::LocalOrigin
    {
        let selected = relay_stage12_owner.leg_mut(LegIdV1::Downstream);
        let chain = selected.trusted_chain_id();
        let contracts = selected.contracts_mut();
        if contracts
            .local_origin_needed_v21(downstream_dom_binding, &chain)
            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
        {
            let path = bootstrap
                .layout()
                .state_dir()
                .join("production-local-origin-secret.v21");
            let bytes = zeroize::Zeroizing::new(
                crate::production_config::read_owner_file_bounded(
                    &path,
                    32,
                    crate::production_config::ProductionConfigErrorV1::ConfigUnavailable,
                )
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
            );
            let scalar = zeroize::Zeroizing::new(
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
            );
            let verified = inputs
                .composition()
                .verify_revealed_scalar(&scalar)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            let secret = dom_adaptor::AdaptorSecret::from_be_bytes(*verified.expose())
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            contracts
                .install_local_origin_v21(
                    downstream_dom_binding,
                    chain,
                    secret,
                    origin_role,
                    origin_terms.adaptor_point_sec1,
                )
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
        }
    }
    let upstream_dom_contracts = relay_stage12_owner
        .leg_mut(LegIdV1::Upstream)
        .contracts_mut()
        .dom_child_store_authority(
            upstream_dom_binding,
            inputs.composition().upstream().dom_leg.deadline,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let downstream_dom_contracts = relay_stage12_owner
        .leg_mut(LegIdV1::Downstream)
        .contracts_mut()
        .dom_child_store_authority(
            downstream_dom_binding,
            inputs.composition().downstream().dom_leg.deadline,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let dom_runtime = RealDomRpcRuntimeV1::new(
        relay_stage12_owner
            .take_dom_chain_adapter()
            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
        dom_history_limit,
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    dom_lease = dom_actuator_store
        .renew_lease(
            dom_lease,
            trusted_now_millis_v1()?,
            runtime_bounds.actuator_lease_ms,
        )
        .map_err(|_| ProductionRunErrorV1::DomActuatorStore)?;
    let dom_child_composition = crate::production_child_dom::compose_production_dom_child_port_v23(
        dom_actuator_store,
        ProductionDomChildBindingsV1 {
            sessions: [
                ProductionDomChildSessionBindingsV1 {
                    leg: settlement_coordinator::SettlementLegV1::Upstream,
                    settlement_id: inputs.composition().upstream().settlement_id.0,
                    binding: upstream_dom_binding,
                    contracts: upstream_dom_contracts,
                },
                ProductionDomChildSessionBindingsV1 {
                    leg: settlement_coordinator::SettlementLegV1::Downstream,
                    settlement_id: inputs.composition().downstream().settlement_id.0,
                    binding: downstream_dom_binding,
                    contracts: downstream_dom_contracts,
                },
            ],
            lease: dom_lease,
            trusted_chain_id: relay_stage12_owner
                .leg(LegIdV1::Upstream)
                .trusted_chain_id(),
            runtime: dom_runtime,
            route_terms_digest: inputs.admission().frozen_bindings().terms_digest,
            materialization_scope: dom_materialization_scope,
        },
        runtime_bounds.actuator_lease_ms,
        funding_window_v23.clone(),
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let (dom_child, dom_public_secret_consumers, dom_f7_scanner) = dom_child_composition.split();
    let dom_f7_scanner = Rc::new(dom_f7_scanner);
    let [upstream_actuator, downstream_actuator] = actuators;
    let [upstream_selected, downstream_selected] = selected;
    let [upstream_bitcoin, downstream_bitcoin] = bitcoin_owners;
    let [upstream_guard, downstream_guard] = actuator_guards;
    let [upstream_readiness, downstream_readiness] = bitcoin_readiness;
    let mut xmr_recovery_pumps_v22 = Vec::new();
    let upstream_child = upstream_selected.into_child(
        &inputs,
        &bootstrap,
        LegIdV1::Upstream,
        &role_plan,
        &upstream_source_scope,
        &downstream_source_scope,
        upstream_actuator,
        upstream_bitcoin,
        upstream_readiness,
        upstream_guard.as_ref(),
        &mut relay_stage12_owner,
        &dom_f7_scanner,
        &mut xmr_recovery_pumps_v22,
        &funding_window_v23,
    )?;
    let downstream_child = downstream_selected.into_child(
        &inputs,
        &bootstrap,
        LegIdV1::Downstream,
        &role_plan,
        &upstream_source_scope,
        &downstream_source_scope,
        downstream_actuator,
        downstream_bitcoin,
        downstream_readiness,
        downstream_guard.as_ref(),
        &mut relay_stage12_owner,
        &dom_f7_scanner,
        &mut xmr_recovery_pumps_v22,
        &funding_window_v23,
    )?;
    let child_router = compose_materializing_route_children_v7(
        &inputs,
        dom_child,
        upstream_child,
        downstream_child,
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;

    // ------------------------------------------------------------------
    // Stages 16-17 — first-exposure custody and the public-secret sources.
    //
    // The route reveals on the downstream DOM leg first (`DomRevealsFirst`,
    // `LocalOrigin`), so the DOM downstream consumer minted by the DOM child
    // composition is the only first-exposure observer. The upstream DOM
    // consumer has no role in this reveal mode and is released here rather
    // than parked. The Bitcoin source is late-installable and is completed by
    // the materialization owner once an exact expected transaction exists. No
    // duplicate EVM RPC is opened: its source shares the retained refund
    // adapter and verifies the exact finalized lock event against exposure.
    // ------------------------------------------------------------------
    let first_exposure =
        ProductionCustodiedFirstExposureClaimAuthorityV1::bind(&inputs, &role_plan)
            .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let [upstream_dom_consumer, downstream_dom_consumer] = dom_public_secret_consumers;
    drop(upstream_dom_consumer);
    let dom_trusted_chain_id = relay_stage12_owner
        .leg(LegIdV1::Downstream)
        .trusted_chain_id();
    let dom_source_scope = ProductionDomPublicSecretSourceScopeV1::authenticate(
        composition_digest,
        settlement_coordinator::SettlementLegV1::Downstream,
        inputs.composition().downstream().settlement_id.0,
        downstream_dom_binding,
        dom_trusted_chain_id,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (dom_secret_source, dom_secret_installer) = relay_stage12_owner
        .leg_mut(LegIdV1::Downstream)
        .contracts_mut()
        .dom_public_secret_source(dom_source_scope, downstream_dom_consumer)
        .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (upstream_public_source, bitcoin_secret_installer) = match upstream_public_source {
        UpstreamPublicSourceV11::Bitcoin { chain_id } => {
            let (source, installer) = ProductionLateBitcoinPublicSecretSourceV1::new_installable(
                route_id,
                composition_digest,
                chain_id,
            )
            .map_err(|_| ProductionRunErrorV1::PlanSource)?;
            (
                Some(Box::new(source) as Box<dyn ProductionChainPublicSecretSourceV1>),
                Some(installer),
            )
        }
        UpstreamPublicSourceV11::Ready(source) => (Some(source), None),
        UpstreamPublicSourceV11::Dom => (None, None),
    };
    let secret_source_router = UniversalPublicSourcesV11 {
        dom: dom_secret_source,
        external: upstream_public_source,
    };

    // ------------------------------------------------------------------
    // Stages 18-21 — materialization owner, plan source, persistence and the
    // five settlement authorities. The owner is split exactly once into the
    // draft materializer (plan source), the child runtime handle (bridge
    // child port) and the authenticated plan authority (persistence). The
    // coordinator is moved into the bridge; no second handle to it exists.
    // ------------------------------------------------------------------
    let materialization_owner = ProductionSettlementMaterializationOwnerV1::authenticate(
        &inputs,
        &coordinator,
        role_plan,
        upstream_source_scope,
        downstream_source_scope,
        child_router,
        first_exposure,
        dom_secret_installer,
        bitcoin_secret_installer,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let mut bitcoin_pump = materialization_owner.bitcoin_post_anchor_pump_v11();
    let mut funding_identities_v20 = materialization_owner.funding_identity_reader_v20();
    let mut actuator_heartbeat = materialization_owner.actuator_heartbeat_v12();
    let bitcoin_calls = [
        inputs.composition().upstream(),
        inputs.composition().downstream(),
    ]
    .map(
        |terms| crate::production_bitcoin_claim_driver::BitcoinPostAnchorCallV11 {
            route_id,
            settlement_id: terms.settlement_id.0,
            composition_digest,
        },
    );
    let mut bitcoin_contracts: [Option<
        crate::production_contracts::ProductionContractsConsumedPostAnchorV2,
    >; 2] = [None, None];
    let (draft_materializer, child_runtime_handle, plan_authority) = materialization_owner.split();
    let plan_source = VerifiedProductionSettlementPlanSourceV1::new(
        route_id,
        inputs.admission().frozen_bindings().clone(),
        inputs.composition_owner(),
        secret_source_router,
        route_secret_retention,
        draft_materializer,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (runtime_admission, time_guard) = inputs
        .into_runtime_admission_and_time_guard()
        .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let plan_persistence = ProductionSettlementPlanPersistenceOwnerV1::new(
        time_guard,
        plan_authority,
        trusted_now_millis_v1()?,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?
    .with_evidence_inbox_v5(
        crate::production_time_inbox::ProductionTimeEvidenceInboxV5::new(Arc::clone(
            &state_capability,
        )),
    );
    let bridge_config = ProductionSettlementBridgeConfigV1::new(
        pins.process_owner_id,
        runtime_bounds.coordinator_lease_ms,
    )
    .map_err(|_| ProductionRunErrorV1::CoordinatorStore)?;
    let settlement = assemble_production_settlement_authorities_with_child_port_v1(
        coordinator,
        bridge_config,
        plan_source,
        plan_persistence,
        funding_window_v23.guard(child_runtime_handle),
    );

    // ------------------------------------------------------------------
    // Stages 25-26 — runner policy audit and route supervisor acquisition.
    //
    // The production runner is the closed external-custody-only policy; it is
    // installed only after the full-history audit proves the retained journal
    // never committed a generic runner action. The supervisor then takes the
    // one route lease under the process owner id and the authenticated V10
    // lease/renewal/dispatch bounds.
    // ------------------------------------------------------------------
    route_store
        .audit_external_custody_only_v1()
        .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    let per_queue_batch_limit = usize::try_from(runtime_bounds.per_queue_batch_limit)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    let supervisor_config = RouteSupervisorConfigV1::new(
        runtime_bounds.lease_duration_ms,
        runtime_bounds.renew_before_ms,
        runtime_bounds.dispatch_lease_ms,
        per_queue_batch_limit,
    )
    .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    let mut supervisor = RouteSupervisorV1::acquire_production_route_store(
        route_store,
        route_id,
        pins.process_owner_id,
        supervisor_config,
        SystemClockV1,
    )
    .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    if let Some(recovery) = &historical_f6_recovery_v24 {
        recovery
            .restrict_runtime(&mut supervisor)
            .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    }
    // Exact composed Unix deadlines were previously only admitted, never
    // scheduled. Stable identities preserve the original timers on restart.
    deadline_timer
        .schedule_bound_deadlines(&mut supervisor)
        .map_err(|_| ProductionRunErrorV1::TimerAuthority)?;

    // ------------------------------------------------------------------
    // Stages 27-29 — the exact authority set and the concrete route runtime.
    // ------------------------------------------------------------------
    let operational = RouteRuntimeOperationalAuthoritiesV1 {
        refund: refund_arming_authority,
        action: funding_window_v23.guard(settlement.action),
        observer: settlement.observer,
        runner: ProductionExternalCustodyOnlyRunnerV1,
    };
    let recovery = RouteRuntimeRecoveryAuthoritiesV1 {
        custody: settlement.custody,
        timers: deadline_timer,
        reconciler: settlement.takeover,
        retirement: settlement.retirement,
    };
    let authorities = RouteRuntimeAuthoritiesV1::new(operational, recovery);
    let runtime_config = RouteRuntimeConfigV1::new(
        runtime_bounds.waiting_backoff_ms,
        runtime_bounds.recovery_backoff_ms,
        supervisor_config,
    )
    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
    let mut route_runtime =
        ProductionRouteRuntimeV1::new(supervisor, runtime_admission, authorities, runtime_config)
            .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;

    // ------------------------------------------------------------------
    // Stages 30-31 — interleaved Relay/route execution until terminal or safe
    // shutdown. Bounded Relay/route invocations re-enter the same loop with
    // the same owners after budget exhaustion. Native F7 phases below also
    // checkpoint ownership separately; that is not a composite I/O timeout.
    // Every route step is durable; nothing reports unrecorded progress.
    // ------------------------------------------------------------------
    // Physical SOL/XMR ownership remains alive until after the router drops;
    // the same per-position epochs fence every retained transaction mutation.
    let _retained_actuator_guards = (upstream_guard, downstream_guard);
    // Native F7 observations/signing are outside RouteRuntime::step. Renewing
    // only actuator ownership here lets several individually slow phases
    // accumulate past the RouteStore lease. Check BOTH owners around each
    // phase, including retryable outcomes, without retrying a phase or minting
    // new funding/Claim authority. One millisecond describes this immediate
    // ownership checkpoint, NOT a timeout for the operation it surrounds.
    // Some legacy DOM scanners still lack a composite I/O deadline: if one
    // phase alone outlives ownership, the post-check fails closed and reopen
    // reconciles any durable work instead of pretending the lease survived.
    macro_rules! owned_native_phase_v24 {
        ($operation:expr) => {
            native_phase_ownership_v24::with_ownership_checkpoints_v24(
                || {
                    route_runtime
                        .prepare_bounded_external_block(Duration::from_millis(1))
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                    actuator_heartbeat
                        .renew()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    Ok::<(), ProductionRunErrorV1>(())
                },
                || Ok($operation),
            )?
        };
    }
    // Refresh before work which can create funding, not only before recovery
    // pumps (which may consume the entire previous observation's lifetime).
    // The shared gate independently rechecks expiry at authorization/dispatch.
    let mut retry_height_observation_v23: bool;
    macro_rules! refresh_funding_window_v23 {
        () => {
            if historical_f6_recovery_v24.is_some() {
                funding_window_v23.close();
            } else if retry_height_observation_v23 && !funding_window_v23.available() {
                funding_window_v23.close();
                let observation_started = std::time::Instant::now();
                let mut all_before_deadline = true;
                let observation_bound = if xmr_deadline_sources_v23.is_empty() {
                    external_call_bound
                } else {
                    external_call_bound.max(Duration::from_secs(60))
                };
                route_runtime
                    .prepare_bounded_external_block(observation_bound)
                    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                actuator_heartbeat
                    .renew()
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                for observed in height_deadlines_v23.observe_selected_v23(
                    &dom_f7_scanner,
                    external_call_bound,
                    &xmr_deadline_sources_v23,
                ) {
                    match observed {
                        Ok(deadlines) => {
                            all_before_deadline &= deadlines.is_empty();
                            for deadline in deadlines {
                                route_runtime
                                    .record_height_deadline_recovery_v23(deadline)
                                    .map_err(|_| ProductionRunErrorV1::TimerAuthority)?;
                            }
                        }
                        Err(crate::supervisor::AuthorityRefusalV1::Unavailable) => {
                            all_before_deadline = false;
                        }
                        Err(_) => return Err(ProductionRunErrorV1::TimerAuthority),
                    }
                }
                if all_before_deadline {
                    funding_window_v23.observed_all_before_deadline(observation_started);
                }
                // A failed/too-slow observation closes fresh funding for this
                // round. Do not spend another full RPC budget at each signing
                // seam and delay recovery. The next round retries naturally.
                retry_height_observation_v23 = funding_window_v23.available();
            }
        };
    }
    macro_rules! drain_terminal_refund_v24 {
        ($snapshot:expr) => {{
            use crate::production_composite_loop::{
                TerminalRefundDrainBudgetV24, TerminalRefundDrainProgressV24,
            };
            use crate::production_xmr_remote_sweep_v23::RefundPublicationProgressV24;
            let snapshot = $snapshot;
            // Terminal serving has no path back to funding or recovery BUILD.
            // Only LOAD/proof verification and the existing public transcript
            // may advance; economic/Relay expiry is never rewritten here.
            funding_window_v23.close();
            let mut budget = TerminalRefundDrainBudgetV24::new(std::time::Instant::now())
                .map_err(|_| ProductionRunErrorV1::CompositeLoop)?;
            let mut progress = [TerminalRefundDrainProgressV24::default(); 2];
            let relay_bound = relay_loop.terminal_refund_relay_bound_v24();
            'drain: while budget.next_round(std::time::Instant::now()) {
                let mut outstanding = false;
                for pump in &mut xmr_recovery_pumps_v22 {
                    let Some(leg) = pump.terminal_refund_leg_v24(&snapshot) else {
                        continue;
                    };
                    let index = match leg {
                        LegIdV1::Upstream => 0,
                        LegIdV1::Downstream => 1,
                    };
                    if progress[index].complete() {
                        continue;
                    }
                    outstanding = true;
                    if crate::RouteRunControlV1::shutdown_requested(&mut _run_control)
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
                        || !budget.permits(std::time::Instant::now(), relay_bound)
                    {
                        break 'drain;
                    }
                    route_runtime
                        .prepare_bounded_external_block(relay_bound)
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                    actuator_heartbeat
                        .renew()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    // Receive the real 0x19 BEFORE the publisher, then flush
                    // the exact resulting 0x1a AFTER it in this same round.
                    let incoming_flushed = relay_loop
                        .step_terminal_refund_v24(leg)
                        .map_err(|_| ProductionRunErrorV1::CompositeLoop)?;
                    progress[index].observe_flush(incoming_flushed);
                    if progress[index].complete() {
                        route_runtime
                            .prepare_bounded_external_block(Duration::from_millis(1))
                            .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                        actuator_heartbeat
                            .renew()
                            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                        continue;
                    }
                    if crate::RouteRunControlV1::shutdown_requested(&mut _run_control)
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
                        || !budget.permits(std::time::Instant::now(), Duration::from_millis(1))
                    {
                        break 'drain;
                    }
                    if progress[index].needs_publication() {
                        let call_bound = Duration::from_secs(60);
                        route_runtime
                            .prepare_bounded_external_block(call_bound)
                            .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                        actuator_heartbeat
                            .renew()
                            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                        let call_deadline = budget.deadline().min(
                            std::time::Instant::now()
                                .checked_add(call_bound)
                                .ok_or(ProductionRunErrorV1::Configuration)?,
                        );
                        let publication = match pump
                            .tick_remote_refund_bounded_v24(&snapshot, call_deadline)
                        {
                            Ok(progress) => progress,
                            Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => {
                                RefundPublicationProgressV24::Waiting
                            }
                            Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                        };
                        if matches!(
                            publication,
                            RefundPublicationProgressV24::Staged
                                | RefundPublicationProgressV24::Complete
                        ) {
                            progress[index].publication_staged();
                        }
                    }
                    // Recheck the retained lease after external observation;
                    // a stale writer must not send a newly staged response.
                    route_runtime
                        .prepare_bounded_external_block(relay_bound)
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                    actuator_heartbeat
                        .renew()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    if crate::RouteRunControlV1::shutdown_requested(&mut _run_control)
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
                        || !budget.permits(std::time::Instant::now(), relay_bound)
                    {
                        break 'drain;
                    }
                    let flushed = relay_loop
                        .step_terminal_refund_v24(leg)
                        .map_err(|_| ProductionRunErrorV1::CompositeLoop)?;
                    route_runtime
                        .prepare_bounded_external_block(Duration::from_millis(1))
                        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                    actuator_heartbeat
                        .renew()
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    progress[index].observe_flush(flushed);
                }
                if !outstanding {
                    break;
                }
                // Finite retry, never a service awaiting a future peer. Budget
                // exhaustion keeps every original pending byte for reopen.
                let backoff = relay_backoff.min(Duration::from_millis(100));
                if !budget.permits(std::time::Instant::now(), backoff) {
                    break;
                }
                crate::RouteRunControlV1::wait(&mut _run_control, backoff)
                    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
            }
        }};
    }
    loop {
        let before_round = route_runtime
            .snapshot()
            .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
        if xmr_recovery_pumps_v22
            .iter()
            .any(|pump| pump.terminal_refund_leg_v24(&before_round).is_some())
        {
            // Reopen of an already-terminal refund must not run the normal
            // bootstrap/F7/compensation pumps even once before public serving.
            drain_terminal_refund_v24!(before_round);
            break;
        }
        retry_height_observation_v23 = true;
        refresh_funding_window_v23!();
        for pump in &mut xmr_recovery_pumps_v22 {
            // The responder reads original refund effects and existing local
            // bytes even after route dispatch has moved past materialization.
            // No peer response is a prerequisite for the funder's own refund.
            let snapshot = route_runtime
                .snapshot()
                .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
            route_runtime
                .prepare_bounded_external_block(std::time::Duration::from_secs(60))
                .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
            actuator_heartbeat
                .renew()
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            match pump.tick_remote_refund_v24(&snapshot) {
                Ok(()) | Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => {}
                Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
            }
            // Separate funding observation and execution ticks preserve the
            // one-minute freshness bound without a second sidecar owner.
            route_runtime
                .prepare_bounded_external_block(std::time::Duration::from_secs(60))
                .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
            actuator_heartbeat
                .renew()
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            match pump.tick() {
                Ok(Some(report)) => match route_runtime.record_xmr_compensation_v22(report) {
                    Ok(()) | Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => {}
                    Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                },
                Ok(None) | Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => {}
                Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
            }
        }
        actuator_heartbeat
            .renew()
            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
        // Observe/install receiver authority before Relay drains the next
        // candidate. Each native profile decides readiness; absent F7 on a
        // Bitcoin leg is not treated as a universal claim authorization.
        for (leg, binding) in [
            (LegIdV1::Upstream, upstream_dom_binding),
            (LegIdV1::Downstream, downstream_dom_binding),
        ] {
            refresh_funding_window_v23!();
            match owned_native_phase_v24!(relay_loop.stage12_owner_mut_v11().step_f7_funding_v20(
                leg,
                binding,
                &dom_f7_scanner,
                &funding_window_v23,
                trusted_now_millis_v1()? / 1_000,
            )) {
                Ok(()) => {}
                Err(error) if error.retryable() => {}
                Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
            }
            let index = match leg {
                LegIdV1::Upstream => 0,
                LegIdV1::Downstream => 1,
            };
            match owned_native_phase_v24!(relay_loop
                .stage12_owner_mut_v11()
                .step_native_xmr_f7_claim_v23(
                    leg,
                    binding,
                    Rc::clone(&dom_f7_scanner),
                    trusted_now_millis_v1()? / 1_000,
                )) {
                Ok(()) => {}
                Err(error) if error.retryable_v20() => {}
                // Closed Claim windows must leave noncooperative recovery running.
                Err(crate::production_contracts::ProductionF7RuntimeErrorV12::Evidence(
                    f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11::WindowClosed,
                )) => {}
                Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
            }
            if let Some(face) = claim_faces_v20[index] {
                let child_leg = match leg {
                    LegIdV1::Upstream => settlement_coordinator::SettlementLegV1::Upstream,
                    LegIdV1::Downstream => settlement_coordinator::SettlementLegV1::Downstream,
                };
                match funding_identities_v20.read(
                    face,
                    child_leg,
                    route_id,
                    bitcoin_calls[index].settlement_id,
                ) {
                    Ok(Some(id)) => {
                        match owned_native_phase_v24!(relay_loop.stage12_owner_mut_v11().step_f7_claim_v20(leg, binding,
                            Rc::clone(&dom_f7_scanner), &mut claim_observers_v20[index], id,
                            trusted_now_millis_v1()? / 1_000)) {
                            Ok(()) => {}
                            Err(error) if error.retryable_v20() => {}
                            // An elapsed signing window refuses claim, while
                            // leaving the route driver able to execute refund.
                            Err(crate::production_contracts::ProductionF7RuntimeErrorV12::Evidence(
                                f7_anchor_authority::families_v11::F7FamilyAuthorityErrorV11::WindowClosed)) => {}
                            Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                        }
                    }
                    Ok(None)
                    | Err(settlement_coordinator::ChildAuthorityRefusalV1::Unavailable) => {}
                    Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                }
            }
            match owned_native_phase_v24!(relay_loop
                .stage12_owner_mut_v11()
                .leg_mut(leg)
                .contracts_mut()
                .step_f7_claim_receiver_v15(binding, dom_trusted_chain_id, &dom_f7_scanner))
            {
                Ok(_) => {}
                Err(error) if error.retryable() => {}
                Err(_) => return Err(ProductionRunErrorV1::SettlementChildAuthority),
            }
        }
        refresh_funding_window_v23!();
        match run_production_composite_runtime_bounded_v1(
            &mut relay_loop,
            &mut route_runtime,
            &mut _run_control,
            // M.8 must be interleaved with each real route step. Running a
            // large batch first could leave the first-exposure guard waiting
            // for the pump which the same root had not yet called.
            1,
        )
        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
        {
            ProductionCompositeRuntimeExitV1::Terminal { .. } => {
                let terminal = route_runtime
                    .snapshot()
                    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
                drain_terminal_refund_v24!(terminal);
                break;
            }
            ProductionCompositeRuntimeExitV1::Shutdown { .. } => break,
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { .. } => {}
        }
        if crate::RouteRunControlV1::shutdown_requested(&mut _run_control)
            .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
        {
            break;
        }
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            actuator_heartbeat
                .renew()
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            let Some(transport) = bitcoin_transports[index].as_mut() else {
                continue;
            };
            if bitcoin_claim_installed_v22[index] || bitcoin_contracts[index].is_some() {
                let binding = if index == 0 {
                    upstream_dom_binding
                } else {
                    downstream_dom_binding
                };
                let bitcoin = bitcoin_dom_clients_v22[index]
                    .as_ref()
                    .ok_or(ProductionRunErrorV1::BitcoinChildAuthority)?;
                match relay_loop.stage12_owner_mut_v11().step_post_m8_claim_v22(
                    leg,
                    binding,
                    &mut bitcoin_contracts[index],
                    Rc::clone(&dom_f7_scanner),
                    Rc::clone(bitcoin),
                    trusted_now_millis_v1()? / 1_000,
                ) {
                    Ok(installed) => bitcoin_claim_installed_v22[index] |= installed,
                    Err(error) if error.retryable() => {}
                    Err(_) => return Err(ProductionRunErrorV1::BitcoinChildAuthority),
                }
                continue;
            }
            transport.start_attempt();
            let mut participant = chain_signers
                .bitcoin_authority(leg)
                .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
            let child_leg = match leg {
                LegIdV1::Upstream => settlement_coordinator::SettlementLegV1::Upstream,
                LegIdV1::Downstream => settlement_coordinator::SettlementLegV1::Downstream,
            };
            let result = bitcoin_pump.drive(
                child_leg,
                bitcoin_calls[index],
                crate::production_bitcoin_claim_driver::BitcoinPostAnchorExternalResourcesV11 {
                    relay: relay_loop.stage12_owner_mut_v11(),
                    scanner: &dom_f7_scanner,
                    participant: &mut participant,
                    transport,
                },
            );
            match result {
                Ok(Some(contracts)) => {
                    contracts
                        .revalidate()
                        .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                    bitcoin_contracts[index] = Some(contracts);
                }
                Ok(None) => {}
                Err(error)
                    if crate::production_bitcoin_runtime_v11::retryable_post_anchor_v11(&error) => {
                }
                Err(_) => return Err(ProductionRunErrorV1::BitcoinChildAuthority),
            }
        }
    }

    // ------------------------------------------------------------------
    // Stages 32-33 — teardown in reverse ownership order. The route runtime
    // (and its lease) goes first, then the Relay loop and its Noise sessions,
    // then every retained store by scope exit; the signal-bridge guard is the
    // last to drop and restores the prior mask on this return path.
    // ------------------------------------------------------------------
    drop(route_runtime);
    drop(relay_loop);
    Ok(())
}

/// Load only selected Bitcoin positions after Relay/F6 activation. A missing
/// or inconsistent bilateral record refuses startup; no generic InvalidStage
/// error is recast as an indefinitely pending peer vote. A later restart can
/// authenticate the same retained Store after the native readiness producer
/// has completed. Non-Bitcoin positions never ask for M.8 authority.
fn load_bitcoin_readiness_v11(
    inputs: &AuthenticatedProductionInputsV1,
    signers: &crate::production_chain_signers::ProductionChainSignerAuthoritiesV1,
    relay: &mut ProductionRelayStage12OwnerV1,
) -> Result<
    [Option<crate::production_contracts::ProductionBitcoinPrefundingReadinessV11>; 2],
    ProductionRunErrorV1,
> {
    let mut readiness = [None, None];
    for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
        .into_iter()
        .enumerate()
    {
        if inputs.bitcoin_session(leg).is_none() {
            continue;
        }
        readiness[index] = Some(
            relay
                .leg_mut(leg)
                .contracts_mut()
                .bitcoin_retained_prefunding_readiness_v11(signers.dom_binding(leg))
                .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?,
        );
    }
    Ok(readiness)
}

fn bind_relay_network_v11(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<ProductionRelayNetworkConfigV1, ProductionRunErrorV1> {
    let peers = bootstrap
        .config()
        .remote_relay_database_ids()
        .ok_or(ProductionRunErrorV1::Configuration)?;
    let local = bootstrap
        .config()
        .relay_authority_pins_v6()
        .ok_or(ProductionRunErrorV1::Configuration)?
        .relay_database_id;
    let network = load_production_relay_network_config_v1(bootstrap.layout().state_dir())
        .map_err(|_| ProductionRunErrorV1::RelayNetworkConfiguration)?;
    if network.shared_peer_v23()
        != bootstrap
            .config()
            .universal_v11()
            .ok_or(ProductionRunErrorV1::Configuration)?
            .shared_relay_peer_v23
    {
        return Err(ProductionRunErrorV1::RelayNetworkConfiguration);
    }
    let upstream =
        RelayDatabaseIdV1::new(peers[0]).map_err(|_| ProductionRunErrorV1::Configuration)?;
    let downstream =
        RelayDatabaseIdV1::new(peers[1]).map_err(|_| ProductionRunErrorV1::Configuration)?;
    let local = RelayDatabaseIdV1::new(local).map_err(|_| ProductionRunErrorV1::Configuration)?;
    network
        .validate_remote_database_ids(upstream, downstream)
        .and_then(|()| network.validate_local_database_id(local))
        .map_err(|_| ProductionRunErrorV1::RelayNetworkConfiguration)?;
    Ok(network)
}

/// No family-specific owner is constructed until both public bundles and both
/// credential tags have been authenticated. Each variant consumes one native
/// client and one local signer/share owner for one position only.
enum SelectedLegV11 {
    Evm {
        rpc: evm_actuator::HttpEvmRpcV1,
        refund: Option<crate::production_refund_arming::ProductionEvmRefundFaceV1>,
        deployment: ResolvedEvmDeploymentV1,
        signers: ProductionUniversalEvmSignerPairV11,
    },
    Bitcoin {
        rpc: btc_actuator::HttpBitcoinCoreRpcV1,
        live: Rc<adapter_btc_live::BitcoinCoreRpcClientV1>,
        bundle: BitcoinAuthorityBundleV11,
    },
    Solana {
        pool: solana_rpc_pool::SolanaRpcPool<solana_rpc::HttpSolanaRpc>,
        deployment: deployment_registry::ResolvedSolanaDeploymentV1,
        signers: ProductionUniversalSolanaSignerPairV11,
    },
    Monero {
        broadcast: xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster,
        funding_daemon_urls_v22: Vec<String>,
        observation: crate::production_children::QuorumXmrObservationPortV1,
        deployment: deployment_registry::ResolvedMoneroDeploymentV1,
        authority: ProductionUniversalXmrAuthorityV11,
        local_store: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
    },
    MoneroEnrollment {
        broadcast: xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster,
        funding_daemon_urls_v22: Vec<String>,
        observation: crate::production_children::QuorumXmrObservationPortV1,
        deployment: deployment_registry::ResolvedMoneroDeploymentV1,
        authority: Option<
            crate::production_universal_leg_authority::ProductionUniversalXmrEnrollmentAuthorityV23,
        >,
        local_participant_v24: [u8; 32],
        opened_v24:
            Option<crate::production_universal_leg_authority::ProductionOpenedXmrEnrollmentV23>,
        local_store: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
    },
}

enum DecodedLegV11 {
    Bitcoin(BitcoinAuthorityBundleV11),
    Selected(ProductionUniversalLegAuthorityV11),
}

impl SelectedLegV11 {
    /// A pending aggregate can conceal a confirmed native child after a crash.
    /// This path is selected only for authenticated economic recovery, never
    /// as a catch-all fallback from fresh F6 or live inventory errors.
    fn recover_native_committed_funding_v24(
        selected: &mut [Self; 2],
        inputs: &AuthenticatedProductionInputsV1,
        coordinator: &settlement_coordinator::DurableSettlementCoordinatorV1,
        state_dir: &Path,
    ) -> Result<
        Option<crate::production_inputs::f6_recovery_v24::HistoricalF6RecoveryV24>,
        ProductionRunErrorV1,
    > {
        for (selected, leg) in selected
            .iter_mut()
            .zip([LegIdV1::Upstream, LegIdV1::Downstream])
        {
            let Self::MoneroEnrollment {
                authority,
                opened_v24,
                local_store,
                sidecar_auth,
                deployment,
                funding_daemon_urls_v22,
                ..
            } = selected
            else {
                continue;
            };
            let Some(candidate) = inputs
                .historical_xmr_funding_candidate_v24(coordinator, leg)
                .map_err(|_| ProductionRunErrorV1::Inputs)?
            else {
                continue;
            };
            if opened_v24.is_some() {
                return Err(ProductionRunErrorV1::SettlementChildAuthority);
            }
            let authority = authority
                .take()
                .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?;
            let opened = authority
                .open_enrolled_resources_v23(
                    inputs,
                    leg,
                    state_dir,
                    std::mem::replace(local_store, Zeroizing::new([0; 32])),
                    std::mem::replace(sidecar_auth, Zeroizing::new([0; 32])),
                )
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            let funding = opened
                .enrolled
                .observe_reopen_funding_v24(deployment, funding_daemon_urls_v22)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
            let recovery = candidate
                .authenticate(inputs, coordinator, funding)
                .map_err(|_| ProductionRunErrorV1::Inputs)?;
            // No reopen or scalar copy at activation: transfer these same
            // authenticated resources into the selected child below.
            *opened_v24 = Some(opened);
            return Ok(Some(recovery));
        }
        Ok(None)
    }

    /// On the local solver, reconstruct the independent inventory source for
    /// the authenticated native XMR/XMR enrollment profile. Mixed routes use
    /// the bound profile and cannot carry this two-leg enrollment artifact.
    fn observe_native_xmr_inventory_v23(
        selected: &mut [Self; 2],
        inputs: &AuthenticatedProductionInputsV1,
        state_dir: &Path,
        solver: [u8; 32],
        max_age_seconds: u64,
    ) -> Result<
        (
            bool,
            Option<crate::production_xmr_inventory_v23::ProductionXmrInventoryVerifiedV23>,
        ),
        ProductionRunErrorV1,
    > {
        let [upstream, downstream] = selected;
        let (
            upstream_observation,
            upstream_deployment,
            upstream_authority,
            upstream_store,
            upstream_sidecar,
            downstream_deployment,
            downstream_authority,
        ) = match (upstream, downstream) {
            (
                Self::MoneroEnrollment {
                    observation,
                    deployment,
                    authority,
                    local_store,
                    sidecar_auth,
                    ..
                },
                Self::MoneroEnrollment {
                    deployment: downstream_deployment,
                    authority: downstream_authority,
                    ..
                },
            ) => (
                observation,
                deployment,
                authority,
                local_store,
                sidecar_auth,
                downstream_deployment,
                downstream_authority,
            ),
            _ => return Ok((false, None)),
        };
        let upstream_authority = upstream_authority
            .as_ref()
            .ok_or(ProductionRunErrorV1::F6Authorities)?;
        let downstream_authority = downstream_authority
            .as_ref()
            .ok_or(ProductionRunErrorV1::F6Authorities)?;
        if upstream_authority.local_participant_id() != downstream_authority.local_participant_id()
        {
            return Err(ProductionRunErrorV1::F6Authorities);
        }
        if upstream_authority.local_participant_id() != solver {
            return Ok((false, None));
        }
        let upstream_identity = (
            upstream_deployment.deployment().genesis_hash,
            upstream_deployment.profile().chain_id,
            upstream_deployment.profile().native_asset,
        );
        let downstream_identity = (
            downstream_deployment.deployment().genesis_hash,
            downstream_deployment.profile().chain_id,
            downstream_deployment.profile().native_asset,
        );
        if upstream_identity != downstream_identity {
            return Err(ProductionRunErrorV1::F6Authorities);
        }
        let upstream_session = inputs
            .monero_session(LegIdV1::Upstream)
            .ok_or(ProductionRunErrorV1::Inputs)?;
        let downstream_session = inputs
            .monero_session(LegIdV1::Downstream)
            .ok_or(ProductionRunErrorV1::Inputs)?;
        if upstream_session.profile() != downstream_session.profile()
            || upstream_session.profile().network != xmr_setup_profile::XmrNetwork::Mainnet
            || downstream_session.profile().network != xmr_setup_profile::XmrNetwork::Mainnet
        {
            return Err(ProductionRunErrorV1::F6Authorities);
        }
        let route_terms = [
            inputs.composition().upstream(),
            inputs.composition().downstream(),
        ];
        let upstream_amount = u64::try_from(route_terms[0].counterparty_leg.amount)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        let downstream_amount = u64::try_from(route_terms[1].counterparty_leg.amount)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        let amount_piconero = upstream_amount
            .checked_add(downstream_amount)
            .ok_or(ProductionRunErrorV1::F6Authorities)?;
        let max_fee_piconero = u64::try_from(route_terms[0].fee_limit.counterparty_max)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?
            .min(
                u64::try_from(route_terms[1].fee_limit.counterparty_max)
                    .map_err(|_| ProductionRunErrorV1::F6Authorities)?,
            )
            .min(upstream_deployment.deployment().max_fee_piconero)
            .min(downstream_deployment.deployment().max_fee_piconero);
        let min_confirmations =
            u64::from(route_terms[0].counterparty_leg.finality.min_confirmations).max(u64::from(
                route_terms[1].counterparty_leg.finality.min_confirmations,
            ));
        let (genesis, chain_id, asset_id) = upstream_identity;
        let (secret_store, sidecar_socket, sidecar_timeout_ms) = upstream_authority
            .inventory_resources_v23(state_dir)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        let source = crate::production_xmr_inventory_v23::NativeF6XmrInventorySourceV23::reopen(
            crate::production_xmr_inventory_v23::NativeF6XmrInventoryOpenV23 {
                state_dir: state_dir.to_path_buf(),
                secret_store,
                sidecar_socket,
                sidecar_timeout_ms,
                local_store_key: Zeroizing::new(**upstream_store),
                sidecar_auth: Zeroizing::new(**upstream_sidecar),
                observation: upstream_observation.clone(),
                expected: crate::production_xmr_inventory_v23::NativeF6XmrInventoryExpectedV23 {
                    network_id: inputs.roster_bundle().network_id(),
                    route_id: inputs.admission().route_id(),
                    sessions: [route_terms[0].session_id.0, route_terms[1].session_id.0],
                    terms: [
                        route_terms[0]
                            .terms_hash()
                            .map_err(|_| ProductionRunErrorV1::F6Authorities)?,
                        route_terms[1]
                            .terms_hash()
                            .map_err(|_| ProductionRunErrorV1::F6Authorities)?,
                    ],
                    authority_id: solver,
                    genesis,
                    chain_id: chain_id.0,
                    asset_id: asset_id.0,
                    amount_piconero,
                    max_fee_piconero,
                    min_confirmations,
                    route_funding_tx_hashes: vec![
                        upstream_session.setup().funding_tx_hash(),
                        downstream_session.setup().funding_tx_hash(),
                    ],
                    max_age_seconds,
                },
            },
        )
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        source
            .observe()
            .map(|verified| (true, Some(verified)))
            .map_err(|_| ProductionRunErrorV1::F6Authorities)
    }

    fn prepare_pair(
        bootstrap: &ValidatedProductionBootstrapV1,
        inputs: &AuthenticatedProductionInputsV1,
        credentials: [ProductionLegCredentialsV4; 2],
        services: SelectedServicesV8,
    ) -> Result<([Self; 2], [Option<Zeroizing<[u8; 32]>>; 2]), ProductionRunErrorV1> {
        let mut funding_urls_v22 = services.xmr_funding_urls_v22();
        let descriptors = &bootstrap
            .config()
            .universal_v11()
            .ok_or(ProductionRunErrorV1::Configuration)?
            .legs;
        let mut decoded = Vec::with_capacity(2);
        let mut extra_paths = Vec::new();
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            if credentials[index].family() != descriptors[index].family {
                return Err(ProductionRunErrorV1::Secrets);
            }
            let bytes = descriptors[index]
                .read_bundle(bootstrap.layout())
                .map_err(|_| ProductionRunErrorV1::Configuration)?;
            let value = if descriptors[index].family == ProductionChainFamilyV11::Btc {
                let bundle =
                    BitcoinAuthorityBundleV11::decode(&bytes, &descriptors[index], inputs, leg)?;
                extra_paths.push((
                    bootstrap
                        .layout()
                        .state_dir()
                        .join(&bundle.prebroadcast_store),
                    crate::production_universal_leg_authority::ProductionResourceLeafV23::Existing,
                ));
                extra_paths.push((
                    bootstrap
                        .layout()
                        .state_dir()
                        .join(&bundle.claim_peer_socket),
                    crate::production_universal_leg_authority::ProductionResourceLeafV23::Existing,
                ));
                DecodedLegV11::Bitcoin(bundle)
            } else {
                let value = ProductionUniversalLegAuthorityV11::decode(
                    &bytes,
                    &descriptors[index],
                    inputs,
                    leg,
                )
                .map_err(|_| ProductionRunErrorV1::ChainSignerAuthorities)?;
                for (path, leaf) in value.resource_paths() {
                    extra_paths.push((bootstrap.layout().state_dir().join(path), leaf));
                }
                DecodedLegV11::Selected(value)
            };
            decoded.push(value);
        }
        require_resource_isolation_v11(bootstrap, &extra_paths)?;
        let clients = services
            .into_clients()
            .map_err(|_| ProductionRunErrorV1::ChainServices)?;
        let mut selected = Vec::with_capacity(2);
        let mut bitcoin = [None, None];
        for (index, ((client, credential), authority)) in clients
            .into_iter()
            .zip(credentials)
            .zip(decoded)
            .enumerate()
        {
            let leg = if index == 0 {
                LegIdV1::Upstream
            } else {
                LegIdV1::Downstream
            };
            let value = match (client, credential, authority) {
                (
                    LegClientsV8::Evm { mut rpc, refund },
                    ProductionLegCredentialsV4::Evm { signing },
                    DecodedLegV11::Selected(ProductionUniversalLegAuthorityV11::Evm(authority)),
                ) => {
                    let session = inputs
                        .evm_session(leg)
                        .ok_or(ProductionRunErrorV1::Inputs)?;
                    let deployment = inputs
                        .admission()
                        .evm_deployment_capability(leg, session)
                        .map_err(|_| ProductionRunErrorV1::Inputs)?;
                    let binding = deployment.adapter_config();
                    let (observed, _) = rpc
                        .finalized_code_hash(binding.contract)
                        .map_err(|_| ProductionRunErrorV1::EscrowCodehash)?;
                    if observed != binding.expected_code_hash {
                        return Err(ProductionRunErrorV1::EscrowCodehash);
                    }
                    let signers = authority
                        .bind_signers(
                            inputs,
                            leg,
                            signing,
                            bootstrap.config().pins().process_owner_id,
                        )
                        .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
                    Self::Evm {
                        rpc,
                        refund: Some(refund),
                        deployment,
                        signers,
                    }
                }
                (
                    LegClientsV8::Bitcoin { rpc, live },
                    ProductionLegCredentialsV4::Bitcoin { participant },
                    DecodedLegV11::Bitcoin(bundle),
                ) => {
                    bitcoin[index] = Some(participant);
                    Self::Bitcoin { rpc, live, bundle }
                }
                (
                    LegClientsV8::Solana { pool, deployment },
                    ProductionLegCredentialsV4::Solana { seed, peer_auth },
                    DecodedLegV11::Selected(ProductionUniversalLegAuthorityV11::Solana(authority)),
                ) => {
                    let signers = authority
                        .bind_signers(inputs, leg, bootstrap.layout().state_dir(), seed, peer_auth)
                        .map_err(|_| ProductionRunErrorV1::ChainSignerAuthorities)?;
                    Self::Solana {
                        pool,
                        deployment,
                        signers,
                    }
                }
                (
                    LegClientsV8::Monero {
                        broadcast,
                        observation,
                        deployment,
                    },
                    ProductionLegCredentialsV4::Monero {
                        local_store,
                        sidecar_auth,
                    },
                    DecodedLegV11::Selected(ProductionUniversalLegAuthorityV11::Monero(authority)),
                ) => Self::Monero {
                    broadcast,
                    funding_daemon_urls_v22: funding_urls_v22[index]
                        .take()
                        .ok_or(ProductionRunErrorV1::ChainServices)?,
                    observation,
                    deployment,
                    authority,
                    local_store,
                    sidecar_auth,
                },
                (
                    LegClientsV8::Monero {
                        broadcast,
                        observation,
                        deployment,
                    },
                    ProductionLegCredentialsV4::Monero {
                        local_store,
                        sidecar_auth,
                    },
                    DecodedLegV11::Selected(ProductionUniversalLegAuthorityV11::MoneroEnrollment(
                        authority,
                    )),
                ) => Self::MoneroEnrollment {
                    broadcast,
                    funding_daemon_urls_v22: funding_urls_v22[index]
                        .take()
                        .ok_or(ProductionRunErrorV1::ChainServices)?,
                    observation,
                    deployment,
                    local_participant_v24: authority.local_participant_id(),
                    authority: Some(authority),
                    opened_v24: None,
                    local_store,
                    sidecar_auth,
                },
                _ => return Err(ProductionRunErrorV1::ChainServices),
            };
            selected.push(value);
        }
        Ok((
            selected
                .try_into()
                .map_err(|_| ProductionRunErrorV1::ChainServices)?,
            bitcoin,
        ))
    }

    fn require_local_participant(&self, expected: [u8; 32]) -> Result<(), ProductionRunErrorV1> {
        let local = match self {
            Self::Evm { signers, .. } => signers.local_participant_id,
            Self::Solana { signers, .. } => signers.local_participant_id(),
            Self::Monero { authority, .. } => authority.local_participant_id(),
            Self::MoneroEnrollment {
                local_participant_v24,
                ..
            } => *local_participant_v24,
            // The selected native Bitcoin participant was checked against
            // this same retained Relay/DOM identity during Stage 8.
            Self::Bitcoin { .. } => return Ok(()),
        };
        if local != expected {
            return Err(ProductionRunErrorV1::ChainSignerAuthorities);
        }
        Ok(())
    }

    const fn family(&self) -> ProductionChainFamilyV11 {
        match self {
            Self::Evm { .. } => ProductionChainFamilyV11::Evm,
            Self::Bitcoin { .. } => ProductionChainFamilyV11::Btc,
            Self::Solana { .. } => ProductionChainFamilyV11::Sol,
            Self::Monero { .. } | Self::MoneroEnrollment { .. } => ProductionChainFamilyV11::Xmr,
        }
    }

    fn public_source(
        &self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<UpstreamPublicSourceV11, ProductionRunErrorV1> {
        match self {
            Self::Evm { refund, .. } => Ok(UpstreamPublicSourceV11::Ready(Box::new(
                refund
                    .as_ref()
                    .ok_or(ProductionRunErrorV1::PlanSource)?
                    .public_secret_source_v4(inputs, leg)
                    .map_err(|_| ProductionRunErrorV1::PlanSource)?,
            ))),
            Self::Bitcoin { .. } => Ok(UpstreamPublicSourceV11::Bitcoin {
                chain_id: inputs
                    .admission()
                    .bitcoin_deployment_capability(leg)
                    .map_err(|_| ProductionRunErrorV1::PlanSource)?
                    .profile()
                    .chain_id
                    .0,
            }),
            Self::Solana {
                pool, deployment, ..
            } => {
                let setup = inputs
                    .solana_session(leg)
                    .ok_or(ProductionRunErrorV1::PlanSource)?
                    .setup()
                    .clone();
                Ok(UpstreamPublicSourceV11::Ready(Box::new(
                    LateSolanaPublicSourceV11 {
                        route_id: inputs.admission().route_id(),
                        composition_digest: inputs.composition().binding_digest(),
                        pool: pool.clone(),
                        deployment: deployment.clone(),
                        setup,
                    },
                )))
            }
            Self::Monero { .. } | Self::MoneroEnrollment { .. } => Ok(UpstreamPublicSourceV11::Dom),
        }
    }

    fn refund_face(
        &mut self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        bitcoin: Option<&ProductionBitcoinPrebroadcastOwnerV7>,
        relay: &ProductionRelayStage12OwnerV1,
    ) -> Result<ProductionCounterpartyRefundFaceV1, ProductionRunErrorV1> {
        use crate::production_refund_arming::{
            ProductionSolanaRefundFaceV1, ProductionXmrRefundFaceV1,
        };
        match self {
            Self::Evm { refund, .. } => Ok(ProductionCounterpartyRefundFaceV1::Evm(
                refund
                    .take()
                    .ok_or(ProductionRunErrorV1::RefundArmingAuthority)?,
            )),
            Self::Bitcoin { .. } => Ok(ProductionCounterpartyRefundFaceV1::Bitcoin(
                bitcoin
                    .ok_or(ProductionRunErrorV1::RefundArmingAuthority)?
                    .refund_face(inputs)
                    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
            )),
            Self::Solana {
                pool, deployment, ..
            } => {
                let setup = inputs
                    .solana_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?
                    .setup()
                    .clone();
                Ok(ProductionCounterpartyRefundFaceV1::Solana(
                    ProductionSolanaRefundFaceV1::new(pool.clone(), setup, deployment.clone())
                        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
                ))
            }
            Self::Monero { deployment, .. } => {
                let session = inputs
                    .monero_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?;
                let refund = session
                    .refund_bundle()
                    .ok_or(ProductionRunErrorV1::RefundArmingAuthority)?;
                let artifact = xmr_refund_policy::XmrRefundArtifactV1 {
                    template_hash: refund.template_hash,
                    adaptor_point_sec1: refund.adaptor_point_sec1,
                    executor_profile_hash: refund.executor_profile_hash,
                    deadline: refund.deadline,
                };
                Ok(ProductionCounterpartyRefundFaceV1::Monero(
                    ProductionXmrRefundFaceV1::new(
                        session.profile().clone(),
                        session.setup().clone(),
                        deployment.clone(),
                        refund.proof.clone(),
                        artifact,
                    )
                    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
                ))
            }
            Self::MoneroEnrollment { deployment, .. } => {
                let session = inputs
                    .monero_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?;
                let graph = relay
                    .bound_xmr_setup_v23(leg)
                    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
                let refund = graph
                    .refund_bundle_v23()
                    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
                let artifact = xmr_refund_policy::XmrRefundArtifactV1 {
                    template_hash: refund.template_hash,
                    adaptor_point_sec1: refund.adaptor_point_sec1,
                    executor_profile_hash: refund.executor_profile_hash,
                    deadline: refund.deadline,
                };
                Ok(ProductionCounterpartyRefundFaceV1::Monero(
                    ProductionXmrRefundFaceV1::new(
                        session.profile().clone(),
                        session.setup().clone(),
                        deployment.clone(),
                        refund.proof.clone(),
                        artifact,
                    )
                    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
                ))
            }
        }
    }
}

fn require_resource_isolation_v11(
    bootstrap: &ValidatedProductionBootstrapV1,
    extras: &[(
        PathBuf,
        crate::production_universal_leg_authority::ProductionResourceLeafV23,
    )],
) -> Result<(), ProductionRunErrorV1> {
    let layout = bootstrap.layout();
    let mut reserved: Vec<PathBuf> = ProductionPathRoleV1::ALL
        .into_iter()
        .map(|role| layout.path(role).to_owned())
        .collect();
    for role in ProductionF6PathRoleV4::ALL {
        if let Some(path) = layout.f6_path_v4(role) {
            reserved.push(path.to_owned());
        }
    }
    for role in ProductionF6PathRoleV8::ALL {
        if let Some(path) = layout.f6_path_v8(role) {
            reserved.push(path.to_owned());
        }
    }
    for path in [
        layout.contracts_transport_identity_store(),
        layout.contracts_budget_policy(),
        layout.contracts_bootstrap(),
        layout.refund_arming_database(),
    ] {
        if let Some(path) = path {
            reserved.push(path.to_owned());
        }
    }
    for leg in &bootstrap
        .config()
        .universal_v11()
        .ok_or(ProductionRunErrorV1::Configuration)?
        .legs
    {
        reserved.push(layout.state_dir().join(&leg.actuator_store));
        reserved.push(layout.state_dir().join(&leg.authority_bundle));
    }
    require_selected_resource_paths_v23(layout.state_dir(), extras, &mut reserved)
}

fn require_selected_resource_paths_v23(
    state: &Path,
    extras: &[(
        PathBuf,
        crate::production_universal_leg_authority::ProductionResourceLeafV23,
    )],
    reserved: &mut Vec<PathBuf>,
) -> Result<(), ProductionRunErrorV1> {
    for (path, leaf) in extras {
        require_selected_parent_chain_v11(state, path, *leaf)?;
        // All selected extra paths were normalized by their semantic decoder.
        // Auxiliary SQLite/process-lock names may not alias any other owner.
        if reserved.iter().any(|other| {
            path == other
                || path.starts_with(other)
                || other.starts_with(path)
                || auxiliary_alias_v11(path, other)
        }) {
            return Err(ProductionRunErrorV1::Configuration);
        }
        reserved.push(path.clone());
    }
    Ok(())
}

fn require_selected_parent_chain_v11(
    state: &Path,
    path: &Path,
    leaf: crate::production_universal_leg_authority::ProductionResourceLeafV23,
) -> Result<(), ProductionRunErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let root = std::fs::symlink_metadata(state).map_err(|_| ProductionRunErrorV1::Configuration)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || root.uid() != rustix::process::getuid().as_raw()
        || root.permissions().mode() & 0o077 != 0
    {
        return Err(ProductionRunErrorV1::Configuration);
    }
    let relative = path
        .strip_prefix(state)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err(ProductionRunErrorV1::Configuration);
    }
    let mut current = state.to_owned();
    let parts: Vec<_> = relative.components().collect();
    for (index, component) in parts.iter().enumerate() {
        current.push(component.as_os_str());
        let is_leaf = index + 1 == parts.len();
        let creatable = leaf == crate::production_universal_leg_authority::ProductionResourceLeafV23::NativeXmrGraphCustodyDirectory;
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if is_leaf && creatable && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(())
            }
            Err(_) => return Err(ProductionRunErrorV1::Configuration),
        };
        if metadata.file_type().is_symlink()
            || metadata.uid() != root.uid()
            || metadata.permissions().mode() & 0o077 != 0
            || ((!is_leaf || creatable) && !metadata.is_dir())
        {
            return Err(ProductionRunErrorV1::Configuration);
        }
    }
    Ok(())
}

fn auxiliary_alias_v11(left: &Path, right: &Path) -> bool {
    ["-wal", "-shm", "-journal", ".process.lock", ".lock"]
        .into_iter()
        .any(|suffix| {
            let mut extended = left.as_os_str().to_os_string();
            extended.push(suffix);
            let mut reversed = right.as_os_str().to_os_string();
            reversed.push(suffix);
            Path::new(&extended) == right || Path::new(&reversed) == left
        })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinAuthorityBundleV11 {
    format: String,
    prebroadcast_store: String,
    claim_peer_socket: String,
    claim_exchange_timeout_ms: u64,
    pins: BitcoinPinsV11,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinPinsV11 {
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_digest: [u8; 32],
    deployment_digest: [u8; 32],
    route_binding: [u8; 32],
    plan_digest: [u8; 32],
    receipt_digest: [u8; 32],
    contract_script_pubkey_digest: [u8; 32],
    claim_destination_script_pubkey_digest: [u8; 32],
    refund_destination_script_pubkey_digest: [u8; 32],
    refund_key_xonly: [u8; 32],
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
}
impl BitcoinAuthorityBundleV11 {
    fn decode(
        bytes: &[u8],
        descriptor: &ProductionUniversalLegV11,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<Self, ProductionRunErrorV1> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ProductionRunErrorV1::Configuration)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        if value.format != "DOM-INTEROPD-BITCOIN-AUTHORITY-V11"
            || serde_json::to_vec(&value).map_err(|_| ProductionRunErrorV1::Configuration)? != bytes
            || value.pins.settlement_id != descriptor.settlement_id
            || value.pins.session_id != descriptor.session_id
            || value.pins.terms_digest
                != terms
                    .terms_hash()
                    .map_err(|_| ProductionRunErrorV1::Inputs)?
            || value.prebroadcast_store.is_empty()
            || !Path::new(&value.prebroadcast_store)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
            || value.claim_peer_socket.is_empty()
            || value.claim_peer_socket.len() > 4096
            || value.claim_peer_socket.contains('\0')
            || value.claim_peer_socket.contains('\\')
            || !Path::new(&value.claim_peer_socket)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
            || value.claim_exchange_timeout_ms == 0
            || value.claim_exchange_timeout_ms > 30_000
            || inputs.bitcoin_session(leg).is_none()
        {
            return Err(ProductionRunErrorV1::Configuration);
        }
        // Native prebroadcast opening revalidates every pin against the
        // funding/refund receipt and the exact admitted registry capability.
        Ok(value)
    }

    fn native_pins(&self, leg: LegIdV1) -> ProductionBitcoinPrebroadcastPinsV7 {
        let p = &self.pins;
        ProductionBitcoinPrebroadcastPinsV7 {
            leg,
            settlement_id: p.settlement_id,
            session_id: p.session_id,
            terms_digest: p.terms_digest,
            deployment_digest: p.deployment_digest,
            route_binding: p.route_binding,
            plan_digest: p.plan_digest,
            receipt_digest: p.receipt_digest,
            contract_script_pubkey_digest: p.contract_script_pubkey_digest,
            claim_destination_script_pubkey_digest: p.claim_destination_script_pubkey_digest,
            refund_destination_script_pubkey_digest: p.refund_destination_script_pubkey_digest,
            refund_key_xonly: p.refund_key_xonly,
            funding_template_hash: p.funding_template_hash,
            claim_template_hash: p.claim_template_hash,
            refund_template_hash: p.refund_template_hash,
        }
    }
}

/// Where the Bitcoin position keeps its own resources, and how long it waits.
///
/// Both paths are state-dir relative and join the cross-position isolation
/// set, so the two legs of a BTC/BTC route must not name the same ones.
pub struct ProductionBitcoinLegResourcesV22 {
    /// Relative path of this position's prebroadcast store.
    pub prebroadcast_store: String,
    /// Relative path of this position's claim peer socket.
    pub claim_peer_socket: String,
    /// Non-zero, at most 30_000.
    pub claim_exchange_timeout_ms: u64,
}

/// The fourteen values the Bitcoin funding and refund ceremony publishes.
///
/// The decoder checks only the three that bind this position's identity; the
/// other eleven are revalidated against the funding/refund receipt and the
/// admitted registry capability when the native prebroadcast store opens. A
/// bundle can therefore encode cleanly and still be refused later, which is
/// the intended order: the receipt is the authority, not this file.
pub struct ProductionBitcoinLegPinsV22 {
    /// Settlement bound by this position; must match the manifest descriptor.
    pub settlement_id: [u8; 32],
    /// Signing session bound by this position; must match the descriptor.
    pub session_id: [u8; 32],
    /// Digest of the terms this position settles under.
    pub terms_digest: [u8; 32],
    /// Admitted Bitcoin deployment capability.
    pub deployment_digest: [u8; 32],
    /// Route binding this position was admitted under.
    pub route_binding: [u8; 32],
    /// Funding plan published by the ceremony.
    pub plan_digest: [u8; 32],
    /// Funding receipt published by the ceremony.
    pub receipt_digest: [u8; 32],
    /// Contract output scriptPubKey.
    pub contract_script_pubkey_digest: [u8; 32],
    /// Claim destination scriptPubKey.
    pub claim_destination_script_pubkey_digest: [u8; 32],
    /// Refund destination scriptPubKey.
    pub refund_destination_script_pubkey_digest: [u8; 32],
    /// X-only refund key.
    pub refund_key_xonly: [u8; 32],
    /// Funding template.
    pub funding_template_hash: [u8; 32],
    /// Claim template.
    pub claim_template_hash: [u8; 32],
    /// Refund template.
    pub refund_template_hash: [u8; 32],
}

/// One encoded Bitcoin leg authority bundle and the digest its entry pins.
pub struct ProductionBitcoinLegBundleV22 {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl ProductionBitcoinLegBundleV22 {
    /// Bytes to write at the descriptor's `authority_bundle` path, mode 0600.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Value to place in the descriptor's `authority_bundle_digest`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Encodes one Bitcoin leg authority bundle.
///
/// Bitcoin deliberately has no variant in the EVM/SOL/XMR wire enum, so this
/// writer is separate for the same reason the decoder is: a Bitcoin bundle
/// must never be parseable as a scriptless-family signer. It builds the same
/// type the decoder reads and serializes it with the same serializer, which
/// is what satisfies the byte-canonicality rule by construction.
pub fn encode_bitcoin_leg_authority_bundle_v22(
    resources: ProductionBitcoinLegResourcesV22,
    pins: &ProductionBitcoinLegPinsV22,
) -> Result<ProductionBitcoinLegBundleV22, ProductionRunErrorV1> {
    let normal = |value: &str| {
        !value.is_empty()
            && value.len() <= 4096
            && !value.contains('\0')
            && !value.contains('\\')
            && Path::new(value)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
    };
    if !normal(&resources.prebroadcast_store)
        || !normal(&resources.claim_peer_socket)
        || resources.claim_exchange_timeout_ms == 0
        || resources.claim_exchange_timeout_ms > 30_000
    {
        return Err(ProductionRunErrorV1::Configuration);
    }
    let value = BitcoinAuthorityBundleV11 {
        format: "DOM-INTEROPD-BITCOIN-AUTHORITY-V11".to_owned(),
        prebroadcast_store: resources.prebroadcast_store,
        claim_peer_socket: resources.claim_peer_socket,
        claim_exchange_timeout_ms: resources.claim_exchange_timeout_ms,
        pins: BitcoinPinsV11 {
            settlement_id: pins.settlement_id,
            session_id: pins.session_id,
            terms_digest: pins.terms_digest,
            deployment_digest: pins.deployment_digest,
            route_binding: pins.route_binding,
            plan_digest: pins.plan_digest,
            receipt_digest: pins.receipt_digest,
            contract_script_pubkey_digest: pins.contract_script_pubkey_digest,
            claim_destination_script_pubkey_digest: pins.claim_destination_script_pubkey_digest,
            refund_destination_script_pubkey_digest: pins.refund_destination_script_pubkey_digest,
            refund_key_xonly: pins.refund_key_xonly,
            funding_template_hash: pins.funding_template_hash,
            claim_template_hash: pins.claim_template_hash,
            refund_template_hash: pins.refund_template_hash,
        },
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| ProductionRunErrorV1::Configuration)?;
    let digest = ProductionUniversalLegV11::bundle_digest(&bytes)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    Ok(ProductionBitcoinLegBundleV22 { bytes, digest })
}

enum ExternalActuatorV11 {
    Evm(DurableEvmActuatorV1),
    Bitcoin(DurableBitcoinActuatorV1),
    Solana(solana_actuator::DurableSolanaActuatorV1),
    Monero(xmr_actuator::DurableXmrActuatorV1),
}

type ActuatorGuardV11 = crate::production_universal_actuator::ProductionUniversalActuatorGuardV11;

fn open_actuator_pair_v11(
    mode: ProductionRunModeV1,
    bootstrap: &ValidatedProductionBootstrapV1,
    journal: &mut DurableProductionProvisioningJournalV1,
    selected: &[SelectedLegV11; 2],
    provisioning_binding: [u8; 32],
) -> Result<([ExternalActuatorV11; 2], [Option<ActuatorGuardV11>; 2]), ProductionRunErrorV1> {
    use crate::production_universal_actuator::{
        open_universal_actuator_v11, ProductionUniversalActuatorV11,
    };
    use blake2::digest::{Update as _, VariableOutput as _};
    let mut stores = Vec::with_capacity(2);
    let mut guards = [None, None];
    for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
        .into_iter()
        .enumerate()
    {
        let stage_id = universal_actuator_stage_v11(leg);
        let before = journal
            .stage_state(stage_id)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
        let path = bootstrap
            .universal_actuator_path_v11(leg)
            .map_err(|_| ProductionRunErrorV1::Configuration)?;
        if mode == ProductionRunModeV1::Create
            && before == ProductionProvisioningStageStateV1::Absent
        {
            match selected[index].family() {
                ProductionChainFamilyV11::Evm => require_evm_actuator_create_prefix_absent(&path)?,
                ProductionChainFamilyV11::Btc => {
                    require_bitcoin_actuator_create_prefix_absent(&path)?
                }
                _ => {
                    if path_entry_present(&path).map_err(|_| ProductionRunErrorV1::ChainServices)?
                        || path_entry_present(&actuator_process_lock_path(&path))
                            .map_err(|_| ProductionRunErrorV1::ChainServices)?
                    {
                        return Err(ProductionRunErrorV1::ChainServices);
                    }
                }
            }
        }
        let stage = match mode {
            ProductionRunModeV1::Create => journal
                .begin(stage_id)
                .map_err(|_| ProductionRunErrorV1::Provisioning)?,
            ProductionRunModeV1::ReopenExisting => before,
        };
        let store = match selected[index].family() {
            ProductionChainFamilyV11::Evm => {
                ExternalActuatorV11::Evm(open_evm_actuator_store(mode, before, stage, &path)?)
            }
            ProductionChainFamilyV11::Btc => {
                ExternalActuatorV11::Bitcoin(open_bitcoin_actuator_store(
                    mode,
                    before,
                    stage,
                    &path,
                    bootstrap.config().pins().process_owner_id,
                )?)
            }
            family @ (ProductionChainFamilyV11::Sol | ProductionChainFamilyV11::Xmr) => {
                let mut hash =
                    blake2::Blake2bVar::new(32).map_err(|_| ProductionRunErrorV1::Configuration)?;
                hash.update(b"DOM-INTEROPD/SELECTED-ACTUATOR/V11\0");
                hash.update(&provisioning_binding);
                hash.update(&[index as u8]);
                let mut binding = [0; 32];
                hash.finalize_variable(&mut binding)
                    .map_err(|_| ProductionRunErrorV1::Configuration)?;
                let (store, guard) =
                    open_universal_actuator_v11(&path, binding, family, mode, before, stage)
                        .map_err(|_| ProductionRunErrorV1::ChainServices)?;
                guards[index] = Some(guard);
                match store {
                    ProductionUniversalActuatorV11::Solana(value) => {
                        ExternalActuatorV11::Solana(value)
                    }
                    ProductionUniversalActuatorV11::Monero(value) => {
                        ExternalActuatorV11::Monero(value)
                    }
                }
            }
        };
        complete_provisioning_stage(mode, stage, stage_id, journal)?;
        stores.push(store);
    }
    Ok((
        stores
            .try_into()
            .map_err(|_| ProductionRunErrorV1::ChainServices)?,
        guards,
    ))
}

fn open_bitcoin_owners_v11(
    bootstrap: &ValidatedProductionBootstrapV1,
    inputs: &AuthenticatedProductionInputsV1,
    selected: &[SelectedLegV11; 2],
) -> Result<[Option<ProductionBitcoinPrebroadcastOwnerV7>; 2], ProductionRunErrorV1> {
    let mut owners = [None, None];
    for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
        .into_iter()
        .enumerate()
    {
        if let SelectedLegV11::Bitcoin { live, bundle, .. } = &selected[index] {
            let path = bootstrap
                .layout()
                .state_dir()
                .join(&bundle.prebroadcast_store);
            owners[index] = Some(
                ProductionBitcoinPrebroadcastOwnerV7::open_existing_for_leg_v11(
                    bootstrap,
                    inputs,
                    leg,
                    &path,
                    bundle.native_pins(leg),
                    Rc::clone(live),
                )
                .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?,
            );
        }
    }
    Ok(owners)
}

fn take_bitcoin_payouts_v11(
    owners: &mut [Option<ProductionBitcoinPrebroadcastOwnerV7>; 2],
) -> Result<[Option<adapter_btc_live::AuthenticatedBitcoinPayoutFaceV1>; 2], ProductionRunErrorV1> {
    let mut result = [None, None];
    for (index, owner) in owners.iter_mut().enumerate() {
        if let Some(owner) = owner {
            result[index] = Some(
                owner
                    .take_payout_face()
                    .map_err(|_| ProductionRunErrorV1::F6Authorities)?,
            );
        }
    }
    Ok(result)
}

impl SelectedLegV11 {
    #[allow(clippy::too_many_arguments)]
    fn into_child<'a>(
        self,
        inputs: &'a AuthenticatedProductionInputsV1,
        bootstrap: &ValidatedProductionBootstrapV1,
        leg: LegIdV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        actuator: ExternalActuatorV11,
        bitcoin: Option<ProductionBitcoinPrebroadcastOwnerV7>,
        bitcoin_readiness: Option<
            crate::production_contracts::ProductionBitcoinPrefundingReadinessV11,
        >,
        guard: Option<&ActuatorGuardV11>,
        relay: &mut ProductionRelayStage12OwnerV1,
        dom_scanner_v22: &crate::production_child_dom::ProductionDomF7ScannerAuthorityV1,
        xmr_pumps_v22: &mut Vec<
            crate::production_xmr_recovery_pump_v22::ProductionXmrRecoveryPumpV22,
        >,
        funding_window_v23: &crate::production_timer::ProductionFundingWindowV23,
    ) -> Result<ProductionCounterpartyChildInputV7<'a>, ProductionRunErrorV1> {
        let pins = bootstrap.config().pins();
        let bounds = bootstrap.config().bounds();
        let now = trusted_now_millis_v1()?;
        let settlement = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        match (self, actuator) {
            (
                Self::Evm {
                    rpc,
                    deployment,
                    signers,
                    ..
                },
                ExternalActuatorV11::Evm(mut actuator),
            ) => {
                let scope = ProductionEvmMaterializationScopeV1::authenticate(
                    inputs,
                    role_plan,
                    upstream_scope,
                    downstream_scope,
                    leg,
                )
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let local_lease = actuator
                    .acquire_lease_for_role(
                        &deployment,
                        signers.local_signer.binding().role(),
                        pins.process_owner_id,
                        now,
                        bounds.actuator_lease_ms,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
                    .lease();
                let remote_transport = relay
                    .leg_mut(leg)
                    .contracts_mut()
                    .evm_remote_transport_authority(
                        &signers.remote_signer,
                        settlement.counterparty_leg.deadline,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                Ok(ProductionCounterpartyChildInputV7::Evm(Box::new(
                    ProductionEvmMaterializingPortInputV1 {
                        actuator,
                        rpc,
                        deployment,
                        local_lease,
                        clock: SystemProductionEvmChildClockV1,
                        lease_renewal_ms_v12: Some(bounds.actuator_lease_ms),
                        settlement,
                        fees: signers.fees,
                        observation_valid_for_ms: signers.observation_valid_for_ms,
                        local_signer: Box::new(signers.local_signer),
                        remote_binding: signers.remote_signer,
                        remote_transport,
                        remote_custody_lease_duration_ms: signers.remote_custody_lease_duration_ms,
                        scope,
                    },
                )))
            }
            (Self::Bitcoin { rpc, .. }, ExternalActuatorV11::Bitcoin(mut actuator)) => {
                let owner = bitcoin.ok_or(ProductionRunErrorV1::BitcoinChildAuthority)?;
                let handoff = owner
                    .into_child_handoff(inputs)
                    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                let readiness =
                    bitcoin_readiness.ok_or(ProductionRunErrorV1::BitcoinChildAuthority)?;
                let prepared = handoff
                    .prepare_claim_v11(
                        inputs,
                        role_plan,
                        upstream_scope,
                        downstream_scope,
                        readiness,
                    )
                    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                let funding = handoff
                    .into_funding_only()
                    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                let scope = crate::production_child_btc::ProductionBitcoinMaterializationScopeV1::authenticate(
                    inputs, role_plan, upstream_scope, downstream_scope, leg)
                    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                let lease = actuator
                    .acquire_lease(now, bounds.actuator_lease_ms)
                    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
                Ok(ProductionCounterpartyChildInputV7::BitcoinPrefunding {
                    input: ProductionBitcoinChildInputV7 {
                        actuator,
                        rpc,
                        lease,
                        funding,
                        lease_renewal_ms_v12: Some(bounds.actuator_lease_ms),
                    },
                    scope,
                    prepared,
                })
            }
            (
                Self::Solana {
                    pool,
                    deployment,
                    signers,
                },
                ExternalActuatorV11::Solana(actuator),
            ) => {
                let setup = inputs
                    .solana_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?
                    .setup()
                    .clone();
                let lease_owner = guard
                    .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?
                    .lease_owner_v11(
                        setup.binding_hash(),
                        pins.process_owner_id,
                        deployment.deployment().genesis_hash,
                        bounds.actuator_lease_ms,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let funder_lease = lease_owner
                    .solana_lease(signers.funder.account(), now)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let beneficiary_lease = lease_owner
                    .solana_lease(signers.beneficiary.account(), now)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let scope = crate::production_child_solana::ProductionSolanaMaterializationScopeV1::authenticate(
                    inputs, role_plan, upstream_scope, downstream_scope, leg)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                Ok(ProductionCounterpartyChildInputV7::Solana(Box::new(
                    crate::production_materializing_children::ProductionSolanaChildInputV7 {
                        actuator,
                        pool,
                        deployment,
                        setup,
                        funder_lease,
                        beneficiary_lease,
                        funder_signer: signers.funder,
                        beneficiary_signer: signers.beneficiary,
                        scope,
                        token_accounts: signers.token_accounts,
                        lease_owner: Some(lease_owner),
                    },
                )))
            }
            (
                Self::Monero {
                    broadcast,
                    funding_daemon_urls_v22,
                    observation,
                    deployment,
                    authority,
                    local_store,
                    sidecar_auth,
                },
                ExternalActuatorV11::Monero(actuator),
            ) => {
                let local_xmr_participant = authority.local_participant_id();
                let setup = inputs
                    .monero_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?
                    .setup()
                    .clone();
                let lease_owner = guard
                    .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?
                    .lease_owner_v11(
                        setup.binding_hash(),
                        pins.process_owner_id,
                        deployment.deployment().genesis_hash,
                        bounds.actuator_lease_ms,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let lease = lease_owner
                    .xmr_lease(now)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let (pump, sweep, recovery, recovery_deferred) = if authority
                    .uses_graph_custody_v23()
                {
                    let deferred = Rc::new(
                        crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23::from_setup(
                            relay
                                .xmr_custody_setup_v23(leg)
                                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                        )
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    );
                    let (resources, nullifiers) = authority
                        .graph_custody_resources_v23(
                            bootstrap.layout().state_dir(),
                            &local_store,
                            &sidecar_auth,
                        )
                        .map_err(|_| {
                            ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable
                        })?;
                    let sweep = authority
                        .open_sweep_v23(
                            inputs,
                            leg,
                            bootstrap.layout().state_dir(),
                            local_store,
                            sidecar_auth,
                            Rc::clone(&deferred),
                        )
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
                        .with_funding_quorum_v22(deployment.clone(), funding_daemon_urls_v22)
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    relay
                        .mount_xmr_custody_resources_v23(
                            leg,
                            resources,
                            nullifiers,
                            &sweep,
                            Rc::clone(&deferred),
                        )
                        .map_err(|_| {
                            ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable
                        })?;
                    let (pump, sweep) = crate::production_xmr_recovery_pump_v22::ProductionXmrRecoveryPumpV22::attach_deferred_v23(
                        leg, sweep, Rc::clone(&deferred),
                    ).map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    (pump, sweep, None, Some(deferred))
                } else {
                    let (parent, directory, key) = authority
                        .recovery_resources_v22(
                            bootstrap.layout().state_dir(),
                            &local_store,
                            &sidecar_auth,
                        )
                        .map_err(|_| {
                            ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable
                        })?;
                    let recovery = relay
                        .reopen_xmr_recovery_v22(leg, parent, &directory, key, dom_scanner_v22)
                        .map_err(|_| {
                            ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable
                        })?;
                    let sweep = authority
                        .open_sweep_v12(
                            inputs,
                            leg,
                            bootstrap.layout().state_dir(),
                            local_store,
                            sidecar_auth,
                            Rc::clone(&recovery),
                        )
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
                        .with_funding_quorum_v22(deployment.clone(), funding_daemon_urls_v22)
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                    let (pump, sweep) =
                    crate::production_xmr_recovery_pump_v22::ProductionXmrRecoveryPumpV22::attach(
                        leg,
                        sweep,
                        Rc::clone(&recovery),
                    );
                    (pump, sweep, Some(recovery), None)
                };
                let scope =
                    crate::production_child_xmr::ProductionXmrMaterializationScopeV1::authenticate(
                        inputs,
                        role_plan,
                        upstream_scope,
                        downstream_scope,
                        leg,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let remote_pins =
                    xmr_remote_claim_pins_v23(inputs, role_plan, leg, &deployment, &setup)?;
                use crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteRefundSourceV23;
                let source = match (&recovery, &recovery_deferred) {
                    (Some(driver), None) => {
                        ProductionXmrRemoteRefundSourceV23::Attached(Rc::clone(driver))
                    }
                    (None, Some(slot)) => {
                        ProductionXmrRemoteRefundSourceV23::Deferred(Rc::clone(slot))
                    }
                    _ => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                };
                let actuator = Rc::new(actuator);
                let (requester, responder) = relay
                    .leg_mut(leg)
                    .contracts_mut()
                    .xmr_remote_action_pair_v24(&remote_pins, settlement)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let (sweep, refund_responder) =
                    crate::production_xmr_remote_sweep_v23::assemble_native_xmr_action_faces_v24(
                        sweep,
                        remote_pins,
                        setup.clone(),
                        source,
                        Rc::clone(&actuator),
                        requester,
                        responder,
                        observation.clone(),
                        local_xmr_participant == settlement.counterparty_leg.beneficiary.0,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let pump = match refund_responder {
                    Some(responder) => pump
                        .with_refund_responder_v24(responder)
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    None => pump,
                };
                xmr_pumps_v22.push(pump);
                Ok(ProductionCounterpartyChildInputV7::Monero(Box::new(
                    crate::production_materializing_children::ProductionXmrChildInputV7 {
                        actuator,
                        funding_window_v23: funding_window_v23.clone(),
                        broadcast,
                        observation,
                        deployment,
                        setup,
                        lease,
                        min_confirmations: u64::from(
                            settlement.counterparty_leg.finality.min_confirmations,
                        ),
                        sweep,
                        scope,
                        lease_owner: Some(lease_owner),
                        recovery_driver_v12: recovery,
                        recovery_deferred_v23: recovery_deferred,
                    },
                )))
            }
            (
                Self::MoneroEnrollment {
                    broadcast,
                    funding_daemon_urls_v22,
                    observation,
                    deployment,
                    authority,
                    local_participant_v24,
                    opened_v24,
                    local_store,
                    sidecar_auth,
                },
                ExternalActuatorV11::Monero(actuator),
            ) => {
                let local_xmr_participant = local_participant_v24;
                let setup = inputs
                    .monero_session(leg)
                    .ok_or(ProductionRunErrorV1::Inputs)?
                    .setup()
                    .clone();
                let lease_owner = guard
                    .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?
                    .lease_owner_v11(
                        setup.binding_hash(),
                        pins.process_owner_id,
                        deployment.deployment().genesis_hash,
                        bounds.actuator_lease_ms,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let lease = lease_owner
                    .xmr_lease(now)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                // Only the authenticated late binding enables activation. The
                // immutable enrollment input remains unchanged.
                let opened = match (authority, opened_v24) {
                    (None, Some(opened)) => opened,
                    (Some(authority), None) => authority
                        .open_enrolled_resources_v23(
                            inputs,
                            leg,
                            bootstrap.layout().state_dir(),
                            local_store,
                            sidecar_auth,
                        )
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    _ => return Err(ProductionRunErrorV1::SettlementChildAuthority),
                };
                let activated = relay
                    .activate_enrolled_xmr_resources_v23(leg, opened.enrolled)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let sweep = match opened.private_funding {
                    Some(metadata) => metadata
                        .attach(activated.sweep)
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    None => activated.sweep,
                }
                .with_funding_quorum_v22(deployment.clone(), funding_daemon_urls_v22)
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let deferred = activated.recovery;
                relay
                    .mount_xmr_custody_resources_v23(
                        leg,
                        opened.archive,
                        activated.nullifiers,
                        &sweep,
                        Rc::clone(&deferred),
                    )
                    .map_err(|_| ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable)?;
                let (pump, sweep) =
                    crate::production_xmr_recovery_pump_v22::ProductionXmrRecoveryPumpV22::attach_deferred_v23(
                        leg, sweep, Rc::clone(&deferred),
                    ).map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let scope =
                    crate::production_child_xmr::ProductionXmrMaterializationScopeV1::authenticate(
                        inputs,
                        role_plan,
                        upstream_scope,
                        downstream_scope,
                        leg,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let remote_pins =
                    xmr_remote_claim_pins_v23(inputs, role_plan, leg, &deployment, &setup)?;
                let source = crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteRefundSourceV23::Deferred(Rc::clone(&deferred));
                let actuator = Rc::new(actuator);
                let (requester, responder) = relay
                    .leg_mut(leg)
                    .contracts_mut()
                    .xmr_remote_action_pair_v24(&remote_pins, settlement)
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let (sweep, refund_responder) =
                    crate::production_xmr_remote_sweep_v23::assemble_native_xmr_action_faces_v24(
                        sweep,
                        remote_pins,
                        setup.clone(),
                        source,
                        Rc::clone(&actuator),
                        requester,
                        responder,
                        observation.clone(),
                        local_xmr_participant == settlement.counterparty_leg.beneficiary.0,
                    )
                    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
                let pump = match refund_responder {
                    Some(responder) => pump
                        .with_refund_responder_v24(responder)
                        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
                    None => pump,
                };
                xmr_pumps_v22.push(pump);
                Ok(ProductionCounterpartyChildInputV7::Monero(Box::new(
                    crate::production_materializing_children::ProductionXmrChildInputV7 {
                        actuator,
                        funding_window_v23: funding_window_v23.clone(),
                        broadcast,
                        observation,
                        deployment,
                        setup,
                        lease,
                        min_confirmations: u64::from(
                            settlement.counterparty_leg.finality.min_confirmations,
                        ),
                        sweep,
                        scope,
                        lease_owner: Some(lease_owner),
                        recovery_driver_v12: None,
                        recovery_deferred_v23: Some(deferred),
                    },
                )))
            }
            _ => Err(ProductionRunErrorV1::SettlementChildAuthority),
        }
    }
}

fn xmr_remote_claim_pins_v23(
    inputs: &AuthenticatedProductionInputsV1,
    role_plan: &ComposedFinalClaimRolePlanV1,
    leg: LegIdV1,
    deployment: &deployment_registry::ResolvedMoneroDeploymentV1,
    setup: &xmr_setup_profile::ValidatedXmrSetup,
) -> Result<
    crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteClaimPinsV23,
    ProductionRunErrorV1,
> {
    let (settlement, plan_leg, child_leg) = match leg {
        LegIdV1::Upstream => (
            inputs.composition().upstream(),
            dom_final_claim_binding::ComposedSettlementLegV1::Upstream,
            settlement_coordinator::SettlementLegV1::Upstream,
        ),
        LegIdV1::Downstream => (
            inputs.composition().downstream(),
            dom_final_claim_binding::ComposedSettlementLegV1::Downstream,
            settlement_coordinator::SettlementLegV1::Downstream,
        ),
    };
    let session = inputs
        .monero_session(leg)
        .ok_or(ProductionRunErrorV1::Inputs)?;
    let max_fee_piconero = u64::try_from(settlement.fee_limit.counterparty_max)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(ProductionRunErrorV1::SettlementChildAuthority)?;
    let pins = crate::production_xmr_remote_sweep_v23::ProductionXmrRemoteClaimPinsV23 {
        network_genesis: deployment.deployment().genesis_hash,
        route_id: inputs.admission().route_id(),
        session_id: settlement.session_id.0,
        route_terms_digest: inputs.admission().frozen_bindings().terms_digest,
        terms_digest: setup.terms_hash(),
        registry_digest: deployment.registry_digest(),
        profile_digest: deployment.profile_digest(),
        deployment_digest: crate::production_child_xmr::resolved_monero_deployment_digest_v1(
            deployment,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
        route_scope_digest: inputs.composition().route_scope_digest(),
        composition_digest: inputs.composition().binding_digest(),
        role_plan_digest: role_plan.digest(),
        source_scope_digest: role_plan.entry(plan_leg).secret_source_scope_digest(),
        max_fee_piconero,
        adapter_max_raw_transaction_bytes: session.profile().max_raw_tx_bytes,
        leg: child_leg,
    };
    if setup.settlement_id() != settlement.settlement_id.0
        || setup.terms_hash()
            != settlement
                .terms_hash()
                .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
        || session.setup().binding_hash() != setup.binding_hash()
    {
        return Err(ProductionRunErrorV1::SettlementChildAuthority);
    }
    Ok(pins)
}

enum UpstreamPublicSourceV11 {
    Ready(Box<dyn ProductionChainPublicSecretSourceV1>),
    Bitcoin { chain_id: [u8; 32] },
    Dom,
}

struct UniversalPublicSourcesV11 {
    dom: ProductionDomPublicSecretSourceV1,
    external: Option<Box<dyn ProductionChainPublicSecretSourceV1>>,
}
impl ProductionPublicSecretSourceV1 for UniversalPublicSourcesV11 {
    fn reextract_public_secret(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<counterparty_api::RevealedSecretBytes, crate::supervisor::AuthorityRefusalV1> {
        let chain = request.exposure().chain_id;
        if self.dom.chain_id() == chain {
            return self.dom.reextract_for_chain(request);
        }
        let source = self
            .external
            .as_mut()
            .filter(|source| source.chain_id() == chain)
            .ok_or(crate::supervisor::AuthorityRefusalV1::Refused)?;
        source.reextract_for_chain(request)
    }
}

/// An authenticated coordinator exposure fixes the exact Solana signature.
/// Reopening does not need a caller-provided precomputed signature: the native
/// extractor rechecks the escrow identity, claim data and cross-curve relation.
struct LateSolanaPublicSourceV11 {
    route_id: [u8; 32],
    composition_digest: [u8; 32],
    pool: solana_rpc_pool::SolanaRpcPool<solana_rpc::HttpSolanaRpc>,
    deployment: deployment_registry::ResolvedSolanaDeploymentV1,
    setup: solana_profile::ValidatedSolanaSetup,
}
impl ProductionChainPublicSecretSourceV1 for LateSolanaPublicSourceV11 {
    fn chain_id(&self) -> [u8; 32] {
        self.deployment.profile().chain_id.0
    }
    fn reextract_for_chain(
        &mut self,
        request: ProductionPublicSecretRequestV1<'_>,
    ) -> Result<counterparty_api::RevealedSecretBytes, crate::supervisor::AuthorityRefusalV1> {
        use crate::supervisor::AuthorityRefusalV1 as Refusal;
        if request.route_id() != self.route_id
            || request.composition_digest() != self.composition_digest
            || request.exposure().chain_id != self.chain_id()
        {
            return Err(Refusal::Inconsistent);
        }
        let mut source = crate::production_plan_source::ProductionSolanaPublicSecretSourceV1::new(
            self.route_id,
            self.composition_digest,
            request.exposure().transaction_id,
            self.pool.clone(),
            self.setup.clone(),
            &self.deployment,
        )?;
        source.reextract_for_chain(request)
    }
}

/// Validate routing bindings. Actual funding authority is established when
/// the selected child reopens the native gate and conditioned recovery custody.
fn require_compensated_xmr_funding_authority_v11(
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<(), ProductionRunErrorV1> {
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        let Some(session) = inputs.monero_session(leg) else {
            continue;
        };
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        if session.setup().binding_hash() == [0; 32]
            || session.setup().terms_hash()
                != terms
                    .terms_hash()
                    .map_err(|_| ProductionRunErrorV1::Inputs)?
            || session.setup().settlement_id() != terms.settlement_id.0
        {
            return Err(ProductionRunErrorV1::XmrCompensatedFundingAuthorityUnavailable);
        }
    }
    // This is only routing readiness. The Monero branch below must reopen the
    // same-Store gate and encrypted V22 conditional graph before constructing
    // either child. No setup hash authorizes funding or compensation.
    Ok(())
}

#[cfg(test)]
mod bitcoin_leg_bundle_writer_v22_tests {
    use super::*;

    fn resources() -> ProductionBitcoinLegResourcesV22 {
        ProductionBitcoinLegResourcesV22 {
            prebroadcast_store: "state/upstream-prebroadcast.sqlite3".to_owned(),
            claim_peer_socket: "run/upstream-claim.sock".to_owned(),
            claim_exchange_timeout_ms: 15_000,
        }
    }

    fn pins() -> ProductionBitcoinLegPinsV22 {
        let mut byte = 31u8;
        let mut next = || {
            byte += 1;
            [byte; 32]
        };
        ProductionBitcoinLegPinsV22 {
            settlement_id: next(),
            session_id: next(),
            terms_digest: next(),
            deployment_digest: next(),
            route_binding: next(),
            plan_digest: next(),
            receipt_digest: next(),
            contract_script_pubkey_digest: next(),
            claim_destination_script_pubkey_digest: next(),
            refund_destination_script_pubkey_digest: next(),
            refund_key_xonly: next(),
            funding_template_hash: next(),
            claim_template_hash: next(),
            refund_template_hash: next(),
        }
    }

    /// Bitcoin's bundle is checked the same way the scriptless families' is:
    /// exact format string, byte canonicality, and every pin carried through
    /// unchanged into the native prebroadcast pins the store revalidates.
    #[test]
    fn encoded_bitcoin_bundle_round_trips_and_carries_all_fourteen_pins() {
        let pins = pins();
        let bundle =
            encode_bitcoin_leg_authority_bundle_v22(resources(), &pins).expect("valid resources");
        let value: BitcoinAuthorityBundleV11 =
            serde_json::from_slice(bundle.bytes()).expect("decodes");
        assert_eq!(
            serde_json::to_vec(&value).expect("re-encodes"),
            bundle.bytes()
        );
        assert_eq!(value.format, "DOM-INTEROPD-BITCOIN-AUTHORITY-V11");
        assert_eq!(value.claim_exchange_timeout_ms, 15_000);
        let native = value.native_pins(LegIdV1::Upstream);
        assert_eq!(native.leg, LegIdV1::Upstream);
        assert_eq!(native.settlement_id, pins.settlement_id);
        assert_eq!(native.session_id, pins.session_id);
        assert_eq!(native.terms_digest, pins.terms_digest);
        assert_eq!(native.deployment_digest, pins.deployment_digest);
        assert_eq!(native.route_binding, pins.route_binding);
        assert_eq!(native.plan_digest, pins.plan_digest);
        assert_eq!(native.receipt_digest, pins.receipt_digest);
        assert_eq!(
            native.contract_script_pubkey_digest,
            pins.contract_script_pubkey_digest
        );
        assert_eq!(
            native.claim_destination_script_pubkey_digest,
            pins.claim_destination_script_pubkey_digest
        );
        assert_eq!(
            native.refund_destination_script_pubkey_digest,
            pins.refund_destination_script_pubkey_digest
        );
        assert_eq!(native.refund_key_xonly, pins.refund_key_xonly);
        assert_eq!(native.funding_template_hash, pins.funding_template_hash);
        assert_eq!(native.claim_template_hash, pins.claim_template_hash);
        assert_eq!(native.refund_template_hash, pins.refund_template_hash);
        assert_eq!(
            bundle.digest(),
            ProductionUniversalLegV11::bundle_digest(bundle.bytes()).expect("digest")
        );
    }

    /// Both paths join the cross-position isolation set, so an absolute path,
    /// a traversal or an empty name has to be refused where it is written and
    /// not only where the route is composed.
    #[test]
    fn the_writer_refuses_resources_the_isolation_check_would_reject() {
        let refused = |resources| {
            matches!(
                encode_bitcoin_leg_authority_bundle_v22(resources, &pins()),
                Err(ProductionRunErrorV1::Configuration)
            )
        };
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            prebroadcast_store: "/absolute/store.sqlite3".to_owned(),
            ..resources()
        }));
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            prebroadcast_store: "../escape.sqlite3".to_owned(),
            ..resources()
        }));
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            claim_peer_socket: String::new(),
            ..resources()
        }));
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            claim_peer_socket: "run/claim\\peer.sock".to_owned(),
            ..resources()
        }));
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            claim_exchange_timeout_ms: 0,
            ..resources()
        }));
        assert!(refused(ProductionBitcoinLegResourcesV22 {
            claim_exchange_timeout_ms: 30_001,
            ..resources()
        }));
        assert!(encode_bitcoin_leg_authority_bundle_v22(
            ProductionBitcoinLegResourcesV22 {
                claim_exchange_timeout_ms: 30_000,
                ..resources()
            },
            &pins()
        )
        .is_ok());
    }
}
