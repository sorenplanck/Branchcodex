//! Provisioning identities and signed economics for the real cold-start daemon.
//! No inventory balance, reservation, F6 grant or mutable daemon DB is created.
use super::{ColdStartSignedTimeV23, NativeXmrColdStartV23, NativeXmrDaemonCredentialsV23};
use crate::production_config::*;
use crate::production_f6_factory::native_daemon_export_v23::{
    encode_native_f6_bundle_v23, NativeF6BundleInputsV23, NativeF6ClaimInputsV23,
    NativeF6SignerEndpointV23,
};
use crate::production_inputs::native_daemon_planning_v23::{
    NativeDaemonOwnerPinsV23, NativeDaemonPlanningContextV23,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use rand::RngCore;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

#[path = "production_xmr_native_daemon_hsm_v23_tests.rs"]
mod hsm_v23;
use hsm_v23::{NativeF6HsmOwnerV23, NativeF6HsmScopeV23};

#[path = "production_xmr_native_f6_observer_v23_tests.rs"]
mod observer_v23;
pub(crate) use observer_v23::{NativeF6XmrInventoryObservationV23, NativeF6XmrInventorySourceV23};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeF6ActorProvisionV23 {
    pub owners: NativeDaemonOwnerPinsV23,
    pub family: ProductionFamilyInputsV6,
    pub bounds: ProductionRuntimeBoundsV1,
    pub bundle: Vec<u8>,
    // Keep actual signer endpoints alive across both daemon create/reopen runs.
    _signers: Vec<NativeF6HsmOwnerV23>,
}

pub(crate) struct NativeF6ProvisionV23 {
    pub actors: [NativeF6ActorProvisionV23; 2],
    /// These independent status-authority keys stay with the scenario owner;
    /// signed status must describe real observed inventory, never a fake grant.
    pub status_secrets: [Zeroizing<[u8; 32]>; 2],
    pub status_authorities: AuthoritySetV1,
}

impl NativeXmrColdStartV23 {
    /// Connected pre-C/D preparation. Caller retains the returned signer owner
    /// while handing resources to the binary; no V11/Relay guard is bypassed.
    pub(crate) fn prepare_mainnet_f6_pair_v23(
        &self,
        nodes: [crate::production_node::ProductionNodeConfigV1; 2],
        funding: &super::xmr_graph_wallet_tests::native_observation_v23::RouteFundingOwnerV23,
        time: &ColdStartSignedTimeV23,
        baseline: &super::xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23,
        credentials: &NativeXmrDaemonCredentialsV23,
        xmr_source: &mut dyn NativeF6XmrInventorySourceV23,
    ) -> Result<(
        [(
            super::NativeXmrDaemonResourcesV23,
            NativeDaemonPlanningContextV23,
        ); 2],
        NativeF6ProvisionV23,
    )> {
        let [alice_node, bob_node] = nodes;
        let alice =
            self.prepare_mainnet_actor_v23(0, alice_node, funding, time, baseline, credentials)?;
        let bob =
            self.prepare_mainnet_actor_v23(1, bob_node, funding, time, baseline, credentials)?;
        let f6 = NativeF6ProvisionV23::prepare(self, [&alice.1, &bob.1], credentials, time)?;
        let xmr_inventory = xmr_source.observe_inventory(self, &alice.1, funding, time)?;
        f6.publish_observations_v23(
            self,
            [&alice.1, &bob.1],
            [&alice.0, &bob.0],
            credentials,
            time,
            baseline,
            &xmr_inventory,
        )?;
        Ok(([alice, bob], f6))
    }
}

impl NativeF6ProvisionV23 {
    pub(crate) fn prepare(
        cold: &NativeXmrColdStartV23,
        plans: [&NativeDaemonPlanningContextV23; 2],
        credentials: &NativeXmrDaemonCredentialsV23,
        time: &ColdStartSignedTimeV23,
    ) -> Result<Self> {
        let secp = SecpContext::new(&[0x56; 32]);
        let limits =
            route_time_anchor::RouteTimePolicyV2::decode(time.policy.policy_bytes())?.limits();
        let pre_f6_limits = route_time_anchor::PreF6TimePolicyLimitsV2 {
            valid_from_seconds: limits.valid_from_seconds,
            expires_at_seconds: limits.expires_at_seconds,
            max_evidence_age_seconds: limits.max_evidence_age_seconds,
        };
        if plans[0].composition().binding_digest() != plans[1].composition().binding_digest()
            || plans[0].roster_bundle().bundle_digest()?
                != plans[1].roster_bundle().bundle_digest()?
        {
            return Err("native F6 actors disagree on admitted route".into());
        }
        let solver = plans[0].roster_bundle().legs()[0]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .ok_or("native F6 missing solver")?
            .participant_id;
        if plans[0].roster_bundle().legs().iter().any(|leg| {
            leg.members
                .iter()
                .find(|member| member.role == relay::SenderRoleV1::Solver)
                .map(|member| member.participant_id)
                != Some(solver)
        }) {
            return Err("native F6 solver role disagreement".into());
        }
        let (bond_secrets, bond_authorities) = authority(&secp)?;
        let (status_secrets, status_authorities) = authority(&secp)?;
        let mut reserved = BTreeSet::new();
        for leg in plans[0].contracts_bootstrap().legs() {
            for participant in leg.participants() {
                let key = participant.schnorr_public_key();
                if key.len() != 33 || !matches!(key[0], 2 | 3) {
                    return Err("native F6 participant key encoding".into());
                }
                reserved.insert(key[1..].try_into()?);
            }
        }
        // Explicit fixture bond policy: principal-sized collateral in the DOM
        // native asset. This is a requirement, NOT evidence that it is present.
        let required_collateral = cold
            .terms
            .iter()
            .map(|term| term.dom_leg.amount)
            .max()
            .ok_or("native F6 collateral terms")?;
        let first = &cold.terms[0];
        if cold.terms.iter().any(|term| {
            term.dom_leg.chain_id != first.dom_leg.chain_id
                || term.dom_leg.asset_id != first.dom_leg.asset_id
        }) {
            return Err("native F6 collateral asset mismatch".into());
        }
        let bond_asset = plans[0]
            .resolved_registry()
            .asset_binding_digest(first.dom_leg.chain_id, first.dom_leg.asset_id)?;
        let mut economics = Vec::from(b"DOM-NATIVE-F6-ECONOMICS-V23\0".as_slice());
        economics.extend_from_slice(&plans[0].composition().binding_digest());
        economics.extend_from_slice(&solver.0);
        economics.extend_from_slice(&bond_asset);
        economics.extend_from_slice(&required_collateral.to_be_bytes());
        economics.extend_from_slice(&limits.expires_at_seconds.to_be_bytes());
        // Bind the actual candidates and negotiated amounts without treating
        // them as confirmed inventory or creating a reservation certificate.
        for position in 0..2 {
            economics.extend_from_slice(&cold.terms[position].terms_hash()?);
            economics.extend_from_slice(&cold.enrolled[position].setup().funding_tx_hash());
            economics
                .extend_from_slice(&cold.terms[position].counterparty_leg.amount.to_be_bytes());
        }
        economics.extend_from_slice(&bond_authorities.canonical_bytes()?);
        economics.extend_from_slice(&status_authorities.canonical_bytes()?);
        let policy = assurance_policy(first, required_collateral)?;
        let policy_bytes = policy.canonical_bytes()?;
        let policy_hash = policy.policy_hash()?;
        economics.extend_from_slice(&policy_bytes);
        let signature = secp.sign_bip340(&[91; 32], &policy_hash, &[0x57; 32])?.0;
        economics.extend_from_slice(&signature);
        let inventory_id = random_id();
        let inventory_binding = digest(
            b"DOM/NATIVE-F6/INVENTORY-OWNER/V23\0",
            &[
                &inventory_id,
                &plans[0].composition().binding_digest(),
                &policy_hash,
            ],
        )?;
        let mut actors = Vec::with_capacity(2);
        for actor in 0..2 {
            let plan = plans[actor];
            let root = cold.actor_work(actor)?;
            publish(root, "native-f6-economics-v23.bin", &economics)?;
            publish(root, "native-assurance-policy-v23.bin", &policy_bytes)?;
            let process = random_id();
            let coordinator = random_id();
            let coordinator_authority = random_id();
            let actuator = digest(
                b"DOM/NATIVE-F6/ACTUATOR-OWNER/V23\0",
                &[&random_id(), &process, &plan.composition().binding_digest()],
            )?;
            let relay_ids: [[u8; 32]; 7] = std::array::from_fn(|_| random_id());
            let mut ownership = Vec::from(b"DOM-NATIVE-OWNERS-V23\0".as_slice());
            for id in [
                process,
                coordinator,
                coordinator_authority,
                actuator,
                inventory_id,
                inventory_binding,
            ] {
                ownership.extend_from_slice(&id);
            }
            for id in relay_ids {
                ownership.extend_from_slice(&id);
            }
            ownership.extend_from_slice(&cold.actor_id(actor)?);
            ownership.extend_from_slice(&plan.composition().binding_digest());
            let ownership_digest = digest(b"DOM/NATIVE-F6/OWNERS/V23\0", &[&ownership])?;
            ownership.extend_from_slice(
                &secp
                    .sign_bip340(&[91; 32], &ownership_digest, &[0x58; 32])?
                    .0,
            );
            publish(root, "native-owner-provision-v23.bin", &ownership)?;
            let owners = NativeDaemonOwnerPinsV23 {
                process_owner_id: process,
                coordinator_id: coordinator,
                coordinator_plan_authority_id: coordinator_authority,
                actuator_bindings_digest: actuator,
                solver_inventory_binding_digest: inventory_binding,
            };
            let mut signers = Vec::new();
            let mut descriptors: [Vec<NativeF6SignerEndpointV23>; 2] = [Vec::new(), Vec::new()];
            for position in 0..2 {
                let directory = root.join(format!("native-f6-hsm-{position}"));
                std::fs::create_dir(&directory)?;
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
                for index in 0..2 {
                    let owner = NativeF6HsmOwnerV23::bind(
                        &directory,
                        u16::try_from(index)?,
                        random_id(),
                        Zeroizing::new(*bond_secrets[index]),
                        Zeroizing::new(*credentials.hsm_auth[position][actor][index]),
                        NativeF6HsmScopeV23 {
                            network_id: plan.roster_bundle().network_id(),
                            composition_id: plan.composition().binding_digest(),
                            position: if position == 0 {
                                rfq::v2::SettlementPositionV2::Upstream
                            } else {
                                rfq::v2::SettlementPositionV2::Downstream
                            },
                            solver,
                            bond_policy_hash: policy_hash,
                            registry_digest: plan.resolved_registry().manifest_digest(),
                            registry_epoch: plan.resolved_registry().epoch(),
                            bond_asset_binding_digest: bond_asset,
                            required_collateral,
                            expires_at_seconds: limits.expires_at_seconds,
                        },
                    )?;
                    descriptors[position].push(NativeF6SignerEndpointV23 {
                        independent_authority_id: owner.descriptor.independent_authority_id,
                        signer_index: owner.descriptor.signer_index,
                        signer_public_key: owner.descriptor.signer_public_key,
                        endpoint_uid: owner.descriptor.endpoint_uid,
                        endpoint: owner.descriptor.endpoint.clone(),
                    });
                    signers.push(owner);
                }
            }
            let input = NativeF6BundleInputsV23 {
                solver,
                inventory_binding_digest: inventory_binding,
                bond_policy_hash: policy_hash,
                bond_asset_binding_digest: bond_asset,
                required_collateral,
                status_max_lifetime_seconds: limits.max_evidence_age_seconds,
                pre_f6_limits,
                bond_authorities: bond_authorities.clone(),
                status_authorities: status_authorities.clone(),
                reserved_participant_keys: reserved.iter().copied().collect(),
                signers: descriptors,
                claim_profile: NativeF6ClaimInputsV23::NativeEnrollment,
            };
            let bundle = encode_native_f6_bundle_v23(plan, &input, |hash| {
                Ok(vec![(
                    0,
                    secp.sign_bip340(&[91; 32], &hash, &[0x5b; 32])?.0,
                )])
            })?;
            let budget = std::fs::read(&cold.plans[actor].budget_policy_file)?;
            dom_scriptless_store::BudgetPolicyV1::from_bytes(&budget)?;
            publish(root, "native-contracts-budget.bin", &budget)?;
            let bootstrap_name =
                retained_native_bootstrap_name_v24(root, &cold.contracts_bootstrap)?;
            let identity = cold
                .identity_store(actor)?
                .strip_prefix(root)?
                .to_str()
                .ok_or("native identity path encoding")?
                .to_owned();
            let f6 = ProductionF6PathReferencesV4::from_ordered(ProductionF6PathRoleV4::ALL.map(
                |role| {
                    format!(
                        "native-{}",
                        role.key().strip_prefix("path_").unwrap_or(role.key())
                    )
                },
            ))?;
            let contracts = plan.contracts_bootstrap();
            let family = ProductionFamilyInputsV6::new(
                ProductionFamilyInputsV5::new(
                    identity,
                    "native-contracts-budget.bin".into(),
                    f6,
                    bootstrap_name.into(),
                    ProductionContractsBootstrapPinsV5::new(
                        *contracts.commit_stage_digest(),
                        *contracts.reveal_stage_digest(),
                    )?,
                ),
                ProductionRelayAuthorityPinsV6 {
                    relay_database_id: relay_ids[0],
                    upstream_sender_store_id: relay_ids[1],
                    upstream_inbox_id: relay_ids[2],
                    upstream_reassembler_id: relay_ids[3],
                    downstream_sender_store_id: relay_ids[4],
                    downstream_inbox_id: relay_ids[5],
                    downstream_reassembler_id: relay_ids[6],
                    relay_max_envelopes: 4096,
                    sender_max_envelopes: 4096,
                    inbox_max_entries: 4096,
                    frame_max_messages: 128,
                    frame_max_active_bytes: 16_777_216,
                    frame_max_active_chunks: 4096,
                },
            );
            actors.push(NativeF6ActorProvisionV23 {
                owners,
                family,
                bounds: runtime_bounds(),
                bundle,
                _signers: signers,
            });
        }
        Ok(Self {
            actors: actors.try_into().map_err(|_| "native F6 actor count")?,
            status_secrets,
            status_authorities,
        })
    }
}

fn assurance_policy(
    terms: &kaystra_core::terms::SettlementTermsV1,
    collateral: u128,
) -> Result<uspe::objects::AssurancePolicyV1> {
    use kaystra_core::types::TimelockSpec;
    use uspe::objects::{AssurancePolicyV1, EvidenceRuleV1, PolicyId, TerminalPolicyV1};
    let TimelockSpec::BlockHeight { value } = terms.dom_leg.deadline else {
        return Err("native F4 requires negotiated DOM block-height deadlines".into());
    };
    let deadline = |delta| -> Result<_> {
        Ok(TimelockSpec::BlockHeight {
            value: value
                .checked_add(delta)
                .ok_or("native F4 deadline overflow")?,
        })
    };
    let policy = AssurancePolicyV1 {
        policy_id: PolicyId(random_id()),
        version: uspe::objects::POLICY_STRUCT_VERSION,
        protected_settlement: terms.settlement_id,
        terms_hash: terms.terms_hash()?,
        bond_chain_id: terms.dom_leg.chain_id,
        bond_asset: terms.dom_leg.asset_id,
        required_collateral: collateral,
        compensation_cap: collateral,
        collateral_deadline: deadline(0)?,
        claim_deadline: deadline(1)?,
        evidence_deadline: deadline(2)?,
        bond_release_deadline: deadline(3)?,
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: counterparty_api::AdaptorPointBytes(terms.adaptor_point_sec1),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    };
    policy.validate()?;
    Ok(policy)
}

fn runtime_bounds() -> ProductionRuntimeBoundsV1 {
    ProductionRuntimeBoundsV1 {
        lease_duration_ms: 120_000,
        renew_before_ms: 60_000,
        dispatch_lease_ms: 30_000,
        coordinator_lease_ms: 120_000,
        actuator_lease_ms: 120_000,
        // Enclose the unchanged native XMR HTTP clients' 30-second bound.
        // Five seconds is refused during service admission, before any swap.
        external_call_timeout_ms: 30_000,
        waiting_backoff_ms: 100,
        recovery_backoff_ms: 100,
        relay_poll_backoff_ms: 100,
        per_queue_batch_limit: 1,
    }
}

#[test]
fn native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24() {
    use crate::production_route_services::require_xmr_rpc_deadline_v24;
    let bounds = runtime_bounds();
    assert!(require_xmr_rpc_deadline_v24(bounds.external_call_timeout_ms).is_ok());
    for too_short in [0, 5_000, 29_999] {
        assert!(require_xmr_rpc_deadline_v24(too_short).is_err());
    }
    assert_eq!(bounds.external_call_timeout_ms, 30_000);
    assert!(bounds.external_call_timeout_ms <= bounds.dispatch_lease_ms);
    assert!(bounds.dispatch_lease_ms <= bounds.renew_before_ms);
    assert!(bounds.renew_before_ms < bounds.lease_duration_ms);
    assert!(bounds.dispatch_lease_ms <= bounds.coordinator_lease_ms);
    assert!(bounds.dispatch_lease_ms <= bounds.actuator_lease_ms);
    assert_eq!(bounds.per_queue_batch_limit, 1);
    // No expiry, backoff or owner lease is extended to mask slow computation.
    assert_eq!(bounds.lease_duration_ms, 120_000);
    assert_eq!(bounds.coordinator_lease_ms, 120_000);
    assert_eq!(bounds.actuator_lease_ms, 120_000);
    assert_eq!(bounds.dispatch_lease_ms, 30_000);
    assert_eq!(bounds.waiting_backoff_ms, 100);
    assert_eq!(bounds.recovery_backoff_ms, 100);
    assert_eq!(bounds.relay_poll_backoff_ms, 100);
}

fn random_id() -> [u8; 32] {
    loop {
        let mut value = [0; 32];
        rand::thread_rng().fill_bytes(&mut value);
        if value != [0; 32] {
            return value;
        }
    }
}

fn authority(secp: &SecpContext) -> Result<([Zeroizing<[u8; 32]>; 2], AuthoritySetV1)> {
    let mut keys = Vec::new();
    while keys.len() < 2 {
        let secret = Zeroizing::new(random_id());
        if let Ok(public) = secp.xonly_public_key(&secret) {
            if keys.iter().all(|(old, _)| *old != public) {
                keys.push((public, secret));
            }
        }
    }
    keys.sort_by_key(|(public, _)| *public);
    let authorities = AuthoritySetV1::new(2, keys.iter().map(|(public, _)| *public).collect())?;
    let secrets = keys
        .into_iter()
        .map(|(_, secret)| secret)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "native F6 authority count")?;
    Ok((secrets, authorities))
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut hash = Blake2bVar::new(32)?;
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    let mut value = [0; 32];
    hash.finalize_variable(&mut value)?;
    if value == [0; 32] {
        return Err("native F6 zero digest".into());
    }
    Ok(value)
}

/// Select the original completed ceremony owner, not a public-only copy. The
/// production mount's reserved basename is intentional: another basename is
/// the externally prepared path and does not reopen the private V13 custody.
/// Never create, rename or replace an artifact to make that guard pass.
pub(crate) fn retained_native_bootstrap_name_v24(
    root: &Path,
    expected: &[u8],
) -> Result<&'static str> {
    let name = crate::production_contracts_bootstrap::producer_v13::ARTIFACT;
    if expected.is_empty() {
        return Err("native completed bootstrap is absent".into());
    }
    let retained = read_owner_file_bounded(
        &root.join(name),
        u64::try_from(expected.len())?,
        ProductionConfigErrorV1::InvalidPublicBinding,
    )?;
    if retained != expected {
        return Err("native original bootstrap differs from authenticated artifact".into());
    }
    Ok(name)
}

fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    if std::fs::read(path)? != bytes {
        return Err("native F6 publication mismatch".into());
    }
    Ok(())
}
