//! Provisioning identities and signed economics for the real DOM↔SOL cold start.
//! No inventory balance, reservation, F6 grant or mutable daemon DB is created.
use super::{
    NativeSolColdStartV23, NativeSolDaemonCredentialsV23, NativeSolDaemonResourcesV23,
    SolColdStartSignedTimeV23, SolanaTestValidatorOwnerV23,
};
use crate::production_config::*;
use crate::production_f6_factory::native_daemon_export_v23::{
    encode_native_f6_bundle_v23, NativeF6BundleInputsV23, NativeF6ClaimInputsV23,
    NativeF6SignerEndpointV23,
};
use crate::production_f6_factory::native_observation_v23::{
    inventory_evidence_digest_v23, NativeF6ObservationBodyV23, FILE_V23,
};
use crate::production_inputs::native_daemon_planning_v23::{
    NativeDaemonOwnerPinsV23, NativeDaemonPlanningContextV23,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use dom_scriptless_chain_adapter::ScriptlessScanCursorV1;
use rand::RngCore;
use route_executor::LegIdV1;
use solver_inventory::{InventoryKeyV1, InventoryObservationKindV1, InventoryObservationV1};
use solver_status::{
    SignedSolverStatusV1, SolverOperationalStateV1, SolverStatusObservationV1, SolverStatusScopeV1,
    SolverStatusSignatureV1, SolverStatusStatementV1,
};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

#[path = "production_xmr_native_daemon_hsm_v23_tests.rs"]
mod hsm_v23;
use hsm_v23::{NativeF6HsmOwnerV23, NativeF6HsmScopeV23};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeSolF6ActorProvisionV23 {
    pub owners: NativeDaemonOwnerPinsV23,
    pub family: ProductionFamilyInputsV6,
    pub bounds: ProductionRuntimeBoundsV1,
    pub bundle: Vec<u8>,
    // Keep actual signer endpoints alive across both daemon create/reopen runs.
    _signers: Vec<NativeF6HsmOwnerV23>,
}

pub(crate) struct NativeSolF6ProvisionV23 {
    pub actors: [NativeSolF6ActorProvisionV23; 2],
    /// Independent status-authority keys stay with the scenario owner; signed
    /// status must describe real observed inventory, never a fake grant.
    status_secrets: [Zeroizing<[u8; 32]>; 2],
}

impl NativeSolColdStartV23 {
    /// Connected pre-C/D preparation. Caller retains the returned signer owner
    /// while handing resources to the binary; no V11/Relay guard is bypassed.
    pub(crate) fn prepare_mainnet_f6_pair_v25(
        &self,
        nodes: [crate::production_node::ProductionNodeConfigV1; 2],
        validator: &SolanaTestValidatorOwnerV23,
        time: &SolColdStartSignedTimeV23,
        baseline: &super::xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23,
        credentials: &NativeSolDaemonCredentialsV23,
    ) -> Result<(
        [(NativeSolDaemonResourcesV23, NativeDaemonPlanningContextV23); 2],
        NativeSolF6ProvisionV23,
    )> {
        let [alice_node, bob_node] = nodes;
        let alice =
            self.prepare_mainnet_actor_v25(0, alice_node, validator, time, baseline, credentials)?;
        let bob =
            self.prepare_mainnet_actor_v25(1, bob_node, validator, time, baseline, credentials)?;
        let f6 = NativeSolF6ProvisionV23::prepare(self, [&alice.1, &bob.1], credentials, time)?;
        f6.publish_observations_v25(
            self,
            [&alice.1, &bob.1],
            [&alice.0, &bob.0],
            credentials,
            time,
            baseline,
            validator,
        )?;
        Ok(([alice, bob], f6))
    }
}

impl NativeSolF6ProvisionV23 {
    pub(crate) fn prepare(
        cold: &NativeSolColdStartV23,
        plans: [&NativeDaemonPlanningContextV23; 2],
        credentials: &NativeSolDaemonCredentialsV23,
        time: &SolColdStartSignedTimeV23,
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
        // Bind the DLEQ-validated setups and negotiated amounts without
        // treating them as confirmed inventory or a reservation certificate.
        for position in 0..2 {
            economics.extend_from_slice(&cold.terms[position].terms_hash()?);
            economics.extend_from_slice(&cold.participant_setups[position].binding.setup_id);
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
                claim_profile: NativeF6ClaimInputsV23::SolanaEnrollment,
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
                super::super::xmr_coldstart_v23::retained_native_bootstrap_name_v24(
                    root,
                    &cold.contracts_bootstrap,
                )?;
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
            actors.push(NativeSolF6ActorProvisionV23 {
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
        })
    }

    /// DOM wallet collateral plus the solver's finalized SOL funder balances.
    /// In the ordinary topology the solver funds only the position it
    /// delivers; the counterparty funds the other one.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_observations_v25(
        &self,
        cold: &NativeSolColdStartV23,
        plans: [&NativeDaemonPlanningContextV23; 2],
        resources: [&NativeSolDaemonResourcesV23; 2],
        credentials: &NativeSolDaemonCredentialsV23,
        time: &SolColdStartSignedTimeV23,
        baseline: &super::xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23,
        validator: &SolanaTestValidatorOwnerV23,
    ) -> Result<()> {
        let plan = plans[0];
        let solver = plan.roster_bundle().legs()[0]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .ok_or("native observer solver missing")?
            .participant_id;
        let actor = (0..2)
            .find(|actor| cold.actor_id(*actor).ok() == Some(solver.0))
            .ok_or("native observer solver wallet owner missing")?;
        let path = resources[actor].state_dir().join(
            resources[actor]
                .paths()
                .get(ProductionPathRoleV1::DomWallet),
        );
        let wallet = dom_wallet2::load_wallet_state(
            &path,
            std::str::from_utf8(&credentials.wallet_passphrases[actor])?,
        )?;
        let adapter = baseline.adapter();
        if wallet.network != dom_wallet2::Network::Mainnet
            || wallet.chain_id != adapter.expected_identity().chain_id
        {
            return Err("native observer wallet identity mismatch".into());
        }
        let mut cursor = ScriptlessScanCursorV1::genesis();
        let mut snapshot = None;
        let mut blocks = Vec::new();
        let mut evidence = Vec::new();
        loop {
            let page = adapter.scan_page(cursor, 64)?;
            let identity = (page.identity.tip_height, page.identity.tip_hash);
            if snapshot.is_some_and(|old| old != identity) {
                return Err("native observer chain changed during full scan".into());
            }
            snapshot = Some(identity);
            for block in &page.blocks {
                evidence.extend_from_slice(&block.canonical_header_bytes);
                for transaction in &block.transactions {
                    evidence.extend_from_slice(transaction.canonical_bytes());
                }
            }
            cursor = page.next_cursor;
            blocks.extend(page.blocks);
            if page.reached_snapshot_tip {
                break;
            }
            if blocks.len() > 16_384 {
                return Err("native observer baseline bound".into());
            }
        }
        let (tip, anchor) = snapshot.ok_or("native observer missing tip")?;
        let mut spendable = 0_u128;
        for output in wallet.outputs.iter().filter(|output| {
            output.status == dom_wallet2::OutputStatus::Confirmed && output.reserved_for.is_none()
        }) {
            let origin = output.origin_block.ok_or("native observer output origin")?;
            if !blocks
                .iter()
                .any(|block| block.height == origin.height && block.block_hash == origin.hash)
                || blocks
                    .iter()
                    .flat_map(|block| &block.transactions)
                    .any(|tx| tx.spends_commitment(&output.commitment))
            {
                continue;
            }
            if output.is_coinbase
                && tip
                    .checked_sub(origin.height)
                    .is_none_or(|age| age < dom_core::COINBASE_MATURITY)
            {
                continue;
            }
            let blind = dom_crypto::BlindingFactor::from_bytes(*output.blinding)?;
            if dom_crypto::pedersen::Commitment::commit(output.value, &blind).as_bytes()
                != &output.commitment
            {
                return Err("native observer owned commitment opening mismatch".into());
            }
            if !output.is_coinbase
                && !blocks
                    .iter()
                    .flat_map(|block| &block.transactions)
                    .any(|tx| tx.creates_commitment(&output.commitment))
            {
                return Err("native observer output provenance unavailable".into());
            }
            spendable = spendable
                .checked_add(u128::from(output.value))
                .ok_or("native observer balance overflow")?;
            evidence.extend_from_slice(&output.commitment);
            evidence.extend_from_slice(&output.value.to_be_bytes());
            evidence.extend_from_slice(&origin.hash);
        }
        if spendable == 0 {
            return Err("native observer has no observed solver collateral".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let limits =
            route_time_anchor::RouteTimePolicyV2::decode(time.policy.policy_bytes())?.limits();
        let until = now
            .checked_add(limits.max_evidence_age_seconds)
            .ok_or("native observer time overflow")?
            .min(limits.expires_at_seconds);
        if now < limits.valid_from_seconds || until <= now {
            return Err("native observer expired policy".into());
        }
        let terms = [plan.composition().upstream(), plan.composition().downstream()];
        // One wallet carries both duties in the ordinary topology: the bond the
        // solver pledges and the DOM position it funds. Publish the observation
        // only when the observed balance covers both.
        let solver_dom_funding: u128 = terms
            .iter()
            .filter(|leg| leg.dom_leg.refund_to == solver)
            .map(|leg| leg.dom_leg.amount)
            .sum();
        let required_dom = terms
            .iter()
            .map(|leg| leg.dom_leg.amount)
            .max()
            .ok_or("native observer DOM collateral terms")?
            .checked_add(solver_dom_funding)
            .ok_or("native observer DOM collateral overflow")?;
        if spendable < required_dom {
            return Err("native observer solver cannot cover its bond and DOM funding".into());
        }
        let profile_bundle_digest = plan.admission().frozen_bindings().profile_bundle_digest;
        let mut observations = vec![InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: rfq::ChainId(terms[0].dom_leg.chain_id.0),
                asset_id: rfq::AssetId(terms[0].dom_leg.asset_id.0),
                authority_id: solver,
            },
            spendable_amount: spendable,
            canonical_height: tip,
            canonical_anchor_digest: anchor,
            evidence_digest: digest(b"DOM/NATIVE-F6/WALLET-RPC-EVIDENCE/V23\0", &[&evidence])?,
            registry_manifest_digest: plan.resolved_registry().manifest_digest(),
            profile_bundle_digest,
            asset_binding_digest: plan
                .resolved_registry()
                .asset_binding_digest(terms[0].dom_leg.chain_id, terms[0].dom_leg.asset_id)?,
            observed_at_unix_ms: now.checked_mul(1000).ok_or("native observer clock")?,
            valid_until_unix_ms: until.checked_mul(1000).ok_or("native observer clock")?,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        }];
        // SOL: one chain/asset key for both legs; each is funded by its own
        // counterparty refund party.
        let chain = terms[0].counterparty_leg.chain_id;
        let asset = terms[0].counterparty_leg.asset_id;
        if terms[1].counterparty_leg.chain_id != chain || terms[1].counterparty_leg.asset_id != asset
        {
            return Err("native observer SOL legs name different chain assets".into());
        }
        // In the ordinary route topology the solver funds exactly the position
        // it delivers; the other one is funded by the counterparty. The solver
        // inventory therefore covers that one leg, never the whole route.
        let mut required = 0_u128;
        let mut accounts = BTreeSet::new();
        for (position, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            let setup = plan.solana_session(leg)?.setup();
            if setup.funder() != cold.participant_setups[position].binding.funder {
                return Err("native observer SOL setup is not the ceremony's".into());
            }
            if terms[position].counterparty_leg.refund_to != solver {
                continue;
            }
            required = required
                .checked_add(terms[position].counterparty_leg.amount)
                .ok_or("native observer SOL amount overflow")?;
            accounts.insert(setup.funder());
        }
        if accounts.is_empty() {
            return Err("native observer solver funds no SOL position".into());
        }
        let (slot, block_hash) = validator.finalized_anchor_v25()?;
        let mut sol_evidence = Vec::new();
        sol_evidence.extend_from_slice(&validator.genesis_hash());
        sol_evidence.extend_from_slice(&slot.to_be_bytes());
        sol_evidence.extend_from_slice(&block_hash);
        let mut lamports = 0_u128;
        for account in &accounts {
            let balance = validator.balance(*account)?;
            lamports = lamports
                .checked_add(u128::from(balance))
                .ok_or("native observer SOL balance overflow")?;
            sol_evidence.extend_from_slice(&account.0);
            sol_evidence.extend_from_slice(&balance.to_be_bytes());
        }
        if lamports < required {
            return Err("native observer solver cannot cover the SOL it delivers".into());
        }
        observations.push(InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: rfq::ChainId(chain.0),
                asset_id: rfq::AssetId(asset.0),
                authority_id: solver,
            },
            spendable_amount: lamports,
            canonical_height: slot,
            canonical_anchor_digest: block_hash,
            evidence_digest: digest(b"DOM/NATIVE-F6/SOL-RPC-EVIDENCE/V25\0", &[&sol_evidence])?,
            registry_manifest_digest: plan.resolved_registry().manifest_digest(),
            profile_bundle_digest,
            asset_binding_digest: plan.resolved_registry().asset_binding_digest(chain, asset)?,
            observed_at_unix_ms: now.checked_mul(1000).ok_or("native observer clock")?,
            valid_until_unix_ms: until.checked_mul(1000).ok_or("native observer clock")?,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        });
        observations.sort_by_key(|value| value.key);
        let inventory_binding = self.actors[0].owners.solver_inventory_binding_digest;
        let source = inventory_evidence_digest_v23(
            plan.roster_bundle().network_id(),
            plan.composition().binding_digest(),
            inventory_binding,
            &observations,
        )?;
        let secp = SecpContext::new(&[0x60; 32]);
        let mut statuses = Vec::new();
        for position in 0..2 {
            let statement = SolverStatusStatementV1::new(
                SolverStatusScopeV1 {
                    network_id: plan.roster_bundle().network_id(),
                    registry_digest: plan.resolved_registry().manifest_digest(),
                    registry_epoch: plan.resolved_registry().epoch(),
                    roster_snapshot: plan.roster_bundle().legs()[position].roster_snapshot,
                    solver_id: solver,
                },
                SolverStatusObservationV1 {
                    status_epoch: 1,
                    source_evidence_digest: source,
                    state: SolverOperationalStateV1::Active,
                    observed_at_seconds: now,
                    valid_until_seconds: until,
                },
            )?;
            let hash = statement.statement_digest()?;
            let signatures = self
                .status_secrets
                .iter()
                .enumerate()
                .map(|(index, secret)| -> Result<_> {
                    Ok(SolverStatusSignatureV1 {
                        signer_index: u16::try_from(index)?,
                        signature: secp.sign_bip340(secret, &hash, &[0x61; 32])?.0,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            statuses.push(SignedSolverStatusV1::new(statement, signatures)?);
        }
        let body = NativeF6ObservationBodyV23 {
            network: plan.roster_bundle().network_id(),
            composition: plan.composition().binding_digest(),
            inventory_binding,
            observations,
            statuses: statuses
                .try_into()
                .map_err(|_| "native observer status pair")?,
        };
        let bytes = body.encode(|hash| {
            self.status_secrets
                .iter()
                .enumerate()
                .map(|(index, secret)| {
                    Ok((
                        index as u16,
                        secp.sign_bip340(secret, &hash, &[0x62; 32])
                            .map_err(|_| {
                                crate::production_f6_lifecycle::ProductionF6ActivationRefusalV2::InvalidBinding
                            })?
                            .0,
                    ))
                })
                .collect()
        })?;
        for actor in 0..2 {
            publish(cold.actor_work(actor)?, FILE_V23, &bytes)?;
        }
        Ok(())
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

/// Same bounds as the XMR campaign: the Solana HTTP clients also carry a
/// fixed 30-second request bound, which service admission requires.
fn runtime_bounds() -> ProductionRuntimeBoundsV1 {
    ProductionRuntimeBoundsV1 {
        lease_duration_ms: 120_000,
        renew_before_ms: 60_000,
        dispatch_lease_ms: 30_000,
        coordinator_lease_ms: 120_000,
        actuator_lease_ms: 120_000,
        external_call_timeout_ms: 30_000,
        waiting_backoff_ms: 100,
        recovery_backoff_ms: 100,
        relay_poll_backoff_ms: 100,
        per_queue_batch_limit: 1,
    }
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
