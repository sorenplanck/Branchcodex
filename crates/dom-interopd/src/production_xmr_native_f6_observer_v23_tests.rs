//! Actual wallet/RPC observations, distinct from funding plans or F6 grants.
use super::*;
use crate::production_f6_factory::native_observation_v23::{
    inventory_evidence_digest_v23, NativeF6ObservationBodyV23, FILE_V23,
};
use dom_scriptless_chain_adapter::ScriptlessScanCursorV1;
use solver_inventory::{InventoryKeyV1, InventoryObservationKindV1, InventoryObservationV1};
use solver_status::{
    SignedSolverStatusV1, SolverOperationalStateV1, SolverStatusObservationV1, SolverStatusScopeV1,
    SolverStatusSignatureV1, SolverStatusStatementV1,
};
use xmr_rpc_broadcast_blocking::BlockingMoneroDaemonReaderV1;

/// Closed result emitted only by the concrete native source-inventory observer.
///
/// There deliberately is NO public constructor from a balance, raw route
/// funding transaction or hash. The owner implementation below combines a
/// distinct solver wallet output, exact raw provenance, authenticated sidecar
/// ownership, quorum inclusion/finality and key-image absence with route IDs
/// and fresh signed time before this value can exist.
pub(crate) struct NativeF6XmrInventoryObservationV23 {
    observations: Vec<InventoryObservationV1>,
}

/// Mandatory real observer port, invoked after ceremony IDs and planning exist.
/// Implementations cannot fabricate the private-field capability above.
pub(crate) trait NativeF6XmrInventorySourceV23 {
    fn observe_inventory(
        &mut self,
        cold: &NativeXmrColdStartV23,
        planning: &NativeDaemonPlanningContextV23,
        funding: &super::super::xmr_graph_wallet_tests::native_observation_v23::RouteFundingOwnerV23,
        time: &ColdStartSignedTimeV23,
    ) -> Result<NativeF6XmrInventoryObservationV23>;
}

impl NativeF6XmrInventorySourceV23
    for super::super::xmr_graph_wallet_tests::native_observation_v23::NativeMainnetXmrInventorySourceV23
{
    fn observe_inventory(
        &mut self,
        cold: &NativeXmrColdStartV23,
        planning: &NativeDaemonPlanningContextV23,
        funding: &super::super::xmr_graph_wallet_tests::native_observation_v23::RouteFundingOwnerV23,
        time: &ColdStartSignedTimeV23,
    ) -> Result<NativeF6XmrInventoryObservationV23> {
        use crate::production_inputs::ProductionRoutePositionV1::{Downstream, Upstream};
        use route_executor::LegIdV1;

        let route = planning.admission().route_id();
        let network = planning.roster_bundle().network_id();
        let upstream = planning.monero_session(LegIdV1::Upstream);
        let downstream = planning.monero_session(LegIdV1::Downstream);
        let sessions = [upstream.session_id(), downstream.session_id()];
        let terms_hashes = [upstream.terms_digest(), downstream.terms_digest()];
        self.require_custody_scope_v23(network, route, sessions, terms_hashes)?;
        let terms = [planning.composition().upstream(), planning.composition().downstream()];
        let solver = planning.roster_bundle().legs()[0]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .ok_or("XMR inventory solver absent")?
            .participant_id;
        if planning.roster_bundle().legs()[1]
            .members
            .iter()
            .find(|member| member.role == relay::SenderRoleV1::Solver)
            .map(|member| member.participant_id)
            != Some(solver)
            || upstream.position() != Upstream
            || downstream.position() != Downstream
            || upstream.route_id() != route
            || downstream.route_id() != route
            || upstream.network_id() != network
            || downstream.network_id() != network
            || upstream.profile() != downstream.profile()
            || upstream.profile().network != xmr_setup_profile::XmrNetwork::Mainnet
            || upstream.deployment().deployment().genesis_hash
                != downstream.deployment().deployment().genesis_hash
            || terms[0].counterparty_leg.chain_id != terms[1].counterparty_leg.chain_id
            || terms[0].counterparty_leg.asset_id != terms[1].counterparty_leg.asset_id
            || terms[0].counterparty_leg.adapter_profile_hash != upstream.deployment().profile_digest()
            || terms[1].counterparty_leg.adapter_profile_hash != downstream.deployment().profile_digest()
        {
            return Err("XMR inventory authenticated Mainnet scope mismatch".into());
        }
        let required = u64::try_from(terms[0].counterparty_leg.amount)?
            .checked_add(u64::try_from(terms[1].counterparty_leg.amount)?)
            .ok_or("XMR inventory required amount overflow")?;
        if self.authority_id() != solver.0
            || self.amount_piconero() != required
            || self.max_fee_piconero() == 0
            || self.max_fee_piconero()
                > upstream.deployment().deployment().max_fee_piconero
            || self.max_fee_piconero()
                > downstream.deployment().deployment().max_fee_piconero
            || self.max_fee_piconero() > u64::try_from(terms[0].fee_limit.counterparty_max)?
            || self.max_fee_piconero() > u64::try_from(terms[1].fee_limit.counterparty_max)?
            || funding.hash(0)? == self.tx_hash()
            || funding.hash(1)? == self.tx_hash()
            || cold.enrolled[0].setup().funding_tx_hash() == self.tx_hash()
            || cold.enrolled[1].setup().funding_tx_hash() == self.tx_hash()
        {
            return Err("XMR inventory reused or relabelled route funding".into());
        }

        let decoded_policy = route_time_anchor::RouteTimePolicyV2::decode(
            time.policy.policy_bytes(),
        )?;
        let decoded_evidence = route_time_anchor::RouteTimeEvidenceV2::decode(
            time.evidence.evidence_bytes(),
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let limits = decoded_policy.limits();
        let route_scope = route_time_anchor::route_scope_digest(terms[0], terms[1])?;
        if time.observed_at_seconds != decoded_evidence.observed_at_seconds()
            || decoded_policy.route_scope_digest() != route_scope
            || decoded_evidence.route_scope_digest() != route_scope
            || decoded_evidence.policy_digest() != decoded_policy.policy_digest()?
            || decoded_evidence.observed_at_seconds() > now
            || now >= decoded_evidence.expires_at_seconds()
            || now < limits.valid_from_seconds
            || now >= limits.expires_at_seconds
            || now.checked_sub(decoded_evidence.observed_at_seconds())
                .ok_or("XMR inventory time underflow")?
                > limits.max_evidence_age_seconds
        {
            return Err("XMR inventory signed time is not fresh".into());
        }

        let profile = upstream.profile();
        let genesis = upstream.deployment().deployment().genesis_hash;
        if funding.urls().len() != usize::from(profile.rpc_node_count)
            || !crate::production_xmr_quorum::valid_quorum_v5(
                funding.urls().len(),
                usize::from(profile.rpc_quorum),
            )
        {
            return Err("XMR inventory quorum profile mismatch".into());
        }
        let mut distinct_ports = std::collections::BTreeSet::new();
        let mut readers = Vec::with_capacity(funding.urls().len());
        for url in funding.urls() {
            let reader = BlockingMoneroDaemonReaderV1::new(url.clone())?;
            let port = reader.loopback_port_v5()?;
            if !distinct_ports.insert(port) {
                return Err("XMR inventory duplicate quorum voter".into());
            }
            readers.push(reader);
        }

        let owned = self.derive_owned_key_image_v23()?;
        if owned.funding().transaction().tx_hash != self.tx_hash()
            || owned.funding().amount_piconero() != self.amount_piconero()
            || self.destination() != self.expected_destination_v23()?
        {
            return Err("XMR inventory exact output provenance mismatch".into());
        }

        let actor = (0..2)
            .find(|actor| cold.actor_id(*actor).ok() == Some(solver.0))
            .ok_or("XMR inventory solver actor absent")?;
        let socket = funding.socket(0, actor)?;
        let nonce = digest(
            b"DOM/NATIVE-F6/XMR-INVENTORY-SIDECAR/V23\0",
            &[
                &network,
                &route,
                &sessions[0],
                &sessions[1],
                &self.tx_hash(),
                &decoded_evidence.evidence_digest()?,
            ],
        )?;
        let sidecar_observation = self.verify_sidecar_v23(actor, socket, nonce, sessions[0])?;
        if sidecar_observation.event_index != owned.funding().output_index()
            || sidecar_observation.received_amount_piconero != self.amount_piconero()
            || !sidecar_observation.spendable
        {
            return Err("XMR inventory sidecar ownership disagreement".into());
        }

        let inclusion_votes = crate::production_xmr_quorum::collect_checked_votes_v8(
            readers
                .iter()
                .map(|reader| reader.transaction_observation_v5(self.tx_hash(), genesis))
                .collect(),
        )?;
        let inclusion = crate::production_xmr_quorum::decide_inclusion_v5(
            &inclusion_votes,
            usize::from(profile.rpc_quorum),
        )?
        .ok_or("XMR inventory output absent from canonical quorum")?;
        let minimum_confirmations = terms
            .iter()
            .map(|value| value.counterparty_leg.finality.min_confirmations)
            .max()
            .ok_or("XMR inventory finality absent")?;
        if inclusion.confirmations < u64::from(minimum_confirmations) {
            return Err("XMR inventory output is not final".into());
        }
        let spent_votes = crate::production_xmr_quorum::collect_checked_votes_v8(
            readers
                .iter()
                .map(|reader| reader.key_image_spent_on_chain_v5(owned.key_image(), genesis))
                .collect(),
        )?;
        if crate::production_xmr_quorum::decide_key_image_v5(
            &spent_votes,
            usize::from(profile.rpc_quorum),
        )? {
            return Err("XMR inventory output is spent or contested".into());
        }

        // Match the daemon's stable public evidence identity, not a second
        // fixture-only domain or the transient RPC tip/voter ordering. All
        // freshness, ownership, quorum/finality and absence checks above remain
        // mandatory; the signed observation below retains its original expiry.
        let evidence_digest = crate::production_xmr_inventory_v23::PublicInventoryEvidenceV24 {
            network_id: network,
            route_id: route,
            sessions,
            terms: terms_hashes,
            genesis,
            tx_hash: self.tx_hash(),
            raw_fingerprint: owned.funding().transaction().raw_fingerprint,
            output_index: owned.funding().output_index(),
            output_key: owned.output_key(),
            key_image: owned.key_image(),
            amount_piconero: self.amount_piconero(),
            fee_piconero: owned.funding().fee_piconero(),
            height: inclusion.height,
            block_hash: inclusion.block_hash,
        }
        .digest()?;
        let observed_at = now.checked_mul(1000).ok_or("XMR inventory clock overflow")?;
        let valid_until_seconds = now
            .checked_add(limits.max_evidence_age_seconds)
            .ok_or("XMR inventory expiry overflow")?
            .min(limits.expires_at_seconds)
            .min(decoded_evidence.expires_at_seconds());
        if valid_until_seconds <= now {
            return Err("XMR inventory observation already expired".into());
        }
        let observation = InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: rfq::ChainId(terms[0].counterparty_leg.chain_id.0),
                asset_id: rfq::AssetId(terms[0].counterparty_leg.asset_id.0),
                authority_id: solver,
            },
            spendable_amount: u128::from(self.amount_piconero()),
            canonical_height: inclusion.height,
            canonical_anchor_digest: inclusion.block_hash,
            evidence_digest,
            registry_manifest_digest: planning.resolved_registry().manifest_digest(),
            profile_bundle_digest: planning.admission().frozen_bindings().profile_bundle_digest,
            asset_binding_digest: planning.resolved_registry().asset_binding_digest(
                terms[0].counterparty_leg.chain_id,
                terms[0].counterparty_leg.asset_id,
            )?,
            observed_at_unix_ms: observed_at,
            valid_until_unix_ms: valid_until_seconds
                .checked_mul(1000)
                .ok_or("XMR inventory expiry clock overflow")?,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        };
        Ok(NativeF6XmrInventoryObservationV23 {
            observations: vec![observation],
        })
    }
}

impl NativeF6ProvisionV23 {
    pub(super) fn publish_observations_v23(
        &self,
        cold: &NativeXmrColdStartV23,
        plans: [&NativeDaemonPlanningContextV23; 2],
        resources: [&super::super::NativeXmrDaemonResourcesV23; 2],
        credentials: &NativeXmrDaemonCredentialsV23,
        time: &ColdStartSignedTimeV23,
        baseline: &super::super::xmr_graph_wallet_tests::native_observation_v23::NativeDomSnapshotV23,
        xmr: &NativeF6XmrInventoryObservationV23,
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
        let terms = plan.composition().upstream();
        let mut observations = vec![InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: rfq::ChainId(terms.dom_leg.chain_id.0),
                asset_id: rfq::AssetId(terms.dom_leg.asset_id.0),
                authority_id: solver,
            },
            spendable_amount: spendable,
            canonical_height: tip,
            canonical_anchor_digest: anchor,
            evidence_digest: digest(b"DOM/NATIVE-F6/WALLET-RPC-EVIDENCE/V23\0", &[&evidence])?,
            registry_manifest_digest: plan.resolved_registry().manifest_digest(),
            profile_bundle_digest: plan.admission().frozen_bindings().profile_bundle_digest,
            asset_binding_digest: plan
                .resolved_registry()
                .asset_binding_digest(terms.dom_leg.chain_id, terms.dom_leg.asset_id)?,
            observed_at_unix_ms: now.checked_mul(1000).ok_or("native observer clock")?,
            valid_until_unix_ms: until.checked_mul(1000).ok_or("native observer clock")?,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        }];
        // The closed XMR producer must cover every counterparty account. An
        // empty/mismatched observation never silently falls back to DOM only.
        for terms in [
            plan.composition().upstream(),
            plan.composition().downstream(),
        ] {
            if !xmr.observations.iter().any(|value| {
                value.key.authority_id == solver
                    && value.key.chain_id.0 == terms.counterparty_leg.chain_id.0
                    && value.key.asset_id.0 == terms.counterparty_leg.asset_id.0
                    && value.spendable_amount >= terms.counterparty_leg.amount
                    && value.registry_manifest_digest == plan.resolved_registry().manifest_digest()
                    && value.profile_bundle_digest
                        == plan.admission().frozen_bindings().profile_bundle_digest
                    && value.observed_at_unix_ms <= now * 1000
                    && value.valid_until_unix_ms > now * 1000
            }) {
                return Err("native observer XMR ownership/unspent evidence missing".into());
            }
        }
        observations.extend(xmr.observations.iter().copied());
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
            self.status_secrets.iter().enumerate().map(|(index, secret)| {
                Ok((index as u16, secp.sign_bip340(secret, &hash, &[0x62; 32])
                    .map_err(|_| crate::production_f6_lifecycle::ProductionF6ActivationRefusalV2::InvalidBinding)?.0))
            }).collect()
        })?;
        for actor in 0..2 {
            publish(cold.actor_work(actor)?, FILE_V23, &bytes)?;
        }
        Ok(())
    }
}
