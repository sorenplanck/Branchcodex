//! Threshold-authenticated inventory/status ingestion after bilateral RFQ.
//! A feed is evidence, never a reservation or a manufactured lease. Only the
//! native enrollment profile consumes this additional owner-scoped artifact.
use super::*;
use solver_inventory::{
    InventoryKeyV1, InventoryObservationKindV1, InventoryObservationV1, InventorySnapshotV1,
    InventoryStoreErrorV1,
};
use solver_status::SignedSolverStatusV1;

pub(crate) const FILE_V23: &str = "native-f6-observations-v23.bin";
const MAGIC: &[u8; 8] = b"DOMF6OV3";
const DOMAIN: &[u8] = b"DOM-INTEROP/F6/OBSERVATIONS/V23\0";
const MAX_BYTES: u64 = 65_536;

pub(crate) struct NativeF6ObservationBodyV23 {
    pub network: Digest32,
    pub composition: Digest32,
    pub inventory_binding: Digest32,
    pub observations: Vec<InventoryObservationV1>,
    pub statuses: [SignedSolverStatusV1; 2],
}

fn inventory_prefix(
    network: Digest32,
    composition: Digest32,
    inventory_binding: Digest32,
    observations: &[InventoryObservationV1],
) -> Result<Vec<u8>, ProductionF6ActivationRefusalV2> {
    if observations.is_empty() || observations.len() > 8 {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&23_u16.to_be_bytes());
    bytes.extend_from_slice(&(observations.len() as u16).to_be_bytes());
    for digest in [network, composition, inventory_binding] {
        bytes.extend_from_slice(&digest);
    }
    let mut previous = None;
    for value in observations {
        if previous.is_some_and(|key| key >= value.key) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        previous = Some(value.key);
        for digest in [
            value.key.chain_id.0,
            value.key.asset_id.0,
            value.key.authority_id.0,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&value.spendable_amount.to_be_bytes());
        bytes.extend_from_slice(&value.canonical_height.to_be_bytes());
        for digest in [
            value.canonical_anchor_digest,
            value.evidence_digest,
            value.registry_manifest_digest,
            value.profile_bundle_digest,
            value.asset_binding_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        for integer in [
            value.observed_at_unix_ms,
            value.valid_until_unix_ms,
            value.acknowledged_consumption_sequence,
        ] {
            bytes.extend_from_slice(&integer.to_be_bytes());
        }
        match value.kind {
            InventoryObservationKindV1::Forward => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 40]);
            }
            InventoryObservationKindV1::Reorg {
                invalidated_from_height,
                reorg_evidence_digest,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&invalidated_from_height.to_be_bytes());
                bytes.extend_from_slice(&reorg_evidence_digest);
            }
        }
    }
    Ok(bytes)
}

pub(crate) fn inventory_evidence_digest_v23(
    network: Digest32,
    composition: Digest32,
    inventory_binding: Digest32,
    observations: &[InventoryObservationV1],
) -> Result<Digest32, ProductionF6ActivationRefusalV2> {
    digest_parts(&[
        DOMAIN,
        &inventory_prefix(network, composition, inventory_binding, observations)?,
    ])
}

fn retained_snapshot_matches_v23(
    retained: &InventorySnapshotV1,
    observation: &InventoryObservationV1,
) -> bool {
    retained.key == observation.key
        && retained.spendable_amount == observation.spendable_amount
        && retained.canonical_height == observation.canonical_height
        && retained.canonical_anchor_digest == observation.canonical_anchor_digest
        && retained.evidence_digest == observation.evidence_digest
        && retained.registry_manifest_digest == observation.registry_manifest_digest
        && retained.profile_bundle_digest == observation.profile_bundle_digest
        && retained.asset_binding_digest == observation.asset_binding_digest
        && retained.observed_at_unix_ms == observation.observed_at_unix_ms
        && retained.valid_until_unix_ms == observation.valid_until_unix_ms
        && retained.acknowledged_consumption_sequence
            == observation.acknowledged_consumption_sequence
}

impl NativeF6ObservationBodyV23 {
    pub(crate) fn inventory_evidence_digest(
        &self,
    ) -> Result<Digest32, ProductionF6ActivationRefusalV2> {
        digest_parts(&[DOMAIN, &self.inventory_prefix()?])
    }

    fn inventory_prefix(&self) -> Result<Vec<u8>, ProductionF6ActivationRefusalV2> {
        inventory_prefix(
            self.network,
            self.composition,
            self.inventory_binding,
            &self.observations,
        )
    }

    pub(crate) fn encode(
        &self,
        sign: impl FnOnce(Digest32) -> Result<Vec<(u16, [u8; 64])>, ProductionF6ActivationRefusalV2>,
    ) -> Result<Vec<u8>, ProductionF6ActivationRefusalV2> {
        let mut bytes = self.inventory_prefix()?;
        let evidence = self.inventory_evidence_digest()?;
        for signed in &self.statuses {
            if signed
                .statement()
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?
                .source_evidence_digest()
                != evidence
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            let status = signed
                .canonical_bytes()
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            if status.len() > 4096 {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            bytes.extend_from_slice(&(status.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&status);
        }
        let signatures = sign(digest_parts(&[DOMAIN, &bytes])?)?;
        if signatures.len() < 2 || signatures.len() > 16 {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        bytes.extend_from_slice(&(signatures.len() as u16).to_be_bytes());
        let mut previous = None;
        for (index, signature) in signatures {
            if previous.is_some_and(|old| old >= index) {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            previous = Some(index);
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(&signature);
        }
        Ok(bytes)
    }
}

fn decode(
    bytes: &[u8],
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<NativeF6ObservationBodyV23, ProductionF6ActivationRefusalV2> {
    let mut reader = BundleReaderV7::new(bytes);
    if reader.take::<8>()? != *MAGIC || reader.u16()? != 23 {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let count = reader.u16()?;
    if !(1..=8).contains(&count) {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let network = reader.take()?;
    let composition = reader.take()?;
    let inventory_binding = reader.take()?;
    let mut observations = Vec::new();
    for _ in 0..count {
        let key = InventoryKeyV1 {
            chain_id: rfq::ChainId(reader.take()?),
            asset_id: rfq::AssetId(reader.take()?),
            authority_id: ParticipantId(reader.take()?),
        };
        let spendable_amount = reader.u128()?;
        let canonical_height = reader.u64()?;
        let canonical_anchor_digest = reader.take()?;
        let evidence_digest = reader.take()?;
        let registry_manifest_digest = reader.take()?;
        let profile_bundle_digest = reader.take()?;
        let asset_binding_digest = reader.take()?;
        let observed_at_unix_ms = reader.u64()?;
        let valid_until_unix_ms = reader.u64()?;
        let acknowledged_consumption_sequence = reader.u64()?;
        let tag = reader.take::<1>()?[0];
        let invalidated_from_height = reader.u64()?;
        let reorg_evidence_digest = reader.take()?;
        let kind = match tag {
            0 if invalidated_from_height == 0 && reorg_evidence_digest == [0; 32] => {
                InventoryObservationKindV1::Forward
            }
            1 if invalidated_from_height != 0 && reorg_evidence_digest != [0; 32] => {
                InventoryObservationKindV1::Reorg {
                    invalidated_from_height,
                    reorg_evidence_digest,
                }
            }
            _ => return Err(ProductionF6ActivationRefusalV2::InvalidBinding),
        };
        observations.push(InventoryObservationV1 {
            key,
            spendable_amount,
            canonical_height,
            canonical_anchor_digest,
            evidence_digest,
            registry_manifest_digest,
            profile_bundle_digest,
            asset_binding_digest,
            observed_at_unix_ms,
            valid_until_unix_ms,
            acknowledged_consumption_sequence,
            kind,
        });
    }
    let inventory_end = reader.position();
    let statuses = [
        SignedSolverStatusV1::decode(reader.length_prefixed(4096)?)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
        SignedSolverStatusV1::decode(reader.length_prefixed(4096)?)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
    ];
    let end = reader.position();
    let count = reader.u16()?;
    if authorities.threshold() < 2
        || count < authorities.threshold()
        || usize::from(count) > authorities.xonly_keys().len()
    {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let digest = digest_parts(&[DOMAIN, &bytes[..end]])?;
    let mut previous = None;
    for _ in 0..count {
        let index = reader.u16()?;
        if previous.is_some_and(|old| old >= index) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        previous = Some(index);
        let key = authorities
            .xonly_keys()
            .get(usize::from(index))
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        secp.verify_bip340(key, &digest, &reader.take::<64>()?)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    }
    reader.finish()?;
    let body = NativeF6ObservationBodyV23 {
        network,
        composition,
        inventory_binding,
        observations,
        statuses,
    };
    if body.inventory_prefix()? != bytes[..inventory_end] {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let evidence = body.inventory_evidence_digest()?;
    if body.statuses.iter().any(|status| {
        status
            .statement()
            .map(|statement| statement.source_evidence_digest() != evidence)
            .unwrap_or(true)
    }) {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    Ok(body)
}

impl ProductionF6PairAuthoritiesFactoryV7 {
    /// Pure preflight before the inventory lease (the first durable economic
    /// effect). The move-only live XMR proof must match exactly one signed
    /// observation and is consumed here, so it cannot authorize another bind.
    pub(super) fn preflight_native_observations_v23(
        &mut self,
        secp: &SecpContext,
    ) -> Result<Option<NativeF6ObservationBodyV23>, ProductionF6ActivationRefusalV2> {
        if !matches!(
            &self.bundle.claim_profile,
            ClaimPlanProfileV23::Enrollment(_)
        ) {
            if self.native_xmr_inventory_required || self.native_xmr_inventory.is_some() {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
            return Ok(None);
        }
        let bytes = crate::production_config::read_owner_file_bounded(
            &self.paths.state_root.join(FILE_V23),
            MAX_BYTES,
            crate::production_config::ProductionConfigErrorV1::InvalidPublicBinding,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let body = decode(&bytes, &self.bundle.status_authorities, secp)?;
        if body.network != self.route.network_id
            || body.composition != self.route.composition_digest
            || body.inventory_binding != self.bundle.inventory_binding_digest
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        if self.native_xmr_inventory_required {
            let native_xmr_inventory = self
                .native_xmr_inventory
                .take()
                .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
            if body
                .observations
                .iter()
                .filter(|observation| native_xmr_inventory.matches(observation))
                .count()
                != 1
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        } else if self.native_xmr_inventory.is_some() {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        Ok(Some(body))
    }

    pub(super) fn ingest_native_observations_v23(
        &mut self,
        body: Option<NativeF6ObservationBodyV23>,
        lease: InventoryLeaseV1,
        upstream: &mut DurableSolverStatusStoreV1,
        downstream: &mut DurableSolverStatusStoreV1,
        secp: &SecpContext,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        let Some(body) = body else {
            return Ok(());
        };
        let historical = self.historical_recovery_v24.is_some();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?
            .as_secs();
        let now_ms = now
            .checked_mul(1000)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        if lease.authority_id != self.bundle.solver
            || lease.owner_id != self.inventory_owner_id
            || lease.lease_until_unix_ms <= now_ms
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        for observation in &body.observations {
            let expected_asset = self
                .route
                .registry
                .asset_binding_digest(
                    kaystra_core::types::ChainId(observation.key.chain_id.0),
                    kaystra_core::types::AssetId(observation.key.asset_id.0),
                )
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            let route_asset = [self.composition.upstream(), self.composition.downstream()]
                .iter()
                .any(|terms| {
                    [terms.dom_leg, terms.counterparty_leg].iter().any(|leg| {
                        leg.chain_id.0 == observation.key.chain_id.0
                            && leg.asset_id.0 == observation.key.asset_id.0
                    })
                });
            if !route_asset
                || observation.key.authority_id != self.bundle.solver
                || observation.registry_manifest_digest != self.bundle.registry_digest
                || observation.profile_bundle_digest != self.bundle.profile_bundle_digest
                || observation.asset_binding_digest != expected_asset
                || (!historical
                    && (observation.observed_at_unix_ms > now_ms
                        || observation.valid_until_unix_ms <= now_ms))
                || observation
                    .valid_until_unix_ms
                    .saturating_sub(observation.observed_at_unix_ms)
                    > self
                        .bundle
                        .pre_f6_limits
                        .max_evidence_age_seconds
                        .saturating_mul(1000)
                || observation.valid_until_unix_ms
                    > self
                        .bundle
                        .pre_f6_limits
                        .expires_at_seconds
                        .saturating_mul(1000)
                || (!historical
                    && now_ms.saturating_sub(observation.observed_at_unix_ms)
                        > self
                            .bundle
                            .pre_f6_limits
                            .max_evidence_age_seconds
                            .saturating_mul(1000))
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        }
        if historical {
            // The original threshold-authenticated observations must already
            // occur in each independent, fully audited status history. Neither
            // wall clock nor inventory snapshot is rewritten on this branch.
            upstream
                .authenticate_retained_signed_v24(&body.statuses[0], secp)
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            downstream
                .authenticate_retained_signed_v24(&body.statuses[1], secp)
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            return Ok(());
        }
        // Install authenticated status only; no boolean Active capability is
        // reconstructed. Each owner performs its own scope/epoch/freshness audit.
        upstream
            .install(&body.statuses[0], secp, now)
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        downstream
            .install(&body.statuses[1], secp, now)
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let inventory = self
            .inventory
            .as_mut()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        for observation in &body.observations {
            let revision = match inventory.load_snapshot(observation.key) {
                Ok(snapshot) => snapshot.revision,
                Err(InventoryStoreErrorV1::SnapshotNotFound) => 0,
                Err(_) => return Err(ProductionF6ActivationRefusalV2::Unavailable),
            };
            let operation = digest_parts(&[
                DOMAIN,
                &body.inventory_evidence_digest()?,
                &observation.key.chain_id.0,
                &observation.key.asset_id.0,
                &revision.to_be_bytes(),
            ])?;
            inventory
                .reconcile_snapshot(lease, revision, operation, observation, now_ms)
                .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
            let retained = inventory
                .load_snapshot(observation.key)
                .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
            if !retained_snapshot_matches_v23(&retained, observation) {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod v23_regressions {
    use super::*;

    fn observation() -> InventoryObservationV1 {
        InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: rfq::ChainId([1; 32]),
                asset_id: rfq::AssetId([2; 32]),
                authority_id: rfq::ParticipantId([3; 32]),
            },
            spendable_amount: 4,
            canonical_height: 5,
            canonical_anchor_digest: [6; 32],
            evidence_digest: [7; 32],
            registry_manifest_digest: [8; 32],
            profile_bundle_digest: [9; 32],
            asset_binding_digest: [10; 32],
            observed_at_unix_ms: 11,
            valid_until_unix_ms: 12,
            acknowledged_consumption_sequence: 13,
            kind: InventoryObservationKindV1::Forward,
        }
    }

    #[test]
    fn divergent_post_reconcile_readback_is_refused() {
        let observation = observation();
        let mut retained = InventorySnapshotV1 {
            key: observation.key,
            revision: 1,
            spendable_amount: observation.spendable_amount,
            encumbered_amount: 0,
            deficit_amount: 0,
            canonical_height: observation.canonical_height,
            canonical_anchor_digest: observation.canonical_anchor_digest,
            evidence_digest: observation.evidence_digest,
            registry_manifest_digest: observation.registry_manifest_digest,
            profile_bundle_digest: observation.profile_bundle_digest,
            asset_binding_digest: observation.asset_binding_digest,
            observed_at_unix_ms: observation.observed_at_unix_ms,
            valid_until_unix_ms: observation.valid_until_unix_ms,
            issued_consumption_sequence: observation.acknowledged_consumption_sequence,
            acknowledged_consumption_sequence: observation.acknowledged_consumption_sequence,
        };
        assert!(retained_snapshot_matches_v23(&retained, &observation));
        retained.evidence_digest[0] ^= 1;
        assert!(!retained_snapshot_matches_v23(&retained, &observation));
    }
}
