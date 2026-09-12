//! Common V6 configuration pins derived from the native planning checkpoint.
//! Process/store identities are supplied by their actual scenario owners;
//! none of the registry/time/terms/roster/participant digests is caller-chosen.
use super::*;
use crate::production_config::{
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionFamilyInputsV6,
    ProductionRoutePinsV1, ProductionRuntimeBoundsV1,
};

pub(crate) struct NativeDaemonOwnerPinsV23 {
    pub process_owner_id: Digest32,
    pub coordinator_id: Digest32,
    pub coordinator_plan_authority_id: Digest32,
    pub actuator_bindings_digest: Digest32,
    pub solver_inventory_binding_digest: Digest32,
}

impl NativeDaemonPlanningContextV23 {
    pub(crate) fn common_v6(
        &self,
        mode: ProductionBootstrapModeV1,
        bounds: ProductionRuntimeBoundsV1,
        family: ProductionFamilyInputsV6,
        owners: &NativeDaemonOwnerPinsV23,
    ) -> Result<ProductionBootstrapConfigV1> {
        let policy = RouteTimePolicyV2::decode(self.signed_policy.policy_bytes())?;
        let evidence = RouteTimeEvidenceV2::decode(self.signed_evidence.evidence_bytes())?;
        let pins = ProductionRoutePinsV1 {
            network_id: self.rosters.network_id(),
            route_id: self.admission.route_id(),
            registry_manifest_digest: self.registry.manifest_digest(),
            registry_minimum_epoch: self.registry.epoch(),
            registry_authority_set_digest: self.authorities.registry.authority_set_digest()?,
            time_policy_authority_set_digest: self.policy_authority_digest,
            time_evidence_authority_set_digest: self.evidence_authority_digest,
            upstream_terms_digest: self.composition.upstream().terms_hash()?,
            downstream_terms_digest: self.composition.downstream().terms_hash()?,
            route_scope_digest: self.composition.route_scope_digest(),
            participant_bindings_digest: self.participants.bundle_digest()?,
            relay_binding_digest: self.rosters.bundle_digest()?,
            time_policy_digest: policy.policy_digest()?,
            time_evidence_digest: evidence.evidence_digest()?,
            process_owner_id: owners.process_owner_id,
            coordinator_id: owners.coordinator_id,
            coordinator_plan_authority_id: owners.coordinator_plan_authority_id,
            actuator_bindings_digest: owners.actuator_bindings_digest,
            solver_inventory_binding_digest: owners.solver_inventory_binding_digest,
        };
        Ok(ProductionBootstrapConfigV1::from_parts_v6(
            mode,
            pins,
            bounds,
            self.paths.clone(),
            family,
        )?)
    }
}
