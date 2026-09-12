//! Pre-F6 planning from the same registry and time authorities used at startup.
//!
//! This boundary computes public request pins, not an F6/funding permission.
//! It needs neither a daemon manifest nor Contracts, participant DLEQs or F6
//! artifacts. The operator supplies actual signed public inputs and dedicated
//! durable planning stores. No store is created, replaced or repaired here.
//! The daemon still independently authenticates all artifacts at startup and
//! revalidates current time at each economic boundary.

use super::*;
use deployment_registry::SignedRegistryV1;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionPreF6PlanningErrorV23 {
    #[error("pre-F6 public planning scope is inconsistent")]
    Input,
    #[error("pre-F6 signed registry or retained registry is not current")]
    Registry,
    #[error("pre-F6 signed route-time ladder is not current")]
    Time,
    #[error("pre-F6 settlement composition is inconsistent")]
    Composition,
    #[error("pre-F6 registry route admission was refused")]
    Admission,
}

type Result<T> = std::result::Result<T, ProductionPreF6PlanningErrorV23>;

/// Borrowed public artifacts only; digests are deliberately not inputs.
pub(crate) struct ProductionPreF6PlanningInputsV23<'a> {
    pub signed_registry: &'a SignedRegistryV1,
    pub authorities: &'a ProductionAuthorityBundleV1,
    pub terms: [&'a SettlementTermsV1; 2],
    pub signed_policy: &'a SignedRouteTimePolicyV2,
    pub signed_evidence: &'a SignedRouteTimeEvidenceV2,
    pub rosters: &'a ProductionRelayRosterBundleV1,
    pub route_id: RouteIdV1,
    pub network_id: Digest32,
    pub minimum_registry_epoch: u64,
    pub now_seconds: u64,
}

impl ProductionPreF6PlanningInputsV23<'_> {
    fn verified_registry(&self, secp: &SecpContext) -> Result<ResolvedRegistryV1> {
        if self.now_seconds == 0
            || self.route_id == [0; 32]
            || self.network_id == [0; 32]
            || self.rosters.network_id() != self.network_id
            || self.rosters.route_id() != self.route_id
        {
            return Err(ProductionPreF6PlanningErrorV23::Input);
        }
        self.rosters
            .validate_shape()
            .map_err(|_| ProductionPreF6PlanningErrorV23::Input)?;
        validate_roster_terms(self.rosters, self.terms[0], self.terms[1], secp)
            .map_err(|_| ProductionPreF6PlanningErrorV23::Input)?;
        self.signed_registry
            .verify(self.authorities.registry(), secp, self.registry_policy())
            .map_err(|_| ProductionPreF6PlanningErrorV23::Registry)
    }

    fn registry_policy(&self) -> RegistryValidationPolicyV1 {
        RegistryValidationPolicyV1 {
            now_seconds: self.now_seconds,
            expected_network_id: self.network_id,
            minimum_epoch: self.minimum_registry_epoch,
        }
    }

    /// Derives the exact configuration for a dedicated planning time store.
    /// The caller owns safe create/reopen and crash handling for that store.
    pub(crate) fn time_store_config(
        &self,
        secp: &SecpContext,
    ) -> Result<RouteTimeAnchorStoreConfigV2> {
        let registry = self.verified_registry(secp)?;
        RouteTimeAnchorStoreConfigV2::new(
            &registry,
            self.terms[0],
            self.terms[1],
            self.authorities.time_policy(),
            self.authorities.time_evidence(),
            secp,
        )
        .map_err(|_| ProductionPreF6PlanningErrorV23::Time)
    }
}

/// Read-only public pins for the F6 signing request's `route` object.
/// Serialization is not an authority codec: these bytes grant no permission,
/// and the F6 artifact consumer must still authenticate the signed artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ProductionPreF6RoutePinsV23 {
    network_id: Digest32,
    route_id: RouteIdV1,
    composition_digest: Digest32,
    route_scope_digest: Digest32,
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_bundle_digest: Digest32,
}

/// Authenticated planning checkpoint; not AuthenticatedProductionInputsV1.
/// Private construction preserves the origin of both otherwise opaque pins.
pub(crate) struct ProductionPreF6PlanningContextV23 {
    admission: AuthenticatedRouteAdmissionV1,
    composition: ComposedBindingV2,
    registry: ResolvedRegistryV1,
}

impl ProductionPreF6PlanningContextV23 {
    /// Consumes the real registry owner and a fresh capability from the real
    /// time store. Retained rollback/expiry rules remain in those authorities.
    pub(crate) fn prepare(
        mut registry_store: RegistryStoreV1,
        time_store: &mut DurableRouteTimeAnchorStoreV2,
        input: &ProductionPreF6PlanningInputsV23<'_>,
        secp: &SecpContext,
    ) -> Result<Self> {
        let signed_registry = input.verified_registry(secp)?;
        registry_store
            .install(
                input.signed_registry,
                input.authorities.registry(),
                secp,
                input.registry_policy(),
            )
            .map_err(|_| ProductionPreF6PlanningErrorV23::Registry)?;
        let registry = registry_store
            .load_current(input.authorities.registry(), secp, input.registry_policy())
            .map_err(|_| ProductionPreF6PlanningErrorV23::Registry)?
            .ok_or(ProductionPreF6PlanningErrorV23::Registry)?;
        if registry.manifest_digest() != signed_registry.manifest_digest()
            || registry.epoch() != signed_registry.epoch()
        {
            return Err(ProductionPreF6PlanningErrorV23::Registry);
        }
        let [upstream, downstream] = input.terms;
        let policy_context = RouteTimePolicyVerificationContextV2::new(
            input.authorities.time_policy(),
            secp,
            &registry,
            upstream,
            downstream,
        );
        let evidence_context = RouteTimeEvidenceVerificationContextV2::new(
            policy_context,
            input.authorities.time_evidence(),
        );
        // Match the production create loader exactly: the signed evidence
        // observation freezes composition identity, not this process's start
        // time. Current freshness is checked separately below, never extended.
        let original_validation_seconds =
            RouteTimeEvidenceV2::decode(input.signed_evidence.evidence_bytes())
                .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?
                .observed_at_seconds();
        if original_validation_seconds > input.now_seconds {
            return Err(ProductionPreF6PlanningErrorV23::Time);
        }
        time_store
            .install_policy(
                input.signed_policy,
                policy_context,
                original_validation_seconds,
            )
            .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        time_store
            .install_evidence(
                input.signed_evidence,
                evidence_context,
                original_validation_seconds,
            )
            .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        let proof = time_store
            .prove_route_ladder(evidence_context, original_validation_seconds)
            .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        let proof = time_store
            .consume_capability_at(proof, original_validation_seconds)
            .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        let composition = ComposedBindingV2::bind(upstream.clone(), downstream.clone(), proof)
            .map_err(|_| ProductionPreF6PlanningErrorV23::Composition)?;
        let authority = RegistryRouteAdmissionAuthorityV1::new(
            registry_store,
            input.authorities.registry().clone(),
            SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1),
            input.network_id,
            input.minimum_registry_epoch,
        )
        .map_err(|_| ProductionPreF6PlanningErrorV23::Admission)?;
        let admission = authority
            .admit_validated_composed_route_v2(
                input.now_seconds,
                input.route_id,
                &composition,
                input.rosters.snapshots(),
            )
            .map_err(|_| ProductionPreF6PlanningErrorV23::Admission)?;
        let context = Self {
            admission,
            composition,
            registry,
        };
        context.require_current(time_store, input, input.now_seconds, secp)?;
        Ok(context)
    }

    /// Rechecks freshness immediately before publishing a public planning
    /// result without changing the original composition or granting funding.
    pub(crate) fn require_current(
        &self,
        time_store: &mut DurableRouteTimeAnchorStoreV2,
        input: &ProductionPreF6PlanningInputsV23<'_>,
        now_seconds: u64,
        secp: &SecpContext,
    ) -> Result<()> {
        if now_seconds < input.now_seconds {
            return Err(ProductionPreF6PlanningErrorV23::Time);
        }
        self.registry
            .manifest()
            .validate_policy(RegistryValidationPolicyV1 {
                now_seconds,
                ..input.registry_policy()
            })
            .map_err(|_| ProductionPreF6PlanningErrorV23::Registry)?;
        let checkpoint = FrozenRouteTimeCheckpointV2::new(
            self.composition.route_scope_digest(),
            self.composition.time_policy_digest(),
            self.composition.time_evidence_digest(),
            self.composition.evidence_sequence(),
        )
        .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        let evidence_context = RouteTimeEvidenceVerificationContextV2::new(
            RouteTimePolicyVerificationContextV2::new(
                input.authorities.time_policy(),
                secp,
                &self.registry,
                self.composition.upstream(),
                self.composition.downstream(),
            ),
            input.authorities.time_evidence(),
        );
        let _current = time_store
            .prove_current_route_ladder_from_checkpoint(checkpoint, evidence_context, now_seconds)
            .map_err(|_| ProductionPreF6PlanningErrorV23::Time)?;
        Ok(())
    }

    pub(crate) fn route_pins(&self) -> ProductionPreF6RoutePinsV23 {
        ProductionPreF6RoutePinsV23 {
            network_id: self.registry.manifest().network_id,
            route_id: self.admission.route_id(),
            composition_digest: self.composition.binding_digest(),
            route_scope_digest: self.composition.route_scope_digest(),
            registry_digest: self.registry.manifest_digest(),
            registry_epoch: self.registry.epoch(),
            profile_bundle_digest: self.admission.frozen_bindings().profile_bundle_digest,
        }
    }

    /// Continue native participant/Contracts verification without reminting or
    /// replacing this planning admission with caller-provided commitments.
    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthenticatedRouteAdmissionV1,
        ComposedBindingV2,
        ResolvedRegistryV1,
    ) {
        (self.admission, self.composition, self.registry)
    }
}
