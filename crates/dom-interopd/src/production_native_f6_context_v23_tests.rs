//! Public encoder context, sealed to the two genuinely admitted test owners.
use super::*;
use crate::admission::AuthenticatedRouteAdmissionV1;
use crate::production_inputs::{
    native_daemon_planning_v23::NativeDaemonPlanningContextV23, ProductionRelayRosterBundleV1,
};

mod seal {
    pub trait Sealed {}
}
pub(crate) trait NativeF6ContextV23: seal::Sealed {
    fn admission(&self) -> &AuthenticatedRouteAdmissionV1;
    fn composition(&self) -> &ComposedBindingV2;
    fn resolved_registry(&self) -> &ResolvedRegistryV1;
    fn registry_authorities(&self) -> &AuthoritySetV1;
    fn time_policy_authorities(&self) -> &AuthoritySetV1;
    fn time_evidence_authorities(&self) -> &AuthoritySetV1;
    fn roster_bundle(&self) -> &ProductionRelayRosterBundleV1;
    fn verification_context(&self) -> &SecpContext;
}

macro_rules! getters {
    ($ty:ty) => {
        fn admission(&self) -> &AuthenticatedRouteAdmissionV1 {
            <$ty>::admission(self)
        }
        fn composition(&self) -> &ComposedBindingV2 {
            <$ty>::composition(self)
        }
        fn resolved_registry(&self) -> &ResolvedRegistryV1 {
            <$ty>::resolved_registry(self)
        }
        fn registry_authorities(&self) -> &AuthoritySetV1 {
            <$ty>::registry_authorities(self)
        }
        fn time_policy_authorities(&self) -> &AuthoritySetV1 {
            <$ty>::time_policy_authorities(self)
        }
        fn time_evidence_authorities(&self) -> &AuthoritySetV1 {
            <$ty>::time_evidence_authorities(self)
        }
        fn roster_bundle(&self) -> &ProductionRelayRosterBundleV1 {
            <$ty>::roster_bundle(self)
        }
    };
}
impl seal::Sealed for AuthenticatedProductionInputsV1 {}
impl NativeF6ContextV23 for AuthenticatedProductionInputsV1 {
    getters!(AuthenticatedProductionInputsV1);
    fn verification_context(&self) -> &SecpContext {
        self.time_verification_context()
    }
}
impl seal::Sealed for NativeDaemonPlanningContextV23 {}
impl NativeF6ContextV23 for NativeDaemonPlanningContextV23 {
    getters!(NativeDaemonPlanningContextV23);
    fn verification_context(&self) -> &SecpContext {
        NativeDaemonPlanningContextV23::verification_context(self)
    }
}

pub(super) fn validate_input(
    context: &impl NativeF6ContextV23,
    input: &NativeF6BundleInputsV23,
) -> Result<()> {
    let secp = context.verification_context();
    if [
        input.solver.0,
        input.inventory_binding_digest,
        input.bond_policy_hash,
        input.bond_asset_binding_digest,
    ]
    .contains(&ZERO_DIGEST)
        || input.required_collateral == 0
        || input.status_max_lifetime_seconds == 0
        || input.pre_f6_limits.valid_from_seconds >= input.pre_f6_limits.expires_at_seconds
        || input.pre_f6_limits.max_evidence_age_seconds == 0
        || input.bond_authorities.threshold() < 2
        || input.status_authorities.threshold() < 2
    {
        return Err("native F6 planning economic or route binding".into());
    }
    match &input.claim_profile {
        NativeF6ClaimInputsV23::Bound { role_plan, sources } => {
            if role_plan.route_id() != context.admission().route_id()
                || role_plan.route_scope_digest() != context.composition().route_scope_digest()
                || role_plan.composition_binding_digest() != context.composition().binding_digest()
            {
                return Err("native F6 role route mismatch".into());
            }
            role_plan.authenticate(
                context.composition().upstream(),
                context.composition().downstream(),
                sources[0].clone(),
                sources[1].clone(),
            )?;
        }
        NativeF6ClaimInputsV23::SolanaEnrollment => {
            claim_enrollment_v23::SolClaimEnrollmentV25::from_composition(context.composition())?;
        }
        NativeF6ClaimInputsV23::NativeEnrollment => {
            claim_enrollment_v23::NativeClaimEnrollmentV23::from_composition(
                context.composition(),
            )?;
        }
    }
    bond_reservation_authority_set_digest_v2(&input.bond_authorities, secp)?;
    candidate_status_authority_set_digest_v2(&input.status_authorities, secp)?;
    let relay: Vec<_> = context
        .roster_bundle()
        .legs()
        .iter()
        .flat_map(|leg| leg.members.iter().map(|member| member.xonly_key))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let chain: Vec<_> = context
        .registry_authorities()
        .xonly_keys()
        .iter()
        .chain(context.time_policy_authorities().xonly_keys())
        .chain(context.time_evidence_authorities().xonly_keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let original_count = context.registry_authorities().xonly_keys().len()
        + context.time_policy_authorities().xonly_keys().len()
        + context.time_evidence_authorities().xonly_keys().len();
    if chain.len() != original_count {
        return Err("native F6 overlapping root authority roles".into());
    }
    ProductionF6ReservedSignerKeysV2::new(
        relay.clone(),
        input.reserved_participant_keys.clone(),
        chain.clone(),
    )?;
    let reserved: BTreeSet<_> = relay
        .into_iter()
        .chain(chain)
        .chain(input.reserved_participant_keys.iter().copied())
        .collect();
    let bond: BTreeSet<_> = input
        .bond_authorities
        .xonly_keys()
        .iter()
        .copied()
        .collect();
    if input
        .status_authorities
        .xonly_keys()
        .iter()
        .any(|key| bond.contains(key))
        || input
            .bond_authorities
            .xonly_keys()
            .iter()
            .chain(input.status_authorities.xonly_keys())
            .any(|key| reserved.contains(key))
    {
        return Err("native F6 signer independence".into());
    }
    for descriptors in &input.signers {
        let descriptors = descriptors
            .iter()
            .map(|signer| ProductionF6BondSignerDescriptorV7 {
                independent_authority_id: signer.independent_authority_id,
                signer_index: signer.signer_index,
                signer_public_key: signer.signer_public_key,
                endpoint_uid: signer.endpoint_uid,
                endpoint: signer.endpoint.clone(),
            })
            .collect::<Vec<_>>();
        validate_signer_descriptors(&input.bond_authorities, &descriptors)?;
        for signer in descriptors {
            let text = signer.endpoint.to_str().ok_or("native F6 endpoint text")?;
            if !signer.endpoint.is_absolute()
                || !lexically_normal(&signer.endpoint)
                || text
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
            {
                return Err("native F6 endpoint scope".into());
            }
        }
    }
    Ok(())
}
