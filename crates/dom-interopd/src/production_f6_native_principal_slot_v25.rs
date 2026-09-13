//! Deferred, move-only native terms ownership. Waiting never manufactures an
//! authority or consumes a factory. Only an authenticated principal can fill it.
use super::*;
use crate::production_f6::terms::ProductionNativeXmrDomFaceOwnerV25;
use crate::production_noise_relay::ProductionAuthenticatedXmrClaimPrincipalV25;
use std::cell::RefCell;

pub(crate) enum ProductionF6DomTermsOwnerV25 {
    Wallet(AuthenticatedDomPayoutFaceV1),
    NativeXmr(ProductionNativePrincipalReceiverV25),
}

impl ProductionF6DomTermsOwnerV25 {
    pub(crate) fn wallet(&self) -> Option<&AuthenticatedDomPayoutFaceV1> {
        match self {
            Self::Wallet(owner) => Some(owner),
            Self::NativeXmr(_) => None,
        }
    }

    pub(super) fn ready(&self) -> Result<bool, ProductionF6ActivationRefusalV2> {
        match self {
            Self::Wallet(_) => Ok(true),
            Self::NativeXmr(receiver) => receiver
                .state
                .try_borrow()
                .map(|state| state.owner.is_some())
                .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable),
        }
    }

    pub(super) fn into_face(
        self,
        binding: &ProductionSolverF6BindingV2,
        settlement: &kaystra_core::SettlementTermsV1,
        composition: &ComposedBindingV2,
        deployment: deployment_registry::ResolvedDomDeploymentV1,
    ) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ActivationRefusalV2> {
        match self {
            Self::Wallet(owner) => AdapterAuthenticatedRefundFaceV2::from_dom(
                owner,
                binding,
                settlement,
                composition,
                deployment,
            )
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding),
            Self::NativeXmr(receiver) => {
                let owner = receiver
                    .state
                    .try_borrow_mut()
                    .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?
                    .owner
                    .take()
                    .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
                owner
                    .into_face(binding, settlement, composition, deployment)
                    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
            }
        }
    }
}

struct PrincipalSlotV25<T> {
    canonical: Option<Vec<u8>>,
    owner: Option<T>,
}

impl<T> PrincipalSlotV25<T> {
    fn publish(
        &mut self,
        canonical: Vec<u8>,
        owner: T,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        if let Some(old) = &self.canonical {
            // Exact retransmission remains idempotent even after consumption.
            // It never replenishes a consumed signing/terms owner.
            return if old == &canonical {
                Ok(())
            } else {
                Err(ProductionF6ActivationRefusalV2::InvalidBinding)
            };
        }
        self.canonical = Some(canonical);
        self.owner = Some(owner);
        Ok(())
    }
}

pub(crate) struct ProductionNativePrincipalPublisherV25 {
    route_id: Digest32,
    terms: kaystra_core::SettlementTermsV1,
    policy: xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    state: Rc<RefCell<PrincipalSlotV25<ProductionNativeXmrDomFaceOwnerV25>>>,
}

pub(crate) struct ProductionNativePrincipalReceiverV25 {
    state: Rc<RefCell<PrincipalSlotV25<ProductionNativeXmrDomFaceOwnerV25>>>,
}

impl ProductionNativePrincipalPublisherV25 {
    pub(crate) fn new(
        route_id: Digest32,
        terms: kaystra_core::SettlementTermsV1,
        policy: xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    ) -> (Self, ProductionF6DomTermsOwnerV25) {
        let state = Rc::new(RefCell::new(PrincipalSlotV25 {
            canonical: None,
            owner: None,
        }));
        let receiver = ProductionNativePrincipalReceiverV25 {
            state: Rc::clone(&state),
        };
        (
            Self {
                route_id,
                terms,
                policy,
                state,
            },
            ProductionF6DomTermsOwnerV25::NativeXmr(receiver),
        )
    }

    pub(crate) fn publish(
        &self,
        principal: ProductionAuthenticatedXmrClaimPrincipalV25,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        if principal.route_id() != self.route_id
            || principal.terms() != &self.terms
            || principal.policy().policy() != self.policy.policy()
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let canonical = principal
            .offer()
            .to_bytes()
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let owner = ProductionNativeXmrDomFaceOwnerV25::from_authenticated_principal_v25(principal)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        self.state
            .try_borrow_mut()
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?
            .publish(canonical, owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn awaiting_slot_preserves_absence_without_creating_an_owner() {
        let state = PrincipalSlotV25::<u8> {
            canonical: None,
            owner: None,
        };
        for _ in 0..8 {
            assert!(state.owner.is_none());
            assert!(state.canonical.is_none());
        }
    }

    #[test]
    fn duplicate_publication_does_not_replenish_consumed_owner() {
        let mut state = PrincipalSlotV25 {
            canonical: None,
            owner: None,
        };
        state.publish(vec![1, 2, 3], 17).unwrap();
        state.publish(vec![1, 2, 3], 18).unwrap();
        assert_eq!(state.owner.take(), Some(17));
        state.publish(vec![1, 2, 3], 19).unwrap();
        assert!(state.owner.is_none());
    }

    #[test]
    fn different_principal_refused_before_and_after_consumption() {
        let mut state = PrincipalSlotV25 {
            canonical: None,
            owner: None,
        };
        state.publish(vec![1, 2, 3], 17).unwrap();
        assert!(state.publish(vec![1, 2, 4], 18).is_err());
        assert_eq!(state.owner.take(), Some(17));
        assert!(state.publish(vec![1, 2], 19).is_err());
        assert!(state.owner.is_none());
        assert_eq!(state.canonical, Some(vec![1, 2, 3]));
    }
}
