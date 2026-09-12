//! Public graph context projected from admission, before any sweep is opened.
use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
use crate::production_inputs::AuthenticatedXmrSessionBindingsV1;
use crate::production_inputs::{ProductionXmrEnrollmentBundleV23, ProductionXmrRefundBundleV1};
use dom_actuator::DomSessionBindingV1;
use dom_final_claim_binding::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
};
use kaystra_core::SettlementTermsV1;
use xmr_setup_profile::ValidatedXmrSetup;

enum RefundBindingV23 {
    LegacyPinned(ProductionXmrRefundBundleV1),
    NativeEnrollment(ProductionXmrEnrollmentBundleV23),
    NativeBound {
        refund: ProductionXmrRefundBundleV1,
        authority: dom_scriptless_store::VerifiedXmrRefundTemplateBindingV23,
    },
}
type ClaimContextV23 = (
    ComposedFinalClaimRolePlanV1,
    FinalClaimSecretSourceScopeV1,
    ComposedSettlementLegV1,
);

/// No raw constructor, secret material, RPC client or funding permission.
pub(crate) struct ProductionXmrGraphSetupV22 {
    binding: DomSessionBindingV1,
    negotiated_tip: u64,
    terms: SettlementTermsV1,
    setup: ValidatedXmrSetup,
    genesis: [u8; 32],
    refund_point: [u8; 33],
    refund_binding: RefundBindingV23,
    claim_context: Option<ClaimContextV23>,
}

impl ProductionXmrGraphSetupV22 {
    pub(crate) fn from_admission(
        session: &AuthenticatedXmrSessionBindingsV1,
        terms: &SettlementTermsV1,
        binding: DomSessionBindingV1,
        negotiated_tip: u64,
    ) -> Result<Self, crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16 as Error;
        let digest = terms.terms_hash().map_err(|_| Error::Binding)?;
        let (refund_point, refund_binding) = match (
            session.refund_bundle(),
            session.native_enrollment_bundle_v23(),
            session.native_enrollment_v23(),
        ) {
            (Some(refund), None, None) => (
                refund.adaptor_point_sec1,
                RefundBindingV23::LegacyPinned(refund.clone()),
            ),
            (None, Some(enrollment), Some(prepared)) => {
                prepared
                    .require_setup(session.setup(), enrollment.proof())
                    .map_err(|_| Error::Binding)?;
                (
                    *enrollment.adaptor_point_sec1(),
                    RefundBindingV23::NativeEnrollment(enrollment.clone()),
                )
            }
            _ => return Err(Error::Binding),
        };
        let genesis = session.deployment().deployment().genesis_hash;
        if session.route_id() != binding.route_id()
            || session.session_id() != binding.session_id()
            || session.terms_digest() != binding.terms_digest()
            || digest != binding.terms_digest()
            || terms.session_id.0 != binding.session_id()
            || terms.dom_leg.chain_id.0 != binding.chain_id()
            || terms
                .roster
                .get(usize::from(binding.participant().protocol_index()))
                .map(|participant| participant.0)
                != Some(binding.participant().participant_id())
            || session.deployment().profile().chain_id != terms.counterparty_leg.chain_id
            || session.setup().terms_hash() != digest
            || session.setup().settlement_id() != terms.settlement_id.0
            || u128::from(session.setup().expected_amount_piconero())
                != terms.counterparty_leg.amount
            || session.setup().claim().secp_compressed != terms.adaptor_point_sec1
            || refund_point == terms.adaptor_point_sec1
            || genesis == [0; 32]
        {
            return Err(Error::Binding);
        }
        // Admission already verified U's DLEQ and that T + U controls the
        // advertised deposit. Do not replace that token with caller fields.
        Ok(Self {
            binding,
            negotiated_tip,
            terms: terms.clone(),
            setup: session.setup().clone(),
            genesis,
            refund_point,
            refund_binding,
            claim_context: None,
        })
    }

    pub(crate) fn install_claim_context_v23(
        &mut self,
        plan: &ComposedFinalClaimRolePlanV1,
        source: &FinalClaimSecretSourceScopeV1,
        leg: ComposedSettlementLegV1,
    ) -> Result<(), crate::production_contracts::ProductionBootstrapRuntimeErrorV16> {
        use crate::production_contracts::ProductionBootstrapRuntimeErrorV16::Binding as Refused;
        if plan.route_id() != self.binding.route_id()
            || plan.entry(leg).session_id().0 != self.binding.session_id()
            || plan.entry(leg).secret_source_scope_digest() != source.digest()
        {
            return Err(Refused);
        }
        let context = (plan.clone(), source.clone(), leg);
        if self
            .claim_context
            .as_ref()
            .is_some_and(|old| old != &context)
        {
            return Err(Refused);
        }
        self.claim_context = Some(context);
        Ok(())
    }

    pub(crate) fn claim_context_v23(&self) -> Option<&ClaimContextV23> {
        self.claim_context.as_ref()
    }

    pub(crate) fn negotiated_tip(&self) -> u64 {
        self.negotiated_tip
    }

    pub(crate) fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }
    pub(crate) fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }
    pub(crate) fn setup(&self) -> &ValidatedXmrSetup {
        &self.setup
    }
    pub(crate) fn genesis(&self) -> [u8; 32] {
        self.genesis
    }
    pub(crate) fn refund_point(&self) -> [u8; 33] {
        self.refund_point
    }
    pub(crate) fn refund_bundle_v23(&self) -> Result<&ProductionXmrRefundBundleV1, Error> {
        match &self.refund_binding {
            RefundBindingV23::LegacyPinned(refund)
            | RefundBindingV23::NativeBound { refund, .. } => Ok(refund),
            RefundBindingV23::NativeEnrollment(_) => Err(Error::Binding),
        }
    }

    pub(crate) fn admitted_refund_template(&self) -> Result<[u8; 32], Error> {
        Ok(self.refund_bundle_v23()?.template_hash)
    }

    /// Proposal construction is not template admission or signing permission.
    /// Native enrollment defers the exact pin to the bilateral Store authority.
    pub(crate) fn require_refund_proposal_v23(&self, hash: [u8; 32]) -> Result<(), Error> {
        if hash == [0; 32] {
            return Err(Error::Binding);
        }
        match &self.refund_binding {
            RefundBindingV23::NativeEnrollment(_) => Ok(()),
            _ if self.admitted_refund_template()? == hash => Ok(()),
            _ => Err(Error::Binding),
        }
    }

    /// Same-open origin must be revalidated by its Contracts owner before
    /// moving enrolled resources into an executable sweep/custody owner.
    pub(crate) fn native_refund_binding_v23(
        &self,
    ) -> Result<&dom_scriptless_store::VerifiedXmrRefundTemplateBindingV23, Error> {
        match &self.refund_binding {
            RefundBindingV23::NativeBound { authority, .. } => Ok(authority),
            _ => Err(Error::Binding),
        }
    }

    pub(crate) fn needs_refund_binding_v23(&self) -> bool {
        matches!(self.refund_binding, RefundBindingV23::NativeEnrollment(_))
    }

    /// Only a Store-issued, bilaterally authenticated origin can supply this
    /// hash. The caller revalidates that origin in the same live Store.
    pub(crate) fn bind_native_refund_v23(
        &mut self,
        authority: dom_scriptless_store::VerifiedXmrRefundTemplateBindingV23,
    ) -> Result<(), Error> {
        if authority.trusted_chain_id().as_bytes() != &self.binding.chain_id()
            || authority.route_id() != self.binding.route_id()
            || authority.session_id() != self.binding.session_id()
            || authority.terms_hash() != self.binding.terms_digest()
            || authority.participant_ids() != self.terms.roster.map(|id| id.0)
            || authority.refund_adaptor_point() != self.refund_point
        {
            return Err(Error::Binding);
        }
        match &self.refund_binding {
            RefundBindingV23::NativeEnrollment(enrollment) => {
                let refund = ProductionXmrRefundBundleV1::new_v10(
                    enrollment.proof().clone(),
                    authority.refund_template_hash(),
                    *enrollment.adaptor_point_sec1(),
                    enrollment.executor_profile_hash(),
                    enrollment.deadline(),
                    enrollment.refund_destination().to_owned(),
                )
                .map_err(|_| Error::Binding)?;
                self.refund_binding = RefundBindingV23::NativeBound { refund, authority };
                Ok(())
            }
            RefundBindingV23::NativeBound {
                authority: previous,
                ..
            } if previous.origin_digest() == authority.origin_digest()
                && previous.graph_proposal_digest() == authority.graph_proposal_digest()
                && previous.refund_template_hash() == authority.refund_template_hash() =>
            {
                Ok(())
            }
            _ => Err(Error::Binding),
        }
    }
}
