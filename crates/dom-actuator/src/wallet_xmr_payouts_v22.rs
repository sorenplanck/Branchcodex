//! Independently pinned policy payouts. These are wallet scopes, not DSC1 rounds.
use super::*;
use kaystra_core::SettlementTermsV1;
use xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11;

pub use xmr_refund_policy::payout_offer_v22::XmrGraphPayoutKindV22 as DomXmrPayoutKindV22;

impl DomParticipantWalletSessionV1<'_> {
    /// Authenticate an existing encrypted opening at its exact policy value
    /// and commitment, then pin it in the same native actuator journal.
    /// A separate derived scope permits two local outputs without replacing
    /// the parent's F6 payout. No opening, nonce, or signing grant is generated.
    /// Missing wallet or journal evidence fails closed after a restart.
    pub fn authenticate_xmr_payout_face_v22(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        kind: DomXmrPayoutKindV22,
        now_unix_ms: u64,
    ) -> DomActuatorResult<AuthenticatedDomPayoutFaceV1> {
        let parent = self.wallet.require_session(self.leg)?;
        self.wallet.audit_physical_authority()?;
        let validated = policy
            .policy()
            .validate_for(terms)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        let (recipient, commitment, value) = kind.policy_payout(policy);
        if &validated != policy
            || policy.policy().session_id != parent.session_id()
            || policy.policy().dom_chain_id != parent.chain_id()
            || policy.terms_hash() != &parent.terms_digest()
            || recipient != parent.participant().participant_id()
            || terms
                .roster
                .get(usize::from(parent.participant().protocol_index()))
                .map(|id| id.0)
                != Some(recipient)
            || now_unix_ms == 0
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        // Validate the actual parent and lease before deriving or binding any
        // auxiliary payout. A public policy cannot introduce another parent.
        store.retained_payout_face_selection(lease, parent, now_unix_ms)?;
        let payout_binding = parent.for_xmr_wallet_payout_v22(policy, kind)?;
        store.bind_session(lease, payout_binding, now_unix_ms)?;
        self.wallet.authenticate_payout_face_for_binding_v22(
            payout_binding,
            store,
            lease,
            DomPayoutFaceRequestV1::new(commitment, value, now_unix_ms)?,
        )
    }
}
