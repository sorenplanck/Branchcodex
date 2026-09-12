//! Public proofs produced only after exact native wallet/actuator authentication.
use super::*;
use kaystra_core::SettlementTermsV1;
use xmr_refund_policy::{
    compensation::ValidatedXmrCompensationPolicyV11,
    economic_graph::produce_xmr_payout_value_proof_v12, payout_offer_v22::XmrPolicyPayoutOfferV22,
};

/// Borrowed native scope for one local policy payout; contains no raw key.
pub struct DomXmrPayoutProofRequestV22<'a> {
    /// Frozen terms authenticated by the composition root.
    pub terms: &'a SettlementTermsV1,
    /// Economic policy bound to those exact terms.
    pub policy: &'a ValidatedXmrCompensationPolicyV11,
    /// Requested output purpose, fixing recipient, value and commitment.
    pub kind: DomXmrPayoutKindV22,
    /// Actual local C capability, fixing chain, roster and direction.
    pub shared: &'a SessionBlindingShareCapabilityV1,
    /// Exact previously retained public bytes, if this payout was published.
    pub retained: Option<&'a [u8]>,
    /// Timestamp used to revalidate the native participant lease.
    pub now_unix_ms: u64,
}

impl DomParticipantWalletSessionV1<'_> {
    /// Build or reauthenticate a public proof without exporting its blinding.
    /// The caller must retain the returned bytes before any peer publication.
    /// A retained proof is never regenerated or replaced after restart.
    pub fn prepare_xmr_payout_proof_v22(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomXmrPayoutProofRequestV22<'_>,
    ) -> DomActuatorResult<XmrPolicyPayoutOfferV22> {
        let parent = self.wallet.require_session(self.leg)?;
        self.wallet.require_shared_binding(parent, request.shared)?;
        let public = request.shared.binding();
        if public.roster() != request.terms.roster.map(|p| p.0).as_slice() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let chain = public.trusted_chain_id();
        let direction = public.role();
        let retained = request
            .retained
            .map(|bytes| {
                XmrPolicyPayoutOfferV22::from_bytes(
                    bytes,
                    request.terms,
                    request.policy,
                    chain,
                    direction,
                )
                .map_err(|_| DomActuatorError::CapabilityMismatch)
            })
            .transpose()?;
        if retained
            .as_ref()
            .is_some_and(|offer| offer.kind() != request.kind)
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let face = self.authenticate_xmr_payout_face_v22(
            store,
            lease,
            request.terms,
            request.policy,
            request.kind,
            request.now_unix_ms,
        )?;
        store.validate_payout_face(lease, &face.retained, request.now_unix_ms)?;
        let opening = self
            .wallet
            .state
            .outputs
            .get(&face.payout_commitment())
            .ok_or(DomActuatorError::WalletUnavailable)?;
        if opening.value != face.payout_value()
            || opening.payout_for().map(PayoutForV1::prepare_digest)
                != Some(face.retained.prepare_digest)
            || payout_ownership_digest(face.binding(), opening)
                != face.retained.wallet_ownership_digest
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let output = super::templates_v17::proven_output(
            opening,
            retained.as_ref().map(|offer| offer.output()),
        )?;
        if let Some(retained) = retained {
            self.wallet.audit_physical_authority()?;
            return Ok(retained);
        }
        let ownership = if let Some(kind) = request.kind.success_kind() {
            let blinding = SigningShareV1::from_be_bytes(*opening.blinding)
                .map_err(|_| DomActuatorError::WalletUnavailable)?;
            Some(
                produce_xmr_payout_value_proof_v12(
                    request.terms,
                    request.policy,
                    kind,
                    direction,
                    chain,
                    &blinding,
                )
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
            )
        } else {
            None
        };
        let offer = XmrPolicyPayoutOfferV22::new(
            request.terms,
            request.policy,
            request.kind,
            output,
            ownership,
            chain,
            direction,
        )
        .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        self.wallet.audit_physical_authority()?;
        Ok(offer)
    }
}
