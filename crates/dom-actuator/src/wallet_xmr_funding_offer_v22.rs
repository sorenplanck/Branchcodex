//! Public funding material reconstructed from the exact native reservation.
use super::*;
use dom_consensus::TransactionInput;
use kaystra_core::SettlementTermsV1;
use xmr_refund_policy::{
    compensation::ValidatedXmrCompensationPolicyV11, funding_offer_v22::XmrFundingOfferV22,
};

impl DomParticipantWalletSessionV1<'_> {
    /// Reopen reserved inputs and prove the native wallet change. Retained
    /// public bytes are verified before wallet mutation, then compared to the
    /// exact reconstruction. The caller must retain bytes before publication.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_xmr_funding_offer_v22(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        policy: &ValidatedXmrCompensationPolicyV11,
        retained: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<XmrFundingOfferV22> {
        let binding = self.wallet.require_session(self.leg)?;
        self.wallet.audit_physical_authority()?;
        let participant = binding.participant().participant_id();
        let old = retained
            .map(|bytes| {
                XmrFundingOfferV22::from_bytes(bytes, terms, policy, participant)
                    .map_err(|_| DomActuatorError::CapabilityMismatch)
            })
            .transpose()?;
        let funding =
            self.prepare_xmr_funding_inputs_v22(store, lease, terms, policy, now_unix_ms)?;
        let mut inputs = Vec::new();
        let mut change = None;
        let mut fee = 0;
        if let Some(funding) = funding {
            self.wallet
                .require_live_reservation(store, binding, funding.reservation())?;
            for input in funding.reservation().outputs() {
                inputs.push(TransactionInput {
                    commitment: Commitment::from_compressed_bytes(&input.commitment())
                        .map_err(|_| DomActuatorError::WalletUnavailable)?,
                });
            }
            inputs.sort_by(|a, b| a.commitment.as_bytes().cmp(b.commitment.as_bytes()));
            // Reject a changed public reservation before even generating a
            // replacement change proof; retained publication is immutable.
            if let Some(old) = &old {
                if old.inputs() != inputs.as_slice()
                    || old.fee() != funding.fee_noms()
                    || old.change().map(|output| *output.commitment.as_bytes())
                        != funding.change_commitment()
                {
                    return Err(DomActuatorError::IdempotencyConflict);
                }
            }
            if let Some(commitment) = funding.change_commitment() {
                let opening = self
                    .wallet
                    .state
                    .outputs
                    .get(&commitment)
                    .ok_or(DomActuatorError::WalletUnavailable)?;
                if opening.value != funding.change_noms() {
                    return Err(DomActuatorError::WalletUnavailable);
                }
                change = Some(super::templates_v17::proven_output(
                    opening,
                    old.as_ref().and_then(XmrFundingOfferV22::change),
                )?);
            }
            fee = funding.fee_noms();
        }
        let offer = XmrFundingOfferV22::new(terms, policy, participant, inputs, change, fee)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        if let Some(old) = old {
            if old
                .to_bytes()
                .map_err(|_| DomActuatorError::CapabilityMismatch)?
                != offer
                    .to_bytes()
                    .map_err(|_| DomActuatorError::CapabilityMismatch)?
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
        }
        self.wallet.audit_physical_authority()?;
        Ok(offer)
    }
}
