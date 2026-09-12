//! Family-neutral bilateral 0x17 sender in the real composite Relay loop.
//!
//! Uses only the selected leg's existing Contracts, identity and Relay owners.
//! A missing native gate is a distinct waiting state, never permission to
//! manufacture readiness. This scheduler does not replace the funding signer.
use super::{ProductionContractsOutboundErrorV1, ProductionContractsV1};
use crate::relay_worker::ContractsRelayIngressErrorV1;
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_store::{OutboundDsc1RecoveryV1, SessionStoreError};
use dom_scriptless_transport::SignedMessageV1;
use relay::TimelockSpec;
use route_transport::F6TransportPortV1;

const READY_KIND: u8 = 0x17;
const ENVELOPE_LIFETIME_SECONDS: u64 = 3600;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionF7ReadinessErrorV19 {
    #[error("F7 readiness retained native state was refused")]
    Store(#[from] SessionStoreError),
    #[error("F7 readiness ingress ownership was refused")]
    Ingress(#[from] ContractsRelayIngressErrorV1),
    #[error("F7 readiness identity/outbox operation was refused")]
    Outbound(#[from] ProductionContractsOutboundErrorV1),
    #[error("F7 readiness transport clock is invalid")]
    Clock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionF7ReadinessStepV19 {
    GateAbsent,
    OtherOutboundPending,
    AwaitingPeer,
    Staged,
    BilateralReady,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// Called by the concrete roots only after F6 and ordinary refund
    /// bootstrap completed. All transaction/proof inputs come from this Store.
    pub(crate) fn prepare_bootstrap_gate_v20(
        &self,
        chain: TrustedChainIdV1,
        plan: &dom_final_claim_binding::ComposedFinalClaimRolePlanV1,
        source: &dom_final_claim_binding::FinalClaimSecretSourceScopeV1,
        leg: dom_final_claim_binding::ComposedSettlementLegV1,
        now_unix_seconds: u64,
    ) -> Result<(), ProductionF7ReadinessErrorV19> {
        if plan.route_id() != self.route_id || plan.entry(leg).session_id().0 != self.session_id {
            return Err(SessionStoreError::InvalidTransition.into());
        }
        let _gate = self.store.prepare_bootstrapped_plain_f7_gate_v20(
            chain,
            self.session_id,
            plan,
            source,
            leg,
            now_unix_seconds,
        )?;
        Ok(())
    }

    pub(crate) fn step_f7_readiness_v19(
        &mut self,
        chain: TrustedChainIdV1,
        now: u64,
    ) -> Result<ProductionF7ReadinessStepV19, ProductionF7ReadinessErrorV19> {
        use ProductionF7ReadinessErrorV19 as Error;
        use ProductionF7ReadinessStepV19 as Step;
        let Some(gate) = self
            .store
            .retained_f7_funding_gate_v19(chain, self.session_id)?
        else {
            return Ok(Step::GateAbsent);
        };
        let next = self
            .store
            .prepare_next_operational_xmr_ready_to_fund_vote_v12(&gate)?;
        // Prepare ingress before staging/replaying the local edge: the peer
        // may already have accepted it when our ACK or process was lost.
        {
            let mut relay = self
                .relay
                .try_borrow_mut()
                .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?;
            if next.is_some() {
                // Reissue from exactly the same Store, not a cloned permit.
                let ingress = self
                    .store
                    .resume_f7_funding_gate_v12(chain, self.session_id)?;
                relay.install_f7_readiness_v19(ingress)?;
            } else {
                relay.finish_f7_readiness_v19()?;
            }
        }
        let expiry = TimelockSpec::TimestampSeconds {
            value: now
                .checked_add(ENVELOPE_LIFETIME_SECONDS)
                .filter(|_| now != 0)
                .ok_or(Error::Clock)?,
        };
        match self.store.resume_outbound_dsc1(self.session_id)? {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if request.message_type() != READY_KIND {
                    return Ok(Step::OtherOutboundPending);
                }
                if request.sender_id() != &self.local_participant {
                    return Err(SessionStoreError::InvalidTransition.into());
                }
                self.sign_commit_and_stage(*request, expiry)?;
                return Ok(Step::Staged);
            }
            OutboundDsc1RecoveryV1::Committed(committed) => {
                let signed = SignedMessageV1::decode_exact(committed.signed_bytes())
                    .map_err(|_| SessionStoreError::Quarantined)?;
                if signed.unsigned().kind() as u8 != READY_KIND {
                    return Ok(Step::OtherOutboundPending);
                }
                if committed.session_id() != &self.session_id
                    || committed.sender_id() != &self.local_participant
                {
                    return Err(SessionStoreError::InvalidTransition.into());
                }
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*committed, expiry)
                    .map_err(ProductionContractsOutboundErrorV1::from)?;
                return Ok(Step::Staged);
            }
            OutboundDsc1RecoveryV1::None => {}
        }
        let Some(vote) = next else {
            return Ok(Step::BilateralReady);
        };
        if vote.participant_id() != self.local_participant {
            return Ok(Step::AwaitingPeer);
        }
        let request = self
            .store
            .prepare_xmr_ready_to_fund_dsc1_signing_request_v12(&gate, &vote)?
            .ok_or(SessionStoreError::InvalidTransition)?;
        self.sign_commit_and_stage(request, expiry)?;
        Ok(Step::Staged)
    }
}
