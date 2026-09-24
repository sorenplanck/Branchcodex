//! Funding-purpose signing scheduler under the sole Stage-12 private owner.
//! It persists exact signed bytes for the settlement child; it never submits
//! them outside the coordinator or copies the retained nonce vault.
use super::{ProductionContractsOutboundErrorV1, ProductionContractsV1};
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use crate::production_dom_claim_driver_v12::{
    prepare_next_dom_funding_edge_v20, ProductionDomClaimProgressV12,
};
use crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12;
use crate::relay_worker::ContractsRelayIngressErrorV1;
use dom_actuator::DomSessionBindingV1;
use dom_adaptor::{AcceptedSigningSessionV1, PurposeV1, TrustedChainIdV1};
use dom_scriptless_store::{OutboundDsc1RecoveryV1, SessionPhaseV1, SessionStoreError};
use dom_scriptless_transport::SignedMessageV1;
use relay::TimelockSpec;
use route_transport::F6TransportPortV1;
use std::time::Duration;

pub(crate) const F7_FUNDING_CONTEXT_POLL_BOUND_V24: Duration = Duration::from_secs(10);

fn bounded_f7_funding_context_budget_v24(
    funding_window: &crate::production_timer::ProductionFundingWindowV23,
) -> Duration {
    funding_window
        .remaining()
        .min(F7_FUNDING_CONTEXT_POLL_BOUND_V24)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionFundingErrorV20 {
    #[error("funding native scope or retained private owner mismatch")]
    Binding,
    #[error("funding native journal refused the operation")]
    Store(#[from] SessionStoreError),
    #[error("funding native signer refused the operation")]
    Signer,
    #[error("funding chain context could not be authenticated")]
    Observation(#[from] adapter_dom_real::RealDomError),
    #[error("funding ingress ownership transition was refused")]
    Ingress(#[from] ContractsRelayIngressErrorV1),
    #[error("funding identity/outbox operation was refused")]
    Outbound(#[from] ProductionContractsOutboundErrorV1),
}
impl ProductionFundingErrorV20 {
    pub(crate) fn retryable(&self) -> bool {
        matches!(
            self,
            // The two *AuthorityUnavailable answers mean the Store has no
            // authority to hand out *yet* (gate not prepared, observation
            // aged past its window); the next round prepares or re-observes.
            // Run 84 died on the claim-signing one; the funding one is the
            // same answer from the fresh-gate predicates in recovery.
            Self::Store(
                SessionStoreError::StoreBusy
                    | SessionStoreError::Filesystem
                    | SessionStoreError::FundingAuthorityUnavailable
                    | SessionStoreError::ClaimSigningAuthorityUnavailable
            )
                | Self::Observation(adapter_dom_real::RealDomError::Chain(
                    dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable
                ))
                | Self::Ingress(ContractsRelayIngressErrorV1::OwnerBusy)
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductionFundingStepV20 {
    GateAbsent,
    // Fresh native signing is closed; pending DSC1/recovery still run.
    WindowClosed,
    AwaitingPeer,
    OtherOutboundPending,
    Staged,
    Committed,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn step_f7_funding_v20(
        &mut self,
        material: &mut ProductionBoundDomSharedOutputV12,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: &ProductionDomF7ScannerAuthorityV1,
        funding_window: &crate::production_timer::ProductionFundingWindowV23,
        vaults: &crate::production_dom_vaults_v12::ProductionXmrGraphVaultProvisionerV23,
        now: u64,
    ) -> Result<ProductionFundingStepV20, ProductionFundingErrorV20> {
        use ProductionFundingErrorV20 as Error;
        use ProductionFundingStepV20 as Step;
        self.validate_dom_binding(binding)
            .map_err(|_| Error::Binding)?;
        let Some(gate) = self
            .store
            .retained_f7_funding_gate_v19(chain, self.session_id)?
        else {
            return Ok(Step::GateAbsent);
        };
        if self
            .store
            .prepare_next_operational_xmr_ready_to_fund_vote_v12(&gate)?
            .is_some()
        {
            return Ok(Step::AwaitingPeer);
        }
        match self.store.resume_f7_committed_funding_v12(&gate) {
            Ok(_) => {
                self.release_funding_vault_v20(material, chain)?;
                return Ok(Step::Committed);
            }
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let recovery = self.store.resume_outbound_dsc1(self.session_id)?;
        let kind = match &recovery {
            OutboundDsc1RecoveryV1::None => None,
            OutboundDsc1RecoveryV1::SigningRequest(request) => Some(request.message_type()),
            OutboundDsc1RecoveryV1::Committed(record) => Some(
                SignedMessageV1::decode_exact(record.signed_bytes())
                    .map_err(|_| Error::Binding)?
                    .unsigned()
                    .kind() as u8,
            ),
        };
        if kind.is_some_and(|kind| !(0x0c..=0x0e).contains(&kind)) {
            return Ok(Step::OtherOutboundPending);
        }
        let phase = self.store.load_session(self.session_id)?.phase();
        if !matches!(
            phase,
            SessionPhaseV1::RefundSigned | SessionPhaseV1::FundingAuthorized
        ) && !(phase == SessionPhaseV1::RefundSigning && material.xmr_graph_shares_v22.is_some())
        {
            return Err(Error::Binding);
        }
        let expiry = TimelockSpec::TimestampSeconds {
            value: now
                .checked_add(3600)
                .filter(|_| now != 0)
                .ok_or(Error::Binding)?,
        };
        // Already committed DSC1 bytes are recovery, not a new signature.
        // Restore their retained ingress owner and retransmit the exact record
        // even if native-height RPC is unavailable. Never enter begin/sign here.
        if let OutboundDsc1RecoveryV1::Committed(record) = recovery {
            if record.sender_id() != &self.local_participant
                || record.session_id() != &self.session_id
            {
                return Err(Error::Binding);
            }
            let transport = self.store.prepare_operational_signing_transport_authority(
                chain,
                self.session_id,
                PurposeV1::Funding,
            )?;
            let mut relay = self
                .relay
                .try_borrow_mut()
                .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?;
            relay.handoff_funding_signing_v20(transport)?;
            relay
                .stage_store_outbound_dsc1(*record, expiry)
                .map_err(ProductionContractsOutboundErrorV1::from)?;
            return Ok(Step::Staged);
        }
        if !funding_window.available() {
            return Ok(Step::WindowClosed);
        }
        // Fresh DOM context on every signing tick. No private operation is
        // authorized by the bootstrap's historical chain projection.
        let context = scanner.funding_validation_context_bounded_v23(
            bounded_f7_funding_context_budget_v24(funding_window),
        )?;
        if !funding_window.available() {
            return Ok(Step::WindowClosed);
        }
        if material.xmr_graph_shares_v22.is_some()
            && phase == SessionPhaseV1::RefundSigning
            && !self
                .store
                .xmr_funding_window_open_v23(chain, self.session_id, context)?
        {
            return Ok(Step::WindowClosed);
        }
        let accepted = self
            .store
            .begin_f7_funding_signing_v20(chain, self.session_id, context)?;
        let transport = self.store.prepare_operational_signing_transport_authority(
            chain,
            self.session_id,
            PurposeV1::Funding,
        )?;
        self.relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .handoff_funding_signing_v20(transport)?;
        match recovery {
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if request.sender_id() != &self.local_participant {
                    return Err(Error::Binding);
                }
                if !funding_window.available() {
                    return Ok(Step::WindowClosed);
                }
                self.sign_commit_and_stage(*request, expiry)?;
                return Ok(Step::Staged);
            }
            // The committed branch returned above without consuming any nonce.
            OutboundDsc1RecoveryV1::Committed(_) => return Err(Error::Binding),
            OutboundDsc1RecoveryV1::None => {}
        }
        if accepted.accepted_signing_messages().count() == 6 {
            // Re-read after signing/replay, immediately before materialization.
            let context = scanner.funding_validation_context_bounded_v23(
                bounded_f7_funding_context_budget_v24(funding_window),
            )?;
            if !funding_window.available() {
                return Ok(Step::WindowClosed);
            }
            let _submission =
                self.store
                    .complete_f7_funding_signing_v20(chain, self.session_id, context)?;
            self.release_funding_vault_v20(material, chain)?;
            return Ok(Step::Committed);
        }
        let signing_context = scanner.funding_validation_context_bounded_v23(
            bounded_f7_funding_context_budget_v24(funding_window),
        )?;
        if !funding_window.available() {
            return Ok(Step::WindowClosed);
        }
        if material.xmr_graph_shares_v22.is_some()
            && !self
                .store
                .xmr_funding_window_open_v23(chain, self.session_id, signing_context)?
        {
            // Keep the same ingress/nonce owner. A peer's already-issued final
            // message may still arrive and make recovery aggregation possible.
            return Ok(Step::WindowClosed);
        }
        self.store
            .require_f7_funding_signing_window_v20(self.session_id, signing_context)?;
        if material.funding_signer_v20.is_none() {
            if material.refund_signer_v18.is_some() {
                return Err(Error::Binding);
            }
            // The Store has already admitted Funding after both ready votes.
            // Never substitute a legacy bootstrap excess for the graph excess.
            if material.vault.is_none() {
                return Err(Error::Binding);
            }
            let share = if let Some(graph_shares) = material.xmr_graph_shares_v22.as_mut() {
                if material.funding_share_v18.is_some() {
                    return Err(Error::Binding);
                }
                if material.funding_vault_v23.is_none() {
                    material.funding_vault_v23 = Some(
                        vaults
                            .provision_funding_v23(&self.store, binding, chain)
                            .map_err(|_| Error::Signer)?,
                    );
                }
                graph_shares
                    .take_funding_share_v23(&self.store)
                    .map_err(|_| Error::Signer)?
            } else {
                material.funding_share_v18.take().ok_or(Error::Binding)?
            };
            let vault = if material.xmr_graph_shares_v22.is_some() {
                material.funding_vault_v23.take().ok_or(Error::Binding)?
            } else {
                if material.funding_vault_v23.is_some() {
                    return Err(Error::Binding);
                }
                material.vault.take().ok_or(Error::Binding)?
            };
            material.funding_signer_v20 = Some(
                dom_actuator::participant_retained_vault_signer_v12(
                    vault,
                    std::rc::Rc::clone(&self.store),
                    binding,
                    chain,
                    share,
                )
                .map_err(|_| Error::Signer)?,
            );
        }
        let transport = self.store.prepare_operational_signing_transport_authority(
            chain,
            self.session_id,
            PurposeV1::Funding,
        )?;
        if !funding_window.available() {
            return Ok(Step::WindowClosed);
        }
        match prepare_next_dom_funding_edge_v20(
            &self.store,
            binding,
            chain,
            material.funding_signer_v20.as_mut().ok_or(Error::Binding)?,
            accepted,
            &transport,
        )
        .map_err(|_| Error::Signer)?
        {
            ProductionDomClaimProgressV12::AwaitingPeer => Ok(Step::AwaitingPeer),
            ProductionDomClaimProgressV12::Prepared(request) => {
                self.sign_commit_and_stage(request, expiry)?;
                Ok(Step::Staged)
            }
            ProductionDomClaimProgressV12::SigningComplete => Err(Error::Binding),
        }
    }

    fn release_funding_vault_v20(
        &mut self,
        material: &mut ProductionBoundDomSharedOutputV12,
        chain: TrustedChainIdV1,
    ) -> Result<(), ProductionFundingErrorV20> {
        let native = material.xmr_graph_shares_v22.is_some();
        let occupied = if native {
            material.funding_vault_v23.is_some()
        } else {
            if material.funding_vault_v23.is_some() {
                return Err(ProductionFundingErrorV20::Binding);
            }
            material.vault.is_some()
        };
        if material.funding_signer_v20.is_some() && occupied {
            return Err(ProductionFundingErrorV20::Binding);
        }
        self.relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .finish_funding_signing_v20(chain)?;
        if let Some(signer) = material.funding_signer_v20.take() {
            if native {
                material.funding_vault_v23 = Some(signer.into_vault_v18());
            } else {
                material.vault = Some(signer.into_vault_v18());
            }
        }
        Ok(())
    }
}
