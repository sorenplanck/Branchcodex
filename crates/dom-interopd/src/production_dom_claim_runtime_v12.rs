//! Retained native DOM claim producer installed under the Contracts owner.
//!
//! A driver owns one wallet share and one purpose-separated nonce vault across
//! ticks. Both participant messages and the aggregate pre-signature use the
//! exact Store-issued DSC1 identity signing and durable Relay staging path.
//! Every tick consumes fresh native F7 observations for the selected profile.

use super::{
    ProductionContractsConsumedPostAnchorV2, ProductionContractsOutboundErrorV1,
    ProductionContractsV1,
};
use crate::production_dom_claim_driver_v12::{
    prepare_next_dom_claim_edge_with_signer_v12, ProductionDomClaimDriverErrorV12,
    ProductionDomClaimProgressV12,
};
use crate::relay_worker::{
    ContractsRelayIngressErrorV1, PreparedContractsIngressV1, RelayWorkerOutboundErrorV1,
};
use dom_actuator::{
    participant_retained_vault_signer_v12, DomParticipantSigningShareV1, DomSessionBindingV1,
    RetainedParticipantVaultSignerV12,
};
use dom_adaptor::{
    ContractKindV1, NonceVaultV1, ParticipantRosterV1, PurposeV1, RestartArtifactRecoveryVaultV1,
    TrustedChainIdV1,
};
use dom_consensus::Transaction;
use dom_scriptless_identity_store::IdentityStoreError;
use dom_scriptless_store::{
    AcceptedContractsSigningSessionV1, AuthenticatedF7ClaimPreSignatureV12,
    AuthenticatedPostAnchorClaimPreSignatureV2, ConsumedF7ClaimAuthorizationV12,
    ContractsSessionStoreV1, OutboundDsc1RecoveryV1, PreparedF7FundingGateV12, SessionStoreError,
};
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1};
use f7_anchor_authority::families_v11::VerifiedF7AnchorAuthorizationV12;
use f7_anchor_authority::VerifiedF7AnchorAuthorizationV2;
use relay::TimelockSpec;
use route_transport::{F6TransportPortV1, RouteApplicationDispositionV2};
use std::rc::Rc;

/// Public claim material whose exact bytes the consumed native V2 authority
/// authenticates. V12 instead reconstructs these fields from its native gate.
pub(crate) struct ProductionDomClaimTemplateV12 {
    pub(crate) contract_kind: ContractKindV1,
    pub(crate) roster: ParticipantRosterV1,
    pub(crate) transaction: Transaction,
    pub(crate) kernel_index: usize,
}

/// Fresh real-chain observations, kept distinct across native Store profiles.
pub(crate) enum ProductionDomClaimAnchorsV12 {
    BitcoinV2(VerifiedF7AnchorAuthorizationV2),
    Universal(VerifiedF7AnchorAuthorizationV12),
}

enum ConsumedAuthorityV12 {
    BitcoinV2(ProductionContractsConsumedPostAnchorV2),
    Universal(ConsumedF7ClaimAuthorizationV12),
}

/// The verified result remains bound to its consumed native Store authority.
#[must_use]
pub(crate) enum ProductionDomClaimCompletionV12 {
    BitcoinV2 {
        authority: ProductionContractsConsumedPostAnchorV2,
        pre_signature: AuthenticatedPostAnchorClaimPreSignatureV2,
    },
    Universal {
        authority: ConsumedF7ClaimAuthorizationV12,
        pre_signature: AuthenticatedF7ClaimPreSignatureV12,
    },
}

enum CompletedPreSignatureV12 {
    BitcoinV2(AuthenticatedPostAnchorClaimPreSignatureV2),
    Universal(AuthenticatedF7ClaimPreSignatureV12),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionDomClaimRuntimeErrorV12 {
    #[error("DOM claim driver belongs to another Contracts owner or F7 profile")]
    Scope,
    #[error("native DOM claim journal refused the operation")]
    Store(#[from] SessionStoreError),
    #[error("native DOM claim participant refused signing or nonce recovery")]
    Participant(#[from] ProductionDomClaimDriverErrorV12),
    #[error("native DOM wallet rejected the retained participant share")]
    Wallet,
    #[error("native DOM claim DSC1 signing or staging failed")]
    Outbound(#[from] ProductionContractsOutboundErrorV1),
    #[error("native DOM claim Relay ingress refused the authority")]
    Ingress(#[from] ContractsRelayIngressErrorV1),
    #[error("fresh native F7 observations did not validate the consumed authority")]
    Anchors,
    #[error("DOM claim pre-signature has not completed native transport")]
    NotComplete,
}

impl ProductionDomClaimRuntimeErrorV12 {
    /// Retry only explicit host contention or I/O. Missing records, signatures,
    /// inconsistent identities and unauthorized scopes are never peer absence.
    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::Store(SessionStoreError::Filesystem | SessionStoreError::StoreBusy)
            | Self::Outbound(ProductionContractsOutboundErrorV1::OwnerBusy)
            | Self::Outbound(ProductionContractsOutboundErrorV1::Identity(
                IdentityStoreError::Filesystem | IdentityStoreError::StoreBusy,
            ))
            | Self::Outbound(ProductionContractsOutboundErrorV1::Store(
                SessionStoreError::Filesystem | SessionStoreError::StoreBusy,
            ))
            | Self::Outbound(ProductionContractsOutboundErrorV1::Relay(
                RelayWorkerOutboundErrorV1::OwnerBusy,
            ))
            | Self::Ingress(ContractsRelayIngressErrorV1::OwnerBusy)
            | Self::Ingress(ContractsRelayIngressErrorV1::Store(
                SessionStoreError::Filesystem | SessionStoreError::StoreBusy,
            )) => true,
            _ => false,
        }
    }
}

/// One bounded native operation; the ordinary Relay pump submits staged bytes.
#[must_use]
pub(crate) enum ProductionDomClaimStepV12 {
    AwaitingPeer,
    Staged(RouteApplicationDispositionV2),
    Complete,
}

/// One retained participant. There is no raw-key getter or constructor from a
/// digest, template alone, or caller-selected Fresh/Resume flag.
pub(crate) struct ProductionDomClaimRuntimeV12<Vault: NonceVaultV1> {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    authorization: ConsumedAuthorityV12,
    signer: RetainedParticipantVaultSignerV12<Vault>,
    completed: Option<CompletedPreSignatureV12>,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// Retains the actual post-M.8 authority, native participant share and vault.
    /// Native binding is idempotent and checks exact retained template ancestry.
    pub(crate) fn start_dom_claim_runtime_v2<Vault>(
        &self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        vault: Vault,
        share: DomParticipantSigningShareV1,
        authorization: ProductionContractsConsumedPostAnchorV2,
        template: ProductionDomClaimTemplateV12,
    ) -> Result<ProductionDomClaimRuntimeV12<Vault>, ProductionDomClaimRuntimeErrorV12>
    where
        Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
    {
        if !Rc::ptr_eq(&self.store, &authorization.store) {
            return Err(ProductionDomClaimRuntimeErrorV12::Scope);
        }
        self.validate_dom_binding(binding)
            .map_err(|_| ProductionDomClaimRuntimeErrorV12::Scope)?;
        if chain.as_bytes() != &binding.chain_id() {
            return Err(ProductionDomClaimRuntimeErrorV12::Scope);
        }
        self.store.bind_post_anchor_dom_claim_signing_session_v2(
            &authorization.authorization,
            chain,
            template.contract_kind,
            template.roster,
            template.transaction,
            template.kernel_index,
        )?;
        let signer = participant_retained_vault_signer_v12(
            vault,
            Rc::clone(&self.store),
            binding,
            chain,
            share,
        )
        .map_err(|_| ProductionDomClaimRuntimeErrorV12::Wallet)?;
        Ok(ProductionDomClaimRuntimeV12 {
            store: Rc::clone(&self.store),
            binding,
            chain,
            authorization: ConsumedAuthorityV12::BitcoinV2(authorization),
            signer,
            completed: None,
        })
    }

    /// Starts EVM/SOL/XMR from the exact native universal gate and fresh F7
    /// anchors. No Bitcoin client, M.8 binding or synthetic Bitcoin ID enters.
    pub(crate) fn start_dom_claim_runtime_v12<Vault>(
        &self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        vault: Vault,
        share: DomParticipantSigningShareV1,
        gate: &PreparedF7FundingGateV12,
        anchors: VerifiedF7AnchorAuthorizationV12,
    ) -> Result<ProductionDomClaimRuntimeV12<Vault>, ProductionDomClaimRuntimeErrorV12>
    where
        Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
    {
        self.validate_dom_binding(binding)
            .map_err(|_| ProductionDomClaimRuntimeErrorV12::Scope)?;
        if chain.as_bytes() != &binding.chain_id()
            || gate.session_id() != &self.session_id
            || anchors.role().session_id().0 != self.session_id
            || anchors.role().route_id() != self.route_id
        {
            return Err(ProductionDomClaimRuntimeErrorV12::Scope);
        }
        let authorization = self
            .store
            .consume_f7_claim_authorization_v12(gate, anchors)?;
        self.store
            .bind_retained_f7_claim_signing_session_v12(&authorization, chain)?;
        let signer = participant_retained_vault_signer_v12(
            vault,
            Rc::clone(&self.store),
            binding,
            chain,
            share,
        )
        .map_err(|_| ProductionDomClaimRuntimeErrorV12::Wallet)?;
        Ok(ProductionDomClaimRuntimeV12 {
            store: Rc::clone(&self.store),
            binding,
            chain,
            authorization: ConsumedAuthorityV12::Universal(authorization),
            signer,
            completed: None,
        })
    }
    /// Native XMR extracts its Claim share only after fresh F7 has been
    /// consumed. Do not consume a second authorization or adopt early/V18.
    pub(crate) fn start_dom_claim_runtime_consumed_v23<Vault>(
        &self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        vault: Vault,
        share: DomParticipantSigningShareV1,
        authorization: ConsumedF7ClaimAuthorizationV12,
    ) -> Result<ProductionDomClaimRuntimeV12<Vault>, ProductionDomClaimRuntimeErrorV12>
    where
        Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
    {
        self.validate_dom_binding(binding)
            .map_err(|_| ProductionDomClaimRuntimeErrorV12::Scope)?;
        if chain.as_bytes() != &binding.chain_id() || authorization.session_id() != self.session_id
        {
            return Err(ProductionDomClaimRuntimeErrorV12::Scope);
        }
        self.store
            .resume_xmr_bounded_claim_signing_v23(chain, &authorization)?;
        let signer = participant_retained_vault_signer_v12(
            vault,
            Rc::clone(&self.store),
            binding,
            chain,
            share,
        )
        .map_err(|_| ProductionDomClaimRuntimeErrorV12::Wallet)?;
        Ok(ProductionDomClaimRuntimeV12 {
            store: Rc::clone(&self.store),
            binding,
            chain,
            authorization: ConsumedAuthorityV12::Universal(authorization),
            signer,
            completed: None,
        })
    }
}

impl<Vault> ProductionDomClaimRuntimeV12<Vault>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    /// Executes one local native signing/staging edge. F7 is recollected by the
    /// concrete root before this call and consumed before any nonce operation.
    pub(crate) fn step<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        anchors: ProductionDomClaimAnchorsV12,
        expiry: TimelockSpec,
    ) -> Result<ProductionDomClaimStepV12, ProductionDomClaimRuntimeErrorV12> {
        self.require_owner(owner)?;
        self.refresh(anchors)?;
        if self.completed.is_some() {
            return Ok(ProductionDomClaimStepV12::Complete);
        }
        if let Some(staged) = self.resume_pending(owner, expiry)? {
            return Ok(ProductionDomClaimStepV12::Staged(staged));
        }
        let accepted = self.accepted()?;
        use dom_adaptor::AcceptedSigningSessionV1;
        if accepted.accepted_signing_messages().count() == 6 {
            return self.finish_pre_signature(owner, expiry);
        }
        let transport = self.store.prepare_operational_signing_transport_authority(
            self.chain,
            self.binding.session_id(),
            PurposeV1::ClaimAdaptor,
        )?;
        self.ensure_signing_ingress(owner)?;
        match prepare_next_dom_claim_edge_with_signer_v12(
            self.store.as_ref(),
            self.binding,
            self.chain,
            &mut self.signer,
            accepted,
            &transport,
        )? {
            ProductionDomClaimProgressV12::AwaitingPeer => {
                Ok(ProductionDomClaimStepV12::AwaitingPeer)
            }
            ProductionDomClaimProgressV12::Prepared(request) => owner
                .sign_commit_and_stage(request, expiry)
                .map(ProductionDomClaimStepV12::Staged)
                .map_err(Into::into),
            ProductionDomClaimProgressV12::SigningComplete => {
                self.finish_pre_signature(owner, expiry)
            }
        }
    }

    /// Consumes the driver only after the exact aggregate 0x0f is durable.
    pub(crate) fn finish(
        self,
    ) -> Result<ProductionDomClaimCompletionV12, ProductionDomClaimRuntimeErrorV12> {
        match (self.authorization, self.completed) {
            (
                ConsumedAuthorityV12::BitcoinV2(authority),
                Some(CompletedPreSignatureV12::BitcoinV2(pre_signature)),
            ) => Ok(ProductionDomClaimCompletionV12::BitcoinV2 {
                authority,
                pre_signature,
            }),
            (
                ConsumedAuthorityV12::Universal(authority),
                Some(CompletedPreSignatureV12::Universal(pre_signature)),
            ) => Ok(ProductionDomClaimCompletionV12::Universal {
                authority,
                pre_signature,
            }),
            _ => Err(ProductionDomClaimRuntimeErrorV12::NotComplete),
        }
    }

    fn require_owner<F: F6TransportPortV1>(
        &self,
        owner: &ProductionContractsV1<F>,
    ) -> Result<(), ProductionDomClaimRuntimeErrorV12> {
        if !Rc::ptr_eq(&self.store, &owner.store)
            || self.binding.session_id() != owner.session_id
            || self.binding.participant().participant_id() != owner.local_participant
        {
            return Err(ProductionDomClaimRuntimeErrorV12::Scope);
        }
        owner
            .validate_dom_binding(self.binding)
            .map_err(|_| ProductionDomClaimRuntimeErrorV12::Scope)
    }

    fn refresh(
        &self,
        anchors: ProductionDomClaimAnchorsV12,
    ) -> Result<(), ProductionDomClaimRuntimeErrorV12> {
        match (&self.authorization, anchors) {
            (
                ConsumedAuthorityV12::BitcoinV2(authority),
                ProductionDomClaimAnchorsV12::BitcoinV2(anchors),
            ) => authority
                .refresh_with_f7_v8(anchors)
                .map_err(|_| ProductionDomClaimRuntimeErrorV12::Anchors),
            (
                ConsumedAuthorityV12::Universal(authority),
                ProductionDomClaimAnchorsV12::Universal(anchors),
            ) => self
                .store
                .revalidate_consumed_f7_claim_authorization_v12(authority, anchors)
                .map_err(Into::into),
            _ => Err(ProductionDomClaimRuntimeErrorV12::Scope),
        }
    }

    fn accepted(
        &self,
    ) -> Result<AcceptedContractsSigningSessionV1, ProductionDomClaimRuntimeErrorV12> {
        match &self.authorization {
            ConsumedAuthorityV12::BitcoinV2(authority) => {
                self.store.resume_post_anchor_dom_claim_signing_session_v2(
                    &authority.authorization,
                    self.chain,
                )
            }
            ConsumedAuthorityV12::Universal(authority) => self
                .store
                .resume_post_anchor_dom_claim_signing_session_v12(authority, self.chain),
        }
        .map_err(Into::into)
    }

    fn ensure_signing_ingress<F: F6TransportPortV1>(
        &self,
        owner: &mut ProductionContractsV1<F>,
    ) -> Result<(), ProductionDomClaimRuntimeErrorV12> {
        let authority = self.store.prepare_operational_signing_transport_authority(
            self.chain,
            self.binding.session_id(),
            PurposeV1::ClaimAdaptor,
        )?;
        owner
            .relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .handoff_claim_signing_v19(authority)?;
        Ok(())
    }

    fn resume_pending<F: F6TransportPortV1>(
        &self,
        owner: &mut ProductionContractsV1<F>,
        expiry: TimelockSpec,
    ) -> Result<Option<RouteApplicationDispositionV2>, ProductionDomClaimRuntimeErrorV12> {
        match self.store.resume_outbound_dsc1(self.binding.session_id())? {
            OutboundDsc1RecoveryV1::None => Ok(None),
            OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if request.session_id() != &self.binding.session_id()
                    || request.sender_id() != &owner.local_participant
                    || !matches!(request.message_type(), 0x0c..=0x0f)
                {
                    return Err(ProductionDomClaimRuntimeErrorV12::Scope);
                }
                if request.message_type() != 0x0f {
                    self.ensure_signing_ingress(owner)?;
                }
                owner
                    .sign_commit_and_stage(*request, expiry)
                    .map(Some)
                    .map_err(Into::into)
            }
            OutboundDsc1RecoveryV1::Committed(committed) => {
                let message = SignedMessageV1::decode_exact(committed.signed_bytes())
                    .map_err(|_| ProductionDomClaimRuntimeErrorV12::Scope)?;
                if committed.session_id() != &self.binding.session_id()
                    || committed.sender_id() != &owner.local_participant
                    || !matches!(
                        message.unsigned().kind(),
                        MessageTypeV1::SigNonceCommit
                            | MessageTypeV1::SigNonceReveal
                            | MessageTypeV1::PartialSignature
                            | MessageTypeV1::AdaptorPreSignature
                    )
                {
                    return Err(ProductionDomClaimRuntimeErrorV12::Scope);
                }
                if message.unsigned().kind() != MessageTypeV1::AdaptorPreSignature {
                    self.ensure_signing_ingress(owner)?;
                }
                owner
                    .relay
                    .try_borrow_mut()
                    .map_err(|_| {
                        ProductionDomClaimRuntimeErrorV12::Outbound(
                            ProductionContractsOutboundErrorV1::OwnerBusy,
                        )
                    })?
                    .stage_store_outbound_dsc1(*committed, expiry)
                    .map(Some)
                    .map_err(|e| ProductionDomClaimRuntimeErrorV12::Outbound(e.into()))
            }
        }
    }

    fn finish_pre_signature<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        expiry: TimelockSpec,
    ) -> Result<ProductionDomClaimStepV12, ProductionDomClaimRuntimeErrorV12> {
        match &self.authorization {
            ConsumedAuthorityV12::BitcoinV2(consumed) => {
                let pre = self
                    .store
                    .reconstruct_post_anchor_dom_claim_pre_signature_v2(
                        &consumed.authorization,
                        self.chain,
                    )?;
                let transport = self
                    .store
                    .prepare_post_anchor_dom_claim_pre_signature_transport_authority_v2(
                        &consumed.authorization,
                        self.chain,
                    )?;
                // The native preparation above proves either the exact terminal
                // prefix or its unique accepted 0x0f descendant. A changed
                // transcript therefore means that native transport completed.
                if self
                    .store
                    .load_session(self.binding.session_id())?
                    .transcript_hash()
                    != *transport.terminal_transcript_hash()
                {
                    self.completed = Some(CompletedPreSignatureV12::BitcoinV2(pre));
                    return Ok(ProductionDomClaimStepV12::Complete);
                }
                self.remove_signing_ingress(owner, false)?;
                if let Some(request) = self
                    .store
                    .prepare_post_anchor_claim_pre_signature_dsc1_signing_request_v2(&transport)?
                {
                    return owner
                        .sign_commit_and_stage(request, expiry)
                        .map(ProductionDomClaimStepV12::Staged)
                        .map_err(Into::into);
                }
                owner.install_contracts_ingress(
                    PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(transport),
                )?;
                Ok(ProductionDomClaimStepV12::AwaitingPeer)
            }
            ConsumedAuthorityV12::Universal(consumed) => {
                let pre = self
                    .store
                    .reconstruct_post_anchor_dom_claim_pre_signature_v12(consumed, self.chain)?;
                let transport = self
                    .store
                    .prepare_f7_claim_pre_signature_transport_v12(consumed, self.chain)?;
                if self
                    .store
                    .load_session(self.binding.session_id())?
                    .transcript_hash()
                    != *transport.terminal_transcript_hash()
                {
                    self.completed = Some(CompletedPreSignatureV12::Universal(pre));
                    return Ok(ProductionDomClaimStepV12::Complete);
                }
                self.remove_signing_ingress(owner, true)?;
                if let Some(request) = self
                    .store
                    .prepare_f7_claim_pre_signature_dsc1_signing_request_v12(&transport)?
                {
                    return owner
                        .sign_commit_and_stage(request, expiry)
                        .map(ProductionDomClaimStepV12::Staged)
                        .map_err(Into::into);
                }
                owner.install_contracts_ingress(
                    PreparedContractsIngressV1::universal_claim_pre_signature_v12(transport),
                )?;
                Ok(ProductionDomClaimStepV12::AwaitingPeer)
            }
        }
    }

    fn remove_signing_ingress<F: F6TransportPortV1>(
        &self,
        owner: &mut ProductionContractsV1<F>,
        universal: bool,
    ) -> Result<(), ProductionDomClaimRuntimeErrorV12> {
        let Some(existing) = owner.take_contracts_ingress()? else {
            return Ok(());
        };
        let existing = match existing.into_operational_signing() {
            Ok(authority) => {
                if authority.session_id() == &self.binding.session_id()
                    && authority.purpose() == PurposeV1::ClaimAdaptor
                {
                    return Ok(());
                }
                owner.install_contracts_ingress(
                    PreparedContractsIngressV1::operational_signing(authority),
                )?;
                return Err(ProductionDomClaimRuntimeErrorV12::Scope);
            }
            Err(existing) => *existing,
        };
        // Replacing an already installed authority of this exact same phase is
        // safe: it is reissued from the same authenticated immutable artifact.
        if universal {
            match existing.into_universal_claim_pre_signature_v12() {
                Ok(authority) if authority.session_id() == &self.binding.session_id() => Ok(()),
                Ok(authority) => {
                    owner.install_contracts_ingress(
                        PreparedContractsIngressV1::universal_claim_pre_signature_v12(authority),
                    )?;
                    Err(ProductionDomClaimRuntimeErrorV12::Scope)
                }
                Err(existing) => {
                    owner.install_contracts_ingress(*existing)?;
                    Err(ProductionDomClaimRuntimeErrorV12::Scope)
                }
            }
        } else {
            match existing.into_post_anchor_claim_pre_signature_v2() {
                Ok(authority) if authority.session_id() == &self.binding.session_id() => Ok(()),
                Ok(authority) => {
                    owner.install_contracts_ingress(
                        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(authority),
                    )?;
                    Err(ProductionDomClaimRuntimeErrorV12::Scope)
                }
                Err(existing) => {
                    owner.install_contracts_ingress(*existing)?;
                    Err(ProductionDomClaimRuntimeErrorV12::Scope)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_substituted_identity_is_not_waiting_for_peer() {
        for error in [
            IdentityStoreError::AuthenticationFailed,
            IdentityStoreError::InvalidInput,
            IdentityStoreError::InvalidKey,
            IdentityStoreError::StoreRejected,
            IdentityStoreError::SigningFailed,
        ] {
            assert!(!ProductionDomClaimRuntimeErrorV12::Outbound(
                ProductionContractsOutboundErrorV1::Identity(error)
            )
            .is_retryable());
        }
        for error in [
            SessionStoreError::SessionNotFound,
            SessionStoreError::Conflict,
            SessionStoreError::Quarantined,
            SessionStoreError::Canonical,
            SessionStoreError::ClaimSigningAuthorityUnavailable,
        ] {
            assert!(!ProductionDomClaimRuntimeErrorV12::Store(error).is_retryable());
        }
        assert!(ProductionDomClaimRuntimeErrorV12::Outbound(
            ProductionContractsOutboundErrorV1::Identity(IdentityStoreError::StoreBusy)
        )
        .is_retryable());
        assert!(
            ProductionDomClaimRuntimeErrorV12::Store(SessionStoreError::Filesystem).is_retryable()
        );
    }
}
