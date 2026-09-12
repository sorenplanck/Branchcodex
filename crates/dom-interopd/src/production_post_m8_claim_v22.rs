//! The consumed Bitcoin M.8 result owns the native DOM claim round.
//! Core and DOM are reobserved before every nonce edge and before exposure.
use super::*;
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12;
use adapter_btc_live::{BitcoinCoreEvidenceCollectorV1, BitcoinCoreRpcClientV1};
use dom_adaptor::{AdaptorSecret, ContractKindV1};
use dom_final_claim_binding::{FinalClaimRoleBindingV1, OperationalM8ReadyBindingV2};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionPostM8ErrorV22 {
    #[error("M.8 DOM claim scope or signer ownership differs")]
    Scope,
    #[error("M.8 DOM signer was consumed during a failed open; restart required")]
    RestartRequired,
    #[error("M.8 DOM retained state refused the operation")]
    Store(#[from] SessionStoreError),
    #[error("M.8 Bitcoin funding observation refused")]
    Bitcoin(#[from] adapter_btc_live::LiveBitcoinError),
    #[error("M.8 real-chain F7 observation refused")]
    F7(#[from] f7_anchor_authority::F7AnchorAuthorityError),
    #[error("M.8 DOM claim signer or transport refused")]
    Claim(#[from] ProductionDomClaimRuntimeErrorV12),
}
impl ProductionPostM8ErrorV22 {
    pub(crate) fn retryable(&self) -> bool {
        use adapter_btc_live::LiveBitcoinError as B;
        use f7_anchor_authority::F7AnchorAuthorityError as F;
        match self {
            Self::Store(SessionStoreError::StoreBusy | SessionStoreError::Filesystem)
            | Self::Bitcoin(
                B::TransactionUnavailable | B::SnapshotChanged | B::InsufficientConfirmations,
            )
            | Self::F7(
                F::DomFundingAbsent
                | F::InsufficientFinality
                | F::Dom(dom_scriptless_chain_adapter::ChainAdapterError::TemporarilyUnavailable),
            ) => true,
            Self::Claim(error) => error.is_retryable(),
            _ => false,
        }
    }
}

pub(super) struct ProductionPostM8ClaimV22 {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
    bitcoin: Rc<BitcoinCoreRpcClientV1>,
    role: FinalClaimRoleBindingV1,
    ready: OperationalM8ReadyBindingV2,
    policy: adapter_btc::timelock::M8TimingPolicyV1,
    dom_funding: [u8; 32],
    bitcoin_funding: [u8; 32],
    transcript: [u8; 32],
    driver: Option<ProductionDomClaimRuntimeV12<ContractsNonceVaultV1>>,
    completion: Option<ProductionDomClaimCompletionV12>,
    exposed: bool,
}

impl ProductionPostM8ClaimV22 {
    fn observe(&self) -> Result<VerifiedF7AnchorAuthorizationV2, ProductionPostM8ErrorV22> {
        let evidence = BitcoinCoreEvidenceCollectorV1::new(self.bitcoin.as_ref())
            .collect_confirmed(
                self.bitcoin_funding,
                self.policy.bitcoin_finality.minimum_confirmations,
            )?;
        if evidence.txid() != self.bitcoin_funding {
            return Err(ProductionPostM8ErrorV22::Scope);
        }
        let verified = self.scanner.verify_f7_route_anchor_authority_v2(
            f7_anchor_authority::F7AnchorValidationRequestV2 {
                final_claim_role_binding: &self.role,
                ready_binding: &self.ready,
                timing_policy: &self.policy,
                expected_dom_funding_txid: self.dom_funding,
                expected_bitcoin_funding_txid: self.bitcoin_funding,
                expected_dom_claim_round_start_transcript_hash: self.transcript,
                bitcoin_funding_block_height: evidence.block_height(),
                canonical_bitcoin_funding_block: evidence.canonical_block_bytes(),
                bitcoin_ancestry_headers: evidence.ancestry_headers(),
                bitcoin_confirmation_headers: evidence.confirmation_headers(),
            },
        )?;
        // This consumer signs only DOM. The Bitcoin authorizations are not
        // reissued to a second participant or used to open another M.8 round.
        let (contracts, bitcoin) = verified.into_parts();
        drop(bitcoin);
        Ok(contracts)
    }

    fn step<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        now: u64,
    ) -> Result<(), ProductionPostM8ErrorV22> {
        if !Rc::ptr_eq(&self.store, &owner.store) || self.binding.session_id() != owner.session_id {
            return Err(ProductionPostM8ErrorV22::Scope);
        }
        if self.exposed || self.completion.is_some() {
            return Ok(());
        }
        let anchors = self.observe()?;
        let expiry = TimelockSpec::TimestampSeconds {
            value: now
                .checked_add(3600)
                .filter(|_| now != 0)
                .ok_or(ProductionPostM8ErrorV22::Scope)?,
        };
        let progress = self
            .driver
            .as_mut()
            .ok_or(ProductionPostM8ErrorV22::RestartRequired)?
            .step(
                owner,
                ProductionDomClaimAnchorsV12::BitcoinV2(anchors),
                expiry,
            )?;
        if matches!(progress, ProductionDomClaimStepV12::Complete) {
            let driver = self
                .driver
                .take()
                .ok_or(ProductionPostM8ErrorV22::RestartRequired)?;
            self.completion = Some(driver.finish()?);
        }
        Ok(())
    }

    pub(super) fn expose(
        &mut self,
        control: &mut dom_actuator::DomActuatorStoreV1,
        lease: dom_actuator::DomLeaseV1,
        chain: &TrustedChainIdV1,
        scope: dom_actuator::ScopedDomActionV1,
        secret: &AdaptorSecret,
        from_public: bool,
        prior_now: u64,
    ) -> Result<(), ProductionF7FinalClaimErrorV14> {
        use ProductionF7FinalClaimErrorV14 as Error;
        if self.binding != scope.binding() || self.chain != *chain || self.exposed {
            return Err(Error::Scope);
        }
        let source = if from_public {
            dom_final_claim_binding::FinalClaimSecretSourceV1::VerifiedCounterpartyClaim
        } else {
            dom_final_claim_binding::FinalClaimSecretSourceV1::LocalOrigin
        };
        if self.role.secret_source() != source {
            return Err(Error::Scope);
        }
        let anchors = self.observe().map_err(|error| {
            if error.retryable() {
                Error::AdaptationRequired
            } else {
                Error::Scope
            }
        })?;
        let height = anchors.dom_observed_tip_height();
        let Some(ProductionDomClaimCompletionV12::BitcoinV2 { authority, .. }) =
            self.completion.as_ref()
        else {
            return Err(Error::AdaptationRequired);
        };
        self.store
            .revalidate_consumed_with_f7_v8(&authority.authorization, anchors)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|t| u64::try_from(t.as_millis()).ok())
            .filter(|n| *n >= prior_now && *n != 0)
            .ok_or(Error::Scope)?;
        let actuator = DomContractsActuatorV1::bind(self.store.as_ref(), self.binding)?;
        let (capability, _) = actuator.authorize_post_m8_claim_broadcast_v22(
            control,
            lease,
            scope,
            chain,
            &authority.authorization,
            now,
        )?;
        let claim = self.store.finalize_retained_post_m8_claim_v22(
            &authority.authorization,
            *chain,
            secret,
            height,
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|t| u64::try_from(t.as_millis()).ok())
            .filter(|n| *n >= now && *n != 0)
            .ok_or(Error::Scope)?;
        let _prepared = actuator.persist_final_claim_exposure_v2(
            control,
            lease,
            chain,
            dom_actuator::DomFinalClaimPersistenceRequestV2::new(
                capability,
                &authority.authorization,
                claim,
                height,
                now,
            ),
        )?;
        self.exposed = true;
        // Release the linear live signer before the child rehydrates its
        // execution-only authority from the now-durable exact exposure.
        self.completion = None;
        Ok(())
    }
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    /// Takes the result of the actual child-owned M.8 round exactly once.
    /// Lookup/observation failures precede movement of private capabilities.
    pub(crate) fn step_post_m8_claim_v22(
        &mut self,
        material: &mut ProductionBoundDomSharedOutputV12,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        pending: &mut Option<ProductionContractsConsumedPostAnchorV2>,
        scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
        bitcoin: Rc<BitcoinCoreRpcClientV1>,
        now: u64,
    ) -> Result<bool, ProductionPostM8ErrorV22> {
        use ProductionPostM8ErrorV22 as Error;
        self.validate_dom_binding(binding)
            .map_err(|_| Error::Scope)?;
        if chain.as_bytes() != &binding.chain_id() {
            return Err(Error::Scope);
        }
        let shared = Rc::clone(&self.claim_owner_v21);
        let mut owner = shared.try_borrow_mut().map_err(|_| Error::Scope)?;
        if owner.m8_start_failed {
            return Err(Error::RestartRequired);
        }
        if owner.m8.is_none() {
            let Some(authorization) = pending.as_ref() else {
                return Ok(false);
            };
            if !Rc::ptr_eq(&self.store, &authorization.store) || owner.pump.is_some() {
                return Err(Error::Scope);
            }
            authorization.revalidate().map_err(|_| Error::Scope)?;
            let auth = &authorization.authorization;
            if auth.session_id() != &binding.session_id()
                || auth.terms_hash() != &binding.terms_digest()
            {
                return Err(Error::Scope);
            }
            let (role, ready, policy) = self
                .store
                .resume_operational_m8_bilateral_bindings_v11(&chain, binding.session_id())?;
            let (transaction, roster, kernel_index) = self
                .store
                .retained_post_m8_claim_template_v22(auth, chain)?;
            let mut pump = ProductionPostM8ClaimV22 {
                store: Rc::clone(&self.store),
                binding,
                chain,
                scanner,
                bitcoin,
                role,
                ready,
                policy,
                dom_funding: *auth.dom_funding_id(),
                bitcoin_funding: *auth.bitcoin_funding_id(),
                transcript: *auth.round_start_transcript_hash(),
                driver: None,
                completion: None,
                exposed: false,
            };
            let fresh = pump.observe()?;
            self.store.revalidate_consumed_with_f7_v8(auth, fresh)?;
            if material.vault.is_none()
                || material.claim_share_v18.is_none()
                || material.funding_signer_v20.is_some()
                || material.refund_signer_v18.is_some()
            {
                return Err(Error::Scope);
            }
            owner.m8_start_failed = true;
            let vault = material.vault.take().ok_or(Error::RestartRequired)?;
            let share = material
                .claim_share_v18
                .take()
                .ok_or(Error::RestartRequired)?;
            let authorization = pending.take().ok_or(Error::RestartRequired)?;
            pump.driver = Some(
                self.start_dom_claim_runtime_v2(
                    binding,
                    chain,
                    vault,
                    share,
                    authorization,
                    ProductionDomClaimTemplateV12 {
                        contract_kind: ContractKindV1::WitnessOrTimeout,
                        roster,
                        transaction,
                        kernel_index,
                    },
                )
                .map_err(|_| Error::RestartRequired)?,
            );
            owner.m8 = Some(pump);
            owner.m8_start_failed = false;
        }
        owner
            .m8
            .as_mut()
            .ok_or(Error::RestartRequired)?
            .step(self, now)?;
        Ok(true)
    }
}
