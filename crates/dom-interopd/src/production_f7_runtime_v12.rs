//! Concrete selected-chain F7 observation and retained native claim pumping.
//!
//! The Store supplies the exact DOM transaction and immutable claim predecessor.
//! Every participant operation is preceded by fresh concrete observations. XMR
//! construction here does not authorize route admission or collateral funding.

#[path = "production_xmr_claim_bootstrap_v23.rs"]
mod xmr_claim_bootstrap_v23;

use super::{
    ProductionContractsV1, ProductionDomClaimAnchorsV12, ProductionDomClaimCompletionV12,
    ProductionDomClaimRuntimeErrorV12, ProductionDomClaimRuntimeV12, ProductionDomClaimStepV12,
};
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use deployment_registry::{
    ResolvedEvmDeploymentV1, ResolvedMoneroDeploymentV1, ResolvedSolanaDeploymentV1,
};
use dom_actuator::{DomParticipantSigningShareV1, DomSessionBindingV1};
use dom_adaptor::{NonceVaultV1, RestartArtifactRecoveryVaultV1, TrustedChainIdV1};
use dom_final_claim_binding::{FinalClaimRoleBindingV1, OperationalM8ReadyBindingV2};
use dom_scriptless_crypto::FrozenSharedOutputV1;
use dom_scriptless_store::{
    ContractsSessionStoreV1, F7AnchorRequestBindingV12, PreparedF7FundingGateV12,
    SessionStoreError, XmrRecoveryCustodyV11,
};
use f7_anchor_authority::families_v11::{
    DomXmrAnchorValidationRequestV11, DomXmrBoundedAnchorValidationRequestV23,
    EvmFundingAuthorityV11, F7ExternalFundingV12, F7FamilyAuthorityErrorV11,
    SolanaFundingAuthorityV11, VerifiedF7AnchorAuthorizationV12, XmrFundingObservationRequestV11,
};
use kaystra_core::{types::LockMechanism, SettlementTermsV1};
use relay::TimelockSpec;
use route_transport::{F6TransportPortV1, RouteApplicationDispositionV2};
use solana_profile::{SolanaAdapterProfileV1, ValidatedSolanaSetup};
use solana_types::SolanaSignature;
use std::{rc::Rc, time::Duration};
use xmr_dleq_sigma::BoundCrossCurveProofV1;
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_refund_policy::compensation::XmrCompensationPolicyV11;
use xmr_secret_store::EncryptedSqliteSecretStore;
use xmr_setup_profile::{ValidatedXmrSetup, XmrAdapterProfileV1};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionF7RuntimeErrorV12 {
    #[error("selected F7 observer or retained claim owner has a different scope")]
    Scope,
    #[error("native selected-chain F7 verifier rejected the response")]
    Evidence(#[from] F7FamilyAuthorityErrorV11),
    #[error("native F7 Store rejected retained funding or claim ancestry")]
    Store(#[from] SessionStoreError),
    #[error("native F7 participant driver rejected the operation")]
    Claim(#[from] ProductionDomClaimRuntimeErrorV12),
    #[error("XMR recovery custody failed authentication")]
    Custody,
    #[error("the selected XMR observation executor could not start")]
    Executor,
    #[error("native claim ownership was already consumed by a failed start")]
    Consumed,
    #[error("native claim custody was consumed during a failed start; authenticated process restart required")]
    RequiresRestart(#[source] Option<ProductionDomClaimRuntimeErrorV12>),
}

impl ProductionF7RuntimeErrorV12 {
    pub(crate) fn retryable_v20(&self) -> bool {
        match self {
            Self::Claim(error) => error.is_retryable(),
            Self::Evidence(F7FamilyAuthorityErrorV11::Unavailable)
            | Self::Store(SessionStoreError::StoreBusy | SessionStoreError::Filesystem) => true,
            _ => false,
        }
    }
}

/// Missing transactions, insufficient finality and service failures have
/// distinct statuses. A substituted transaction never reaches any of them.
pub(crate) enum ProductionF7ObservationV12 {
    FundingAbsent,
    AwaitingFinality,
    TemporarilyUnavailable,
    Verified(VerifiedF7AnchorAuthorizationV12),
}

/// Selected, authenticated observation inputs without a caller-supplied txid.
/// Only the retained child custody reader supplies the missing exact identity.
pub(crate) enum ProductionF7ObserverPlanV20 {
    Evm {
        authority: EvmFundingAuthorityV11,
        terms_hash: [u8; 32],
        minimum_remaining_seconds: u64,
    },
    Solana {
        authority: SolanaFundingAuthorityV11,
        terms_hash: [u8; 32],
    },
}
impl ProductionF7ObserverPlanV20 {
    pub(crate) fn bind(
        self,
        id: crate::production_child_router::ProductionRetainedFundingIdV20,
    ) -> Result<ProductionSelectedF7ObserverV12, ProductionF7RuntimeErrorV12> {
        use crate::production_child_router::ProductionRetainedFundingIdV20 as Id;
        let (selected, terms_hash) = match (self, id) {
            (
                Self::Evm {
                    authority,
                    terms_hash,
                    minimum_remaining_seconds,
                },
                Id::Evm(txid),
            ) if txid != [0; 32] => (
                SelectedObserverV12::Evm {
                    authority,
                    txid,
                    minimum_remaining_seconds,
                },
                terms_hash,
            ),
            (
                Self::Solana {
                    authority,
                    terms_hash,
                },
                Id::Solana(signature),
            ) if signature.0 != [0; 64] => (
                SelectedObserverV12::Solana {
                    authority,
                    signature,
                },
                terms_hash,
            ),
            _ => return Err(ProductionF7RuntimeErrorV12::Scope),
        };
        Ok(ProductionSelectedF7ObserverV12 {
            selected,
            terms_hash,
            executor: None,
        })
    }
}

enum SelectedObserverV12 {
    Evm {
        authority: EvmFundingAuthorityV11,
        txid: [u8; 32],
        minimum_remaining_seconds: u64,
    },
    Solana {
        authority: SolanaFundingAuthorityV11,
        signature: SolanaSignature,
    },
    Monero(Box<ProductionXmrF7InputsV12>),
}

/// Only public verified collateral is shared; neither variant is a signing grant.
pub(crate) enum ProductionXmrF7GraphV23 {
    Legacy {
        ready: OperationalM8ReadyBindingV2,
        collateral: Rc<FrozenSharedOutputV1>,
    },
    Native(Rc<xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12>),
}

/// Existing native XMR resources are handed over once. This does not open a
/// second secret database, create shares, or obtain a different sidecar key.
pub(crate) struct ProductionXmrF7InputsV12 {
    pub(crate) setup: ValidatedXmrSetup,
    pub(crate) profile: XmrAdapterProfileV1,
    pub(crate) deployment: ResolvedMoneroDeploymentV1,
    pub(crate) daemon_urls: Vec<String>,
    pub(crate) policy: XmrCompensationPolicyV11,
    pub(crate) graph: ProductionXmrF7GraphV23,
    pub(crate) refund_share_proof: BoundCrossCurveProofV1,
    pub(crate) custody: Rc<XmrRecoveryCustodyV11>,
    pub(crate) sidecar: Rc<std::cell::RefCell<BlockingUdsSidecarPort>>,
    pub(crate) secrets: Rc<EncryptedSqliteSecretStore>,
}

/// One selected native verifier, with no unrelated Bitcoin/EVM dependency.
pub(crate) struct ProductionSelectedF7ObserverV12 {
    selected: SelectedObserverV12,
    terms_hash: [u8; 32],
    executor: Option<tokio::runtime::Runtime>,
}

impl ProductionSelectedF7ObserverV12 {
    pub(crate) fn evm(
        deployment: &ResolvedEvmDeploymentV1,
        terms: &SettlementTermsV1,
        endpoint: &str,
        timeout_seconds: u64,
        exact_funding_txid: [u8; 32],
        minimum_remaining_seconds: u64,
    ) -> Result<Self, ProductionF7RuntimeErrorV12> {
        if exact_funding_txid == [0; 32] || minimum_remaining_seconds == 0 {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        let authority = EvmFundingAuthorityV11::new(deployment, terms, endpoint, timeout_seconds)?;
        Ok(Self {
            selected: SelectedObserverV12::Evm {
                authority,
                txid: exact_funding_txid,
                minimum_remaining_seconds,
            },
            terms_hash: terms
                .terms_hash()
                .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?,
            executor: None,
        })
    }

    pub(crate) fn solana(
        deployment: &ResolvedSolanaDeploymentV1,
        terms: &SettlementTermsV1,
        setup: &ValidatedSolanaSetup,
        profile: SolanaAdapterProfileV1,
        endpoints: &[String],
        exact_funding_signature: SolanaSignature,
    ) -> Result<Self, ProductionF7RuntimeErrorV12> {
        if exact_funding_signature.0 == [0; 64] {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        let authority =
            SolanaFundingAuthorityV11::new(deployment, terms, setup, profile, endpoints)?;
        Ok(Self {
            selected: SelectedObserverV12::Solana {
                authority,
                signature: exact_funding_signature,
            },
            terms_hash: terms
                .terms_hash()
                .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?,
            executor: None,
        })
    }

    /// Observation is deliberately separate from XMR admission. The root must
    /// retain its native recovery-design refusal until that design is ratified.
    pub(crate) fn monero(
        terms: &SettlementTermsV1,
        inputs: ProductionXmrF7InputsV12,
    ) -> Result<Self, ProductionF7RuntimeErrorV12> {
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?;
        if terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
            || inputs.setup.terms_hash() != terms_hash
            || inputs.custody.scope().binding.terms_hash != terms_hash
            || inputs.daemon_urls.is_empty()
            || inputs.daemon_urls.len() > 16
        {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        inputs
            .custody
            .revalidate()
            .map_err(|_| ProductionF7RuntimeErrorV12::Custody)?;
        inputs
            .policy
            .validate_for(terms)
            .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProductionF7RuntimeErrorV12::Executor)?;
        Ok(Self {
            selected: SelectedObserverV12::Monero(Box::new(inputs)),
            terms_hash,
            executor: Some(executor),
        })
    }

    fn require_role(
        &self,
        role: &FinalClaimRoleBindingV1,
    ) -> Result<(), ProductionF7RuntimeErrorV12> {
        let terms = role.terms();
        if terms
            .terms_hash()
            .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?
            != self.terms_hash
            || !matches!(
                (&self.selected, terms.counterparty_leg.mechanism),
                (
                    SelectedObserverV12::Evm { .. },
                    LockMechanism::ConditionLock
                ) | (
                    SelectedObserverV12::Solana { .. },
                    LockMechanism::CrossCurveConditionLock
                ) | (
                    SelectedObserverV12::Monero(_),
                    LockMechanism::CrossCurveSharedSpend
                )
            )
        {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        Ok(())
    }

    fn observe(
        &mut self,
        scanner: &ProductionDomF7ScannerAuthorityV1,
        binding: &F7AnchorRequestBindingV12,
    ) -> Result<ProductionF7ObservationV12, ProductionF7RuntimeErrorV12> {
        self.require_role(binding.role())?;
        let result = match &mut self.selected {
            SelectedObserverV12::Evm {
                authority,
                txid,
                minimum_remaining_seconds,
            } => match authority.observe(*txid, *minimum_remaining_seconds) {
                Ok(Some(funding)) => scanner.verify_f7_anchor_authority_v12(
                    binding.role(),
                    binding.dom_funding_txid(),
                    binding.round_start_transcript_hash(),
                    F7ExternalFundingV12::Evm(funding),
                ),
                Ok(None) => Err(F7FamilyAuthorityErrorV11::FundingAbsent),
                Err(error) => Err(error),
            },
            SelectedObserverV12::Solana {
                authority,
                signature,
            } => match authority.observe(*signature) {
                Ok(Some(funding)) => scanner.verify_f7_anchor_authority_v12(
                    binding.role(),
                    binding.dom_funding_txid(),
                    binding.round_start_transcript_hash(),
                    F7ExternalFundingV12::Solana(funding),
                ),
                Ok(None) => Err(F7FamilyAuthorityErrorV11::FundingAbsent),
                Err(error) => Err(error),
            },
            SelectedObserverV12::Monero(inputs) => {
                let executor = self
                    .executor
                    .as_ref()
                    .ok_or(ProductionF7RuntimeErrorV12::Executor)?;
                let ProductionXmrF7InputsV12 {
                    setup,
                    profile,
                    deployment,
                    daemon_urls,
                    policy,
                    graph: retained_graph,
                    refund_share_proof,
                    custody,
                    sidecar,
                    secrets,
                } = inputs.as_mut();
                let mut sidecar = sidecar.try_borrow_mut().map_err(|_| {
                    ProductionF7RuntimeErrorV12::Evidence(F7FamilyAuthorityErrorV11::Unavailable)
                })?;
                // Retain the custody loan across both observations. Native
                // DOM HTTP must run outside block_on; promotion rechecks the
                // exact XMR request and does not renew the observation's age.
                custody
                    .with_graph(|graph| {
                        let xmr_request = || XmrFundingObservationRequestV11 {
                            terms: binding.role().terms(),
                            setup,
                            profile,
                            deployment,
                            daemon_urls,
                        };
                        match retained_graph {
                            ProductionXmrF7GraphV23::Legacy { ready, collateral } => executor
                                .block_on(async {
                                    let request = DomXmrAnchorValidationRequestV11 {
                                        role: binding.role(),
                                        ready,
                                        compensation_policy: policy,
                                        recovery_graph: graph,
                                        collateral: collateral.as_ref(),
                                        refund_share_proof,
                                        expected_dom_funding_txid: binding.dom_funding_txid(),
                                        claim_round_start_transcript_hash: binding
                                            .round_start_transcript_hash(),
                                        xmr: xmr_request(),
                                    };
                                    tokio::time::timeout(
                                        Duration::from_secs(60),
                                        scanner.verify_f7_xmr_anchor_authority_v12(
                                            request,
                                            &mut sidecar,
                                            secrets.as_ref(),
                                        ),
                                    )
                                    .await
                                    .unwrap_or(Err(F7FamilyAuthorityErrorV11::Unavailable))
                                }),
                            ProductionXmrF7GraphV23::Native(produced) => {
                                if produced.graph().graph_digest() != graph.graph_digest() {
                                    return Err(F7FamilyAuthorityErrorV11::Binding);
                                }
                                let funding = executor.block_on(async {
                                    tokio::time::timeout(
                                        Duration::from_secs(60),
                                        f7_anchor_authority::families_v11::verify_xmr_funding_v11(
                                            xmr_request(),
                                            &mut sidecar,
                                            secrets.as_ref(),
                                        ),
                                    )
                                    .await
                                    .unwrap_or(Err(F7FamilyAuthorityErrorV11::Unavailable))
                                })?;
                                // Blocking DOM RPC is bounded by its own client.
                                // The synchronous verifier rejects XMR evidence
                                // that aged out while that RPC was in progress.
                                scanner.verify_f7_xmr_bounded_anchor_authority_v23(
                                    DomXmrBoundedAnchorValidationRequestV23 {
                                        role: binding.role(),
                                        produced: produced.as_ref(),
                                        refund_share_proof,
                                        expected_dom_funding_txid: binding.dom_funding_txid(),
                                        claim_round_start_transcript_hash: binding
                                            .round_start_transcript_hash(),
                                        xmr: xmr_request(),
                                    },
                                    funding,
                                )
                            }
                        }
                    })
                    .map_err(|_| ProductionF7RuntimeErrorV12::Custody)?
            }
        };
        classify_observation(result)
    }
}

fn classify_observation(
    result: Result<VerifiedF7AnchorAuthorizationV12, F7FamilyAuthorityErrorV11>,
) -> Result<ProductionF7ObservationV12, ProductionF7RuntimeErrorV12> {
    match result {
        Ok(value) => Ok(ProductionF7ObservationV12::Verified(value)),
        Err(F7FamilyAuthorityErrorV11::FundingAbsent) => {
            Ok(ProductionF7ObservationV12::FundingAbsent)
        }
        Err(F7FamilyAuthorityErrorV11::InsufficientFinality) => {
            Ok(ProductionF7ObservationV12::AwaitingFinality)
        }
        Err(F7FamilyAuthorityErrorV11::Unavailable) => {
            Ok(ProductionF7ObservationV12::TemporarilyUnavailable)
        }
        Err(error) => Err(ProductionF7RuntimeErrorV12::Evidence(error)),
    }
}

/// Sample the trusted wall clock after blocking observations, without renewing
/// the participant's lease. The actuator still checks the durable fencing
/// generation; this guard refuses an already expired local capability before
/// any secret-bearing operation is called.
fn exposure_time_after_observation(
    previous_now: u64,
    lease: dom_actuator::DomLeaseV1,
    since_epoch: Option<Duration>,
) -> Result<u64, super::ProductionF7FinalClaimErrorV14> {
    use super::ProductionF7FinalClaimErrorV14 as Error;
    let now = since_epoch
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|value| previous_now != 0 && *value >= previous_now)
        .ok_or(Error::Scope)?;
    if now > lease.lease_until_unix_ms() {
        return Err(dom_actuator::DomActuatorError::LeaseExpired.into());
    }
    Ok(now)
}

#[must_use]
pub(crate) enum ProductionF7StepV12 {
    FundingAbsent,
    AwaitingFinality,
    TemporarilyUnavailable,
    Started,
    AwaitingPeer,
    Staged(RouteApplicationDispositionV2),
    Complete,
}

/// A same-Store post-funding owner; fresh and restarted processes use the
/// identical native gate, issuance and nonce-recovery paths.
pub(crate) struct ProductionF7RuntimeV12<Vault: NonceVaultV1> {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    gate: PreparedF7FundingGateV12,
    scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
    observer: ProductionSelectedF7ObserverV12,
    initial_signer: Option<(Vault, DomParticipantSigningShareV1)>,
    claim: Option<ProductionDomClaimRuntimeV12<Vault>>,
    completion: Option<ProductionDomClaimCompletionV12>,
    completed: bool,
    restart_required: bool,
}

impl<F: F6TransportPortV1> ProductionContractsV1<F> {
    pub(crate) fn step_bootstrapped_f7_claim_v20(
        &mut self,
        material: &mut crate::production_dom_shared_bootstrap_v12::ProductionBoundDomSharedOutputV12,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
        observer: &mut Option<ProductionF7ObserverPlanV20>,
        funding: crate::production_child_router::ProductionRetainedFundingIdV20,
        now: u64,
    ) -> Result<(), ProductionF7RuntimeErrorV12> {
        use ProductionF7RuntimeErrorV12 as Error;
        self.validate_dom_binding(binding)
            .map_err(|_| Error::Scope)?;
        let head = self.store.load_session(binding.session_id())?;
        // Signing may not obstruct refund execution or restart recovery of an
        // already exposed claim. Those are driven by their durable children.
        if head.irreversible().adaptor_secret_exposed
            || matches!(
                head.phase(),
                dom_scriptless_store::SessionPhaseV1::RefundBroadcast
                    | dom_scriptless_store::SessionPhaseV1::Refunded
                    | dom_scriptless_store::SessionPhaseV1::FailedClosed
            )
        {
            return Ok(());
        }
        // An exposure file may have been published just before the native
        // successor CAS. Inspect authenticated custody as well as the head:
        // recovery must not start another round during that crash prefix.
        if let Some(facts) = self.store.f7_claim_verification_facts_v15(
            chain,
            binding.session_id(),
            self.local_participant,
        )? {
            if facts.receiver_id() != self.local_participant
                && self
                    .store
                    .f7_final_claim_progress_v14(chain, binding.session_id())?
                    != dom_scriptless_store::F7FinalClaimProgressV14::NeedsAdaptation
            {
                return Ok(());
            }
        }
        // Share the same linear signer completion with the settlement child.
        let shared = Rc::clone(&self.claim_owner_v21);
        let mut claim_owner = shared.try_borrow_mut().map_err(|_| Error::Scope)?;
        if claim_owner.pump.is_none() {
            let Some(gate) = self
                .store
                .retained_f7_funding_gate_v19(chain, binding.session_id())?
            else {
                return Ok(());
            };
            match self.store.resume_f7_committed_funding_v12(&gate) {
                Ok(_) => {}
                Err(SessionStoreError::SessionNotFound) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            if material.funding_signer_v20.is_some()
                || material.refund_signer_v18.is_some()
                || material.vault.is_none()
                || material.claim_share_v18.is_none()
            {
                return Err(Error::Scope);
            }
            let observer = observer.take().ok_or(Error::Consumed)?.bind(funding)?;
            let vault = material.vault.take().ok_or(Error::Consumed)?;
            let share = material.claim_share_v18.take().ok_or(Error::Consumed)?;
            claim_owner.pump = Some(
                self.open_f7_claim_pump_v12(binding, chain, scanner, observer, vault, share)
                    // The unique private capabilities have moved. Any failed open
                    // must reopen their authenticated custody, never retry with
                    // empty in-memory owners or generate replacement shares.
                    .map_err(|_| Error::RequiresRestart(None))?,
            );
        }
        let pump = claim_owner.pump.as_mut().ok_or(Error::Consumed)?;
        // A new retained external identity cannot silently retarget an issued
        // adaptor round. Only absence is a wait condition.
        match (&pump.observer.selected, funding) {
            (
                SelectedObserverV12::Evm { txid, .. },
                crate::production_child_router::ProductionRetainedFundingIdV20::Evm(id),
            ) if *txid == id => {}
            (
                SelectedObserverV12::Solana { signature, .. },
                crate::production_child_router::ProductionRetainedFundingIdV20::Solana(id),
            ) if *signature == id => {}
            _ => return Err(Error::Scope),
        }
        let expiry = TimelockSpec::TimestampSeconds {
            value: now
                .checked_add(3600)
                .filter(|_| now != 0)
                .ok_or(Error::Scope)?,
        };
        let _progress = pump.step(self, expiry)?;
        Ok(())
    }

    /// Open only after the exact DOM funding commit exists. An absent or
    /// corrupted commit is a hard error here, never an unknown RPC transaction.
    pub(crate) fn open_f7_claim_pump_v12<Vault>(
        &self,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        scanner: Rc<ProductionDomF7ScannerAuthorityV1>,
        observer: ProductionSelectedF7ObserverV12,
        vault: Vault,
        share: DomParticipantSigningShareV1,
    ) -> Result<ProductionF7RuntimeV12<Vault>, ProductionF7RuntimeErrorV12>
    where
        Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
    {
        self.validate_dom_binding(binding)
            .map_err(|_| ProductionF7RuntimeErrorV12::Scope)?;
        if chain.as_bytes() != &binding.chain_id() {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        let gate = self
            .store
            .resume_f7_funding_gate_v12(chain, self.session_id)?;
        let request = self.store.f7_anchor_request_binding_v12(&gate, chain)?;
        observer.require_role(request.role())?;
        Ok(ProductionF7RuntimeV12 {
            store: Rc::clone(&self.store),
            binding,
            chain,
            gate,
            scanner,
            observer,
            initial_signer: Some((vault, share)),
            claim: None,
            completion: None,
            completed: false,
            restart_required: false,
        })
    }
}

impl<Vault> ProductionF7RuntimeV12<Vault>
where
    Vault: NonceVaultV1 + RestartArtifactRecoveryVaultV1,
{
    pub(crate) fn step<F: F6TransportPortV1>(
        &mut self,
        owner: &mut ProductionContractsV1<F>,
        expiry: TimelockSpec,
    ) -> Result<ProductionF7StepV12, ProductionF7RuntimeErrorV12> {
        if !Rc::ptr_eq(&self.store, &owner.store) || self.binding.session_id() != owner.session_id {
            return Err(ProductionF7RuntimeErrorV12::Scope);
        }
        // A previous startup attempt consumed the unique share/vault. This is
        // terminal for this owner even when its original cause was transient.
        // Refuse before querying RPCs, so an unavailable node cannot disguise
        // that custody must be recovered by an authenticated process reopen.
        if self.restart_required {
            return Err(ProductionF7RuntimeErrorV12::RequiresRestart(None));
        }
        if self.completed {
            return Ok(ProductionF7StepV12::Complete);
        }
        let claim_authority_recent = self
            .claim
            .as_ref()
            .is_some_and(|claim| claim.universal_authority_recent_v12());
        let anchors = if claim_authority_recent {
            None
        } else {
            let request = self
                .store
                .f7_anchor_request_binding_v12(&self.gate, self.chain)?;
            Some(
                match self.observer.observe(self.scanner.as_ref(), &request)? {
                    ProductionF7ObservationV12::FundingAbsent => {
                        return Ok(ProductionF7StepV12::FundingAbsent)
                    }
                    ProductionF7ObservationV12::AwaitingFinality => {
                        return Ok(ProductionF7StepV12::AwaitingFinality)
                    }
                    ProductionF7ObservationV12::TemporarilyUnavailable => {
                        return Ok(ProductionF7StepV12::TemporarilyUnavailable)
                    }
                    ProductionF7ObservationV12::Verified(value) => value,
                },
            )
        };
        if self.claim.is_none() {
            let anchors = anchors.ok_or(ProductionF7RuntimeErrorV12::Scope)?;
            // Arm the terminal state before moving either capability. Only a
            // successful retained native owner may clear it. Earlier observer
            // failures leave both the state and original custody untouched.
            self.restart_required = true;
            let (vault, share) = self
                .initial_signer
                .take()
                .ok_or(ProductionF7RuntimeErrorV12::RequiresRestart(None))?;
            self.claim = Some(
                owner
                    .start_dom_claim_runtime_v12(
                        self.binding,
                        self.chain,
                        vault,
                        share,
                        &self.gate,
                        anchors,
                    )
                    .map_err(|error| ProductionF7RuntimeErrorV12::RequiresRestart(Some(error)))?,
            );
            self.restart_required = false;
            return Ok(ProductionF7StepV12::Started);
        }
        let claim = self
            .claim
            .as_mut()
            .ok_or(ProductionF7RuntimeErrorV12::Consumed)?;
        let claim_anchors = anchors
            .map(ProductionDomClaimAnchorsV12::Universal)
            .unwrap_or(ProductionDomClaimAnchorsV12::UniversalRecent);
        match claim.step(owner, claim_anchors, expiry)? {
            ProductionDomClaimStepV12::AwaitingPeer => Ok(ProductionF7StepV12::AwaitingPeer),
            ProductionDomClaimStepV12::Staged(value) => Ok(ProductionF7StepV12::Staged(value)),
            ProductionDomClaimStepV12::Complete => {
                let claim = self
                    .claim
                    .take()
                    .ok_or(ProductionF7RuntimeErrorV12::Consumed)?;
                self.completion = Some(claim.finish()?);
                self.completed = true;
                Ok(ProductionF7StepV12::Complete)
            }
        }
    }

    /// First adaptation for the concrete settlement child. Both chain
    /// anchors are reobserved and the process-bound F7 authority is refreshed
    /// immediately before any secret-bearing transaction becomes durable.
    pub(crate) fn expose_for_child_v21(
        &mut self,
        control: &mut dom_actuator::DomActuatorStoreV1,
        lease: dom_actuator::DomLeaseV1,
        chain: &TrustedChainIdV1,
        scope: dom_actuator::ScopedDomActionV1,
        secret: &dom_adaptor::AdaptorSecret,
        from_public_claim: bool,
        previous_now: u64,
    ) -> Result<(), super::ProductionF7FinalClaimErrorV14> {
        use super::ProductionF7FinalClaimErrorV14 as Error;
        if self.binding != scope.binding() || self.chain != *chain || self.restart_required {
            return Err(Error::Scope);
        }
        if !self.completed {
            return Err(Error::AdaptationRequired);
        }
        let Some(ProductionDomClaimCompletionV12::Universal { authority, .. }) =
            self.completion.as_ref()
        else {
            return Err(Error::AdaptationRequired);
        };
        let request = self
            .store
            .f7_anchor_request_binding_v12(&self.gate, self.chain)?;
        // The new source remains explicitly public. A retained/local T can
        // never substitute for the downstream DOM observation gate.
        use dom_final_claim_binding::FinalClaimSecretSourceV1 as Source;
        if !matches!(
            (request.role().secret_source(), from_public_claim),
            (Source::LocalOrigin, false)
                | (Source::VerifiedCounterpartyClaim, true)
                | (Source::VerifiedDownstreamDomClaimV23, true)
        ) {
            return Err(Error::Scope);
        }
        let anchors = match self.observer.observe(self.scanner.as_ref(), &request)? {
            ProductionF7ObservationV12::Verified(anchors) => anchors,
            ProductionF7ObservationV12::FundingAbsent
            | ProductionF7ObservationV12::AwaitingFinality
            | ProductionF7ObservationV12::TemporarilyUnavailable => {
                return Err(Error::AdaptationRequired)
            }
        };
        self.store
            .revalidate_consumed_f7_claim_authorization_v12(authority, anchors)?;
        let height = self
            .store
            .load_session(self.binding.session_id())?
            .chain()
            .tip_height;
        // Observation can block on RPC. Never reuse the pre-observation clock
        // for an irreversible write guarded by an expiring actuator lease.
        let now = exposure_time_after_observation(
            previous_now,
            lease,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok(),
        )?;
        let actuator =
            dom_actuator::DomContractsActuatorV1::bind(self.store.as_ref(), self.binding)?;
        let _submission = actuator.prepare_and_expose_f7_final_claim_v14(
            control,
            lease,
            chain,
            dom_actuator::DomF7FinalClaimRequestV14 {
                scope,
                authority,
                secret,
                validation_height: height,
                now_unix_ms: now,
            },
        )?;
        Ok(())
    }

    pub(crate) fn take_completion(&mut self) -> Option<ProductionDomClaimCompletionV12> {
        self.completion.take()
    }

    /// Consume the completed native round in the final-claim actuator and
    /// outbox. Reobserve the selected chain immediately before first exposure;
    /// after exposure, recover bytes without asking for the secret or new F7.
    pub(crate) fn step_final_claim_v14<'a, F: F6TransportPortV1>(
        &'a mut self,
        owner: &mut ProductionContractsV1<F>,
        mut request: super::ProductionF7FinalClaimRequestV14<'a>,
        secret: Option<&'a dom_adaptor::AdaptorSecret>,
    ) -> Result<super::ProductionF7FinalClaimStepV14, super::ProductionF7FinalClaimErrorV14> {
        use super::{
            ProductionF7FinalClaimErrorV14 as Error, ProductionF7FinalClaimStepV14 as Step,
        };
        if !Rc::ptr_eq(&self.store, &owner.store)
            || self.binding != request.binding
            || self.chain != request.chain
            || request.adaptation.is_some()
        {
            return Err(Error::Scope);
        }
        let _pending = self.store.resume_outbound_dsc1(self.binding.session_id())?;
        let progress = self
            .store
            .f7_final_claim_progress_v14(self.chain, self.binding.session_id())?;
        if progress == dom_scriptless_store::F7FinalClaimProgressV14::NeedsAdaptation {
            if self.restart_required || !self.completed {
                return Err(Error::AdaptationRequired);
            }
            let Some(ProductionDomClaimCompletionV12::Universal { authority, .. }) =
                self.completion.as_ref()
            else {
                return Err(Error::AdaptationRequired);
            };
            let secret = secret.ok_or(Error::AdaptationRequired)?;
            let binding = self
                .store
                .f7_anchor_request_binding_v12(&self.gate, self.chain)?;
            let anchors = match self.observer.observe(self.scanner.as_ref(), &binding)? {
                ProductionF7ObservationV12::FundingAbsent => return Ok(Step::FundingAbsent),
                ProductionF7ObservationV12::AwaitingFinality => return Ok(Step::AwaitingFinality),
                ProductionF7ObservationV12::TemporarilyUnavailable => {
                    return Ok(Step::TemporarilyUnavailable)
                }
                ProductionF7ObservationV12::Verified(anchors) => anchors,
            };
            self.store
                .revalidate_consumed_f7_claim_authorization_v12(authority, anchors)?;
            let height = self
                .store
                .load_session(self.binding.session_id())?
                .chain()
                .tip_height;
            // The selected-chain observations may outlive the caller's lease.
            // Match the settlement-child path: a stale pre-RPC timestamp must
            // never authorize first exposure, and this does not renew a lease.
            request.now_unix_ms = exposure_time_after_observation(
                request.now_unix_ms,
                request.lease,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok(),
            )?;
            request.adaptation = Some(super::ProductionF7ClaimAdaptationV14 {
                authority,
                secret,
                validation_height: height,
            });
        }
        owner.step_f7_final_claim_v14(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn fresh_exposure_clock_refuses_rpc_delay_past_the_original_lease() {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut control =
            dom_actuator::DomActuatorStoreV1::create(&root.path().join("actuator")).unwrap();
        let lease = control.acquire_lease([1; 32], [2; 32], 1_000, 100).unwrap();
        assert_eq!(
            exposure_time_after_observation(1_000, lease, Some(Duration::from_millis(1_100)))
                .unwrap(),
            1_100
        );
        // No secret/nonce owner is passed to the guard. The later exposure
        // operation cannot be reached when an RPC used up the original lease.
        assert!(matches!(
            exposure_time_after_observation(1_000, lease, Some(Duration::from_millis(1_101))),
            Err(super::super::ProductionF7FinalClaimErrorV14::Actuator(
                dom_actuator::DomActuatorError::LeaseExpired
            ))
        ));
        // This guard must not renew the underlying durable lease either.
        assert_eq!(
            control
                .acquire_lease([1; 32], [2; 32], 1_050, 9_000)
                .unwrap(),
            lease
        );
    }

    #[test]
    fn fresh_exposure_clock_refuses_invalid_backwards_and_overflowing_time() {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let mut control =
            dom_actuator::DomActuatorStoreV1::create(&root.path().join("actuator")).unwrap();
        let lease = control.acquire_lease([1; 32], [2; 32], 1_000, 100).unwrap();
        for (previous, current) in [
            (0, Some(Duration::from_millis(1_000))),
            (1_000, None),
            (1_000, Some(Duration::ZERO)),
            (1_000, Some(Duration::from_millis(999))),
            (1_000, Some(Duration::from_secs(u64::MAX))),
        ] {
            assert!(matches!(
                exposure_time_after_observation(previous, lease, current),
                Err(super::super::ProductionF7FinalClaimErrorV14::Scope)
            ));
        }
    }

    #[test]
    fn missing_exact_funding_is_distinct_from_wrong_identity_and_service_failure() {
        assert!(matches!(
            classify_observation(Err(F7FamilyAuthorityErrorV11::FundingAbsent)),
            Ok(ProductionF7ObservationV12::FundingAbsent)
        ));
        assert!(matches!(
            classify_observation(Err(F7FamilyAuthorityErrorV11::InsufficientFinality)),
            Ok(ProductionF7ObservationV12::AwaitingFinality)
        ));
        assert!(matches!(
            classify_observation(Err(F7FamilyAuthorityErrorV11::Unavailable)),
            Ok(ProductionF7ObservationV12::TemporarilyUnavailable)
        ));
        for error in [
            F7FamilyAuthorityErrorV11::InvalidEvidence,
            F7FamilyAuthorityErrorV11::Binding,
            F7FamilyAuthorityErrorV11::Bounds,
            F7FamilyAuthorityErrorV11::WindowClosed,
        ] {
            assert!(matches!(classify_observation(Err(error)),
                Err(ProductionF7RuntimeErrorV12::Evidence(value)) if value == error));
        }
    }
}
