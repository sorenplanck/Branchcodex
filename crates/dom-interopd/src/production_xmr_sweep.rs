//! Per-participant DOM↔XMR sweep execution. There are no BTC/EVM owners here.
//!
//! A participant owns ONE local share: U for receiving XMR after the DOM
//! claim, or T for recovering the funded XMR after the DOM refund. Importing
//! both shares before either on-chain revelation would defeat the swap.
//! Raw signed bytes go back to the existing durable XMR actuator; this module
//! has no broadcast port and cannot send a sweep before actuator persistence.
use adapter_dom_real::{VerifiedDomRefundSecretV10, VerifiedDomRefundSecretV11};
use kaystra_core::terms::SettlementTermsV1;
use route_composer::RouteScalar;
use route_executor::LegIdV1;
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use xmr_crypto::{combine_public_shares, XmrPrivateViewKey, XmrSpendShare};
use xmr_dleq_sigma::{revealed_dom_secret_to_xmr_scalar, CrossCurvePublicClaim};
use xmr_live_sidecar_api::{
    BuildSweepRequestV2, SecretScalarBytes, VerifyFundingRequestV2, API_VERSION_V2,
};
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_raw_tx_verify::verify_exact_raw_sweep_bounded_v23;
use xmr_refund_adaptor::{verify_refund_bundle, DomRefundAdaptorExecutor};
use xmr_refund_policy::NonCooperativeRefundCapability;
use xmr_secret_store::{
    EncryptedSqliteSecretStore, SecretMaterialStore, SecretStoreError, XmrSecretMaterial,
};
use xmr_setup_profile::{
    proof_context_hash, ValidatedXmrSetup, XmrAdapterProfileV1, XmrProofContextV1,
};
use xmr_spend_port::{FundingVerifyPort, SpendPortError, SweepBuildPort};

use crate::production_child_xmr::{
    ScopedXmrSweepAuthorityV1, XmrBuiltSweepV1, XmrExternalFundingFactsV1,
};
use crate::production_contracts::ProductionDomRefundRevealSourceV10;
use crate::production_inputs::{AuthenticatedProductionInputsV1, ProductionXmrRefundBundleV1};
use crate::production_xmr_recovery_source::ProductionDomXmrRecoverySourceV11;

#[path = "production_xmr_deferred_recovery_v23.rs"]
mod deferred_recovery_v23;
#[path = "production_xmr_enrolled_resources_v23.rs"]
mod enrolled_resources_v23;
pub(crate) use deferred_recovery_v23::ProductionXmrDeferredRecoveryV23;
pub(crate) use enrolled_resources_v23::{
    ActivatedXmrResourcesV23, ProductionXmrEnrolledResourcesV23,
};

#[path = "production_xmr_claim_origin_v23.rs"]
mod claim_origin_v23;
mod private_funding_v12;
#[path = "production_xmr_private_refund_v23.rs"]
mod private_refund_v23;
#[path = "production_xmr_remote_builder_v23.rs"]
mod remote_builder_v23;
pub(crate) use private_refund_v23::ProductionXmrPrivateRefundOwnerV23;
#[path = "production_xmr_f7_resources_v23.rs"]
mod f7_resources_v23;
pub(crate) use f7_resources_v23::ProductionXmrF7ResourcesV23;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalRole {
    ClaimReceiver,
    RefundReceiver,
}

/// Closed concrete sources. Both obtain U through native canonical observation;
/// the V11 source additionally proves the cancel/refund/punish graph ancestry.
pub(crate) enum ProductionXmrRefundRevealSourceV11 {
    RecoveryDeferredV23(std::rc::Rc<ProductionXmrDeferredRecoveryV23>),
    LegacyV10(ProductionDomRefundRevealSourceV10),
    RecoveryV11(ProductionDomXmrRecoverySourceV11),
    RecoveryV12(
        std::rc::Rc<crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12>,
    ),
}

enum ObservedXmrRefundSecret {
    LegacyV10(VerifiedDomRefundSecretV10),
    RecoveryV11(VerifiedDomRefundSecretV11),
}
impl ProductionXmrRefundRevealSourceV11 {
    fn require_binding(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        template: [u8; 32],
        point: [u8; 33],
        minimum: u32,
        max_reorg: u32,
    ) -> Result<(), Refusal> {
        match self {
            Self::RecoveryDeferredV23(source) => {
                source.require_binding(session, chain, template, point, minimum, max_reorg)
            }
            Self::LegacyV10(source) => {
                source.require_binding(session, chain, template, point, minimum, max_reorg)
            }
            Self::RecoveryV11(source) => {
                source.require_binding(session, chain, template, point, minimum, max_reorg)
            }
            Self::RecoveryV12(source) => {
                source.require_refund_binding(session, chain, template, point, minimum, max_reorg)
            }
        }
    }
    fn observe(&self) -> Result<ObservedXmrRefundSecret, Refusal> {
        match self {
            Self::RecoveryDeferredV23(source) => source
                .require_driver()?
                .observe_refund_share()
                .map(ObservedXmrRefundSecret::RecoveryV11),
            Self::LegacyV10(source) => source.observe().map(ObservedXmrRefundSecret::LegacyV10),
            Self::RecoveryV11(source) => source.observe().map(ObservedXmrRefundSecret::RecoveryV11),
            Self::RecoveryV12(source) => source
                .observe_refund_share()
                .map(ObservedXmrRefundSecret::RecoveryV11),
        }
    }
}
impl ObservedXmrRefundSecret {
    fn require_binding(&self, binding: &SweepBinding) -> Result<(), Refusal> {
        let (session, chain, template, point) = match self {
            Self::LegacyV10(value) => (
                value.session_id(),
                value.chain_id(),
                value.template_hash(),
                value.refund_point(),
            ),
            Self::RecoveryV11(value) => {
                if value.finality().terms_hash() != binding.setup.terms_hash() {
                    return Err(Refusal::Conflict);
                }
                (
                    value.session_id(),
                    value.chain_id(),
                    value.template_hash(),
                    value.refund_point(),
                )
            }
        };
        if binding.local_role != LocalRole::RefundReceiver
            || session != binding.session_id
            || chain != binding.dom_chain_id
            || template != binding.refund_template
            || point != binding.refund_claim.secp_compressed
        {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }
    fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        match self {
            Self::LegacyV10(value) => value.expose(operation),
            Self::RecoveryV11(value) => value.expose(operation),
        }
    }
}

/// Public bindings are reconstructed from admitted terms, not from the
/// sidecar's response or caller-selected addresses. No raw constructor is
/// exposed outside this module.
struct SweepBinding {
    setup: ValidatedXmrSetup,
    session_id: [u8; 32],
    dom_chain_id: [u8; 32],
    refund_claim: CrossCurvePublicClaim,
    refund_template: [u8; 32],
    refund_destination: String,
    local_role: LocalRole,
    max_raw_bytes: usize,
    max_fee_piconero: u64,
}

impl SweepBinding {
    fn authenticate(
        terms: &SettlementTermsV1,
        setup: &ValidatedXmrSetup,
        profile: &XmrAdapterProfileV1,
        refund: &ProductionXmrRefundBundleV1,
        local_participant: [u8; 32],
    ) -> Result<Self, Refusal> {
        if setup.settlement_id() != terms.settlement_id.0
            || setup.terms_hash() != terms.terms_hash().map_err(|_| Refusal::Conflict)?
            || terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
        {
            return Err(Refusal::Conflict);
        }
        let local_role = if local_participant == terms.counterparty_leg.beneficiary.0 {
            LocalRole::ClaimReceiver
        } else if local_participant == terms.counterparty_leg.refund_to.0 {
            LocalRole::RefundReceiver
        } else {
            return Err(Refusal::Conflict);
        };
        crate::production_inputs::authenticate_xmr_refund_deadline_v23(
            terms,
            setup,
            refund.deadline,
        )
        .map_err(|_| Refusal::Conflict)?;
        if profile.profile_hash() != terms.counterparty_leg.adapter_profile_hash {
            return Err(Refusal::Conflict);
        }
        let context = proof_context_hash(
            profile,
            &XmrProofContextV1 {
                settlement_id: terms.settlement_id.0,
                chain_id: terms.counterparty_leg.chain_id.0,
                asset_id: terms.counterparty_leg.asset_id.0,
                amount_piconero: terms.counterparty_leg.amount,
                min_confirmations: terms.counterparty_leg.finality.min_confirmations,
                max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
            },
        )
        .map_err(|_| Refusal::Conflict)?;
        let refund_claim = verify_refund_bundle(&refund.proof, &terms.settlement_id.0, &context)
            .map_err(|_| Refusal::Conflict)?;
        if refund_claim.secp_compressed != refund.adaptor_point_sec1
            || setup.claim().secp_compressed != terms.adaptor_point_sec1
            || refund_claim.ed_compressed == setup.claim().ed_compressed
            || DomRefundAdaptorExecutor::new(refund_claim).profile_hash()
                != refund.executor_profile_hash
            || combine_public_shares(setup.claim().ed_compressed, refund_claim.ed_compressed)
                .map_err(|_| Refusal::Conflict)?
                != setup.combined_spend_public_key()
        {
            return Err(Refusal::Conflict);
        }
        let refund_destination = refund
            .refund_destination()
            .ok_or(Refusal::Conflict)?
            .to_owned();
        let max_raw_bytes =
            usize::try_from(profile.max_raw_tx_bytes).map_err(|_| Refusal::Conflict)?;
        if max_raw_bytes == 0 || max_raw_bytes > xmr_live_sidecar_api::MAX_RAW_TX_BYTES {
            return Err(Refusal::Conflict);
        }
        let max_fee_piconero = u64::try_from(terms.fee_limit.counterparty_max)
            .ok()
            .filter(|fee| *fee != 0)
            .ok_or(Refusal::Conflict)?;
        Ok(Self {
            setup: setup.clone(),
            session_id: terms.session_id.0,
            dom_chain_id: terms.dom_leg.chain_id.0,
            refund_claim,
            refund_template: refund.template_hash,
            refund_destination,
            local_role,
            max_raw_bytes,
            max_fee_piconero,
        })
    }

    fn local_keys(
        &self,
        material: &XmrSecretMaterial,
    ) -> Result<(XmrSpendShare, XmrPrivateViewKey), Refusal> {
        material.expose(|share, view| {
            let share =
                XmrSpendShare::from_canonical_bytes(*share).map_err(|_| Refusal::Conflict)?;
            let view =
                XmrPrivateViewKey::from_canonical_bytes(*view).map_err(|_| Refusal::Conflict)?;
            let expected = match self.local_role {
                LocalRole::ClaimReceiver => self.refund_claim.ed_compressed,
                LocalRole::RefundReceiver => self.setup.claim().ed_compressed,
            };
            if share.public_share().map_err(|_| Refusal::Conflict)? != expected {
                return Err(Refusal::Conflict);
            }
            Ok((share, view))
        })
    }
}

/// The concrete daemon-owned sidecar/store pair. It can only build, never
/// broadcast. Recovery reopens one encrypted share row under exact terms.
pub(crate) struct ProductionXmrSweepAuthorityV10 {
    binding: SweepBinding,
    secrets: std::rc::Rc<EncryptedSqliteSecretStore>,
    sidecar: std::rc::Rc<std::cell::RefCell<BlockingUdsSidecarPort>>,
    refund_source: Option<ProductionXmrRefundRevealSourceV11>,
    private_funding_v12: Option<private_funding_v12::RetainedPrivateFundingV12>,
    funding_terms_v22: SettlementTermsV1,
    funding_profile_v22: XmrAdapterProfileV1,
    funding_quorum_v22: Option<FundingQuorumV22>,
}

struct FundingQuorumV22 {
    deployment: deployment_registry::ResolvedMoneroDeploymentV1,
    urls: Vec<String>,
    executor: tokio::runtime::Runtime,
}

impl ProductionXmrSweepAuthorityV10 {
    pub(crate) fn with_funding_quorum_v22(
        mut self,
        deployment: deployment_registry::ResolvedMoneroDeploymentV1,
        urls: Vec<String>,
    ) -> Result<Self, Refusal> {
        if self.funding_quorum_v22.is_some()
            || urls.len() != usize::from(self.funding_profile_v22.rpc_node_count)
            || deployment.profile().chain_id != self.funding_terms_v22.counterparty_leg.chain_id
        {
            return Err(Refusal::Conflict);
        }
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Refusal::Unavailable)?;
        self.funding_quorum_v22 = Some(FundingQuorumV22 {
            deployment,
            urls,
            executor,
        });
        Ok(self)
    }

    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        local_participant: [u8; 32],
        secrets: EncryptedSqliteSecretStore,
        sidecar: BlockingUdsSidecarPort,
        refund_source: Option<ProductionXmrRefundRevealSourceV11>,
    ) -> Result<Self, Refusal> {
        let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let binding = SweepBinding::authenticate(
            terms,
            session.setup(),
            session.profile(),
            session.refund_bundle().ok_or(Refusal::Conflict)?,
            local_participant,
        )?;
        if let Some(ProductionXmrRefundRevealSourceV11::RecoveryDeferredV23(slot)) =
            refund_source.as_ref()
        {
            slot.require_terms(terms.terms_hash().map_err(|_| Refusal::Conflict)?)?;
        }
        if binding.local_role == LocalRole::RefundReceiver {
            let source = refund_source.as_ref().ok_or(Refusal::Conflict)?;
            source.require_binding(
                binding.session_id,
                binding.dom_chain_id,
                binding.refund_template,
                binding.refund_claim.secp_compressed,
                terms.dom_leg.finality.min_confirmations,
                terms.dom_leg.finality.max_reorg_depth,
            )?;
        } else if refund_source.is_some() {
            return Err(Refusal::Conflict);
        }
        // Fail before any RPC or spend scalar leaves the process when the
        // operator supplied another session's, role's or terms' local key.
        let material = secrets
            .load(&binding.setup.settlement_id(), &binding.setup.terms_hash())
            .map_err(map_secret)?;
        binding.local_keys(&material)?;
        Ok(Self {
            binding,
            secrets: std::rc::Rc::new(secrets),
            sidecar: std::rc::Rc::new(std::cell::RefCell::new(sidecar)),
            refund_source,
            private_funding_v12: None,
            funding_terms_v22: terms.clone(),
            funding_profile_v22: session.profile().clone(),
            funding_quorum_v22: None,
        })
    }

    pub(crate) fn attach_private_funding_v12(
        mut self,
        state_dir: &std::path::Path,
        relative: &str,
        max_fee_piconero: u64,
    ) -> Result<Self, Refusal> {
        if self.binding.local_role != LocalRole::RefundReceiver
            || self.private_funding_v12.is_some()
        {
            return Err(Refusal::Conflict);
        }
        let material = self.material()?;
        let (_, view) = self.binding.local_keys(&material)?;
        let setup = &self.binding.setup;
        let retained = view.expose(|view| {
            private_funding_v12::RetainedPrivateFundingV12::open(
                state_dir,
                relative,
                self.binding.max_raw_bytes,
                setup.funding_tx_hash(),
                setup.combined_spend_public_key(),
                view,
                setup.expected_amount_piconero(),
                max_fee_piconero,
            )
        })?;
        self.private_funding_v12 = Some(retained);
        Ok(self)
    }

    fn material(&self) -> Result<XmrSecretMaterial, Refusal> {
        self.secrets
            .load(
                &self.binding.setup.settlement_id(),
                &self.binding.setup.terms_hash(),
            )
            .map_err(map_secret)
    }

    fn build(
        &mut self,
        nonce: [u8; 32],
        remote: XmrSpendShare,
        refund: bool,
    ) -> Result<XmrBuiltSweepV1, Refusal> {
        let material = self.material()?;
        let (local, view) = self.binding.local_keys(&material)?;
        let combined = local.combine(&remote).map_err(|_| Refusal::Conflict)?;
        if combined.public_key().map_err(|_| Refusal::Conflict)?
            != self.binding.setup.combined_spend_public_key()
        {
            return Err(Refusal::Conflict);
        }
        let setup = &self.binding.setup;
        let request = BuildSweepRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce: nonce,
            settlement_id: setup.settlement_id(),
            funding_tx_hash: setup.funding_tx_hash(),
            expected_amount_piconero: setup.expected_amount_piconero(),
            destination: if refund {
                self.binding.refund_destination.clone()
            } else {
                setup.destination().to_owned()
            },
            spend_scalar: combined.expose(|bytes| SecretScalarBytes::new(*bytes)),
            expected_spend_public_key: setup.combined_spend_public_key(),
            view_scalar: view.expose(|bytes| SecretScalarBytes::new(*bytes)),
            auth_tag: [0; 32],
        };
        request
            .validate_public_fields()
            .map_err(|_| Refusal::Conflict)?;
        let result = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .build_sweep(request)
            .map_err(map_port)?;
        result.validate_for(&nonce).map_err(|_| Refusal::Conflict)?;
        if result.raw_tx.len() > self.binding.max_raw_bytes {
            return Err(Refusal::Conflict);
        }
        // The sidecar/RPC fee estimate cannot override the signed ceiling.
        // Verify the fee encoded in these exact bytes before actuator retention.
        let verified = verify_exact_raw_sweep_bounded_v23(
            &result.raw_tx,
            result.tx_hash,
            setup.expected_amount_piconero(),
            self.binding.max_fee_piconero,
        )
        .map_err(|_| Refusal::Conflict)?;
        // The current durable actuator's absence evidence represents exactly
        // one key image. Multiple inputs require a versioned actuator record.
        let [key_image] = verified.sweep().key_images.as_slice() else {
            return Err(Refusal::Conflict);
        };
        Ok(XmrBuiltSweepV1 {
            tx_hash: result.tx_hash,
            key_image: *key_image,
            raw_transaction: result.raw_tx,
            remote_custody_v23: None,
        })
    }
}

impl ScopedXmrSweepAuthorityV1 for ProductionXmrSweepAuthorityV10 {
    fn observe_verified_funding_v22(
        &mut self,
    ) -> Result<f7_anchor_authority::families_v11::VerifiedXmrFundingV11, Refusal> {
        use f7_anchor_authority::families_v11::{
            verify_xmr_funding_v11, F7FamilyAuthorityErrorV11 as E, XmrFundingObservationRequestV11,
        };
        let quorum = self.funding_quorum_v22.as_ref().ok_or(Refusal::Conflict)?;
        let mut sidecar = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?;
        quorum
            .executor
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    verify_xmr_funding_v11(
                        XmrFundingObservationRequestV11 {
                            terms: &self.funding_terms_v22,
                            setup: &self.binding.setup,
                            profile: &self.funding_profile_v22,
                            deployment: &quorum.deployment,
                            daemon_urls: &quorum.urls,
                        },
                        &mut sidecar,
                        self.secrets.as_ref(),
                    ),
                )
                .await
                .unwrap_or(Err(E::Unavailable))
            })
            .map_err(|error| match error {
                E::Unavailable | E::FundingAbsent | E::InsufficientFinality => Refusal::Unavailable,
                _ => Refusal::Conflict,
            })
    }

    fn broadcast_funding_v12(
        &mut self,
        recovery: &crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        broadcast: &mut dyn xmr_spend_port::ExactBroadcastPort,
    ) -> Result<(), Refusal> {
        if self.binding.local_role == LocalRole::ClaimReceiver {
            // The opposite participant owns the funding wallet. This daemon
            // observes its exact pinned output through the native scanner.
            if self.private_funding_v12.is_some() {
                return Err(Refusal::Conflict);
            }
            return Ok(());
        }
        let retained = self.private_funding_v12.as_mut().ok_or(Refusal::Conflict)?;
        retained.revalidate()?;
        recovery.broadcast_private_funding(
            self.binding.setup.terms_hash(),
            self.binding.setup.binding_hash(),
            retained.candidate(),
            broadcast,
        )
    }

    fn build_claim_sweep(
        &mut self,
        request_nonce: [u8; 32],
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, Refusal> {
        if self.binding.local_role != LocalRole::ClaimReceiver {
            return Err(Refusal::Conflict);
        }
        let bytes =
            revealed_dom_secret_to_xmr_scalar(*scalar.expose(), &self.binding.setup.claim())
                .map_err(|_| Refusal::Conflict)?;
        let remote = XmrSpendShare::from_canonical_bytes(bytes).map_err(|_| Refusal::Conflict)?;
        self.build(request_nonce, remote, false)
    }

    fn build_refund_sweep(&mut self, request_nonce: [u8; 32]) -> Result<XmrBuiltSweepV1, Refusal> {
        if self.binding.local_role != LocalRole::RefundReceiver {
            return Err(Refusal::Conflict);
        }
        // No callback returning a naked scalar can authorize this path. The
        // source re-reads the actual Contracts Store and canonical DOM chain.
        let revealed = self
            .refund_source
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .observe()?;
        revealed.require_binding(&self.binding)?;
        let executor = DomRefundAdaptorExecutor::new(self.binding.refund_claim);
        let remote = revealed
            .expose(|bytes| executor.recover_share(*bytes))
            .map_err(|_| Refusal::Conflict)?;
        self.build(request_nonce, remote, true)
    }

    fn verify_external_funding(
        &mut self,
        request_nonce: [u8; 32],
    ) -> Result<XmrExternalFundingFactsV1, Refusal> {
        let material = self.material()?;
        let (_, view) = self.binding.local_keys(&material)?;
        let setup = &self.binding.setup;
        let request = VerifyFundingRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce,
            settlement_id: setup.settlement_id(),
            funding_tx_hash: setup.funding_tx_hash(),
            expected_amount_piconero: setup.expected_amount_piconero(),
            expected_spend_public_key: setup.combined_spend_public_key(),
            view_scalar: view.expose(|bytes| SecretScalarBytes::new(*bytes)),
            auth_tag: [0; 32],
        };
        request
            .validate_public_fields()
            .map_err(|_| Refusal::Conflict)?;
        let response = self
            .sidecar
            .try_borrow_mut()
            .map_err(|_| Refusal::Unavailable)?
            .verify_funding(request)
            .map_err(map_port)?;
        if response.api_version != API_VERSION_V2
            || response.request_nonce != request_nonce
            || response.funding_tx_hash != setup.funding_tx_hash()
            || response.received_amount_piconero != setup.expected_amount_piconero()
            || !response.spendable
        {
            return Err(Refusal::Conflict);
        }
        Ok(XmrExternalFundingFactsV1 {
            received_amount_piconero: response.received_amount_piconero,
            spendable: response.spendable,
        })
    }
}

fn map_port(error: SpendPortError) -> Refusal {
    match error {
        SpendPortError::Retryable => Refusal::Unavailable,
        SpendPortError::Rejected => Refusal::Conflict,
    }
}

fn map_secret(error: SecretStoreError) -> Refusal {
    match error {
        SecretStoreError::Unavailable => Refusal::Unavailable,
        _ => Refusal::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaystra_core::types::*;
    use xmr_dleq_sigma::{
        prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
    };
    use xmr_setup_profile::{validate_setup, XmrNetwork, XmrSetupBindingV1};

    #[test]
    fn v10_both_xmr_roles_recover_the_same_key_and_refuse_wrong_local_shares() {
        let mut t = [0; 32];
        t[0] = 7;
        let mut u = [0; 32];
        u[0] = 11;
        let mut v = [0; 32];
        v[0] = 13;
        let t = CrossCurveSecret252::from_little_endian(t).expect("test t");
        let u = CrossCurveSecret252::from_little_endian(u).expect("test u");
        let claim = t.public_claim().expect("T");
        let refund_claim = u.public_claim().expect("U");
        let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2).expect("profile");
        let a = ParticipantId([1; 32]);
        let b = ParticipantId([2; 32]);
        let mut terms = SettlementTermsV1 {
            settlement_id: SettlementId([4; 32]),
            session_id: SessionId([5; 32]),
            intent_hash: IntentHash([6; 32]),
            solver_id: SolverId([7; 32]),
            roster: [a, b],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([8; 32]),
                asset_id: AssetId([9; 32]),
                amount: 100,
                beneficiary: b,
                refund_to: a,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 100 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 1,
                    max_reorg_depth: 2,
                },
                adapter_profile_hash: [10; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([11; 32]),
                asset_id: AssetId([12; 32]),
                amount: 100,
                beneficiary: a,
                refund_to: b,
                mechanism: LockMechanism::CrossCurveSharedSpend,
                deadline: TimelockSpec::TimestampSeconds {
                    value: 1_900_000_000,
                },
                finality: FinalityPolicyV1 {
                    min_confirmations: 10,
                    max_reorg_depth: 20,
                },
                adapter_profile_hash: profile.profile_hash(),
            },
            adaptor_point_sec1: claim.secp_compressed,
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 10,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: vec![],
        };
        let context = proof_context_hash(
            &profile,
            &XmrProofContextV1 {
                settlement_id: terms.settlement_id.0,
                chain_id: terms.counterparty_leg.chain_id.0,
                asset_id: terms.counterparty_leg.asset_id.0,
                amount_piconero: 100,
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
        )
        .expect("economic context");
        let dleq = prove_bound(
            &t,
            terms.settlement_id.0,
            context,
            ROLE_XMR_SHARED_SPEND,
            &mut rand::thread_rng(),
        )
        .expect("claim DLEQ");
        let refund_proof = prove_bound(
            &u,
            terms.settlement_id.0,
            context,
            ROLE_XMR_REFUND_SHARE,
            &mut rand::thread_rng(),
        )
        .expect("refund DLEQ");
        let combined =
            combine_public_shares(claim.ed_compressed, refund_claim.ed_compressed).expect("T+U");
        let setup_input = XmrSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash().expect("terms"),
            dleq,
            funding_tx_hash: [15; 32],
            expected_amount_piconero: 100,
            destination: "5ClaimDestinationFixture".to_owned(),
            combined_spend_public_key: combined,
        };
        let setup = validate_setup(&terms, &profile, setup_input.clone(), None)
            .expect("real verified setup");
        let refund = ProductionXmrRefundBundleV1::new_v10(
            refund_proof,
            [16; 32],
            refund_claim.secp_compressed,
            DomRefundAdaptorExecutor::new(refund_claim).profile_hash(),
            1_900_000_000,
            "5RefundDestinationFixture".to_owned(),
        )
        .expect("refund bundle");
        let receiver = SweepBinding::authenticate(&terms, &setup, &profile, &refund, a.0)
            .expect("claim receiver");
        let funder = SweepBinding::authenticate(&terms, &setup, &profile, &refund, b.0)
            .expect("refund receiver");
        assert_eq!(receiver.max_fee_piconero, 10);
        assert_eq!(funder.max_fee_piconero, 10);
        let local_u = XmrSecretMaterial::new(u.xmr_share_little_endian(), v).expect("local U");
        let local_t = XmrSecretMaterial::new(t.xmr_share_little_endian(), v).expect("local T");
        assert!(receiver.local_keys(&local_t).is_err());
        assert!(funder.local_keys(&local_u).is_err());
        let revealed_t = XmrSpendShare::from_canonical_bytes(
            revealed_dom_secret_to_xmr_scalar(t.dom_secret_big_endian(), &claim)
                .expect("observed t conversion"),
        )
        .expect("t share");
        let revealed_u = DomRefundAdaptorExecutor::new(refund_claim)
            .recover_share(u.dom_secret_big_endian())
            .expect("observed u conversion");
        assert_eq!(
            receiver
                .local_keys(&local_u)
                .expect("local U")
                .0
                .combine(&revealed_t)
                .expect("claim spend")
                .public_key()
                .expect("public"),
            combined
        );
        assert_eq!(
            funder
                .local_keys(&local_t)
                .expect("local T")
                .0
                .combine(&revealed_u)
                .expect("refund spend")
                .public_key()
                .expect("public"),
            combined
        );
        assert_ne!(receiver.setup.destination(), funder.refund_destination);
        assert!(SweepBinding::authenticate(&terms, &setup, &profile, &refund, [99; 32]).is_err());
        let mut bad = refund.clone();
        bad.refund_destination = None;
        assert!(SweepBinding::authenticate(&terms, &setup, &profile, &bad, a.0).is_err());
        let mut bad = refund.clone();
        bad.deadline += 1;
        assert!(SweepBinding::authenticate(&terms, &setup, &profile, &bad, a.0).is_err());
        let mut bad = refund.clone();
        bad.proof.role = ROLE_XMR_SHARED_SPEND;
        assert!(SweepBinding::authenticate(&terms, &setup, &profile, &bad, a.0).is_err());
        // Changing only the deadline unit, even with the same integer, cannot
        // reuse a setup bound to the original signed terms.
        let mut height_terms = terms.clone();
        height_terms.counterparty_leg.deadline = TimelockSpec::BlockHeight {
            value: refund.deadline,
        };
        assert!(SweepBinding::authenticate(&height_terms, &setup, &profile, &refund, a.0).is_err());
        let mut height_input = setup_input.clone();
        height_input.terms_hash = height_terms.terms_hash().expect("height terms");
        let height_setup = validate_setup(&height_terms, &profile, height_input, None)
            .expect("setup bound to height terms");
        assert!(matches!(
            crate::production_inputs::authenticate_xmr_refund_deadline_v23(
                &height_terms, &height_setup, refund.deadline,
            ),
            Ok(TimelockSpec::BlockHeight { value }) if value == refund.deadline
        ));
        assert!(
            SweepBinding::authenticate(&height_terms, &height_setup, &profile, &refund, a.0)
                .is_ok()
        );
        assert!(SweepBinding::authenticate(&terms, &height_setup, &profile, &refund, a.0).is_err());
        let mut height_bad = refund.clone();
        height_bad.deadline += 1;
        assert!(SweepBinding::authenticate(
            &height_terms,
            &height_setup,
            &profile,
            &height_bad,
            a.0
        )
        .is_err());
        let mut wrong_sum = setup_input;
        wrong_sum.combined_spend_public_key = claim.ed_compressed;
        let wrong_sum = validate_setup(&terms, &profile, wrong_sum, None)
            .expect("old setup alone does not bind U");
        assert!(SweepBinding::authenticate(&terms, &wrong_sum, &profile, &refund, a.0).is_err());
        terms.counterparty_leg.amount += 1;
        assert!(SweepBinding::authenticate(&terms, &setup, &profile, &refund, a.0).is_err());
    }
}
