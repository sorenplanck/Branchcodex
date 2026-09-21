//! Native family-specific V12 readiness, funding and claim authority.
//!
//! These records are retained under the same locked Contracts Store root.
//! Bilateral readiness is DSC1 0x17, domain-separated from historical M8 0x11.
//! A private XMR U-final signature is never part of a readiness payload.

use super::*;
#[path = "f7_downstream_claim_gate_v23.rs"]
mod downstream_claim_gate_v23;
pub(super) use downstream_claim_gate_v23::DownstreamClaimLeaseV23;
#[path = "f7_xmr_funding_wait_v23.rs"]
mod xmr_funding_wait_v23;
#[path = "f7_xmr_recovery_pending_v23.rs"]
mod xmr_recovery_pending_v23;
#[path = "f7_xmr_refund_readiness_v23.rs"]
mod xmr_refund_readiness_v23;
pub use xmr_refund_readiness_v23::VerifiedXmrRefundReadinessV23;
#[path = "f7_xmr_refund_transport_v23.rs"]
mod xmr_refund_transport_v23;
use xmr_refund_transport_v23::{validate_refund_transport_bytes_v23, REFUND_TRANSPORT_LEN_V23};
#[path = "funding_child_v20.rs"]
mod funding_child_v20;
pub use funding_child_v20::RealDomFundingFactsV23;
#[path = "funding_signing_v20.rs"]
mod funding_signing_v20;
#[path = "f7_xmr_bounded_v23.rs"]
mod xmr_bounded_v23;
#[path = "f7_xmr_funding_round_v23.rs"]
mod xmr_funding_round_v23;
use funding_signing_v20::{F7FundingSigningV20, SIGNING_MAX_V20};
pub(super) use xmr_funding_round_v23::parse_xmr_funding_vault_name_v23;
pub use xmr_funding_round_v23::{
    PreparedXmrFundingVaultProvisioningV23, XmrFundingVaultProvisioningStateV23,
};

#[path = "claim_receiver_v15.rs"]
mod claim_receiver_v15;
#[path = "final_claim_v14.rs"]
mod final_claim_v14;
use claim_receiver_v15::{validate_f7_observation_bytes_v15, OBSERVATION_PREFIX_V15};
pub use claim_receiver_v15::{
    F7ClaimObserverFactsV15, ObservedF7FinalClaimV15, PreparedF7FinalClaimIngressV15,
};
pub(super) const OBSERVATION_MAX_V15: usize = claim_receiver_v15::OBSERVATION_MAX_V15;
use super::super::xmr_recovery::XmrRecoveryCustodyV11;
use dom_scriptless_crypto::{FrozenSharedOutputV1, VerifiedXmrRecoveryGraphV11};
use f7_anchor_authority::families_v11::{F7ExternalFamilyV11, VerifiedF7AnchorAuthorizationV12};
use final_claim_v14::{validate_final_claim_artifact_v14, ADMISSION_LEN_V14, EXPOSURE_MAX_V14};
pub use final_claim_v14::{
    AdmittedF7FinalClaimV14, F7FinalClaimActionV14, F7FinalClaimFactsV14, F7FinalClaimProgressV14,
    PreparedF7FinalClaimSubmissionV14,
};
use kaystra_core::types::{LockMechanism, TimelockSpec};
use xmr_refund_policy::{
    compensation::{ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyV11},
    economic_graph::VerifiedXmrEconomicRecoveryGraphV11,
};

#[path = "f7_xmr_claim_v23.rs"]
mod xmr_claim_v23;
pub(super) use xmr_claim_v23::parse_xmr_claim_vault_name_v23;
pub use xmr_claim_v23::{PreparedXmrClaimVaultProvisioningV23, XmrClaimVaultProvisioningStateV23};

const GATE_MAGIC: &[u8; 8] = b"DOMFGT12";
const GATE_MAX: usize = 128 * 1024;
const COMMIT_MAX: usize = 2 * 1024 * 1024;
const GATE_DOMAIN: &str = "DOM-INTEROP/F7-GATE/V12\0";
const READY_DOMAIN: &str = "DOM-INTEROP/F7-BILATERAL-READY/V12\0";
const BOUNDED_GATE_DOMAIN_V23: &str = "DOM-INTEROP/F7-XMR-BOUNDED-GATE/V23\0";
const BOUNDED_READY_DOMAIN_V23: &str = "DOM-INTEROP/F7-XMR-BOUNDED-READY/V23\0";

#[path = "f7_xmr_compensation_guard_v23.rs"]
mod compensation_guard_v23;
use compensation_guard_v23::require_bounded_compensation_profile_v23;

#[derive(Clone, Copy, PartialEq, Eq)]
enum F7RecoveryProfileV23 {
    Legacy,
    XmrBounded,
}
impl F7RecoveryProfileV23 {
    fn decode(tag: u8) -> Result<Self, SessionStoreError> {
        match tag {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::XmrBounded),
            _ => Err(SessionStoreError::Quarantined),
        }
    }
    fn gate_domain(self) -> &'static str {
        match self {
            Self::Legacy => GATE_DOMAIN,
            Self::XmrBounded => BOUNDED_GATE_DOMAIN_V23,
        }
    }
    fn ready_domain(self) -> &'static str {
        match self {
            Self::Legacy => READY_DOMAIN,
            Self::XmrBounded => BOUNDED_READY_DOMAIN_V23,
        }
    }
}

/// Recovery proof appropriate to the selected external family.
pub enum F7RecoveryPreparationV12<'a> {
    /// EVM/Solana retain the native, ordinary DOM refund before funding.
    PlainRefund {
        /// Exact ordinary final refund already authenticated in this Store.
        refund_bytes: &'a [u8],
    },
    /// Native V23 graph and durable custody under signed bounded availability.
    /// This profile is distinct from the conditional-compensation legacy path.
    XmrBoundedV23 {
        /// Reconstructed native graph and signed economic policy.
        produced: &'a xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12,
        /// Exact role-scoped encrypted archive already marked Ready in this Store.
        custody: &'a XmrRecoveryCustodyV11,
        /// Same-Store completed Cancel and Compensation signing histories.
        ordinary_rounds: &'a VerifiedXmrOrdinaryRecoveryRoundsV11,
        /// Authenticated setup binding the exact native Monero funding transaction.
        setup: &'a xmr_setup_profile::ValidatedXmrSetup,
    },
    /// Monero retains the complete collateral graph and both plain rounds.
    Xmr {
        /// Native five-transaction graph, including adaptor refund U.
        graph: &'a VerifiedXmrRecoveryGraphV11,
        /// Native confidential value and signed payout proof.
        economic: &'a VerifiedXmrEconomicRecoveryGraphV11,
        /// Locked encrypted custody, with private final U only for its owner.
        custody: &'a XmrRecoveryCustodyV11,
        /// Native ordinary cancel/compensation histories from this same Store.
        ordinary_rounds: &'a VerifiedXmrOrdinaryRecoveryRoundsV11,
        /// Native admitted setup, including exact funding transaction and combined key.
        setup: &'a xmr_setup_profile::ValidatedXmrSetup,
    },
}

/// Live, fully typed input to the separate V12 prefunding gate.
pub struct F7FundingGatePreparationV12<'a> {
    /// Exact operational role decoded under the native chain authority.
    pub role: &'a FinalClaimRoleBindingV1,
    /// Native verified formation of the shared collateral output.
    pub collateral: &'a FrozenSharedOutputV1,
    /// Signature-omitting native funding template.
    pub funding_template: &'a Transaction,
    /// Exact native claim template which will be signed only after anchors.
    pub claim_template: &'a Transaction,
    /// Recovery appropriate to the actual external family.
    pub recovery: F7RecoveryPreparationV12<'a>,
    /// Exact currently authenticated DOM chain projection.
    pub context: DomTransactionValidationContextV1,
}

/// Same-Store, process-bound reference to one immutable universal funding gate.
pub struct PreparedOperationalXmrFundingGateV12 {
    session_id: [u8; 32],
    digest: [u8; 32],
    ready_digest: [u8; 32],
    open_instance_id: [u8; 32],
}
impl PreparedOperationalXmrFundingGateV12 {
    /// Exact admitted leg session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Deterministic payload signed independently by both identities.
    pub const fn ready_to_fund_vote_payload(&self) -> [u8; 32] {
        self.ready_digest
    }
}
/// Family-neutral spelling of the same closed capability.
pub type PreparedF7FundingGateV12 = PreparedOperationalXmrFundingGateV12;

/// Exact next identity-signed readiness edge selected by the Store journal.
pub struct PreparedOperationalXmrReadyToFundVoteV12 {
    session_id: [u8; 32],
    participant_id: [u8; 32],
    sequence: u64,
    previous_transcript_hash: [u8; 32],
    payload: [u8; 32],
    gate_record_digest: [u8; 32],
    open_instance_id: [u8; 32],
}
impl PreparedOperationalXmrReadyToFundVoteV12 {
    /// Session authenticated by the native gate.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Next participant in the immutable two-person transport roster.
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }
    /// Exact durable sender sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact transcript predecessor.
    pub const fn previous_transcript_hash(&self) -> [u8; 32] {
        self.previous_transcript_hash
    }
    /// Complete scope digest for the new 0x17 profile.
    pub const fn payload(&self) -> [u8; 32] {
        self.payload
    }
}

pub(super) struct F7GateRecordV12 {
    pub(super) bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
    pub(super) role: RetainedFinalClaimRoleBindingAuditV1,
    pub(super) session_id: [u8; 32],
    pub(super) chain_id: [u8; 32],
    pub(super) terms_hash: [u8; 32],
    pub(super) family: F7ExternalFamilyV11,
    profile: F7RecoveryProfileV23,
    pub(super) bound_revision: u64,
    pub(super) bound_record_digest: [u8; 32],
    pub(super) phase: SessionPhaseV1,
    pub(super) ready_digest: [u8; 32],
    pub(super) bp_statement_hash: [u8; 32],
    pub(super) recovery_binding_hash: [u8; 32],
    pub(super) graph_digest: [u8; 32],
    pub(super) custody_id: [u8; 32],
    pub(super) ordinary_scope: [u8; 32],
    pub(super) cancel_session: [u8; 32],
    pub(super) compensation_session: [u8; 32],
    pub(super) xmr_setup_binding_hash: [u8; 32],
    pub(super) xmr_funding_tx_hash: [u8; 32],
    pub(super) graph_binding_bytes: Vec<u8>,
    pub(super) policy_bytes: Vec<u8>,
    pub(super) funding_template: Vec<u8>,
    pub(super) claim_template: Vec<u8>,
    pub(super) refund_bytes: Vec<u8>,
}

impl ContractsSessionStoreV1 {
    /// Prepare or resume the exact V12 native gate. All mathematical and
    /// custody inputs are reverified; retained public hashes cannot recreate
    /// the native collateral, economic proof or ordinary signing transcripts.
    pub fn prepare_f7_funding_gate_v12(
        &self,
        input: F7FundingGatePreparationV12<'_>,
    ) -> Result<PreparedF7FundingGateV12, SessionStoreError> {
        if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
            return Err(SessionStoreError::PolicyProfile);
        }
        if matches!(
            &input.recovery,
            F7RecoveryPreparationV12::XmrBoundedV23 { .. }
        ) {
            let chain = self.require_process_trusted_chain_v23(&input.role.dom_chain_id().0)?;
            return self.prepare_or_resume_xmr_bounded_f7_gate_v23(chain, input);
        }
        if let F7RecoveryPreparationV12::Xmr {
            graph,
            economic,
            custody,
            ordinary_rounds,
            ..
        } = &input.recovery
        {
            self.revalidate_xmr_ordinary_recovery_rounds_v11(
                ordinary_rounds,
                input.role,
                graph,
                economic.policy(),
                custody,
            )?;
        }
        let _guard = self.operation_lock()?;
        let role = input.role;
        let session = role.session_id().0;
        let terms_hash = role
            .terms_hash()
            .map_err(|_| SessionStoreError::Canonical)?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let early = self.load_early_transport_authority(session)?;
        let bp = self.load_bp_transport_authority(session)?;
        let template = self.load_template_transport_authority(session)?;
        let statement = input.collateral.statement();
        let expected_roster = [role.terms().roster[0].0, role.terms().roster[1].0];
        let (_, funding_hash) = canonical_template_v1(input.funding_template)
            .map_err(|_| SessionStoreError::Canonical)?;
        let (_, claim_hash) = canonical_template_v1(input.claim_template)
            .map_err(|_| SessionStoreError::Canonical)?;
        if current.terms_hash() != terms_hash
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || role.dom_chain_id().0 != roster.chain_id
            || input.context.chain_id() != &roster.chain_id
            || input.context.current_height() != current.chain().tip_height
            || input.context.now_unix_seconds() == 0
            || input.collateral.terms_hash() != &terms_hash
            || statement.chain_id() != roster.chain_id
            || statement.session_id() != session
            || statement.participant_ids() != expected_roster.as_slice()
            || input.collateral.aggregate_commitment() != &role.shared_output_commitment()
            || statement.recovery_binding_hash() != &early.recovery_binding_hash
            || funding_hash != role.funding_template_hash()
            || claim_hash != role.claim_template_hash()
            || template.template_commit_payload[..32] != funding_hash
            || template.template_commit_payload[32..64] != claim_hash
            || template.template_commit_payload[64..96] != role.refund_template_hash()
            || template.template_commit_payload[96..128] != statement.statement_hash()
            || early.terms_hash != terms_hash
            || bp.terms_hash != terms_hash
            || bp.statement.statement_hash() != statement.statement_hash()
            || bp.early_authority_digest != early.digest
            || template.bp_authority_digest != bp.digest
            || role.roster().entries().len() != roster.participants.len()
            || role.roster().entries().iter().any(|expected| {
                !roster.participants.iter().any(|actual| {
                    &actual.participant_id == expected.participant_id()
                        && &actual.identity_key == expected.identity_public_key()
                })
            })
            || self.funding_gate_exists(session)?
            || self.m8_funding_gate_exists(session)?
            || self.m8_funding_gate_v2_exists(session)?
            || self.any_operational_issuance_exists(session)?
            || self.any_operational_commit_exists(session)?
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        self.require_no_pre_anchor_claim_signing_evidence(session, current.revision())?;
        let (
            family,
            phase,
            graph_digest,
            custody_id,
            ordinary_scope,
            cancel_session,
            compensation_session,
            xmr_setup_binding_hash,
            xmr_funding_tx_hash,
            graph_binding_bytes,
            policy_bytes,
            refund_bytes,
        ) = match input.recovery {
            F7RecoveryPreparationV12::XmrBoundedV23 { .. } => {
                return Err(SessionStoreError::FundingAuthorityUnavailable);
            }
            F7RecoveryPreparationV12::PlainRefund { refund_bytes } => {
                let family = match role.terms().counterparty_leg.mechanism {
                    LockMechanism::ConditionLock => F7ExternalFamilyV11::Evm,
                    LockMechanism::CrossCurveConditionLock => F7ExternalFamilyV11::Solana,
                    _ => return Err(SessionStoreError::InvalidTransition),
                };
                if current.phase() != SessionPhaseV1::RefundSigned {
                    return Err(SessionStoreError::InvalidTransition);
                }
                let retained = self.load_operational_final_refund_v2(session)?;
                self.authenticate_operational_final_refund_v2_at_terminal(
                    session,
                    retained.terminal_revision,
                )?;
                let expected_collateral = if role.terms().policy_version
                    == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17
                {
                    let budget = dom_adaptor::DomBootstrapBudgetV17::new(
                        role.terms().dom_leg.amount,
                        role.terms().fee_limit.dom_max,
                    )
                    .map_err(|_| SessionStoreError::InvalidTransition)?;
                    let refund = <Transaction as DomDeserialize>::from_bytes(refund_bytes)
                        .map_err(|_| SessionStoreError::Canonical)?;
                    if input.funding_template.kernels.len() != 1
                        || input.claim_template.kernels.len() != 1
                        || refund.kernels.len() != 1
                        || refund.inputs.len() != 1
                        || refund.outputs.len() != 1
                        || input.claim_template.inputs.len() != 1
                        || input.claim_template.outputs.len() != 1
                        || input.funding_template.kernels[0].fee.noms()
                            > budget.funding_fee_ceiling()
                        || input.claim_template.kernels[0].fee.noms() != budget.exit_fee()
                        || refund.kernels[0].fee.noms() != budget.exit_fee()
                    {
                        return Err(SessionStoreError::InvalidTransition);
                    }
                    u128::from(budget.shared_value())
                } else {
                    role.terms().dom_leg.amount
                };
                if retained.exact_transaction_bytes != refund_bytes
                    || input.collateral.value_noms() as u128 != expected_collateral
                {
                    return Err(SessionStoreError::InvalidTransition);
                }
                (
                    family,
                    SessionPhaseV1::RefundSigned,
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    [0; 32],
                    vec![],
                    vec![],
                    refund_bytes.to_vec(),
                )
            }
            F7RecoveryPreparationV12::Xmr {
                graph,
                economic,
                custody,
                ordinary_rounds,
                setup,
            } => {
                graph
                    .require_conditional_compensation_v22()
                    .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
                if current.phase() != SessionPhaseV1::TemplatesCommitted
                    || role.terms().counterparty_leg.mechanism
                        != LockMechanism::CrossCurveSharedSpend
                    || setup.terms_hash() != terms_hash
                    || setup.settlement_id() != role.settlement_id().0
                    || setup.claim().secp_compressed != role.adaptor_point_sec1()
                    || graph.graph_digest() != economic.graph_digest()
                    || economic.bp_statement_hash() != &statement.statement_hash()
                    || economic.policy().terms_hash() != &terms_hash
                    || graph.binding().funding_commitment != role.shared_output_commitment()
                    || ordinary_rounds.parent_session() != &session
                    || ordinary_rounds.parent_record_digest() != current.digest()
                    || custody.scope().graph_digest != *graph.graph_digest()
                {
                    return Err(SessionStoreError::InvalidTransition);
                }
                graph
                    .require_claim_window(current.chain().tip_height)
                    .map_err(|_| SessionStoreError::InvalidTransition)?;
                (
                    F7ExternalFamilyV11::Monero,
                    SessionPhaseV1::TemplatesCommitted,
                    *graph.graph_digest(),
                    custody.scope().custody_id,
                    *ordinary_rounds.scope_digest(),
                    *ordinary_rounds.cancel_session(),
                    *ordinary_rounds.compensation_session(),
                    setup.binding_hash(),
                    setup.funding_tx_hash(),
                    encode_xmr_graph_binding_v12(graph.binding()),
                    economic
                        .policy()
                        .policy()
                        .to_bytes()
                        .map_err(|_| SessionStoreError::Canonical)?,
                    vec![],
                )
            }
        };
        let record = F7GateRecordV12::new(
            role,
            &current,
            family,
            phase,
            F7RecoveryProfileV23::Legacy,
            statement.statement_hash(),
            *statement.recovery_binding_hash(),
            graph_digest,
            custody_id,
            ordinary_scope,
            cancel_session,
            compensation_session,
            xmr_setup_binding_hash,
            xmr_funding_tx_hash,
            graph_binding_bytes,
            policy_bytes,
            canonical_dom_transaction_bytes_v1(input.funding_template)?,
            canonical_dom_transaction_bytes_v1(input.claim_template)?,
            refund_bytes,
        )?;
        self.publish_f7_v12(session, "gate", &record.bytes, GATE_MAX)?;
        let durable = self.load_f7_gate_v12(session)?;
        if durable.bytes != record.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        test_crash_hook("f7-v12-after-gate");
        Ok(self.f7_handle_v12(&durable))
    }

    pub(super) fn prepare_or_resume_bootstrap_f7_gate_v20(
        &self,
        chain: TrustedChainIdV1,
        input: F7FundingGatePreparationV12<'_>,
    ) -> Result<PreparedF7FundingGateV12, SessionStoreError> {
        let F7RecoveryPreparationV12::PlainRefund { refund_bytes } = &input.recovery else {
            return Err(SessionStoreError::InvalidTransition);
        };
        if let Some(handle) = self.retained_f7_funding_gate_v19(chain, input.role.session_id().0)? {
            let _guard = self.operation_lock()?;
            let gate = self.authenticate_f7_gate_v12(&handle)?;
            if gate.role.canonical_bytes()
                != input
                    .role
                    .canonical_bytes()
                    .map_err(|_| SessionStoreError::Canonical)?
                    .as_slice()
                || gate.refund_bytes.as_slice() != *refund_bytes
                || gate.funding_template
                    != canonical_dom_transaction_bytes_v1(input.funding_template)?
                || gate.claim_template != canonical_dom_transaction_bytes_v1(input.claim_template)?
                || gate.bp_statement_hash != input.collateral.statement().statement_hash()
                || gate.family == F7ExternalFamilyV11::Monero
            {
                return Err(SessionStoreError::Conflict);
            }
            return Ok(handle);
        }
        self.prepare_f7_funding_gate_v12(input)
    }

    fn f7_handle_v12(&self, gate: &F7GateRecordV12) -> PreparedF7FundingGateV12 {
        PreparedF7FundingGateV12 {
            session_id: gate.session_id,
            digest: gate.digest,
            ready_digest: gate.ready_digest,
            open_instance_id: self.open_instance_id,
        }
    }

    /// Reopen an existing native gate without creating or repairing it. Every
    /// issuance still requires its bilateral votes and the exact retained head.
    pub fn resume_f7_funding_gate_v12(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedF7FundingGateV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        if &gate.chain_id != chain.as_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        Ok(self.f7_handle_v12(&gate))
    }

    /// Discover a retained gate without confusing an absent gate with a
    /// missing ancestor, wrong chain, malformed object, or partial inventory.
    /// This does not construct a gate or authorize signing/funding.
    pub fn retained_f7_funding_gate_v19(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<Option<PreparedF7FundingGateV12>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        if &roster.chain_id != chain.as_bytes() {
            return Err(SessionStoreError::InvalidTransition);
        }
        let (inventory, _, _) = self.census_f7_artifacts_v12()?;
        let Some(kinds) = inventory.get(&session) else {
            // An accepted V12 vote without its gate is corruption, not a
            // fresh session. Never turn this into a scheduler waiting state.
            if self
                .authenticated_derived_transport_records(session, current.revision())?
                .iter()
                .any(|record| record.message_type == 0x17)
            {
                return Err(SessionStoreError::Quarantined);
            }
            return Ok(None);
        };
        if !kinds.contains(&F7ArtifactKindV12::Gate) {
            return Err(SessionStoreError::Quarantined);
        }
        let gate = self.load_f7_gate_v12(session)?;
        if &gate.chain_id != chain.as_bytes() || gate.terms_hash != current.terms_hash() {
            return Err(SessionStoreError::Quarantined);
        }
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        Ok(Some(self.f7_handle_v12(&gate)))
    }

    fn authenticate_f7_gate_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<F7GateRecordV12, SessionStoreError> {
        if self.policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
            return Err(SessionStoreError::PolicyProfile);
        }
        if handle.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let gate = self.load_f7_gate_v12(handle.session_id)?;
        if gate.digest != handle.digest || gate.ready_digest != handle.ready_digest {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        Ok(gate)
    }

    fn authenticate_f7_gate_ancestry_v12(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<(), SessionStoreError> {
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            self.authenticate_xmr_bounded_f7_ancestry_v23(gate)?;
            return Ok(());
        }
        let bound = self.load_session_revision(gate.session_id, gate.bound_revision)?;
        let roster = self.load_transport_roster(gate.session_id)?;
        let identities = self.load_transport_identity_binding(gate.session_id)?;
        require_transport_identity_binding(&roster, &identities)?;
        let early = self.load_early_transport_authority(gate.session_id)?;
        let bp = self.load_bp_transport_authority(gate.session_id)?;
        let template = self.load_template_transport_authority(gate.session_id)?;
        if bound.digest() != &gate.bound_record_digest
            || bound.terms_hash() != gate.terms_hash
            || bound.phase() != gate.phase
            || bound.irreversible().funding_authorized
            || roster.chain_id != gate.chain_id
            || early.terms_hash != gate.terms_hash
            || bp.terms_hash != gate.terms_hash
            || early.recovery_binding_hash != gate.recovery_binding_hash
            || bp.statement.statement_hash() != gate.bp_statement_hash
            || bp.early_authority_digest != early.digest
            || template.bp_authority_digest != bp.digest
            || template.template_commit_payload[..32] != gate.role.funding_template_hash()
            || template.template_commit_payload[32..64] != gate.role.claim_template_hash()
            || template.template_commit_payload[64..96] != gate.role.refund_template_hash()
            || template.template_commit_payload[96..128] != gate.bp_statement_hash
            || self.m8_funding_gate_v2_exists(gate.session_id)?
            || self.m8_funding_gate_exists(gate.session_id)?
            || self.funding_gate_exists(gate.session_id)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        if gate.family == F7ExternalFamilyV11::Monero {
            let cancel = self.audit_xmr_plain_auxiliary_round_v11(
                &roster,
                gate.cancel_session,
                &self
                    .load_operational_final_refund_v2(gate.cancel_session)?
                    .exact_transaction_bytes,
            )?;
            let compensation = self.audit_xmr_plain_auxiliary_round_v11(
                &roster,
                gate.compensation_session,
                &self
                    .load_operational_final_refund_v2(gate.compensation_session)?
                    .exact_transaction_bytes,
            )?;
            let mut bytes = Vec::new();
            for digest in [
                gate.chain_id,
                gate.session_id,
                gate.terms_hash,
                gate.bound_record_digest,
                gate.role.digest(),
                gate.graph_digest,
                gate.custody_id,
                gate.cancel_session,
                gate.compensation_session,
                cancel,
                compensation,
            ] {
                bytes.extend_from_slice(&digest);
            }
            if tagged_hash("DOM-INTEROP/XMR-ORDINARY-RECOVERY-ROUNDS/V11\0", &bytes)
                != gate.ordinary_scope
            {
                return Err(SessionStoreError::Quarantined);
            }
        } else {
            let refund = self.load_operational_final_refund_v2(gate.session_id)?;
            self.authenticate_operational_final_refund_v2_at_terminal(
                gate.session_id,
                refund.terminal_revision,
            )?;
            if refund.exact_transaction_bytes != gate.refund_bytes {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(())
    }

    /// Prepare exactly the next missing bilateral V12 readiness signature.
    pub fn prepare_next_operational_xmr_ready_to_fund_vote_v12(
        &self,
        gate: &PreparedF7FundingGateV12,
    ) -> Result<Option<PreparedOperationalXmrReadyToFundVoteV12>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.prepare_next_f7_ready_vote_locked_v12(gate)
    }
    /// DIAG(temporary): who the local signer is versus whose vote is expected.
    fn diag_ready_signer_v25(signer: &[u8; 32], expected: &[u8; 32]) {
        use std::cell::RefCell;
        thread_local! {
            static LAST_SIGNER_V25: RefCell<String> = const { RefCell::new(String::new()) };
        }
        let line = format!(
            "signer={} expected={} match={}",
            Self::hex_prefix_v25(signer),
            Self::hex_prefix_v25(expected),
            signer == expected,
        );
        LAST_SIGNER_V25.with(|last| {
            let mut last = last.borrow_mut();
            if *last != line {
                eprintln!("DOM_READY_SIGNER_V25 {line}");
                *last = line;
            }
        });
    }

    /// DIAG(temporary): one line per change of the ready-to-fund quorum shape.
    fn diag_ready_quorum_v25(
        local: &str,
        accepted: usize,
        bound_revision: u64,
        current_revision: u64,
        next_voter: Option<[u8; 32]>,
    ) {
        use std::cell::RefCell;
        thread_local! {
            static LAST_QUORUM_V25: RefCell<String> = const { RefCell::new(String::new()) };
        }
        let line = format!(
            "local={local} accepted={accepted} bound_rev={bound_revision} cur_rev={current_revision} next={}",
            next_voter
                .map(|id| Self::hex_prefix_v25(&id))
                .unwrap_or_else(|| "none".to_string()),
        );
        LAST_QUORUM_V25.with(|last| {
            let mut last = last.borrow_mut();
            if *last != line {
                eprintln!("DOM_READY_QUORUM_V25 {line}");
                *last = line;
            }
        });
    }

    fn hex_prefix_v25(id: &[u8; 32]) -> String {
        id[..3].iter().map(|b| format!("{b:02x}")).collect()
    }
    fn prepare_next_f7_ready_vote_locked_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<Option<PreparedOperationalXmrReadyToFundVoteV12>, SessionStoreError> {
        let gate = self.authenticate_f7_gate_v12(handle)?;
        let current = self.load_session_locked(gate.session_id)?;
        let accepted = self.f7_ready_count_v12(&gate, current.revision())?;
        if accepted == 2 {
            return Ok(None);
        }
        if current.phase() != gate.phase
            || current.irreversible().funding_authorized
            || current.revision() != gate.bound_revision + accepted as u64
            || self.operational_abort_transport_authority_exists(gate.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let roster = self.load_transport_roster(gate.session_id)?;
        // DIAG(temporary): name the LOCAL peer on every quorum line. Without it
        // two daemons' lines are indistinguishable in one log, which is exactly
        // how absence of a token was repeatedly misread as absence of state.
        let local_v25 = self
            .authenticate_local_transport_signer_binding(gate.session_id)
            .map(|signer| Self::hex_prefix_v25(&signer.participant_id))
            .unwrap_or_else(|_| "unknown".to_string());
        // DIAG(temporary): `AwaitingPeer` is the only thing the caller sees when
        // this returns `Some`, and it cannot say whose vote is still missing.
        // Print the quorum shape once per change: how many votes are accepted,
        // where the gate was bound, and which roster index owes the next one.
        Self::diag_ready_quorum_v25(
            &local_v25,
            accepted,
            gate.bound_revision,
            current.revision(),
            roster.participants.get(accepted).map(|p| p.participant_id),
        );
        let participant = roster
            .participants
            .get(accepted)
            .ok_or(SessionStoreError::Quarantined)?;
        Ok(Some(PreparedOperationalXmrReadyToFundVoteV12 {
            session_id: gate.session_id,
            participant_id: participant.participant_id,
            sequence: self.next_transport_sequence(gate.session_id, participant.participant_id)?,
            previous_transcript_hash: current.transcript_hash(),
            payload: gate.ready_digest,
            gate_record_digest: gate.digest,
            open_instance_id: self.open_instance_id,
        }))
    }

    fn f7_ready_count_v12(
        &self,
        gate: &F7GateRecordV12,
        revision: u64,
    ) -> Result<usize, SessionStoreError> {
        let records = self.authenticated_derived_transport_records(gate.session_id, revision)?;
        let roster = self.load_transport_roster(gate.session_id)?;
        let votes = records
            .iter()
            .filter(|record| record.message_type == 0x17)
            .collect::<Vec<_>>();
        if votes.len() > 2 {
            return Err(SessionStoreError::Quarantined);
        }
        for (index, vote) in votes.iter().enumerate() {
            if vote.revision
                != gate
                    .bound_revision
                    .checked_add(index as u64 + 1)
                    .ok_or(SessionStoreError::Quarantined)?
                || vote.phase != gate.phase
                || vote.payload.as_slice() != gate.ready_digest
                || Some(&vote.sender_id)
                    != roster.participants.get(index).map(|p| &p.participant_id)
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok(votes.len())
    }

    /// Accept only the exact gate-owned signed vote and append its transcript.
    pub fn accept_prepared_operational_xmr_ready_to_fund_vote_v12(
        &self,
        gate: &PreparedF7FundingGateV12,
        vote: PreparedOperationalXmrReadyToFundVoteV12,
        bytes: &[u8],
    ) -> Result<(), SessionStoreError> {
        let successor = {
            let _guard = self.operation_lock()?;
            let expected = self
                .prepare_next_f7_ready_vote_locked_v12(gate)?
                .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
            require_same_vote_v12(&vote, &expected)?;
            let envelope = ParsedTransportEnvelopeV1::parse(bytes)?;
            let current = self.load_session_locked(vote.session_id)?;
            let roster = self.load_transport_roster(vote.session_id)?;
            let participant = roster
                .participants
                .iter()
                .find(|p| p.participant_id == vote.participant_id)
                .ok_or(SessionStoreError::InvalidTransition)?;
            envelope.verify(&participant.identity_key)?;
            if envelope.session_id != vote.session_id
                || envelope.sender_id != vote.participant_id
                || envelope.sequence != vote.sequence
                || envelope.previous_transcript_hash != vote.previous_transcript_hash
                || envelope.message_type != 0x17
                || envelope.payload(bytes)? != vote.payload
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let transcript = accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                participant.direction,
                0x17,
                current.phase(),
            )?;
            current.advance(
                current.revision(),
                current.phase(),
                transcript,
                current.irreversible(),
                current.chain(),
                current.encrypted_payload(),
            )?
        };
        match self.accept_transport_message_with_successor(bytes, &successor, None)? {
            DurableTransportOutcomeV1::Accepted(receipt)
                if receipt.message_type == 0x17
                    && receipt.transcript_hash == successor.transcript_hash() =>
            {
                Ok(())
            }
            _ => Err(SessionStoreError::Quarantined),
        }
    }

    /// Persist the exact local identity-signer request before it leaves Store.
    pub fn prepare_xmr_ready_to_fund_dsc1_signing_request_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        vote: &PreparedOperationalXmrReadyToFundVoteV12,
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        // DIAG(temporary): prove entry before any `?` can abort silently. The
        // signer line below sits behind three fallible steps, so its absence
        // never distinguished "not called" from "aborted on the way".
        eprintln!(
            "DOM_READY_ENTRY_V25 vote_for={}",
            Self::hex_prefix_v25(&vote.participant_id)
        );
        let expected = self
            .prepare_next_f7_ready_vote_locked_v12(handle)?
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        if let Err(error) = require_same_vote_v12(vote, &expected) {
            eprintln!(
                "DOM_READY_ENTRY_V25 same_vote=refused have={} expected={}",
                Self::hex_prefix_v25(&vote.participant_id),
                Self::hex_prefix_v25(&expected.participant_id),
            );
            return Err(error);
        }
        let signer = self.authenticate_local_transport_signer_binding(vote.session_id)?;
        // DIAG(temporary): the only silent exit on the readiness path. If both
        // peers take it, the quorum can never reach two and nothing reports why.
        Self::diag_ready_signer_v25(&signer.participant_id, &vote.participant_id);
        if signer.participant_id != vote.participant_id {
            return Ok(None);
        }
        let gate = self.authenticate_f7_gate_v12(handle)?;
        let current = self.load_session_locked(vote.session_id)?;
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::UniversalReadyToFundV12,
            chain_id: gate.chain_id,
            session_id: vote.session_id,
            sender_id: vote.participant_id,
            sequence: vote.sequence,
            previous_transcript_hash: vote.previous_transcript_hash,
            predecessor: &current,
            authority_digest: gate.digest,
            payload: &vote.payload,
        })
        .map(Some)
    }

    pub(super) fn f7_ready_phase_locked_v12(
        &self,
        session: [u8; 32],
    ) -> Result<SessionPhaseV1, SessionStoreError> {
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        Ok(gate.phase)
    }
    pub(super) fn audit_f7_ready_request_locked_v12(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        _current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let gate = self.load_f7_gate_v12(request.session_id)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        if request.chain_id != gate.chain_id
            || request.authority_digest != gate.digest
            || request.payload.as_slice() != gate.ready_digest
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
    pub(super) fn expected_f7_ready_request_locked_v12(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<([u8; 32], u64, [u8; 32]), SessionStoreError> {
        self.audit_f7_ready_request_locked_v12(request, current)?;
        let gate = self.load_f7_gate_v12(request.session_id)?;
        let vote = self
            .prepare_next_f7_ready_vote_locked_v12(&self.f7_handle_v12(&gate))?
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        Ok((
            vote.participant_id,
            vote.sequence,
            vote.previous_transcript_hash,
        ))
    }
    pub(super) fn require_bounded_f7_ready_transport_edge_v12(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let gate = self.load_f7_gate_v12(envelope.session_id)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let offset = current
            .revision()
            .checked_sub(gate.bound_revision)
            .ok_or(SessionStoreError::InvalidTransition)?;
        let index = usize::try_from(offset).map_err(|_| SessionStoreError::InvalidTransition)?;
        let roster = self.load_transport_roster(gate.session_id)?;
        let participant = roster
            .participants
            .get(index)
            .ok_or(SessionStoreError::InvalidTransition)?;
        if index >= 2
            || current.phase() != gate.phase
            || successor.phase() != gate.phase
            || current.terms_hash() != gate.terms_hash
            || current.irreversible().funding_authorized
            || current.irreversible() != successor.irreversible()
            || envelope.chain_id != gate.chain_id
            || envelope.message_type != 0x17
            || envelope.sender_id != participant.participant_id
            || direction != participant.direction
            || envelope.previous_transcript_hash != current.transcript_hash()
            || envelope.payload(bytes)? != gate.ready_digest
            || envelope.sequence
                != self.transport_sequence_at_revision(
                    gate.session_id,
                    participant.participant_id,
                    current.revision(),
                )?
            || successor.revision()
                != current
                    .revision()
                    .checked_add(1)
                    .ok_or(SessionStoreError::InvalidTransition)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        envelope.verify(&participant.identity_key)?;
        if successor.transcript_hash()
            != accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                direction,
                0x17,
                gate.phase,
            )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn load_f7_gate_v12(&self, session: [u8; 32]) -> Result<F7GateRecordV12, SessionStoreError> {
        let bytes = self.read_f7_v12(session, "gate", GATE_MAX)?;
        let record = F7GateRecordV12::decode(&bytes)?;
        if record.session_id != session {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }
    fn read_f7_v12(
        &self,
        session: [u8; 32],
        kind: &str,
        limit: usize,
    ) -> Result<Vec<u8>, SessionStoreError> {
        match self.artifacts.read_bounded_file(
            &ValidatedComponent::registered(&f7_name_v12(session, kind))?,
            limit,
        ) {
            Ok(bytes) => Ok(bytes),
            Err(LinuxCapabilityError::NotFound) => Err(SessionStoreError::SessionNotFound),
            Err(error) => Err(error.into()),
        }
    }
    fn publish_f7_v12(
        &self,
        session: [u8; 32],
        kind: &str,
        bytes: &[u8],
        limit: usize,
    ) -> Result<(), SessionStoreError> {
        let name = f7_name_v12(session, kind);
        let (_, record_kind) =
            parse_f7_artifact_name_v12(&name).ok_or(SessionStoreError::Canonical)?;
        if limit != record_kind.maximum_length() {
            return Err(SessionStoreError::Canonical);
        }
        validate_f7_artifact_bytes_v12(session, record_kind, bytes)?;
        self.require_f7_artifact_publication_budget_v12(&name, bytes.len())?;
        publish_immutable(
            &self.artifacts,
            &format!(".{name}.staging"),
            &name,
            bytes,
            limit,
        )
    }
}

fn f7_name_v12(session: [u8; 32], kind: &str) -> String {
    format!("{}.f7-v12-{kind}", hex_lower(&session))
}
fn require_same_vote_v12(
    a: &PreparedOperationalXmrReadyToFundVoteV12,
    b: &PreparedOperationalXmrReadyToFundVoteV12,
) -> Result<(), SessionStoreError> {
    if a.session_id != b.session_id
        || a.participant_id != b.participant_id
        || a.sequence != b.sequence
        || a.previous_transcript_hash != b.previous_transcript_hash
        || a.payload != b.payload
        || a.gate_record_digest != b.gate_record_digest
        || a.open_instance_id != b.open_instance_id
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}

impl F7GateRecordV12 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        role: &FinalClaimRoleBindingV1,
        current: &SessionRecordV1,
        family: F7ExternalFamilyV11,
        phase: SessionPhaseV1,
        profile: F7RecoveryProfileV23,
        bp: [u8; 32],
        recovery: [u8; 32],
        graph: [u8; 32],
        custody: [u8; 32],
        ordinary: [u8; 32],
        cancel: [u8; 32],
        compensation: [u8; 32],
        xmr_setup: [u8; 32],
        xmr_tx: [u8; 32],
        graph_binding: Vec<u8>,
        policy: Vec<u8>,
        funding: Vec<u8>,
        claim: Vec<u8>,
        refund: Vec<u8>,
    ) -> Result<Self, SessionStoreError> {
        let role_bytes = role
            .canonical_bytes()
            .map_err(|_| SessionStoreError::Canonical)?;
        let mut bytes = GATE_MAGIC.to_vec();
        bytes.push(family as u8);
        bytes.extend_from_slice(&(phase as u16).to_le_bytes());
        bytes.push(match profile {
            F7RecoveryProfileV23::Legacy => 0,
            F7RecoveryProfileV23::XmrBounded => 1,
        });
        bytes.extend_from_slice(&current.revision().to_le_bytes());
        for digest in [
            role.dom_chain_id().0,
            role.session_id().0,
            role.terms_hash()
                .map_err(|_| SessionStoreError::Canonical)?,
            *current.digest(),
            bp,
            recovery,
            graph,
            custody,
            ordinary,
            cancel,
            compensation,
            xmr_setup,
            xmr_tx,
        ] {
            bytes.extend_from_slice(&digest);
        }
        for blob in [
            role_bytes.as_slice(),
            graph_binding.as_slice(),
            policy.as_slice(),
            funding.as_slice(),
            claim.as_slice(),
            refund.as_slice(),
        ] {
            put_blob(&mut bytes, blob)?;
        }
        let digest = tagged_hash(profile.gate_domain(), &bytes);
        bytes.extend_from_slice(&digest);
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() > GATE_MAX
            || bytes.len() < 20 + 13 * 32 + 6 * 4 + 32
            || &bytes[..8] != GATE_MAGIC
            || tagged_hash(
                F7RecoveryProfileV23::decode(bytes[11])?.gate_domain(),
                &bytes[..bytes.len() - 32],
            ) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let profile = F7RecoveryProfileV23::decode(bytes[11])?;
        let family = match bytes[8] {
            1 => F7ExternalFamilyV11::Evm,
            3 => F7ExternalFamilyV11::Solana,
            4 => F7ExternalFamilyV11::Monero,
            _ => return Err(SessionStoreError::Quarantined),
        };
        let phase = match u16::from_le_bytes(copy_array(&bytes[9..11])?) {
            80 => SessionPhaseV1::TemplatesCommitted,
            90 if profile == F7RecoveryProfileV23::XmrBounded => SessionPhaseV1::RefundSigning,
            100 => SessionPhaseV1::RefundSigned,
            _ => return Err(SessionStoreError::Quarantined),
        };
        let bound_revision = u64::from_le_bytes(copy_array(&bytes[12..20])?);
        let mut cursor = 20;
        let mut hashes = [[0; 32]; 13];
        for hash in &mut hashes {
            *hash = copy_array(&bytes[cursor..cursor + 32])?;
            cursor += 32;
        }
        let role_bytes = take_blob(bytes, &mut cursor, GATE_MAX)?;
        let graph_binding_bytes = take_blob(bytes, &mut cursor, 1024)?.to_vec();
        let policy_bytes = take_blob(bytes, &mut cursor, 1024)?.to_vec();
        let funding_template = take_blob(bytes, &mut cursor, GATE_MAX)?.to_vec();
        let claim_template = take_blob(bytes, &mut cursor, GATE_MAX)?.to_vec();
        let refund_bytes = take_blob(bytes, &mut cursor, GATE_MAX)?.to_vec();
        if cursor + 32 != bytes.len() {
            return Err(SessionStoreError::Quarantined);
        }
        let role = RetainedFinalClaimRoleBindingAuditV1::decode_canonical(&hashes[0], role_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if role.session_id().0 != hashes[1]
            || role
                .terms_hash()
                .map_err(|_| SessionStoreError::Quarantined)?
                != hashes[2]
            || hashes[..6].contains(&[0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let funding = Transaction::from_bytes(&funding_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let claim =
            Transaction::from_bytes(&claim_template).map_err(|_| SessionStoreError::Quarantined)?;
        if canonical_dom_transaction_bytes_v1(&funding)? != funding_template
            || canonical_dom_transaction_bytes_v1(&claim)? != claim_template
            || canonical_template_v1(&funding)
                .map_err(|_| SessionStoreError::Quarantined)?
                .1
                != role.funding_template_hash()
            || canonical_template_v1(&claim)
                .map_err(|_| SessionStoreError::Quarantined)?
                .1
                != role.claim_template_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        match family {
            F7ExternalFamilyV11::Monero => {
                let policy = XmrCompensationPolicyV11::from_bytes(&policy_bytes)
                    .map_err(|_| SessionStoreError::Quarantined)?;
                policy
                    .validate_for(role.terms())
                    .map_err(|_| SessionStoreError::Quarantined)?;
                let graph = decode_xmr_graph_binding_v12(&graph_binding_bytes)?;
                if graph.chain_id != hashes[0]
                    || graph.session_id != hashes[1]
                    || graph.terms_hash != hashes[2]
                    || graph.funding_commitment != role.shared_output_commitment()
                    || graph.claim_adaptor_point != role.adaptor_point_sec1()
                    || graph.cancel_height != policy.cancel_height
                    || graph.punish_height != policy.compensation_height
                    || graph.reveal_safety_blocks != policy.reveal_safety_blocks
                    || graph.cancel_fee != policy.cancel_fee_noms
                    || graph.refund_fee != policy.refund_fee_noms
                    || graph.punish_fee != policy.compensation_fee_noms
                    || graph.refund_recipient_commitment != policy.refund_recipient_commitment
                    || graph.punish_recipient_commitment != policy.compensation_recipient_commitment
                {
                    return Err(SessionStoreError::Quarantined);
                }
                if phase
                    != match profile {
                        F7RecoveryProfileV23::Legacy => SessionPhaseV1::TemplatesCommitted,
                        F7RecoveryProfileV23::XmrBounded => SessionPhaseV1::RefundSigning,
                    }
                    || (profile == F7RecoveryProfileV23::XmrBounded
                        && policy.bounded_availability_v23.is_none())
                    || !refund_bytes.is_empty()
                    || hashes[6..].contains(&[0; 32])
                {
                    return Err(SessionStoreError::Quarantined);
                }
            }
            _ => {
                if profile != F7RecoveryProfileV23::Legacy
                    || phase != SessionPhaseV1::RefundSigned
                    || !policy_bytes.is_empty()
                    || !graph_binding_bytes.is_empty()
                    || hashes[6..].iter().any(|hash| *hash != [0; 32])
                    || refund_bytes.is_empty()
                {
                    return Err(SessionStoreError::Quarantined);
                }
            }
        }
        let mut ready = Vec::new();
        ready.push(family as u8);
        ready.extend_from_slice(&role.digest());
        for hash in [
            hashes[4], hashes[5], hashes[6], hashes[9], hashes[10], hashes[11], hashes[12],
        ] {
            ready.extend_from_slice(&hash);
        }
        put_blob(&mut ready, &graph_binding_bytes)?;
        put_blob(&mut ready, &policy_bytes)?;
        put_blob(&mut ready, &refund_bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: copy_array(&bytes[bytes.len() - 32..])?,
            role,
            family,
            phase,
            bound_revision,
            chain_id: hashes[0],
            session_id: hashes[1],
            terms_hash: hashes[2],
            bound_record_digest: hashes[3],
            bp_statement_hash: hashes[4],
            recovery_binding_hash: hashes[5],
            graph_digest: hashes[6],
            custody_id: hashes[7],
            ordinary_scope: hashes[8],
            cancel_session: hashes[9],
            compensation_session: hashes[10],
            xmr_setup_binding_hash: hashes[11],
            xmr_funding_tx_hash: hashes[12],
            ready_digest: tagged_hash(profile.ready_domain(), &ready),
            profile,
            graph_binding_bytes,
            policy_bytes,
            funding_template,
            claim_template,
            refund_bytes,
        })
    }
}
fn put_blob(out: &mut Vec<u8>, blob: &[u8]) -> Result<(), SessionStoreError> {
    out.extend_from_slice(
        &u32::try_from(blob.len())
            .map_err(|_| SessionStoreError::CapacityExceeded)?
            .to_le_bytes(),
    );
    out.extend_from_slice(blob);
    Ok(())
}
fn take_blob<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max: usize,
) -> Result<&'a [u8], SessionStoreError> {
    let header_end = cursor
        .checked_add(4)
        .ok_or(SessionStoreError::Quarantined)?;
    let len = u32::from_le_bytes(copy_array(
        bytes
            .get(*cursor..header_end)
            .ok_or(SessionStoreError::Quarantined)?,
    )?) as usize;
    let end = header_end
        .checked_add(len)
        .ok_or(SessionStoreError::Quarantined)?;
    if len > max || end > bytes.len().saturating_sub(32) {
        return Err(SessionStoreError::Quarantined);
    }
    *cursor = end;
    bytes
        .get(header_end..end)
        .ok_or(SessionStoreError::Quarantined)
}

/// Linear permission to sign the exact native funding template after both
/// readiness signatures. It contains no external-chain placeholder fields.
pub struct F7FundingAuthorizationV12 {
    gate: PreparedF7FundingGateV12,
    funding_template: Transaction,
    predecessor_digest: [u8; 32],
}
impl F7FundingAuthorizationV12 {
    /// Only this exact signature-omitting template is authorized.
    pub const fn template(&self) -> &Transaction {
        &self.funding_template
    }
    /// Exact leg whose two identities accepted the recovery graph.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.gate.session_id
    }
}

/// Exact already-persisted transaction bytes permitted for DOM submission.
pub struct PreparedF7FundingSubmissionV12 {
    gate_digest: [u8; 32],
    terms_hash: [u8; 32],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    tx_hash: [u8; 32],
    bytes: Vec<u8>,
}
impl PreparedF7FundingSubmissionV12 {
    /// Authenticated recovery/template/readiness gate.
    pub const fn gate_digest(&self) -> [u8; 32] {
        self.gate_digest
    }
    /// Signed terms belonging to this native session.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }
    /// Exact leg session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Native chain used to validate the transaction.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
    /// Hash recomputed from exact signed bytes, never copied from a response.
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    /// Immutable persisted native transaction.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct F7FundingCommitV12 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    gate_digest: [u8; 32],
    predecessor_digest: [u8; 32],
    funding_bytes: Vec<u8>,
    successor: SessionRecordV1,
    validation_now_unix_seconds: u64,
}

/// Same-Store proof of armed recovery and exact signed collateral funding.
/// A fresh native observer still controls maturity, finality and exposure.
pub struct VerifiedXmrRecoveryExecutionAuthorityV12 {
    profile: F7RecoveryProfileV23,
    bounded_refund_pre_signature: Option<Vec<u8>>,
    bounded_custody_scope: Option<super::super::xmr_recovery::XmrRecoveryCustodyScopeV11>,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    graph_digest: [u8; 32],
    custody_id: [u8; 32],
    funding_tx_hash: [u8; 32],
    policy: ValidatedXmrCompensationPolicyV11,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    xmr_setup_binding_hash: [u8; 32],
    xmr_funding_tx_hash: [u8; 32],
    xmr_funding_observation: Option<f7_anchor_authority::families_v11::VerifiedXmrFundingV11>,
}
impl VerifiedXmrRecoveryExecutionAuthorityV12 {
    /// Authenticated native chain.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
    /// Actual leg session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Full signed economic terms.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }
    /// Complete native graph including plain cancel and compensation.
    pub const fn graph_digest(&self) -> [u8; 32] {
        self.graph_digest
    }
    /// Identity of the exact encrypted locked custody.
    pub const fn custody_id(&self) -> [u8; 32] {
        self.custody_id
    }
    /// Exact committed collateral transaction.
    pub const fn funding_tx_hash(&self) -> [u8; 32] {
        self.funding_tx_hash
    }
    /// Exact native setup admitted in both signed readiness votes.
    pub const fn xmr_setup_binding_hash(&self) -> [u8; 32] {
        self.xmr_setup_binding_hash
    }
    /// Exact native Monero funding transaction admitted in both readiness votes.
    pub const fn xmr_funding_tx_hash(&self) -> [u8; 32] {
        self.xmr_funding_tx_hash
    }
    /// Signed and mathematically validated compensation terms.
    pub const fn policy(&self) -> &ValidatedXmrCompensationPolicyV11 {
        &self.policy
    }
    /// Signed minimum canonical confirmations.
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }
    /// Signed maximum canonical reorganization depth.
    pub const fn max_reorg_depth(&self) -> u32 {
        self.max_reorg_depth
    }
    /// Compensation additionally requires a fresh exact native XMR funding
    /// observation. DOM collateral alone never establishes that XMR was paid.
    pub fn require_xmr_funding_observed_v12(&self) -> Result<(), SessionStoreError> {
        let observation = self
            .xmr_funding_observation
            .as_ref()
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
        if observation.facts().age() > std::time::Duration::from_secs(60) {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        Ok(())
    }
    /// Borrow only the fresh concrete proof already authenticated against this
    /// same gate. Historical observation checkpoints cannot construct it.
    pub fn xmr_funding_observation_v22(
        &self,
    ) -> Result<&f7_anchor_authority::families_v11::VerifiedXmrFundingV11, SessionStoreError> {
        self.require_xmr_funding_observed_v12()?;
        self.xmr_funding_observation
            .as_ref()
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)
    }

    /// Issue an advisory scope witness only from this authority's fresh,
    /// verified funding observation. This never replaces the V22 consensus
    /// condition or its attestor certificate and cannot authorize a payment.
    pub fn compensation_funding_witness_v22(
        &self,
    ) -> Result<dom_scriptless_crypto::XmrCompensationFundingWitnessV22, SessionStoreError> {
        let observation = self.xmr_funding_observation_v22()?;
        let funding_id = match observation.funding_id() {
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(hash) => *hash,
            _ => return Err(SessionStoreError::InvalidTransition),
        };
        if funding_id != self.xmr_funding_tx_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        dom_scriptless_crypto::XmrCompensationFundingWitnessV22::from_authorized_observation_v22(
            self.chain_id,
            self.session_id,
            self.terms_hash,
            funding_id,
        )
        .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)
    }

    /// Check the closed Store-origin profile against this exact graph. The
    /// bounded profile relies on its signed environmental availability bounds;
    /// it never claims a consensus condition on an ordinary compensation.
    pub fn require_graph_profile_v23(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
    ) -> Result<(), SessionStoreError> {
        if graph.graph_digest() != &self.graph_digest
            || graph.binding().chain_id != self.chain_id
            || graph.binding().session_id != self.session_id
            || graph.binding().terms_hash != self.terms_hash
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match self.profile {
            F7RecoveryProfileV23::Legacy => graph
                .require_conditional_compensation_v22()
                .map_err(|_| SessionStoreError::FundingAuthorityUnavailable),
            F7RecoveryProfileV23::XmrBounded => {
                if self.bounded_refund_pre_signature.as_deref()
                    != Some(graph.refund_pre_signature().to_bytes().as_slice())
                {
                    return Err(SessionStoreError::InvalidTransition);
                }
                let availability = self
                    .policy
                    .policy()
                    .bounded_availability_v23
                    .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
                availability
                    .required_reserves(self.minimum_confirmations, self.max_reorg_depth)
                    .map_err(|_| SessionStoreError::FundingAuthorityUnavailable)?;
                Ok(())
            }
        }
    }

    /// Permit ordinary compensation only for the Store-authenticated bounded
    /// profile and a fresh exact XMR payment proof. This is not a consensus
    /// condition; role, height and write-ahead attempt remain execution gates.
    pub fn require_bounded_compensation_v23(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
    ) -> Result<(), SessionStoreError> {
        require_bounded_compensation_profile_v23(self.profile)?;
        self.require_graph_profile_v23(graph)?;
        self.require_xmr_funding_observed_v12()
    }

    /// Reauthenticate custody immediately before reading private material.
    pub fn require_custody(
        &self,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<(), SessionStoreError> {
        custody
            .revalidate()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let scope = custody.scope();
        if self.profile == F7RecoveryProfileV23::XmrBounded {
            let expected = self
                .bounded_custody_scope
                .as_ref()
                .ok_or(SessionStoreError::Quarantined)?;
            if scope != expected {
                return Err(SessionStoreError::InvalidTransition);
            }
            custody
                .with_graph(|graph| self.require_graph_profile_v23(graph))
                .map_err(|_| SessionStoreError::Quarantined)??;
        }
        if scope.custody_id != self.custody_id
            || scope.graph_digest != self.graph_digest
            || scope.binding.chain_id != self.chain_id
            || scope.binding.session_id != self.session_id
            || scope.binding.terms_hash != self.terms_hash
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
}

impl ContractsSessionStoreV1 {
    /// Issue funding only after both native identity-signed V12 votes exist.
    /// This grants the exact DOM template, never XMR funding before collateral.
    pub fn authorize_f7_funding_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<F7FundingAuthorizationV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            // Native bounded funding must use the durable post-vote origin and
            // six audited messages, never this raw-template authorization path.
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let current = self.load_session_locked(gate.session_id)?;
        if self.f7_ready_count_v12(&gate, current.revision())? != 2
            || current.revision()
                != gate
                    .bound_revision
                    .checked_add(2)
                    .ok_or(SessionStoreError::Quarantined)?
            || current.phase() != gate.phase
            || current.irreversible().funding_authorized
            || self.operational_abort_transport_authority_exists(gate.session_id)?
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_f7_funding_window_v12(&gate, current.chain().tip_height)?;
        match self.read_f7_v12(gate.session_id, "funding", COMMIT_MAX) {
            Err(SessionStoreError::SessionNotFound) => {}
            Ok(_) => return Err(SessionStoreError::Conflict),
            Err(error) => return Err(error),
        }
        let funding_template = Transaction::from_bytes(&gate.funding_template)
            .map_err(|_| SessionStoreError::Quarantined)?;
        Ok(F7FundingAuthorizationV12 {
            gate: self.f7_handle_v12(&gate),
            funding_template,
            predecessor_digest: *current.digest(),
        })
    }

    /// Commit exact signed collateral bytes before any submission capability
    /// exists. The native verifier checks the full transaction and template.
    pub fn commit_f7_funding_v12(
        &self,
        authorization: F7FundingAuthorizationV12,
        signed_bytes: &[u8],
        context: DomTransactionValidationContextV1,
    ) -> Result<PreparedF7FundingSubmissionV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(&authorization.gate)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        let current = self.load_session_locked(gate.session_id)?;
        if current.digest() != &authorization.predecessor_digest
            || current.phase() != gate.phase
            || current.irreversible().funding_authorized
            || context.chain_id() != &gate.chain_id
            || context.current_height() != current.chain().tip_height
            || self.f7_ready_count_v12(&gate, current.revision())? != 2
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        require_f7_funding_window_v12(&gate, current.chain().tip_height)?;
        let transaction = validate_exact_dom_transaction(signed_bytes, context)?;
        if canonical_template_v1(&transaction)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            .1
            != gate.role.funding_template_hash()
            || transaction
                .outputs
                .iter()
                .filter(|o| o.commitment.as_bytes() == &gate.role.shared_output_commitment())
                .count()
                != 1
        {
            return Err(SessionStoreError::InvalidDomTransaction);
        }
        let mut irreversible = current.irreversible();
        irreversible.funding_authorized = true;
        let successor = current.advance(
            current.revision(),
            SessionPhaseV1::FundingBroadcast,
            current.transcript_hash(),
            irreversible,
            current.chain(),
            current.encrypted_payload(),
        )?;
        let commit = F7FundingCommitV12::new(
            gate.digest,
            *current.digest(),
            signed_bytes,
            successor,
            context.now_unix_seconds(),
        )?;
        self.publish_f7_v12(gate.session_id, "funding", &commit.bytes, COMMIT_MAX)?;
        test_crash_hook("f7-v12-funding-after-exact-bytes");
        self.persist_session_record(&commit.successor)?;
        test_crash_hook("f7-v12-funding-after-successor");
        let durable = self.load_f7_funding_v12(&gate)?;
        if durable.bytes != commit.bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(f7_submission(&gate, durable.funding_bytes))
    }

    /// Recover only the same signed bytes after a crash; no replacement
    /// transaction or new signature is generated by this recovery edge.
    pub fn resume_f7_committed_funding_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<PreparedF7FundingSubmissionV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        let commit = self.load_f7_funding_v12(&gate)?;
        let current = self.load_session_locked(gate.session_id)?;
        if current.digest() == &commit.predecessor_digest {
            self.persist_session_record(&commit.successor)?;
        } else if current.revision() < commit.successor.revision()
            || !current.irreversible().funding_authorized
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(f7_submission(&gate, commit.funding_bytes))
    }

    /// Produce a closed recovery permission from the actual committed V12
    /// collateral and bilateral ready signatures. Recovery does not require
    /// the absent counterparty to sign again.
    pub fn authorize_xmr_recovery_execution_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<VerifiedXmrRecoveryExecutionAuthorityV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if gate.family != F7ExternalFamilyV11::Monero {
            return Err(SessionStoreError::InvalidTransition);
        }
        let commit = self.load_xmr_recovery_funding_v23(&gate, custody)?;
        let policy = XmrCompensationPolicyV11::from_bytes(&gate.policy_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?
            .validate_for(gate.role.terms())
            .map_err(|_| SessionStoreError::Quarantined)?;
        let bounded_refund_pre_signature = match gate.profile {
            F7RecoveryProfileV23::Legacy => None,
            F7RecoveryProfileV23::XmrBounded => Some(
                self.reconstruct_completed_xmr_graph_v23(gate.session_id)?
                    .graph()
                    .refund_pre_signature()
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let authority = VerifiedXmrRecoveryExecutionAuthorityV12 {
            profile: gate.profile,
            bounded_refund_pre_signature,
            bounded_custody_scope: match gate.profile {
                F7RecoveryProfileV23::XmrBounded => {
                    Some(self.expected_xmr_recovery_scope_locked_v23(&gate)?)
                }
                F7RecoveryProfileV23::Legacy => None,
            },
            chain_id: gate.chain_id,
            session_id: gate.session_id,
            terms_hash: gate.terms_hash,
            graph_digest: gate.graph_digest,
            custody_id: gate.custody_id,
            funding_tx_hash: *blake2b_256(&commit.funding_bytes).as_bytes(),
            policy,
            minimum_confirmations: gate.role.terms().dom_leg.finality.min_confirmations,
            max_reorg_depth: gate.role.terms().dom_leg.finality.max_reorg_depth,
            xmr_setup_binding_hash: gate.xmr_setup_binding_hash,
            xmr_funding_tx_hash: gate.xmr_funding_tx_hash,
            xmr_funding_observation: None,
        };
        authority.require_custody(custody)?;
        Ok(authority)
    }

    fn load_f7_funding_v12(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<F7FundingCommitV12, SessionStoreError> {
        let commit = F7FundingCommitV12::decode(&self.read_f7_v12(
            gate.session_id,
            "funding",
            COMMIT_MAX,
        )?)?;
        let signing = self.optional_f7_funding_signing_v20(gate)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded && signing.is_none() {
            return Err(SessionStoreError::Quarantined);
        }
        let predecessor_revision = match signing.as_ref() {
            Some(record) => record.successor.revision().checked_add(6),
            None => gate.bound_revision.checked_add(2),
        }
        .ok_or(SessionStoreError::Quarantined)?;
        let predecessor = self.load_session_revision(gate.session_id, predecessor_revision)?;
        if commit.gate_digest != gate.digest
            || commit.predecessor_digest != *predecessor.digest()
            || commit.successor.session_id() != gate.session_id
            || commit.successor.terms_hash() != gate.terms_hash
            || commit.successor.phase() != SessionPhaseV1::FundingBroadcast
            || !commit.successor.irreversible().funding_authorized
            || predecessor.irreversible().funding_authorized != signing.is_some()
            || commit.successor.revision()
                != predecessor
                    .revision()
                    .checked_add(1)
                    .ok_or(SessionStoreError::Quarantined)?
            || self.f7_ready_count_v12(gate, predecessor.revision())? != 2
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut irreversible = predecessor.irreversible();
        irreversible.funding_authorized = true;
        let expected = predecessor.advance(
            predecessor.revision(),
            SessionPhaseV1::FundingBroadcast,
            predecessor.transcript_hash(),
            irreversible,
            predecessor.chain(),
            predecessor.encrypted_payload(),
        )?;
        if expected.as_bytes() != commit.successor.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        let transaction = Transaction::from_bytes(&commit.funding_bytes)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if canonical_dom_transaction_bytes_v1(&transaction)? != commit.funding_bytes
            || canonical_template_v1(&transaction)
                .map_err(|_| SessionStoreError::Quarantined)?
                .1
                != gate.role.funding_template_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        if let Some(signing) = signing.as_ref() {
            let signature = self
                .audit_f7_funding_signing_v20(gate, signing, &predecessor, true)?
                .ok_or(SessionStoreError::Quarantined)?;
            if transaction.kernels.len() != 1
                || transaction.kernels[0].excess_signature != signature.to_bytes()
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        // Recheck actual native signatures at the historical committed height;
        // timestamps do not authorize claim or refund through this reader.
        validate_exact_dom_transaction(
            &commit.funding_bytes,
            DomTransactionValidationContextV1::new(
                predecessor.chain().tip_height,
                gate.chain_id,
                commit.validation_now_unix_seconds,
            ),
        )?;
        Ok(commit)
    }
    pub(super) fn audit_f7_funded_session_v12(
        &self,
        current: &SessionRecordV1,
    ) -> Result<bool, SessionStoreError> {
        let gate = match self.load_f7_gate_v12(current.session_id()) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let before_funding_commit = match self.read_f7_v12(gate.session_id, "funding", COMMIT_MAX) {
            Ok(_) => false,
            Err(SessionStoreError::SessionNotFound) => true,
            Err(error) => return Err(error),
        };
        if before_funding_commit
            && matches!(
                current.phase(),
                SessionPhaseV1::FundingAuthorized | SessionPhaseV1::FailedClosed
            )
        {
            if let Some(signing) = self.optional_f7_funding_signing_v20(&gate)? {
                let _signature =
                    self.audit_f7_funding_signing_v20(&gate, &signing, current, false)?;
                return Ok(true);
            }
        }
        let commit = self.load_f7_funding_v12(&gate)?;
        if current.digest() == &commit.predecessor_digest
            && current.phase() == SessionPhaseV1::FundingAuthorized
            && self.optional_f7_funding_signing_v20(&gate)?.is_some()
        {
            // Signed bytes were published, then the process stopped before
            // FundingBroadcast CAS. load_f7_funding authenticated all six
            // signatures; the exact frozen successor is repaired on resume.
            return Ok(true);
        }
        if current.revision() < commit.successor.revision()
            || current.terms_hash() != gate.terms_hash
            || !current.irreversible().funding_authorized
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(true)
    }
}
fn f7_submission(gate: &F7GateRecordV12, bytes: Vec<u8>) -> PreparedF7FundingSubmissionV12 {
    PreparedF7FundingSubmissionV12 {
        gate_digest: gate.digest,
        terms_hash: gate.terms_hash,
        session_id: gate.session_id,
        chain_id: gate.chain_id,
        tx_hash: *blake2b_256(&bytes).as_bytes(),
        bytes,
    }
}
fn require_f7_funding_window_v12(
    gate: &F7GateRecordV12,
    height: u64,
) -> Result<(), SessionStoreError> {
    let deadline = match gate.role.terms().dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => return Err(SessionStoreError::InvalidTransition),
    };
    let reserve = u64::from(gate.role.terms().dom_leg.finality.min_confirmations)
        .checked_add(u64::from(
            gate.role.terms().dom_leg.finality.max_reorg_depth,
        ))
        .ok_or(SessionStoreError::InvalidTransition)?;
    require_f7_funding_windows_v23(
        deadline,
        reserve,
        gate.profile,
        &gate.graph_binding_bytes,
        height,
    )
}

// Callers authenticate the complete gate before this public-data timing check.
// It never reconstructs a graph or mints an authority.
fn require_f7_funding_windows_v23(
    deadline: u64,
    reserve: u64,
    profile: F7RecoveryProfileV23,
    graph_binding_bytes: &[u8],
    height: u64,
) -> Result<(), SessionStoreError> {
    if height
        .checked_add(reserve)
        .ok_or(SessionStoreError::InvalidTransition)?
        >= deadline
    {
        return Err(SessionStoreError::FundingAuthorityUnavailable);
    }
    if profile == F7RecoveryProfileV23::XmrBounded {
        let binding = decode_xmr_graph_binding_v12(graph_binding_bytes)?;
        // Preserve the negotiated reveal margin on every fresh signing and
        // transmission check. Equality closes the window, just like
        // VerifiedXmrRecoveryGraphV11::require_claim_window.
        height
            .checked_add(binding.reveal_safety_blocks)
            .filter(|reserved| *reserved < binding.cancel_height)
            .ok_or(SessionStoreError::FundingAuthorityUnavailable)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "f7_xmr_funding_window_v23_tests.rs"]
mod xmr_funding_window_v23_tests;

impl F7FundingCommitV12 {
    fn new(
        gate_digest: [u8; 32],
        predecessor_digest: [u8; 32],
        funding: &[u8],
        successor: SessionRecordV1,
        validation_now_unix_seconds: u64,
    ) -> Result<Self, SessionStoreError> {
        let mut bytes = b"DOMFFC12".to_vec();
        bytes.extend_from_slice(&gate_digest);
        bytes.extend_from_slice(&predecessor_digest);
        bytes.extend_from_slice(&validation_now_unix_seconds.to_le_bytes());
        put_blob(&mut bytes, funding)?;
        put_blob(&mut bytes, successor.as_bytes())?;
        let digest = tagged_hash("DOM-INTEROP/F7-FUNDING-COMMIT/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < 120
            || bytes.len() > COMMIT_MAX
            || &bytes[..8] != b"DOMFFC12"
            || tagged_hash(
                "DOM-INTEROP/F7-FUNDING-COMMIT/V12\0",
                &bytes[..bytes.len() - 32],
            ) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let gate_digest = copy_array(&bytes[8..40])?;
        let predecessor_digest = copy_array(&bytes[40..72])?;
        let validation_now_unix_seconds = u64::from_le_bytes(copy_array(&bytes[72..80])?);
        let mut cursor = 80;
        let funding_bytes = take_blob(bytes, &mut cursor, COMMIT_MAX)?.to_vec();
        let successor =
            SessionRecordV1::from_bytes(take_blob(bytes, &mut cursor, SESSION_RECORD_MAX_LEN)?)?;
        if cursor + 32 != bytes.len()
            || gate_digest == [0; 32]
            || predecessor_digest == [0; 32]
            || validation_now_unix_seconds == 0
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: copy_array(&bytes[bytes.len() - 32..])?,
            gate_digest,
            predecessor_digest,
            funding_bytes,
            successor,
            validation_now_unix_seconds,
        })
    }
}

/// Native post-anchor permission consumed durably before any claim nonce.
pub struct ConsumedF7ClaimAuthorizationV12 {
    session_id: [u8; 32],
    issuance_digest: [u8; 32],
    consumption_digest: [u8; 32],
    open_instance_id: [u8; 32],
    owner: Arc<()>,
    observed_at: std::cell::Cell<std::time::Instant>,
}
impl ConsumedF7ClaimAuthorizationV12 {
    /// Exact native claim session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    fn require_recent_observation(&self) -> Result<(), SessionStoreError> {
        if self.observed_at.get().elapsed()
            > f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        Ok(())
    }

    /// True while the last concrete external-chain observation can still back
    /// Store operations guarded by the native F7 recency window.
    pub fn has_recent_observation_v12(&self) -> bool {
        self.require_recent_observation().is_ok()
    }

    /// True when callers can skip an RPC refresh and still have enough recency
    /// headroom for the next local Store operation to complete its checks.
    pub fn can_reuse_observation_v12(&self) -> bool {
        const MIN_HEADROOM: std::time::Duration = std::time::Duration::from_secs(15);
        self.observed_at.get().elapsed() + MIN_HEADROOM
            <= f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE
    }

    /// Called only after the fresh opaque F7 token has passed scope and ancestry
    /// validation. Retain its scan origin, not the completion time of this audit.
    fn retain_observation_at(&self, observed_at: std::time::Instant) {
        self.observed_at.set(observed_at);
    }
}

pub(super) struct F7ClaimRecordV12 {
    pub(super) bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
    pub(super) consumption_digest: [u8; 32],
    pub(super) session_id: [u8; 32],
    pub(super) chain_id: [u8; 32],
    pub(super) terms_hash: [u8; 32],
    pub(super) dom_funding_id: [u8; 32],
    pub(super) claim_template_hash: [u8; 32],
    pub(super) adaptor_point: PublicKey,
    pub(super) bound_session_revision: u64,
    pub(super) bound_session_record_digest: [u8; 32],
    pub(super) round_start_transcript_hash: [u8; 32],
    pub(super) issuance_id: [u8; 32],
    pub(super) gate_digest: [u8; 32],
    pub(super) funding_commit_digest: [u8; 32],
    pub(super) final_claim_role_binding_digest: [u8; 32],
    pub(super) ready_binding_digest: [u8; 32],
    external_funding: f7_anchor_authority::families_v11::F7FundingIdV11,
}

pub(super) struct F7ClaimRoundBindingV12 {
    pub(super) issuance_record_digest: [u8; 32],
    pub(super) consumption_record_digest: [u8; 32],
    pub(super) signing_binding_record_digest: [u8; 32],
    pub(super) roster_digest: [u8; 32],
    pub(super) round_start_record_digest: [u8; 32],
    pub(super) final_claim_role_binding_digest: [u8; 32],
    pub(super) ready_binding_digest: [u8; 32],
}
impl ContractsSessionStoreV1 {
    /// Authenticate a prefunding recovery attachment without granting funding
    /// or returning private U. Later execution additionally requires commit.
    pub fn validate_xmr_recovery_attachment_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        self.validate_xmr_recovery_attachment_locked_v23(&gate, custody)
    }

    fn validate_xmr_recovery_attachment_locked_v23(
        &self,
        gate: &F7GateRecordV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<(), SessionStoreError> {
        custody
            .revalidate()
            .map_err(|_| SessionStoreError::Quarantined)?;
        if gate.family != F7ExternalFamilyV11::Monero
            || custody.scope().custody_id != gate.custody_id
            || custody.scope().graph_digest != gate.graph_digest
            || custody.scope().binding.chain_id != gate.chain_id
            || custody.scope().binding.session_id != gate.session_id
            || custody.scope().binding.terms_hash != gate.terms_hash
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if gate.profile == F7RecoveryProfileV23::XmrBounded
            && custody.scope() != &self.expected_xmr_recovery_scope_locked_v23(gate)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Consume fresh concrete F7 anchors, persist native funding confirmation,
    /// then issue and consume exactly one claim authorization. Restart repeats
    /// native chain verification and recovers the same immutable issuance.
    pub fn consume_f7_claim_authorization_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        anchors: VerifiedF7AnchorAuthorizationV12,
    ) -> Result<ConsumedF7ClaimAuthorizationV12, SessionStoreError> {
        anchors
            .require_recent()
            .map_err(|_| SessionStoreError::ClaimSigningAuthorityUnavailable)?;
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        self.require_downstream_claim_gate_locked_v23(&gate)?;
        let commit = self.load_f7_funding_v12(&gate)?;
        let mut current = self.load_session_locked(gate.session_id)?;
        if anchors.family() != gate.family
            || anchors
                .role()
                .digest()
                .map_err(|_| SessionStoreError::Canonical)?
                != gate.role.digest()
            || anchors.dom_funding_txid() != blake2b_256(&commit.funding_bytes).as_bytes()
            || anchors.graph_digest()
                != (gate.family == F7ExternalFamilyV11::Monero).then_some(gate.graph_digest)
            || !f7_anchors_match_xmr_setup_v12(&gate, &anchors)
            || !current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || !matches!(
                current.phase(),
                SessionPhaseV1::FundingBroadcast | SessionPhaseV1::FundingConfirmed
            )
            || self.post_anchor_claim_issuance_v2_exists(gate.session_id)?
            || self.post_anchor_claim_issuance_exists(gate.session_id)?
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        if current.phase() == SessionPhaseV1::FundingBroadcast {
            if anchors.round_start_transcript_hash() != &current.transcript_hash() {
                return Err(SessionStoreError::InvalidTransition);
            }
            let mut chain = current.chain();
            chain.tip_id = *anchors.dom_tip_hash();
            chain.tip_height = anchors.dom_tip_height();
            chain.funding = SessionTxObservationV1::Confirmed {
                block_id: *anchors.dom_block_hash(),
                height: anchors.dom_height(),
            };
            current = current.advance(
                current.revision(),
                SessionPhaseV1::FundingConfirmed,
                current.transcript_hash(),
                current.irreversible(),
                chain,
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&current)?;
        }
        let issued = match self.read_f7_v12(gate.session_id, "claim-issued", 4096) {
            Ok(bytes) => {
                let issued = F7ClaimRecordV12::decode(&bytes)?;
                if issued.external_funding != anchors.funding_id()
                    || issued.gate_digest != gate.digest
                    || issued.funding_commit_digest != commit.digest
                    || issued.dom_funding_id != *anchors.dom_funding_txid()
                    || issued.round_start_transcript_hash != *anchors.round_start_transcript_hash()
                {
                    return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
                }
                issued
            }
            Err(SessionStoreError::SessionNotFound) => {
                if current.transcript_hash() != *anchors.round_start_transcript_hash() {
                    return Err(SessionStoreError::InvalidTransition);
                }
                let issued =
                    F7ClaimRecordV12::new(&gate, &commit, &current, &anchors, random_nonzero()?)?;
                self.publish_f7_v12(gate.session_id, "claim-issued", &issued.bytes, 4096)?;
                test_crash_hook("f7-v12-claim-after-issuance");
                issued
            }
            Err(error) => return Err(error),
        };
        self.require_live_f7_claim_v12(&issued, &current)?;
        // Native monotonic time is fresh here. Updating the current projection
        // does not replace the immutable claim-round predecessor.
        if current.chain().tip_id != *anchors.dom_tip_hash()
            || current.chain().tip_height != anchors.dom_tip_height()
        {
            let mut chain = current.chain();
            chain.tip_id = *anchors.dom_tip_hash();
            chain.tip_height = anchors.dom_tip_height();
            chain.funding = SessionTxObservationV1::Confirmed {
                block_id: *anchors.dom_block_hash(),
                height: anchors.dom_height(),
            };
            current = current.advance(
                current.revision(),
                current.phase(),
                current.transcript_hash(),
                current.irreversible(),
                chain,
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&current)?;
        }
        let owner = self.reserve_claim_signing_process_owner_v2(issued.issuance_id)?;
        let consumed = f7_claim_consumption(&issued);
        self.publish_f7_v12(gate.session_id, "claim-consumed", &consumed, 128)?;
        test_crash_hook("f7-v12-claim-after-consumption");
        let (_, authenticated, _) = self.authenticate_f7_claim_v12(gate.session_id)?;
        Ok(ConsumedF7ClaimAuthorizationV12 {
            session_id: gate.session_id,
            issuance_digest: issued.digest,
            consumption_digest: authenticated.consumption_digest,
            open_instance_id: self.open_instance_id,
            owner,
            observed_at: std::cell::Cell::new(anchors.observed_at()),
        })
    }

    fn require_f7_consumed_handle_v12(
        &self,
        handle: &ConsumedF7ClaimAuthorizationV12,
    ) -> Result<(F7GateRecordV12, F7ClaimRecordV12, SessionRecordV1), SessionStoreError> {
        if handle.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        handle.require_recent_observation()?;
        let result = self.authenticate_f7_claim_v12(handle.session_id)?;
        self.require_downstream_claim_gate_locked_v23(&result.0)?;
        if result.1.digest != handle.issuance_digest
            || result.1.consumption_digest != handle.consumption_digest
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.require_claim_signing_process_owner_v2(result.1.issuance_id, &handle.owner)?;
        self.require_live_f7_claim_v12(&result.1, &result.2)?;
        Ok(result)
    }

    pub(super) fn f7_claim_profile_exists_v12(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        let issued = match self.read_f7_v12(session, "claim-issued", 4096) {
            Ok(bytes) => F7ClaimRecordV12::decode(&bytes)?,
            Err(SessionStoreError::SessionNotFound) => {
                for kind in [
                    "claim-consumed",
                    "claim-binding",
                    "claim-pre",
                    "claim-exposure-v14",
                    "claim-admission-v14",
                ] {
                    match self.read_f7_v12(session, kind, GATE_MAX) {
                        Err(SessionStoreError::SessionNotFound) => {}
                        Ok(_) => return Err(SessionStoreError::Quarantined),
                        Err(error) => return Err(error),
                    }
                }
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if issued.session_id != session
            || self.post_anchor_claim_issuance_v2_exists(session)?
            || self.post_anchor_claim_issuance_exists(session)?
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(true)
    }
    pub(super) fn authenticate_f7_claim_v12(
        &self,
        session: [u8; 32],
    ) -> Result<(F7GateRecordV12, F7ClaimRecordV12, SessionRecordV1), SessionStoreError> {
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let funding = self.load_f7_funding_v12(&gate)?;
        let mut issued =
            F7ClaimRecordV12::decode(&self.read_f7_v12(session, "claim-issued", 4096)?)?;
        let consumed = self.read_f7_v12(session, "claim-consumed", 128)?;
        if consumed != f7_claim_consumption(&issued) {
            return Err(SessionStoreError::Quarantined);
        }
        self.authenticate_f7_issuance_ancestry_v12(&gate, &funding, &issued)?;
        issued.consumption_digest = copy_array(&consumed[consumed.len() - 32..])?;
        let current = self.load_session_locked(session)?;
        Ok((gate, issued, current))
    }
    fn authenticate_f7_issuance_ancestry_v12(
        &self,
        gate: &F7GateRecordV12,
        funding: &F7FundingCommitV12,
        issued: &F7ClaimRecordV12,
    ) -> Result<(), SessionStoreError> {
        let session = gate.session_id;
        if issued.session_id != session
            || issued.chain_id != gate.chain_id
            || issued.terms_hash != gate.terms_hash
            || issued.gate_digest != gate.digest
            || issued.funding_commit_digest != funding.digest
            || issued.dom_funding_id != *blake2b_256(&funding.funding_bytes).as_bytes()
            || issued.claim_template_hash != gate.role.claim_template_hash()
            || issued.adaptor_point.to_compressed_bytes() != gate.role.adaptor_point_sec1()
            || issued.final_claim_role_binding_digest != gate.role.digest()
            || issued.ready_binding_digest != gate.ready_digest
        {
            return Err(SessionStoreError::Quarantined);
        }
        let bound = self.load_session_revision(session, issued.bound_session_revision)?;
        if bound.digest() != &issued.bound_session_record_digest
            || bound.phase() != SessionPhaseV1::FundingConfirmed
            || bound.transcript_hash() != issued.round_start_transcript_hash
            || !bound.irreversible().funding_authorized
        {
            return Err(SessionStoreError::Quarantined);
        }
        if bound.terms_hash() != gate.terms_hash
            || bound.revision() <= funding.successor.revision()
            || !matches!(
                bound.chain().funding,
                SessionTxObservationV1::Confirmed { .. }
            )
            || !matches!(
                (gate.family, issued.external_funding),
                (
                    F7ExternalFamilyV11::Solana,
                    f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(_)
                ) | (
                    F7ExternalFamilyV11::Evm | F7ExternalFamilyV11::Monero,
                    f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(_)
                )
            )
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
    pub(super) fn require_live_f7_claim_v12(
        &self,
        issued: &F7ClaimRecordV12,
        current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        if current.session_id() != issued.session_id
            || current.terms_hash() != issued.terms_hash
            || current.phase() != SessionPhaseV1::FundingConfirmed
            || !current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || current.revision() < issued.bound_session_revision
            || !matches!(
                current.chain().funding,
                SessionTxObservationV1::Confirmed { .. }
            )
            || !matches!(current.chain().claim, SessionTxObservationV1::Unknown)
            || !matches!(current.chain().refund, SessionTxObservationV1::Unknown)
            || self.f7_abort_blocks_revision_v12(issued.session_id, current.revision())?
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        let gate = self.load_f7_gate_v12(issued.session_id)?;
        require_f7_funding_window_v12(&gate, current.chain().tip_height)
    }

    /// Bind the real native ClaimAdaptor signing session only after its V12
    /// authority has been consumed and both actual anchors remain valid.
    pub fn bind_post_anchor_dom_claim_signing_session_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
        kind: ContractKindV1,
        roster: ParticipantRosterV1,
        transaction: Transaction,
        kernel_index: usize,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (gate, issued, current) = self.require_f7_consumed_handle_v12(authorization)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            let binding = self.authenticate_xmr_bounded_claim_binding_v23(issued.session_id)?;
            if chain != binding.chain
                || kind != ContractKindV1::WitnessOrTimeout
                || kernel_index != 0
                || participant_roster_digest(&roster) != participant_roster_digest(&binding.roster)
                || canonical_dom_transaction_bytes_v1(&transaction)?
                    != canonical_dom_transaction_bytes_v1(&binding.template)?
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            self.audit_xmr_bounded_claim_current_round_v23(&binding, &current)?;
            let record = self.xmr_claim_binding_record_v23(&binding);
            self.publish_f7_v12(issued.session_id, "claim-binding", &record.encode(), 512)?;
            return self.resume_xmr_bounded_claim_signing_locked_v23(chain, authorization);
        }
        if chain.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let transport = self.load_transport_roster(issued.session_id)?;
        let early =
            self.load_authenticated_early_signing_authority(issued.session_id, &transport)?;
        self.validate_post_anchor_signing_inputs(
            &chain,
            &current,
            kind,
            &roster,
            &transaction,
            kernel_index,
            &issued.adaptor_point,
            &transport,
            &early,
        )?;
        let template_hash = canonical_template_v1(&transaction)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?
            .1;
        if template_hash != issued.claim_template_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        let round = self.audit_operational_signing_round(
            issued.session_id,
            PurposeV1::ClaimAdaptor,
            &roster,
            template_hash,
            SessionPhaseV1::FundingConfirmed,
        )?;
        if round.round_start_transcript_hash != issued.round_start_transcript_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        let initial = initial_transcript_hash_v1(&chain, &issued.session_id, kind, &roster);
        let binding = SigningSessionBindingRecordV1::new(
            &chain,
            &current,
            kind,
            PurposeV1::ClaimAdaptor,
            &roster,
            &canonical_dom_transaction_bytes_v1(&transaction)?,
            template_hash,
            kernel_index,
            Some(&issued.adaptor_point),
            initial,
            &round,
        )?;
        self.persist_signing_binding(&binding)?;
        let binding_digest = copy_array(&binding.bytes[binding.bytes.len() - 32..])?;
        let round_binding = F7ClaimRoundBindingV12 {
            issuance_record_digest: issued.digest,
            consumption_record_digest: issued.consumption_digest,
            signing_binding_record_digest: binding_digest,
            roster_digest: participant_roster_digest(&roster),
            round_start_record_digest: round.round_start_record_digest,
            final_claim_role_binding_digest: issued.final_claim_role_binding_digest,
            ready_binding_digest: issued.ready_binding_digest,
        };
        self.publish_f7_v12(
            issued.session_id,
            "claim-binding",
            &round_binding.encode(),
            512,
        )?;
        Ok(AcceptedContractsSigningSessionV1 {
            trusted_chain_id: chain,
            session_id: issued.session_id,
            contract_kind: kind,
            purpose: PurposeV1::ClaimAdaptor,
            roster,
            transaction_template: transaction,
            kernel_index,
            adaptor_point: Some(issued.adaptor_point),
            initial_transcript_hash: initial,
            round_start_transcript_hash: round.round_start_transcript_hash,
            sender_sequence_bases: round.sender_sequence_bases,
            accepted_messages: round.accepted_messages,
            _session_revision: round.round_start_revision,
            _session_record_digest: round.round_start_record_digest,
            _open_instance_id: self.open_instance_id,
            _post_anchor_consumption_digest: Some(issued.consumption_digest),
        })
    }
    /// Resume from the same native binding and nonce transcript, never a new
    /// caller-chosen template or nonce epoch.
    pub fn resume_post_anchor_dom_claim_signing_session_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let decoded = {
            let _guard = self.operation_lock()?;
            let (gate, _, _) = self.require_f7_consumed_handle_v12(authorization)?;
            if gate.profile == F7RecoveryProfileV23::XmrBounded {
                return self.resume_xmr_bounded_claim_signing_locked_v23(chain, authorization);
            }
            self.load_signing_binding(authorization.session_id, PurposeV1::ClaimAdaptor)?
                .decode(&chain)?
        };
        self.bind_post_anchor_dom_claim_signing_session_v12(
            authorization,
            chain,
            decoded.contract_kind,
            decoded.roster,
            decoded.transaction_template,
            decoded.kernel_index,
        )
    }
    pub(super) fn read_f7_claim_binding_v12(
        &self,
        session: [u8; 32],
    ) -> Result<F7ClaimRoundBindingV12, SessionStoreError> {
        F7ClaimRoundBindingV12::decode(&self.read_f7_v12(session, "claim-binding", 512)?)
    }
}
impl F7ClaimRecordV12 {
    fn new(
        gate: &F7GateRecordV12,
        funding: &F7FundingCommitV12,
        current: &SessionRecordV1,
        anchors: &VerifiedF7AnchorAuthorizationV12,
        issuance_id: [u8; 32],
    ) -> Result<Self, SessionStoreError> {
        let mut bytes = b"DOMFCA12".to_vec();
        bytes.extend_from_slice(&current.revision().to_le_bytes());
        for hash in [
            gate.session_id,
            gate.chain_id,
            gate.terms_hash,
            *anchors.dom_funding_txid(),
            gate.role.claim_template_hash(),
            *current.digest(),
            current.transcript_hash(),
            issuance_id,
            gate.digest,
            funding.digest,
            gate.role.digest(),
            gate.ready_digest,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&gate.role.adaptor_point_sec1());
        match anchors.funding_id() {
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id);
                bytes.extend_from_slice(&[0; 32]);
            }
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(id) => {
                bytes.push(2);
                bytes.extend_from_slice(&id);
            }
        }
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-ISSUANCE/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        const LEN: usize = 8 + 8 + 12 * 32 + 33 + 1 + 64 + 32;
        if bytes.len() != LEN
            || &bytes[..8] != b"DOMFCA12"
            || tagged_hash("DOM-INTEROP/F7-CLAIM-ISSUANCE/V12\0", &bytes[..LEN - 32])
                != bytes[LEN - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut cursor = 16;
        let mut hashes = [[0; 32]; 12];
        for hash in &mut hashes {
            *hash = copy_array(&bytes[cursor..cursor + 32])?;
            cursor += 32;
        }
        if hashes.contains(&[0; 32]) {
            return Err(SessionStoreError::Quarantined);
        }
        let adaptor_point =
            PublicKey::from_compressed_bytes(&copy_array::<33>(&bytes[cursor..cursor + 33])?)
                .map_err(|_| SessionStoreError::Quarantined)?;
        cursor += 33;
        let external_funding = match bytes[cursor] {
            1 if bytes[cursor + 33..cursor + 65] == [0; 32] => {
                f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(copy_array(
                    &bytes[cursor + 1..cursor + 33],
                )?)
            }
            2 => f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(copy_array(
                &bytes[cursor + 1..cursor + 65],
            )?),
            _ => return Err(SessionStoreError::Quarantined),
        };
        match external_funding {
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(id) if id == [0; 32] => {
                return Err(SessionStoreError::Quarantined);
            }
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(id)
                if id == [0; 64] =>
            {
                return Err(SessionStoreError::Quarantined);
            }
            _ => {}
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: copy_array(&bytes[LEN - 32..])?,
            consumption_digest: [0; 32],
            session_id: hashes[0],
            chain_id: hashes[1],
            terms_hash: hashes[2],
            dom_funding_id: hashes[3],
            claim_template_hash: hashes[4],
            bound_session_revision: u64::from_le_bytes(copy_array(&bytes[8..16])?),
            bound_session_record_digest: hashes[5],
            round_start_transcript_hash: hashes[6],
            issuance_id: hashes[7],
            gate_digest: hashes[8],
            funding_commit_digest: hashes[9],
            final_claim_role_binding_digest: hashes[10],
            ready_binding_digest: hashes[11],
            adaptor_point,
            external_funding,
        })
    }
}
fn f7_claim_consumption(issued: &F7ClaimRecordV12) -> Vec<u8> {
    let mut bytes = b"DOMFCN12".to_vec();
    bytes.extend_from_slice(&issued.session_id);
    bytes.extend_from_slice(&issued.digest);
    let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-CONSUMPTION/V12\0", &bytes);
    bytes.extend_from_slice(&digest);
    bytes
}
impl F7ClaimRoundBindingV12 {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = b"DOMFCB12".to_vec();
        for hash in [
            self.issuance_record_digest,
            self.consumption_record_digest,
            self.signing_binding_record_digest,
            self.roster_digest,
            self.round_start_record_digest,
            self.final_claim_role_binding_digest,
            self.ready_binding_digest,
        ] {
            bytes.extend_from_slice(&hash);
        }
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-ROUND-BINDING/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != 8 + 8 * 32
            || &bytes[..8] != b"DOMFCB12"
            || tagged_hash(
                "DOM-INTEROP/F7-CLAIM-ROUND-BINDING/V12\0",
                &bytes[..bytes.len() - 32],
            ) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut hashes = [[0; 32]; 7];
        for (i, h) in hashes.iter_mut().enumerate() {
            *h = copy_array(&bytes[8 + i * 32..8 + (i + 1) * 32])?;
        }
        if hashes.contains(&[0; 32]) {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self {
            issuance_record_digest: hashes[0],
            consumption_record_digest: hashes[1],
            signing_binding_record_digest: hashes[2],
            roster_digest: hashes[3],
            round_start_record_digest: hashes[4],
            final_claim_role_binding_digest: hashes[5],
            ready_binding_digest: hashes[6],
        })
    }
}

impl ContractsSessionStoreV1 {
    /// Bind using only the exact already-authenticated gate's native roster and
    /// transaction. Caller cannot replace a payout or signing participant.
    pub fn bind_retained_f7_claim_signing_session_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
    ) -> Result<AcceptedContractsSigningSessionV1, SessionStoreError> {
        let (role, transaction) = {
            let _guard = self.operation_lock()?;
            let (gate, _, _) = self.require_f7_consumed_handle_v12(authorization)?;
            let role =
                FinalClaimRoleBindingV1::decode_canonical(&chain, gate.role.canonical_bytes())
                    .map_err(|_| SessionStoreError::Quarantined)?;
            let tx = Transaction::from_bytes(&gate.claim_template)
                .map_err(|_| SessionStoreError::Quarantined)?;
            (role, tx)
        };
        self.bind_post_anchor_dom_claim_signing_session_v12(
            authorization,
            chain,
            ContractKindV1::WitnessOrTimeout,
            role.roster().clone(),
            transaction,
            role.claim_kernel_index() as usize,
        )
    }
    /// Refresh a consumed authority using new concrete native observations.
    /// The immutable issuance, original round transcript and nonce epoch stay.
    pub fn revalidate_consumed_f7_claim_authorization_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        anchors: VerifiedF7AnchorAuthorizationV12,
    ) -> Result<(), SessionStoreError> {
        anchors
            .require_recent()
            .map_err(|_| SessionStoreError::ClaimSigningAuthorityUnavailable)?;
        let _guard = self.operation_lock()?;
        let (gate, issued, current) = self.authenticate_f7_claim_v12(authorization.session_id)?;
        self.require_downstream_claim_gate_locked_v23(&gate)?;
        if authorization.open_instance_id != self.open_instance_id
            || authorization.issuance_digest != issued.digest
            || authorization.consumption_digest != issued.consumption_digest
            || anchors.family() != gate.family
            || anchors
                .role()
                .digest()
                .map_err(|_| SessionStoreError::Canonical)?
                != gate.role.digest()
            || anchors.dom_funding_txid() != &issued.dom_funding_id
            || anchors.funding_id() != issued.external_funding
            || anchors.graph_digest()
                != (gate.family == F7ExternalFamilyV11::Monero).then_some(gate.graph_digest)
            || !f7_anchors_match_xmr_setup_v12(&gate, &anchors)
            || anchors.round_start_transcript_hash() != &issued.round_start_transcript_hash
        {
            return Err(SessionStoreError::ClaimSigningAuthorityUnavailable);
        }
        self.require_claim_signing_process_owner_v2(issued.issuance_id, &authorization.owner)?;
        self.require_live_f7_claim_v12(&issued, &current)?;
        require_f7_funding_window_v12(&gate, anchors.dom_tip_height())?;
        if current.chain().tip_id != *anchors.dom_tip_hash()
            || current.chain().tip_height != anchors.dom_tip_height()
        {
            let mut projection = current.chain();
            projection.tip_id = *anchors.dom_tip_hash();
            projection.tip_height = anchors.dom_tip_height();
            projection.funding = SessionTxObservationV1::Confirmed {
                block_id: *anchors.dom_block_hash(),
                height: anchors.dom_height(),
            };
            let next = current.advance(
                current.revision(),
                current.phase(),
                current.transcript_hash(),
                current.irreversible(),
                projection,
                current.encrypted_payload(),
            )?;
            self.persist_session_record(&next)?;
        }
        authorization.retain_observation_at(anchors.observed_at());
        Ok(())
    }
    pub(super) fn require_authenticated_f7_claim_signing_successor_v12(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        if envelope.message_type == 0x0f {
            return self.require_bounded_f7_claim_pre_signature_edge_v12(
                current,
                envelope,
                bytes,
                direction,
                successor,
                recovery_scope,
            );
        }
        let (gate, issued, _) = self.authenticate_f7_claim_v12(current.session_id())?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            return self.require_xmr_bounded_claim_successor_v23(
                current,
                envelope,
                bytes,
                direction,
                successor,
                recovery_scope,
            );
        }
        self.require_live_f7_claim_v12(&issued, current)?;
        let signing = self.load_signing_binding(current.session_id(), PurposeV1::ClaimAdaptor)?;
        let binding = self.read_f7_claim_binding_v12(current.session_id())?;
        if successor.phase() != SessionPhaseV1::FundingConfirmed
            || signing.bytes[48..80] != issued.chain_id
            || signing.bytes[80..112] != issued.terms_hash
            || binding.issuance_record_digest != issued.digest
            || binding.consumption_record_digest != issued.consumption_digest
            || binding.signing_binding_record_digest
                != copy_array(&signing.bytes[signing.bytes.len() - 32..])?
            || binding.final_claim_role_binding_digest != issued.final_claim_role_binding_digest
            || binding.ready_binding_digest != issued.ready_binding_digest
            || !(0x0c..=0x0e).contains(&envelope.message_type)
            || signing_payload_purpose(envelope.message_type, envelope.payload(bytes)?)?
                != PurposeV1::ClaimAdaptor
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(current.session_id())?;
        self.require_derived_transport_prefix_with_recovery_scope(
            current,
            &roster,
            envelope,
            bytes,
            SessionPhaseV1::FundingConfirmed,
            recovery_scope,
        )?;
        self.require_signing_transport_semantic_replay_with_recovery_scope(
            current,
            envelope,
            bytes,
            successor,
            (PurposeV1::ClaimAdaptor, SessionPhaseV1::FundingConfirmed),
            recovery_scope,
        )?;
        require_exact_successor(current, current.revision(), successor)?;
        if envelope.previous_transcript_hash != current.transcript_hash()
            || successor.transcript_hash()
                != accepted_transport_transcript_hash(
                    &current.transcript_hash(),
                    &envelope.message_digest,
                    direction,
                    envelope.message_type,
                    SessionPhaseV1::FundingConfirmed,
                )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
}

impl ContractsSessionStoreV1 {
    fn derive_f7_pre_at_terminal_v12(
        &self,
        session_id: [u8; 32],
        terminal_revision: u64,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<F7PreRecordV12, SessionStoreError> {
        let (gate, issued, _) = self.authenticate_f7_claim_v12(session_id)?;
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            return self.derive_xmr_bounded_claim_pre_v23(
                session_id,
                terminal_revision,
                recovery_scope,
            );
        }
        let terminal = self.load_session_revision(session_id, terminal_revision)?;
        let signing = self.load_signing_binding(session_id, PurposeV1::ClaimAdaptor)?;
        let signing_digest_offset = signing
            .bytes
            .len()
            .checked_sub(DIGEST_LEN)
            .ok_or(SessionStoreError::Quarantined)?;
        let signing_binding_record_digest = copy_array(
            signing
                .bytes
                .get(signing_digest_offset..)
                .ok_or(SessionStoreError::Quarantined)?,
        )?;
        let round_binding = self.read_f7_claim_binding_v12(session_id)?;
        let binding = self.authenticate_signing_replay_binding(
            &terminal,
            PurposeV1::ClaimAdaptor,
            SessionPhaseV1::FundingConfirmed,
        )?;
        let roster = self.load_transport_roster(session_id)?;

        let mut roster_bytes = Vec::with_capacity(202);
        roster_bytes.extend_from_slice(&2_u16.to_le_bytes());
        for index in 0..2 {
            let offset = 472 + index * 99;
            roster_bytes.extend_from_slice(
                signing
                    .bytes
                    .get(offset..offset + 99)
                    .ok_or(SessionStoreError::Quarantined)?,
            );
        }
        let roster_digest = tagged_hash(POST_ANCHOR_CLAIM_ROSTER_HASH_TAG, &roster_bytes);
        let round_start = self.load_session_revision(session_id, binding.round_start_revision)?;
        self.require_live_f7_claim_v12(&issued, &round_start)
            .map_err(|_| SessionStoreError::Quarantined)?;
        self.require_live_f7_claim_v12(&issued, &terminal)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if issued.session_id != session_id
            || terminal.revision() != terminal_revision
            || terminal.phase() != SessionPhaseV1::FundingConfirmed
            || terminal_revision <= binding.round_start_revision
            || roster.chain_id != issued.chain_id
            || signing.session_id != session_id
            || signing.purpose != PurposeV1::ClaimAdaptor
            || signing.bytes[48..80] != issued.chain_id
            || binding.template_hash != issued.claim_template_hash
            || binding.adaptor_point.as_ref() != Some(&issued.adaptor_point)
            || binding.round_start_transcript_hash != issued.round_start_transcript_hash
            || round_binding.issuance_record_digest != issued.digest
            || round_binding.consumption_record_digest != issued.consumption_digest
            || round_binding.signing_binding_record_digest != signing_binding_record_digest
            || round_binding.roster_digest != roster_digest
            || round_binding.round_start_record_digest != binding.round_start_record_digest
            || round_binding.final_claim_role_binding_digest
                != issued.final_claim_role_binding_digest
            || round_binding.ready_binding_digest != issued.ready_binding_digest
        {
            return Err(SessionStoreError::Quarantined);
        }

        let records = self.authenticated_derived_transport_records_with_recovery_scope(
            session_id,
            terminal_revision,
            recovery_scope,
        )?;
        let mut accepted_messages = Vec::with_capacity(6);
        let signing_records: Vec<_> = records
            .iter()
            .filter(|record| {
                record.revision > binding.round_start_revision
                    && record.revision <= terminal_revision
                    && (0x0c..=0x0e).contains(&record.message_type)
                    && record.purpose == Some(PurposeV1::ClaimAdaptor)
            })
            .collect();
        if signing_records.len() != 6
            || signing_records.last().map(|record| record.revision) != Some(terminal_revision)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut previous_round_record = round_start;
        for record in signing_records {
            if record.phase != SessionPhaseV1::FundingConfirmed
                || !(0x0c..=0x0e).contains(&record.message_type)
                || record.purpose != Some(PurposeV1::ClaimAdaptor)
            {
                return Err(SessionStoreError::Quarantined);
            }
            let predecessor_revision = record
                .revision
                .checked_sub(1)
                .ok_or(SessionStoreError::Quarantined)?;
            let predecessor = self.load_session_revision(session_id, predecessor_revision)?;
            self.require_projection_only_session_lineage(&previous_round_record, &predecessor)?;
            self.require_live_f7_claim_v12(&issued, &predecessor)
                .map_err(|_| SessionStoreError::Quarantined)?;
            previous_round_record = self.load_session_revision(session_id, record.revision)?;
            self.require_live_f7_claim_v12(&issued, &previous_round_record)
                .map_err(|_| SessionStoreError::Quarantined)?;
            accepted_messages.push(record.signed_bytes.clone());
        }
        if previous_round_record.as_bytes() != terminal.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }

        let mut transcript = binding.round_start_transcript_hash;
        let mut reveal_transcript_hash = None;
        for (position, bytes) in accepted_messages.iter().enumerate() {
            let envelope = ParsedTransportEnvelopeV1::parse(bytes)?;
            let participant = binding
                .participant(position % 2)
                .ok_or(SessionStoreError::Quarantined)?;
            let phase = signing_phase_for_message(envelope.message_type)
                .ok_or(SessionStoreError::Quarantined)?;
            transcript = advance_transcript_hash_v1(
                &transcript,
                &envelope.message_digest,
                participant.direction,
                phase,
            );
            if position == 3 {
                reveal_transcript_hash = Some(transcript);
            }
        }
        let round = OperationalSigningRoundAuditV1 {
            round_start_revision: binding.round_start_revision,
            round_start_record_digest: binding.round_start_record_digest,
            round_start_transcript_hash: binding.round_start_transcript_hash,
            reveal_transcript_hash,
            terminal_revision,
            terminal_record_digest: *terminal.digest(),
            terminal_transcript_hash: terminal.transcript_hash(),
            sender_sequence_bases: binding.sender_sequence_bases,
            template_commit_payload: binding.template_commit_payload,
            accepted_messages,
        };
        validate_operational_signing_round_semantics(
            &issued.chain_id,
            session_id,
            PurposeV1::ClaimAdaptor,
            &binding,
            &round,
        )?;
        let pre_signature = derive_post_anchor_claim_pre_signature(
            &issued.chain_id,
            session_id,
            &issued.claim_template_hash,
            &issued.adaptor_point,
            &binding,
            &round,
        )?;
        let canonical_sender = binding
            .participant(0)
            .ok_or(SessionStoreError::Quarantined)?;
        let canonical_sender_sequence = binding.sender_sequence_bases[0]
            .checked_add(3)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        if self.transport_sequence_at_revision(
            session_id,
            *canonical_sender.participant_id,
            terminal_revision,
        )? != canonical_sender_sequence
        {
            return Err(SessionStoreError::Quarantined);
        }
        F7PreRecordV12::new(
            &issued,
            &round,
            signing_binding_record_digest,
            *canonical_sender.participant_id,
            canonical_sender_sequence,
            canonical_sender.direction,
            pre_signature,
        )
    }
}

struct F7PreRecordV12 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    terminal_revision: u64,
    terminal_transcript_hash: [u8; 32],
    terminal_record_digest: [u8; 32],
    canonical_sender_id: [u8; 32],
    canonical_sender_sequence: u64,
    canonical_sender_direction: DirectionV1,
    reveal_transcript_hash: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
}
impl F7PreRecordV12 {
    fn new(
        issued: &F7ClaimRecordV12,
        round: &OperationalSigningRoundAuditV1,
        signing_digest: [u8; 32],
        sender: [u8; 32],
        sequence: u64,
        direction: DirectionV1,
        pre_signature: AdaptorPreSignatureV1,
    ) -> Result<Self, SessionStoreError> {
        let reveal = round
            .reveal_transcript_hash
            .ok_or(SessionStoreError::Quarantined)?;
        let mut bytes = b"DOMFCP12".to_vec();
        bytes.extend_from_slice(&round.terminal_revision.to_le_bytes());
        bytes.extend_from_slice(&sequence.to_le_bytes());
        bytes.push(direction.to_byte());
        for hash in [
            issued.session_id,
            issued.chain_id,
            issued.digest,
            issued.consumption_digest,
            signing_digest,
            round.terminal_transcript_hash,
            round.terminal_record_digest,
            sender,
            reveal,
        ] {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&pre_signature.to_bytes());
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-PRE/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        Ok(Self {
            bytes,
            digest,
            session_id: issued.session_id,
            chain_id: issued.chain_id,
            terminal_revision: round.terminal_revision,
            terminal_transcript_hash: round.terminal_transcript_hash,
            terminal_record_digest: round.terminal_record_digest,
            canonical_sender_id: sender,
            canonical_sender_sequence: sequence,
            canonical_sender_direction: direction,
            reveal_transcript_hash: reveal,
            pre_signature,
        })
    }
}
/// Authenticated aggregate pre-signature derived from all six native shares.
pub struct AuthenticatedF7ClaimPreSignatureV12 {
    session_id: [u8; 32],
    claim_template_hash: [u8; 32],
    reveal_transcript_hash: [u8; 32],
    pre_signature: AdaptorPreSignatureV1,
}
impl AuthenticatedF7ClaimPreSignatureV12 {
    /// Exact native session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Frozen claim template covered by the pre-signature.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }
    /// Exact transcript at the nonce reveal boundary.
    pub const fn reveal_transcript_hash(&self) -> &[u8; 32] {
        &self.reveal_transcript_hash
    }
    /// Consume the native verified aggregate into the DOM finalizer.
    pub fn into_pre_signature(self) -> AdaptorPreSignatureV1 {
        self.pre_signature
    }
}
/// Closed authority for the single native V12 aggregate0x0f exchange.
pub struct PreparedF7ClaimPreSignatureTransportV12 {
    record: F7PreRecordV12,
    open_instance_id: [u8; 32],
}
impl PreparedF7ClaimPreSignatureTransportV12 {
    /// Exact leg session.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.record.session_id
    }
    /// Native six-message terminal transcript.
    pub const fn terminal_transcript_hash(&self) -> &[u8; 32] {
        &self.record.terminal_transcript_hash
    }
    /// Deterministic participant that publishes the aggregate pre-signature.
    pub const fn canonical_sender_id(&self) -> [u8; 32] {
        self.record.canonical_sender_id
    }
}
impl ContractsSessionStoreV1 {
    /// Reconstruct the aggregate only from the complete native retained round.
    pub fn reconstruct_post_anchor_dom_claim_pre_signature_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
    ) -> Result<AuthenticatedF7ClaimPreSignatureV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (_, issued, current) = self.require_f7_consumed_handle_v12(authorization)?;
        if chain.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let terminal =
            self.f7_signing_terminal_revision_v12(issued.session_id, current.revision())?;
        let record = self.derive_f7_pre_at_terminal_v12(issued.session_id, terminal, None)?;
        self.publish_f7_v12(issued.session_id, "claim-pre", &record.bytes, 4096)?;
        test_crash_hook("f7-v12-claim-after-native-pre");
        Ok(AuthenticatedF7ClaimPreSignatureV12 {
            session_id: issued.session_id,
            claim_template_hash: issued.claim_template_hash,
            reveal_transcript_hash: record.reveal_transcript_hash,
            pre_signature: record.pre_signature,
        })
    }
    fn f7_signing_terminal_revision_v12(
        &self,
        session: [u8; 32],
        maximum: u64,
    ) -> Result<u64, SessionStoreError> {
        let records = self.authenticated_derived_transport_records(session, maximum)?;
        records
            .iter()
            .filter(|r| r.message_type == 0x0e && r.purpose == Some(PurposeV1::ClaimAdaptor))
            .map(|r| r.revision)
            .max()
            .ok_or(SessionStoreError::ClaimSigningAuthorityUnavailable)
    }
    fn load_f7_pre_v12(&self, session: [u8; 32]) -> Result<F7PreRecordV12, SessionStoreError> {
        let bytes = self.read_f7_v12(session, "claim-pre", 4096)?;
        if bytes.len() < 24 || &bytes[..8] != b"DOMFCP12" {
            return Err(SessionStoreError::Quarantined);
        }
        let terminal = u64::from_le_bytes(copy_array(&bytes[8..16])?);
        let record = self.derive_f7_pre_at_terminal_v12(session, terminal, None)?;
        if record.bytes != bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }
    /// Prepare only the same already-retained native aggregate exchange.
    pub fn prepare_f7_claim_pre_signature_transport_v12(
        &self,
        authorization: &ConsumedF7ClaimAuthorizationV12,
        chain: TrustedChainIdV1,
    ) -> Result<PreparedF7ClaimPreSignatureTransportV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let (_, issued, current) = self.require_f7_consumed_handle_v12(authorization)?;
        if chain.as_bytes() != &issued.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = self.load_f7_pre_v12(issued.session_id)?;
        self.require_f7_pre_head_v12(&record, &current)?;
        Ok(PreparedF7ClaimPreSignatureTransportV12 {
            record,
            open_instance_id: self.open_instance_id,
        })
    }
    fn require_f7_pre_head_v12(
        &self,
        record: &F7PreRecordV12,
        current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let terminal = self.load_session_revision(record.session_id, record.terminal_revision)?;
        if terminal.digest() != &record.terminal_record_digest {
            return Err(SessionStoreError::Quarantined);
        }
        if current.transcript_hash() == record.terminal_transcript_hash {
            return self.require_projection_only_session_lineage(&terminal, current);
        }
        let name = transport_message_name(
            record.session_id,
            record.canonical_sender_id,
            record.canonical_sender_sequence,
            false,
        );
        let retained = TransportMessageRecordV1::from_bytes(&self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        )?)?;
        // Authenticate the already accepted edge at its own predecessor. This
        // does not allow a second edge or a new transcript after a restart.
        let (envelope, _) = self.authenticate_transport_record(&name, &retained)?;
        if envelope.message_type != 0x0f
            || envelope.previous_transcript_hash != record.terminal_transcript_hash
            || envelope.payload(&retained.signed_bytes)? != record.pre_signature.to_bytes()
            || current.transcript_hash() != retained.successor.transcript_hash()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_projection_only_session_lineage(&retained.successor, current)
    }
    /// Persist an exact request for the selected local identity signer.
    pub fn prepare_f7_claim_pre_signature_dsc1_signing_request_v12(
        &self,
        prepared: &PreparedF7ClaimPreSignatureTransportV12,
    ) -> Result<Option<PreparedDsc1SigningRequestV1>, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if prepared.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = self.load_f7_pre_v12(prepared.record.session_id)?;
        if record.bytes != prepared.record.bytes {
            return Err(SessionStoreError::InvalidTransition);
        }
        let current = self.load_session_locked(record.session_id)?;
        self.require_f7_pre_head_v12(&record, &current)?;
        let signer = self.authenticate_local_transport_signer_binding(record.session_id)?;
        if signer.participant_id != record.canonical_sender_id {
            return Ok(None);
        }
        self.issue_outbound_dsc1_request_locked(OutboundDsc1RequestIssueV1 {
            authority_class: OutboundDsc1AuthorityClassV1::UniversalClaimPreSignatureV12,
            chain_id: record.chain_id,
            session_id: record.session_id,
            sender_id: record.canonical_sender_id,
            sequence: record.canonical_sender_sequence,
            previous_transcript_hash: record.terminal_transcript_hash,
            predecessor: &current,
            authority_digest: record.digest,
            payload: &record.pre_signature.to_bytes(),
        })
        .map(Some)
    }
    /// Accept one exact identity-signed0x0f with native aggregate verification.
    pub fn accept_prepared_f7_claim_pre_signature_transport_v12(
        &self,
        prepared: &PreparedF7ClaimPreSignatureTransportV12,
        bytes: &[u8],
    ) -> Result<DurableTransportOutcomeV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        if prepared.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = self.load_f7_pre_v12(prepared.record.session_id)?;
        if record.bytes != prepared.record.bytes {
            return Err(SessionStoreError::InvalidTransition);
        }
        let envelope = ParsedTransportEnvelopeV1::parse(bytes)?;
        let roster = self.load_transport_roster(record.session_id)?;
        let participant = roster
            .participants
            .iter()
            .find(|p| p.participant_id == record.canonical_sender_id)
            .ok_or(SessionStoreError::Quarantined)?;
        envelope.verify(&participant.identity_key)?;
        if envelope.chain_id != record.chain_id
            || envelope.session_id != record.session_id
            || envelope.sender_id != record.canonical_sender_id
            || envelope.sequence != record.canonical_sender_sequence
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let name = transport_message_name(
            record.session_id,
            record.canonical_sender_id,
            record.canonical_sender_sequence,
            false,
        );
        match self.messages.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            TRANSPORT_MESSAGE_MAX_LEN,
        ) {
            Ok(retained_bytes) => {
                let retained = TransportMessageRecordV1::from_bytes(&retained_bytes)?;
                let (retained_envelope, _) =
                    self.authenticate_transport_record(&name, &retained)?;
                if retained_envelope.message_type != 0x0f
                    || retained_envelope.previous_transcript_hash != record.terminal_transcript_hash
                    || retained_envelope.payload(&retained.signed_bytes)?
                        != record.pre_signature.to_bytes()
                {
                    return Err(SessionStoreError::Quarantined);
                }
                let current = self.load_session_locked(record.session_id)?;
                match self.accept_transport_message_with_successor_locked(bytes, &current, None) {
                    Ok(outcome) => return Ok(outcome),
                    Err(SessionStoreError::InvalidTransition) => {}
                    Err(error) => return Err(error),
                }
                let current = self.load_session_locked(record.session_id)?;
                let failed = current.advance(
                    current.revision(),
                    SessionPhaseV1::FailedClosed,
                    current.transcript_hash(),
                    current.irreversible(),
                    current.chain(),
                    current.encrypted_payload(),
                )?;
                return self.accept_transport_message_with_successor_locked(
                    bytes,
                    &current,
                    Some(&failed),
                );
            }
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let current = self.load_session_locked(record.session_id)?;
        self.require_f7_pre_head_v12(&record, &current)?;
        let transcript = accepted_transport_transcript_hash(
            &current.transcript_hash(),
            &envelope.message_digest,
            record.canonical_sender_direction,
            0x0f,
            SessionPhaseV1::FundingConfirmed,
        )?;
        let successor = current.advance(
            current.revision(),
            current.phase(),
            transcript,
            current.irreversible(),
            current.chain(),
            current.encrypted_payload(),
        )?;
        self.require_bounded_f7_claim_pre_signature_edge_v12(
            &current,
            &envelope,
            bytes,
            record.canonical_sender_direction,
            &successor,
            None,
        )?;
        self.accept_transport_message_with_successor_locked(bytes, &successor, None)
    }
    pub(super) fn audit_f7_claim_pre_signature_request_locked_v12(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        _current: &SessionRecordV1,
    ) -> Result<(), SessionStoreError> {
        let record = self.load_f7_pre_v12(request.session_id)?;
        if request.authority_digest != record.digest
            || request.chain_id != record.chain_id
            || request.payload != record.pre_signature.to_bytes()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
    pub(super) fn expected_f7_claim_pre_signature_request_locked_v12(
        &self,
        request: &OutboundDsc1SigningRequestRecordV1,
        current: &SessionRecordV1,
    ) -> Result<([u8; 32], u64, [u8; 32]), SessionStoreError> {
        self.audit_f7_claim_pre_signature_request_locked_v12(request, current)?;
        let record = self.load_f7_pre_v12(request.session_id)?;
        self.require_f7_pre_head_v12(&record, current)?;
        if current.transcript_hash() != record.terminal_transcript_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok((
            record.canonical_sender_id,
            record.canonical_sender_sequence,
            record.terminal_transcript_hash,
        ))
    }
    fn require_bounded_f7_claim_pre_signature_edge_v12(
        &self,
        current: &SessionRecordV1,
        envelope: &ParsedTransportEnvelopeV1,
        bytes: &[u8],
        direction: DirectionV1,
        successor: &SessionRecordV1,
        recovery_scope: Option<&RecoveryTransportAuditScopeV1>,
    ) -> Result<(), SessionStoreError> {
        let persisted = self.read_f7_v12(current.session_id(), "claim-pre", 4096)?;
        if persisted.len() < 24 || &persisted[..8] != b"DOMFCP12" {
            return Err(SessionStoreError::Quarantined);
        }
        let record = self.derive_f7_pre_at_terminal_v12(
            current.session_id(),
            u64::from_le_bytes(copy_array(&persisted[8..16])?),
            recovery_scope,
        )?;
        if record.bytes != persisted {
            return Err(SessionStoreError::Quarantined);
        }
        if current.transcript_hash() != record.terminal_transcript_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.require_f7_pre_head_v12(&record, current)?;
        let roster = self.load_transport_roster(record.session_id)?;
        let participant = roster
            .participants
            .iter()
            .find(|p| p.participant_id == record.canonical_sender_id)
            .ok_or(SessionStoreError::Quarantined)?;
        envelope.verify(&participant.identity_key)?;
        if envelope.chain_id != record.chain_id
            || envelope.session_id != record.session_id
            || envelope.sender_id != record.canonical_sender_id
            || envelope.sequence != record.canonical_sender_sequence
            || direction != record.canonical_sender_direction
            || envelope.message_type != 0x0f
            || envelope.previous_transcript_hash != record.terminal_transcript_hash
            || envelope.payload(bytes)? != record.pre_signature.to_bytes()
            || successor.phase() != SessionPhaseV1::FundingConfirmed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        require_exact_successor(current, current.revision(), successor)?;
        if successor.transcript_hash()
            != accepted_transport_transcript_hash(
                &current.transcript_hash(),
                &envelope.message_digest,
                direction,
                0x0f,
                SessionPhaseV1::FundingConfirmed,
            )?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
}
fn encode_xmr_graph_binding_v12(
    value: &dom_scriptless_crypto::XmrRecoveryGraphBindingV11,
) -> Vec<u8> {
    let mut bytes = b"DOMXGB12".to_vec();
    for hash in [value.chain_id, value.session_id, value.terms_hash] {
        bytes.extend_from_slice(&hash);
    }
    for point in [
        value.funding_commitment,
        value.cancelled_commitment,
        value.refund_recipient_commitment,
        value.punish_recipient_commitment,
        value.claim_adaptor_point,
        value.refund_adaptor_point,
    ] {
        bytes.extend_from_slice(&point);
    }
    for number in [
        value.cancel_height,
        value.punish_height,
        value.reveal_safety_blocks,
        value.cancel_fee,
        value.refund_fee,
        value.punish_fee,
    ] {
        bytes.extend_from_slice(&number.to_le_bytes());
    }
    bytes
}
fn decode_xmr_graph_binding_v12(
    bytes: &[u8],
) -> Result<dom_scriptless_crypto::XmrRecoveryGraphBindingV11, SessionStoreError> {
    if bytes.len() != 8 + 3 * 32 + 6 * 33 + 6 * 8 || &bytes[..8] != b"DOMXGB12" {
        return Err(SessionStoreError::Quarantined);
    }
    let mut cursor = 8;
    let mut hashes = [[0; 32]; 3];
    for hash in &mut hashes {
        *hash = copy_array(&bytes[cursor..cursor + 32])?;
        cursor += 32;
    }
    let mut points = [[0; 33]; 6];
    for point in &mut points {
        *point = copy_array(&bytes[cursor..cursor + 33])?;
        cursor += 33;
        PublicKey::from_compressed_bytes(point).map_err(|_| SessionStoreError::Quarantined)?;
    }
    let mut nums = [0u64; 6];
    for number in &mut nums {
        *number = u64::from_le_bytes(copy_array(&bytes[cursor..cursor + 8])?);
        cursor += 8;
    }
    if hashes.contains(&[0; 32]) || nums[0] == 0 || nums[1] <= nums[0] || nums[2] == 0 {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(dom_scriptless_crypto::XmrRecoveryGraphBindingV11 {
        chain_id: hashes[0],
        session_id: hashes[1],
        terms_hash: hashes[2],
        funding_commitment: points[0],
        cancelled_commitment: points[1],
        refund_recipient_commitment: points[2],
        punish_recipient_commitment: points[3],
        claim_adaptor_point: points[4],
        refund_adaptor_point: points[5],
        cancel_height: nums[0],
        punish_height: nums[1],
        reveal_safety_blocks: nums[2],
        cancel_fee: nums[3],
        refund_fee: nums[4],
        punish_fee: nums[5],
    })
}
impl ContractsSessionStoreV1 {
    /// Recover the exact previously admitted custody scope from the native
    /// gate, fixing local private/public role from the authenticated signer.
    pub fn expected_xmr_recovery_scope_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
    ) -> Result<super::super::xmr_recovery::XmrRecoveryCustodyScopeV11, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        self.expected_xmr_recovery_scope_locked_v23(&gate)
    }

    // Caller holds the operation lock and has authenticated the gate ancestry.
    fn expected_xmr_recovery_scope_locked_v23(
        &self,
        gate: &F7GateRecordV12,
    ) -> Result<super::super::xmr_recovery::XmrRecoveryCustodyScopeV11, SessionStoreError> {
        if gate.family != F7ExternalFamilyV11::Monero {
            return Err(SessionStoreError::InvalidTransition);
        }
        let signer = self.authenticate_local_transport_signer_binding(gate.session_id)?;
        let role = if signer.participant_id == gate.role.terms().dom_leg.refund_to.0 {
            super::super::xmr_recovery::XmrRecoveryCustodyRoleV11::PrivateRefundOwner
        } else if signer.participant_id == gate.role.terms().counterparty_leg.refund_to.0 {
            super::super::xmr_recovery::XmrRecoveryCustodyRoleV11::PublicCounterparty
        } else {
            return Err(SessionStoreError::InvalidTransition);
        };
        Ok(super::super::xmr_recovery::XmrRecoveryCustodyScopeV11 {
            binding: decode_xmr_graph_binding_v12(&gate.graph_binding_bytes)?,
            graph_digest: gate.graph_digest,
            custody_id: gate.custody_id,
            role,
        })
    }
}
impl ContractsSessionStoreV1 {
    /// Add a fresh concrete XMR funding observation to the same recovery
    /// authority. This fresh daemon permission supplements the independent
    /// consensus certificate required by every new V22 compensation.
    pub fn authorize_xmr_recovery_with_funding_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
        observation: f7_anchor_authority::families_v11::VerifiedXmrFundingV11,
    ) -> Result<VerifiedXmrRecoveryExecutionAuthorityV12, SessionStoreError> {
        let mut authority = self.authorize_xmr_recovery_execution_v12(handle, custody)?;
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if observation.setup_binding_hash() != &gate.xmr_setup_binding_hash
            || observation.funding_id()
                != &f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(
                    gate.xmr_funding_tx_hash,
                )
            || observation.facts().terms_hash() != &gate.terms_hash
            || observation.facts().settlement_id() != &gate.role.settlement_id().0
            || observation.facts().chain_registry_id()
                != &gate.role.terms().counterparty_leg.chain_id.0
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        if observation.confirmations()
            < gate
                .role
                .terms()
                .counterparty_leg
                .finality
                .min_confirmations
            || observation.facts().age() > std::time::Duration::from_secs(60)
        {
            return Err(SessionStoreError::FundingAuthorityUnavailable);
        }
        authority.xmr_funding_observation = Some(observation);
        Ok(authority)
    }
}
/// Read-only inputs for the concrete family observer. This is never a signing
/// grant; observers still query exact native transactions on both chains.
pub struct F7AnchorRequestBindingV12 {
    role: FinalClaimRoleBindingV1,
    dom_funding_txid: [u8; 32],
    round_start_transcript_hash: [u8; 32],
}
impl F7AnchorRequestBindingV12 {
    /// Exact operational role decoded under the supplied native chain.
    pub const fn role(&self) -> &FinalClaimRoleBindingV1 {
        &self.role
    }
    /// Hash recomputed from the same Store's committed signed funding bytes.
    pub const fn dom_funding_txid(&self) -> [u8; 32] {
        self.dom_funding_txid
    }
    /// Immutable pre-round transcript when issuance already exists.
    pub const fn round_start_transcript_hash(&self) -> [u8; 32] {
        self.round_start_transcript_hash
    }
}
impl ContractsSessionStoreV1 {
    /// Recover exact requested funding identity and immutable round predecessor
    /// without using the mutable current signing transcript after restart.
    pub fn f7_anchor_request_binding_v12(
        &self,
        handle: &PreparedF7FundingGateV12,
        chain: TrustedChainIdV1,
    ) -> Result<F7AnchorRequestBindingV12, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if chain.as_bytes() != &gate.chain_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let commit = self.load_f7_funding_v12(&gate)?;
        let role = FinalClaimRoleBindingV1::decode_canonical(&chain, gate.role.canonical_bytes())
            .map_err(|_| SessionStoreError::Quarantined)?;
        let round_start_transcript_hash =
            match self.read_f7_v12(gate.session_id, "claim-issued", 4096) {
                Ok(bytes) => {
                    let issued = F7ClaimRecordV12::decode(&bytes)?;
                    if issued.gate_digest != gate.digest
                        || issued.funding_commit_digest != commit.digest
                    {
                        return Err(SessionStoreError::Quarantined);
                    }
                    issued.round_start_transcript_hash
                }
                Err(SessionStoreError::SessionNotFound) => {
                    let current = self.load_session_locked(gate.session_id)?;
                    if !matches!(
                        current.phase(),
                        SessionPhaseV1::FundingBroadcast | SessionPhaseV1::FundingConfirmed
                    ) || !current.irreversible().funding_authorized
                    {
                        return Err(SessionStoreError::InvalidTransition);
                    }
                    current.transcript_hash()
                }
                Err(error) => return Err(error),
            };
        Ok(F7AnchorRequestBindingV12 {
            role,
            dom_funding_txid: *blake2b_256(&commit.funding_bytes).as_bytes(),
            round_start_transcript_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    assert_not_impl_any!(PreparedF7FundingGateV12:Clone,Copy,core::fmt::Debug);
    assert_not_impl_any!(ConsumedF7ClaimAuthorizationV12:Clone,Copy,core::fmt::Debug);
    assert_not_impl_any!(VerifiedXmrRecoveryExecutionAuthorityV12:Clone,Copy,core::fmt::Debug);

    #[test]
    fn consumed_claim_retains_scan_age_across_revalidation_without_sleeping() {
        let origin = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(30))
            .unwrap();
        let handle = ConsumedF7ClaimAuthorizationV12 {
            session_id: [1; 32],
            issuance_digest: [2; 32],
            consumption_digest: [3; 32],
            open_instance_id: [4; 32],
            owner: Arc::new(()),
            observed_at: std::cell::Cell::new(origin),
        };
        assert!(handle.require_recent_observation().is_ok());
        for _ in 0..3 {
            handle.retain_observation_at(origin);
            assert_eq!(handle.observed_at.get(), origin);
        }
        let expired = std::time::Instant::now()
            .checked_sub(
                f7_anchor_authority::families_v11::MAX_V11_EXTERNAL_ANCHOR_AGE
                    + std::time::Duration::from_secs(1),
            )
            .unwrap();
        // A slow ancestry/storage operation does not renew the scan. The next
        // signing/exposure check rejects it before accepting the handle's owner.
        handle.retain_observation_at(expired);
        assert_eq!(handle.observed_at.get(), expired);
        assert!(matches!(
            handle.require_recent_observation(),
            Err(SessionStoreError::ClaimSigningAuthorityUnavailable)
        ));
        // Only a genuinely new, already-verified observation can restore age.
        let fresh = std::time::Instant::now();
        handle.retain_observation_at(fresh);
        assert!(handle.require_recent_observation().is_ok());
        assert_eq!(handle.observed_at.get(), fresh);
    }

    fn claim_bytes(
        id: f7_anchor_authority::families_v11::F7FundingIdV11,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = b"DOMFCA12".to_vec();
        bytes.extend_from_slice(&42u64.to_le_bytes());
        for tag in 1..=12 {
            bytes.extend_from_slice(&[tag; 32]);
        }
        bytes.extend_from_slice(
            &dom_crypto::SecretKey::from_bytes(&[3; 32])?
                .public_key()
                .to_compressed_bytes(),
        );
        match id {
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value);
                bytes.extend_from_slice(&[0; 32]);
            }
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(value) => {
                bytes.push(2);
                bytes.extend_from_slice(&value);
            }
        }
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-ISSUANCE/V12\0", &bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }
    #[test]
    fn solana_full_second_half_is_retained_and_bound() -> Result<(), Box<dyn std::error::Error>> {
        let mut signature = [7; 64];
        signature[63] = 9;
        let bytes = claim_bytes(
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(signature),
        )?;
        let parsed = F7ClaimRecordV12::decode(&bytes)?;
        assert_eq!(
            parsed.external_funding,
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(signature)
        );
        let mut swapped = bytes.clone();
        let index = swapped.len() - 33;
        swapped[index] ^= 1;
        assert!(F7ClaimRecordV12::decode(&swapped).is_err());
        let mut changed = signature;
        changed[63] ^= 1;
        let another = F7ClaimRecordV12::decode(&claim_bytes(
            f7_anchor_authority::families_v11::F7FundingIdV11::SolanaSignature(changed),
        )?)?;
        assert_ne!(parsed.digest, another.digest);
        assert_ne!(parsed.external_funding, another.external_funding);
        Ok(())
    }
    #[test]
    fn claim_record_rejects_truncation_trailing_and_unknown_family_tag(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = claim_bytes(f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(
            [4; 32],
        ))?;
        for length in 0..bytes.len() {
            assert!(F7ClaimRecordV12::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(F7ClaimRecordV12::decode(&trailing).is_err());
        let mut unknown = bytes.clone();
        unknown[8 + 8 + 12 * 32 + 33] = 3;
        let end = unknown.len() - 32;
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-ISSUANCE/V12\0", &unknown[..end]);
        unknown[end..].copy_from_slice(&digest);
        assert!(F7ClaimRecordV12::decode(&unknown).is_err());
        Ok(())
    }
    #[test]
    fn hash32_padding_cannot_carry_hidden_identifier_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = claim_bytes(f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(
            [4; 32],
        ))?;
        let index = bytes.len() - 33;
        bytes[index] = 1;
        let end = bytes.len() - 32;
        let digest = tagged_hash("DOM-INTEROP/F7-CLAIM-ISSUANCE/V12\0", &bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
        assert!(F7ClaimRecordV12::decode(&bytes).is_err());
        Ok(())
    }
    #[test]
    fn claim_consumption_is_bound_to_one_issuance() -> Result<(), Box<dyn std::error::Error>> {
        let a = F7ClaimRecordV12::decode(&claim_bytes(
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32([4; 32]),
        )?)?;
        let b = F7ClaimRecordV12::decode(&claim_bytes(
            f7_anchor_authority::families_v11::F7FundingIdV11::Hash32([5; 32]),
        )?)?;
        assert_ne!(f7_claim_consumption(&a), f7_claim_consumption(&b));
        assert_eq!(f7_claim_consumption(&a).len(), 104);
        Ok(())
    }
    #[test]
    fn bounded_blob_reader_rejects_overflow_and_digest_overlap() {
        let mut bytes = vec![0; 40];
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(take_blob(&bytes, &mut 0, 1024).is_err());
        bytes[..4].copy_from_slice(&9u32.to_le_bytes());
        assert!(take_blob(&bytes, &mut 0, 1024).is_err());
        bytes[..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(take_blob(&bytes, &mut 0, 1024).ok(), Some(&[0; 4][..]));
    }
}

// The new profile shares the existing retained artifacts directory. Keeping the
// nine root objects unchanged also keeps the native staging capture, inode
// checks and prepared-open revalidation authoritative for every V12 write.
const F7_V12_ARTIFACT_COUNT_MAX: usize = MAX_PREPARED_RECOVERY_SOURCES * 11;
const F7_V12_ARTIFACT_BYTES_MAX: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum F7ArtifactKindV12 {
    Gate,
    Funding,
    FundingSigningV20,
    Issued,
    Consumed,
    Binding,
    Pre,
    ExposureV14,
    AdmissionV14,
    ObservationV15,
    RefundTransportV23,
}
impl F7ArtifactKindV12 {
    fn suffix(self) -> &'static str {
        match self {
            Self::Gate => "gate",
            Self::Funding => "funding",
            Self::FundingSigningV20 => "funding-signing-v20",
            Self::Issued => "claim-issued",
            Self::Consumed => "claim-consumed",
            Self::Binding => "claim-binding",
            Self::Pre => "claim-pre",
            Self::ExposureV14 => "claim-exposure-v14",
            Self::AdmissionV14 => "claim-admission-v14",
            Self::ObservationV15 => "claim-observation-v15",
            Self::RefundTransportV23 => "refund-transport-v23",
        }
    }
    fn maximum_length(self) -> usize {
        match self {
            Self::Gate => GATE_MAX,
            Self::Funding => COMMIT_MAX,
            Self::FundingSigningV20 => SIGNING_MAX_V20,
            Self::Issued | Self::Pre => 4096,
            Self::Consumed => 128,
            Self::Binding => 512,
            Self::ExposureV14 => EXPOSURE_MAX_V14,
            Self::AdmissionV14 => ADMISSION_LEN_V14,
            Self::ObservationV15 => OBSERVATION_MAX_V15,
            Self::RefundTransportV23 => REFUND_TRANSPORT_LEN_V23,
        }
    }
}

/// Exact lowercase session namespace; a suffix match alone is insufficient.
pub(super) fn parse_f7_artifact_name_v12(name: &str) -> Option<([u8; 32], F7ArtifactKindV12)> {
    let (session, suffix) = name.split_once(".f7-v12-")?;
    if session.len() != 64
        || !session
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let session = decode_hex_32(session)?;
    if session == [0; 32] {
        return None;
    }
    let kind = match suffix {
        "gate" => F7ArtifactKindV12::Gate,
        "funding" => F7ArtifactKindV12::Funding,
        "funding-signing-v20" => F7ArtifactKindV12::FundingSigningV20,
        "claim-issued" => F7ArtifactKindV12::Issued,
        "claim-consumed" => F7ArtifactKindV12::Consumed,
        "claim-binding" => F7ArtifactKindV12::Binding,
        "claim-pre" => F7ArtifactKindV12::Pre,
        "claim-exposure-v14" => F7ArtifactKindV12::ExposureV14,
        "claim-admission-v14" => F7ArtifactKindV12::AdmissionV14,
        "claim-observation-v15" => F7ArtifactKindV12::ObservationV15,
        "refund-transport-v23" => F7ArtifactKindV12::RefundTransportV23,
        _ => return None,
    };
    Some((session, kind))
}

/// Byte-first check also used for uncommitted staging files. This never mints
/// authority: final records additionally undergo the complete native graph
/// audit below; staged files are discarded by the existing crash recovery.
pub(super) fn validate_f7_artifact_bytes_v12(
    session: [u8; 32],
    kind: F7ArtifactKindV12,
    bytes: &[u8],
) -> Result<(), SessionStoreError> {
    if bytes.len() > kind.maximum_length() {
        return Err(SessionStoreError::CapacityExceeded);
    }
    match kind {
        F7ArtifactKindV12::RefundTransportV23 => {
            validate_refund_transport_bytes_v23(session, bytes)?
        }
        F7ArtifactKindV12::ObservationV15 => validate_f7_observation_bytes_v15(session, bytes)?,
        F7ArtifactKindV12::ExposureV14 | F7ArtifactKindV12::AdmissionV14 => {
            validate_final_claim_artifact_v14(session, kind, bytes)?;
        }
        F7ArtifactKindV12::Gate => {
            if F7GateRecordV12::decode(bytes)?.session_id != session {
                return Err(SessionStoreError::Quarantined);
            }
        }
        F7ArtifactKindV12::FundingSigningV20 => {
            if F7FundingSigningV20::decode(bytes)?.successor.session_id() != session {
                return Err(SessionStoreError::Quarantined);
            }
        }
        F7ArtifactKindV12::Funding => {
            let commit = F7FundingCommitV12::decode(bytes)?;
            if commit.successor.session_id() != session {
                return Err(SessionStoreError::Quarantined);
            }
            let tx = Transaction::from_bytes(&commit.funding_bytes)
                .map_err(|_| SessionStoreError::Quarantined)?;
            if canonical_dom_transaction_bytes_v1(&tx)? != commit.funding_bytes {
                return Err(SessionStoreError::Quarantined);
            }
        }
        F7ArtifactKindV12::Issued => {
            if F7ClaimRecordV12::decode(bytes)?.session_id != session {
                return Err(SessionStoreError::Quarantined);
            }
        }
        F7ArtifactKindV12::Consumed => {
            if bytes.len() != 104
                || &bytes[..8] != b"DOMFCN12"
                || bytes[8..40] != session
                || bytes[40..72] == [0; 32]
                || tagged_hash("DOM-INTEROP/F7-CLAIM-CONSUMPTION/V12\0", &bytes[..72])
                    != bytes[72..]
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        F7ArtifactKindV12::Binding => {
            F7ClaimRoundBindingV12::decode(bytes)?;
        }
        F7ArtifactKindV12::Pre => {
            // Native AdaptorPreSignatureV1 has a frozen 162-byte encoding.
            const LEN: usize = 25 + 9 * 32 + 162 + 32;
            if bytes.len() != LEN
                || &bytes[..8] != b"DOMFCP12"
                || bytes[25..57] != session
                || u64::from_le_bytes(copy_array(&bytes[8..16])?) == 0
                || !matches!(bytes[24], 0x01 | 0x02)
                || tagged_hash("DOM-INTEROP/F7-CLAIM-PRE/V12\0", &bytes[..LEN - 32])
                    != bytes[LEN - 32..]
            {
                return Err(SessionStoreError::Quarantined);
            }
            for value in bytes[25..313].chunks_exact(32) {
                if value == [0; 32] {
                    return Err(SessionStoreError::Quarantined);
                }
            }
            let pre = AdaptorPreSignatureV1::from_bytes(&bytes[313..475])
                .map_err(|_| SessionStoreError::Quarantined)?;
            if pre.to_bytes().as_slice() != &bytes[313..475] {
                return Err(SessionStoreError::Quarantined);
            }
        }
    }
    Ok(())
}

impl ContractsSessionStoreV1 {
    fn f7_abort_blocks_revision_v12(
        &self,
        session: [u8; 32],
        revision: u64,
    ) -> Result<bool, SessionStoreError> {
        let abort = match self.load_operational_abort_transport_authority(session) {
            Ok(record) => record,
            Err(SessionStoreError::SessionNotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        let predecessor = self.load_session_revision(session, abort.predecessor_revision)?;
        if predecessor.digest() != &abort.predecessor_record_digest
            || predecessor.terms_hash() != abort.terms_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(revision >= abort.predecessor_revision)
    }

    fn f7_native_claim_binding_exists_v12(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        if self.load_f7_gate_v12(session)?.profile == F7RecoveryProfileV23::XmrBounded {
            return match self.read_f7_claim_binding_v12(session) {
                Ok(_) => {
                    let native = self.authenticate_xmr_bounded_claim_binding_v23(session)?;
                    self.require_xmr_claim_binding_record_v23(&native)?;
                    Ok(true)
                }
                Err(SessionStoreError::SessionNotFound) => Ok(false),
                Err(error) => Err(error),
            };
        }
        match self.load_signing_binding(session, PurposeV1::ClaimAdaptor) {
            Ok(_) => Ok(true),
            Err(SessionStoreError::SessionNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn census_f7_artifacts_v12(
        &self,
    ) -> Result<
        (
            BTreeMap<[u8; 32], BTreeSet<F7ArtifactKindV12>>,
            usize,
            usize,
        ),
        SessionStoreError,
    > {
        let mut sessions = BTreeMap::<[u8; 32], BTreeSet<F7ArtifactKindV12>>::new();
        let mut count = 0usize;
        let mut total = 0usize;
        for (directory_kind, directory) in self.durable_profile_directories() {
            let mut names = Vec::new();
            directory.scan_lexicographic(|name, node| {
                if let Some(parsed) = parse_f7_artifact_name_v12(name) {
                    if directory_kind != M8F7DurableDirectory::Artifacts
                        || node.node_type != ExpectedNodeType::RegularFile
                    {
                        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
                    }
                    if names.len() >= F7_V12_ARTIFACT_COUNT_MAX {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    names.push((name.to_owned(), parsed));
                }
                Ok(())
            })?;
            for (name, (session, kind)) in names {
                let bytes = directory.read_bounded_file(
                    &ValidatedComponent::registered(&name)?,
                    kind.maximum_length(),
                )?;
                count = count
                    .checked_add(1)
                    .ok_or(SessionStoreError::CapacityExceeded)?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or(SessionStoreError::CapacityExceeded)?;
                if count > F7_V12_ARTIFACT_COUNT_MAX || total > F7_V12_ARTIFACT_BYTES_MAX {
                    return Err(SessionStoreError::CapacityExceeded);
                }
                validate_f7_artifact_bytes_v12(session, kind, &bytes)?;
                if !sessions.entry(session).or_default().insert(kind) {
                    return Err(SessionStoreError::Quarantined);
                }
            }
        }
        Ok((sessions, count, total))
    }

    fn require_f7_artifact_publication_budget_v12(
        &self,
        name: &str,
        length: usize,
    ) -> Result<(), SessionStoreError> {
        let (_, count, total) = self.census_f7_artifacts_v12()?;
        match self
            .artifacts
            .open_file(&ValidatedComponent::registered(name)?, false)
        {
            Ok(_) => return Ok(()),
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        if count >= F7_V12_ARTIFACT_COUNT_MAX
            || total
                .checked_add(length)
                .filter(|size| *size <= F7_V12_ARTIFACT_BYTES_MAX)
                .is_none()
        {
            return Err(SessionStoreError::CapacityExceeded);
        }
        Ok(())
    }

    /// Authenticate every final, including gate-only and issuance-only crash
    /// prefixes. Missing authority ancestors are corruption; a final's absent
    /// next publication is a legitimate prefix and never synthesized here.
    pub(super) fn audit_f7_artifact_inventory_v12(&self) -> Result<(), SessionStoreError> {
        let (sessions, _, _) = self.census_f7_artifacts_v12()?;
        for (session, kinds) in sessions {
            use F7ArtifactKindV12 as K;
            if !kinds.contains(&K::Gate) {
                return Err(SessionStoreError::Quarantined);
            }
            let gate = self.load_f7_gate_v12(session)?;
            self.authenticate_f7_gate_ancestry_v12(&gate)?;
            let current = self.load_session_locked(session)?;
            if current.irreversible().adaptor_secret_exposed
                && !kinds.contains(&K::ExposureV14)
                && !kinds.contains(&K::ObservationV15)
            {
                return Err(SessionStoreError::Quarantined);
            }
            if current.terms_hash() != gate.terms_hash
                || current.revision() < gate.bound_revision
                || self.post_anchor_claim_issuance_exists(session)?
                || self.post_anchor_claim_issuance_v2_exists(session)?
            {
                return Err(SessionStoreError::Quarantined);
            }
            let signing_extra = usize::from(kinds.contains(&K::FundingSigningV20));
            let transport_extra = usize::from(kinds.contains(&K::RefundTransportV23));
            if transport_extra != 0 {
                self.audit_native_xmr_refund_transport_v23(session)?;
            }
            let signing = self.optional_f7_funding_signing_v20(&gate)?;
            if signing.is_some() != (signing_extra == 1) {
                return Err(SessionStoreError::Quarantined);
            }
            if !kinds.contains(&K::Funding) {
                if kinds.len() != 1 + signing_extra + transport_extra {
                    return Err(SessionStoreError::Quarantined);
                }
                if let Some(signing) = signing.as_ref() {
                    let _signature =
                        self.audit_f7_funding_signing_v20(&gate, signing, &current, false)?;
                } else if current.irreversible().funding_authorized {
                    return Err(SessionStoreError::Quarantined);
                }
                self.f7_ready_count_v12(&gate, current.revision())?;
                continue;
            }
            let funding = self.load_f7_funding_v12(&gate)?;
            if current.revision() < funding.successor.revision() {
                if current.digest() != &funding.predecessor_digest
                    || kinds.len() != 2 + signing_extra + transport_extra
                {
                    return Err(SessionStoreError::Quarantined);
                }
                // Exact signed bytes already durable; resume_f7_committed_funding_v12
                // republishes this exact frozen successor before exposing submission.
                continue;
            }
            if self
                .load_session_revision(session, funding.successor.revision())?
                .as_bytes()
                != funding.successor.as_bytes()
            {
                return Err(SessionStoreError::Quarantined);
            }
            if !kinds.contains(&K::Issued) {
                if kinds.len() != 2 + signing_extra + transport_extra {
                    return Err(SessionStoreError::Quarantined);
                }
                continue;
            }
            let issued =
                F7ClaimRecordV12::decode(&self.read_f7_v12(session, "claim-issued", 4096)?)?;
            self.authenticate_f7_issuance_ancestry_v12(&gate, &funding, &issued)?;
            if !kinds.contains(&K::Consumed) {
                if kinds.len() != 3 + signing_extra + transport_extra
                    || self.f7_native_claim_binding_exists_v12(session)?
                {
                    return Err(SessionStoreError::Quarantined);
                }
                continue;
            }
            let (_, issued, _) = self.authenticate_f7_claim_v12(session)?;
            if kinds.contains(&K::Binding) {
                self.audit_f7_round_binding_inventory_v12(session, &issued)?;
            } else if kinds.contains(&K::Pre) {
                return Err(SessionStoreError::Quarantined);
            } else if self.f7_native_claim_binding_exists_v12(session)? {
                // The native binding is published first; it may be the last
                // durable write before the companion record. No signing edge
                // may have occurred until that companion exists.
                let records =
                    self.authenticated_derived_transport_records(session, current.revision())?;
                if records.iter().any(|record| {
                    record.purpose == Some(PurposeV1::ClaimAdaptor)
                        && matches!(record.message_type, 0x0c..=0x0f)
                }) {
                    return Err(SessionStoreError::Quarantined);
                }
                self.audit_f7_native_binding_at_start_v12(session, &issued)?;
            }
            if kinds.contains(&K::Pre) {
                self.load_f7_pre_v12(session)?;
            }
            self.audit_f7_final_claim_inventory_v14(session, &kinds)?;
            self.audit_f7_observation_inventory_v15(session, &kinds)?;
        }
        Ok(())
    }

    fn audit_f7_native_binding_at_start_v12(
        &self,
        session: [u8; 32],
        issued: &F7ClaimRecordV12,
    ) -> Result<AuthenticatedSigningReplayBindingV1, SessionStoreError> {
        let signing = self.load_signing_binding(session, PurposeV1::ClaimAdaptor)?;
        let revision = u64::from_le_bytes(copy_array(&signing.bytes[112..120])?);
        let historical = self.load_session_revision(session, revision)?;
        let current = self.load_session_locked(session)?;
        if current.revision() < revision || current.terms_hash() != historical.terms_hash() {
            return Err(SessionStoreError::Quarantined);
        }
        let replay = self.authenticate_signing_replay_binding(
            &historical,
            PurposeV1::ClaimAdaptor,
            SessionPhaseV1::FundingConfirmed,
        )?;
        if replay.template_hash != issued.claim_template_hash
            || replay.adaptor_point.as_ref() != Some(&issued.adaptor_point)
            || replay.round_start_transcript_hash != issued.round_start_transcript_hash
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(replay)
    }

    fn audit_f7_round_binding_inventory_v12(
        &self,
        session: [u8; 32],
        issued: &F7ClaimRecordV12,
    ) -> Result<(), SessionStoreError> {
        if self.load_f7_gate_v12(session)?.profile == F7RecoveryProfileV23::XmrBounded {
            let native = self.authenticate_xmr_bounded_claim_binding_v23(session)?;
            if native.issued.digest != issued.digest
                || native.issued.consumption_digest != issued.consumption_digest
            {
                return Err(SessionStoreError::Quarantined);
            }
            self.require_xmr_claim_binding_record_v23(&native)?;
            let current = self.load_session_locked(session)?;
            let records =
                self.authenticated_derived_transport_records(session, current.revision())?;
            // Historical inventory must remain readable after expiry, abort or
            // exposure. Fresh issuance is still guarded by the live entrypoints.
            let revision = records
                .iter()
                .filter(|r| {
                    r.revision > native.start.revision()
                        && (0x0c..=0x0e).contains(&r.message_type)
                        && r.purpose == Some(PurposeV1::ClaimAdaptor)
                })
                .map(|r| r.revision)
                .max()
                .unwrap_or(native.start.revision());
            let terminal = self.load_session_revision(session, revision)?;
            self.audit_xmr_bounded_claim_round_at_v23(&native, &terminal, None)?;
            return Ok(());
        }
        let binding = self.read_f7_claim_binding_v12(session)?;
        let signing = self.load_signing_binding(session, PurposeV1::ClaimAdaptor)?;
        let signing_digest = copy_array(&signing.bytes[signing.bytes.len() - 32..])?;
        let mut roster_bytes = Vec::with_capacity(202);
        roster_bytes.extend_from_slice(&2_u16.to_le_bytes());
        for index in 0..2 {
            let offset = 472 + index * 99;
            roster_bytes.extend_from_slice(
                signing
                    .bytes
                    .get(offset..offset + 99)
                    .ok_or(SessionStoreError::Quarantined)?,
            );
        }
        // Native replay validation binds the actual round start, exact
        // transaction, participant PoPs and every accepted nonce/share.
        let replay = self.audit_f7_native_binding_at_start_v12(session, issued)?;
        if binding.issuance_record_digest != issued.digest
            || binding.consumption_record_digest != issued.consumption_digest
            || binding.signing_binding_record_digest != signing_digest
            || binding.roster_digest
                != tagged_hash(POST_ANCHOR_CLAIM_ROSTER_HASH_TAG, &roster_bytes)
            || binding.round_start_record_digest != replay.round_start_record_digest
            || binding.final_claim_role_binding_digest != issued.final_claim_role_binding_digest
            || binding.ready_binding_digest != issued.ready_binding_digest
            || replay.round_start_transcript_hash != issued.round_start_transcript_hash
            || replay.template_hash != issued.claim_template_hash
            || replay.adaptor_point.as_ref() != Some(&issued.adaptor_point)
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
}

/// A power loss may leave zero bytes or any proper prefix of a publication.
/// Such bytes never authorize an operation and are removed only by the native
/// retained-inode staging recovery after its complete prepared-open audit.
pub(super) fn validate_f7_artifact_staging_v12(
    session: [u8; 32],
    kind: F7ArtifactKindV12,
    bytes: &[u8],
) -> Result<(), SessionStoreError> {
    let magic: &[u8; 8] = match kind {
        F7ArtifactKindV12::Gate => GATE_MAGIC,
        F7ArtifactKindV12::Funding => b"DOMFFC12",
        F7ArtifactKindV12::FundingSigningV20 => b"DOMFFS20",
        F7ArtifactKindV12::Issued => b"DOMFCA12",
        F7ArtifactKindV12::Consumed => b"DOMFCN12",
        F7ArtifactKindV12::Binding => b"DOMFCB12",
        F7ArtifactKindV12::Pre => b"DOMFCP12",
        F7ArtifactKindV12::ExposureV14 => b"DOMFCX14",
        F7ArtifactKindV12::AdmissionV14 => b"DOMFAD14",
        F7ArtifactKindV12::ObservationV15 => b"DOMFOB15",
        F7ArtifactKindV12::RefundTransportV23 => b"DOMXRT24",
    };
    if bytes.len() > kind.maximum_length()
        || bytes.get(..bytes.len().min(8)) != Some(&magic[..bytes.len().min(8)])
    {
        return Err(SessionStoreError::Quarantined);
    }
    let session_offset = match kind {
        F7ArtifactKindV12::Gate => Some(52),
        F7ArtifactKindV12::Issued => Some(16),
        F7ArtifactKindV12::Consumed => Some(8),
        F7ArtifactKindV12::Pre => Some(25),
        F7ArtifactKindV12::ExposureV14 => Some(24),
        F7ArtifactKindV12::AdmissionV14 => Some(8),
        F7ArtifactKindV12::ObservationV15 => Some(40),
        F7ArtifactKindV12::RefundTransportV23 => Some(40),
        _ => None,
    };
    if let Some(offset) = session_offset {
        if bytes.len() >= offset + 32 && bytes[offset..offset + 32] != session {
            return Err(SessionStoreError::Quarantined);
        }
    }
    let (mut cursor, blob_count) = match kind {
        F7ArtifactKindV12::Gate => (20 + 13 * 32, 6),
        F7ArtifactKindV12::Funding => (80, 2),
        F7ArtifactKindV12::FundingSigningV20 => (72, 1),
        F7ArtifactKindV12::Issued => (8 + 8 + 12 * 32 + 33 + 1 + 64, 0),
        F7ArtifactKindV12::Consumed => (72, 0),
        F7ArtifactKindV12::Binding => (8 + 7 * 32, 0),
        F7ArtifactKindV12::Pre => (25 + 9 * 32 + 162, 0),
        F7ArtifactKindV12::ExposureV14 => (24 + 10 * 32, 2),
        F7ArtifactKindV12::AdmissionV14 => (170, 0),
        F7ArtifactKindV12::ObservationV15 => (OBSERVATION_PREFIX_V15, 1),
        F7ArtifactKindV12::RefundTransportV23 => (REFUND_TRANSPORT_LEN_V23 - 32, 0),
    };
    for _ in 0..blob_count {
        if bytes.len() < cursor + 4 {
            return Ok(());
        }
        let length = u32::from_le_bytes(copy_array(&bytes[cursor..cursor + 4])?) as usize;
        cursor = cursor
            .checked_add(4)
            .and_then(|n| n.checked_add(length))
            .ok_or(SessionStoreError::CapacityExceeded)?;
        if cursor
            .checked_add(32)
            .filter(|n| *n <= kind.maximum_length())
            .is_none()
        {
            return Err(SessionStoreError::Quarantined);
        }
        if bytes.len() < cursor {
            return Ok(());
        }
    }
    let complete_length = cursor
        .checked_add(32)
        .ok_or(SessionStoreError::CapacityExceeded)?;
    if bytes.len() < complete_length {
        return Ok(());
    }
    validate_f7_artifact_bytes_v12(session, kind, bytes)
}

fn f7_anchors_match_xmr_setup_v12(
    gate: &F7GateRecordV12,
    anchors: &VerifiedF7AnchorAuthorizationV12,
) -> bool {
    if gate.family == F7ExternalFamilyV11::Monero {
        anchors.xmr_setup_binding_hash() == Some(gate.xmr_setup_binding_hash)
            && anchors.funding_id()
                == f7_anchor_authority::families_v11::F7FundingIdV11::Hash32(
                    gate.xmr_funding_tx_hash,
                )
    } else {
        anchors.xmr_setup_binding_hash().is_none()
    }
}
