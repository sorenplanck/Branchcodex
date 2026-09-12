//! Retained-capability runtime foundations.
//!
//! The module remains private so callers can reach only the deliberately
//! re-exported concrete vault and error boundary, not filesystem internals or
//! constructors for sensitive process-local capabilities.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    PreparedXmrRecoveryAttemptV12, XmrRecoveryCustodyErrorV11, XmrRecoveryCustodyRoleV11,
    XmrRecoveryCustodyScopeV11, XmrRecoveryCustodyV11, XmrRecoveryObservedExitV12,
    XmrRecoveryOperationV12,
};

#[cfg(all(target_os = "linux", feature = "evidence-only"))]
pub use linux::{
    evidence_only_stage_post_anchor_v2_graph, BackupPolicyLimitsV1, CompletedBackupV1,
    EvidenceOnlyPostAnchorAnchorFactsV2, EvidenceOnlyStagedPostAnchorV2,
};
#[cfg(target_os = "linux")]
pub use linux::{
    verify_funding_artifacts_v1, verify_operational_funding_gate_evidence_v1,
    verify_operational_m8_funding_gate_evidence_v1, AcceptedContractsSigningSessionV1,
    AcceptedEvmActionRequestV1, AcceptedEvmSignedActionV1, AcceptedXmrRemoteSweepRequestV23,
    AcceptedXmrRemoteSweepResponseV23, AdmittedF7FinalClaimV14, AuthenticatedContractsRefundV1,
    AuthenticatedF7ClaimPreSignatureV12, AuthenticatedOperationalBpContinuationV1,
    AuthenticatedOperationalBpFinalProofV1, AuthenticatedPostAnchorClaimPreSignatureV1,
    AuthenticatedPostAnchorClaimPreSignatureV2, ClaimSigningAuthorizationV1,
    ClaimSigningAuthorizationV2, CommittedOutboundDsc1V1, ConsumedClaimSigningAuthorizationV1,
    ConsumedClaimSigningAuthorizationV2, ConsumedF7ClaimAuthorizationV12,
    ContractsReservationLookupCustodyV1, ContractsSessionStoreV1,
    ContractsSigningSessionAuthorityV1, DomTransactionValidationContextV1,
    DurableContractsReservationLookupV1, DurableTransportOutcomeV1, DurableTransportReceiptV1,
    ExactDomFundingBroadcasterV1, ExactDomRefundBroadcasterV1, F7AnchorRequestBindingV12,
    F7ClaimObserverFactsV15, F7FinalClaimActionV14, F7FinalClaimFactsV14, F7FinalClaimProgressV14,
    F7FundingAuthorizationV12, F7FundingGatePreparationV12, F7RecoveryPreparationV12,
    FinalClaimTransactionSinkRefV2, FundingAuthorizationRefV1, FundingAuthorizationV1,
    FundingBroadcastV1, FundingRetransmissionV1, FundingTransactionSinkRefV1,
    M8FundingAuthorizationRefV1, M8FundingTransactionSinkRefV1, M8FundingTransactionSinkRefV2,
    ObservedF7FinalClaimV15, ObservedFinalClaimExposureV2, OperationalBpContinuationStageV1,
    OperationalFundingGateVerificationRequestV1, OperationalM8BackupParticipantAuditV2,
    OperationalM8BackupProvenanceAuditV2, OperationalM8FundingGatePreparationV2,
    OperationalM8FundingGateVerificationRequestV1, OutboundDsc1RecoveryV1,
    PreparedContractsSessionStoreOpenV1, PreparedDsc1SigningRequestV1,
    PreparedEarlyTransportAuthorityV1, PreparedEvmSignedActionImportV1,
    PreparedF7ClaimPreSignatureTransportV12, PreparedF7FinalClaimIngressV15,
    PreparedF7FinalClaimSubmissionV14, PreparedF7FundingGateV12, PreparedF7FundingSubmissionV12,
    PreparedOperationalAbortTransportAuthorityV1, PreparedOperationalBpTransportAuthorityV1,
    PreparedOperationalFinalClaimIngressAuthorityV2, PreparedOperationalFinalClaimSubmissionV2,
    PreparedOperationalFinalClaimTransportAuthorityV2,
    PreparedOperationalFinalRefundTransportAuthorityV1, PreparedOperationalM8BackupProvenanceV2,
    PreparedOperationalM8FundingGateV1, PreparedOperationalM8FundingGateV2,
    PreparedOperationalM8ReadyToFundVoteV1, PreparedOperationalM8ReadyToFundVoteV2,
    PreparedOperationalSigningTransportAuthorityV1,
    PreparedOperationalTemplateTransportAuthorityV1, PreparedOperationalXmrFundingGateV12,
    PreparedOperationalXmrReadyToFundVoteV12,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, PreparedXmrClaimVaultProvisioningV23,
    PreparedXmrFundingVaultProvisioningV23, PreparedXmrGraphCommitIngressV23,
    PreparedXmrGraphCustodyProvisioningV23, PreparedXmrGraphResourceV23,
    PreparedXmrGraphSigningIngressV23, PreparedXmrRemoteSweepImportV23, RealDomContractFactsV2,
    RealDomFundingFactsV23, RealDomRefundFactsV11, ReconciledOperationalFinalClaimTransportV2,
    RefundBroadcastV1, RetainedClaimRoundFactsV2, SessionStoreError,
    SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
    TerminalCollaborativeSessionEvidenceV1, VerifiedFundingArtifactsV1,
    VerifiedOperationalFundingGateEvidenceV1, VerifiedOperationalM8FundingGateEvidenceV1,
    VerifiedXmrOrdinaryRecoveryRoundsV11, VerifiedXmrRecoveryExecutionAuthorityV12,
    VerifiedXmrRefundReadinessV23, VerifiedXmrRefundTemplateBindingV23,
    XmrClaimVaultProvisioningStateV23, XmrFundingVaultProvisioningStateV23,
    XmrGraphCustodyProvisioningStateV23, XmrGraphRecoverySigningEdgeV23, XmrGraphResourceKindV23,
    XmrGraphResourceStateV23, XmrOrdinaryRecoveryRoundSessionsV11,
};
#[cfg(target_os = "linux")]
pub use linux::{
    CollaborativeBpCustodyV16, ContractsNonceVaultV1, InventoryError, RetainedRestoreTargetV1,
};
