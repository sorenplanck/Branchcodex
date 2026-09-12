//! Native selected-DOM execution of a durably authorized XMR recovery graph.
//! No generic broadcaster or caller-supplied transaction is accepted here.

use super::*;
use dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11;
use dom_scriptless_store::{
    VerifiedXmrRecoveryExecutionAuthorityV12, XmrRecoveryCustodyErrorV11,
    XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyV11, XmrRecoveryObservedExitV12,
    XmrRecoveryOperationV12,
};

/// Fresh collateral observation and the native Store funding commitment agree.
/// This is a short-lived prerequisite to XMR funding, not a reusable signature.
/// A runtime must reissue it at the actual selected-XMR funding boundary.
pub struct VerifiedDomXmrFundingPrerequisiteV12 {
    collateral: VerifiedDomXmrCollateralV11,
    custody_id: [u8; 32],
    policy_hash: [u8; 32],
}
impl VerifiedDomXmrFundingPrerequisiteV12 {
    /// Exact native collateral/funding finality from the actual DOM scanner.
    pub const fn collateral(&self) -> &VerifiedDomXmrCollateralV11 {
        &self.collateral
    }
    /// Exact retained recovery custody that made the exit paths executable.
    pub const fn custody_id(&self) -> [u8; 32] {
        self.custody_id
    }
    /// Economically authoritative signed assurance-policy commitment.
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }
}

/// Concrete native recovery progress. DOM compensation is never an XMR refund.
pub enum DomXmrRecoveryProgressV12 {
    /// Confirmed collateral remains available before the cancellation deadline.
    CollateralReady(VerifiedDomXmrCollateralV11),
    /// Cancel is final; the local share role must wait for its own safe window.
    AwaitingRecoveryWindow(VerifiedDomXmrCancellationV11),
    /// Exact retained bytes reached economic admission, with a durable marker.
    /// This is not chain finality; a later tick must observe the native graph.
    Submitted {
        /// Native graph operation actually submitted.
        operation: XmrRecoveryOperationV12,
        /// Opaque exact-transaction receipt from this runtime's DOM node.
        receipt: SubmissionReceiptV1,
    },
    /// DOM refund revealed U; the selected-XMR actuator must still sweep XMR.
    RefundShareRevealed(VerifiedDomRefundSecretV11),
    /// Catastrophic DOM payout, with no assertion that XMR was returned.
    DomCompensated(VerifiedDomCompensationObservationV11),
}

impl RealDomRpcRuntimeV1 {
    /// Observe an authorized retained graph without submitting any operation.
    /// Used by the XMR sweep boundary, where only canonical refund U is useful.
    pub fn observe_xmr_recovery_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
        authority.require_custody(custody)?;
        let state = custody
            .with_graph(|graph| self.observe_authorized_xmr_graph_v12(authority, graph))
            .map_err(custody_error)??;
        retain_observed_exit(authority, custody, &state)?;
        Ok(state)
    }

    /// Revalidate signed collateral value, recovery custody and actual C before
    /// allowing the selected XMR funding boundary to construct/externalize XMR.
    /// Missing collateral is retryable; a different funding txid is a conflict.
    pub fn verify_xmr_funding_prerequisite_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<VerifiedDomXmrFundingPrerequisiteV12, RealDomError> {
        authority.require_custody(custody)?;
        custody
            .with_graph(|graph| {
                let observed = self.observe_authorized_xmr_graph_v12(authority, graph)?;
                match observed {
                    VerifiedDomXmrRecoveryStateV11::CollateralReady(collateral) => {
                        if collateral.finality().confirmation_depth()
                            < authority.policy().policy().collateral_confirmations
                        {
                            return Err(RealDomError::InsufficientConfirmations);
                        }
                        // The Store-issued authority selects the authenticated
                        // graph profile. Raw policy presence cannot unlock funding.
                        authority
                            .require_graph_profile_v23(graph)
                            .map_err(|_| RealDomError::InvalidEvidence)?;
                        // Funding after the claim safety window would strand XMR
                        // even though the collateral exists. Refuse that ordering.
                        graph
                            .require_claim_window(collateral.finality().observed_tip_height())
                            .map_err(|_| RealDomError::InvalidEvidence)?;
                        Ok(VerifiedDomXmrFundingPrerequisiteV12 {
                            collateral,
                            custody_id: authority.custody_id(),
                            policy_hash: authority
                                .policy()
                                .policy()
                                .policy_hash()
                                .map_err(|_| RealDomError::InvalidEvidence)?,
                        })
                    }
                    _ => Err(RealDomError::InvalidEvidence),
                }
            })
            .map_err(custody_error)?
    }

    /// Advance one recovery operation using only the selected native DOM client.
    /// Both parties already retained ordinary cancel/compensation signatures;
    /// this path never requests a new signature or contacts the counterparty.
    /// The exact intent is synced before RPC and rechecked against a second
    /// fresh canonical scan, so a restart can retry the same transaction.
    pub fn advance_xmr_recovery_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<DomXmrRecoveryProgressV12, RealDomError> {
        authority.require_custody(custody)?;
        let state = custody
            .with_graph(|graph| self.observe_authorized_xmr_graph_v12(authority, graph))
            .map_err(custody_error)??;
        retain_observed_exit(authority, custody, &state)?;
        let operation = match state {
            VerifiedDomXmrRecoveryStateV11::Refunded(secret) => {
                return Ok(DomXmrRecoveryProgressV12::RefundShareRevealed(secret))
            }
            VerifiedDomXmrRecoveryStateV11::Compensated(compensation) => {
                return Ok(DomXmrRecoveryProgressV12::DomCompensated(compensation))
            }
            VerifiedDomXmrRecoveryStateV11::CollateralReady(collateral) => {
                if collateral.finality().observed_tip_height()
                    < authority.policy().policy().cancel_height
                {
                    return Ok(DomXmrRecoveryProgressV12::CollateralReady(collateral));
                }
                XmrRecoveryOperationV12::Cancel
            }
            VerifiedDomXmrRecoveryStateV11::Cancelled(cancelled) => {
                let height = cancelled.finality().observed_tip_height();
                match recovery_operation_at_height(
                    custody.scope().role,
                    height,
                    authority.policy().policy().cancel_height,
                    authority.policy().policy().compensation_height,
                    authority.policy().policy().reveal_safety_blocks,
                )? {
                    Some(operation) => operation,
                    None => {
                        return Ok(DomXmrRecoveryProgressV12::AwaitingRecoveryWindow(cancelled))
                    }
                }
            }
        };
        // Ordinary compensation is available only under the authenticated,
        // signed bounded-availability profile. Legacy remains refused.
        if operation == XmrRecoveryOperationV12::Compensate {
            custody
                .with_graph(|graph| authority.require_bounded_compensation_v23(graph))
                .map_err(custody_error)??;
        }
        let attempt = custody
            .prepare_recovery_attempt_v12(authority, operation)
            .map_err(custody_error)?;
        // A crash after this point is ambiguous externalization, never a fresh
        // semantic action. The retained exact identity survives process death.
        custody
            .with_graph(|graph| {
                let fresh = self.observe_authorized_xmr_graph_v12(authority, graph)?;
                require_operation_state(operation, custody.scope().role, &fresh, graph)
            })
            .map_err(custody_error)??;
        custody
            .require_attempt_v12(&attempt)
            .map_err(custody_error)?;
        if operation == XmrRecoveryOperationV12::Compensate {
            authority.require_xmr_funding_observed_v12()?;
        }
        let receipt = match operation {
            XmrRecoveryOperationV12::Cancel | XmrRecoveryOperationV12::Compensate => custody
                .with_graph(|graph| {
                    let bytes = if operation == XmrRecoveryOperationV12::Cancel {
                        graph.cancel_bytes()
                    } else {
                        // Recheck profile, exact graph and proof freshness after
                        // durable intent and the second DOM scan, before RPC.
                        authority.require_bounded_compensation_v23(graph)?;
                        graph.punish_bytes()
                    };
                    if canonical_transaction_hash_v1(bytes)? != *attempt.transaction_hash() {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    self.adapter
                        .submit_canonical_transaction(bytes)
                        .map_err(RealDomError::Chain)
                })
                .map_err(custody_error)??,
            XmrRecoveryOperationV12::Refund => custody
                .with_private_refund(|private| {
                    if private.transaction_hash() != attempt.transaction_hash() {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    private.with_secret_bytes(|bytes| {
                        self.adapter
                            .submit_canonical_transaction(bytes)
                            .map_err(RealDomError::Chain)
                    })
                })
                .map_err(custody_error)??,
        };
        custody
            .retain_recovery_admission_v12(&attempt, &receipt)
            .map_err(custody_error)?;
        Ok(DomXmrRecoveryProgressV12::Submitted { operation, receipt })
    }

    fn observe_authorized_xmr_graph_v12(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        graph: &VerifiedXmrRecoveryGraphV11,
    ) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
        let binding = graph.binding();
        if authority.chain_id() != binding.chain_id
            || authority.session_id() != binding.session_id
            || authority.terms_hash() != binding.terms_hash
            || authority.graph_digest() != *graph.graph_digest()
        {
            return Err(RealDomError::InvalidEvidence);
        }
        // The stronger collateral-confirmation requirement applies before XMR
        // funding. Recovery transactions use the signed DOM finality policy;
        // applying collateral depth again here could consume the refund window.
        let minimum = authority.minimum_confirmations();
        let state =
            self.verified_xmr_recovery_state_v11(graph, minimum, authority.max_reorg_depth())?;
        let finality = match &state {
            VerifiedDomXmrRecoveryStateV11::CollateralReady(value) => value.finality(),
            VerifiedDomXmrRecoveryStateV11::Cancelled(value) => value.finality(),
            VerifiedDomXmrRecoveryStateV11::Refunded(value) => value.finality(),
            VerifiedDomXmrRecoveryStateV11::Compensated(value) => value.finality(),
        };
        if finality.funding_tx_hash() != authority.funding_tx_hash() {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(state)
    }
}

fn recovery_operation_at_height(
    role: XmrRecoveryCustodyRoleV11,
    height: u64,
    cancel_height: u64,
    compensation_height: u64,
    safety: u64,
) -> Result<Option<XmrRecoveryOperationV12>, RealDomError> {
    if height < cancel_height
        || safety == 0
        || cancel_height
            .checked_add(safety)
            .filter(|end| *end < compensation_height)
            .is_none()
    {
        return Err(RealDomError::InvalidEvidence);
    }
    match role {
        XmrRecoveryCustodyRoleV11::PrivateRefundOwner => Ok(height
            .checked_add(safety)
            .filter(|end| *end < compensation_height)
            .map(|_| XmrRecoveryOperationV12::Refund)),
        XmrRecoveryCustodyRoleV11::PublicCounterparty => {
            Ok((height >= compensation_height).then_some(XmrRecoveryOperationV12::Compensate))
        }
    }
}

fn require_operation_state(
    operation: XmrRecoveryOperationV12,
    role: XmrRecoveryCustodyRoleV11,
    state: &VerifiedDomXmrRecoveryStateV11,
    graph: &VerifiedXmrRecoveryGraphV11,
) -> Result<(), RealDomError> {
    let binding = graph.binding();
    match (operation, state) {
        (
            XmrRecoveryOperationV12::Cancel,
            VerifiedDomXmrRecoveryStateV11::CollateralReady(collateral),
        ) if collateral.finality().observed_tip_height() >= binding.cancel_height => Ok(()),
        (
            XmrRecoveryOperationV12::Refund | XmrRecoveryOperationV12::Compensate,
            VerifiedDomXmrRecoveryStateV11::Cancelled(cancelled),
        ) => {
            if recovery_operation_at_height(
                role,
                cancelled.finality().observed_tip_height(),
                binding.cancel_height,
                binding.punish_height,
                binding.reveal_safety_blocks,
            )? == Some(operation)
            {
                Ok(())
            } else {
                Err(RealDomError::EvidenceNotFound)
            }
        }
        // State advanced or reorged between scans: observe again on the next
        // tick instead of sending bytes from the superseded snapshot.
        _ => Err(RealDomError::EvidenceNotFound),
    }
}

fn custody_error(error: XmrRecoveryCustodyErrorV11) -> RealDomError {
    match error {
        XmrRecoveryCustodyErrorV11::NotFound
        | XmrRecoveryCustodyErrorV11::Unavailable
        | XmrRecoveryCustodyErrorV11::Busy => {
            RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
        }
        _ => RealDomError::InvalidEvidence,
    }
}

fn retain_observed_exit(
    authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
    custody: &XmrRecoveryCustodyV11,
    state: &VerifiedDomXmrRecoveryStateV11,
) -> Result<(), RealDomError> {
    let (exit, finality) = match state {
        VerifiedDomXmrRecoveryStateV11::Refunded(value) => (
            XmrRecoveryObservedExitV12::DomRefundShareRevealed,
            value.finality(),
        ),
        VerifiedDomXmrRecoveryStateV11::Compensated(value) => {
            (XmrRecoveryObservedExitV12::DomCompensated, value.finality())
        }
        _ => return Ok(()),
    };
    custody
        .retain_recovery_exit_checkpoint_v12(
            authority,
            exit,
            finality.transaction_hash(),
            finality.evidence_digest(),
        )
        .map_err(custody_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refund_reveal_has_strict_mempool_safety_cutoff_and_no_compensation_role() {
        let owner = XmrRecoveryCustodyRoleV11::PrivateRefundOwner;
        assert_eq!(
            recovery_operation_at_height(owner, 100, 100, 200, 20).ok(),
            Some(Some(XmrRecoveryOperationV12::Refund))
        );
        assert_eq!(
            recovery_operation_at_height(owner, 179, 100, 200, 20).ok(),
            Some(Some(XmrRecoveryOperationV12::Refund))
        );
        assert_eq!(
            recovery_operation_at_height(owner, 180, 100, 200, 20).ok(),
            Some(None)
        );
        assert_eq!(
            recovery_operation_at_height(owner, 200, 100, 200, 20).ok(),
            Some(None)
        );
    }
    #[test]
    fn compensation_is_unilateral_but_never_early_or_adaptor_refund() {
        let owner = XmrRecoveryCustodyRoleV11::PublicCounterparty;
        assert_eq!(
            recovery_operation_at_height(owner, 100, 100, 200, 20).ok(),
            Some(None)
        );
        assert_eq!(
            recovery_operation_at_height(owner, 199, 100, 200, 20).ok(),
            Some(None)
        );
        assert_eq!(
            recovery_operation_at_height(owner, 200, 100, 200, 20).ok(),
            Some(Some(XmrRecoveryOperationV12::Compensate))
        );
    }
    #[test]
    fn bounded_compensation_still_rejects_wrong_role_and_invalid_windows() {
        let public = XmrRecoveryCustodyRoleV11::PublicCounterparty;
        let private = XmrRecoveryCustodyRoleV11::PrivateRefundOwner;
        assert!(recovery_operation_at_height(public, 200, 100, 200, 0).is_err());
        assert!(recovery_operation_at_height(public, u64::MAX, u64::MAX - 1, u64::MAX, 2).is_err());
        assert!(recovery_operation_at_height(public, 200, 100, 120, 20).is_err());
        assert_eq!(
            recovery_operation_at_height(private, 200, 100, 200, 20).ok(),
            Some(None)
        );
        assert_eq!(
            recovery_operation_at_height(public, 199, 100, 200, 20).ok(),
            Some(None)
        );
    }

    #[test]
    fn invalid_cancel_and_overflow_never_open_a_reveal_window() {
        let owner = XmrRecoveryCustodyRoleV11::PrivateRefundOwner;
        assert!(recovery_operation_at_height(owner, 99, 100, 200, 20).is_err());
        assert!(recovery_operation_at_height(owner, 100, 100, 120, 20).is_err());
        assert_eq!(
            recovery_operation_at_height(owner, u64::MAX, 100, 200, 20).ok(),
            Some(None)
        );
    }
}
