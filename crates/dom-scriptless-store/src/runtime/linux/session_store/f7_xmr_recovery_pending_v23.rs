//! An attached native recovery owner may exist before funding is committed.
//! Legitimate absence is a wait, but a lost committed journal is corruption.
use super::*;

impl ContractsSessionStoreV1 {
    pub(super) fn load_xmr_recovery_funding_v23(
        &self,
        gate: &F7GateRecordV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<F7FundingCommitV12, SessionStoreError> {
        // Classify absence of this exact file, not SessionNotFound propagated
        // from an unrelated missing ancestor inside the commit verifier.
        if gate.profile == F7RecoveryProfileV23::XmrBounded {
            match self.read_f7_v12(gate.session_id, "funding", COMMIT_MAX) {
                Ok(_) => {}
                Err(SessionStoreError::SessionNotFound) => {
                    self.validate_xmr_recovery_attachment_locked_v23(gate, custody)?;
                    self.audit_f7_artifact_inventory_v12()?;
                    let current = self.load_session_locked(gate.session_id)?;
                    if native_xmr_commit_may_be_pending_v23(
                        current.phase(),
                        current.irreversible().funding_authorized,
                        current.irreversible().adaptor_secret_exposed,
                    ) {
                        return Err(SessionStoreError::FundingAuthorityUnavailable);
                    }
                    // In particular, FundingBroadcast/Confirmed never return
                    // a retryable absence after the immutable commit is lost.
                    return Err(SessionStoreError::Quarantined);
                }
                Err(error) => return Err(error),
            }
        }
        self.load_f7_funding_v12(gate)
    }
}

fn native_xmr_commit_may_be_pending_v23(
    phase: SessionPhaseV1,
    funding_authorized: bool,
    exposed: bool,
) -> bool {
    !exposed
        && matches!(
            (phase, funding_authorized),
            (SessionPhaseV1::RefundSigning, false) | (SessionPhaseV1::FundingAuthorized, true)
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_native_precommit_phases_can_wait() {
        assert!(native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::RefundSigning,
            false,
            false
        ));
        assert!(native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::FundingAuthorized,
            true,
            false
        ));
        assert!(!native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::RefundSigning,
            true,
            false
        ));
        assert!(!native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::FundingAuthorized,
            false,
            false
        ));
        for phase in [
            SessionPhaseV1::FundingBroadcast,
            SessionPhaseV1::FundingConfirmed,
            SessionPhaseV1::RefundBroadcast,
            SessionPhaseV1::Refunded,
            SessionPhaseV1::FailedClosed,
        ] {
            for authorized in [false, true] {
                assert!(!native_xmr_commit_may_be_pending_v23(
                    phase, authorized, false
                ));
            }
        }
    }

    #[test]
    fn secret_exposure_never_becomes_a_prefunding_wait() {
        assert!(!native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::RefundSigning,
            false,
            true
        ));
        assert!(!native_xmr_commit_may_be_pending_v23(
            SessionPhaseV1::FundingAuthorized,
            true,
            true
        ));
    }
}
