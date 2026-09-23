//! Resume a pending funding call without inferring absence from a failed send.
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildExecutionOutcomeV1, ChildExternalizationReceiptV1,
    ChildReconciliationOutcomeV1,
};

pub(super) fn report_refusal(stage: &'static str, error: &ChildAuthorityRefusalV1) {
    // Only a fixed stage label and the closed refusal enum; no transaction,
    // scalar, URL, or private custody material is emitted.
    eprintln!("DOM_XMR_FUNDING_REFUSAL_V25 stage={stage} refusal={error:?}");
}

pub(super) fn reconcile(
    confirmations: Option<u64>,
    minimum: u64,
    receipt: ChildExternalizationReceiptV1,
    unknown_evidence: [u8; 32],
    resume_local: Option<impl FnOnce() -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1>>,
) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
    if confirmations.is_some_and(|depth| depth >= minimum) {
        return Ok(ChildReconciliationOutcomeV1::Externalized(receipt));
    }
    if confirmations.is_none() {
        if let Some(resume) = resume_local {
            if let ChildExecutionOutcomeV1::Externalized(receipt) = resume()? {
                return Ok(ChildReconciliationOutcomeV1::Externalized(receipt));
            }
        }
    }
    // A retry which stopped before submission does not prove that an earlier
    // attempt was never submitted. Preserve the original pending call.
    Ok(ChildReconciliationOutcomeV1::Unknown {
        evidence_digest: unknown_evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use settlement_coordinator::SettlementFaceV1;

    fn receipt() -> ChildExternalizationReceiptV1 {
        ChildExternalizationReceiptV1 {
            plan_id: [1; 32],
            child_index: 1,
            face: SettlementFaceV1::Monero,
            chain_id: [2; 32],
            transaction_id: [3; 32],
            intent_digest: [4; 32],
            custody_digest: [5; 32],
            externalization_evidence_digest: [6; 32],
            first_exposure_evidence_digest: None,
        }
    }

    #[test]
    fn pending_local_funding_recovers_after_prerequisite_becomes_available() {
        let exact = receipt();
        let attempts = std::cell::Cell::new(0);
        let attempt = |allowed: bool| {
            reconcile(
                None,
                10,
                exact,
                [7; 32],
                Some(|| {
                    attempts.set(attempts.get() + 1);
                    if !allowed {
                        return Err(ChildAuthorityRefusalV1::Unavailable);
                    }
                    Ok(ChildExecutionOutcomeV1::Externalized(exact))
                }),
            )
        };
        assert_eq!(attempt(false), Err(ChildAuthorityRefusalV1::Unavailable));
        assert_eq!(
            attempt(true),
            Ok(ChildReconciliationOutcomeV1::Externalized(exact))
        );
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn a_later_unsent_retry_does_not_disprove_an_earlier_ambiguous_attempt() {
        for outcome in [
            ChildExecutionOutcomeV1::RetryableBeforeExternalization {
                evidence_digest: [8; 32],
            },
            ChildExecutionOutcomeV1::Unknown {
                evidence_digest: [9; 32],
            },
        ] {
            assert_eq!(
                reconcile(None, 10, receipt(), [7; 32], Some(|| Ok(outcome))),
                Ok(ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: [7; 32],
                })
            );
        }
        assert_eq!(
            reconcile(
                None,
                10,
                receipt(),
                [7; 32],
                Some(|| { Err(ChildAuthorityRefusalV1::Conflict) })
            ),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }

    #[test]
    fn external_funding_and_included_transactions_do_not_dispatch() {
        type Resume = fn() -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1>;
        assert_eq!(
            reconcile(None, 10, receipt(), [7; 32], None::<Resume>),
            Ok(ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: [7; 32],
            })
        );
        for depth in [0, 9, 10, 11] {
            let actual = reconcile(
                Some(depth),
                10,
                receipt(),
                [7; 32],
                Some(|| panic!("an included transaction must not be retransmitted")),
            );
            let expected = if depth >= 10 {
                ChildReconciliationOutcomeV1::Externalized(receipt())
            } else {
                ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: [7; 32],
                }
            };
            assert_eq!(actual, Ok(expected));
        }
    }
}
