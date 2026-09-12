//! Shared decision for both retained signing requests and committed outbox rows.
use super::ProductionBootstrapRuntimeErrorV16 as Error;

pub(super) fn resumed_outbound_may_complete_v22(
    message_type: u8,
    proof_complete: bool,
    has_xmr_policy: bool,
) -> Result<bool, Error> {
    if !proof_complete || (1..=10).contains(&message_type) {
        // Keep replaying the exact retained bootstrap message. A complete
        // proof must not prevent delivery of its still-pending final message.
        return Ok(false);
    }
    if has_xmr_policy {
        return Err(Error::XmrRecoveryGraphRequired);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumed_outbound_never_completes_xmr_from_message_phase_alone() {
        for message in u8::MIN..=u8::MAX {
            for proof_complete in [false, true] {
                for has_xmr_policy in [false, true] {
                    let result =
                        resumed_outbound_may_complete_v22(message, proof_complete, has_xmr_policy);
                    if !proof_complete || (1..=10).contains(&message) {
                        assert!(!result.unwrap(), "pending BP delivery is not completion");
                    } else if has_xmr_policy {
                        assert!(matches!(result, Err(Error::XmrRecoveryGraphRequired)));
                    } else {
                        assert!(result.unwrap(), "retain ordinary post-BP behavior");
                    }
                }
            }
        }
    }
}
