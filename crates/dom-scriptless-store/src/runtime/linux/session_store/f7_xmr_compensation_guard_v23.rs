//! Closed profile selection only, never an execution capability by itself.
use super::{F7RecoveryProfileV23, SessionStoreError};

pub(super) fn require_bounded_compensation_profile_v23(
    profile: F7RecoveryProfileV23,
) -> Result<(), SessionStoreError> {
    match profile {
        F7RecoveryProfileV23::Legacy => Err(SessionStoreError::FundingAuthorityUnavailable),
        F7RecoveryProfileV23::XmrBounded => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_compensation_remains_closed_without_consensus_migration() {
        assert!(matches!(
            require_bounded_compensation_profile_v23(F7RecoveryProfileV23::Legacy),
            Err(SessionStoreError::FundingAuthorityUnavailable)
        ));
    }

    #[test]
    fn bounded_profile_selection_does_not_construct_an_execution_authority() {
        // This checks only the closed enum. The public token method must still
        // authenticate the exact graph/policy/U and fresh native XMR funding.
        assert!(require_bounded_compensation_profile_v23(F7RecoveryProfileV23::XmrBounded).is_ok());
    }
}
