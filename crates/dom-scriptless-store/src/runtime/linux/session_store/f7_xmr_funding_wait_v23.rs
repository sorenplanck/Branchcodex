//! A closed native funding window pauses fresh signing, not durable recovery.
use super::*;

impl ContractsSessionStoreV1 {
    /// Read-only timing classification for the native XMR scheduler.
    /// `true` is not signing authority. The signer and transmission boundaries
    /// still revalidate the window immediately before their own operation.
    /// Only a valid native prefunding state can report a closed window; broken
    /// ancestry, substituted chain context, abort and terminal state are errors.
    pub fn xmr_funding_window_open_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        context: DomTransactionValidationContextV1,
    ) -> Result<bool, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let current = self.load_session_locked(session)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
            || chain.as_bytes() != &gate.chain_id
            || context.chain_id() != &gate.chain_id
            || context.current_height() < current.chain().tip_height
            || context.now_unix_seconds() == 0
            || current.irreversible().adaptor_secret_exposed
            || !matches!(
                (current.phase(), current.irreversible().funding_authorized),
                (SessionPhaseV1::RefundSigning, false) | (SessionPhaseV1::FundingAuthorized, true)
            )
            || self.operational_abort_transport_authority_exists(session)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        match require_f7_funding_window_v12(&gate, context.current_height()) {
            Ok(()) => Ok(true),
            // This exact helper reports this variant only for the signed
            // deadline/reveal margin. Never classify arbitrary Store errors.
            Err(SessionStoreError::FundingAuthorityUnavailable) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
