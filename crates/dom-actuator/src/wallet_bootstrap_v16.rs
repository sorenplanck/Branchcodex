//! Production creation of a local payout opening before the F6 handoff.
//!
//! The C0 blinding is encrypted before any public payout authority is issued.
//! Existing selections are reauthenticated; absence alone permits creation.
use super::*;

impl DomParticipantWalletSessionV1<'_> {
    /// Create a missing local payout opening, then pin and authenticate it in
    /// the native actuator store. No on-chain value is created or broadcast:
    /// this prepares the wallet-owned confidential output a later transaction
    /// will pay. Its amount is supplied by the authenticated settlement terms.
    ///
    /// An existing selection, conflicting candidates, expired lease or damaged
    /// wallet is never interpreted as permission to generate another opening.
    pub fn prepare_unique_payout_face_v16(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomPayoutFaceSelectionRequestV1,
    ) -> DomActuatorResult<AuthenticatedDomPayoutFaceV1> {
        self.wallet
            .prepare_missing_payout_opening_v16(self.leg, store, lease, request)?;
        self.wallet
            .authenticate_unique_payout_face_for_session(self.leg, store, lease, request)
    }
}

impl DomParticipantWalletV1 {
    pub(super) fn prepare_missing_payout_opening_v16(
        &mut self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomPayoutFaceSelectionRequestV1,
    ) -> DomActuatorResult<()> {
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        if request.payout_value == 0
            || request.payout_value > dom_crypto::range_proof::MAX_PROVABLE_VALUE
            || request.now_unix_ms == 0
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        // This native query checks the session and the live participant lease
        // before randomness or mutation. A missing opening under a retained
        // selection is corruption, and the existing authenticator rejects it.
        if store
            .retained_payout_face_selection(lease, binding, request.now_unix_ms)?
            .is_some()
        {
            return Ok(());
        }
        let candidates = self
            .state
            .outputs
            .iter()
            .filter(|output| {
                output.value == request.payout_value
                    && output.origin == OutputOrigin::ReceiveSlate
                    && !output.is_coinbase
                    && output.derivable.is_none()
                    && output.reserved_for.is_none()
                    && output.payout_for().is_none()
                    && output.status == OutputStatus::Unconfirmed
                    && output.origin_block.is_none()
            })
            .take(2)
            .count();
        match candidates {
            1 => return Ok(()),
            0 => {}
            _ => return Err(DomActuatorError::OutputReservationConflict),
        }
        let blinding = fresh_blinding_v16()?;
        let commitment = *Commitment::commit(request.payout_value, &blinding).as_bytes();
        let opening = StoredOutput::new_unconfirmed(
            commitment,
            request.payout_value,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            request.now_unix_ms / 1_000,
        );
        self.state
            .outputs
            .insert(opening)
            .map_err(|_| DomActuatorError::OutputReservationConflict)?;
        if let Err(error) = self.persist_securely() {
            self.bootstrap_publication_failed_v16 = true;
            return Err(error);
        }
        // A crash here leaves one encrypted C0 candidate. Restart selects the
        // same opening and completes the existing preparation/pin/activation
        // sequence; it does not choose another blinding or another commitment.
        self.audit_physical_authority()
    }
}

pub(super) fn fresh_blinding_v16() -> DomActuatorResult<BlindingFactor> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    for _ in 0..64 {
        getrandom::getrandom(entropy.as_mut())
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        if let Ok(blinding) = BlindingFactor::from_bytes(*entropy) {
            return Ok(blinding);
        }
    }
    Err(DomActuatorError::CryptoAuthorityUnavailable)
}
