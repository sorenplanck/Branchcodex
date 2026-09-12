//! An owned pointer to the exact native Contracts opening for bounded signers.

use std::rc::Rc;

use dom_adaptor::{
    LocalReservationPresenceV12, NonceVaultV1, PreparedFreshReservationV1,
    ReservationLookupCustodyV1, ReservationLookupInitializationCustodyV12,
    ReservationLookupRecoveryCustodyV1, ReservationLookupRecoveryRequestV1,
    ReservationRequestLookupV1, SessionId, TrustedChainIdV1, VaultBackedSignerV1,
};
use dom_scriptless_store::{
    ContractsSessionStoreV1, ContractsSigningSessionAuthorityV1,
    DurableContractsReservationLookupV1, SessionStoreError,
};

use crate::{
    DomActuatorError, DomActuatorResult, DomContractsActuatorV1, DomParticipantSigningShareV1,
    DomSessionBindingV1,
};

/// Closed ownership adapter. Every decision is delegated to the exact retained
/// Contracts opening; it cannot be constructed from paths or public hashes.
pub struct RetainedDomReservationCustodyV12 {
    store: Rc<ContractsSessionStoreV1>,
}

impl ReservationLookupCustodyV1 for RetainedDomReservationCustodyV12 {
    type Error = SessionStoreError;
    type DurableLookup = DurableContractsReservationLookupV1;

    fn persist_prepared_lookup(
        &mut self,
        prepared: &PreparedFreshReservationV1,
    ) -> Result<Self::DurableLookup, Self::Error> {
        self.store
            .reservation_lookup_custody()
            .persist_prepared_lookup(prepared)
    }

    fn abandon_before_vault_claim(
        &mut self,
        lookup: &ReservationRequestLookupV1,
        session: &SessionId,
        context: &[u8; 32],
    ) -> Result<(), Self::Error> {
        self.store
            .reservation_lookup_custody()
            .abandon_before_vault_claim(lookup, session, context)
    }
}

impl ReservationLookupRecoveryCustodyV1 for RetainedDomReservationCustodyV12 {
    fn load_custodied_lookup(
        &mut self,
        request: &ReservationLookupRecoveryRequestV1,
    ) -> Result<ReservationRequestLookupV1, Self::Error> {
        self.store
            .reservation_lookup_custody()
            .load_custodied_lookup(request)
    }
}

impl ReservationLookupInitializationCustodyV12 for RetainedDomReservationCustodyV12 {
    fn classify_local_reservation_v12(
        &mut self,
        request: &ReservationLookupRecoveryRequestV1,
    ) -> Result<LocalReservationPresenceV12, Self::Error> {
        // First distinguish an absent session from absence of a lookup inside
        // an authenticated session. The following native reader scans and
        // validates every lookup file and refuses duplicates or abandonment.
        self.store.load_session(*request.session_id().as_bytes())?;
        match self.load_custodied_lookup(request) {
            Ok(_) => Ok(LocalReservationPresenceV12::Present),
            Err(SessionStoreError::SessionNotFound) => Ok(LocalReservationPresenceV12::Absent),
            Err(error) => Err(error),
        }
    }
}

/// One local opaque wallet share, its statically selected vault, and the exact
/// retained native Contracts custody. No secret share is exported on drop or
/// conversion, and no second participant's key can enter this constructor.
pub type RetainedParticipantVaultSignerV12<Vault> = VaultBackedSignerV1<
    Vault,
    RetainedDomReservationCustodyV12,
    ContractsSigningSessionAuthorityV1,
>;

/// Consume a wallet-owned share into a signer that can live across loop ticks.
pub fn participant_retained_vault_signer_v12<Vault: NonceVaultV1>(
    vault: Vault,
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    chain: TrustedChainIdV1,
    local_share: DomParticipantSigningShareV1,
) -> DomActuatorResult<RetainedParticipantVaultSignerV12<Vault>> {
    let _bound = DomContractsActuatorV1::bind(store.as_ref(), binding)?;
    if chain.as_bytes() != &binding.chain_id() {
        return Err(DomActuatorError::InvalidBinding);
    }
    let share = local_share.into_inner_for_binding(binding)?;
    let sessions = store.operational_signing_session_authority();
    Ok(VaultBackedSignerV1::new_operational(
        vault,
        RetainedDomReservationCustodyV12 { store },
        sessions,
        chain,
        share,
    ))
}
