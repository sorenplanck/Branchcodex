//! Bind a participant's native C -> D excess to its actual auxiliary signing
//! session. The two shared-output capabilities keep all blinding material in
//! the native vault boundary, and ordinary signing remains Store-authorized.

use crate::{
    DomActuatorError, DomActuatorResult, DomContractsActuatorV1, DomParticipantSigningShareV1,
    DomSessionBindingV1,
};
use dom_adaptor::SessionBlindingShareCapabilityV1;
use dom_scriptless_store::ContractsSessionStoreV1;

/// Compose one local cancellation kernel share for a separately initialized
/// native auxiliary session. Both C and D must have the same economic terms,
/// participant and chain as that session. No wallet key or raw scalar escapes.
pub fn participant_shared_transition_signing_share_v12(
    store: &ContractsSessionStoreV1,
    auxiliary: DomSessionBindingV1,
    source: &SessionBlindingShareCapabilityV1,
    destination: &SessionBlindingShareCapabilityV1,
    participant_offset: &[u8; 32],
) -> DomActuatorResult<DomParticipantSigningShareV1> {
    let _bound = DomContractsActuatorV1::bind(store, auxiliary)?;
    if source.binding().chain_id() != &auxiliary.chain_id()
        || source.binding().terms_hash() != &auxiliary.terms_digest()
        || source.binding().participant_id() != &auxiliary.participant().participant_id()
        || auxiliary.session_id() == *source.binding().session_id()
        || auxiliary.session_id() == *destination.binding().session_id()
    {
        return Err(DomActuatorError::InvalidBinding);
    }
    let share = source
        .compose_shared_output_transition_signing_share_v12(destination, participant_offset)
        .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
    Ok(DomParticipantSigningShareV1::new(auxiliary, share))
}
