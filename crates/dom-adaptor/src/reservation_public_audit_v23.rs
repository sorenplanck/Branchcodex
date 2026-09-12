//! Public-data comparison only. This module cannot return reservation authority.
use super::*;

/// Recompute the exact native recovery reservation digest from public data.
///
/// This returns only a digest for an authenticated Store's lookup audit. It
/// does not return a context, signing share, reservation, or signing authority.
/// The existing context and roster codecs are reused without a fabricated share.
pub fn reservation_context_digest_for_graph_v23(
    inputs: crate::SessionContextInputsV1,
    roster: &ParticipantRosterV1,
    local_protocol_index: u16,
) -> Result<[u8; 32]> {
    if !matches!(inputs.purpose, PurposeV1::Refund | PurposeV1::RefundAdaptor)
        || roster.entries().len() != 2
        || local_protocol_index > 1
    {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let public_key = roster.entries()[usize::from(local_protocol_index)].signing_public_key();
    let context = SessionContextV1::from_public_inputs_v23(inputs, public_key)?;
    let binding = ReservationContextBindingV1::from_public_context_v23(
        &context,
        roster,
        local_protocol_index,
        public_key,
    )?;
    Ok(*binding.digest())
}
