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
    if !matches!(inputs.purpose, PurposeV1::Refund | PurposeV1::RefundAdaptor) {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    public_reservation_digest(inputs, roster, local_protocol_index)
}

/// Public-data digest of the exact Funding reservation context. This returns
/// no signing or reservation authority and preserves the native context codec.
/// Unlike the recovery-only graph audit, this path requires Funding explicitly.
pub fn reservation_context_digest_for_funding_v23(
    inputs: crate::SessionContextInputsV1,
    roster: &ParticipantRosterV1,
    local_protocol_index: u16,
) -> Result<[u8; 32]> {
    if inputs.purpose != PurposeV1::Funding {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    public_reservation_digest(inputs, roster, local_protocol_index)
}

/// Public-data digest for the post-anchor ClaimAdaptor reservation only. The
/// caller still needs independent F7/Store authority to reserve or sign.
pub fn reservation_context_digest_for_claim_v23(
    inputs: crate::SessionContextInputsV1,
    roster: &ParticipantRosterV1,
    local_protocol_index: u16,
) -> Result<[u8; 32]> {
    if inputs.purpose != PurposeV1::ClaimAdaptor {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    public_reservation_digest(inputs, roster, local_protocol_index)
}

fn public_reservation_digest(
    inputs: crate::SessionContextInputsV1,
    roster: &ParticipantRosterV1,
    local_protocol_index: u16,
) -> Result<[u8; 32]> {
    if roster.entries().len() != 2 || local_protocol_index > 1 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectionV1, ParticipantIdentityV1, SessionContextInputsV1, TrustedChainIdV1};

    struct Fixture {
        chain: TrustedChainIdV1,
        roster: ParticipantRosterV1,
        shares: [SigningShareV1; 2],
    }
    impl Fixture {
        fn new() -> Self {
            let chain = TrustedChainIdV1::from_authenticated_genesis(
                17,
                &dom_crypto::Hash256::from_bytes([19; 32]),
            );
            let shares = [
                SigningShareV1::from_be_bytes([7; 32]).unwrap(),
                SigningShareV1::from_be_bytes([11; 32]).unwrap(),
            ];
            let mut entries = shares
                .iter()
                .enumerate()
                .map(|(index, share)| {
                    ParticipantIdentityV1::new(
                        &chain,
                        share.public_key().clone(),
                        share.public_key().clone(),
                        if index == 0 {
                            DirectionV1::Initiator
                        } else {
                            DirectionV1::Responder
                        },
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| *entry.participant_id());
            Self {
                chain,
                roster: ParticipantRosterV1::new(entries).unwrap(),
                shares,
            }
        }

        fn inputs(&self, purpose: PurposeV1, index: usize) -> SessionContextInputsV1 {
            let local = &self.roster.entries()[index];
            let mut keys = self
                .shares
                .iter()
                .map(|s| s.public_key().clone())
                .collect::<Vec<_>>();
            keys.sort_by_key(dom_crypto::PublicKey::to_compressed_bytes);
            SessionContextInputsV1 {
                chain_id: *self.chain.as_bytes(),
                session_id: [21; 32],
                purpose,
                direction: local.direction(),
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash: [23; 32],
                message_digest: [25; 32],
                transcript_hash: [27; 32],
                retry_counter: 0,
                participant_public_keys: keys,
                participant_index: self.roster.signing_index(local.participant_id()).unwrap(),
                adaptor_point: matches!(
                    purpose,
                    PurposeV1::ClaimAdaptor | PurposeV1::RefundAdaptor
                )
                .then(|| self.shares[0].public_key().clone()),
            }
        }
    }

    fn audit(
        inputs: SessionContextInputsV1,
        roster: &ParticipantRosterV1,
        index: u16,
    ) -> Result<[u8; 32]> {
        match inputs.purpose {
            PurposeV1::Funding => reservation_context_digest_for_funding_v23(inputs, roster, index),
            PurposeV1::ClaimAdaptor => {
                reservation_context_digest_for_claim_v23(inputs, roster, index)
            }
            _ => reservation_context_digest_for_graph_v23(inputs, roster, index),
        }
    }

    #[test]
    fn public_audits_match_the_real_signer_context_for_each_purpose_and_participant() {
        let f = Fixture::new();
        let mut distinct = std::collections::BTreeSet::new();
        for purpose in [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
            PurposeV1::RefundAdaptor,
        ] {
            for index in 0..2 {
                let key = f.roster.entries()[index].signing_public_key();
                let share = f
                    .shares
                    .iter()
                    .find(|share| share.public_key() == key)
                    .unwrap();
                let real = SessionContextV1::new(f.inputs(purpose, index), share).unwrap();
                let bound = ReservationContextBindingV1::new(&real, &f.roster, index as u16, share)
                    .unwrap();
                let digest = audit(f.inputs(purpose, index), &f.roster, index as u16).unwrap();
                assert_eq!(&digest, bound.digest());
                assert!(
                    distinct.insert(digest),
                    "purpose/local participant must remain domain-bound"
                );
            }
        }
        assert_eq!(distinct.len(), 8);
    }

    #[test]
    fn public_audits_keep_purpose_boundaries_and_refuse_invalid_native_contexts() {
        let f = Fixture::new();
        for purpose in [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
            PurposeV1::RefundAdaptor,
            PurposeV1::Sponsor,
        ] {
            assert_eq!(
                reservation_context_digest_for_funding_v23(f.inputs(purpose, 0), &f.roster, 0)
                    .is_ok(),
                purpose == PurposeV1::Funding
            );
            assert_eq!(
                reservation_context_digest_for_claim_v23(f.inputs(purpose, 0), &f.roster, 0)
                    .is_ok(),
                purpose == PurposeV1::ClaimAdaptor
            );
            assert_eq!(
                reservation_context_digest_for_graph_v23(f.inputs(purpose, 0), &f.roster, 0)
                    .is_ok(),
                matches!(purpose, PurposeV1::Refund | PurposeV1::RefundAdaptor)
            );
        }
        for purpose in [PurposeV1::Funding, PurposeV1::ClaimAdaptor] {
            for mutation in 0..10 {
                let mut inputs = f.inputs(purpose, 0);
                let mut protocol_index = 0;
                match mutation {
                    0 => inputs.chain_id = [0; 32],
                    1 => inputs.session_id = [0; 32],
                    2 => inputs.retry_counter = 1,
                    3 => inputs.signing_phase = SigningPhaseV1::SigNonceReveal,
                    4 => inputs.participant_index ^= 1,
                    5 => inputs.participant_public_keys.reverse(),
                    6 => {
                        inputs.participant_public_keys[1] =
                            inputs.participant_public_keys[0].clone()
                    }
                    7 => protocol_index = 2,
                    8 => {
                        inputs.adaptor_point = if inputs.adaptor_point.is_some() {
                            None
                        } else {
                            Some(f.shares[0].public_key().clone())
                        }
                    }
                    _ => {
                        inputs.direction = match inputs.direction {
                            DirectionV1::Initiator => DirectionV1::Responder,
                            DirectionV1::Responder => DirectionV1::Initiator,
                        }
                    }
                }
                assert!(
                    audit(inputs, &f.roster, protocol_index).is_err(),
                    "mutation {mutation}"
                );
            }
        }
    }
}
