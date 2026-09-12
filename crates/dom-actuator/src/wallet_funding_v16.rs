//! Fee-aware native funding input selection and restart-safe reservation.
use super::*;
use crate::ScopedDomActionV1;
use dom_core::fee_policy::{fee_breakdown, TransactionShape};
use kaystra_core::SettlementTermsV1;

/// Actual local funding inputs reserved by the native wallet and actuator.
/// This is public construction material, not a signature or broadcast permit.
pub struct DomBootstrapFundingInputsV16 {
    binding: DomSessionBindingV1,
    principal: u64,
    fee: u64,
    change: u64,
    change_commitment: Option<[u8; 33]>,
    reservation: DomOutputReservationV1,
}

impl DomBootstrapFundingInputsV16 {
    /// Exact participant and session that own the selected inputs.
    pub const fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }
    /// Shared output amount, excluding the funding transaction fee.
    pub const fn principal_noms(&self) -> u64 {
        self.principal
    }
    /// Actual funding fee after accounting for the native transaction weight.
    pub const fn fee_noms(&self) -> u64 {
        self.fee
    }
    /// Amount that must return to this same wallet as funding change.
    pub const fn change_noms(&self) -> u64 {
        self.change
    }
    /// Wallet-owned change opening, encrypted and pinned before publication.
    pub const fn change_commitment(&self) -> Option<[u8; 33]> {
        self.change_commitment
    }
    /// Retained native input reservation; contains no private blinding.
    pub const fn reservation(&self) -> &DomOutputReservationV1 {
        &self.reservation
    }
}

impl DomParticipantWalletSessionV1<'_> {
    /// Select and reserve only the DOM funder's inputs. The other participant
    /// returns `None` without asking for a balance or reserving any outputs.
    /// The terms hash, chain, participant, amount and fee ceiling are checked
    /// against this wallet's authenticated session before changing custody.
    ///
    /// Reopening an active reservation reconstructs the same inputs and fee;
    /// it does not rerun coin selection against a different wallet balance.
    pub fn prepare_funding_inputs_v16(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomBootstrapFundingInputsV16>> {
        self.wallet.prepare_funding_inputs_for_session_v16(
            self.leg,
            store,
            lease,
            terms,
            None,
            now_unix_ms,
        )
    }

    /// Reserve the exact policy-bound XMR collateral plus its funding fee.
    /// Revalidates the policy against frozen terms; a raw caller amount is not
    /// sufficient authority to change this session's economic reservation.
    pub fn prepare_xmr_funding_inputs_v22(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        policy: &xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomBootstrapFundingInputsV16>> {
        self.wallet.prepare_funding_inputs_for_session_v16(
            self.leg,
            store,
            lease,
            terms,
            Some(policy),
            now_unix_ms,
        )
    }
}

impl DomParticipantWalletV1 {
    fn prepare_funding_inputs_for_session_v16(
        &mut self,
        leg: DomWalletSessionLegV1,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        xmr_policy: Option<&xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<Option<DomBootstrapFundingInputsV16>> {
        let binding = self.require_session(leg)?;
        self.audit_physical_authority()?;
        if terms.session_id.0 != binding.session_id()
            || terms
                .terms_hash()
                .map_err(|_| DomActuatorError::InvalidBinding)?
                != binding.terms_digest()
            || terms.dom_leg.chain_id.0 != binding.chain_id()
            || terms
                .roster
                .get(usize::from(binding.participant().protocol_index()))
                .map(|participant| participant.0)
                != Some(binding.participant().participant_id())
            || now_unix_ms == 0
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let (principal, ceiling) = funding_budget(terms, xmr_policy)?;
        // This native query validates the live lease and bound session even
        // for the non-paying participant; no payout selection is required.
        store.retained_payout_face_selection(lease, binding, now_unix_ms)?;
        if terms.dom_leg.refund_to.0 != binding.participant().participant_id() {
            return Ok(None);
        }

        if principal == 0 || principal > dom_crypto::range_proof::MAX_PROVABLE_VALUE || ceiling == 0
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        let mut context = Vec::new();
        context.extend_from_slice(b"DOM:wallet-bootstrap-funding:v16\0");
        context.extend_from_slice(&binding.route_id());
        context.extend_from_slice(&binding.session_id());
        context.extend_from_slice(&binding.participant().participant_id());
        context.extend_from_slice(&binding.terms_digest());
        context.extend_from_slice(&principal.to_be_bytes());
        context.extend_from_slice(&ceiling.to_be_bytes());
        let evidence = *dom_crypto::blake2b_256(&context).as_bytes();
        context.extend_from_slice(b"/reservation-effect");
        let effect = *dom_crypto::blake2b_256(&context).as_bytes();
        let scope = ScopedDomActionV1::new(binding, effect, DomActionV1::ReserveOutputs)?;
        let retained = store.reservation_for_effect(effect)?;
        let (selected, fee, change) = match retained.as_ref() {
            Some(record) => {
                let total = sum_values(&record.outputs)?;
                let (fee, change) = funding_shape(total, record.outputs.len(), principal, ceiling)?
                    .ok_or(DomActuatorError::IdempotencyConflict)?;
                (record.outputs.clone(), fee, change)
            }
            None => select_funding(&self.state, principal, ceiling)?,
        };
        let request = WalletReservationRequestV1::new(
            principal
                .checked_add(fee)
                .ok_or(DomActuatorError::InvalidBinding)?,
        )?;
        let expected_digest = reservation_digest(scope, request, &selected);
        if retained
            .as_ref()
            .is_some_and(|record| record.reservation_digest != expected_digest)
        {
            return Err(DomActuatorError::IdempotencyConflict);
        }
        let reservation = if retained
            .as_ref()
            .is_some_and(|record| record.status == RESERVATION_ACTIVE)
        {
            // A completed reservation is read-only across a new lease epoch.
            // It is not reauthorized as a fresh action or released on restart.
            let reservation = DomOutputReservationV1 {
                reservation_digest: expected_digest,
                total_value: sum_values(&selected)?,
                outputs: selected
                    .iter()
                    .map(|&(commitment, value)| DomReservedOutputV1 { commitment, value })
                    .collect(),
            };
            self.require_live_reservation(store, binding, &reservation)?;
            reservation
        } else {
            let (capability, _) =
                store.authorize_action(lease, scope, evidence, None, now_unix_ms)?;
            let reservation = self.reserve_outputs_for_session(
                leg,
                store,
                lease,
                capability,
                request,
                now_unix_ms,
            )?;
            if reservation.reservation_digest != expected_digest {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            reservation
        };
        let change_pin = if change == 0 {
            None
        } else {
            Some(store.funding_change_pin_v16(
                lease,
                binding,
                reservation.reservation_digest,
                change,
                now_unix_ms,
            )?)
        };
        let change_commitment =
            self.prepare_funding_change_v16(&reservation, change, change_pin, now_unix_ms)?;
        self.audit_physical_authority()?;
        Ok(Some(DomBootstrapFundingInputsV16 {
            binding,
            principal,
            fee,
            change,
            change_commitment,
            reservation,
        }))
    }

    fn prepare_funding_change_v16(
        &mut self,
        reservation: &DomOutputReservationV1,
        value: u64,
        pin: Option<PayoutForV1>,
        now: u64,
    ) -> DomActuatorResult<Option<[u8; 33]>> {
        if value == 0 && pin.is_none() {
            return Ok(None);
        }
        if value > dom_crypto::range_proof::MAX_PROVABLE_VALUE {
            return Err(DomActuatorError::InvalidBinding);
        }
        let pin = pin.ok_or(DomActuatorError::InvalidBinding)?;
        if let Some(output) = self
            .state
            .outputs
            .iter()
            .find(|output| output.payout_for() == Some(pin))
        {
            let blinding = BlindingFactor::from_bytes(*output.blinding)
                .map_err(|_| DomActuatorError::WalletUnavailable)?;
            if output.value != value
                || output.origin != OutputOrigin::ReceiveSlate
                || output.is_coinbase
                || output.derivable.is_some()
                || output.reserved_for.is_some()
                || Commitment::commit(value, &blinding).as_bytes() != &output.commitment
            {
                return Err(DomActuatorError::WalletUnavailable);
            }
            return Ok(Some(output.commitment));
        }
        // Missing change after the inputs have been observed spent must never
        // be repaired by creating a new opening that cannot recover that tx.
        if reservation.outputs.iter().any(|input| {
            self.state
                .outputs
                .get(&input.commitment)
                .is_none_or(|output| output.status != OutputStatus::Confirmed)
        }) {
            return Err(DomActuatorError::WalletUnavailable);
        }
        let blinding = super::bootstrap_v16::fresh_blinding_v16()?;
        let commitment = *Commitment::commit(value, &blinding).as_bytes();
        let output = StoredOutput::new_unconfirmed(
            commitment,
            value,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            now / 1_000,
        );
        self.state
            .outputs
            .insert(output)
            .map_err(|_| DomActuatorError::OutputReservationConflict)?;
        self.state
            .outputs
            .pin_payout(&commitment, pin, now / 1_000)
            .map_err(|_| DomActuatorError::OutputReservationConflict)?;
        if let Err(error) = self.persist_securely() {
            self.bootstrap_publication_failed_v16 = true;
            return Err(error);
        }
        Ok(Some(commitment))
    }
}

fn sum_values(inputs: &[([u8; 33], u64)]) -> DomActuatorResult<u64> {
    inputs.iter().try_fold(0u64, |sum, (_, value)| {
        sum.checked_add(*value)
            .ok_or(DomActuatorError::InvalidBinding)
    })
}

/// Native weight/fee policy only; no duplicated rate or weight constants.
fn funding_shape(
    total: u64,
    count: usize,
    principal: u64,
    ceiling: u64,
) -> DomActuatorResult<Option<(u64, u64)>> {
    if count == 0 || count > dom_core::MAX_INPUTS_PER_TX {
        return Err(DomActuatorError::InvalidBinding);
    }
    let fee = |outputs| -> DomActuatorResult<u64> {
        let shape = TransactionShape::from_counts(count, outputs, 1)
            .map_err(|_| DomActuatorError::InvalidBinding)?;
        Ok(fee_breakdown(shape)
            .map_err(|_| DomActuatorError::InvalidBinding)?
            .recommended_fee_noms)
    };
    let plain = fee(1)?;
    let with_change = fee(2)?;
    if plain > ceiling {
        return Err(DomActuatorError::InvalidBinding);
    }
    let Some(remainder) = total.checked_sub(principal) else {
        return Ok(None);
    };
    if remainder < plain {
        return Ok(None);
    }
    // It costs no more to consume a remainder below the extra output cost
    // than to create change. The signed ceiling remains an absolute bound.
    if remainder <= with_change && remainder <= ceiling {
        return Ok(Some((remainder, 0)));
    }
    if with_change > ceiling {
        return Err(DomActuatorError::InvalidBinding);
    }
    if remainder > with_change {
        return Ok(Some((with_change, remainder - with_change)));
    }
    Ok(None)
}

fn select_funding(
    state: &WalletV2State,
    principal: u64,
    ceiling: u64,
) -> DomActuatorResult<(Vec<([u8; 33], u64)>, u64, u64)> {
    let mut required = principal;
    for _ in 0..dom_core::MAX_INPUTS_PER_TX {
        let inputs = select_outputs(state, required)?;
        let total = sum_values(&inputs)?;
        if let Some((fee, change)) = funding_shape(total, inputs.len(), principal, ceiling)? {
            return Ok((inputs, fee, change));
        }
        // Require one more input, then recalculate its actual weight. The
        // strictly increasing total bounds this loop even with zero outputs.
        required = total
            .checked_add(1)
            .ok_or(DomActuatorError::InvalidBinding)?;
    }
    Err(DomActuatorError::InsufficientFunds)
}

fn funding_budget(
    terms: &SettlementTermsV1,
    xmr_policy: Option<&xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11>,
) -> DomActuatorResult<(u64, u64)> {
    if terms.counterparty_leg.mechanism == kaystra_core::types::LockMechanism::CrossCurveSharedSpend
    {
        let policy = xmr_policy.ok_or(DomActuatorError::CapabilityMismatch)?;
        let validated = policy
            .policy()
            .validate_for(terms)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        if &validated != policy {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        return Ok((
            validated.collateral_noms(),
            u64::try_from(terms.fee_limit.dom_max).map_err(|_| DomActuatorError::InvalidBinding)?,
        ));
    }
    if xmr_policy.is_some() {
        return Err(DomActuatorError::CapabilityMismatch);
    }
    if terms.policy_version == dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17 {
        let budget =
            dom_adaptor::DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max)
                .map_err(|_| DomActuatorError::InvalidBinding)?;
        Ok((budget.shared_value(), budget.funding_fee_ceiling()))
    } else {
        Ok((
            u64::try_from(terms.dom_leg.amount).map_err(|_| DomActuatorError::InvalidBinding)?,
            u64::try_from(terms.fee_limit.dom_max).map_err(|_| DomActuatorError::InvalidBinding)?,
        ))
    }
}

#[cfg(test)]
#[path = "wallet_funding_xmr_v22_tests.rs"]
mod xmr_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_v16_selection_adds_input_and_reprices_its_weight(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use dom_wallet2::{BlockRef, Network};
        let principal = 1_000_000;
        let fee_two = fee_breakdown(TransactionShape::from_counts(2, 1, 1)?)?.recommended_fee_noms;
        let mut state = WalletV2State::new(Network::Regtest, [4; 32]);
        state.meta.last_reconciled_tip = 10;
        for (index, value) in [principal, fee_two].into_iter().enumerate() {
            let blinding = BlindingFactor::from_bytes([index as u8 + 1; 32])?;
            let mut output = StoredOutput::new_unconfirmed(
                *Commitment::commit(value, &blinding).as_bytes(),
                value,
                *blinding.as_bytes(),
                OutputOrigin::ReceiveSlate,
                false,
                None,
                1,
            );
            output.confirm(
                BlockRef {
                    height: 2,
                    hash: [10; 32],
                },
                2,
            )?;
            state.outputs.insert(output)?;
        }
        let (selected, fee, change) = select_funding(&state, principal, fee_two)?;
        assert_eq!(selected.len(), 2);
        assert_eq!((fee, change), (fee_two, 0));
        assert_eq!(sum_values(&selected)?, principal + fee);
        assert!(selected.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(select_funding(&state, principal, fee_two - 1).is_err());
        // Planning by itself does not reserve or mutate the source wallet.
        assert!(state
            .outputs
            .iter()
            .all(|output| output.reserved_for.is_none()));
        Ok(())
    }

    #[test]
    fn bootstrap_v16_funding_fee_conserves_value_and_obeys_ceiling(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let principal = 1_000_000;
        let fee = fee_breakdown(TransactionShape::from_counts(1, 1, 1)?)?.recommended_fee_noms;
        assert_eq!(
            funding_shape(principal + fee, 1, principal, fee)?,
            Some((fee, 0))
        );
        assert!(funding_shape(principal + fee, 1, principal, fee - 1).is_err());
        assert_eq!(
            funding_shape(principal + fee - 1, 1, principal, u64::MAX)?,
            None
        );
        let total = 10_000_000;
        let (actual_fee, change) = funding_shape(total, 1, principal, u64::MAX)?
            .ok_or(DomActuatorError::InsufficientFunds)?;
        assert!(change > 0);
        assert_eq!(principal + actual_fee + change, total);
        assert_eq!(
            actual_fee,
            fee_breakdown(TransactionShape::from_counts(1, 2, 1)?)?.recommended_fee_noms
        );
        assert!(funding_shape(
            u64::MAX,
            dom_core::MAX_INPUTS_PER_TX + 1,
            principal,
            u64::MAX
        )
        .is_err());
        Ok(())
    }
}
