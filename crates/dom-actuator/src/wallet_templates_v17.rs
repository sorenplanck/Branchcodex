//! Native wallet construction of purpose-specific bootstrap signing material.
use super::*;
use dom_adaptor::{
    DomBootstrapBudgetV17, DomBootstrapOfferV17, PurposeV1, DOM_NATIVE_BOOTSTRAP_POLICY_V17,
};
use dom_consensus::{TransactionInput, TransactionOutput};
use kaystra_core::{types::LockMechanism, SettlementTermsV1};

/// The same participant's distinct funding, claim and refund kernel shares.
/// No scalar getter, serialization, clone or debug representation is exposed.
/// Actual signing still requires the native Contracts session authorization.
pub struct DomBootstrapSigningSharesV17 {
    funding: DomParticipantSigningShareV1,
    claim: DomParticipantSigningShareV1,
    refund: DomParticipantSigningShareV1,
}
impl DomBootstrapSigningSharesV17 {
    /// Prove knowledge of all three kernel shares without exporting them.
    /// Reuse the retained public proofs after a restart to preserve exact bytes.
    pub fn prove_offer_v18(
        &self,
        offer: &DomBootstrapOfferV17,
        shared: &SessionBlindingShareCapabilityV1,
        retained: Option<&dom_adaptor::DomBootstrapProvenOfferV18>,
    ) -> DomActuatorResult<dom_adaptor::DomBootstrapProvenOfferV18> {
        let binding = shared.binding();
        let chain = binding.trusted_chain_id();
        if let Some(old) = retained {
            if old
                .offer()
                .to_bytes()
                .map_err(|_| DomActuatorError::CapabilityMismatch)?
                != offer
                    .to_bytes()
                    .map_err(|_| DomActuatorError::CapabilityMismatch)?
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            old.verify(
                chain,
                binding.roster(),
                binding.role(),
                binding.participant_index(),
            )
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
            return Ok(old.clone());
        }
        let mut proofs = Vec::new();
        for (purpose, share) in [
            (PurposeV1::Funding, &self.funding),
            (PurposeV1::ClaimAdaptor, &self.claim),
            (PurposeV1::Refund, &self.refund),
        ] {
            let statement = dom_adaptor::bootstrap_key_statement_v18(
                offer,
                chain,
                binding.roster(),
                binding.role(),
                binding.participant_index(),
                purpose,
            )
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
            proofs.push(share.prove_native_signing_share_v12(&statement)?);
        }
        dom_adaptor::DomBootstrapProvenOfferV18::new(
            offer.clone(),
            proofs
                .try_into()
                .map_err(|_| DomActuatorError::CapabilityMismatch)?,
        )
        .map_err(|_| DomActuatorError::CapabilityMismatch)
    }

    /// Move the opaque shares into their separately authorized native rounds.
    pub fn into_parts(
        self,
    ) -> (
        DomParticipantSigningShareV1,
        DomParticipantSigningShareV1,
        DomParticipantSigningShareV1,
    ) {
        (self.funding, self.claim, self.refund)
    }
}

impl DomParticipantWalletSessionV1<'_> {
    /// Build a public wallet offer and the real corresponding signing shares.
    ///
    /// Inputs and change are obtained from the native wallet reservation; the
    /// payout opening is authenticated by the actuator. Offsets derive from
    /// the retained shared-blinding capability under three distinct purposes.
    /// A retained offer reuses its exact range-proof bytes, and every public
    /// field must match the wallet reconstruction before it is returned.
    ///
    /// The caller must durably retain the public offer before publishing it.
    /// Supplying an arbitrary retained offer cannot mint a signing capability.
    pub fn prepare_bootstrap_offer_v17(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        terms: &SettlementTermsV1,
        shared: &SessionBlindingShareCapabilityV1,
        payout: &AuthenticatedDomPayoutFaceV1,
        retained: Option<&DomBootstrapOfferV17>,
        now: u64,
    ) -> DomActuatorResult<(DomBootstrapOfferV17, DomBootstrapSigningSharesV17)> {
        let binding = self.wallet.require_session(self.leg)?;
        self.wallet.audit_physical_authority()?;
        self.wallet.require_shared_binding(binding, shared)?;
        if terms.policy_version != DOM_NATIVE_BOOTSTRAP_POLICY_V17
            || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || terms
                .terms_hash()
                .map_err(|_| DomActuatorError::InvalidBinding)?
                != binding.terms_digest()
            || terms.session_id.0 != binding.session_id()
            || terms.dom_leg.chain_id.0 != binding.chain_id()
            || terms.roster.map(|p| p.0).as_slice() != shared.binding().roster()
            || terms.dom_leg.beneficiary == terms.dom_leg.refund_to
            || !terms.roster.contains(&terms.dom_leg.beneficiary)
            || !terms.roster.contains(&terms.dom_leg.refund_to)
            || payout.binding() != binding
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some(offer) = retained {
            if offer.chain_id != binding.chain_id()
                || offer.session_id != binding.session_id()
                || offer.terms_hash != binding.terms_digest()
                || offer.participant_id != binding.participant().participant_id()
            {
                return Err(DomActuatorError::CapabilityMismatch);
            }
        }
        let budget = DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max)
            .map_err(|_| DomActuatorError::InvalidBinding)?;
        if payout.payout_value() != budget.principal() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        store.validate_payout_face(lease, &payout.retained, now)?;
        let funding = self.prepare_funding_inputs_v16(store, lease, terms, now)?;
        let local_funds = binding.participant().participant_id() == terms.dom_leg.refund_to.0;
        if local_funds != funding.is_some() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let payout_opening = self
            .wallet
            .state
            .outputs
            .get(&payout.payout_commitment())
            .ok_or(DomActuatorError::WalletUnavailable)?;
        if payout_opening.value != budget.principal()
            || payout_opening.origin != OutputOrigin::ReceiveSlate
            || payout_opening.is_coinbase
            || payout_opening.derivable.is_some()
            || payout_opening.reserved_for.is_some()
            || payout_opening.payout_for().map(PayoutForV1::prepare_digest)
                != Some(payout.retained.prepare_digest)
            || payout_ownership_digest(binding, payout_opening)
                != payout.retained.wallet_ownership_digest
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let payout_output = proven_output(payout_opening, retained.map(|r| &r.payout))?;
        let purposes = [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
        ];
        let mut offsets = [[0; 32]; 3];
        for (i, purpose) in purposes.into_iter().enumerate() {
            offsets[i] = shared
                .transaction_offset_contribution_v12(purpose)
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        }
        let mut inputs = Vec::new();
        let mut input_blindings = Vec::new();
        let mut change_opening = None;
        let mut change_output = None;
        let fee = if let Some(funding) = funding.as_ref() {
            if funding.binding() != binding
                || funding.principal_noms() != budget.shared_value()
                || funding.fee_noms() > budget.funding_fee_ceiling()
            {
                return Err(DomActuatorError::CapabilityMismatch);
            }
            self.wallet
                .require_live_reservation(store, binding, funding.reservation())?;
            for input in funding.reservation().outputs() {
                let output = self
                    .wallet
                    .state
                    .outputs
                    .get(&input.commitment())
                    .ok_or(DomActuatorError::WalletUnavailable)?;
                let blinding = BlindingFactor::from_bytes(*output.blinding)
                    .map_err(|_| DomActuatorError::WalletUnavailable)?;
                if output.value != input.value()
                    || Commitment::commit(output.value, &blinding).as_bytes() != &input.commitment()
                {
                    return Err(DomActuatorError::WalletUnavailable);
                }
                inputs.push(TransactionInput {
                    commitment: Commitment::from_compressed_bytes(&input.commitment())
                        .map_err(|_| DomActuatorError::WalletUnavailable)?,
                });
                input_blindings.push(&*output.blinding);
            }
            if let Some(commitment) = funding.change_commitment() {
                let output = self
                    .wallet
                    .state
                    .outputs
                    .get(&commitment)
                    .ok_or(DomActuatorError::WalletUnavailable)?;
                if output.value != funding.change_noms() {
                    return Err(DomActuatorError::WalletUnavailable);
                }
                change_output = Some(proven_output(
                    output,
                    retained.and_then(|r| r.funding_change.as_ref()),
                )?);
                change_opening = Some(&*output.blinding);
            }
            funding.fee_noms()
        } else {
            0
        };
        let compose = |index: usize,
                       wallet_inputs: Vec<&[u8; 32]>,
                       output: Option<&[u8; 32]>|
         -> DomActuatorResult<DomParticipantSigningShareV1> {
            let mut excess = Zeroizing::new(
                dom_slate::sender_excess_blinding(wallet_inputs, output, &offsets[index])
                    .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
            );
            let wallet_share = SigningShareV1::from_be_bytes(*excess)
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
            excess.zeroize();
            let share = if index == 0 {
                shared.compose_funding_signing_share_v1(&wallet_share)
            } else {
                shared.compose_shared_output_spend_signing_share_v1(&wallet_share)
            }
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
            Ok(DomParticipantSigningShareV1::new(binding, share))
        };
        let funding_share = compose(0, input_blindings, change_opening)?;
        let claim_share = compose(
            1,
            Vec::new(),
            if local_funds {
                None
            } else {
                Some(&*payout_opening.blinding)
            },
        )?;
        let refund_share = compose(
            2,
            Vec::new(),
            if local_funds {
                Some(&*payout_opening.blinding)
            } else {
                None
            },
        )?;
        let offer = DomBootstrapOfferV17 {
            chain_id: binding.chain_id(),
            session_id: binding.session_id(),
            terms_hash: binding.terms_digest(),
            participant_id: binding.participant().participant_id(),
            payout: payout_output,
            funding_inputs: inputs,
            funding_change: change_output,
            funding_fee: fee,
            signing_keys: [
                funding_share.public_key_v12().clone(),
                claim_share.public_key_v12().clone(),
                refund_share.public_key_v12().clone(),
            ],
            offsets,
        };
        let bytes = offer
            .to_bytes()
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        if let Some(retained) = retained {
            if retained
                .to_bytes()
                .map_err(|_| DomActuatorError::CapabilityMismatch)?
                != bytes
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
        }
        self.wallet.audit_physical_authority()?;
        Ok((
            offer,
            DomBootstrapSigningSharesV17 {
                funding: funding_share,
                claim: claim_share,
                refund: refund_share,
            },
        ))
    }
}

pub(super) fn proven_output(
    opening: &StoredOutput,
    retained: Option<&TransactionOutput>,
) -> DomActuatorResult<TransactionOutput> {
    let blinding = BlindingFactor::from_bytes(*opening.blinding)
        .map_err(|_| DomActuatorError::WalletUnavailable)?;
    let commitment = Commitment::commit(opening.value, &blinding);
    if commitment.as_bytes() != &opening.commitment {
        return Err(DomActuatorError::WalletUnavailable);
    }
    if let Some(output) = retained {
        if output.commitment != commitment {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        dom_adaptor::VerifiedSharedOutputV1::from_retained_output_v14(output, &opening.commitment)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        return Ok(output.clone());
    }
    let (proof, generated) = dom_crypto::range_proof_prove_bytes(opening.value, &blinding)
        .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
    if generated != opening.commitment {
        return Err(DomActuatorError::CryptoAuthorityUnavailable);
    }
    Ok(TransactionOutput { commitment, proof })
}
