//! Five local XMR graph excesses reconstructed from native wallet and C/D custody.
//! No scalar is exported; producing these shares does not authorize a signature.
use super::*;
use crate::DomContractsActuatorV1;
use dom_adaptor::{AcceptedSigningSessionV1, ContractKindV1, PurposeV1};
use dom_crypto::PublicKey;
use dom_scriptless_crypto::{XmrOrdinaryRecoveryKindV12, XmrRecoveryGraphBindingV11};
use dom_scriptless_store::ContractsSessionStoreV1;
use kaystra_core::SettlementTermsV1;
use xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11;

#[path = "wallet_xmr_recovery_custody_v23.rs"]
mod recovery_custody_v23;

/// Borrowed construction scope for the five native graph equations.
pub struct DomXmrGraphSharesRequestV22<'a> {
    /// Exact frozen settlement terms.
    pub terms: &'a SettlementTermsV1,
    /// Full validated collateral and payout policy.
    pub policy: &'a ValidatedXmrCompensationPolicyV11,
    /// Local independent collateral capability C.
    pub collateral: &'a SessionBlindingShareCapabilityV1,
    /// Local independent cancellation capability D.
    pub cancelled: &'a SessionBlindingShareCapabilityV1,
    /// Timestamp for native lease and reservation revalidation.
    pub now_unix_ms: u64,
}

/// Opaque local shares, ordered funding/claim/cancel/refund/compensation.
/// No Clone, Debug, serialization or scalar getter is provided.
pub struct DomXmrGraphSigningSharesV22 {
    binding: DomSessionBindingV1,
    proof_binding: dom_adaptor::SharedBlindingBindingV1,
    shares: [Option<SigningShareV1>; 5],
    keys: [PublicKey; 5],
    offsets: [[u8; 32]; 5],
    funding: Option<DomBootstrapFundingInputsV16>,
}
impl DomXmrGraphSigningSharesV22 {
    /// Public local excesses, not aggregate keys or signing permission.
    pub const fn public_keys(&self) -> &[PublicKey; 5] {
        &self.keys
    }
    /// Purpose- and C/D-separated native offset contributions.
    pub const fn offsets(&self) -> &[[u8; 32]; 5] {
        &self.offsets
    }
    /// Actual retained funding reservation, absent for the XMR funder.
    pub const fn funding(&self) -> Option<&DomBootstrapFundingInputsV16> {
        self.funding.as_ref()
    }

    /// Recomputable public restart/peer commitment, without reservation IDs
    /// or individual input/change values. This is not a funding permit.
    pub fn public_commitment_v22(&self) -> [u8; 32] {
        use xmr_refund_policy::graph_contribution_digest_v22::{
            XmrGraphContributionDigestV22, XmrGraphFundingDigestV22,
        };
        let inputs: Vec<_> = self
            .funding
            .as_ref()
            .map(|funding| {
                funding
                    .reservation()
                    .outputs()
                    .iter()
                    .map(|input| input.commitment())
                    .collect()
            })
            .unwrap_or_default();
        XmrGraphContributionDigestV22 {
            scope: [
                self.binding.chain_id(),
                self.binding.route_id(),
                self.binding.session_id(),
                self.binding.terms_digest(),
                self.binding.participant().participant_id(),
            ],
            keys: &self.keys,
            offsets: &self.offsets,
            funding: self
                .funding
                .as_ref()
                .map(|funding| XmrGraphFundingDigestV22 {
                    inputs: &inputs,
                    change: funding.change_commitment(),
                    fee: funding.fee_noms(),
                }),
        }
        .digest()
    }

    /// Prove knowledge of all five exact excesses without consuming shares.
    /// Retained bytes are reverified, never regenerated after publication.
    /// This grants no Contracts signing permission or funding authority.
    pub fn prove_public_commitment_v22(
        &self,
        retained: Option<&[u8]>,
    ) -> DomActuatorResult<Vec<u8>> {
        use xmr_refund_policy::graph_key_proofs_v22::XmrGraphKeyProofScopeV22;
        let binding = &self.proof_binding;
        let scope = XmrGraphKeyProofScopeV22 {
            chain: binding.trusted_chain_id(),
            session_id: self.binding.session_id(),
            roster: binding.roster(),
            direction: binding.role(),
            participant_index: binding.participant_index(),
            terms_hash: self.binding.terms_digest(),
            public_commitment: self.public_commitment_v22(),
            keys: &self.keys,
        };
        if let Some(retained) = retained {
            scope
                .verify(retained)
                .map_err(|_| DomActuatorError::CapabilityMismatch)?;
            return Ok(retained.to_vec());
        }
        if self.shares.iter().any(Option::is_none) {
            return Err(DomActuatorError::InvalidStage);
        }
        let mut bytes = Vec::with_capacity(XmrGraphKeyProofScopeV22::ENCODED_LEN);
        for (stage, share) in self.shares.iter().enumerate() {
            let statement = scope
                .statement(stage)
                .map_err(|_| DomActuatorError::CapabilityMismatch)?;
            let proof = dom_adaptor::prove_share_knowledge_v1(
                &statement,
                share.as_ref().ok_or(DomActuatorError::InvalidStage)?,
            )
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
            bytes.extend_from_slice(&proof.to_bytes());
        }
        scope
            .verify(&bytes)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        Ok(bytes)
    }

    /// Bind an ordinary excess only to its canonical, already retained
    /// auxiliary Contracts signing session, exact template and local excess.
    /// A merely created session is insufficient; failed checks consume nothing.
    /// Signing still needs that session's permit.
    pub fn take_ordinary_share_v22(
        &mut self,
        store: &ContractsSessionStoreV1,
        graph: &XmrRecoveryGraphBindingV11,
        kind: XmrOrdinaryRecoveryKindV12,
        template_hash: [u8; 32],
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        if kind == XmrOrdinaryRecoveryKindV12::Compensation {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let binding = self
            .binding
            .for_xmr_ordinary_recovery_v22(graph, kind, template_hash)?;
        self.require_recovery_custody_v23(
            store,
            binding,
            PurposeV1::Refund,
            template_hash,
            None,
            2,
        )?;
        self.take_recovery_index_v23(binding, 2)
    }

    /// Move the V23 compensation excess only after the retained Store round
    /// matches the exact policy, template, roster identities and local key.
    /// No share is consumed on a failed check. A signing permit is still required.
    pub fn take_compensation_share_v23(
        &mut self,
        store: &ContractsSessionStoreV1,
        templates: &xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        let (_, hash) = dom_adaptor::canonical_template_v1(templates.compensation())
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        let binding =
            self.binding
                .for_xmr_compensation_v23(templates.binding(), templates.policy(), hash)?;
        self.require_recovery_custody_v23(store, binding, PurposeV1::Refund, hash, None, 4)?;
        self.take_recovery_index_v23(binding, 4)
    }

    /// Move only the collateral-funding share after the Store has retained
    /// its dedicated bounded-profile origin and both readiness votes.
    /// This neither reserves a nonce nor authorizes a transaction broadcast.
    pub fn take_funding_share_v23(
        &mut self,
        store: &ContractsSessionStoreV1,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        let _bound = DomContractsActuatorV1::bind(store, self.binding)?;
        let trusted = *self.proof_binding.trusted_chain_id();
        let accepted = store
            .resume_xmr_bounded_funding_signing_v23(trusted, self.binding.session_id())
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let entries = accepted.roster().entries();
        if accepted.session_id() != &self.binding.session_id()
            || accepted.trusted_chain_id() != &trusted
            || trusted.as_bytes() != &self.binding.chain_id()
            || accepted.contract_kind() != ContractKindV1::WitnessOrTimeout
            || accepted.purpose() != PurposeV1::Funding
            || accepted.kernel_index() != 0
            || accepted.adaptor_point().is_some()
            || entries.len() != 2
            || entries.iter().map(|entry| *entry.participant_id()).ne(self
                .proof_binding
                .roster()
                .iter()
                .copied())
            || entries[0].direction() == entries[1].direction()
            || !entries.iter().any(|entry| {
                entry.participant_id() == &self.binding.participant().participant_id()
                    && entry.direction() == self.proof_binding.role()
                    && entry.signing_public_key() == &self.keys[0]
            })
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let share = self.shares[0]
            .take()
            .ok_or(DomActuatorError::InvalidStage)?;
        Ok(DomParticipantSigningShareV1::new(self.binding, share))
    }

    /// Move only the Claim share only after the Store has consumed fresh native F7
    /// anchors and authenticated the graph Claim origin and local key.
    /// This neither reserves a nonce nor authorizes a transaction broadcast.
    pub fn take_claim_share_v23(
        &mut self,
        store: &ContractsSessionStoreV1,
        authorization: &dom_scriptless_store::ConsumedF7ClaimAuthorizationV12,
    ) -> DomActuatorResult<DomParticipantSigningShareV1> {
        let _bound = DomContractsActuatorV1::bind(store, self.binding)?;
        let trusted = *self.proof_binding.trusted_chain_id();
        let accepted = store
            .resume_xmr_bounded_claim_signing_v23(trusted, authorization)
            .map_err(|_| DomActuatorError::ContractsAuthorityUnavailable)?;
        let entries = accepted.roster().entries();
        if accepted.session_id() != &self.binding.session_id()
            || accepted.trusted_chain_id() != &trusted
            || trusted.as_bytes() != &self.binding.chain_id()
            || accepted.contract_kind() != ContractKindV1::WitnessOrTimeout
            || accepted.purpose() != PurposeV1::ClaimAdaptor
            || accepted.kernel_index() != 0
            || accepted.adaptor_point().is_none()
            || entries.len() != 2
            || entries.iter().map(|entry| *entry.participant_id()).ne(self
                .proof_binding
                .roster()
                .iter()
                .copied())
            || entries[0].direction() == entries[1].direction()
            || !entries.iter().any(|entry| {
                entry.participant_id() == &self.binding.participant().participant_id()
                    && entry.direction() == self.proof_binding.role()
                    && entry.signing_public_key() == &self.keys[1]
            })
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let share = self.shares[1]
            .take()
            .ok_or(DomActuatorError::InvalidStage)?;
        Ok(DomParticipantSigningShareV1::new(self.binding, share))
    }

    /// Legacy bulk extraction of parent funding, claim and refund shares.
    /// Recovery-only production composition must instead use
    /// [`Self::take_refund_adaptor_share_v23`] to leave funding/claim in custody.
    /// Refund spends D, even though its native adaptor round uses the parent.
    pub fn take_parent_shares_v22(
        &mut self,
    ) -> DomActuatorResult<(
        DomParticipantSigningShareV1,
        DomParticipantSigningShareV1,
        DomParticipantSigningShareV1,
    )> {
        if [0, 1, 3].iter().any(|&index| self.shares[index].is_none()) {
            return Err(DomActuatorError::InvalidStage);
        }
        let mut take = |index: usize| {
            self.shares[index]
                .take()
                .map(|share| DomParticipantSigningShareV1::new(self.binding, share))
                .ok_or(DomActuatorError::InvalidStage)
        };
        Ok((take(0)?, take(1)?, take(3)?))
    }
}

impl DomParticipantWalletSessionV1<'_> {
    /// Compose exact local excesses for C funding, C success, C->D cancel,
    /// D revealing refund and D compensation. All private material stays
    /// inside the wallet/native capability boundary.
    pub fn prepare_xmr_graph_shares_v22(
        &mut self,
        store: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        request: DomXmrGraphSharesRequestV22<'_>,
    ) -> DomActuatorResult<DomXmrGraphSigningSharesV22> {
        let binding = self.wallet.require_session(self.leg)?;
        self.wallet.audit_physical_authority()?;
        let validated = request
            .policy
            .policy()
            .validate_for(request.terms)
            .map_err(|_| DomActuatorError::CapabilityMismatch)?;
        if &validated != request.policy {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.wallet
            .require_shared_binding(binding, request.collateral)?;
        self.wallet
            .require_shared_binding(binding.for_xmr_cancelled_output_v22()?, request.cancelled)?;
        let c = request.collateral.binding();
        let d = request.cancelled.binding();
        if c.roster() != request.terms.roster.map(|p| p.0).as_slice()
            || d.roster() != c.roster()
            || d.role() != c.role()
            || d.share_point() == c.share_point()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let local_funds =
            binding.participant().participant_id() == request.policy.policy().dom_funder;
        let (success_kind, recovery_kind) = if local_funds {
            (
                DomXmrPayoutKindV22::ClaimChange,
                DomXmrPayoutKindV22::Refund,
            )
        } else {
            (
                DomXmrPayoutKindV22::ClaimPrincipal,
                DomXmrPayoutKindV22::Compensation,
            )
        };
        let success = self.authenticate_xmr_payout_face_v22(
            store,
            lease,
            request.terms,
            request.policy,
            success_kind,
            request.now_unix_ms,
        )?;
        let recovery = self.authenticate_xmr_payout_face_v22(
            store,
            lease,
            request.terms,
            request.policy,
            recovery_kind,
            request.now_unix_ms,
        )?;
        let funding = self.prepare_xmr_funding_inputs_v22(
            store,
            lease,
            request.terms,
            request.policy,
            request.now_unix_ms,
        )?;
        if local_funds != funding.is_some() {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let mut offsets = [[0; 32]; 5];
        for (index, capability, purpose) in [
            (0, request.collateral, PurposeV1::Funding),
            (1, request.collateral, PurposeV1::ClaimAdaptor),
            (2, request.collateral, PurposeV1::Refund),
            (3, request.cancelled, PurposeV1::RefundAdaptor),
            (4, request.cancelled, PurposeV1::Refund),
        ] {
            offsets[index] = capability
                .transaction_offset_contribution_v12(purpose)
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
        }
        let mut inputs = Vec::new();
        let mut change = None;
        if let Some(funding) = &funding {
            self.wallet
                .require_live_reservation(store, binding, funding.reservation())?;
            for input in funding.reservation().outputs() {
                let opening = self
                    .wallet
                    .state
                    .outputs
                    .get(&input.commitment())
                    .ok_or(DomActuatorError::WalletUnavailable)?;
                let blinding = BlindingFactor::from_bytes(*opening.blinding)
                    .map_err(|_| DomActuatorError::WalletUnavailable)?;
                if opening.value != input.value()
                    || Commitment::commit(opening.value, &blinding).as_bytes()
                        != &input.commitment()
                {
                    return Err(DomActuatorError::WalletUnavailable);
                }
                inputs.push(&*opening.blinding);
            }
            if let Some(commitment) = funding.change_commitment() {
                let opening = self
                    .wallet
                    .state
                    .outputs
                    .get(&commitment)
                    .ok_or(DomActuatorError::WalletUnavailable)?;
                let blinding = BlindingFactor::from_bytes(*opening.blinding)
                    .map_err(|_| DomActuatorError::WalletUnavailable)?;
                if opening.value != funding.change_noms()
                    || Commitment::commit(opening.value, &blinding).as_bytes() != &commitment
                {
                    return Err(DomActuatorError::WalletUnavailable);
                }
                change = Some(&*opening.blinding);
            }
        }
        let opening = |face: &AuthenticatedDomPayoutFaceV1| -> DomActuatorResult<&[u8; 32]> {
            let output = self
                .wallet
                .state
                .outputs
                .get(&face.payout_commitment())
                .ok_or(DomActuatorError::WalletUnavailable)?;
            if output.value != face.payout_value()
                || output.payout_for().map(PayoutForV1::prepare_digest)
                    != Some(face.retained.prepare_digest)
                || payout_ownership_digest(face.binding(), output)
                    != face.retained.wallet_ownership_digest
            {
                return Err(DomActuatorError::CapabilityMismatch);
            }
            Ok(&*output.blinding)
        };
        let success_opening = opening(&success)?;
        let recovery_opening = opening(&recovery)?;
        let compose = |index: usize,
                       inputs: Vec<&[u8; 32]>,
                       output: Option<&[u8; 32]>,
                       shared: &SessionBlindingShareCapabilityV1|
         -> DomActuatorResult<SigningShareV1> {
            let excess = Zeroizing::new(
                dom_slate::sender_excess_blinding(inputs, output, &offsets[index])
                    .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
            );
            let wallet = SigningShareV1::from_be_bytes(*excess)
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?;
            if index == 0 {
                shared.compose_funding_signing_share_v1(&wallet)
            } else {
                shared.compose_shared_output_spend_signing_share_v1(&wallet)
            }
            .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)
        };
        let shares = [
            compose(0, inputs, change, request.collateral)?,
            compose(1, Vec::new(), Some(success_opening), request.collateral)?,
            request
                .collateral
                .compose_shared_output_transition_signing_share_v12(request.cancelled, &offsets[2])
                .map_err(|_| DomActuatorError::CryptoAuthorityUnavailable)?,
            compose(
                3,
                Vec::new(),
                local_funds.then_some(recovery_opening),
                request.cancelled,
            )?,
            compose(
                4,
                Vec::new(),
                (!local_funds).then_some(recovery_opening),
                request.cancelled,
            )?,
        ];
        let keys = shares.each_ref().map(|share| share.public_key().clone());
        self.wallet.audit_physical_authority()?;
        Ok(DomXmrGraphSigningSharesV22 {
            binding,
            proof_binding: c.clone(),
            shares: shares.map(Some),
            keys,
            offsets,
            funding,
        })
    }
}
