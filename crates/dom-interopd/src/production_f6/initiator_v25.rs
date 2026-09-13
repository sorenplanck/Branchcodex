//! Initiator-side F6 receiver. This owns no solver inventory capability.
//!
//! The binding journal is a local mirror of threshold-attested reservations,
//! not the solver's reservation store. It has a distinct physical binding and
//! never escapes this type. Only the solver can commit or release inventory.
//! RFQ, selection and acceptance are applied only after the existing Relay
//! inbox authenticates the initiator's own outbound envelope. Preparing bytes
//! does not substitute for that authenticated durable delivery.

use super::*;

const INITIATOR_LOG_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-INITIATOR-LOG/V25\0";
const INITIATOR_RECEIPTS_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-INITIATOR-RECEIPTS/V25\0";

/// Owned, least-privilege inputs. In particular there is no inventory, lease,
/// local solver status store, reservation signer, or terminal-release source.
pub(crate) struct ProductionInitiatorF6AuthoritiesV25 {
    pub historical_recovery_v24:
        Option<crate::production_inputs::f6_recovery_v24::HistoricalF6RecoveryV24>,
    pub pre_f6_time: DurablePreF6TimeStoreV2,
    pub bond_attestation_authorities: AuthoritySetV1,
    pub remote_status_authorities: AuthoritySetV1,
    pub secp: SecpContext,
    pub rosters: RosterRegistryV1,
    pub terms: Box<dyn ProductionF6TermsAuthorityV2>,
}

/// Receives the authenticated negotiation for the initiator of one position.
/// Neither this receiver nor anything it returns is a funding capability.
pub(crate) struct ProductionInitiatorF6AuthorityV25 {
    historical_recovery_v24:
        Option<crate::production_inputs::f6_recovery_v24::HistoricalF6RecoveryV24>,
    binding: ProductionSolverF6BindingV2,
    binding_log: DurableBindingV2<StoreLogV2>,
    receipts: Store,
    pre_f6_time: DurablePreF6TimeStoreV2,
    candidate_book: DurableCandidateBookV2<CandidateBookStoreLogV2>,
    bond_attestation_authorities: AuthoritySetV1,
    remote_status_authorities: AuthoritySetV1,
    secp: SecpContext,
    rosters: RosterRegistryV1,
    terms: Box<dyn ProductionF6TermsAuthorityV2>,
}

impl core::fmt::Debug for ProductionInitiatorF6AuthorityV25 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionInitiatorF6AuthorityV25([authorities redacted])")
    }
}

impl ProductionInitiatorF6AuthorityV25 {
    pub(crate) fn create_production(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        local_participant: ParticipantId,
        authorities: ProductionInitiatorF6AuthoritiesV25,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(
            paths,
            binding,
            local_participant,
            authorities,
            OpenModeV2::Create,
        )
    }

    pub(crate) fn open_existing(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        local_participant: ParticipantId,
        authorities: ProductionInitiatorF6AuthoritiesV25,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(
            paths,
            binding,
            local_participant,
            authorities,
            OpenModeV2::Open,
        )
    }

    pub(crate) fn open_or_resume_prepared_production(
        paths: ProductionF6PathsV2<'_>,
        prepared: ProductionF6PreparedBindingsV2,
        binding: ProductionSolverF6BindingV2,
        local_participant: ParticipantId,
        authorities: ProductionInitiatorF6AuthoritiesV25,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(
            paths,
            binding,
            local_participant,
            authorities,
            OpenModeV2::Prepared(prepared),
        )
    }

    fn open_with_mode(
        paths: ProductionF6PathsV2<'_>,
        binding: ProductionSolverF6BindingV2,
        local_participant: ParticipantId,
        authorities: ProductionInitiatorF6AuthoritiesV25,
        mode: OpenModeV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        binding.validate()?;
        require_local_initiator(binding, local_participant)?;
        validate_roster(binding, &authorities.rosters)?;
        validate_pre_f6_authority(
            binding,
            authorities.pre_f6_time.scope_digest(),
            authorities.pre_f6_time.negotiation_clock(),
        )?;
        if authorities
            .historical_recovery_v24
            .as_ref()
            .is_some_and(|recovery| {
                !recovery.require_scope(binding.wire.route_id, binding.composition_id)
            })
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        // Historical receipt replay cannot provision a missing authority.
        let mode = if authorities.historical_recovery_v24.is_some() {
            OpenModeV2::Open
        } else {
            mode
        };
        let log_binding = binding.authority_digest(INITIATOR_LOG_DOMAIN)?;
        let log = match mode {
            OpenModeV2::Create => StoreLogV2::create_production(paths.binding_log, log_binding),
            OpenModeV2::Open => StoreLogV2::open_production(paths.binding_log, log_binding),
            OpenModeV2::Resume => {
                StoreLogV2::resume_create_production(paths.binding_log, log_binding)
            }
            OpenModeV2::Prepared(prepared) => StoreLogV2::open_or_resume_prepared_production(
                paths.binding_log,
                prepared.binding_log,
                log_binding,
            ),
        }
        .map_err(map_engine)?;
        let binding_log = DurableBindingV2::open(log).map_err(map_engine)?;
        let receipt_binding =
            ProductionStoreBindingV1::new(binding.authority_digest(INITIATOR_RECEIPTS_DOMAIN)?)
                .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        let receipts = match mode {
            OpenModeV2::Create => Store::create_production(paths.receipt_store, receipt_binding),
            OpenModeV2::Open => Store::open_production(paths.receipt_store, receipt_binding),
            OpenModeV2::Resume => {
                Store::resume_create_production(paths.receipt_store, receipt_binding)
            }
            OpenModeV2::Prepared(prepared) => Store::open_or_resume_prepared_production(
                paths.receipt_store,
                ProductionStoreBindingV1::new(prepared.receipt_store)
                    .map_err(|_| ProductionF6ErrorV2::Receipt)?,
                receipt_binding,
            ),
        }
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
        let scope = candidate_scope(binding);
        let log = match mode {
            OpenModeV2::Create => {
                CandidateBookStoreLogV2::create_production(paths.candidate_book, scope)
            }
            OpenModeV2::Open => {
                CandidateBookStoreLogV2::open_production(paths.candidate_book, scope)
            }
            OpenModeV2::Resume => {
                CandidateBookStoreLogV2::resume_create_production(paths.candidate_book, scope)
            }
            OpenModeV2::Prepared(prepared) => {
                CandidateBookStoreLogV2::open_or_resume_prepared_production(
                    paths.candidate_book,
                    prepared.candidate_book,
                    scope,
                )
            }
        }
        .map_err(map_candidate)?;
        let verifiers = CandidateVerificationAuthoritiesV2::new(
            &authorities.bond_attestation_authorities,
            &authorities.remote_status_authorities,
            &authorities.secp,
            &authorities.rosters,
        );
        // Reopen re-verifies every original signed candidate frame. A mirror
        // ledger row or an opaque cached boolean is not candidate authority.
        let candidate_book =
            DurableCandidateBookV2::open(log, scope, &verifiers).map_err(map_candidate)?;
        Ok(Self {
            historical_recovery_v24: authorities.historical_recovery_v24,
            binding,
            binding_log,
            receipts,
            candidate_book,
            pre_f6_time: authorities.pre_f6_time,
            bond_attestation_authorities: authorities.bond_attestation_authorities,
            remote_status_authorities: authorities.remote_status_authorities,
            secp: authorities.secp,
            rosters: authorities.rosters,
            terms: authorities.terms,
        })
    }

    /// Derives unsigned selection bytes from fresh, complete portable
    /// authority. The caller must sign/send through the ordinary Relay owner
    /// and deliver that authenticated envelope back to this receiver.
    pub(crate) fn prepare_selection(&mut self) -> Result<SelectionV2, ProductionF6ErrorV2> {
        let rfq = self.load_rfq()?;
        let (candidates, current) = self.current_candidates(&rfq)?;
        let selected = select_winner_with_authority_digest_v2(
            &rfq,
            &candidates.candidates,
            self.binding.dom_chain_id,
            current.observation(),
            candidates.snapshot_digest,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?
        .selection;
        self.require_designated_winner(&candidates, selected.winning_quote)?;
        Ok(selected)
    }

    /// Prepares, but does not apply, acceptance of adapter-authenticated
    /// terms for the already authenticated and still-current selection.
    pub(crate) fn prepare_acceptance(&mut self) -> Result<AcceptanceV2, ProductionF6ErrorV2> {
        let rfq = self.load_rfq()?;
        let quote = self.current_selected_quote(&rfq)?;
        let terms = self.load_or_authenticate_terms(&rfq, &quote)?;
        AcceptanceV2::from_terms(&terms, self.binding.initiator)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)
    }

    fn load_rfq(&self) -> Result<RfqV2, ProductionF6ErrorV2> {
        let bytes = load_required_f6_receipt(
            &self.receipts,
            RFQ_NAMESPACE,
            self.binding.rfq_id,
            RequiredF6ReceiptV2::Rfq,
        )?;
        let rfq = RfqV2::decode(&bytes).map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        validate_rfq(self.binding, &rfq)?;
        Ok(rfq)
    }

    fn current_time(
        &mut self,
        rfq: &RfqV2,
        now: u64,
    ) -> Result<CurrentPreF6NegotiationTimeV2, ProductionF6ErrorV2> {
        if self.historical_recovery_v24.is_some() {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let current = self
            .pre_f6_time
            .prove_current_pre_f6_time(&self.secp, now)
            .map_err(|_| ProductionF6ErrorV2::TimeUnavailable)?;
        validate_time(self.binding, rfq, &current)?;
        Ok(current)
    }

    fn current_candidates(
        &mut self,
        rfq: &RfqV2,
    ) -> Result<
        (
            ProductionCandidateAuthorityV2,
            CurrentPreF6NegotiationTimeV2,
        ),
        ProductionF6ErrorV2,
    > {
        let wall = observe_trusted_wall()?;
        let current = self.current_time(rfq, wall.seconds)?;
        // Both bond and status signatures were verified on admission/reopen;
        // every selection/acceptance rechecks their exact current validity.
        let proof = self
            .candidate_book
            .prove_current_candidates(wall.seconds)
            .map_err(map_candidate)?;
        if proof.scope() != candidate_scope(self.binding)
            || proof.revision() == 0
            || proof.inputs_digest() == ZERO_DIGEST
            || proof.candidates().is_empty()
        {
            return Err(ProductionF6ErrorV2::Binding);
        }
        let candidates = proof.candidates().to_vec();
        let mut quotes = BTreeSet::new();
        let mut solvers = BTreeSet::new();
        let mut reservations = BTreeSet::new();
        for (quote, _) in &candidates {
            if !quotes.insert(quote.quote_id)
                || !solvers.insert(quote.solver)
                || !reservations.insert(quote.bond_reservation_id)
            {
                return Err(ProductionF6ErrorV2::InvalidPayload);
            }
        }
        Ok((
            ProductionCandidateAuthorityV2 {
                candidates,
                snapshot_digest: proof.inputs_digest(),
            },
            current,
        ))
    }

    fn require_designated_winner(
        &self,
        candidates: &ProductionCandidateAuthorityV2,
        id: Digest32,
    ) -> Result<QuoteV2, ProductionF6ErrorV2> {
        let quote = candidates
            .candidates
            .iter()
            .find(|entry| entry.0.quote_id == id)
            .map(|entry| entry.0)
            .ok_or(ProductionF6ErrorV2::Binding)?;
        // A previously enrolled composition does not permit silently replacing
        // its solver even when a different roster candidate wins the auction.
        if quote.solver != self.binding.solver {
            return Err(ProductionF6ErrorV2::WrongRole);
        }
        Ok(quote)
    }

    fn current_selected_quote(&mut self, rfq: &RfqV2) -> Result<QuoteV2, ProductionF6ErrorV2> {
        let (candidates, current) = self.current_candidates(rfq)?;
        let selected = self
            .binding_log
            .ledger()
            .selection(
                self.binding.composition_id,
                self.binding.position,
                self.binding.rfq_id,
            )
            .ok_or(ProductionF6ErrorV2::Binding)?;
        let expected = select_winner_with_authority_digest_v2(
            rfq,
            &candidates.candidates,
            self.binding.dom_chain_id,
            current.observation(),
            candidates.snapshot_digest,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let quote = self.require_designated_winner(&candidates, selected.winning_quote)?;
        validate_current_local_selection(
            quote.quote_id,
            candidates.snapshot_digest,
            selected.winning_quote,
            selected.inputs_digest,
            &expected.selection,
        )?;
        Ok(quote)
    }

    fn load_or_authenticate_terms(
        &mut self,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<TermsBindingV2, ProductionF6ErrorV2> {
        if let Some(bytes) = self
            .receipts
            .opaque(TERMS_NAMESPACE, &self.binding.rfq_id)
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
        {
            return decode_terms_record(self.binding, quote, &bytes);
        }
        let authenticated = self.terms.authenticate_terms(&self.binding, rfq, quote)?;
        validate_authenticated_terms(self.binding, rfq, quote, &authenticated)?;
        let record = encode_terms_record(self.binding, &authenticated)?;
        retain_exact(
            &mut self.receipts,
            TERMS_NAMESPACE,
            &self.binding.rfq_id,
            &record,
        )?;
        decode_terms_record(self.binding, quote, &record)
    }

    fn accept_authenticated(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
        let applied = delivery_record(delivery, DurablePayloadDispositionV1::Applied)?;
        let failed = delivery_record(delivery, DurablePayloadDispositionV1::FailedClosed)?;
        if let Some(existing) = self
            .receipts
            .opaque(DELIVERY_NAMESPACE, delivery.envelope_digest())
            .map_err(|_| ProductionF6ErrorV2::Receipt)?
        {
            return exact_delivery_replay(&existing, &applied, &failed);
        }
        if self.historical_recovery_v24.is_some() {
            return Err(ProductionF6ErrorV2::Receipt);
        }
        self.apply_delivery(delivery)?;
        retain_exact(
            &mut self.receipts,
            DELIVERY_NAMESPACE,
            delivery.envelope_digest(),
            &applied,
        )?;
        durable_commit(&applied, DurablePayloadDispositionV1::Applied, false)
    }

    fn apply_delivery(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        use relay::auth::message_type;
        match delivery.message_type() {
            message_type::RFQ => {
                require_initiator_sender(self.binding, delivery.sender_id())?;
                let rfq = RfqV2::decode(delivery.payload())
                    .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
                validate_rfq(self.binding, &rfq)?;
                retain_exact(
                    &mut self.receipts,
                    RFQ_NAMESPACE,
                    &self.binding.rfq_id,
                    delivery.payload(),
                )
            }
            message_type::QUOTE => self.accept_quote(delivery),
            message_type::SELECTION => self.accept_selection(delivery),
            message_type::ACCEPTANCE => self.accept_acceptance(delivery),
            _ => Err(ProductionF6ErrorV2::InvalidPayload),
        }
    }

    fn accept_quote(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        if self
            .binding_log
            .ledger()
            .selection(
                self.binding.composition_id,
                self.binding.position,
                self.binding.rfq_id,
            )
            .is_some()
        {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        let candidate =
            CandidateQuoteDeliveryV2::decode(delivery.payload()).map_err(map_candidate)?;
        let quote = candidate.quote();
        require_quote_sender(self.binding, delivery.sender_id(), quote.solver)?;
        let rfq = self.load_rfq()?;
        let wall = observe_trusted_wall()?;
        let current = self.current_time(&rfq, wall.seconds)?;
        verify_candidate_quote_delivery_v2(
            &candidate,
            candidate_scope(self.binding),
            &self.bond_attestation_authorities,
            &self.remote_status_authorities,
            &self.secp,
            wall.seconds,
        )
        .map_err(map_candidate)?;
        let request = candidate
            .attestation()
            .attestation()
            .map_err(map_candidate)?
            .request();
        let verifiers = CandidateVerificationAuthoritiesV2::new(
            &self.bond_attestation_authorities,
            &self.remote_status_authorities,
            &self.secp,
            &self.rosters,
        );
        validate_and_admit_remote_candidate(
            &rfq,
            &quote,
            request,
            self.binding.dom_chain_id,
            current.observation(),
            || {
                self.candidate_book
                    .admit_remote(&candidate, &verifiers, wall.seconds)
                    .map_err(map_candidate)
            },
        )?;
        // Only after real bond/status/roster signatures and RFQ economics
        // passed may this independent mirror record a remote reservation.
        if !self.binding_log.ledger().reservation_backs(
            quote.bond_reservation_id,
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
            quote.quote_id,
            quote.solver,
        ) {
            self.binding_log
                .apply(&BindingEventV2::Reserved {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    reservation_id: quote.bond_reservation_id,
                    rfq_id: self.binding.rfq_id,
                    quote_id: quote.quote_id,
                    solver: quote.solver,
                })
                .map_err(map_engine)?;
        }
        Ok(())
    }

    fn accept_selection(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        require_initiator_sender(self.binding, delivery.sender_id())?;
        let rfq = self.load_rfq()?;
        let (candidates, current) = self.current_candidates(&rfq)?;
        let selection = SelectionV2::decode(delivery.payload())
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let ids: Vec<_> = candidates
            .candidates
            .iter()
            .map(|entry| entry.0.quote_id)
            .collect();
        selection
            .validate_against_authority_snapshot(&rfq, &ids, candidates.snapshot_digest)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        let expected = select_winner_with_authority_digest_v2(
            &rfq,
            &candidates.candidates,
            self.binding.dom_chain_id,
            current.observation(),
            candidates.snapshot_digest,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        if expected.selection != selection {
            return Err(ProductionF6ErrorV2::InvalidPayload);
        }
        self.require_designated_winner(&candidates, selection.winning_quote)?;
        match self.binding_log.ledger().selection(
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
        ) {
            Some(existing)
                if existing.winning_quote == selection.winning_quote
                    && existing.inputs_digest == selection.inputs_digest =>
            {
                Ok(())
            }
            Some(_) => Err(ProductionF6ErrorV2::Binding),
            None => self
                .binding_log
                .apply(&BindingEventV2::Selected {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    rfq_id: self.binding.rfq_id,
                    winning_quote: selection.winning_quote,
                    inputs_digest: selection.inputs_digest,
                })
                .map_err(map_engine),
        }
    }

    fn accept_acceptance(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<(), ProductionF6ErrorV2> {
        require_initiator_sender(self.binding, delivery.sender_id())?;
        let acceptance = AcceptanceV2::decode(delivery.payload())
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        require_initiator_sender(self.binding, acceptance.accepted_by)?;
        let rfq = self.load_rfq()?;
        let quote = self.current_selected_quote(&rfq)?;
        let terms = self.load_or_authenticate_terms(&rfq, &quote)?;
        acceptance
            .validate_against(&terms)
            .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
        match self.binding_log.ledger().binding(
            self.binding.composition_id,
            self.binding.position,
            self.binding.rfq_id,
        ) {
            Some(existing)
                if existing.composition_id == self.binding.composition_id
                    && existing.position == self.binding.position
                    && existing.quote_id == quote.quote_id
                    && existing.solver == quote.solver
                    && existing.accepted_by == acceptance.accepted_by
                    && existing.reservation_id == quote.bond_reservation_id
                    && existing.terms_hash == acceptance.terms_hash =>
            {
                Ok(())
            }
            Some(_) => Err(ProductionF6ErrorV2::Binding),
            None => self
                .binding_log
                .apply(&BindingEventV2::Bound {
                    composition_id: self.binding.composition_id,
                    position: self.binding.position,
                    rfq_id: self.binding.rfq_id,
                    quote_id: quote.quote_id,
                    solver: quote.solver,
                    accepted_by: acceptance.accepted_by,
                    reservation_id: quote.bond_reservation_id,
                    terms_hash: acceptance.terms_hash,
                })
                .map_err(map_engine),
        }
        // Deliberately no inventory commit: the authenticated acceptance must
        // independently reach the solver's receiver and exclusive lease.
    }

    fn fail_closed_delivery(
        &mut self,
        delivery: &F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
        let record = delivery_record(delivery, DurablePayloadDispositionV1::FailedClosed)?;
        retain_exact(
            &mut self.receipts,
            DELIVERY_NAMESPACE,
            delivery.envelope_digest(),
            &record,
        )?;
        durable_commit(&record, DurablePayloadDispositionV1::FailedClosed, false)
    }
}

impl F6TransportPortV1 for ProductionInitiatorF6AuthorityV25 {
    type Error = ProductionF6ErrorV2;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        match self.accept_authenticated(&delivery) {
            Ok(commit) => Ok(commit),
            Err(error) if is_permanent_f6_refusal(&error) => self.fail_closed_delivery(&delivery),
            Err(error) => Err(error),
        }
    }
}

fn require_local_initiator(
    binding: ProductionSolverF6BindingV2,
    local: ParticipantId,
) -> Result<(), ProductionF6ErrorV2> {
    require_initiator_sender(binding, local)
}

fn require_initiator_sender(
    binding: ProductionSolverF6BindingV2,
    sender: ParticipantId,
) -> Result<(), ProductionF6ErrorV2> {
    if sender != binding.initiator {
        return Err(ProductionF6ErrorV2::WrongRole);
    }
    Ok(())
}

fn require_quote_sender(
    binding: ProductionSolverF6BindingV2,
    sender: ParticipantId,
    solver: ParticipantId,
) -> Result<(), ProductionF6ErrorV2> {
    if sender != solver || solver == binding.initiator {
        return Err(ProductionF6ErrorV2::WrongRole);
    }
    Ok(())
}

fn retain_exact(
    store: &mut Store,
    namespace: &[u8],
    key: &[u8],
    bytes: &[u8],
) -> Result<(), ProductionF6ErrorV2> {
    store
        .put_opaque_if_absent(namespace, key, bytes)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?;
    if store
        .opaque(namespace, key)
        .map_err(|_| ProductionF6ErrorV2::Receipt)?
        .as_deref()
        != Some(bytes)
    {
        return Err(ProductionF6ErrorV2::Receipt);
    }
    Ok(())
}

fn exact_delivery_replay(
    existing: &[u8],
    applied: &[u8],
    failed: &[u8],
) -> Result<DurablePayloadCommitV1, ProductionF6ErrorV2> {
    if existing == applied {
        durable_commit(existing, DurablePayloadDispositionV1::Applied, true)
    } else if existing == failed {
        durable_commit(existing, DurablePayloadDispositionV1::FailedClosed, true)
    } else {
        Err(ProductionF6ErrorV2::Receipt)
    }
}

#[cfg(test)]
#[path = "initiator_v25_tests.rs"]
mod tests;
