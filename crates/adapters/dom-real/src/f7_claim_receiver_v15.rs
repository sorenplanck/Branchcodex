//! Concrete DOM observation for the native universal F7 receiver.
use super::*;
use dom_scriptless_store::{F7ClaimObserverFactsV15, ObservedF7FinalClaimV15};

#[path = "f7_claim_receiver_bounded_v24.rs"]
mod bounded_v24;
pub(super) use bounded_v24::F7ClaimScanProgressV24;

impl RealDomRpcRuntimeV1 {
    /// Discover the canonical M.8 claim using the retained public verifier.
    /// A refund does not match the claim template; duplicate matches conflict.
    pub fn find_post_m8_claim_v22(
        &self,
        verifier: &RealDomClaimVerifierV1,
        minimum_confirmations: u32,
    ) -> Result<Option<VerifiedDomClaimObservationV1>, RealDomError> {
        if self.adapter.expected_identity().chain_id != verifier.contract.chain_id.0
            || minimum_confirmations == 0
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let (state, identity) = self.scan_through_with_tip(0)?;
        let (_, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let candidate = {
            let mut cache = self.cache()?;
            cache
                .blocks
                .retain(|height, _| *height <= identity.tip_height);
            let blocks = cache.blocks.clone();
            cache.transactions.retain(|_, tx| {
                tx.location().block_height() <= identity.tip_height
                    && blocks
                        .get(&tx.location().block_height())
                        .is_some_and(|(hash, _)| *hash == tx.location().block_hash())
            });
            let mut candidate = None;
            for tx in cache.transactions.values() {
                if tx.spends_commitment(&verifier.contract.shared_output_commitment)
                    && tx.template_hash()? == verifier.contract.claim_template_hash
                {
                    if candidate.is_some() {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    candidate = Some(tx.clone());
                }
            }
            candidate
        };
        let Some(tx) = candidate else {
            return Ok(None);
        };
        let depth = identity
            .tip_height
            .checked_sub(tx.location().block_height())
            .and_then(|n| n.checked_add(1))
            .ok_or(RealDomError::InvalidEvidence)?;
        if depth < u64::from(minimum_confirmations) {
            return Err(RealDomError::InsufficientConfirmations);
        }
        verifier
            .observe_exact_claim(
                &ProvedClaimObservationEvidenceV1::sealed(
                    tx,
                    identity.tip_height,
                    identity.tip_hash,
                ),
                DomClaimObservationTagV1::CounterpartyClaimObserved,
            )
            .map(Some)
    }

    /// Observe the exact requested claim using a single ancestry-proved tip.
    /// Evidence absence is `EvidenceNotFound`; mismatched identity is invalid.
    pub fn observe_f7_final_claim_v15(
        &self,
        facts: &F7ClaimObserverFactsV15,
        evidence: &EvidenceRefV1,
    ) -> Result<VerifiedDomClaimObservationV1, RealDomError> {
        if evidence.chain_id.0 != facts.chain_id() {
            return Err(RealDomError::InvalidEvidence);
        }
        let (transaction, identity) = self.transaction_with_proved_tip(evidence)?;
        verify_f7_observation_v15(
            facts,
            &ProvedClaimObservationEvidenceV1::sealed(
                transaction,
                identity.tip_height,
                identity.tip_hash,
            ),
        )
    }

    /// Discover the canonical spend of the frozen output whose exact template
    /// is the claim. Refunds are not claims. Multiple matching spends are a
    /// contradiction, not a selection policy. No scalar is returned.
    pub fn find_f7_final_claim_v15(
        &self,
        facts: &F7ClaimObserverFactsV15,
    ) -> Result<Option<VerifiedDomClaimObservationV1>, RealDomError> {
        // Existing receiver/downstream-gate consumers use the bounded path
        // without creating another scanner or changing their authority API.
        let deadline =
            Instant::now()
                .checked_add(Duration::from_secs(60))
                .ok_or(RealDomError::Chain(
                    ChainAdapterError::TemporarilyUnavailable,
                ))?;
        self.find_f7_final_claim_until_v24(facts, deadline)
    }

    /// Refetch and revalidate after the native receiver observation is durable.
    /// A reorg never clears the exposure marker; it prevents consumption of
    /// orphaned evidence here. No local boolean substitutes for the token.
    pub fn consume_observed_f7_claim_v15(
        &self,
        facts: &F7ClaimObserverFactsV15,
        observed: &ObservedF7FinalClaimV15,
    ) -> Result<RevealedSecretBytes, RealDomError> {
        if facts.session_id() != observed.session_id()
            || facts.chain_id() != observed.chain_id()
            || facts.receiver_id() != observed.receiver_id()
        {
            return Err(RealDomError::InvalidEvidence);
        }
        self.extract_exact_f7_claim_v21(facts, observed.tx_hash())
    }

    /// Re-extract the sender's already admitted claim from canonical chain
    /// evidence. Native admission proves durable exposure, never finality;
    /// finality and the adaptor opening are independently checked below.
    /// This capability is not receiver ingress and cannot impersonate it.
    pub fn consume_admitted_f7_claim_v21(
        &self,
        facts: &F7ClaimObserverFactsV15,
        admitted: &dom_scriptless_store::AdmittedF7FinalClaimV14,
    ) -> Result<RevealedSecretBytes, RealDomError> {
        if facts.session_id() != admitted.session_id()
            || admitted.exposure_digest() == [0; 32]
            || admitted.admission_digest() == [0; 32]
        {
            return Err(RealDomError::InvalidEvidence);
        }
        self.extract_exact_f7_claim_v21(facts, admitted.tx_hash())
    }

    fn extract_exact_f7_claim_v21(
        &self,
        facts: &F7ClaimObserverFactsV15,
        exact_txid: [u8; 32],
    ) -> Result<RevealedSecretBytes, RealDomError> {
        let evidence = EvidenceRefV1 {
            chain_id: ChainId(facts.chain_id()),
            tx_id: exact_txid,
            event_index: 0,
            block_height: 0,
            block_anchor: [0; 32],
        };
        let (transaction, identity) = self.transaction_with_proved_tip(&evidence)?;
        let proved = ProvedClaimObservationEvidenceV1::sealed(
            transaction,
            identity.tip_height,
            identity.tip_hash,
        );
        let _verified_durable_observation = verify_f7_observation_v15(facts, &proved)?;
        // The caller supplied either the durable receiver observation or the
        // durable sender admission. Reverification gates extraction; it must
        // not mint or persist a second exposure marker here.
        let signature = SchnorrSignature::from_bytes(proved.transaction().kernel_signature(0)?)
            .map_err(|_| RealDomError::InvalidEvidence)?;
        let secret = facts
            .pre_signature()
            .extract_revealed_secret_be_bytes(
                &signature,
                &facts.template_hash(),
                facts.reveal_transcript(),
                facts.signing_key(),
                &facts.chain_id(),
                facts.kernel_message(),
            )
            .map_err(LegError::from)?;
        Ok(RevealedSecretBytes::new(*secret))
    }
}

pub(super) fn verify_f7_observation_v15(
    facts: &F7ClaimObserverFactsV15,
    evidence: &ProvedClaimObservationEvidenceV1,
) -> Result<VerifiedDomClaimObservationV1, RealDomError> {
    let tx = evidence.transaction();
    let txid = canonical_transaction_hash_v1(tx.canonical_bytes())?;
    if txid != tx.tx_hash()
        || !tx.spends_commitment(&facts.shared_commitment())
        || tx.template_hash()? != facts.template_hash()
    {
        return Err(RealDomError::InvalidEvidence);
    }
    let depth = evidence
        .tip_height()
        .checked_sub(tx.location().block_height())
        .and_then(|n| n.checked_add(1))
        .ok_or(RealDomError::InvalidEvidence)?;
    if facts.minimum_confirmations() == 0 || depth < u64::from(facts.minimum_confirmations()) {
        return Err(RealDomError::InsufficientConfirmations);
    }
    let signature = SchnorrSignature::from_bytes(tx.kernel_signature(0)?)
        .map_err(|_| RealDomError::InvalidEvidence)?;
    let proof = facts
        .pre_signature()
        .prove_observed_claim_opens_adaptor_point_v1(
            &signature,
            &FinalSignatureOpeningContextV1 {
                expected_claim_template_hash: &facts.template_hash(),
                expected_transcript_hash: facts.reveal_transcript(),
                signing_key: facts.signing_key(),
                chain_id: &facts.chain_id(),
                kernel_message: facts.kernel_message(),
            },
            ObservedClaimBindingV1 {
                tx_hash: txid,
                shared_output_commitment: facts.shared_commitment(),
                kernel_index: 0,
            },
        )
        .map_err(LegError::from)?;
    Ok(VerifiedDomClaimObservationV1::from_verified_opening_v1(
        proof,
        DomClaimObservationTagV1::CounterpartyClaimObserved,
        ObservedClaimFactsV1 {
            chain_id: facts.chain_id(),
            session_id: facts.session_id(),
            tx_hash: txid,
            template_hash: facts.template_hash(),
            shared_output_commitment: facts.shared_commitment(),
            location: ObservedClaimLocationV1 {
                block_height: tx.location().block_height(),
                block_hash: tx.location().block_hash(),
                transaction_index: tx.location().transaction_index(),
            },
            observed_tip_height: evidence.tip_height(),
            observed_tip_id: *evidence.tip_id(),
        },
    )?)
}
