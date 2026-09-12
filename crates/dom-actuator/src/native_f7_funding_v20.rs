//! Mirror authenticated native F7 custody atomically, without manufacturing
//! legacy signing operations or reporting a node submission that did not occur.
use super::*;
impl DomActuatorStoreV1 {
    /// Native Contracts owns the sealed proof of templates, BP, refund, votes
    /// and committed signed funding. This mirror holds only commitments.
    pub(crate) fn retain_native_f7_funding_v20(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        native: &dom_scriptless_store::PreparedF7FundingSubmissionV12,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        self.retain_native_f7_custody_v20(lease, scope, native, None, now_unix_ms)
    }

    pub(crate) fn retain_native_f7_refund_v20(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        native: &dom_scriptless_store::PreparedF7FundingSubmissionV12,
        refund_hash: Digest32,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        self.retain_native_f7_custody_v20(lease, scope, native, Some(refund_hash), now_unix_ms)
    }

    fn retain_native_f7_custody_v20(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        native: &dom_scriptless_store::PreparedF7FundingSubmissionV12,
        refund_hash: Option<Digest32>,
        now_unix_ms: u64,
    ) -> DomActuatorResult<()> {
        let receipt = refund_hash.unwrap_or_else(|| native.tx_hash());
        validate_digest(receipt)?;
        let action = if refund_hash.is_some() {
            DomActionV1::BroadcastRefund
        } else {
            DomActionV1::BroadcastFunding
        };
        if scope.action() != action
            || scope.binding().session_id() != native.session_id()
            || scope.binding().chain_id() != native.chain_id()
            || scope.binding().terms_digest() != native.terms_hash()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let evidence = hash_parts(&[
            b"DOM:actuator-native-f7-custody:v20",
            &native.gate_digest(),
            &receipt,
            &[action.tag()],
        ]);
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        require_scope(&transaction, lease, scope)?;
        require_no_refund_after_claim_exposure(&transaction, scope)?;
        let scope_hash = scope_digest(scope);
        let authorization = authorization_digest(scope_hash, evidence, None, lease.fencing_epoch);
        if let Some(old) = load_operation(&transaction, scope.effect_id())? {
            if old.scope_digest != scope_hash
                || old.evidence_digest != evidence
                || old.secret_binding_digest.is_some()
                || old.status != OP_COMPLETED
                || old.receipt_digest != Some(receipt)
                || old.fencing_epoch > lease.fencing_epoch
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            if old.fencing_epoch == lease.fencing_epoch {
                if old.authorization_digest != authorization {
                    return Err(DomActuatorError::IdempotencyConflict);
                }
                transaction.commit().map_err(storage)?;
                return Ok(());
            }
            // Reuse the existing exact non-secret takeover boundary after
            // authenticating this new profile's evidence and native outbox.
            let previous = old.authorization_digest;
            transaction.commit().map_err(storage)?;
            let capability = self.reauthorize_retained_exact_replay(
                lease,
                scope,
                previous,
                receipt,
                now_unix_ms,
            )?;
            self.complete_action(lease, capability, receipt, now_unix_ms)?;
            return Ok(());
        }
        let stage = load_stage(&transaction, scope.binding().session_id())?;
        let next = if action == DomActionV1::BroadcastRefund {
            next_stage(stage, action)?
        } else {
            if !(STAGE_BOUND..=STAGE_CLAIM_PREPARED).contains(&stage) {
                return Err(DomActuatorError::InvalidStage);
            }
            STAGE_FUNDING_BROADCAST
        };
        // Only this sealed native snapshot may advance across the earlier
        // local mirror stages: all of those real operations already reside
        // in the independent Contracts journal authenticated by its issuer.
        transaction
            .execute(
                "INSERT INTO dom_operations
            (effect_id,route_id,session_id,participant_id,action_tag,fencing_epoch,scope_digest,
             evidence_digest,secret_binding_digest,authorization_digest,status_tag,receipt_digest,
             reconciliation_digest,created_at_unix_ms,updated_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,1,?10,NULL,?11,?11)",
                params![
                    scope.effect_id().as_slice(),
                    scope.binding().route_id().as_slice(),
                    scope.binding().session_id().as_slice(),
                    scope.binding().participant().participant_id().as_slice(),
                    i64::from(scope.action().tag()),
                    to_sql(lease.fencing_epoch)?,
                    scope_hash.as_slice(),
                    evidence.as_slice(),
                    authorization.as_slice(),
                    receipt.as_slice(),
                    to_sql(now_unix_ms)?
                ],
            )
            .map_err(storage)?;
        let event = hash_parts(&[
            b"DOM:actuator-native-f7-custody-complete:v20",
            &scope_hash,
            &evidence,
        ]);
        append_event(
            &transaction,
            scope.binding().session_id(),
            scope.effect_id(),
            event,
            next,
            lease.fencing_epoch,
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)
    }
}
