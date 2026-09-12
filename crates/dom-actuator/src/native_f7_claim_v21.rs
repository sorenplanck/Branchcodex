//! Owner-bound preparation recovery in the existing authenticated journal.
//! No schema change, transaction bytes, secret or caller-selected authority.
use super::*;

/// Preparation/re-fencing is not completion of the claim operation. Keep its
/// journal identity distinct so the ordinary operation audit remains strict.
pub(super) fn claim_prefix_effect_v21(scope: ScopedDomActionV1) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-claim-preparation-effect:v21",
        &scope_digest(scope),
    ])
}

pub(super) fn claim_prefix_digest_v21(
    scope: ScopedDomActionV1,
    owner: Digest32,
    fence: u64,
    authorization: Digest32,
) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-claim-preparation-owner:v21",
        &scope_digest(scope),
        &owner,
        &fence.to_be_bytes(),
        &authorization,
    ])
}

impl DomActuatorStoreV1 {
    /// Read the retained authorization. A prepared-only crash prefix can be
    /// re-fenced only by the same owner recorded atomically with preparation.
    /// Completed attempts use the existing stricter V2 replay boundary.
    pub(crate) fn f7_claim_previous_authorization_v21(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        evidence: Digest32,
        now: u64,
    ) -> DomActuatorResult<Option<Digest32>> {
        if scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now)?;
        require_scope(&transaction, lease, scope)?;
        let Some(old) = load_operation(&transaction, scope.effect_id())? else {
            transaction.commit().map_err(storage)?;
            return Ok(None);
        };
        if old.scope_digest != scope_digest(scope)
            || old.evidence_digest != evidence
            || old.secret_binding_digest.is_some()
            || old.fencing_epoch > lease.fencing_epoch
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if old.status != OP_PREPARED || old.fencing_epoch == lease.fencing_epoch {
            transaction.commit().map_err(storage)?;
            return Ok(Some(old.authorization_digest));
        }
        if old.receipt_digest.is_some()
            || load_final_claim_attempt_v2(&transaction, scope.binding().session_id())?.is_some()
            || load_final_claim_admission_v2(&transaction, scope.binding().session_id())?.is_some()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let expected = claim_prefix_digest_v21(
            scope,
            lease.owner_id,
            old.fencing_epoch,
            old.authorization_digest,
        );
        let count: i64 = transaction.query_row(
            "SELECT count(*) FROM dom_session_events WHERE session_id=?1 AND effect_id=?2 AND event_digest=?3 AND fencing_epoch=?4",
            params![scope.binding().session_id().as_slice(), claim_prefix_effect_v21(scope).as_slice(),
                expected.as_slice(), to_sql(old.fencing_epoch)?], |row| row.get(0),
        ).map_err(storage)?;
        if count != 1 {
            return Err(DomActuatorError::ReconciliationRequired);
        }
        let next = authorization_digest(old.scope_digest, evidence, None, lease.fencing_epoch);
        let changed = transaction.execute(
            "UPDATE dom_operations SET fencing_epoch=?2,authorization_digest=?3,updated_at_unix_ms=?4
             WHERE effect_id=?1 AND status_tag=0 AND fencing_epoch=?5 AND authorization_digest=?6",
            params![scope.effect_id().as_slice(), to_sql(lease.fencing_epoch)?, next.as_slice(),
                to_sql(now)?, to_sql(old.fencing_epoch)?, old.authorization_digest.as_slice()],
        ).map_err(storage)?;
        if changed != 1 {
            return Err(DomActuatorError::RevisionConflict);
        }
        let stage = load_stage(&transaction, scope.binding().session_id())?;
        append_event(
            &transaction,
            scope.binding().session_id(),
            claim_prefix_effect_v21(scope),
            claim_prefix_digest_v21(scope, lease.owner_id, lease.fencing_epoch, next),
            stage,
            lease.fencing_epoch,
            now,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(Some(next))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        advance_to_funding_confirmed, binding, digest, final_claim_v2_facts,
        final_claim_v2_state_snapshot, setup, TestContext, TestResult,
    };
    use super::*;

    #[test]
    fn v21_prepared_claim_recovers_same_owner_without_an_attempt_or_secret() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store.bind_session(lease, bound, 1_000)?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let scope = ScopedDomActionV1::new(bound, digest(27), DomActionV1::BroadcastClaim)?;
        let evidence = digest(163);
        let (old, _) = store.authorize_f7_claim_action_v21(lease, scope, evidence, 1_510)?;
        let facts = final_claim_v2_facts(evidence, bound);
        drop(store);
        let mut store =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen prepared F7 claim")?;
        let lease = store.acquire_lease(digest(9), digest(20), 12_000, 10_000)?;
        let restored = store.f7_claim_previous_authorization_v21(lease, scope, evidence, 12_001)?;
        assert!(restored.is_some());
        assert_ne!(restored, Some(old.authorization_digest()));
        // Repeating recovery does not add attempts or journal entries.
        let before =
            final_claim_v2_state_snapshot(&store, bound).test_context("audit prepared F7 claim")?;
        assert_eq!(
            store.f7_claim_previous_authorization_v21(lease, scope, evidence, 12_002)?,
            restored
        );
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        let (capability, disposition) =
            store.authorize_action(lease, scope, evidence, None, 12_003)?;
        assert_eq!(disposition, DomOperationDispositionV1::Idempotent);
        let _latched = store.latch_final_claim_attempt_v2(lease, &capability, &facts, 12_004)?;
        let audit = store.audit_final_claim_custody_v2(lease, bound, 12_005)?;
        assert_eq!(audit.send_attempt_count(), 1);
        assert_eq!(audit.tx_hash(), facts.tx_hash);
        Ok(())
    }

    #[test]
    fn v21_prepared_claim_marker_survives_successive_refences_without_completion() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store.bind_session(lease, bound, 1_000)?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let scope = ScopedDomActionV1::new(bound, digest(27), DomActionV1::BroadcastClaim)?;
        let evidence = digest(163);
        let (initial, _) = store.authorize_f7_claim_action_v21(lease, scope, evidence, 1_510)?;
        let marker = claim_prefix_effect_v21(scope);
        assert_ne!(marker, scope.effect_id());
        let other = ScopedDomActionV1::new(bound, digest(28), DomActionV1::BroadcastClaim)?;
        assert_ne!(marker, claim_prefix_effect_v21(other));
        let mut previous = initial.authorization_digest();
        for (index, now) in [12_000, 24_000].into_iter().enumerate() {
            drop(store);
            store = DomActuatorStoreV1::open_existing(&path)?;
            let lease = store.acquire_lease(digest(9), digest(20), now, 10_000)?;
            let recovered = store
                .f7_claim_previous_authorization_v21(lease, scope, evidence, now + 1)?
                .ok_or("missing prepared authorization")?;
            assert_ne!(recovered, previous);
            previous = recovered;
            let counts = |effect: Digest32| -> TestResult<i64> {
                Ok(store.connection.query_row(
                    "SELECT count(*) FROM dom_session_events WHERE session_id=?1 AND effect_id=?2",
                    params![bound.session_id().as_slice(), effect.as_slice()],
                    |row| row.get(0),
                )?)
            };
            assert_eq!(counts(scope.effect_id())?, 0);
            assert_eq!(counts(marker)?, index as i64 + 2);
            assert!(matches!(
                store.audit_final_claim_custody_v2(lease, bound, now + 2),
                Err(DomActuatorError::ReconciliationRequired)
            ));
        }
        drop(store);
        let _reopened = DomActuatorStoreV1::open_existing(&path)?;
        Ok(())
    }

    #[test]
    fn v21_prepared_claim_rejects_other_owner_or_evidence_without_writes() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let bound = binding(1, 2)?;
        store.bind_session(lease, bound, 1_000)?;
        advance_to_funding_confirmed(&mut store, lease, bound)?;
        let scope = ScopedDomActionV1::new(bound, digest(27), DomActionV1::BroadcastClaim)?;
        let evidence = digest(163);
        let _prepared = store.authorize_f7_claim_action_v21(lease, scope, evidence, 1_510)?;
        let before =
            final_claim_v2_state_snapshot(&store, bound).test_context("audit prepared F7 claim")?;
        assert!(matches!(
            store.f7_claim_previous_authorization_v21(lease, scope, digest(199), 1_512),
            Err(DomActuatorError::CapabilityMismatch)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        drop(store);
        let mut store =
            DomActuatorStoreV1::open_existing(&path).test_context("reopen prepared F7 claim")?;
        let stranger = store.acquire_lease(digest(9), digest(21), 12_000, 10_000)?;
        let before =
            final_claim_v2_state_snapshot(&store, bound).test_context("audit prepared F7 claim")?;
        assert!(matches!(
            store.f7_claim_previous_authorization_v21(stranger, scope, evidence, 12_001),
            Err(DomActuatorError::ReconciliationRequired)
        ));
        assert_eq!(final_claim_v2_state_snapshot(&store, bound)?, before);
        Ok(())
    }
}
