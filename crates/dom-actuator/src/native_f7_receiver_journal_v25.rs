//! Receiver-only historical observation receipts. No signing/exposure attempt
//! or admission is created. Fresh canonicality remains a separate requirement.
use super::*;

fn receiver_evidence_v25(scope: ScopedDomActionV1, tx: Digest32) -> Digest32 {
    hash_parts(&[
        b"DOM:actuator-f7-receiver-observation:v25",
        &scope_digest(scope),
        &tx,
    ])
}

pub(super) fn receiver_operation_matches_v25(
    scope: ScopedDomActionV1,
    tx: Digest32,
    operation: &StoredOperation,
) -> bool {
    scope.action() == DomActionV1::BroadcastClaim
        && tx != [0; 32]
        && operation.scope_digest == scope_digest(scope)
        && operation.status == OP_COMPLETED
        && operation.secret_binding_digest.is_none()
        && operation.receipt_digest == Some(tx)
        && operation.evidence_digest == receiver_evidence_v25(scope, tx)
        && operation.authorization_digest
            == authorization_digest(
                operation.scope_digest,
                operation.evidence_digest,
                None,
                operation.fencing_epoch,
            )
}

pub(super) fn receiver_transaction_v25(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
) -> DomActuatorResult<Option<Digest32>> {
    let mut statement = transaction
        .prepare(
            "SELECT effect_id,receipt_digest FROM dom_operations
         WHERE session_id=?1 AND participant_id=?2 AND action_tag=?3 AND status_tag=1",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(
            params![
                binding.session_id().as_slice(),
                binding.participant().participant_id().as_slice(),
                i64::from(DomActionV1::BroadcastClaim.tag())
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .map_err(storage)?;
    let mut found = None;
    for row in rows {
        let (effect, receipt) = row.map_err(storage)?;
        let Some(receipt) = receipt else { continue };
        let effect = blob32(effect)?;
        let tx = blob32(receipt)?;
        let scope = ScopedDomActionV1::new(binding, effect, DomActionV1::BroadcastClaim)?;
        let operation =
            load_operation(transaction, effect)?.ok_or(DomActuatorError::UnsupportedFormat)?;
        if receiver_operation_matches_v25(scope, tx, &operation) {
            if found.replace(tx).is_some() {
                return Err(DomActuatorError::UnsupportedFormat);
            }
        }
    }
    Ok(found)
}

// Only finality/reorg persistence and their reopen audit use this identity.
// Sender custody and submission methods keep their separate attempt checks.
pub(super) fn require_terminal_claim_identity_v25(
    transaction: &Transaction<'_>,
    binding: DomSessionBindingV1,
    tx: Digest32,
) -> DomActuatorResult<()> {
    if let Some(observed) = receiver_transaction_v25(transaction, binding)? {
        if observed != tx
            || load_final_claim_attempt_v2(transaction, binding.session_id())?.is_some()
            || load_claim_custody(transaction, binding.session_id())?.is_some()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        return Ok(());
    }
    require_exposed_claim_identity(transaction, binding, tx)
}

impl DomActuatorStoreV1 {
    // The facade must reauthenticate the exact observation from its bound
    // Contracts Store immediately before calling. This receipt grants no send
    // permission: sender APIs still require their distinct native authority.
    pub(crate) fn retain_f7_receiver_claim_v25(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        observed: &dom_scriptless_store::ObservedF7FinalClaimV15,
        now: u64,
    ) -> DomActuatorResult<()> {
        if observed.session_id() != scope.binding().session_id()
            || observed.chain_id() != scope.binding().chain_id()
            || observed.receiver_id() != scope.binding().participant().participant_id()
            || observed.observation_digest() == [0; 32]
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        self.retain_receiver_receipt_v25(lease, scope, observed.tx_hash(), now)
    }

    // Private journal primitive; production callers arrive only through the
    // Store-minted receiver observation above. Tests use synthetic identities
    // solely to exercise persistence, not to simulate chain verification.
    fn retain_receiver_receipt_v25(
        &mut self,
        lease: DomLeaseV1,
        scope: ScopedDomActionV1,
        tx: Digest32,
        now: u64,
    ) -> DomActuatorResult<()> {
        validate_digest(tx)?;
        if scope.action() != DomActionV1::BroadcastClaim {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now)?;
        require_scope(&transaction, lease, scope)?;
        let session = scope.binding().session_id();
        if load_final_claim_attempt_v2(&transaction, session)?.is_some()
            || load_claim_custody(&transaction, session)?.is_some()
        {
            return Err(DomActuatorError::CapabilityMismatch);
        }
        if let Some(old) = load_operation(&transaction, scope.effect_id())? {
            if !receiver_operation_matches_v25(scope, tx, &old)
                || old.fencing_epoch > lease.fencing_epoch
            {
                return Err(DomActuatorError::IdempotencyConflict);
            }
            // Read-only replay retains the original receipt and authorization;
            // no new broadcast capability is minted for the new lease.
            return transaction.commit().map_err(storage);
        }
        let stage = load_stage(&transaction, session)?;
        if !matches!(stage, STAGE_FUNDING_CONFIRMED | STAGE_CLAIM_PREPARED) {
            return Err(DomActuatorError::InvalidStage);
        }
        let scope_hash = scope_digest(scope);
        let evidence = receiver_evidence_v25(scope, tx);
        let authorization = authorization_digest(scope_hash, evidence, None, lease.fencing_epoch);
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
                    session.as_slice(),
                    scope.binding().participant().participant_id().as_slice(),
                    i64::from(scope.action().tag()),
                    to_sql(lease.fencing_epoch)?,
                    scope_hash.as_slice(),
                    evidence.as_slice(),
                    authorization.as_slice(),
                    tx.as_slice(),
                    to_sql(now)?
                ],
            )
            .map_err(storage)?;
        append_event(
            &transaction,
            session,
            scope.effect_id(),
            evidence,
            STAGE_CLAIM_BROADCAST,
            lease.fencing_epoch,
            now,
        )?;
        transaction.commit().map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{advance_to_funding_confirmed, binding, setup, TestResult};
    use super::*;

    #[test]
    #[ignore = "requires private archived Contracts and control copy in DOM_XMR_CLAIM_REPLAY_V25"]
    fn archived_receiver_facade_waits_without_sender_authority() -> TestResult {
        let root = std::path::PathBuf::from(std::env::var("DOM_XMR_CLAIM_REPLAY_V25")?);
        let mut control = DomActuatorStoreV1::open_existing(&root.join("control.sqlite"))?;
        let binding = {
            let transaction = control.immediate()?;
            load_binding(&transaction, [0xd1; 32])?.ok_or("missing archived binding")?
        };
        let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
            binding.runtime_identity().network_magic,
            &dom_crypto::Hash256::from_bytes(binding.genesis_hash()),
        );
        let contracts =
            dom_scriptless_store::ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
                std::sync::Arc::new(cap_std::fs::Dir::open_ambient_dir(
                    &root,
                    cap_std::ambient_authority(),
                )?),
                "contracts",
                dom_scriptless_store::BudgetPolicyV1::from_bytes(&std::fs::read(
                    root.join("budget.bin"),
                )?)?,
                chain,
            )?;
        let before = contracts
            .load_session(binding.session_id())?
            .as_bytes()
            .to_vec();
        let facade = crate::DomContractsActuatorV1::bind(&contracts, binding)?;
        assert!(matches!(
            facade.f7_receiver_observation_v25(&chain),
            Err(DomActuatorError::ContractsAuthorityUnavailable)
        ));
        assert!(facade.f7_final_claim_progress_v21(&chain).is_err());
        assert_eq!(
            before,
            contracts.load_session(binding.session_id())?.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn receiver_receipt_reopens_without_sender_attempt_and_rejects_other_tx() -> TestResult {
        let (_directory, path, mut store, lease) = setup()?;
        let binding = binding(1, 2)?;
        store.bind_session(lease, binding, 1_001)?;
        advance_to_funding_confirmed(&mut store, lease, binding)?;
        let scope = ScopedDomActionV1::new(binding, [180; 32], DomActionV1::BroadcastClaim)?;
        let tx = [181; 32];
        store.retain_receiver_receipt_v25(lease, scope, tx, 2_000)?;
        let request = DomSettlementChildBindingRequestV1::new(
            scope,
            [182; 32],
            binding.deployment_digest(),
            [183; 32],
            [184; 32],
            DomSettlementChildExposureV1::FirstSecretExposure,
        )?;
        let child =
            store.persist_authenticated_settlement_child_binding(lease, request, tx, 2_001)?;
        assert!(store
            .audit_final_claim_custody_v2(lease, binding, 2_001)
            .is_err());
        assert!(store
            .retain_receiver_receipt_v25(lease, scope, [185; 32], 2_002)
            .is_err());
        drop(store);
        let mut store = DomActuatorStoreV1::open_existing(&path)?;
        store.retain_receiver_receipt_v25(lease, scope, tx, 2_003)?;
        let resumed = store.settlement_child_binding(lease, request.custody_digest(), 2_004)?;
        assert_eq!(resumed.transaction_id(), tx);
        assert_eq!(resumed.locator(), child.locator());
        use super::super::tests::finality_record;
        let checkpoint = vec![0x51; 606];
        assert!(store
            .record_terminal_finality(
                lease,
                binding,
                finality_record(DomTerminalKindV1::Claim, [186; 32], &checkpoint),
                2_005
            )
            .is_err());
        store.record_terminal_finality(
            lease,
            binding,
            finality_record(DomTerminalKindV1::Claim, tx, &checkpoint),
            2_006,
        )?;
        drop(store);
        let mut store = DomActuatorStoreV1::open_existing(&path)?;
        store.record_terminal_reorg(
            lease,
            binding,
            DomTerminalReorgRecordV1 {
                kind: DomTerminalKindV1::Claim,
                tx_hash: tx,
                prior_evidence_digest: [132; 32],
                current_tip_height: 12,
                current_tip_hash: [140; 32],
                common_ancestor_height: 7,
                removed_depth: 3,
                minimum_confirmations: 2,
                max_reorg_depth: 10,
                evidence_digest: [141; 32],
            },
            2_007,
        )?;
        let refund = ScopedDomActionV1::new(binding, [187; 32], DomActionV1::BroadcastRefund)?;
        assert!(store
            .authorize_action(lease, refund, [188; 32], None, 2_008)
            .is_err());
        drop(store);
        let mut store = DomActuatorStoreV1::open_existing(&path)?;
        let lease = store.acquire_lease([9; 32], [20; 32], 12_000, 10_000)?;
        store.retain_receiver_receipt_v25(lease, scope, tx, 12_001)?;
        assert_eq!(
            store
                .settlement_child_binding(lease, request.custody_digest(), 12_002)?
                .locator(),
            child.locator()
        );

        assert!(store
            .audit_final_claim_custody_v2(lease, binding, 12_003)
            .is_err());
        Ok(())
    }
}
