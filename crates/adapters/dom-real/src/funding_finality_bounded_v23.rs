//! Incremental, bounded funding reconciliation. A retained prefix is never
//! evidence: each grant requires a new anchor check and a complete canonical
//! walk through the same rechecked tip. Cache holds at most four exact scopes.
use super::*;

const MAX_FUNDING_SCOPES_V23: usize = 4;

pub(crate) struct FundingFinalityScanV23 {
    state: CursorStateV1,
    transaction: Option<CanonicalTransactionEvidenceV1>,
    block_time_seconds: Option<u64>,
    touched_at: Instant,
}

impl FundingFinalityScanV23 {
    fn new(now: Instant) -> Self {
        Self {
            state: CursorStateV1::genesis(),
            transaction: None,
            block_time_seconds: None,
            touched_at: now,
        }
    }
}

fn require_live(deadline: Instant) -> Result<(), RealDomError> {
    if Instant::now() >= deadline {
        return Err(ChainAdapterError::TemporarilyUnavailable.into());
    }
    Ok(())
}

fn reserve_scope(
    cache: &mut BTreeMap<[u8; 32], FundingFinalityScanV23>,
    scope: [u8; 32],
    now: Instant,
) {
    if !cache.contains_key(&scope) && cache.len() >= MAX_FUNDING_SCOPES_V23 {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.touched_at)
            .map(|(key, _)| *key)
        {
            cache.remove(&oldest);
        }
    }
    cache
        .entry(scope)
        .or_insert_with(|| FundingFinalityScanV23::new(now))
        .touched_at = now;
}

impl RealDomRpcRuntimeV1 {
    /// Resolve exact funding under the original caller deadline. Timeouts keep
    /// only an authenticated scan prefix, never a partial or stale finality grant.
    /// No transaction is submitted by this observation-only method.
    #[allow(clippy::too_many_arguments)]
    pub fn verified_funding_finality_until_v23(
        &self,
        evidence: &EvidenceRefV1,
        expected_tx_hash: [u8; 32],
        expected_shared_output_commitment: [u8; 33],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
        deadline: Instant,
    ) -> Result<VerifiedDomFundingFinalityV1, RealDomError> {
        require_live(deadline)?;
        validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
        let resolve_mode = self.validate_evidence_scope(evidence)?;
        if evidence.tx_id != expected_tx_hash
            || expected_tx_hash == [0; 32]
            || expected_shared_output_commitment == [0; 33]
            || self.history_limit
                < usize::try_from(max_reorg_depth)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or(RealDomError::FinalityPolicyInvalid)?
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let scope = digest_parts(
            b"DOM/FUNDING-RECONCILE-SCAN/V23\0",
            &[
                &self.adapter.expected_identity().chain_id,
                &expected_tx_hash,
                &expected_shared_output_commitment,
                &minimum_confirmations.to_be_bytes(),
                &max_reorg_depth.to_be_bytes(),
            ],
        );
        let mut cache = self
            .funding_finality_scan_v23
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
                }
                std::sync::TryLockError::Poisoned(_) => RealDomError::LockPoisoned,
            })?;
        reserve_scope(&mut cache, scope, Instant::now());
        let progress = cache.get_mut(&scope).ok_or(RealDomError::InvalidEvidence)?;
        let snapshot = self.scan_funding_until_v23(progress, expected_tx_hash, deadline);
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(RealDomError::Chain(ChainAdapterError::ReorgDetected)) => {
                cache.remove(&scope);
                return Err(ChainAdapterError::TemporarilyUnavailable.into());
            }
            Err(
                error @ (RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
                | RealDomError::EvidenceNotFound),
            ) => return Err(error),
            Err(error) => {
                cache.remove(&scope);
                return Err(error);
            }
        };
        drop(cache);
        if !resolve_mode {
            validate_evidence_reference(evidence, snapshot.transaction.clone())?;
        }
        let finality = self.funding_finality_from_snapshot_v23(
            snapshot,
            expected_tx_hash,
            expected_shared_output_commitment,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        require_live(deadline)?;
        Ok(finality)
    }

    fn scan_funding_until_v23(
        &self,
        progress: &mut FundingFinalityScanV23,
        expected_tx_hash: [u8; 32],
        deadline: Instant,
    ) -> Result<CanonicalTerminalSnapshotV1, RealDomError> {
        let mut completed_tip = None;
        for _ in 0..MAX_SNAPSHOT_SCAN_PAGES {
            require_live(deadline)?;
            let page = self.adapter.scan_page_until_v23(
                progress.state.scanner_cursor(),
                MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
                deadline,
            )?;
            let mut next = progress.state.clone();
            let mut transaction_on_page = progress.transaction.clone();
            let mut transaction_time = progress.block_time_seconds;
            for block in &page.blocks {
                require_live(deadline)?;
                next.append(block.height, block.block_hash, self.history_limit)?;
                for transaction in &block.transactions {
                    if transaction.tx_hash() == expected_tx_hash {
                        // The same transaction cannot appear twice on the one
                        // canonical branch, even with identical serialized bytes.
                        if transaction_on_page.is_some() {
                            return Err(RealDomError::InvalidEvidence);
                        }
                        transaction_on_page = Some(transaction.clone());
                        transaction_time = Some(block.timestamp);
                    }
                }
            }
            if next.scanner_cursor() != page.next_cursor {
                return Err(RealDomError::InvalidEvidence);
            }
            let advanced = next.next_height != progress.state.next_height;
            progress.state = next;
            progress.transaction = transaction_on_page;
            progress.block_time_seconds = transaction_time;
            if progress.state.next_height > page.identity.tip_height {
                let tip = (page.identity.tip_height, page.identity.tip_hash);
                if progress.state.history.last().copied() != Some(tip) {
                    return Err(RealDomError::InvalidEvidence);
                }
                if completed_tip == Some(tip) && !advanced {
                    require_live(deadline)?;
                    return Ok(CanonicalTerminalSnapshotV1 {
                        transaction: progress
                            .transaction
                            .clone()
                            .ok_or(RealDomError::EvidenceNotFound)?,
                        state: progress.state.clone(),
                        identity: page.identity,
                        block_time_seconds: progress
                            .block_time_seconds
                            .ok_or(RealDomError::InvalidEvidence)?,
                    });
                }
                completed_tip = Some(tip);
            } else {
                completed_tip = None;
                if !advanced {
                    return Err(ChainAdapterError::TemporarilyUnavailable.into());
                }
            }
        }
        Err(ChainAdapterError::TemporarilyUnavailable.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn funding_scan_cache_evicts_old_scope_and_never_invents_a_transaction_v23() {
        let mut cache = BTreeMap::new();
        let now = Instant::now();
        for tag in 1..=8 {
            reserve_scope(
                &mut cache,
                [tag; 32],
                now + Duration::from_millis(u64::from(tag)),
            );
            assert!(cache.len() <= MAX_FUNDING_SCOPES_V23);
        }
        assert!(!cache.contains_key(&[1; 32]));
        assert!(cache.contains_key(&[8; 32]));
        assert!(cache
            .values()
            .all(|entry| entry.transaction.is_none() && entry.state.next_height == 0));
    }

    #[test]
    fn funding_scan_expired_budget_never_yields_authority_v23() {
        assert!(matches!(
            require_live(Instant::now()),
            Err(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable
            ))
        ));
    }
}
