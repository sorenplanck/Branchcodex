//! Resumable canonical walks for exact transactions and terminal checkpoints.
//! A retained cursor is only work already verified, never current evidence.
//! Each result reauthenticates its anchor and closes twice at the same tip.
use super::*;

// Two route legs, each with funding/claim/refund, can use both anchored
// and resolve references plus a terminal reorg checkpoint: 18 concurrent
// scopes before replacement checkpoints. Leave bounded room for those
// replacements so the ordinary route does not evict unfinished walks.
const MAX_CANONICAL_SCOPES_V27: usize = 32;

pub(super) struct CanonicalScanProgressV27 {
    state: CursorStateV1,
    transaction: Option<CanonicalTransactionEvidenceV1>,
    transaction_time: Option<u64>,
    tip_time: Option<u64>,
    required_blocks: BTreeMap<u64, ([u8; 32], u64)>,
    touched_at: Instant,
}

impl CanonicalScanProgressV27 {
    fn new(now: Instant) -> Self {
        Self {
            state: CursorStateV1::genesis(),
            transaction: None,
            transaction_time: None,
            tip_time: None,
            required_blocks: BTreeMap::new(),
            touched_at: now,
        }
    }
}

pub(super) struct CanonicalScanSnapshotV27 {
    pub(super) state: CursorStateV1,
    pub(super) identity: ObservedDomIdentityV1,
    pub(super) transaction: Option<CanonicalTransactionEvidenceV1>,
    pub(super) transaction_time: Option<u64>,
    pub(super) required_blocks: BTreeMap<u64, ([u8; 32], u64)>,
}

fn unavailable() -> RealDomError {
    ChainAdapterError::TemporarilyUnavailable.into()
}

fn require_live(deadline: Instant) -> Result<(), RealDomError> {
    if Instant::now() >= deadline {
        return Err(unavailable());
    }
    Ok(())
}

impl RealDomRpcRuntimeV1 {
    /// Resolve one exact reference from its own authenticated, resumable walk.
    /// All location fields scope the cache; a changed reference cannot borrow
    /// a prefix or candidate from a different request.
    pub(super) fn transaction_snapshot_until_v27(
        &self,
        evidence: &EvidenceRefV1,
        deadline: Instant,
    ) -> Result<CanonicalScanSnapshotV27, RealDomError> {
        let resolve = self.validate_evidence_scope(evidence)?;
        let selector = digest_parts(
            b"DOM/CANONICAL-TRANSACTION-REFERENCE/V27\0",
            &[
                &evidence.chain_id.0,
                &evidence.tx_id,
                &evidence.event_index.to_be_bytes(),
                &evidence.block_height.to_be_bytes(),
                &evidence.block_anchor,
            ],
        );
        let mut snapshot =
            self.canonical_scan_until_v27(selector, evidence.tx_id, &[], deadline)?;
        let transaction = snapshot
            .transaction
            .take()
            .ok_or(RealDomError::EvidenceNotFound)?;
        if transaction.tx_hash() != evidence.tx_id || snapshot.transaction_time.is_none() {
            return Err(RealDomError::InvalidEvidence);
        }
        snapshot.transaction = Some(if resolve {
            transaction
        } else {
            validate_evidence_reference(evidence, transaction)?
        });
        require_live(deadline)?;
        Ok(snapshot)
    }

    /// Keep only one candidate and the checkpoint heights requested by this
    /// scope. The bounded canonical tail lives in `CursorStateV1`; no global
    /// transaction cache is used as an ancestry or absence proof.
    pub(super) fn canonical_scan_until_v27(
        &self,
        selector: [u8; 32],
        expected_transaction: [u8; 32],
        required_heights: &[u64],
        deadline: Instant,
    ) -> Result<CanonicalScanSnapshotV27, RealDomError> {
        require_live(deadline)?;
        if selector == [0; 32]
            || expected_transaction == [0; 32]
            || required_heights.len() > MAX_CURSOR_HISTORY + 1
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let mut heights = required_heights.to_vec();
        heights.sort_unstable();
        heights.dedup();
        let mut encoded_heights = Vec::with_capacity(heights.len() * 8);
        for height in &heights {
            encoded_heights.extend_from_slice(&height.to_be_bytes());
        }
        let scope = digest_parts(
            b"DOM/CANONICAL-SCAN/V27\0",
            &[
                &self.adapter.expected_identity().chain_id,
                &selector,
                &expected_transaction,
                &encoded_heights,
            ],
        );
        let mut cache = self
            .canonical_scan_v27
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => unavailable(),
                std::sync::TryLockError::Poisoned(_) => RealDomError::LockPoisoned,
            })?;
        if !cache.contains_key(&scope) && cache.len() >= MAX_CANONICAL_SCOPES_V27 {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, progress)| progress.touched_at)
                .map(|(key, _)| *key)
            {
                cache.remove(&oldest);
            }
        }
        let progress = cache
            .entry(scope)
            .or_insert_with(|| CanonicalScanProgressV27::new(Instant::now()));
        progress.touched_at = Instant::now();
        let result =
            self.continue_canonical_scan_v27(progress, expected_transaction, &heights, deadline);
        match result {
            // The next request starts from genesis, never from an orphaned
            // prefix. A moving chain is a reason to retry, not corruption.
            Err(RealDomError::Chain(ChainAdapterError::ReorgDetected)) => {
                cache.remove(&scope);
                Err(unavailable())
            }
            // Only an authenticated prefix survives budget/network refusal.
            Err(error @ RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)) => {
                Err(error)
            }
            Err(error) => {
                cache.remove(&scope);
                Err(error)
            }
            Ok(snapshot) => Ok(snapshot),
        }
    }

    fn continue_canonical_scan_v27(
        &self,
        progress: &mut CanonicalScanProgressV27,
        expected_transaction: [u8; 32],
        required_heights: &[u64],
        deadline: Instant,
    ) -> Result<CanonicalScanSnapshotV27, RealDomError> {
        let mut completed_tip = None;
        for _ in 0..MAX_SNAPSHOT_SCAN_PAGES {
            require_live(deadline)?;
            // The cursor carries the previous block hash. Even an empty page
            // rechecks this retained anchor against the currently canonical
            // chain before any candidate or absence can be returned.
            let page = self.adapter.scan_page_until_v23(
                progress.state.scanner_cursor(),
                MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
                deadline,
            )?;
            let mut state = progress.state.clone();
            let mut candidate = progress.transaction.clone();
            let mut candidate_time = progress.transaction_time;
            let mut tip_time = progress.tip_time;
            let mut required_blocks = progress.required_blocks.clone();
            for block in &page.blocks {
                require_live(deadline)?;
                state.append(block.height, block.block_hash, self.history_limit)?;
                tip_time = Some(block.timestamp);
                if required_heights.binary_search(&block.height).is_ok() {
                    required_blocks.insert(block.height, (block.block_hash, block.timestamp));
                }
                for transaction in &block.transactions {
                    require_live(deadline)?;
                    if transaction.tx_hash() == expected_transaction {
                        if candidate.is_some() {
                            return Err(RealDomError::InvalidEvidence);
                        }
                        candidate = Some(transaction.clone());
                        candidate_time = Some(block.timestamp);
                        required_blocks.insert(block.height, (block.block_hash, block.timestamp));
                    }
                }
            }
            if state.scanner_cursor() != page.next_cursor {
                return Err(RealDomError::InvalidEvidence);
            }
            let advanced = state.next_height != progress.state.next_height;
            require_live(deadline)?;
            progress.state = state;
            progress.transaction = candidate;
            progress.transaction_time = candidate_time;
            progress.tip_time = tip_time;
            progress.required_blocks = required_blocks;
            if page.reached_snapshot_tip {
                let tip = (page.identity.tip_height, page.identity.tip_hash);
                if progress.state.history.last().copied() != Some(tip) {
                    return Err(RealDomError::InvalidEvidence);
                }
                if completed_tip.as_ref() == Some(&page.identity) && !advanced {
                    let mut required_blocks = progress.required_blocks.clone();
                    required_blocks.entry(tip.0).or_insert((
                        tip.1,
                        progress.tip_time.ok_or(RealDomError::InvalidEvidence)?,
                    ));
                    require_live(deadline)?;
                    return Ok(CanonicalScanSnapshotV27 {
                        state: progress.state.clone(),
                        identity: page.identity,
                        transaction: progress.transaction.clone(),
                        transaction_time: progress.transaction_time,
                        required_blocks,
                    });
                }
                completed_tip = Some(page.identity.clone());
            } else {
                completed_tip = None;
                if !advanced {
                    return Err(unavailable());
                }
            }
        }
        Err(unavailable())
    }
}
