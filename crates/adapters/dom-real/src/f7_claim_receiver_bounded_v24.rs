//! Incremental F7 Claim discovery through the physical authenticated DOM client.
//! A cached prefix is never a claim/absence/finality token. Every result closes
//! ancestry at a fresh, rechecked tip and re-verifies the original adaptor proof.
use super::*;
use dom_scriptless_chain_adapter::ScriptlessScanPageV1;

const MAX_CLAIM_SCOPES_V24: usize = 4;
const MAX_CLAIM_SCAN_BUDGET_V24: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct F7ClaimScanProgressV24 {
    state: CursorStateV1,
    candidate: Option<CanonicalTransactionEvidenceV1>,
    touched_at: Instant,
}

impl F7ClaimScanProgressV24 {
    fn new(now: Instant) -> Self {
        Self {
            state: CursorStateV1::genesis(),
            candidate: None,
            touched_at: now,
        }
    }
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

fn reserve_scope(
    cache: &mut BTreeMap<[u8; 32], F7ClaimScanProgressV24>,
    scope: [u8; 32],
    now: Instant,
) {
    if !cache.contains_key(&scope) && cache.len() >= MAX_CLAIM_SCOPES_V24 {
        if let Some(evicted) = cache
            .iter()
            .min_by_key(|(_, progress)| progress.touched_at)
            .map(|(key, _)| *key)
        {
            cache.remove(&evicted);
        }
    }
    cache
        .entry(scope)
        .or_insert_with(|| F7ClaimScanProgressV24::new(now))
        .touched_at = now;
}

impl RealDomRpcRuntimeV1 {
    /// Discover the original F7 Claim within one monotonic budget (at most
    /// 60 s). Each HTTP read uses the original remaining deadline; no worker is
    /// spawned and no timed-out task continues scanning in the background.
    /// Bounded synchronous page/proof validation is never bypassed or forcibly
    /// interrupted; a result finishing after the deadline is refused.
    ///
    /// At most four exact scopes retain an authenticated prefix and one public
    /// transaction. Timeouts return Unavailable, never absence or partial proof.
    /// Reorgs discard the prefix and require a new genesis-anchored scan.
    pub fn find_f7_final_claim_until_v24(
        &self,
        facts: &F7ClaimObserverFactsV15,
        deadline: Instant,
    ) -> Result<Option<VerifiedDomClaimObservationV1>, RealDomError> {
        require_live(deadline)?;
        if deadline.saturating_duration_since(Instant::now()) > MAX_CLAIM_SCAN_BUDGET_V24 {
            return Err(unavailable());
        }
        if self.adapter.expected_identity().chain_id != facts.chain_id()
            || facts.minimum_confirmations() == 0
        {
            return Err(RealDomError::InvalidEvidence);
        }
        // The cache only selects public bytes; every call below independently
        // verifies all supplied signing/adaptor facts against those bytes.
        let scope = digest_parts(
            b"DOM/F7-CLAIM-DISCOVERY/V24\0",
            &[
                &facts.chain_id(),
                &facts.session_id(),
                &facts.receiver_id(),
                &facts.shared_commitment(),
                &facts.template_hash(),
                &facts.minimum_confirmations().to_be_bytes(),
            ],
        );
        let (candidate, identity) = self.scan_f7_claim_until_v24(
            scope,
            facts.shared_commitment(),
            facts.template_hash(),
            deadline,
        )?;
        require_live(deadline)?;
        let observed = candidate
            .map(|transaction| {
                verify_f7_observation_v15(
                    facts,
                    &ProvedClaimObservationEvidenceV1::sealed(
                        transaction,
                        identity.tip_height,
                        identity.tip_hash,
                    ),
                )
            })
            .transpose()?;
        require_live(deadline)?;
        Ok(observed)
    }

    fn scan_f7_claim_until_v24(
        &self,
        scope: [u8; 32],
        commitment: [u8; 33],
        template: [u8; 32],
        deadline: Instant,
    ) -> Result<
        (
            Option<CanonicalTransactionEvidenceV1>,
            ObservedDomIdentityV1,
        ),
        RealDomError,
    > {
        require_live(deadline)?;
        let mut cache = self
            .f7_claim_scan_v24
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => unavailable(),
                std::sync::TryLockError::Poisoned(_) => RealDomError::LockPoisoned,
            })?;
        reserve_scope(&mut cache, scope, Instant::now());
        let progress = cache.get_mut(&scope).ok_or(RealDomError::InvalidEvidence)?;
        let result = scan_pages_until(
            progress,
            commitment,
            template,
            self.history_limit,
            deadline,
            |cursor, blocks, until| {
                self.adapter
                    .scan_page_until_v23(cursor, blocks, until)
                    .map_err(RealDomError::Chain)
            },
        );
        match result {
            Ok(identity) => Ok((progress.candidate.clone(), identity)),
            Err(RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)) => {
                Err(unavailable())
            }
            Err(RealDomError::Chain(ChainAdapterError::ReorgDetected)) => {
                cache.remove(&scope);
                Err(unavailable())
            }
            Err(error) => {
                cache.remove(&scope);
                Err(error)
            }
        }
    }
}

// Only the real adapter supplies pages in production. Keeping this traversal
// separate allows tests to inspect deadline/cursor sequencing without minting
// opaque transaction, signature, Claim or finality capabilities.
fn scan_pages_until(
    progress: &mut F7ClaimScanProgressV24,
    commitment: [u8; 33],
    template: [u8; 32],
    history_limit: usize,
    deadline: Instant,
    mut read_page: impl FnMut(
        ScriptlessScanCursorV1,
        u64,
        Instant,
    ) -> Result<ScriptlessScanPageV1, RealDomError>,
) -> Result<ObservedDomIdentityV1, RealDomError> {
    for _ in 0..MAX_SNAPSHOT_SCAN_PAGES {
        require_live(deadline)?;
        let page = read_page(
            progress.state.scanner_cursor(),
            MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
            deadline,
        )?;
        require_live(deadline)?;
        let mut next = progress.clone();
        for block in &page.blocks {
            require_live(deadline)?;
            next.state
                .append(block.height, block.block_hash, history_limit)?;
            for transaction in &block.transactions {
                require_live(deadline)?;
                if transaction.spends_commitment(&commitment)
                    && transaction.template_hash()? == template
                {
                    // Reject a duplicate even if its serialized bytes match.
                    if next.candidate.is_some() {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    next.candidate = Some(transaction.clone());
                }
            }
        }
        if next.state.scanner_cursor() != page.next_cursor {
            return Err(RealDomError::InvalidEvidence);
        }
        let advanced = next.state.next_height != progress.state.next_height;
        require_live(deadline)?;
        *progress = next;
        if page.reached_snapshot_tip {
            if progress.state.history.last().copied()
                != Some((page.identity.tip_height, page.identity.tip_hash))
            {
                return Err(RealDomError::InvalidEvidence);
            }
            let recheck = read_page(progress.state.scanner_cursor(), 1, deadline)?;
            require_live(deadline)?;
            if recheck.identity != page.identity
                || !recheck.blocks.is_empty()
                || recheck.next_cursor != progress.state.scanner_cursor()
                || !recheck.reached_snapshot_tip
            {
                // Concurrent chain growth is not proof of absence, nor a
                // permanent protocol error. Reauthenticate this prefix next tick.
                return Err(unavailable());
            }
            return Ok(page.identity);
        }
        if !advanced {
            return Err(unavailable());
        }
    }
    Err(unavailable())
}

#[cfg(test)]
#[path = "f7_claim_receiver_bounded_v24_tests.rs"]
mod tests;
