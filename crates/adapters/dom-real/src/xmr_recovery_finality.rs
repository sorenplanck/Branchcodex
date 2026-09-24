//! Native DOM observation of the C -> D XMR recovery graph. Every outcome is
//! derived from a complete bounded canonical scan, including conflicting spends.

use super::*;
use dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11;

#[path = "xmr_refund_reorg_v23.rs"]
mod refund_reorg_v23;
pub use refund_reorg_v23::{VerifiedDomXmrRefundReorgV23, VerifiedDomXmrRefundRevalidationV23};

#[cfg(test)]
mod tests;

/// Public finality facts minted only by a complete canonical graph observation.
/// Persistable bytes are an audit checkpoint; they cannot recreate this token.
pub struct VerifiedDomXmrRecoveryFinalityV11 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    graph_digest: [u8; 32],
    funding_tx_hash: [u8; 32],
    cancel_tx_hash: Option<[u8; 32]>,
    transaction_hash: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    transaction_index: u32,
    tip_height: u64,
    tip_hash: [u8; 32],
    confirmation_depth: u32,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    evidence_digest: [u8; 32],
    checkpoint_bytes: Vec<u8>,
    observed_at: std::time::Instant,
}
impl VerifiedDomXmrRecoveryFinalityV11 {
    /// Authenticated DOM chain identity.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }
    /// Exact native contract session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }
    /// Signed negotiated terms digest.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.terms_hash
    }
    /// Exact native recovery graph digest.
    pub const fn graph_digest(&self) -> [u8; 32] {
        self.graph_digest
    }
    /// Actual canonical funding transaction creating C.
    pub const fn funding_tx_hash(&self) -> [u8; 32] {
        self.funding_tx_hash
    }
    /// Canonical cancel, absent only while C is still unspent collateral.
    pub const fn cancel_tx_hash(&self) -> Option<[u8; 32]> {
        self.cancel_tx_hash
    }
    /// Exact observed event transaction identity.
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical event inclusion height.
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }
    /// Canonical event containing block.
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }
    /// Event's position in its containing block.
    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }
    /// Freshly walked snapshot tip height.
    pub const fn observed_tip_height(&self) -> u64 {
        self.tip_height
    }
    /// Freshly walked snapshot tip identifier.
    pub const fn observed_tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }
    /// Actual depth, including the event block.
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }
    /// Frozen minimum confirmation requirement.
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }
    /// Frozen bounded reorganization policy.
    pub const fn max_reorg_depth(&self) -> u32 {
        self.max_reorg_depth
    }
    /// Domain-separated digest of scope, graph, locations and canonical tail.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }
    /// Public audit checkpoint. Reopening it never authorizes an operation;
    /// the actual scanner must observe and revalidate the graph again.
    pub fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint_bytes
    }
}

/// Native confirmed C exists and is unspent on the freshly walked snapshot.
/// Economic values and signed participant admission remain separate checks.
pub struct VerifiedDomXmrCollateralV11 {
    finality: VerifiedDomXmrRecoveryFinalityV11,
}
impl VerifiedDomXmrCollateralV11 {
    /// Exact collateral finality and scope.
    pub const fn finality(&self) -> &VerifiedDomXmrRecoveryFinalityV11 {
        &self.finality
    }
}

/// Exact cancel is canonical and D has no canonical spend at the observed tip.
/// This is observation evidence; it does not grant a refund/punish broadcast.
pub struct VerifiedDomXmrCancellationV11 {
    finality: VerifiedDomXmrRecoveryFinalityV11,
}
impl VerifiedDomXmrCancellationV11 {
    /// Exact cancel finality and scope.
    pub const fn finality(&self) -> &VerifiedDomXmrRecoveryFinalityV11 {
        &self.finality
    }
}

/// U extracted only from the unique, canonical, final D -> refund transaction.
/// No public scalar constructor, Clone, Debug or Deserialize is implemented.
pub struct VerifiedDomRefundSecretV11 {
    scalar: zeroize::Zeroizing<[u8; 32]>,
    template_hash: [u8; 32],
    refund_point: [u8; 33],
    finality: VerifiedDomXmrRecoveryFinalityV11,
}
impl VerifiedDomRefundSecretV11 {
    /// Require a live canonical observation at a productive consumer boundary.
    /// Persisted checkpoint bytes cannot recreate this monotonic freshness.
    pub fn require_recent_v23(&self) -> Result<(), RealDomError> {
        if self.finality.observed_at.elapsed() > std::time::Duration::from_secs(30) {
            return Err(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable,
            ));
        }
        Ok(())
    }

    /// Exact native session of the observed refund.
    pub const fn session_id(&self) -> [u8; 32] {
        self.finality.session_id
    }
    /// Canonical native DOM chain.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.finality.chain_id
    }
    /// Native signature-omitting refund template hash.
    pub const fn template_hash(&self) -> [u8; 32] {
        self.template_hash
    }
    /// Verified refund witness point U.
    pub const fn refund_point(&self) -> [u8; 33] {
        self.refund_point
    }
    /// Complete canonical graph ancestry and finality.
    pub const fn finality(&self) -> &VerifiedDomXmrRecoveryFinalityV11 {
        &self.finality
    }
    /// Closure-only access for the authenticated cross-curve share recovery.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.scalar)
    }
}

/// Canonical plain punish pays DOM compensation. This is a distinct economic
/// outcome: it contains neither T nor U and does not assert any XMR refund.
pub struct VerifiedDomCompensationObservationV11 {
    finality: VerifiedDomXmrRecoveryFinalityV11,
    canonical_transaction_v22: Vec<u8>,
}
impl VerifiedDomCompensationObservationV11 {
    /// Exact public transaction authenticated at the containing block.
    pub fn canonical_transaction_v22(&self) -> &[u8] {
        &self.canonical_transaction_v22
    }
    /// Exact DOM compensation finality and negotiated graph scope.
    pub const fn finality(&self) -> &VerifiedDomXmrRecoveryFinalityV11 {
        &self.finality
    }
    /// Refuse a process-cached observation at a productive terminal boundary.
    /// Durable checkpoints never reconstruct this monotonic freshness token.
    pub fn require_recent_v12(&self) -> Result<(), RealDomError> {
        if self.finality.observed_at.elapsed() > std::time::Duration::from_secs(30) {
            Err(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable,
            ))
        } else {
            Ok(())
        }
    }
}

/// Mutually exclusive native graph states from one complete canonical snapshot.
pub enum VerifiedDomXmrRecoveryStateV11 {
    /// C is confirmed and remains unspent.
    CollateralReady(VerifiedDomXmrCollateralV11),
    /// Exact cancel is confirmed and D remains unspent.
    Cancelled(VerifiedDomXmrCancellationV11),
    /// Exact canonical adaptor refund revealed U; XMR sweeping is a later step.
    Refunded(VerifiedDomRefundSecretV11),
    /// Exact canonical plain punish paid DOM compensation, without revealing T.
    Compensated(VerifiedDomCompensationObservationV11),
}

#[derive(Clone, Default)]
struct GraphTrace {
    funding: Option<CanonicalTransactionEvidenceV1>,
    c_spend: Option<CanonicalTransactionEvidenceV1>,
    d_creation: Option<CanonicalTransactionEvidenceV1>,
    d_spend: Option<CanonicalTransactionEvidenceV1>,
}

// A bounded authenticated prefix, never a proof of absence or finality.
// Retained only in this physical runtime opening and keyed by graph/checkpoint.
#[derive(Clone)]
pub(super) struct NativeGraphScanProgressV23 {
    state: CursorStateV1,
    trace: GraphTrace,
    blocks: std::collections::BTreeMap<u64, [u8; 32]>,
    touched_at: std::time::Instant,
}
impl Default for NativeGraphScanProgressV23 {
    fn default() -> Self {
        Self {
            state: CursorStateV1::genesis(),
            trace: GraphTrace::default(),
            blocks: std::collections::BTreeMap::new(),
            touched_at: std::time::Instant::now(),
        }
    }
}

impl RealDomRpcRuntimeV1 {
    /// Observe the native graph with no legacy plain-refund Store assumption.
    /// A bounded, complete, linked scan proves both inclusion and absence of
    /// other C/D spends. Each batch closes against one snapshot; retained
    /// prefixes are reanchored on the selected canonical chain before reuse.
    /// Missing/immature evidence is retryable; substituted identities, unknown
    /// spends, duplicate graph outputs, and contradictory ancestry are refused.
    pub fn verified_xmr_recovery_state_v11(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
        self.verified_xmr_recovery_state_bounded_v23(
            graph,
            minimum_confirmations,
            max_reorg_depth,
            std::time::Duration::from_secs(60),
        )
    }

    /// Resume an authenticated canonical prefix within the caller's budget.
    /// The cache contains no readiness grant: every result requires the current
    /// anchored tip, complete graph trace, finality and post-classification bound.
    pub fn verified_xmr_recovery_state_bounded_v23(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
        budget: std::time::Duration,
    ) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
        let unavailable = || RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable);
        if budget.is_zero() || budget > std::time::Duration::from_secs(60) {
            return Err(unavailable());
        }
        // The caller's budget bounds this scan; the armed route-step ceiling
        // bounds the step that contains it. Narrow to whichever ends first —
        // a budget anchored at "now" otherwise admits a fresh full minute
        // inside a step that has already spent most of its lease.
        let deadline = crate::route_step_deadline_v27::clamp_v27(
            std::time::Instant::now()
                .checked_add(budget)
                .ok_or_else(unavailable)?,
        );
        self.verified_xmr_recovery_state_until_v24(
            graph,
            minimum_confirmations,
            max_reorg_depth,
            deadline,
        )
    }

    /// Preserve one absolute cutoff through the authenticated incremental scan.
    /// Expiration is checked before cache access or any chain request.
    pub fn verified_xmr_recovery_state_until_v24(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
        deadline: std::time::Instant,
    ) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
        let unavailable = || RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable);
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(unavailable)?;
        if remaining.is_zero() || remaining > std::time::Duration::from_secs(60) {
            return Err(unavailable());
        }
        let required = usize::try_from(max_reorg_depth)
            .ok()
            .and_then(|v| v.checked_add(1))
            .ok_or(RealDomError::FinalityPolicyInvalid)?;
        if graph.binding().chain_id != self.adapter.expected_identity().chain_id
            || minimum_confirmations == 0
            || max_reorg_depth < minimum_confirmations
            || required > self.history_limit
            || required > MAX_CURSOR_HISTORY
        {
            return Err(RealDomError::FinalityPolicyInvalid);
        }
        let cache_scope = digest_parts(
            b"DOM-INTEROP/XMR-RECOVERY-LIVE-SCAN/V23\0",
            &[
                graph.graph_digest(),
                &minimum_confirmations.to_be_bytes(),
                &max_reorg_depth.to_be_bytes(),
            ],
        );
        let (trace, state, identity, _) = self.scan_xmr_recovery_graph_watched_v23(
            graph,
            &std::collections::BTreeSet::new(),
            Some(deadline),
            Some(cache_scope),
        )?;
        let observed = classify_graph(
            graph,
            trace,
            &state,
            &identity,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        if std::time::Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(observed)
    }

    fn scan_xmr_recovery_graph_watched_v23(
        &self,
        graph: &VerifiedXmrRecoveryGraphV11,
        watched: &std::collections::BTreeSet<u64>,
        deadline: Option<std::time::Instant>,
        cache_scope: Option<[u8; 32]>,
    ) -> Result<
        (
            GraphTrace,
            CursorStateV1,
            ObservedDomIdentityV1,
            std::collections::BTreeMap<u64, [u8; 32]>,
        ),
        RealDomError,
    > {
        if watched.len() > MAX_CURSOR_HISTORY + 1 {
            return Err(RealDomError::BoundsExceeded);
        }
        if cache_scope.is_some() && deadline.is_none() {
            return Err(RealDomError::InvalidEvidence);
        }
        let mut cache = if cache_scope.is_some() {
            Some(
                self.xmr_refund_reorg_scan_v23
                    .try_lock()
                    .map_err(|error| match error {
                        std::sync::TryLockError::WouldBlock => {
                            RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
                        }
                        std::sync::TryLockError::Poisoned(_) => RealDomError::LockPoisoned,
                    })?,
            )
        } else {
            None
        };
        let progress = match (cache.as_mut(), cache_scope) {
            (Some(cache), Some(key)) => cache.remove(&key).unwrap_or_default(),
            _ => NativeGraphScanProgressV23::default(),
        };
        let NativeGraphScanProgressV23 {
            mut state,
            mut trace,
            mut blocks,
            ..
        } = progress;
        let mut expected_tip: Option<ObservedDomIdentityV1> = None;
        let result = (|| {
            for _ in 0..MAX_SNAPSHOT_SCAN_PAGES {
                let page = match deadline {
                    Some(deadline) => self.adapter.scan_page_until_v23(
                        state.scanner_cursor(),
                        MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
                        deadline,
                    )?,
                    None => self
                        .adapter
                        .scan_page(state.scanner_cursor(), MAX_SCRIPTLESS_SCAN_BLOCKS_V1)?,
                };
                if let Some(expected) = &expected_tip {
                    require_same_snapshot(expected, &page.identity)?;
                } else {
                    expected_tip = Some(page.identity.clone());
                }
                for block in &page.blocks {
                    if deadline.is_some_and(|end| std::time::Instant::now() >= end) {
                        return Err(RealDomError::Chain(
                            ChainAdapterError::TemporarilyUnavailable,
                        ));
                    }
                    if watched.contains(&block.height) {
                        blocks.insert(block.height, block.block_hash);
                    }
                    for transaction in &block.transactions {
                        trace.observe(graph, transaction)?;
                    }
                    state.append(block.height, block.block_hash, self.history_limit)?;
                }
                if state.scanner_cursor() != page.next_cursor {
                    return Err(RealDomError::InvalidEvidence);
                }
                if page.reached_snapshot_tip {
                    if state.history.last().copied()
                        != Some((page.identity.tip_height, page.identity.tip_hash))
                    {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    // A response for the successor cursor must confirm the same tip
                    // with no extra block. This closes a scan concurrent with reorg.
                    let recheck = match deadline {
                        Some(deadline) => {
                            self.adapter
                                .scan_page_until_v23(state.scanner_cursor(), 1, deadline)?
                        }
                        None => self.adapter.scan_page(state.scanner_cursor(), 1)?,
                    };
                    require_same_snapshot(&page.identity, &recheck.identity)?;
                    if !recheck.blocks.is_empty()
                        || recheck.next_cursor != state.scanner_cursor()
                        || !recheck.reached_snapshot_tip
                    {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    if deadline.is_some_and(|end| std::time::Instant::now() >= end) {
                        return Err(RealDomError::Chain(
                            ChainAdapterError::TemporarilyUnavailable,
                        ));
                    }
                    return Ok(page.identity);
                }
                if page.blocks.is_empty() {
                    return Err(RealDomError::EvidenceNotFound);
                }
            }
            if deadline.is_some() {
                Err(RealDomError::Chain(
                    ChainAdapterError::TemporarilyUnavailable,
                ))
            } else {
                Err(RealDomError::BoundsExceeded)
            }
        })();
        let progress = NativeGraphScanProgressV23 {
            state,
            trace,
            blocks,
            touched_at: std::time::Instant::now(),
        };
        if let (Some(cache), Some(key)) = (cache.as_mut(), cache_scope) {
            retain_native_graph_progress_v23(cache, key, &progress, result.as_ref().err());
        }
        result
            .map(|identity| (progress.trace, progress.state, identity, progress.blocks))
            .map_err(|error| match error {
                RealDomError::Chain(ChainAdapterError::ReorgDetected) if cache_scope.is_some() => {
                    RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
                }
                other => other,
            })
    }
}

fn retain_native_graph_progress_v23(
    cache: &mut std::collections::BTreeMap<[u8; 32], NativeGraphScanProgressV23>,
    key: [u8; 32],
    progress: &NativeGraphScanProgressV23,
    error: Option<&RealDomError>,
) {
    let retained = match error {
        None | Some(RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)) => {
            Some(progress.clone())
        }
        Some(RealDomError::Chain(ChainAdapterError::ReorgDetected)) => {
            Some(NativeGraphScanProgressV23::default())
        }
        _ => None,
    };
    cache.remove(&key);
    if let Some(mut retained) = retained {
        // At most four graph/checkpoint scopes, each four graph events and
        // max_reorg+2 watched headers. Evict the least recently used scope so
        // stale checkpoints cannot starve a newly active graph prefix.
        if cache.len() >= 4 {
            if let Some(evicted) = cache
                .iter()
                .min_by_key(|(_, v)| v.touched_at)
                .map(|(key, _)| *key)
            {
                cache.remove(&evicted);
            }
        }
        retained.touched_at = std::time::Instant::now();
        cache.insert(key, retained);
    }
}

fn require_same_snapshot(
    expected: &ObservedDomIdentityV1,
    current: &ObservedDomIdentityV1,
) -> Result<(), RealDomError> {
    if expected.chain_id != current.chain_id || expected.genesis_hash != current.genesis_hash {
        return Err(RealDomError::InvalidEvidence);
    }
    if expected.tip_height != current.tip_height || expected.tip_hash != current.tip_hash {
        return Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable,
        ));
    }
    Ok(())
}

impl GraphTrace {
    fn observe(
        &mut self,
        graph: &VerifiedXmrRecoveryGraphV11,
        tx: &CanonicalTransactionEvidenceV1,
    ) -> Result<(), RealDomError> {
        let binding = graph.binding();
        if tx.creates_commitment(&binding.funding_commitment)
            || tx.spends_commitment(&binding.funding_commitment)
            || tx.creates_commitment(&binding.cancelled_commitment)
            || tx.spends_commitment(&binding.cancelled_commitment)
        {
            // The full-fidelity scanner authenticates the linked location and
            // exact transaction projection. Native consensus additionally checks
            // its signature/proofs and timelock at that containing height.
            graph
                .validate_observed_transaction(tx.transaction(), tx.location().block_height())
                .map_err(|_| RealDomError::InvalidEvidence)?;
        }
        if tx.creates_commitment(&binding.funding_commitment) {
            retain_once(&mut self.funding, tx)?;
        }
        if tx.spends_commitment(&binding.funding_commitment) {
            retain_once(&mut self.c_spend, tx)?;
        }
        if tx.creates_commitment(&binding.cancelled_commitment) {
            retain_once(&mut self.d_creation, tx)?;
        }
        if tx.spends_commitment(&binding.cancelled_commitment) {
            retain_once(&mut self.d_spend, tx)?;
        }
        Ok(())
    }
}
fn retain_once(
    slot: &mut Option<CanonicalTransactionEvidenceV1>,
    tx: &CanonicalTransactionEvidenceV1,
) -> Result<(), RealDomError> {
    if slot.is_some() {
        return Err(RealDomError::InvalidEvidence);
    }
    *slot = Some(tx.clone());
    Ok(())
}
fn before(left: &CanonicalTransactionEvidenceV1, right: &CanonicalTransactionEvidenceV1) -> bool {
    (
        left.location().block_height(),
        left.location().transaction_index(),
    ) < (
        right.location().block_height(),
        right.location().transaction_index(),
    )
}

fn classify_graph(
    graph: &VerifiedXmrRecoveryGraphV11,
    trace: GraphTrace,
    state: &CursorStateV1,
    identity: &ObservedDomIdentityV1,
    minimum: u32,
    max_reorg: u32,
) -> Result<VerifiedDomXmrRecoveryStateV11, RealDomError> {
    let funding = match trace.funding {
        Some(funding) => funding,
        None if trace.c_spend.is_none()
            && trace.d_creation.is_none()
            && trace.d_spend.is_none() =>
        {
            return Err(RealDomError::EvidenceNotFound)
        }
        None => return Err(RealDomError::InvalidEvidence),
    };
    let funding_template = dom_adaptor::canonical_template_v1(graph.funding_template())
        .map_err(|_| RealDomError::InvalidEvidence)?
        .1;
    if funding.template_hash()? != funding_template {
        return Err(RealDomError::InvalidEvidence);
    }
    let cancel = match trace.c_spend {
        None if trace.d_creation.is_none() && trace.d_spend.is_none() => {
            return Ok(VerifiedDomXmrRecoveryStateV11::CollateralReady(
                VerifiedDomXmrCollateralV11 {
                    finality: finality(
                        1, graph, &funding, None, &funding, state, identity, minimum, max_reorg,
                    )?,
                },
            ));
        }
        None => return Err(RealDomError::InvalidEvidence),
        Some(spend) => spend,
    };
    if !before(&funding, &cancel) {
        return Err(RealDomError::InvalidEvidence);
    }
    if cancel.canonical_bytes() != graph.cancel_bytes() {
        let claim_template = dom_adaptor::canonical_template_v1(graph.claim_template())
            .map_err(|_| RealDomError::InvalidEvidence)?
            .1;
        if cancel.template_hash()? == claim_template
            && trace.d_creation.is_none()
            && trace.d_spend.is_none()
        {
            return Err(RealDomError::EvidenceNotFound);
        }
        return Err(RealDomError::InvalidEvidence);
    }
    let created = trace.d_creation.ok_or(RealDomError::InvalidEvidence)?;
    if created.tx_hash() != cancel.tx_hash() || created.location() != cancel.location() {
        return Err(RealDomError::InvalidEvidence);
    }
    // Cancel and finality both have to be present. In particular, a malicious
    // scanner cannot present only an otherwise valid D spend with a guessed D.
    let cancel_finality = finality(
        2,
        graph,
        &funding,
        Some(&cancel),
        &cancel,
        state,
        identity,
        minimum,
        max_reorg,
    )?;
    let terminal = match trace.d_spend {
        None => {
            return Ok(VerifiedDomXmrRecoveryStateV11::Cancelled(
                VerifiedDomXmrCancellationV11 {
                    finality: cancel_finality,
                },
            ))
        }
        Some(terminal) => terminal,
    };
    if !before(&cancel, &terminal) {
        return Err(RealDomError::InvalidEvidence);
    }
    if terminal.canonical_bytes() == graph.punish_bytes() {
        return Ok(VerifiedDomXmrRecoveryStateV11::Compensated(
            VerifiedDomCompensationObservationV11 {
                canonical_transaction_v22: terminal.canonical_bytes().to_vec(),
                finality: finality(
                    4,
                    graph,
                    &funding,
                    Some(&cancel),
                    &terminal,
                    state,
                    identity,
                    minimum,
                    max_reorg,
                )?,
            },
        ));
    }
    let pre = graph.refund_pre_signature();
    if terminal.template_hash()? != *pre.template_hash() {
        return Err(RealDomError::InvalidEvidence);
    }
    let proof = finality(
        3,
        graph,
        &funding,
        Some(&cancel),
        &terminal,
        state,
        identity,
        minimum,
        max_reorg,
    )?;
    let scalar = pre
        .extract(terminal.kernel_signature(0)?)
        .map_err(|_| RealDomError::InvalidEvidence)?;
    Ok(VerifiedDomXmrRecoveryStateV11::Refunded(
        VerifiedDomRefundSecretV11 {
            scalar,
            template_hash: *pre.template_hash(),
            refund_point: pre.refund_adaptor_point(),
            finality: proof,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn finality(
    kind: u8,
    graph: &VerifiedXmrRecoveryGraphV11,
    funding: &CanonicalTransactionEvidenceV1,
    cancel: Option<&CanonicalTransactionEvidenceV1>,
    event: &CanonicalTransactionEvidenceV1,
    state: &CursorStateV1,
    identity: &ObservedDomIdentityV1,
    minimum: u32,
    max_reorg: u32,
) -> Result<VerifiedDomXmrRecoveryFinalityV11, RealDomError> {
    let depth = identity
        .tip_height
        .checked_sub(event.location().block_height())
        .and_then(|depth| depth.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(RealDomError::InvalidEvidence)?;
    if depth < minimum {
        return Err(RealDomError::InsufficientConfirmations);
    }
    let required_tail = u64::from(max_reorg)
        .checked_add(1)
        .ok_or(RealDomError::BoundsExceeded)?
        .min(
            identity
                .tip_height
                .checked_add(1)
                .ok_or(RealDomError::BoundsExceeded)?,
        );
    let required_tail = usize::try_from(required_tail).map_err(|_| RealDomError::BoundsExceeded)?;
    if state.history.len() < required_tail {
        return Err(RealDomError::FinalityPolicyInvalid);
    }
    let binding = graph.binding();
    let cancel_hash = cancel.map(CanonicalTransactionEvidenceV1::tx_hash);
    let mut bytes = b"DOMXRFIN11\0".to_vec();
    bytes.push(kind);
    for value in [
        binding.chain_id,
        binding.session_id,
        binding.terms_hash,
        *graph.graph_digest(),
        funding.tx_hash(),
        cancel_hash.unwrap_or([0; 32]),
        event.tx_hash(),
        event.location().block_hash(),
        identity.tip_hash,
    ] {
        bytes.extend_from_slice(&value);
    }
    for value in [event.location().block_height(), identity.tip_height] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        event.location().transaction_index(),
        depth,
        minimum,
        max_reorg,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for (height, hash) in &state.history[state.history.len() - required_tail..] {
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(hash);
    }
    let evidence_digest = digest_parts(b"DOM-INTEROP/XMR-RECOVERY-FINALITY/V11\0", &[&bytes]);
    bytes.extend_from_slice(&evidence_digest);
    Ok(VerifiedDomXmrRecoveryFinalityV11 {
        chain_id: binding.chain_id,
        session_id: binding.session_id,
        terms_hash: binding.terms_hash,
        graph_digest: *graph.graph_digest(),
        funding_tx_hash: funding.tx_hash(),
        cancel_tx_hash: cancel_hash,
        transaction_hash: event.tx_hash(),
        block_height: event.location().block_height(),
        block_hash: event.location().block_hash(),
        transaction_index: event.location().transaction_index(),
        tip_height: identity.tip_height,
        tip_hash: identity.tip_hash,
        confirmation_depth: depth,
        minimum_confirmations: minimum,
        max_reorg_depth: max_reorg,
        evidence_digest,
        checkpoint_bytes: bytes,
        observed_at: std::time::Instant::now(),
    })
}
