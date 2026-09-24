//! Native graph checkpoint revalidation; the plain-refund codec is not used.
use super::*;
use dom_scriptless_store::{VerifiedXmrRecoveryExecutionAuthorityV12, XmrRecoveryCustodyV11};
use std::collections::{BTreeMap, BTreeSet};

const MAGIC: &[u8] = b"DOMXRFIN11\0";
const PREFIX: usize = 12 + 9 * 32 + 2 * 8 + 4 * 4;

#[cfg(test)]
#[path = "xmr_refund_reorg_v23_tests.rs"]
mod tests;

struct NativeRefundCheckpointV23 {
    chain: [u8; 32],
    session: [u8; 32],
    terms: [u8; 32],
    graph: [u8; 32],
    funding: [u8; 32],
    transaction: [u8; 32],
    block: [u8; 32],
    tip: [u8; 32],
    height: u64,
    tip_height: u64,
    minimum: u32,
    maximum: u32,
    evidence: [u8; 32],
    tail: Vec<(u64, [u8; 32])>,
}

/// Fresh bounded fork proof for one exact native U-refund checkpoint.
/// No public constructor, Clone, codec or secret accessor exists.
pub struct VerifiedDomXmrRefundReorgV23 {
    prior: NativeRefundCheckpointV23,
    current_height: u64,
    current_hash: [u8; 32],
    ancestor_height: u64,
    removed: u32,
    evidence: [u8; 32],
    observed_at: std::time::Instant,
}

/// Two exclusive results of one complete bounded native checkpoint scan.
pub enum VerifiedDomXmrRefundRevalidationV23 {
    /// Original inclusion remains canonical and satisfies the frozen depth.
    StillFinal(VerifiedDomRefundSecretV11),
    /// Original inclusion was removed by the exactly proved bounded fork.
    Invalidated(VerifiedDomXmrRefundReorgV23),
}

macro_rules! prior_getter {
    ($name:ident, $field:ident, $ty:ty, $doc:literal) => {
        #[doc = $doc]
        pub const fn $name(&self) -> $ty {
            self.prior.$field
        }
    };
}
impl VerifiedDomXmrRefundReorgV23 {
    prior_getter!(chain_id, chain, [u8; 32], "Authenticated native chain.");
    prior_getter!(session_id, session, [u8; 32], "Exact Contracts session.");
    prior_getter!(terms_hash, terms, [u8; 32], "Original negotiated terms.");
    prior_getter!(
        graph_digest,
        graph,
        [u8; 32],
        "Authenticated recovery graph."
    );
    prior_getter!(
        funding_tx_hash,
        funding,
        [u8; 32],
        "Exact collateral transaction."
    );
    prior_getter!(
        transaction_hash,
        transaction,
        [u8; 32],
        "Invalidated U-refund transaction."
    );
    prior_getter!(
        prior_block_hash,
        block,
        [u8; 32],
        "Original inclusion block."
    );
    prior_getter!(
        prior_block_height,
        height,
        u64,
        "Original inclusion height."
    );
    prior_getter!(
        prior_evidence_digest,
        evidence,
        [u8; 32],
        "Original finality evidence digest."
    );
    prior_getter!(
        minimum_confirmations,
        minimum,
        u32,
        "Frozen minimum confirmations."
    );
    prior_getter!(
        max_reorg_depth,
        maximum,
        u32,
        "Frozen maximum rollback depth."
    );
    /// Fresh canonical tip height.
    pub const fn current_tip_height(&self) -> u64 {
        self.current_height
    }
    /// Fresh canonical tip hash.
    pub const fn current_tip_hash(&self) -> [u8; 32] {
        self.current_hash
    }
    /// Highest proved shared ancestor in the original bounded tail.
    pub const fn common_ancestor_height(&self) -> u64 {
        self.ancestor_height
    }
    /// Number of removed blocks above that ancestor in the original snapshot.
    pub const fn removed_depth(&self) -> u32 {
        self.removed
    }
    /// Domain-separated identity of this exact fork and checkpoint.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence
    }
    /// Recheck monotonic freshness immediately before a durable mutation.
    pub fn require_recent_v23(&self) -> Result<(), RealDomError> {
        if self.observed_at.elapsed() > std::time::Duration::from_secs(30) {
            return Err(RealDomError::Chain(
                ChainAdapterError::TemporarilyUnavailable,
            ));
        }
        Ok(())
    }
}

impl RealDomRpcRuntimeV1 {
    /// Prove rollback using the original native checkpoint and a new complete
    /// canonical graph scan. An unchanged inclusion returns a fresh U token;
    /// loss of depth alone is pending, never evidence of a removed block.
    pub fn verified_xmr_refund_reorg_v23(
        &self,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &XmrRecoveryCustodyV11,
        checkpoint: &[u8],
        expected_transaction: [u8; 32],
        budget: std::time::Duration,
    ) -> Result<VerifiedDomXmrRefundRevalidationV23, RealDomError> {
        let unavailable = || RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable);
        if budget.is_zero() || budget > std::time::Duration::from_secs(60) {
            return Err(unavailable());
        }
        // Same narrowing as every other scan reached from a route step.
        let deadline = crate::route_step_deadline_v27::clamp_v27(
            std::time::Instant::now()
                .checked_add(budget)
                .ok_or_else(unavailable)?,
        );
        authority.require_custody(custody)?;
        let prior = decode_native_refund_v23(checkpoint)?;
        if prior.chain != authority.chain_id()
            || prior.session != authority.session_id()
            || prior.terms != authority.terms_hash()
            || prior.graph != authority.graph_digest()
            || prior.funding != authority.funding_tx_hash()
            || prior.transaction != expected_transaction
            || prior.minimum != authority.minimum_confirmations()
            || prior.maximum != authority.max_reorg_depth()
            || prior.chain != self.adapter.expected_identity().chain_id
            || u64::from(prior.maximum) + 1 > self.history_limit as u64
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let watched: BTreeSet<_> = prior
            .tail
            .iter()
            .map(|(height, _)| *height)
            .chain(std::iter::once(prior.height))
            .collect();
        let result = custody
            .with_graph(|graph| {
                authority.require_graph_profile_v23(graph)?;
                if graph.binding().chain_id != prior.chain
                    || graph.binding().session_id != prior.session
                    || graph.binding().terms_hash != prior.terms
                    || *graph.graph_digest() != prior.graph
                {
                    return Err(RealDomError::InvalidEvidence);
                }
                let cache_scope = digest_parts(
                    b"DOM-INTEROP/XMR-REFUND-REORG-SCAN/V23\0",
                    &[&prior.graph, &prior.evidence],
                );
                let (trace, state, identity, blocks) = self.scan_xmr_recovery_graph_watched_v23(
                    graph,
                    &watched,
                    Some(deadline),
                    Some(cache_scope),
                )?;
                let location = trace
                    .d_spend
                    .as_ref()
                    .filter(|tx| tx.tx_hash() == prior.transaction)
                    .map(|tx| (tx.location().block_height(), tx.location().block_hash()));
                match prove_native_refund_fork_v23(
                    prior,
                    &blocks,
                    identity.tip_height,
                    identity.tip_hash,
                    location,
                ) {
                    Ok(proof) => Ok(VerifiedDomXmrRefundRevalidationV23::Invalidated(proof)),
                    Err(RealDomError::TransactionStillCanonical) => {
                        match classify_graph(
                            graph,
                            trace,
                            &state,
                            &identity,
                            authority.minimum_confirmations(),
                            authority.max_reorg_depth(),
                        )? {
                            VerifiedDomXmrRecoveryStateV11::Refunded(observed)
                                if observed.finality().funding_tx_hash()
                                    == authority.funding_tx_hash() =>
                            {
                                Ok(VerifiedDomXmrRefundRevalidationV23::StillFinal(observed))
                            }
                            _ => Err(RealDomError::InvalidEvidence),
                        }
                    }
                    Err(error) => Err(error),
                }
            })
            .map_err(|_| RealDomError::InvalidEvidence)??;
        if std::time::Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(result)
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], RealDomError> {
    let end = cursor.checked_add(N).ok_or(RealDomError::InvalidEvidence)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(RealDomError::InvalidEvidence)?
        .try_into()
        .map_err(|_| RealDomError::InvalidEvidence)?;
    *cursor = end;
    Ok(value)
}

fn decode_native_refund_v23(bytes: &[u8]) -> Result<NativeRefundCheckpointV23, RealDomError> {
    if bytes.len() < PREFIX + 40 + 32
        || bytes.len() > PREFIX + MAX_CURSOR_HISTORY * 40 + 32
        || !bytes.starts_with(MAGIC)
        || bytes.get(MAGIC.len()) != Some(&3)
    {
        return Err(RealDomError::InvalidEvidence);
    }
    let body = &bytes[..bytes.len() - 32];
    let evidence: [u8; 32] = bytes[bytes.len() - 32..]
        .try_into()
        .map_err(|_| RealDomError::InvalidEvidence)?;
    if evidence != digest_parts(b"DOM-INTEROP/XMR-RECOVERY-FINALITY/V11\0", &[body]) {
        return Err(RealDomError::InvalidEvidence);
    }
    let mut at = MAGIC.len() + 1;
    let chain = take(body, &mut at)?;
    let session = take(body, &mut at)?;
    let terms = take(body, &mut at)?;
    let graph = take(body, &mut at)?;
    let funding = take(body, &mut at)?;
    let cancel = take(body, &mut at)?;
    let transaction = take(body, &mut at)?;
    let block = take(body, &mut at)?;
    let tip = take(body, &mut at)?;
    let height = u64::from_be_bytes(take(body, &mut at)?);
    let tip_height = u64::from_be_bytes(take(body, &mut at)?);
    let _transaction_index = u32::from_be_bytes(take(body, &mut at)?);
    let depth = u32::from_be_bytes(take(body, &mut at)?);
    let minimum = u32::from_be_bytes(take(body, &mut at)?);
    let maximum = u32::from_be_bytes(take(body, &mut at)?);
    let count = u64::from(maximum)
        .checked_add(1)
        .and_then(|n| tip_height.checked_add(1).map(|tip| n.min(tip)))
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(RealDomError::InvalidEvidence)?;
    if minimum == 0
        || maximum < minimum
        || count > MAX_CURSOR_HISTORY
        || u64::from(maximum) + 1 > MAX_CURSOR_HISTORY as u64
        || body.len() != PREFIX + count * 40
        || tip_height
            .checked_sub(height)
            .and_then(|v| v.checked_add(1))
            != Some(u64::from(depth))
        || depth < minimum
        || funding == transaction
        || funding == cancel
        || cancel == transaction
        || [
            chain,
            session,
            terms,
            graph,
            funding,
            cancel,
            transaction,
            block,
            tip,
            evidence,
        ]
        .contains(&[0; 32])
    {
        return Err(RealDomError::InvalidEvidence);
    }
    let mut tail = Vec::with_capacity(count);
    let start = tip_height
        .checked_add(1)
        .and_then(|n| n.checked_sub(count as u64))
        .ok_or(RealDomError::InvalidEvidence)?;
    for index in 0..count {
        let h = u64::from_be_bytes(take(body, &mut at)?);
        let hash = take(body, &mut at)?;
        if h != start + index as u64 || hash == [0; 32] || (h == height && hash != block) {
            return Err(RealDomError::InvalidEvidence);
        }
        tail.push((h, hash));
    }
    if at != body.len() || tail.last() != Some(&(tip_height, tip)) {
        return Err(RealDomError::InvalidEvidence);
    }
    Ok(NativeRefundCheckpointV23 {
        chain,
        session,
        terms,
        graph,
        funding,
        transaction,
        block,
        tip,
        height,
        tip_height,
        minimum,
        maximum,
        evidence,
        tail,
    })
}

fn prove_native_refund_fork_v23(
    prior: NativeRefundCheckpointV23,
    blocks: &BTreeMap<u64, [u8; 32]>,
    height: u64,
    tip: [u8; 32],
    location: Option<(u64, [u8; 32])>,
) -> Result<VerifiedDomXmrRefundReorgV23, RealDomError> {
    if tip == [0; 32]
        || location
            .is_some_and(|(location_height, hash)| location_height > height || hash == [0; 32])
    {
        return Err(RealDomError::InvalidEvidence);
    }
    if location == Some((prior.height, prior.block)) {
        if height
            .checked_sub(prior.height)
            .and_then(|v| v.checked_add(1))
            .is_none_or(|depth| depth < u64::from(prior.minimum))
        {
            return Err(RealDomError::InsufficientConfirmations);
        }
        return Err(RealDomError::TransactionStillCanonical);
    }
    if blocks.get(&prior.height) == Some(&prior.block) {
        return Err(RealDomError::InvalidEvidence);
    }
    let (ancestor_height, ancestor_hash) = prior
        .tail
        .iter()
        .rev()
        .find(|(h, hash)| *h <= height && blocks.get(h) == Some(hash))
        .copied()
        .ok_or(RealDomError::ReorgBeyondPolicy)?;
    let removed = prior
        .tip_height
        .checked_sub(ancestor_height)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|depth| *depth > 0 && *depth <= prior.maximum)
        .ok_or(RealDomError::ReorgBeyondPolicy)?;
    let (tag, reheight, rehash) = location
        .map(|(h, hash)| (1u8, h, hash))
        .unwrap_or((0, 0, [0; 32]));
    let evidence = digest_parts(
        b"DOM-INTEROP/XMR-REFUND-REORG/V23\0",
        &[
            &prior.evidence,
            &prior.chain,
            &prior.session,
            &prior.graph,
            &prior.transaction,
            &prior.tip_height.to_be_bytes(),
            &prior.tip,
            &height.to_be_bytes(),
            &tip,
            &ancestor_height.to_be_bytes(),
            &ancestor_hash,
            &removed.to_be_bytes(),
            &[tag],
            &reheight.to_be_bytes(),
            &rehash,
        ],
    );
    Ok(VerifiedDomXmrRefundReorgV23 {
        prior,
        current_height: height,
        current_hash: tip,
        ancestor_height,
        removed,
        evidence,
        observed_at: std::time::Instant::now(),
    })
}
