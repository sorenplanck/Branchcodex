//! Bounded public SharePoK equations, never a share, nonce or authorization.
//!
//! The 202 statement bytes do NOT contain the authenticated roster digest.
//! Both that digest and the actual point used by the original challenge and
//! equation are separate exact operands and must participate in every lookup.
//! Canonical parsing and the caller's roster/state guards remain unchanged.
use super::{verify_share_knowledge_uncached_v25, Result, SharePoPStatementV1, ShareProofV1};
use std::sync::Mutex;

const DOMAIN: &[u8] = b"DOM:offchain:share-pop-equation:v25\0";
const CAPACITY: usize = 64;
const KEY_BYTES: usize = DOMAIN.len() + SharePoPStatementV1::ENCODED_LEN + 32 + 33 + 65;
type ExactEquationV25 = [u8; KEY_BYTES];

struct SuccessesV25 {
    entries: [Option<ExactEquationV25>; CAPACITY],
    next: usize,
    len: usize,
}

impl SuccessesV25 {
    const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            next: 0,
            len: 0,
        }
    }

    fn contains(&self, exact: &ExactEquationV25) -> bool {
        self.entries.iter().flatten().any(|entry| entry == exact)
    }

    // Private and reached only after the original verifier returns Ok(true).
    fn remember_success(&mut self, exact: ExactEquationV25) {
        if self.contains(&exact) {
            return;
        }
        self.entries[self.next] = Some(exact);
        self.next = if self.next == CAPACITY - 1 {
            0
        } else {
            self.next + 1
        };
        self.len = self.len.saturating_add(1).min(CAPACITY);
    }
}

struct CacheV25 {
    successful: Mutex<SuccessesV25>,
    #[cfg(test)]
    original_calls: std::sync::atomic::AtomicUsize,
}

impl CacheV25 {
    const fn new() -> Self {
        Self {
            successful: Mutex::new(SuccessesV25::new()),
            #[cfg(test)]
            original_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

// Fixed arrays plus const initialization: no heap allocation, fallible capacity
// growth, or blocking lazy initialization is introduced by this cache.
static CACHE: CacheV25 = CacheV25::new();

fn exact_equation(statement: &SharePoPStatementV1, proof: &ShareProofV1) -> ExactEquationV25 {
    let mut exact = [0; KEY_BYTES];
    let statement_end = DOMAIN.len() + SharePoPStatementV1::ENCODED_LEN;
    let roster_end = statement_end + 32;
    let point_end = roster_end + 33;
    exact[..DOMAIN.len()].copy_from_slice(DOMAIN);
    exact[DOMAIN.len()..statement_end].copy_from_slice(&statement.bytes);
    exact[statement_end..roster_end].copy_from_slice(&statement.roster_digest);
    exact[roster_end..point_end].copy_from_slice(&statement.share_point.to_compressed_bytes());
    exact[point_end..].copy_from_slice(&proof.to_bytes());
    exact
}

pub(super) fn verify(statement: &SharePoPStatementV1, proof: &ShareProofV1) -> Result<bool> {
    verify_using(&CACHE, statement, proof)
}

fn verify_using(
    cache: &CacheV25,
    statement: &SharePoPStatementV1,
    proof: &ShareProofV1,
) -> Result<bool> {
    let exact = exact_equation(statement, proof);
    if let Ok(successful) = cache.successful.try_lock() {
        if successful.contains(&exact) {
            return Ok(true);
        }
    }
    // Never hold the mutex while doing cryptography. Busy/poisoned caches and
    // evicted operands all take the identical original path without waiting.
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let accepted = verify_share_knowledge_uncached_v25(statement, proof)?;
    if accepted {
        if let Ok(mut successful) = cache.successful.try_lock() {
            successful.remember_success(exact);
        }
    }
    Ok(accepted)
}

#[cfg(test)]
#[path = "share_pop_verification_cache_v25_tests.rs"]
mod tests;
