//! Exact public mathematical successes only, never a nonce/finalizer/authority.
//! Raw extra_commit remains raw: imposing RecoveryCapsule framing here would
//! change the original driver's compatibility and error behavior.
use super::*;
use std::{collections::VecDeque, sync::OnceLock};

const DOMAIN: &[u8] = b"DOM:offchain:collaborative-final-proof:v25\0";
const ENTRIES: usize = 16;
const STATEMENT_BYTES: usize = 187 + 65 * BpStatementV1::MAX_PARTICIPANTS;
const EXTRA_BYTES: usize = 4096; // Cache eligibility only, never a protocol limit.
const KEY_BYTES: usize = DOMAIN.len() + 12 + STATEMENT_BYTES + RANGE_PROOF_SIZE + EXTRA_BYTES;

#[derive(Default)]
struct CacheV25 {
    keys: Mutex<VecDeque<Box<[u8]>>>,
    #[cfg(test)]
    original_calls: std::sync::atomic::AtomicUsize,
}

static CACHE: OnceLock<CacheV25> = OnceLock::new();

fn key(statement: &BpStatementV1, proof: &RangeProof739, extra: &[u8]) -> Option<Vec<u8>> {
    if statement.to_bytes().len() > STATEMENT_BYTES || extra.len() > EXTRA_BYTES {
        return None;
    }
    let fields = [statement.to_bytes(), proof.as_bytes().as_slice(), extra];
    let length = fields.iter().try_fold(DOMAIN.len(), |size, field| {
        size.checked_add(4)?.checked_add(field.len())
    })?;
    if length > KEY_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.extend_from_slice(DOMAIN);
    for field in fields {
        bytes.extend_from_slice(&u32::try_from(field.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Some(bytes)
}

pub(super) fn verify(
    driver: &DomCollaborativeRangeProofV1,
    statement: &BpStatementV1,
    proof: &RangeProof739,
) -> Result<()> {
    verify_using(
        CACHE.get_or_init(CacheV25::default),
        driver,
        statement,
        proof,
    )
}

fn verify_using(
    cache: &CacheV25,
    driver: &DomCollaborativeRangeProofV1,
    statement: &BpStatementV1,
    proof: &RangeProof739,
) -> Result<()> {
    // Always run the original driver/statement guard. Proof framing is already
    // enforced by RangeProof739; statement fields are immutable and canonical.
    driver.require_statement(statement)?;
    let key = key(statement, proof, &driver.extra_commit);
    if let Some(key) = &key {
        if let Ok(keys) = cache.keys.try_lock() {
            if keys.iter().any(|prior| prior.as_ref() == key.as_slice()) {
                return Ok(());
            }
        }
    }
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    driver.verify_final_uncached_v25(statement, proof)?;
    if let Some(key) = key {
        if let Ok(mut keys) = cache.keys.try_lock() {
            if !keys.iter().any(|prior| prior.as_ref() == key.as_slice())
                && keys.try_reserve(1).is_ok()
            {
                if keys.len() == ENTRIES {
                    keys.pop_front();
                }
                keys.push_back(key.into_boxed_slice());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "collaborative_final_proof_cache_v25_tests.rs"]
mod tests;
