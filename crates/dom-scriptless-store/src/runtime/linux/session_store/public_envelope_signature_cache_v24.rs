//! Bounded memo of public DSC1 Schnorr equations, never of Store authority.
//!
//! The caller still parses every envelope/signature, reloads its authenticated
//! roster and checks its durable successor, sequence, transcript and ownership.
//! Only the exact operands of `dom_crypto::schnorr_verify` are remembered. Its
//! message operand is the already recomputed DSC1 digest, not a cache-made hash.
use dom_core::DomError;
use dom_crypto::{schnorr_verify, PublicKey, SchnorrSignature};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const CAPACITY: usize = 1024;
const KEY_BYTES: usize = 65 + 33 + 32 + 32;
type ExactEquationV24 = [u8; KEY_BYTES];

#[derive(Default)]
struct PublicEnvelopeSignatureCacheV24 {
    successful: Mutex<VecDeque<ExactEquationV24>>,
    #[cfg(test)]
    original_calls: std::sync::atomic::AtomicUsize,
}

static CACHE: OnceLock<PublicEnvelopeSignatureCacheV24> = OnceLock::new();

fn exact_equation(
    signature: &SchnorrSignature,
    key: &PublicKey,
    chain: &[u8; 32],
    message_digest: &[u8; 32],
) -> ExactEquationV24 {
    let mut bytes = [0; KEY_BYTES];
    bytes[..65].copy_from_slice(&signature.to_bytes());
    bytes[65..98].copy_from_slice(&key.to_compressed_bytes());
    bytes[98..130].copy_from_slice(chain);
    bytes[130..].copy_from_slice(message_digest);
    bytes
}

// Private module and fixed-size operands keep this memo separate from every
// other equation/domain. No key-only, digest-only or partially compared hit.
pub(super) fn verify(
    signature: &SchnorrSignature,
    key: &PublicKey,
    chain: &[u8; 32],
    message_digest: &[u8; 32],
) -> Result<bool, DomError> {
    verify_using(
        CACHE.get_or_init(PublicEnvelopeSignatureCacheV24::default),
        signature,
        key,
        chain,
        message_digest,
    )
}

fn verify_using(
    cache: &PublicEnvelopeSignatureCacheV24,
    signature: &SchnorrSignature,
    key: &PublicKey,
    chain: &[u8; 32],
    message_digest: &[u8; 32],
) -> Result<bool, DomError> {
    let exact = exact_equation(signature, key, chain, message_digest);
    if let Ok(successful) = cache.successful.try_lock() {
        if successful.contains(&exact) {
            return Ok(true);
        }
    }
    // The mutex is never held during cryptography. Contention/poison always
    // takes the original verifier; concurrent misses may safely do extra work.
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let accepted = schnorr_verify(signature, key, chain, message_digest)?;
    if accepted {
        if let Ok(mut successful) = cache.successful.try_lock() {
            if !successful.contains(&exact) {
                // Evict before reserving: the queue never grows beyond 1024
                // exact equations (165,888 retained operand bytes).
                if successful.len() == CAPACITY {
                    successful.pop_front();
                }
                if successful.try_reserve(1).is_ok() {
                    successful.push_back(exact);
                }
            }
        }
    }
    Ok(accepted)
}

#[cfg(test)]
#[path = "public_envelope_signature_cache_v24_tests.rs"]
mod tests;
