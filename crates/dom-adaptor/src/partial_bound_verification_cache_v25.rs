//! Public partial-equation memo at the authenticated signing-round boundary.
//!
//! Roster/index, transcript and public-input derivation stay in verify_partial.
//! Purpose/template guards run before lookup and the unchanged verify_bound is
//! the sole miss oracle. No secret nonce, share or signing permission is held.
use crate::{AdaptorError, PartialSignatureV1, PurposeV1, Result};
use dom_crypto::PublicKey;
use std::sync::Mutex;

const DOMAIN: &[u8] = b"DOM:offchain:bound-partial-equation:v25\0";
const CAPACITY: usize = 64;
// This bounds memo memory only, NOT the protocol or original verifier's input.
const MAX_CACHED_MESSAGE_BYTES: usize = 1_024;
const KEY_BYTES: usize = DOMAIN.len()
    + PartialSignatureV1::ENCODED_LEN
    + 1
    + 32
    + 4 * 33
    + 32
    + 4
    + MAX_CACHED_MESSAGE_BYTES;
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

// Const-initialized fixed arrays: no heap growth, allocation failure, waiting
// initialization or eviction I/O. Contention/poison always use the original.
static CACHE: CacheV25 = CacheV25::new();

#[derive(Clone, Copy)]
struct OperandsV25<'a> {
    partial: &'a PartialSignatureV1,
    expected_purpose: PurposeV1,
    expected_template_hash: &'a [u8; 32],
    bound_public_nonce: &'a PublicKey,
    participant_key: &'a PublicKey,
    aggregate_nonce_hat: &'a PublicKey,
    aggregate_signing_key: &'a PublicKey,
    chain_id: &'a [u8; 32],
    kernel_message: &'a [u8],
}

impl OperandsV25<'_> {
    fn original(self) -> Result<bool> {
        self.partial.verify_bound(
            self.expected_purpose,
            self.expected_template_hash,
            self.bound_public_nonce,
            self.participant_key,
            self.aggregate_nonce_hat,
            self.aggregate_signing_key,
            self.chain_id,
            self.kernel_message,
        )
    }

    fn exact(self) -> Option<ExactEquationV25> {
        if self.kernel_message.len() > MAX_CACHED_MESSAGE_BYTES {
            return None;
        }
        let mut exact = [0; KEY_BYTES];
        let mut offset = 0;
        let partial_bytes = self.partial.to_bytes();
        let purpose_bytes = [self.expected_purpose.to_byte()];
        let nonce_bytes = self.bound_public_nonce.to_compressed_bytes();
        let participant_bytes = self.participant_key.to_compressed_bytes();
        let aggregate_nonce_bytes = self.aggregate_nonce_hat.to_compressed_bytes();
        let aggregate_key_bytes = self.aggregate_signing_key.to_compressed_bytes();
        let message_length = (self.kernel_message.len() as u32).to_be_bytes();
        // Every scalar, point and context byte is compared, never only a hash.
        // The explicit length distinguishes trailing zeros from padding.
        for field in [
            DOMAIN,
            &partial_bytes,
            &purpose_bytes,
            self.expected_template_hash,
            &nonce_bytes,
            &participant_bytes,
            &aggregate_nonce_bytes,
            &aggregate_key_bytes,
            self.chain_id,
            &message_length,
            self.kernel_message,
        ] {
            exact[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        Some(exact)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    partial: &PartialSignatureV1,
    expected_purpose: PurposeV1,
    expected_template_hash: &[u8; 32],
    bound_public_nonce: &PublicKey,
    participant_key: &PublicKey,
    aggregate_nonce_hat: &PublicKey,
    aggregate_signing_key: &PublicKey,
    chain_id: &[u8; 32],
    kernel_message: &[u8],
) -> Result<bool> {
    verify_using(
        &CACHE,
        OperandsV25 {
            partial,
            expected_purpose,
            expected_template_hash,
            bound_public_nonce,
            participant_key,
            aggregate_nonce_hat,
            aggregate_signing_key,
            chain_id,
            kernel_message,
        },
    )
}

fn verify_using(cache: &CacheV25, operands: OperandsV25<'_>) -> Result<bool> {
    let OperandsV25 {
        partial,
        expected_purpose,
        expected_template_hash,
        ..
    } = operands;
    // Same guards and error order as the unchanged original method. They
    // cannot be satisfied by an old successful equation from another session.
    partial.purpose().require_strict_phase1()?;
    expected_purpose.require_strict_phase1()?;
    if partial.purpose() != expected_purpose {
        return Err(AdaptorError::InvalidTranscript(
            "partial signature purpose does not match the session",
        ));
    }
    if partial.template_hash() != expected_template_hash {
        return Err(AdaptorError::InvalidTranscript(
            "partial signature template does not match the session",
        ));
    }
    let exact = operands.exact();
    if let Some(exact) = &exact {
        if let Ok(successful) = cache.successful.try_lock() {
            if successful.contains(exact) {
                return Ok(true);
            }
        }
    }
    #[cfg(test)]
    cache
        .original_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // No lock spans the original cryptography. The original repeats all guards
    // on a miss and accepts oversize messages exactly as it did before.
    finish_original(cache, exact, operands.original())
}

fn finish_original(
    cache: &CacheV25,
    exact: Option<ExactEquationV25>,
    result: Result<bool>,
) -> Result<bool> {
    if let Ok(true) = &result {
        if let Some(exact) = exact {
            if let Ok(mut successful) = cache.successful.try_lock() {
                successful.remember_success(exact);
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "partial_bound_verification_cache_v25_tests.rs"]
mod tests;
