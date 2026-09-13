//! Bounded, process-local memo of successful mathematical output checks only.
//! The exact commitment AND complete proof/capsule envelope are the key. This
//! grants no session, ownership, nonce, funding, lease, freshness or finality
//! authority. All full transaction validators remain unchanged in consensus.
use dom_consensus::{Transaction, TransactionOutput};
use dom_core::DomError;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const DOMAIN: &[u8] = b"DOM:offchain:public-range-proof:v24\0";
const ENTRIES: usize = 64;
const KEY_BYTES: usize = DOMAIN.len() + 33 + 2 + dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE;
const RETAINED_BYTES: usize = ENTRIES * KEY_BYTES;

#[derive(Default)]
struct SuccessfulOutputsV24 {
    keys: VecDeque<Box<[u8]>>,
    bytes: usize,
}

impl SuccessfulOutputsV24 {
    fn contains(&self, key: &[u8]) -> bool {
        self.keys.iter().any(|prior| prior.as_ref() == key)
    }

    // Private: production calls this only after the unchanged verifier accepts
    // the exact output, or after the ENTIRE original transaction proof check.
    fn remember_success(&mut self, key: Vec<u8>) {
        if key.len() > KEY_BYTES || self.contains(&key) {
            return;
        }
        if self.keys.try_reserve(1).is_err() {
            return;
        }
        while self.keys.len() >= ENTRIES || self.bytes.saturating_add(key.len()) > RETAINED_BYTES {
            let Some(oldest) = self.keys.pop_front() else {
                return;
            };
            self.bytes -= oldest.len();
        }
        self.bytes += key.len();
        self.keys.push_back(key.into_boxed_slice());
    }
}

#[derive(Default)]
struct PublicProofCacheV24 {
    successful: Mutex<SuccessfulOutputsV24>,
    #[cfg(test)]
    original_output_calls: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    original_transaction_calls: std::sync::atomic::AtomicUsize,
}

static CACHE: OnceLock<PublicProofCacheV24> = OnceLock::new();

// Framing/capsule parsing always precedes this allocation and any lookup.
fn exact_key(output: &TransactionOutput) -> Option<Vec<u8>> {
    if output.proof.len() > dom_core::MAX_OUTPUT_PROOF_ENVELOPE_SIZE {
        return None;
    }
    let size = DOMAIN.len() + 33 + 2 + output.proof.len();
    let mut key = Vec::new();
    key.try_reserve_exact(size).ok()?;
    key.extend_from_slice(DOMAIN);
    key.extend_from_slice(output.commitment.as_bytes());
    key.extend_from_slice(&u16::try_from(output.proof.len()).ok()?.to_be_bytes());
    key.extend_from_slice(&output.proof);
    Some(key)
}

pub(crate) fn verify_public_output_range_proof_v24(
    output: &TransactionOutput,
) -> Result<bool, DomError> {
    verify_output_using(CACHE.get_or_init(PublicProofCacheV24::default), output)
}

fn verify_output_using(
    cache: &PublicProofCacheV24,
    output: &TransactionOutput,
) -> Result<bool, DomError> {
    let proof = output.range_proof_bytes()?;
    let capsule = output.recovery_capsule()?;
    let key = exact_key(output);
    if let Some(key) = &key {
        if let Ok(successful) = cache.successful.try_lock() {
            if successful.contains(key) {
                return Ok(true);
            }
        }
    }
    #[cfg(test)]
    cache
        .original_output_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let accepted = match capsule {
        Some(capsule) => dom_crypto::range_proof_verify_with_extra_commit(
            output.commitment.as_bytes(),
            proof,
            capsule.as_bytes(),
        ),
        None => dom_crypto::range_proof_verify(output.commitment.as_bytes(), proof),
    }?;
    if accepted {
        if let Some(key) = key {
            if let Ok(mut successful) = cache.successful.try_lock() {
                successful.remember_success(key);
            }
        }
    }
    Ok(accepted)
}

/// Off-chain mathematical range-proof check with exactly the original errors.
///
/// Only an all-output hit can avoid the original verifier. Any miss, malformed
/// envelope, allocation failure, lock contention or poisoned mutex executes
/// `dom_consensus::validate_range_proofs` for the WHOLE transaction. Therefore
/// even mixed cached/invalid outputs preserve original error order and index.
/// No new output is remembered unless that complete original check succeeds.
/// This is not a replacement for full transaction or live authority validation.
pub fn validate_public_range_proofs_v24(transaction: &Transaction) -> Result<(), DomError> {
    validate_transaction_using(CACHE.get_or_init(PublicProofCacheV24::default), transaction)
}

fn transaction_keys(transaction: &Transaction) -> Option<Vec<Vec<u8>>> {
    // This is a memory budget, NOT a consensus output limit. Larger inputs take
    // the unchanged validator and are not cached, whether accepted or rejected.
    if transaction.outputs.len() > ENTRIES {
        return None;
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(transaction.outputs.len()).ok()?;
    for output in &transaction.outputs {
        output.range_proof_bytes().ok()?;
        output.recovery_capsule().ok()?;
        keys.push(exact_key(output)?);
    }
    Some(keys)
}

fn validate_transaction_using(
    cache: &PublicProofCacheV24,
    transaction: &Transaction,
) -> Result<(), DomError> {
    let keys = transaction_keys(transaction);
    if let Some(keys) = &keys {
        if let Ok(successful) = cache.successful.try_lock() {
            if keys.iter().all(|key| successful.contains(key)) {
                return Ok(());
            }
        }
    }
    #[cfg(test)]
    cache
        .original_transaction_calls
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    dom_consensus::validate_range_proofs(transaction)?;
    // Release the lock before cryptography; cache failures cannot affect the
    // original result. Atomic admission follows whole-transaction success.
    if let Some(keys) = keys {
        if let Ok(mut successful) = cache.successful.try_lock() {
            for key in keys {
                successful.remember_success(key);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::recovery::{
        RecoveryCapsule, RECOVERY_CAPSULE_SIZE, RECOVERY_CIPHERTEXT_SIZE, RECOVERY_VERSION,
    };
    use std::sync::atomic::Ordering;

    fn output(value: u64, seed: u8, capsule: bool) -> TransactionOutput {
        let mut scalar = [0; 32];
        scalar[31] = seed;
        let blinding = BlindingFactor::from_bytes(scalar).expect("fixture blinding");
        let commitment = Commitment::commit(value, &blinding);
        if capsule {
            // This is a public framing fixture, not a decryptable wallet secret.
            // Its exact bytes are nevertheless real range-proof extra_commit.
            let mut bytes = [seed; RECOVERY_CAPSULE_SIZE];
            bytes[..2].copy_from_slice(&RECOVERY_VERSION.to_le_bytes());
            bytes[14..16].copy_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
            let capsule = RecoveryCapsule::from_bytes(&bytes).expect("canonical capsule");
            let (proof, proved_commitment) = dom_crypto::range_proof_prove_bytes_with_extra_commit(
                value,
                &blinding,
                capsule.as_bytes(),
            )
            .expect("real capsule-bound proof");
            assert_eq!(commitment.as_bytes(), &proved_commitment);
            TransactionOutput::with_recovery_capsule(commitment, proof, &capsule)
                .expect("output envelope")
        } else {
            let (proof, proved_commitment) =
                dom_crypto::range_proof_prove_bytes(value, &blinding).expect("real plain proof");
            assert_eq!(commitment.as_bytes(), &proved_commitment);
            TransactionOutput { commitment, proof }
        }
    }

    fn transaction(outputs: Vec<TransactionOutput>) -> Transaction {
        // The API deliberately checks ONLY proof math, exactly like the
        // consensus helper; callers keep structure, kernels and balance checks.
        Transaction {
            inputs: Vec::new(),
            outputs,
            kernels: Vec::new(),
            offset: [0; 32],
        }
    }

    fn unchanged(output: &TransactionOutput) -> Result<bool, DomError> {
        let proof = output.range_proof_bytes()?;
        match output.recovery_capsule()? {
            Some(capsule) => dom_crypto::range_proof_verify_with_extra_commit(
                output.commitment.as_bytes(),
                proof,
                capsule.as_bytes(),
            ),
            None => dom_crypto::range_proof_verify(output.commitment.as_bytes(), proof),
        }
    }

    #[test]
    fn public_range_proof_cache_real_plain_and_capsule_64_replays_use_one_original_v24() {
        for capsule in [false, true] {
            let cache = PublicProofCacheV24::default();
            let output = output(17, 3, capsule);
            assert_eq!(unchanged(&output), Ok(true));
            for _ in 0..64 {
                assert_eq!(verify_output_using(&cache, &output), Ok(true));
            }
            assert_eq!(cache.original_output_calls.load(Ordering::Relaxed), 1);
            let cache = PublicProofCacheV24::default();
            let tx = transaction(vec![output]);
            // Public primitive measurement, not a daemon/swap SLA. Fixture
            // proving is outside BOTH measured paths. The baseline calls the
            // unchanged consensus helper directly, which has no memo here.
            let baseline_started = std::time::Instant::now();
            let mut original_calls = 0;
            for _ in 0..64 {
                assert_eq!(dom_consensus::validate_range_proofs(&tx), Ok(()));
                original_calls += 1;
            }
            let baseline_elapsed = baseline_started.elapsed();
            let memo_started = std::time::Instant::now();
            assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
            let cold_elapsed = memo_started.elapsed();
            let warm_started = std::time::Instant::now();
            for _ in 1..64 {
                assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
            }
            let warm_elapsed = warm_started.elapsed();
            let memo_elapsed = memo_started.elapsed();
            assert_eq!(original_calls, 64);
            assert_eq!(cache.original_transaction_calls.load(Ordering::Relaxed), 1);
            let millis =
                |elapsed: std::time::Duration| elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
            eprintln!(
                "{}",
                serde_json::json!({
                    "schema": "DOM_PUBLIC_RANGE_PROOF_TIMING_V24",
                    "measurement": "pure_public_proof_math_not_swap_latency",
                    "envelope": if capsule { "capsule" } else { "plain" },
                    "iterations": 64,
                    "baseline_native_validator_calls": original_calls,
                    "memo_native_validator_calls": cache.original_transaction_calls.load(Ordering::Relaxed),
                    "baseline_elapsed_ms": millis(baseline_elapsed),
                    "memo_total_elapsed_ms": millis(memo_elapsed),
                    "memo_cold_elapsed_ms": millis(cold_elapsed),
                    "memo_warm_iterations": 63,
                    "memo_warm_elapsed_ms": millis(warm_elapsed),
                    "proof_generation_excluded_from_both_intervals": true,
                })
            );
        }
    }

    #[test]
    fn public_range_proof_cache_mutations_never_reuse_success_or_cache_failure_v24() {
        let cache = PublicProofCacheV24::default();
        let original = output(18, 4, true);
        assert_eq!(verify_output_using(&cache, &original), Ok(true));
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.commitment = output(19, 5, false).commitment;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof[50] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof[dom_crypto::RANGE_PROOF_SIZE + 20] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof.truncate(dom_crypto::RANGE_PROOF_SIZE);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof[dom_crypto::RANGE_PROOF_SIZE] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof[dom_crypto::RANGE_PROOF_SIZE + 14] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.proof.pop();
        mutations.push(changed);
        for changed in mutations {
            let expected = unchanged(&changed);
            assert_ne!(expected, Ok(true));
            let framed = changed.range_proof_bytes().is_ok() && changed.recovery_capsule().is_ok();
            let before = cache.original_output_calls.load(Ordering::Relaxed);
            for _ in 0..2 {
                assert_eq!(verify_output_using(&cache, &changed), expected);
            }
            assert_eq!(
                cache.original_output_calls.load(Ordering::Relaxed),
                before + if framed { 2 } else { 0 }
            );
            assert_eq!(cache.successful.lock().expect("cache").keys.len(), 1);
        }
    }

    #[test]
    fn public_range_proof_cache_transaction_preserves_error_index_order_and_atomic_admission_v24() {
        let cache = PublicProofCacheV24::default();
        let first = output(20, 6, false);
        let next = output(21, 7, true);
        assert_eq!(verify_output_using(&cache, &first), Ok(true));
        let mut invalid = first.clone();
        invalid.proof[50] ^= 1;
        let mut malformed = first.clone();
        malformed.proof.pop();
        for (outputs, rejected_index) in [
            (vec![first.clone(), invalid.clone()], 1),
            (vec![invalid.clone(), malformed], 0),
            (vec![first.clone(), next.clone(), invalid], 2),
        ] {
            let tx = transaction(outputs);
            let expected = dom_consensus::validate_range_proofs(&tx);
            assert!(expected.is_err());
            assert!(expected
                .as_ref()
                .expect_err("invalid native proof")
                .to_string()
                .contains(&format!("output {rejected_index} range proof")));
            assert_eq!(validate_transaction_using(&cache, &tx), expected);
            // Even the valid, uncached `next` cannot be admitted on failure.
            assert_eq!(cache.successful.lock().expect("cache").keys.len(), 1);
        }
        let tx = transaction(vec![first, next]);
        assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
        assert_eq!(cache.successful.lock().expect("cache").keys.len(), 2);
        let calls = cache.original_transaction_calls.load(Ordering::Relaxed);
        assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
        assert_eq!(
            cache.original_transaction_calls.load(Ordering::Relaxed),
            calls
        );
        let empty = transaction(Vec::new());
        assert_eq!(
            validate_transaction_using(&cache, &empty),
            dom_consensus::validate_range_proofs(&empty)
        );
    }

    #[test]
    fn public_range_proof_cache_contention_and_poison_use_original_verifiers_v24() {
        let cache = PublicProofCacheV24::default();
        let output = output(22, 8, false);
        let tx = transaction(vec![output.clone()]);
        assert_eq!(verify_output_using(&cache, &output), Ok(true));
        {
            let _held = cache.successful.lock().expect("held cache");
            assert_eq!(verify_output_using(&cache, &output), Ok(true));
            assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
        }
        assert_eq!(cache.original_output_calls.load(Ordering::Relaxed), 2);
        assert_eq!(cache.original_transaction_calls.load(Ordering::Relaxed), 1);
        let poisoned = std::panic::catch_unwind(|| {
            let _held = cache.successful.lock().expect("cache before poisoning");
            panic!("fixture poisons optimization mutex only");
        });
        assert!(poisoned.is_err());
        assert_eq!(verify_output_using(&cache, &output), Ok(true));
        assert_eq!(validate_transaction_using(&cache, &tx), Ok(()));
        assert_eq!(cache.original_output_calls.load(Ordering::Relaxed), 3);
        assert_eq!(cache.original_transaction_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn public_range_proof_cache_budget_eviction_is_bounded_and_not_a_validation_limit_v24() {
        // Exercise storage mechanics separately, without falsely treating
        // synthetic keys as verified outputs or adding 65 costly proof provers.
        let mut successful = SuccessfulOutputsV24::default();
        for index in 0..=ENTRIES {
            let mut key = vec![0; KEY_BYTES];
            key[0] = index as u8;
            successful.remember_success(key);
        }
        assert_eq!(successful.keys.len(), ENTRIES);
        assert_eq!(successful.bytes, RETAINED_BYTES);
        assert!(successful.bytes <= 60 * 1024);
        assert!(!successful.contains(&vec![0; KEY_BYTES]));
        let oldest_retained = successful.keys.front().expect("retained key").to_vec();
        assert_eq!(oldest_retained[0], 1);
        successful.remember_success(vec![0; KEY_BYTES + 1]);
        assert_eq!(successful.keys.len(), ENTRIES);
        assert_eq!(successful.bytes, RETAINED_BYTES);

        let cache = PublicProofCacheV24::default();
        let output = output(23, 9, false);
        assert_eq!(verify_output_using(&cache, &output), Ok(true));
        // This malformed over-budget transaction must retain the original
        // result. No output-count policy is added by an optimization budget.
        let mut outputs = vec![output; ENTRIES + 1];
        outputs[0].proof.pop();
        let tx = transaction(outputs);
        assert!(transaction_keys(&tx).is_none());
        assert_eq!(
            validate_transaction_using(&cache, &tx),
            dom_consensus::validate_range_proofs(&tx)
        );
        assert_eq!(cache.original_transaction_calls.load(Ordering::Relaxed), 1);
    }
}
