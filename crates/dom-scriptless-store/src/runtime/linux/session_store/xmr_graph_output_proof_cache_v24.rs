//! Volatile, exact-public-input mathematical-result memoization, not authority.
//! No filesystem metadata, revision, nonce, lease or chain observation is cached.
use std::{collections::VecDeque, sync::Mutex};

const CAPACITY: usize = 8;
const MAX_KEY_BYTES: usize = super::MAX_BYTES + 4096;
const DOMAIN: &[u8] = b"DOM/XMR/public-output-proof-cache/V24";

// Private generic mechanics permit cheap counting regressions without creating
// cryptographic ceremonies. The sole production instantiation stores only the
// VerifiedSharedOutput returned by the unchanged two verifiers in the parent.
pub(super) struct ExactProofCacheV24<T> {
    entries: VecDeque<(Vec<u8>, T)>,
}

impl<T> ExactProofCacheV24<T> {
    pub(super) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }
}

pub(super) fn key(
    statement: &[u8],
    capsule: &[u8],
    payloads: &[&[u8]],
    commitment: &[u8; 33],
) -> Option<Vec<u8>> {
    if payloads.len() != 11 {
        return None;
    }
    let fields = std::iter::once(statement)
        .chain(std::iter::once(capsule))
        .chain(payloads.iter().copied())
        .chain(std::iter::once(commitment.as_slice()));
    let mut length = DOMAIN.len();
    for field in fields.clone() {
        length = length.checked_add(8)?.checked_add(field.len())?;
        if length > MAX_KEY_BYTES {
            return None;
        }
    }
    let mut key = Vec::with_capacity(length);
    key.extend_from_slice(DOMAIN);
    for field in fields {
        key.extend_from_slice(&u64::try_from(field.len()).ok()?.to_le_bytes());
        key.extend_from_slice(field);
    }
    Some(key)
}

pub(super) fn verified<T: Clone, E>(
    cache: &Mutex<ExactProofCacheV24<T>>,
    key: Option<Vec<u8>>,
    verify: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let Some(key) = key.filter(|key| key.len() <= MAX_KEY_BYTES) else {
        return verify();
    };
    // Never hold this lock across cryptography; neither contention nor poison
    // can skip verification or prevent recovery. Simultaneous misses may work
    // twice, but cannot grant an unverified result.
    if let Ok(cache) = cache.try_lock() {
        if let Some((_, value)) = cache.entries.iter().find(|(retained, _)| *retained == key) {
            return Ok(value.clone());
        }
    }
    let value = verify()?;
    if let Ok(mut cache) = cache.try_lock() {
        if !cache.entries.iter().any(|(retained, _)| *retained == key) {
            if cache.entries.len() == CAPACITY {
                cache.entries.pop_front();
            }
            cache.entries.push_back((key, value.clone()));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // One real collaborative BP ceremony, no network, Store reopening or
    // fabricated VerifiedSharedOutput. The fresh cache makes the cold path
    // unconditional even when other tests warmed the process-wide cache.
    #[test]
    fn real_output_cold_warm_and_all_public_mutations_match_original_v24(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use super::super::super::evidence_only_staging::{
            record_with_session_and_terms_hash, EarlyTransportTestFixture,
            PreparedOperationalBpPayloads,
        };
        use super::super::{
            verify_public_output_uncached_v24, BpStatementV1, RecoveryCapsule, SessionPhaseV1,
        };
        let initial =
            record_with_session_and_terms_hash([23; 32], SessionPhaseV1::Created, [24; 32])?;
        let fixture = EarlyTransportTestFixture::new_signing_compatible(&initial, true)?;
        let bp = PreparedOperationalBpPayloads::new(&initial, &fixture)?;
        let commitment = bp.statement.aggregate_commitment().to_compressed_bytes();
        let cache = Mutex::new(ExactProofCacheV24::new());
        let calls = Cell::new(0usize);
        let check = |statement: &BpStatementV1,
                     capsule: &RecoveryCapsule,
                     messages: &[Vec<u8>],
                     commitment: &[u8; 33]| {
            let payloads: Vec<_> = messages.iter().map(Vec::as_slice).collect();
            verified(
                &cache,
                key(
                    statement.to_bytes(),
                    capsule.as_bytes(),
                    &payloads,
                    commitment,
                ),
                || {
                    calls.set(calls.get() + 1);
                    verify_public_output_uncached_v24(statement, capsule, &payloads, commitment)
                },
            )
        };
        let refs: Vec<_> = bp.messages.iter().map(Vec::as_slice).collect();
        let original = verify_public_output_uncached_v24(
            &bp.statement,
            &fixture.recovery_capsule,
            &refs,
            &commitment,
        )?;
        assert_eq!(
            check(
                &bp.statement,
                &fixture.recovery_capsule,
                &bp.messages,
                &commitment
            )?,
            original
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            check(
                &bp.statement,
                &fixture.recovery_capsule,
                &bp.messages,
                &commitment
            )?,
            original
        );
        assert_eq!(calls.get(), 1);

        // Measures this BP reconstruction layer, not end-to-end latency or an
        // entirely cache-free primitive baseline. Its output constructor may
        // independently reuse a public range-proof result. The counter names
        // below count this layer's verifier invocations, never scalar operations.
        // Assertions cover exact outputs and execution counts, never wall time.
        let warm_started = std::time::Instant::now();
        for _ in 0..64 {
            assert_eq!(
                check(
                    &bp.statement,
                    &fixture.recovery_capsule,
                    &bp.messages,
                    &commitment
                )?,
                original
            );
        }
        let warm_elapsed = warm_started.elapsed();
        assert_eq!(calls.get(), 1);
        let original_started = std::time::Instant::now();
        let mut original_calls = 0;
        for _ in 0..64 {
            original_calls += 1;
            assert_eq!(
                verify_public_output_uncached_v24(
                    &bp.statement,
                    &fixture.recovery_capsule,
                    &refs,
                    &commitment
                )?,
                original
            );
        }
        assert_eq!(original_calls, 64);
        eprintln!(
            "public BP reconstruction layer: uncached_bp_layer_calls={original_calls}, cached_cold_bp_layer_calls={}, repetitions=64, uncached_bp_layer_ms={}, warm_bp_layer_ms={}",
            calls.get(), original_started.elapsed().as_millis(), warm_elapsed.as_millis()
        );

        for field in 0..14 {
            let mut statement_bytes = bp.statement.to_bytes().to_vec();
            let mut capsule_bytes = fixture.recovery_capsule.as_bytes().to_vec();
            let mut messages = bp.messages.clone();
            let mut expected = commitment;
            match field {
                0 => statement_bytes[38] ^= 1, // canonical but different session
                1 => *capsule_bytes.last_mut().unwrap() ^= 1,
                2..=12 => messages[field - 2][0] ^= 1,
                13 => expected = fixture.signing_shares[0].public_key().to_compressed_bytes(),
                _ => unreachable!(),
            }
            let statement = BpStatementV1::from_bytes(&statement_bytes, &fixture.trusted_chain_id)?;
            let capsule = RecoveryCapsule::from_bytes(&capsule_bytes)?;
            let refs: Vec<_> = messages.iter().map(Vec::as_slice).collect();
            let original_error =
                verify_public_output_uncached_v24(&statement, &capsule, &refs, &expected)
                    .unwrap_err();
            let before = calls.get();
            for _ in 0..2 {
                let error = check(&statement, &capsule, &messages, &expected).unwrap_err();
                assert_eq!(
                    std::mem::discriminant(&error),
                    std::mem::discriminant(&original_error)
                );
            }
            assert_eq!(
                calls.get(),
                before + 2,
                "invalid input must never warm field {field}"
            );
            assert_eq!(cache.lock().unwrap().entries.len(), 1);
        }
        assert_eq!(
            check(
                &bp.statement,
                &fixture.recovery_capsule,
                &bp.messages,
                &commitment
            )?,
            original
        );
        Ok(())
    }

    fn example_key() -> Vec<u8> {
        key(
            b"statement",
            b"capsule",
            &[b"payload".as_slice(); 11],
            &[7; 33],
        )
        .unwrap()
    }

    #[test]
    fn cold_executes_and_warm_reuses_only_exact_success_v24() {
        let cache = Mutex::new(ExactProofCacheV24::new());
        let calls = Cell::new(0);
        for _ in 0..2 {
            let result: Result<_, ()> = verified(&cache, Some(example_key()), || {
                calls.set(calls.get() + 1);
                Ok(vec![1, 2, 3])
            });
            assert_eq!(result.unwrap(), vec![1, 2, 3]);
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn every_public_input_and_field_boundary_changes_key_v24() {
        let original = example_key();
        for field in 0..14 {
            let mut fields: Vec<Vec<u8>> = [b"statement".as_slice(), b"capsule"]
                .into_iter()
                .chain([b"payload".as_slice(); 11])
                .map(Vec::from)
                .collect();
            let mut commitment = [7; 33];
            if field == 13 {
                commitment[0] ^= 1;
            } else {
                fields[field][0] ^= 1;
            }
            let payloads: Vec<&[u8]> = fields[2..].iter().map(Vec::as_slice).collect();
            let changed = key(&fields[0], &fields[1], &payloads, &commitment).unwrap();
            assert_ne!(changed, original);
            let cache = Mutex::new(ExactProofCacheV24::new());
            assert_eq!(
                verified(&cache, Some(original.clone()), || Ok::<_, ()>(1)),
                Ok(1)
            );
            assert_eq!(
                verified(&cache, Some(changed), || Err::<u8, _>("changed")),
                Err("changed")
            );
        }
        assert_ne!(
            key(b"a", b"bc", &[b"x".as_slice(); 11], &[7; 33]),
            key(b"ab", b"c", &[b"x".as_slice(); 11], &[7; 33])
        );
    }

    #[test]
    fn failures_are_never_memoized_v24() {
        let cache = Mutex::new(ExactProofCacheV24::new());
        let calls = Cell::new(0);
        for _ in 0..2 {
            assert_eq!(
                verified(&cache, Some(example_key()), || {
                    calls.set(calls.get() + 1);
                    Err::<u8, _>("invalid")
                }),
                Err("invalid")
            );
        }
        assert_eq!(calls.get(), 2);
        assert!(cache.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn bounded_fifo_eviction_and_oversize_fall_back_v24() {
        let cache = Mutex::new(ExactProofCacheV24::new());
        for index in 0..=CAPACITY {
            assert_eq!(
                verified(&cache, Some(vec![index as u8]), || Ok::<_, ()>(index)),
                Ok(index)
            );
        }
        assert_eq!(cache.lock().unwrap().entries.len(), CAPACITY);
        assert_eq!(verified(&cache, Some(vec![0]), || Ok::<_, ()>(99)), Ok(99));
        assert!(key(
            &vec![0; MAX_KEY_BYTES],
            b"",
            &[b"x".as_slice(); 11],
            &[7; 33]
        )
        .is_none());
        assert!(key(b"s", b"c", &[b"x".as_slice(); 10], &[7; 33]).is_none());
        assert_eq!(
            verified(&cache, None, || Err::<usize, _>("verify")),
            Err("verify")
        );
    }

    #[test]
    fn contention_and_poison_use_original_verifier_v24() {
        let cache = Mutex::new(ExactProofCacheV24::new());
        assert_eq!(
            verified(&cache, Some(example_key()), || Ok::<_, ()>(1)),
            Ok(1)
        );
        let guard = cache.lock().unwrap();
        assert_eq!(
            verified(&cache, Some(example_key()), || Err::<u8, _>("contended")),
            Err("contended")
        );
        drop(guard);
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.lock().unwrap();
            panic!("test-only cache poison");
        });
        assert_eq!(
            verified(&cache, Some(example_key()), || Err::<u8, _>("poisoned")),
            Err("poisoned")
        );
    }
}
