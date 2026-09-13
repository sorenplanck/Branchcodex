use super::*;
use crate::TrustedChainIdV1;
use dom_core::Hash256;
use std::sync::atomic::Ordering;

struct Fixture {
    statement: BpStatementV1,
    proof: RangeProof739,
    extra: Vec<u8>,
}

fn signing_share(value: u8) -> SigningShareV1 {
    let mut scalar = [0; 32];
    scalar[31] = value;
    SigningShareV1::from_be_bytes(scalar).unwrap()
}

fn statement(extra: &[u8], variant: usize) -> Result<BpStatementV1> {
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        0x112233,
        &Hash256::from_bytes([if variant == 1 { 12 } else { 11 }; 32]),
    );
    let shares = vec![
        signing_share(if variant == 5 { 4 } else { 3 })
            .public_key()
            .clone(),
        signing_share(5).public_key().clone(),
    ];
    let value = if variant == 4 { 43 } else { 42 };
    let aggregate = BpStatementV1::aggregate_commitment_from_shares(&shares, value)?;
    BpStatementV1::new(
        &chain,
        [if variant == 2 { 23 } else { 22 }; 32],
        vec![[31; 32], [if variant == 3 { 33 } else { 32 }; 32]],
        value,
        shares,
        aggregate,
        Some(*blake2b_256(extra).as_bytes()),
    )
}

fn produce(extra: Vec<u8>) -> Result<Fixture> {
    let statement = statement(&extra, 0)?;
    let a = DomCollaborativeRangeProofV1::new(&statement, extra.clone())?;
    let b = DomCollaborativeRangeProofV1::new(&statement, extra.clone())?;
    let (pending_a, commitment_a) = PendingCommonNonce::new(&statement, 0, &signing_share(3))?;
    let (pending_b, commitment_b) = PendingCommonNonce::new(&statement, 1, &signing_share(5))?;
    let reveal_a = pending_a.reveal_bytes();
    let reveal_b = pending_b.reveal_bytes();
    let commitments = [commitment_a, commitment_b];
    let local_a = pending_a.finish(
        &statement,
        &commitments,
        vec![reveal_a.clone(), reveal_b.clone()],
    )?;
    let local_b = pending_b.finish(&statement, &commitments, vec![reveal_a, reveal_b])?;
    let r1a = a.round1(&statement, &local_a)?;
    let r1b = b.round1(&statement, &local_b)?;
    let r1 = AggregateBpRound1::new(
        &statement,
        &[r1a.reveal_commitment(), r1b.reveal_commitment()],
        &[r1a, r1b],
    )?;
    // Fresh one-shot production mathematics; no finalizer/share is cached.
    let r2 = AggregateBpRound2::new(
        &statement,
        vec![
            a.round2(&statement, &local_a, &r1)?,
            b.round2(&statement, &local_b, &r1)?,
        ],
    )?;
    let proof = b.finalize(&statement, &r1, &r2)?;
    assert!(b.finalize(&statement, &r1, &r2).is_err());
    Ok(Fixture {
        statement,
        proof,
        extra,
    })
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    // Raw extra_commit is intentionally not RecoveryCapsule framing: the
    // original BP API supports this, and the memo must not narrow that API.
    FIXTURE.get_or_init(|| produce(vec![0x5a; 96]).expect("real two-party proof"))
}

#[test]
fn native_two_party_final_proof_cold_warm_repeat64_matches_original_v25() -> Result<()> {
    let f = fixture();
    let driver = DomCollaborativeRangeProofV1::new(&f.statement, f.extra.clone())?;
    let cache = CacheV25::default();
    // Compare exactly 64 calls on each side, including the cache's cold miss.
    // Fixture construction is outside both measurements; this is primitive
    // verification only, not ceremony, persistence or end-to-end latency.
    let cache_started = std::time::Instant::now();
    let cold_started = std::time::Instant::now();
    assert_eq!(
        verify_using(&cache, &driver, &f.statement, &f.proof),
        Ok(())
    );
    let cold_us = cold_started.elapsed().as_micros();
    let warm_started = std::time::Instant::now();
    for _ in 0..63 {
        assert_eq!(
            verify_using(&cache, &driver, &f.statement, &f.proof),
            Ok(())
        );
    }
    let warm_63_us = warm_started.elapsed().as_micros();
    let cache_total = cache_started.elapsed();
    let cache_original_calls = cache.original_calls.load(Ordering::Relaxed);
    assert_eq!(cache_original_calls, 1);
    let original_started = std::time::Instant::now();
    let mut original_calls = 0;
    for _ in 0..64 {
        original_calls += 1;
        assert_eq!(
            driver.verify_final_uncached_v25(&f.statement, &f.proof),
            Ok(())
        );
    }
    let original_total = original_started.elapsed();
    assert_eq!(original_calls, 64);
    eprintln!(
        "DOM_COLLABORATIVE_FINAL_PROOF_TIMING_V25 {{\"scope\":\"primitive_only\",\"original_iterations\":64,\"cache_iterations\":64,\"original_calls\":{original_calls},\"cache_original_calls\":{cache_original_calls},\"cold_us\":{cold_us},\"warm_63_us\":{warm_63_us},\"cache_total_us\":{},\"cache_total_ms\":{},\"original_total_us\":{},\"original_total_ms\":{}}}",
        cache_total.as_micros(),
        cache_total.as_millis(),
        original_total.as_micros(),
        original_total.as_millis(),
    );
    Ok(())
}

#[test]
fn full_statement_scope_proof_and_raw_extra_mutations_match_original_v25() -> Result<()> {
    let f = fixture();
    let cache = CacheV25::default();
    let original_driver = DomCollaborativeRangeProofV1::new(&f.statement, f.extra.clone())?;
    verify_using(&cache, &original_driver, &f.statement, &f.proof)?;
    for variant in 1..=5 {
        let changed = statement(&f.extra, variant)?;
        // Driver scope remains mandatory even after the mathematical proof hit.
        assert_eq!(
            verify_using(&cache, &original_driver, &changed, &f.proof),
            Err(AdaptorError::AuthorizationMismatch)
        );
        let driver = DomCollaborativeRangeProofV1::new(&changed, f.extra.clone())?;
        let expected = driver.verify_final_uncached_v25(&changed, &f.proof);
        let before = cache.original_calls.load(Ordering::Relaxed);
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, &driver, &changed, &f.proof), expected);
        }
        assert_eq!(
            cache.original_calls.load(Ordering::Relaxed),
            before + if expected.is_ok() { 1 } else { 2 }
        );
    }
    for index in [0, RANGE_PROOF_SIZE / 2, RANGE_PROOF_SIZE - 1] {
        let mut bytes = *f.proof.as_bytes();
        bytes[index] ^= 1;
        let bad = RangeProof739::try_from(bytes.as_slice())?;
        let expected = original_driver.verify_final_uncached_v25(&f.statement, &bad);
        assert!(expected.is_err());
        let before = cache.original_calls.load(Ordering::Relaxed);
        for _ in 0..2 {
            assert_eq!(
                verify_using(&cache, &original_driver, &f.statement, &bad),
                expected
            );
        }
        assert_eq!(cache.original_calls.load(Ordering::Relaxed), before + 2);
    }
    let mut extra = f.extra.clone();
    extra[0] ^= 1;
    assert!(DomCollaborativeRangeProofV1::new(&f.statement, extra.clone()).is_err());
    let changed = statement(&extra, 0)?;
    let driver = DomCollaborativeRangeProofV1::new(&changed, extra)?;
    let expected = driver.verify_final_uncached_v25(&changed, &f.proof);
    assert!(expected.is_err());
    let before = cache.original_calls.load(Ordering::Relaxed);
    for _ in 0..2 {
        assert_eq!(verify_using(&cache, &driver, &changed, &f.proof), expected);
    }
    assert_eq!(cache.original_calls.load(Ordering::Relaxed), before + 2);
    Ok(())
}

#[test]
fn successful_cache_is_bounded_and_evicted_context_reexecutes_original_v25() -> Result<()> {
    let f = fixture();
    let cache = CacheV25::default();
    // The original proof math binds commitment + extra_commit, not session ID.
    // Every session below has its own correctly bound driver; the full-key memo
    // still conservatively rechecks it once. No new proof or authority is forged.
    let chain =
        TrustedChainIdV1::from_authenticated_genesis(0x112233, &Hash256::from_bytes([11; 32]));
    for index in 0..=ENTRIES {
        let mut bytes = f.statement.to_bytes().to_vec();
        bytes[38] = u8::try_from(index).unwrap();
        let changed = BpStatementV1::from_bytes(&bytes, &chain)?;
        let driver = DomCollaborativeRangeProofV1::new(&changed, f.extra.clone())?;
        driver.verify_final_uncached_v25(&changed, &f.proof)?;
        verify_using(&cache, &driver, &changed, &f.proof)?;
    }
    let keys = cache.keys.lock().unwrap();
    assert_eq!(keys.len(), ENTRIES);
    assert!(keys.iter().all(|key| key.len() <= KEY_BYTES));
    assert!(keys.iter().map(|key| key.len()).sum::<usize>() <= ENTRIES * KEY_BYTES);
    drop(keys);
    let mut bytes = f.statement.to_bytes().to_vec();
    bytes[38] = 0;
    let oldest = BpStatementV1::from_bytes(&bytes, &chain)?;
    let driver = DomCollaborativeRangeProofV1::new(&oldest, f.extra.clone())?;
    let before = cache.original_calls.load(Ordering::Relaxed);
    verify_using(&cache, &driver, &oldest, &f.proof)?;
    assert_eq!(cache.original_calls.load(Ordering::Relaxed), before + 1);
    Ok(())
}

#[test]
fn oversized_valid_extra_commit_falls_back_and_framing_never_bypasses_v25() -> Result<()> {
    let f = produce(vec![0x6b; EXTRA_BYTES + 1])?;
    let driver = DomCollaborativeRangeProofV1::new(&f.statement, f.extra.clone())?;
    let cache = CacheV25::default();
    assert!(key(&f.statement, &f.proof, &f.extra).is_none());
    for _ in 0..2 {
        verify_using(&cache, &driver, &f.statement, &f.proof)?;
    }
    assert_eq!(cache.original_calls.load(Ordering::Relaxed), 2);
    assert!(cache.keys.lock().unwrap().is_empty());
    for length in [0, 1, RANGE_PROOF_SIZE - 1, RANGE_PROOF_SIZE + 1] {
        assert!(RangeProof739::try_from(vec![0; length].as_slice()).is_err());
    }
    Ok(())
}

#[test]
fn poisoned_or_busy_cache_reexecutes_original_without_reusing_finalizer_v25() -> Result<()> {
    let f = fixture();
    let driver = DomCollaborativeRangeProofV1::new(&f.statement, f.extra.clone())?;
    let cache = CacheV25::default();
    verify_using(&cache, &driver, &f.statement, &f.proof)?;
    let guard = cache.keys.lock().unwrap();
    verify_using(&cache, &driver, &f.statement, &f.proof)?;
    drop(guard);
    let _ = std::panic::catch_unwind(|| {
        let _guard = cache.keys.lock().unwrap();
        panic!("test-only public proof cache poison");
    });
    verify_using(&cache, &driver, &f.statement, &f.proof)?;
    assert_eq!(cache.original_calls.load(Ordering::Relaxed), 3);
    assert!(driver.finalizer.lock().unwrap().is_none());
    Ok(())
}
