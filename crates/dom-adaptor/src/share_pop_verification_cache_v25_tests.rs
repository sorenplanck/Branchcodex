use super::*;
use crate::{prove_share_knowledge_v1, DirectionV1, SigningShareV1, TrustedChainIdV1};
use std::sync::atomic::Ordering;

fn signing_share(value: u8) -> SigningShareV1 {
    let mut scalar = [0; 32];
    scalar[31] = value;
    SigningShareV1::from_be_bytes(scalar).expect("canonical test-only share")
}

fn statement(variant: usize) -> SharePoPStatementV1 {
    let chain = TrustedChainIdV1::from_signed_fixture([if variant == 1 { 0x12 } else { 0x11 }; 32]);
    let roster = [[if variant == 3 { 0x20 } else { 0x21 }; 32], [0x42; 32]];
    SharePoPStatementV1::new(
        &chain,
        [if variant == 2 { 0x23 } else { 0x22 }; 32],
        &roster,
        if variant == 4 {
            DirectionV1::Responder
        } else {
            DirectionV1::Initiator
        },
        u16::from(variant == 5),
        signing_share(if variant == 6 { 8 } else { 7 })
            .public_key()
            .clone(),
        [if variant == 7 { 0x34 } else { 0x33 }; 32],
        [if variant == 8 { 0x45 } else { 0x44 }; 32],
    )
    .expect("validated public context")
}

fn fixture() -> (SharePoPStatementV1, ShareProofV1) {
    let statement = statement(0);
    // Every new proof gets its own OS-generated nonce through the production
    // prover. Neither the proof generator nor its private state is memoized.
    let proof = prove_share_knowledge_v1(&statement, &signing_share(7))
        .expect("real SharePoK with fresh nonce");
    (statement, proof)
}

fn calls(cache: &CacheV25) -> usize {
    cache.original_calls.load(Ordering::Relaxed)
}

#[test]
fn real_share_pop_cold_plus_warm64_matches_64_original_verifications_v25() {
    let (statement, proof) = fixture();
    let cache = CacheV25::new();
    // Exactly 64 operations per side, with the first memo miss INCLUDED. This
    // measures one public primitive, not proof production or swap completion.
    let memo_started = std::time::Instant::now();
    let cold_started = std::time::Instant::now();
    assert_eq!(verify_using(&cache, &statement, &proof), Ok(true));
    let cold_us = cold_started.elapsed().as_micros();
    let warm_started = std::time::Instant::now();
    for _ in 0..63 {
        assert_eq!(verify_using(&cache, &statement, &proof), Ok(true));
    }
    let warm_63_us = warm_started.elapsed().as_micros();
    let memo_total = memo_started.elapsed();
    assert_eq!(calls(&cache), 1);
    let original_started = std::time::Instant::now();
    let mut original_calls = 0;
    for _ in 0..64 {
        original_calls += 1;
        assert_eq!(
            verify_share_knowledge_uncached_v25(&statement, &proof),
            Ok(true)
        );
    }
    let original_total = original_started.elapsed();
    assert_eq!(original_calls, 64);
    eprintln!(
        "DOM_SHARE_POP_VERIFICATION_TIMING_V25 {{\"scope\":\"primitive_only\",\"original_iterations\":64,\"cache_iterations\":64,\"original_calls\":{original_calls},\"cache_original_calls\":{},\"cold_us\":{cold_us},\"warm_63_us\":{warm_63_us},\"cache_total_us\":{},\"cache_total_ms\":{},\"original_total_us\":{},\"original_total_ms\":{}}}",
        calls(&cache), memo_total.as_micros(), memo_total.as_millis(),
        original_total.as_micros(), original_total.as_millis(),
    );
    // Exercise the shipped wrapper too, without using its global cache to
    // measure any local counter or cold/warm boundary.
    assert_eq!(
        crate::verify_share_knowledge_v1(&statement, &proof),
        Ok(true)
    );
}

#[test]
fn every_statement_operand_and_proof_mutation_matches_original_v25() {
    let (original, proof) = fixture();
    let cache = CacheV25::new();
    assert_eq!(verify_using(&cache, &original, &proof), Ok(true));
    for variant in 1..=8 {
        let changed = statement(variant);
        let expected = verify_share_knowledge_uncached_v25(&changed, &proof);
        assert_eq!(expected, Ok(false));
        let before = calls(&cache);
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, &changed, &proof), expected);
        }
        assert_eq!(calls(&cache), before + 2);
    }
    let mut changed_commitment = proof.clone();
    changed_commitment.commitment = signing_share(19).public_key().clone();
    let mut changed_response = proof.clone();
    changed_response.response = [0; 32];
    for changed in [changed_commitment, changed_response] {
        let changed = ShareProofV1::from_bytes(&changed.to_bytes())
            .expect("changed operands remain canonically parseable");
        let expected = verify_share_knowledge_uncached_v25(&original, &changed);
        assert_eq!(expected, Ok(false));
        let before = calls(&cache);
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, &original, &changed), expected);
        }
        assert_eq!(calls(&cache), before + 2);
    }
    assert_eq!(cache.successful.lock().unwrap().len, 1);

    // Every encoded byte is copied into the key, including framing. Internal
    // mutation is test-only; the shipped constructors still reject bad framing.
    let original_key = exact_equation(&original, &proof);
    for index in 0..SharePoPStatementV1::ENCODED_LEN {
        let mut changed = original.clone();
        changed.bytes[index] ^= 1;
        assert_ne!(exact_equation(&changed, &proof), original_key);
    }
    let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
    let roster = [[0x21; 32], [0x42; 32]];
    for index in [0, 4, 102, 104] {
        let mut invalid = original.to_bytes();
        invalid[index] = 0xff;
        assert!(SharePoPStatementV1::from_bytes(&invalid, &chain, &roster).is_err());
    }
    assert!(SharePoPStatementV1::from_bytes(&original.to_bytes()[..201], &chain, &roster).is_err());
    assert!(ShareProofV1::from_bytes(&proof.to_bytes()[..64]).is_err());
    assert!(ShareProofV1::from_bytes(&[0; 65]).is_err());
}

#[test]
fn identical_statement_bytes_with_another_authenticated_roster_cannot_hit_v25() {
    let (original, proof) = fixture();
    let cache = CacheV25::new();
    assert_eq!(verify_using(&cache, &original, &proof), Ok(true));
    let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
    let changed_roster = [[0x21; 32], [0x43; 32]];
    let changed = SharePoPStatementV1::from_bytes(&original.to_bytes(), &chain, &changed_roster)
        .expect("same local participant, another valid authenticated peer");
    assert_eq!(changed.to_bytes(), original.to_bytes());
    assert_eq!(changed.participant_index(), original.participant_index());
    assert_eq!(changed.participant_id(), original.participant_id());
    assert_ne!(changed.roster_digest, original.roster_digest);
    assert_ne!(
        exact_equation(&changed, &proof),
        exact_equation(&original, &proof)
    );
    assert!(changed
        .require_authenticated_roster_v22(&[[0x21; 32], [0x42; 32]])
        .is_err());
    changed
        .require_authenticated_roster_v22(&changed_roster)
        .expect("new exact roster");
    assert_eq!(
        verify_share_knowledge_uncached_v25(&changed, &proof),
        Ok(false)
    );
    let before = calls(&cache);
    for _ in 0..2 {
        assert_eq!(verify_using(&cache, &changed, &proof), Ok(false));
    }
    assert_eq!(calls(&cache), before + 2);
    assert_eq!(cache.successful.lock().unwrap().len, 1);
}

#[test]
fn actual_public_point_operand_is_not_replaced_by_encoded_statement_bytes_v25() {
    let (original, proof) = fixture();
    let cache = CacheV25::new();
    assert_eq!(verify_using(&cache, &original, &proof), Ok(true));
    // Defensive test of the exact primitive boundary, using private-field
    // access available only to this descendant unit-test module. Public
    // constructors cannot create this encoded/actual-point inconsistency.
    let mut changed = original.clone();
    changed.share_point = signing_share(13).public_key().clone();
    assert_eq!(changed.to_bytes(), original.to_bytes());
    assert_eq!(changed.roster_digest, original.roster_digest);
    assert_ne!(
        exact_equation(&changed, &proof),
        exact_equation(&original, &proof)
    );
    let expected = verify_share_knowledge_uncached_v25(&changed, &proof);
    assert_eq!(expected, Ok(false));
    let before = calls(&cache);
    for _ in 0..2 {
        assert_eq!(verify_using(&cache, &changed, &proof), expected);
    }
    assert_eq!(calls(&cache), before + 2);
    assert_eq!(cache.successful.lock().unwrap().len, 1);
}

#[test]
fn false_and_original_backend_errors_never_enter_success_cache_v25() {
    let (statement, proof) = fixture();
    let cache = CacheV25::new();
    let mut false_proof = proof.clone();
    false_proof.response = [0; 32];
    assert!(ShareProofV1::from_bytes(&false_proof.to_bytes()).is_ok());
    assert_eq!(
        verify_share_knowledge_uncached_v25(&statement, &false_proof),
        Ok(false)
    );
    // Noncanonical response is impossible through the public parser. Inject
    // it only here to prove the backend's exact error remains uncached too.
    let mut invalid_proof = proof.clone();
    invalid_proof.response = [0xff; 32];
    assert!(ShareProofV1::from_bytes(&invalid_proof.to_bytes()).is_err());
    let rejected = verify_share_knowledge_uncached_v25(&statement, &invalid_proof);
    assert!(rejected.is_err());
    for _ in 0..2 {
        assert_eq!(verify_using(&cache, &statement, &false_proof), Ok(false));
        assert_eq!(verify_using(&cache, &statement, &invalid_proof), rejected);
    }
    assert_eq!(calls(&cache), 4);
    assert_eq!(cache.successful.lock().unwrap().len, 0);
    assert_eq!(verify_using(&cache, &statement, &proof), Ok(true));
    assert_eq!(verify_using(&cache, &statement, &proof), Ok(true));
    assert_eq!(calls(&cache), 5);
    assert_eq!(cache.successful.lock().unwrap().len, 1);
}

#[test]
fn fixed_capacity_evicts_only_successes_and_rechecks_old_equations_v25() {
    let statement = statement(0);
    let cache = CacheV25::new();
    let mut proofs = Vec::new();
    for _ in 0..=CAPACITY {
        let proof = prove_share_knowledge_v1(&statement, &signing_share(7))
            .expect("fresh proof nonce for each independent public proof");
        assert!(proofs.iter().all(|prior: &ShareProofV1| prior != &proof));
        assert_eq!(verify_using(&cache, &statement, &proof), Ok(true));
        proofs.push(proof);
    }
    assert_eq!(calls(&cache), CAPACITY + 1);
    {
        let successful = cache.successful.lock().unwrap();
        assert_eq!(successful.len, CAPACITY);
        assert_eq!(successful.entries.iter().flatten().count(), CAPACITY);
        assert!(!successful.contains(&exact_equation(&statement, &proofs[0])));
        assert!(successful.contains(&exact_equation(&statement, &proofs[CAPACITY])));
    }
    assert!(!std::mem::needs_drop::<ExactEquationV25>());
    assert!(std::mem::size_of::<SuccessesV25>() <= CAPACITY * (KEY_BYTES + 1) + 32);
    assert!(std::mem::size_of::<CacheV25>() <= CAPACITY * (KEY_BYTES + 1) + 128);
    assert_eq!(
        verify_using(&cache, &statement, &proofs[CAPACITY]),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 1);
    assert_eq!(verify_using(&cache, &statement, &proofs[0]), Ok(true));
    assert_eq!(calls(&cache), CAPACITY + 2);
    assert_eq!(
        verify_using(&cache, &statement, &proofs[CAPACITY]),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 2);
}

#[test]
fn contention_and_poison_fall_back_to_original_without_waiting_v25() {
    let (statement, proof) = fixture();
    let busy = CacheV25::new();
    assert_eq!(verify_using(&busy, &statement, &proof), Ok(true));
    let held = busy.successful.lock().unwrap();
    for _ in 0..2 {
        assert_eq!(verify_using(&busy, &statement, &proof), Ok(true));
    }
    assert_eq!(calls(&busy), 3);
    assert_eq!(held.len, 1);
    drop(held);
    assert_eq!(verify_using(&busy, &statement, &proof), Ok(true));
    assert_eq!(calls(&busy), 3);

    let poisoned = CacheV25::new();
    assert_eq!(verify_using(&poisoned, &statement, &proof), Ok(true));
    let result = std::panic::catch_unwind(|| {
        let _held = poisoned.successful.lock().unwrap();
        panic!("intentional test-only public equation cache poison");
    });
    assert!(result.is_err());
    assert!(poisoned.successful.is_poisoned());
    for _ in 0..2 {
        assert_eq!(verify_using(&poisoned, &statement, &proof), Ok(true));
    }
    assert_eq!(calls(&poisoned), 3);
}
