//! Real public partial equations, with isolated cache instances and fresh
//! test-only signing nonces. Measurements cover one verifier, not a swap.
use super::*;
use dom_crypto::{schnorr_add_public_keys, schnorr_partial_sign, PartialSig, SecretKey};
use rand_core::{OsRng, RngCore};
use std::sync::atomic::Ordering;

fn secret(value: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    SecretKey::from_bytes(&bytes).expect("canonical test key")
}

fn fresh_nonce() -> SecretKey {
    let mut bytes = zeroize::Zeroizing::new([0; 32]);
    for _ in 0..128 {
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .expect("test OS randomness");
        if let Ok(nonce) = SecretKey::from_bytes(bytes.as_ref()) {
            return nonce;
        }
    }
    panic!("bounded test nonce sampling exhausted")
}

struct Fixture {
    partial: PartialSignatureV1,
    bound_nonce: PublicKey,
    participant_key: PublicKey,
    aggregate_nonce: PublicKey,
    aggregate_key: PublicKey,
    chain: [u8; 32],
    message: Vec<u8>,
    template: [u8; 32],
}

impl Fixture {
    fn new(message: &[u8]) -> Self {
        let participant = secret(7);
        let nonce = fresh_nonce();
        let participant_key = participant.public_key();
        let bound_nonce = nonce.public_key();
        let aggregate_key =
            schnorr_add_public_keys(&[participant_key.clone(), secret(11).public_key()])
                .expect("two public participant keys");
        let aggregate_nonce =
            schnorr_add_public_keys(&[bound_nonce.clone(), fresh_nonce().public_key()])
                .expect("two public nonce points");
        let chain = [0x15; 32];
        let template = [0x26; 32];
        let partial = schnorr_partial_sign(
            &participant,
            &nonce,
            &aggregate_nonce,
            &aggregate_key,
            &chain,
            message,
        )
        .expect("real DOM partial equation");
        // Private keys/nonces drop here. Only public verification operands are
        // retained in this fixture and, independently, the bounded memo.
        Self {
            partial: PartialSignatureV1::new(PurposeV1::Funding, 0, template, partial),
            bound_nonce,
            participant_key,
            aggregate_nonce,
            aggregate_key,
            chain,
            message: message.to_vec(),
            template,
        }
    }

    fn operands(&self) -> OperandsV25<'_> {
        OperandsV25 {
            partial: &self.partial,
            expected_purpose: PurposeV1::Funding,
            expected_template_hash: &self.template,
            bound_public_nonce: &self.bound_nonce,
            participant_key: &self.participant_key,
            aggregate_nonce_hat: &self.aggregate_nonce,
            aggregate_signing_key: &self.aggregate_key,
            chain_id: &self.chain,
            kernel_message: &self.message,
        }
    }
}

fn calls(cache: &CacheV25) -> usize {
    cache.original_calls.load(Ordering::Relaxed)
}

fn shipped(operands: OperandsV25<'_>) -> Result<bool> {
    verify(
        operands.partial,
        operands.expected_purpose,
        operands.expected_template_hash,
        operands.bound_public_nonce,
        operands.participant_key,
        operands.aggregate_nonce_hat,
        operands.aggregate_signing_key,
        operands.chain_id,
        operands.kernel_message,
    )
}

#[test]
fn real_bound_partial_cold_plus_warm64_matches_64_original_verifications_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let cache = CacheV25::new();
    let operands = fixture.operands();
    let memo_started = std::time::Instant::now();
    let cold_started = std::time::Instant::now();
    assert_eq!(verify_using(&cache, operands), Ok(true));
    let cold_us = cold_started.elapsed().as_micros();
    let warm_started = std::time::Instant::now();
    for _ in 0..63 {
        assert_eq!(verify_using(&cache, operands), Ok(true));
    }
    let warm_63_us = warm_started.elapsed().as_micros();
    let memo_total = memo_started.elapsed();
    assert_eq!(calls(&cache), 1);
    let original_started = std::time::Instant::now();
    let mut original_calls = 0;
    for _ in 0..64 {
        original_calls += 1;
        assert_eq!(operands.original(), Ok(true));
    }
    let original_total = original_started.elapsed();
    assert_eq!(original_calls, 64);
    eprintln!(
        "DOM_BOUND_PARTIAL_VERIFICATION_TIMING_V25 {{\"scope\":\"primitive_only\",\"original_iterations\":64,\"cache_iterations\":64,\"original_calls\":{original_calls},\"cache_original_calls\":{},\"cold_us\":{cold_us},\"warm_63_us\":{warm_63_us},\"cache_total_us\":{},\"cache_total_ms\":{},\"original_total_us\":{},\"original_total_ms\":{}}}",
        calls(&cache), memo_total.as_micros(), memo_total.as_millis(),
        original_total.as_micros(), original_total.as_millis(),
    );
    assert_eq!(shipped(operands), Ok(true));
}

#[test]
fn every_public_partial_equation_operand_matches_original_on_mutation_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let cache = CacheV25::new();
    let original = fixture.operands();
    assert_eq!(verify_using(&cache, original), Ok(true));
    let other_point = secret(29).public_key();
    let other_chain = [0x16; 32];
    let other_message = [0x38; 32];
    let wrong_scalar = PartialSignatureV1::new(
        PurposeV1::Funding,
        0,
        fixture.template,
        PartialSig::from_bytes(&secret(1).to_be_bytes_raw())
            .expect("canonical wrong public scalar"),
    );
    let cases = [
        OperandsV25 {
            bound_public_nonce: &other_point,
            ..original
        },
        OperandsV25 {
            participant_key: &other_point,
            ..original
        },
        OperandsV25 {
            aggregate_nonce_hat: &other_point,
            ..original
        },
        OperandsV25 {
            aggregate_signing_key: &other_point,
            ..original
        },
        OperandsV25 {
            chain_id: &other_chain,
            ..original
        },
        OperandsV25 {
            kernel_message: &other_message,
            ..original
        },
        OperandsV25 {
            partial: &wrong_scalar,
            ..original
        },
    ];
    for changed in cases {
        assert_ne!(changed.exact(), original.exact());
        let expected = changed.original();
        assert_eq!(expected, Ok(false));
        let before = calls(&cache);
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, changed), expected);
        }
        assert_eq!(calls(&cache), before + 2);
    }
    assert_eq!(cache.successful.lock().unwrap().len, 1);

    // Context metadata is not part of the bare equation, but MUST still be
    // part of the exact key. Only paired authorized changes pass both guards.
    let other_template = [0x27; 32];
    let other_index = PartialSignatureV1::new(
        PurposeV1::Funding,
        1,
        fixture.template,
        fixture.partial.partial().clone(),
    );
    let other_purpose = PartialSignatureV1::new(
        PurposeV1::Refund,
        0,
        fixture.template,
        fixture.partial.partial().clone(),
    );
    let other_hash = PartialSignatureV1::new(
        PurposeV1::Funding,
        0,
        other_template,
        fixture.partial.partial().clone(),
    );
    for changed in [
        OperandsV25 {
            partial: &other_index,
            ..original
        },
        OperandsV25 {
            partial: &other_purpose,
            expected_purpose: PurposeV1::Refund,
            ..original
        },
        OperandsV25 {
            partial: &other_hash,
            expected_template_hash: &other_template,
            ..original
        },
    ] {
        assert_ne!(changed.exact(), original.exact());
        assert_eq!(changed.original(), Ok(true));
        let before = calls(&cache);
        assert_eq!(verify_using(&cache, changed), Ok(true));
        assert_eq!(calls(&cache), before + 1);
        assert_eq!(verify_using(&cache, changed), Ok(true));
        assert_eq!(calls(&cache), before + 1);
    }
    assert_eq!(cache.successful.lock().unwrap().len, 4);
    // Every canonically parseable single-byte payload mutation changes the
    // key. Actual and expected purpose/template are paired here deliberately;
    // the separate warm-guard test checks unpaired context substitutions.
    let mut compared = 0;
    for position in 0..PartialSignatureV1::ENCODED_LEN {
        let mut bytes = fixture.partial.to_bytes();
        bytes[position] ^= 1;
        if let Ok(changed) = PartialSignatureV1::from_bytes(&bytes) {
            let operands = OperandsV25 {
                partial: &changed,
                expected_purpose: changed.purpose(),
                expected_template_hash: changed.template_hash(),
                ..original
            };
            assert_ne!(operands.exact(), original.exact());
            compared += 1;
        }
    }
    assert!(compared >= 35); // all metadata bytes, regardless of scalar edges
    assert!(PartialSignatureV1::from_bytes(&fixture.partial.to_bytes()[..66]).is_err());
    let mut noncanonical = fixture.partial.to_bytes();
    noncanonical[35..].fill(0xff);
    assert!(PartialSignatureV1::from_bytes(&noncanonical).is_err());
}

#[test]
fn warm_partial_cache_cannot_bypass_purpose_or_template_guards_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let cache = CacheV25::new();
    let original = fixture.operands();
    assert_eq!(verify_using(&cache, original), Ok(true));
    assert_eq!(shipped(original), Ok(true));
    let other_template = [0x28; 32];
    let sponsor = PartialSignatureV1::new(
        PurposeV1::Sponsor,
        0,
        fixture.template,
        fixture.partial.partial().clone(),
    );
    let refund = PartialSignatureV1::new(
        PurposeV1::Refund,
        0,
        fixture.template,
        fixture.partial.partial().clone(),
    );
    let other_hash = PartialSignatureV1::new(
        PurposeV1::Funding,
        0,
        other_template,
        fixture.partial.partial().clone(),
    );
    for changed in [
        OperandsV25 {
            expected_purpose: PurposeV1::Sponsor,
            ..original
        },
        OperandsV25 {
            partial: &sponsor,
            ..original
        },
        OperandsV25 {
            partial: &sponsor,
            expected_purpose: PurposeV1::Sponsor,
            expected_template_hash: &other_template,
            ..original
        },
        OperandsV25 {
            expected_purpose: PurposeV1::Refund,
            ..original
        },
        OperandsV25 {
            partial: &refund,
            ..original
        },
        OperandsV25 {
            expected_template_hash: &other_template,
            ..original
        },
        OperandsV25 {
            partial: &other_hash,
            ..original
        },
    ] {
        let expected = changed.original();
        assert!(expected.is_err());
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, changed), expected);
            assert_eq!(shipped(changed), expected);
        }
        // Guards precede lookup AND the original arithmetic on the miss path.
        assert_eq!(calls(&cache), 1);
    }
    assert_eq!(cache.successful.lock().unwrap().len, 1);
}

#[test]
fn false_results_and_explicit_backend_error_policy_never_insert_success_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let cache = CacheV25::new();
    let original = fixture.operands();
    let other_nonce = secret(31).public_key();
    let rejected = OperandsV25 {
        bound_public_nonce: &other_nonce,
        ..original
    };
    for _ in 0..2 {
        assert_eq!(rejected.original(), Ok(false));
        assert_eq!(verify_using(&cache, rejected), Ok(false));
    }
    assert_eq!(calls(&cache), 2);
    assert_eq!(cache.successful.lock().unwrap().len, 0);
    // Honest policy seam: this is a real backend error for an explicitly zero
    // challenge, NOT a claimed kernel-message preimage of that challenge.
    // Valid public types cannot manufacture an invalid point/partial scalar;
    // no unsafe construction or changed challenge function is used here.
    let backend_error: Result<bool> = dom_scriptless_primitives::scriptless_verify_bound_partial(
        fixture.partial.partial(),
        &fixture.bound_nonce,
        &fixture.participant_key,
        &[0; 32],
    )
    .map_err(Into::into);
    assert!(backend_error.is_err());
    for _ in 0..2 {
        assert_eq!(
            finish_original(&cache, original.exact(), backend_error.clone()),
            backend_error
        );
    }
    assert_eq!(cache.successful.lock().unwrap().len, 0);
    assert_eq!(verify_using(&cache, original), Ok(true));
    assert_eq!(verify_using(&cache, original), Ok(true));
    assert_eq!(calls(&cache), 3);
}

#[test]
fn message_length_padding_and_oversize_preserve_original_acceptance_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let original = fixture.operands();
    let empty: &[u8] = &[];
    let zero: &[u8] = &[0];
    let two_zeros: &[u8] = &[0, 0];
    let keys = [empty, zero, two_zeros].map(|kernel_message| {
        OperandsV25 {
            kernel_message,
            ..original
        }
        .exact()
    });
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    for length in [
        0,
        1,
        MAX_CACHED_MESSAGE_BYTES,
        MAX_CACHED_MESSAGE_BYTES + 1,
        MAX_CACHED_MESSAGE_BYTES * 4,
    ] {
        let fixture = Fixture::new(&vec![0x48; length]);
        let cache = CacheV25::new();
        let operands = fixture.operands();
        assert_eq!(operands.original(), Ok(true));
        assert_eq!(
            operands.exact().is_some(),
            length <= MAX_CACHED_MESSAGE_BYTES
        );
        for _ in 0..2 {
            assert_eq!(verify_using(&cache, operands), Ok(true));
        }
        let cached = length <= MAX_CACHED_MESSAGE_BYTES;
        assert_eq!(calls(&cache), if cached { 1 } else { 2 });
        assert_eq!(cache.successful.lock().unwrap().len, usize::from(cached));
        assert_eq!(shipped(operands), Ok(true));
    }
}

#[test]
fn fixed_capacity_rechecks_evicted_partial_equations_v25() {
    let cache = CacheV25::new();
    let fixtures: Vec<_> = (0..=CAPACITY).map(|_| Fixture::new(&[0x37; 32])).collect();
    for fixture in &fixtures {
        assert_eq!(verify_using(&cache, fixture.operands()), Ok(true));
    }
    assert_eq!(calls(&cache), CAPACITY + 1);
    {
        let successful = cache.successful.lock().unwrap();
        assert_eq!(successful.len, CAPACITY);
        assert_eq!(successful.entries.iter().flatten().count(), CAPACITY);
        assert!(!successful.contains(&fixtures[0].operands().exact().unwrap()));
        assert!(successful.contains(&fixtures[CAPACITY].operands().exact().unwrap()));
    }
    assert!(!std::mem::needs_drop::<ExactEquationV25>());
    assert!(std::mem::size_of::<SuccessesV25>() <= CAPACITY * (KEY_BYTES + 1) + 32);
    assert!(std::mem::size_of::<CacheV25>() <= CAPACITY * (KEY_BYTES + 1) + 128);
    assert_eq!(
        verify_using(&cache, fixtures[CAPACITY].operands()),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 1);
    assert_eq!(verify_using(&cache, fixtures[0].operands()), Ok(true));
    assert_eq!(calls(&cache), CAPACITY + 2);
    assert_eq!(
        verify_using(&cache, fixtures[CAPACITY].operands()),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 2);
}

#[test]
fn partial_cache_contention_and_poison_use_original_without_waiting_v25() {
    let fixture = Fixture::new(&[0x37; 32]);
    let original = fixture.operands();
    let busy = CacheV25::new();
    assert_eq!(verify_using(&busy, original), Ok(true));
    let held = busy.successful.lock().unwrap();
    for _ in 0..2 {
        assert_eq!(verify_using(&busy, original), Ok(true));
    }
    assert_eq!(calls(&busy), 3);
    assert_eq!(held.len, 1);
    drop(held);
    assert_eq!(verify_using(&busy, original), Ok(true));
    assert_eq!(calls(&busy), 3);
    let poisoned = CacheV25::new();
    assert_eq!(verify_using(&poisoned, original), Ok(true));
    let result = std::panic::catch_unwind(|| {
        let _held = poisoned.successful.lock().unwrap();
        panic!("intentional test-only partial equation cache poison");
    });
    assert!(result.is_err());
    assert!(poisoned.successful.is_poisoned());
    for _ in 0..2 {
        assert_eq!(verify_using(&poisoned, original), Ok(true));
    }
    assert_eq!(calls(&poisoned), 3);
}
