use super::*;
use dom_crypto::{schnorr_sign, SecretKey};
use std::sync::atomic::Ordering;
use std::time::Instant;

fn secret(value: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    SecretKey::from_bytes(&bytes).expect("public signature test fixture key")
}

fn sample() -> (SchnorrSignature, PublicKey, [u8; 32], [u8; 32]) {
    let signer = secret(19);
    let chain = [21; 32];
    let digest = [22; 32];
    let signature = schnorr_sign(&signer, &digest, &chain).expect("real Schnorr fixture");
    (signature, signer.public_key(), chain, digest)
}

fn calls(cache: &PublicEnvelopeSignatureCacheV24) -> usize {
    cache.original_calls.load(Ordering::Relaxed)
}

#[test]
fn public_envelope_real_64_replays_match_uncached_and_use_one_equation_v24() {
    let (signature, key, chain, digest) = sample();
    let cache = PublicEnvelopeSignatureCacheV24::default();
    let baseline = Instant::now();
    for _ in 0..64 {
        assert_eq!(schnorr_verify(&signature, &key, &chain, &digest), Ok(true));
    }
    let baseline_elapsed = baseline.elapsed();
    let cold = Instant::now();
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    let cold_elapsed = cold.elapsed();
    assert_eq!(calls(&cache), 1);
    let warm = Instant::now();
    for _ in 0..63 {
        assert_eq!(
            verify_using(&cache, &signature, &key, &chain, &digest),
            Ok(true)
        );
    }
    let warm_elapsed = warm.elapsed();
    assert_eq!(calls(&cache), 1);
    assert_eq!(cache.successful.lock().unwrap().len(), 1);
    // Primitive-only timing, not Store audit or swap latency. No timing assert.
    eprintln!(
        "DOM_PUBLIC_ENVELOPE_SIGNATURE_TIMING_V24 {{\"scope\":\"schnorr_equation_only\",\"checks\":64,\"baseline_native_calls\":64,\"memo_native_calls\":1,\"baseline_ms\":{:.3},\"cold_ms\":{:.3},\"warm_63_ms\":{:.3}}}",
        baseline_elapsed.as_secs_f64() * 1000.0,
        cold_elapsed.as_secs_f64() * 1000.0,
        warm_elapsed.as_secs_f64() * 1000.0,
    );
}

#[test]
fn public_envelope_every_primitive_operand_mutation_misses_and_matches_original_v24() {
    let (signature, key, chain, digest) = sample();
    let cache = PublicEnvelopeSignatureCacheV24::default();
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    let mut scalar_changed = signature.to_bytes();
    scalar_changed[33..].fill(0);
    scalar_changed[64] = 1;
    let scalar_changed = SchnorrSignature::from_bytes(&scalar_changed).unwrap();
    let mut point_changed = signature.to_bytes();
    point_changed[0] ^= 1; // opposite valid SEC1 parity, still a canonical point
    let point_changed = SchnorrSignature::from_bytes(&point_changed).unwrap();
    let mut other_chain = chain;
    other_chain[0] ^= 1;
    let mut other_digest = digest;
    other_digest[31] ^= 1;
    let variants = [
        (scalar_changed, key.clone(), chain, digest),
        (point_changed, key.clone(), chain, digest),
        (signature.clone(), secret(20).public_key(), chain, digest),
        (signature.clone(), key.clone(), other_chain, digest),
        (signature.clone(), key.clone(), chain, other_digest),
    ];
    for (index, (changed_signature, changed_key, changed_chain, changed_digest)) in
        variants.iter().enumerate()
    {
        let original = schnorr_verify(
            changed_signature,
            changed_key,
            changed_chain,
            changed_digest,
        );
        assert_eq!(original, Ok(false));
        for _ in 0..2 {
            assert_eq!(
                verify_using(
                    &cache,
                    changed_signature,
                    changed_key,
                    changed_chain,
                    changed_digest
                ),
                original,
            );
        }
        assert_eq!(calls(&cache), 1 + (index + 1) * 2);
        assert_eq!(cache.successful.lock().unwrap().len(), 1);
    }
    let before = calls(&cache);
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    assert_eq!(calls(&cache), before);
}

#[test]
fn public_envelope_contention_falls_back_to_real_verifier_without_waiting_v24() {
    let (signature, key, chain, digest) = sample();
    let cache = PublicEnvelopeSignatureCacheV24::default();
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    let held = cache.successful.lock().unwrap();
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    assert_eq!(calls(&cache), 2);
    let other_digest = [23; 32];
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &other_digest),
        schnorr_verify(&signature, &key, &chain, &other_digest),
    );
    assert_eq!(calls(&cache), 3);
    assert_eq!(held.len(), 1);
    drop(held);
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    assert_eq!(calls(&cache), 3);
}

#[test]
fn public_envelope_poison_falls_back_to_real_verifier_and_never_admits_failure_v24() {
    let (signature, key, chain, digest) = sample();
    let cache = PublicEnvelopeSignatureCacheV24::default();
    assert_eq!(
        verify_using(&cache, &signature, &key, &chain, &digest),
        Ok(true)
    );
    let poisoned = std::panic::catch_unwind(|| {
        let _held = cache.successful.lock().unwrap();
        panic!("deliberate public signature cache poison");
    });
    assert!(poisoned.is_err());
    for _ in 0..2 {
        assert_eq!(
            verify_using(&cache, &signature, &key, &chain, &digest),
            Ok(true)
        );
        let other_digest = [24; 32];
        assert_eq!(
            verify_using(&cache, &signature, &key, &chain, &other_digest),
            schnorr_verify(&signature, &key, &chain, &other_digest),
        );
    }
    assert_eq!(calls(&cache), 5);
    assert_eq!(cache.successful.lock().unwrap_err().into_inner().len(), 1);
}

#[test]
fn public_envelope_real_success_eviction_is_bounded_and_not_a_validation_limit_v24() {
    let signer = secret(29);
    let key = signer.public_key();
    let chain = [30; 32];
    let cache = PublicEnvelopeSignatureCacheV24::default();
    let first_digest = [0; 32];
    let first = schnorr_sign(&signer, &first_digest, &chain).unwrap();
    for index in 0..=CAPACITY {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let signature = schnorr_sign(&signer, &digest, &chain).unwrap();
        assert_eq!(
            verify_using(&cache, &signature, &key, &chain, &digest),
            Ok(true)
        );
        let retained = cache.successful.lock().unwrap();
        assert_eq!(retained.len(), (index + 1).min(CAPACITY));
        assert!(retained.len() * KEY_BYTES <= 165_888);
    }
    assert_eq!(calls(&cache), CAPACITY + 1);
    assert!(!cache.successful.lock().unwrap().contains(&exact_equation(
        &first,
        &key,
        &chain,
        &first_digest,
    )));
    assert_eq!(
        verify_using(&cache, &first, &key, &chain, &first_digest),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 2);
    assert_eq!(cache.successful.lock().unwrap().len(), CAPACITY);
    let mut newest_digest = [0; 32];
    newest_digest[..8].copy_from_slice(&(CAPACITY as u64).to_be_bytes());
    let newest = schnorr_sign(&signer, &newest_digest, &chain).unwrap();
    assert_eq!(
        verify_using(&cache, &newest, &key, &chain, &newest_digest),
        Ok(true)
    );
    assert_eq!(calls(&cache), CAPACITY + 2);
}

fn signed_envelope() -> (PublicKey, Vec<u8>) {
    use super::super::{
        encode_canonical_unsigned_dsc1, tagged_hash, OutboundDsc1UnsignedFieldsV1,
        TRANSPORT_MESSAGE_DIGEST_TAG,
    };
    let signer = secret(31);
    let chain = [32; 32];
    let payload =
        dom_adaptor::NonceCommitmentV1::new(dom_adaptor::PurposeV1::Refund, 0, [33; 32]).to_bytes();
    let mut unsigned = encode_canonical_unsigned_dsc1(&OutboundDsc1UnsignedFieldsV1 {
        message_type: 0x0c,
        chain_id: chain,
        session_id: [34; 32],
        sender_id: [35; 32],
        sequence: 0,
        previous_transcript_hash: [36; 32],
        payload: &payload,
    })
    .unwrap();
    let digest = tagged_hash(TRANSPORT_MESSAGE_DIGEST_TAG, &unsigned);
    let signature = schnorr_sign(&signer, &digest, &chain).unwrap();
    unsigned.extend_from_slice(&signature.to_bytes());
    (signer.public_key(), unsigned)
}

#[test]
fn public_envelope_warm_hit_never_accepts_changed_dsc1_context_or_framing_v24() {
    use super::super::{ParsedTransportEnvelopeV1, SessionStoreError};
    let (key, bytes) = signed_envelope();
    let envelope = ParsedTransportEnvelopeV1::parse(&bytes).unwrap();
    envelope.verify(&key).unwrap();
    envelope.verify(&key).unwrap();
    // Every authenticated DSC1 context is rehashed before the equation lookup.
    // This test grants no Store authority and does not skip its separate audits.
    for offset in [8, 40, 72, 104, 112, 151] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let parsed = ParsedTransportEnvelopeV1::parse(&changed).unwrap();
        assert!(matches!(
            parsed.verify(&key),
            Err(SessionStoreError::Canonical)
        ));
    }
    for offset in [0, 7, 144] {
        let mut malformed = bytes.clone();
        malformed[offset] ^= 1;
        assert!(matches!(
            ParsedTransportEnvelopeV1::parse(&malformed),
            Err(SessionStoreError::Canonical),
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ParsedTransportEnvelopeV1::parse(&trailing).is_err());
    assert!(ParsedTransportEnvelopeV1::parse(&bytes[..bytes.len() - 1]).is_err());
    envelope.verify(&key).unwrap();
}

#[test]
fn public_envelope_malformed_signature_is_rejected_before_warm_lookup_v24() {
    use super::super::{ParsedTransportEnvelopeV1, SessionStoreError};
    let (key, bytes) = signed_envelope();
    let valid = ParsedTransportEnvelopeV1::parse(&bytes).unwrap();
    valid.verify(&key).unwrap();
    let mut malformed = Vec::new();
    let mut zero_scalar = valid.signature;
    zero_scalar[33..].fill(0);
    malformed.push(zero_scalar);
    let mut oversized_scalar = valid.signature;
    oversized_scalar[33..].fill(0xff);
    malformed.push(oversized_scalar);
    let mut invalid_point = valid.signature;
    invalid_point[..33].fill(0);
    malformed.push(invalid_point);
    for signature in malformed {
        assert!(SchnorrSignature::from_bytes(&signature).is_err());
        let mut parsed = ParsedTransportEnvelopeV1::parse(&bytes).unwrap();
        parsed.signature = signature;
        assert!(matches!(
            parsed.verify(&key),
            Err(SessionStoreError::Canonical)
        ));
    }
    assert!(SchnorrSignature::from_bytes(&valid.signature[..64]).is_err());
    valid.verify(&key).unwrap();
}
