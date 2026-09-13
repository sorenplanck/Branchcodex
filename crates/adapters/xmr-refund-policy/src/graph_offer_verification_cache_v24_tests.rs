//! Real native range/value/knowledge proofs, reusing only immutable fixture
//! bytes across tests. Every cache below is local, independent and initially cold.
use super::*;
use crate::funding_offer_v22::XmrFundingOfferV22;
use crate::graph_key_proofs_v22::XmrGraphKeyProofScopeV22;
use crate::payout_offer_v22::{XmrGraphPayoutKindV22 as Kind, XmrPolicyPayoutOfferV22};
use dom_adaptor::{DirectionV1, SigningShareV1, TrustedChainIdV1};
use dom_consensus::{TransactionInput, TransactionOutput};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use std::sync::atomic::Ordering;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    chain: TrustedChainIdV1,
    terms: SettlementTermsV1,
    policy: ValidatedXmrCompensationPolicyV11,
    bytes: Vec<u8>,
}
impl Fixture {
    fn scope(&self) -> XmrGraphOfferScopeV22<'_> {
        XmrGraphOfferScopeV22 {
            chain: &self.chain,
            route_id: [88; 32],
            participant: self.policy.policy().dom_funder,
            direction: DirectionV1::Initiator,
        }
    }
    fn offer(&self) -> TestResult<XmrGraphOfferV22> {
        Ok(XmrGraphOfferV22::from_bytes(
            &self.bytes,
            &self.terms,
            &self.policy,
            &self.scope(),
        )?)
    }
}

fn fixture() -> TestResult<&'static Fixture> {
    static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| build_fixture().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone().into())
}

fn build_fixture() -> TestResult<Fixture> {
    // Same economic fixture/proof producers as payout_offer_v22_tests; no
    // sentinel verification, scalar injection, generated finality or mock gate.
    let (mut raw_policy, mut terms) = crate::compensation::tests::fixture();
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        0x000d_0012,
        &dom_core::Hash256::from_bytes([91; 32]),
    );
    raw_policy.dom_chain_id = *chain.as_bytes();
    terms.dom_leg.chain_id.0 = *chain.as_bytes();
    terms.assurance_policy_hash = Some(raw_policy.policy_hash()?);
    let amounts = raw_policy.validate_for(&terms)?;
    let values = [
        raw_policy.dom_principal_noms,
        amounts.successful_change_noms(),
        amounts.refund_payout_noms(),
        amounts.compensation_payout_noms(),
    ];
    let commitments: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(index, amount)| {
            let blinding = BlindingFactor::from_bytes([index as u8 + 11; 32]).unwrap();
            *Commitment::commit(*amount, &blinding).as_bytes()
        })
        .collect();
    raw_policy.claim_principal_commitment = commitments[0];
    raw_policy.claim_change_commitment = commitments[1];
    raw_policy.refund_recipient_commitment = commitments[2];
    raw_policy.compensation_recipient_commitment = commitments[3];
    terms.assurance_policy_hash = Some(raw_policy.policy_hash()?);
    let policy = raw_policy.validate_for(&terms)?;
    let mut payouts = Vec::new();
    for (index, kind) in [(1, Kind::ClaimChange), (2, Kind::Refund)] {
        let blinding = BlindingFactor::from_bytes([index as u8 + 11; 32])?;
        let (proof, commitment) = dom_crypto::range_proof_prove_bytes(values[index], &blinding)?;
        let output = TransactionOutput {
            commitment: Commitment::from_compressed_bytes(&commitment)?,
            proof,
        };
        let ownership = match kind.success_kind() {
            Some(kind) => Some(crate::economic_graph::produce_xmr_payout_value_proof_v12(
                &terms,
                &policy,
                kind,
                DirectionV1::Initiator,
                &chain,
                &SigningShareV1::from_be_bytes([index as u8 + 11; 32])?,
            )?),
            None => None,
        };
        payouts.push(XmrPolicyPayoutOfferV22::new(
            &terms,
            &policy,
            kind,
            output,
            ownership,
            &chain,
            DirectionV1::Initiator,
        )?);
    }
    let funding = XmrFundingOfferV22::new(
        &terms,
        &policy,
        raw_policy.dom_funder,
        vec![TransactionInput {
            commitment: Commitment::commit(1000, &BlindingFactor::from_bytes([21; 32])?),
        }],
        None,
        1,
    )?;
    let shares: Vec<_> = (0..5)
        .map(|stage| SigningShareV1::from_be_bytes([30 + stage; 32]))
        .collect::<Result<_, _>>()?;
    let mut offer = XmrGraphOfferV22 {
        route_id: [88; 32],
        keys: std::array::from_fn(|stage| shares[stage].public_key().clone()),
        offsets: std::array::from_fn(|stage| [50 + stage as u8; 32]),
        funding,
        payouts: payouts
            .try_into()
            .map_err(|_| "two real payouts required")?,
        proofs: [0; XmrGraphKeyProofScopeV22::ENCODED_LEN],
    };
    let scope = XmrGraphOfferScopeV22 {
        chain: &chain,
        route_id: offer.route_id,
        participant: raw_policy.dom_funder,
        direction: DirectionV1::Initiator,
    };
    sign_knowledge(&mut offer, &terms, &policy, &scope)?;
    offer.verify_uncached_v24(&terms, &policy, &scope)?;
    // Exercise the public constructor as well as strict decode below.
    let offer = XmrGraphOfferV22::new(
        &terms,
        &policy,
        &scope,
        offer.keys,
        offer.offsets,
        offer.funding,
        offer.payouts,
        offer.proofs,
    )?;
    Ok(Fixture {
        chain,
        terms,
        policy,
        bytes: offer.to_bytes()?,
    })
}

fn sign_knowledge(
    offer: &mut XmrGraphOfferV22,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    scope: &XmrGraphOfferScopeV22<'_>,
) -> TestResult {
    let roster = terms.roster.map(|party| party.0);
    let proof_scope = XmrGraphKeyProofScopeV22 {
        chain: scope.chain,
        session_id: policy.policy().session_id,
        roster: &roster,
        direction: scope.direction,
        participant_index: roster
            .iter()
            .position(|party| party == &scope.participant)
            .ok_or("participant")? as u16,
        terms_hash: *policy.terms_hash(),
        keys: &offer.keys,
        public_commitment: offer.public_commitment(policy, scope),
    };
    for stage in 0..5 {
        let share = SigningShareV1::from_be_bytes([30 + stage as u8; 32])?;
        let proof = dom_adaptor::prove_share_knowledge_v1(&proof_scope.statement(stage)?, &share)?
            .to_bytes();
        let start = stage * dom_adaptor::ShareProofV1::ENCODED_LEN;
        offer.proofs[start..start + proof.len()].copy_from_slice(&proof);
    }
    Ok(())
}

fn calls(cache: &VerificationCacheV24) -> usize {
    cache.original_calls.load(Ordering::Relaxed)
}

fn reject_equally(
    cache: &VerificationCacheV24,
    offer: &XmrGraphOfferV22,
    terms: &SettlementTermsV1,
    policy: &ValidatedXmrCompensationPolicyV11,
    scope: &XmrGraphOfferScopeV22<'_>,
) {
    let original = offer.verify_uncached_v24(terms, policy, scope);
    assert!(original.is_err());
    let before = calls(cache);
    for index in 1..=2 {
        assert_eq!(verify_using(cache, offer, terms, policy, scope), original);
        assert_eq!(
            calls(cache),
            before + index,
            "errors may never become cache entries"
        );
    }
}

#[test]
fn real_graph_offer_cold_warm_and_uncached_results_are_identical_v24() -> TestResult {
    let fixture = fixture()?;
    let offer = fixture.offer()?;
    let cache = VerificationCacheV24::default();
    let scope = fixture.scope();
    let original = offer.verify_uncached_v24(&fixture.terms, &fixture.policy, &scope);
    assert_eq!(original, Ok(()));
    assert_eq!(
        verify_using(&cache, &offer, &fixture.terms, &fixture.policy, &scope),
        original
    );
    assert_eq!(calls(&cache), 1);
    for _ in 0..3 {
        assert_eq!(
            verify_using(&cache, &offer, &fixture.terms, &fixture.policy, &scope),
            original
        );
    }
    assert_eq!(
        calls(&cache),
        1,
        "warm exact offer must skip only the pure verifier"
    );
    assert_eq!(offer.to_bytes()?, fixture.bytes);
    assert_eq!(fixture.offer()?.to_bytes()?, fixture.bytes);
    Ok(())
}

#[test]
fn real_graph_offer_cache_misses_every_trusted_scope_and_terms_family_v24() -> TestResult {
    let f = fixture()?;
    let offer = f.offer()?;
    let cache = VerificationCacheV24::default();
    verify_using(&cache, &offer, &f.terms, &f.policy, &f.scope())?;
    let other_chain = TrustedChainIdV1::from_authenticated_genesis(
        0x000d_0012,
        &dom_core::Hash256::from_bytes([92; 32]),
    );
    for index in 0..4 {
        let mut scope = f.scope();
        match index {
            0 => scope.chain = &other_chain,
            1 => scope.route_id[0] ^= 1,
            2 => scope.participant = f.policy.policy().xmr_funder,
            _ => scope.direction = DirectionV1::Responder,
        }
        reject_equally(&cache, &offer, &f.terms, &f.policy, &scope);
    }
    for index in 0..15 {
        let mut terms = f.terms.clone();
        match index {
            0 => terms.session_id.0[0] ^= 1,
            1 => terms.settlement_id.0[0] ^= 1,
            2 => terms.roster.swap(0, 1),
            3 => terms.intent_hash.0[0] ^= 1,
            4 => terms.dom_leg.amount += 1,
            5 => terms.counterparty_leg.amount += 1,
            6 => terms.dom_leg.adapter_profile_hash[0] ^= 1,
            7 => terms.counterparty_leg.finality.max_reorg_depth += 1,
            8 => terms.fee_limit.dom_max += 1,
            9 => terms.metadata.push(42),
            10 => terms.recovery.evidence_retention_blocks += 1,
            11 => terms.assurance_policy_hash = Some([0; 32]),
            12 => {
                terms.dom_leg.deadline =
                    kaystra_core::types::TimelockSpec::BlockHeight { value: 101 }
            }
            13 => {
                terms.counterparty_leg.deadline =
                    kaystra_core::types::TimelockSpec::TimestampSeconds {
                        value: 1_900_000_001,
                    }
            }
            _ => terms.solver_id.0[0] ^= 1,
        }
        reject_equally(&cache, &offer, &terms, &f.policy, &f.scope());
    }
    let mut policy = *f.policy.policy();
    policy.compensation_height += 1;
    let mut terms = f.terms.clone();
    terms.assurance_policy_hash = Some(policy.policy_hash()?);
    let policy = policy.validate_for(&terms)?;
    reject_equally(&cache, &offer, &terms, &policy, &f.scope());
    assert_eq!(cache.successful.lock().unwrap().keys.len(), 1);
    Ok(())
}

#[test]
fn real_graph_offer_cache_misses_payload_keys_offsets_proofs_funding_and_payouts_v24() -> TestResult
{
    let f = fixture()?;
    let cache = VerificationCacheV24::default();
    verify_using(&cache, &f.offer()?, &f.terms, &f.policy, &f.scope())?;
    for index in 0..8 {
        let mut offer = f.offer()?;
        match index {
            0 => offer.route_id[0] ^= 1,
            1 => offer.keys.swap(0, 1),
            2 => offer.offsets[0][0] ^= 1,
            3 => offer.proofs[0] ^= 1,
            4 => offer.payouts.swap(0, 1),
            5 => offer.offsets[4] = [0xff; 32],
            6 => {
                offer.funding = XmrFundingOfferV22::new(
                    &f.terms,
                    &f.policy,
                    f.policy.policy().dom_funder,
                    offer.funding.inputs().to_vec(),
                    None,
                    2,
                )?
            }
            _ => {
                offer.funding = XmrFundingOfferV22::new(
                    &f.terms,
                    &f.policy,
                    f.policy.policy().dom_funder,
                    offer.funding.inputs().to_vec(),
                    Some(offer.payouts[0].output().clone()),
                    1,
                )?
            }
        }
        reject_equally(&cache, &offer, &f.terms, &f.policy, &f.scope());
    }
    assert_eq!(cache.successful.lock().unwrap().keys.len(), 1);
    Ok(())
}

#[test]
fn real_graph_offer_full_key_equality_and_strict_decode_survive_warm_cache_v24() -> TestResult {
    let f = fixture()?;
    let offer = f.offer()?;
    let cache = VerificationCacheV24::default();
    verify_using(&cache, &offer, &f.terms, &f.policy, &f.scope())?;
    let key = exact_key(&offer, &f.terms, &f.policy, &f.scope()).ok_or("real key")?;
    let successful = cache.successful.lock().unwrap();
    for offset in 0..key.len() {
        let mut changed = key.clone();
        changed[offset] ^= 1;
        assert!(
            !successful.contains(&changed),
            "changed full key byte {offset}"
        );
    }
    drop(successful);
    let decode =
        |bytes: &[u8]| XmrGraphOfferV22::from_bytes(bytes, &f.terms, &f.policy, &f.scope());
    // The global production cache is warm too, from the public constructor.
    for bytes in [&f.bytes[..f.bytes.len() - 1], &[0u8; 7][..]] {
        assert!(decode(bytes).is_err());
    }
    let mut trailing = f.bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    assert!(decode(&vec![0; XmrGraphOfferV22::MAX_BYTES + 1]).is_err());
    let payload_start = 8 + 32 + 5 * 33 + 5 * 32 + XmrGraphKeyProofScopeV22::ENCODED_LEN;
    let mut payload = payload_start;
    for _ in 0..3 {
        let length = u32::from_le_bytes(f.bytes[payload..payload + 4].try_into()?) as usize;
        for offset in [
            payload,
            payload + 4,
            payload + 4 + length / 2,
            payload + 3 + length,
        ] {
            let mut changed = f.bytes.clone();
            changed[offset] ^= 0x80;
            assert!(
                decode(&changed).is_err(),
                "changed nested payload byte {offset}"
            );
        }
        let mut overflow = f.bytes.clone();
        overflow[payload..payload + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&overflow).is_err());
        payload += 4 + length;
    }
    assert_eq!(payload, f.bytes.len());
    assert_eq!(decode(&f.bytes)?.to_bytes()?, f.bytes);
    Ok(())
}

#[test]
fn real_graph_offer_cache_is_bounded_and_eviction_reexecutes_original_v24() -> TestResult {
    let f = fixture()?;
    let cache = VerificationCacheV24::default();
    let original = f.offer()?;
    verify_using(&cache, &original, &f.terms, &f.policy, &f.scope())?;
    for index in 0..ENTRIES {
        let mut scope = f.scope();
        scope.route_id = [100 + index as u8; 32];
        let mut offer = f.offer()?;
        offer.route_id = scope.route_id;
        sign_knowledge(&mut offer, &f.terms, &f.policy, &scope)?;
        assert_eq!(
            offer.verify_uncached_v24(&f.terms, &f.policy, &scope),
            Ok(())
        );
        verify_using(&cache, &offer, &f.terms, &f.policy, &scope)?;
        let successful = cache.successful.lock().unwrap();
        assert!(successful.keys.len() <= ENTRIES);
        assert!(successful.bytes <= RETAINED_BYTES);
        assert_eq!(
            successful.bytes,
            successful.keys.iter().map(|key| key.len()).sum::<usize>()
        );
    }
    assert_eq!(cache.successful.lock().unwrap().keys.len(), ENTRIES);
    let before = calls(&cache);
    verify_using(&cache, &original, &f.terms, &f.policy, &f.scope())?;
    assert_eq!(calls(&cache), before + 1);
    let mut maximum_terms = f.terms.clone();
    maximum_terms
        .metadata
        .resize(kaystra_core::terms::MAX_METADATA_BYTES, 42);
    let maximum_policy = f.policy.policy().validate_for(&maximum_terms)?;
    let maximum_key = exact_key(&original, &maximum_terms, &maximum_policy, &f.scope())
        .ok_or("maximum legal terms must remain cache-eligible")?;
    assert!(maximum_key.len() <= KEY_BYTES);
    reject_equally(
        &cache,
        &original,
        &maximum_terms,
        &maximum_policy,
        &f.scope(),
    );
    let mut oversized = f.terms.clone();
    oversized
        .metadata
        .resize(kaystra_core::terms::MAX_METADATA_BYTES + 1, 0);
    assert!(exact_key(&original, &oversized, &f.policy, &f.scope()).is_none());
    reject_equally(&cache, &original, &oversized, &f.policy, &f.scope());
    Ok(())
}

#[test]
fn real_graph_offer_poison_and_contention_fall_back_to_original_v24() -> TestResult {
    let f = fixture()?;
    let offer = f.offer()?;
    let cache = VerificationCacheV24::default();
    let guard = cache.successful.lock().unwrap();
    assert_eq!(
        verify_using(&cache, &offer, &f.terms, &f.policy, &f.scope()),
        offer.verify_uncached_v24(&f.terms, &f.policy, &f.scope())
    );
    assert_eq!(calls(&cache), 1);
    assert!(guard.keys.is_empty());
    drop(guard);
    verify_using(&cache, &offer, &f.terms, &f.policy, &f.scope())?;
    assert_eq!(calls(&cache), 2);
    assert_eq!(cache.successful.lock().unwrap().keys.len(), 1);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = cache.successful.lock().unwrap();
        panic!("isolated cache poison regression");
    }));
    for expected in 3..=4 {
        assert_eq!(
            verify_using(&cache, &offer, &f.terms, &f.policy, &f.scope()),
            Ok(())
        );
        assert_eq!(calls(&cache), expected);
    }
    let mut wrong = f.scope();
    wrong.route_id[0] ^= 1;
    reject_equally(&cache, &offer, &f.terms, &f.policy, &wrong);
    Ok(())
}

#[test]
fn real_graph_offer_warm_repeat64_reports_actual_verifier_counts_v24() -> TestResult {
    // Counts measure entry into the unchanged GraphOffer verifier body only.
    // Nested public range-proof caches may also be enabled in this binary:
    // direct calls are NOT an old whole-stack baseline or64 full crypto runs.
    let f = fixture()?;
    let offer = f.offer()?;
    let scope = f.scope();
    let cache = VerificationCacheV24::default();
    verify_using(&cache, &offer, &f.terms, &f.policy, &scope)?;
    assert_eq!(calls(&cache), 1);
    let warm_start = std::time::Instant::now();
    for _ in 0..64 {
        verify_using(&cache, &offer, &f.terms, &f.policy, &scope)?;
    }
    let warm_elapsed = warm_start.elapsed();
    assert_eq!(
        calls(&cache),
        1,
        "all64 exact repeats must reuse the GraphOffer-layer result"
    );
    let original_start = std::time::Instant::now();
    let mut original_verified = 0usize;
    for _ in 0..64 {
        offer.verify_uncached_v24(&f.terms, &f.policy, &scope)?;
        original_verified += 1;
    }
    let original_elapsed = original_start.elapsed();
    assert_eq!(original_verified, 64);
    eprintln!("real graph-offer layer repeat64: cold_offer_body_entries={} warm_extra_offer_body_entries=0 direct_offer_body_successes={} warm_layer_us={} direct_layer_us={} nested_public_proof_cache=may-be-enabled old_whole_stack_baseline=false",
        calls(&cache), original_verified, warm_elapsed.as_micros(), original_elapsed.as_micros());
    // Timing is evidence, never a flaky pass condition or a promised bound.
    Ok(())
}
