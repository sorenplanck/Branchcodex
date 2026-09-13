use super::*;
use crate::collaborative_range_proof::tests::TestNonceVault;
use crate::TrustedChainIdV1;
use dom_core::Hash256;
use std::time::{Duration, Instant};

static_assertions::assert_not_impl_any!(Round1ContinuationV25: Clone, Copy, core::fmt::Debug, core::fmt::Display);
static_assertions::assert_not_impl_any!(OriginV25: Clone, Copy, core::fmt::Debug, core::fmt::Display);
static_assertions::assert_not_impl_any!(BpRound1PrivateOriginV25: Clone, Copy, core::fmt::Debug, core::fmt::Display);

fn signing_share(value: u8) -> SigningShareV1 {
    let mut bytes = [0; 32];
    bytes[31] = value;
    SigningShareV1::from_be_bytes(bytes).unwrap()
}

fn statement(extra: &[u8], session: u8) -> BpStatementV1 {
    let chain =
        TrustedChainIdV1::from_authenticated_genesis(0x112233, &Hash256::from_bytes([0x11; 32]));
    let points = vec![
        signing_share(3).public_key().clone(),
        signing_share(5).public_key().clone(),
    ];
    let aggregate = BpStatementV1::aggregate_commitment_from_shares(&points, 42).unwrap();
    BpStatementV1::new(
        &chain,
        [session; 32],
        vec![[0x31; 32], [0x32; 32]],
        42,
        points,
        aggregate,
        Some(*blake2b_256(extra).as_bytes()),
    )
    .unwrap()
}

struct Fixture {
    statement: BpStatementV1,
    extra: Vec<u8>,
    vaults: [TestNonceVault; 2],
    commitments: [[u8; 32]; 2],
    reveals: [Zeroizing<[u8; 32]>; 2],
}

impl Fixture {
    fn new(extra: Vec<u8>, session: u8) -> Self {
        let statement = statement(&extra, session);
        let mut vaults = [TestNonceVault::default(), TestNonceVault::default()];
        let mut commitments = [[0; 32]; 2];
        let mut reveals = [Zeroizing::new([0; 32]), Zeroizing::new([0; 32])];
        for actor in 0..2 {
            let (pending, commitment) = PendingCommonNonce::new_vault_backed_v1(
                &statement,
                actor as u16,
                &signing_share(if actor == 0 { 3 } else { 5 }),
                &mut vaults[actor],
            )
            .unwrap();
            commitments[actor] = commitment;
            reveals[actor] = pending.reveal_bytes();
        }
        Self {
            statement,
            extra,
            vaults,
            commitments,
            reveals,
        }
    }

    fn fresh(&mut self, actor: usize) -> LocalBpSecrets {
        // Real vault capability import and the original full commit/reveal
        // validation on EVERY call, even when the continuation is already hot.
        let (pending, commitment) = PendingCommonNonce::resume_vault_backed_v1(
            &self.statement,
            actor as u16,
            &signing_share(if actor == 0 { 3 } else { 5 }),
            &mut self.vaults[actor],
        )
        .unwrap();
        assert_eq!(commitment, self.commitments[actor]);
        pending
            .finish(&self.statement, &self.commitments, self.reveals.to_vec())
            .unwrap()
    }

    fn driver(&self) -> DomCollaborativeRangeProofV1 {
        DomCollaborativeRangeProofV1::new(&self.statement, self.extra.clone()).unwrap()
    }

    fn independent_nonce_snapshot(&self) -> Self {
        // Test-only copy of the original sealed fixture record, not a Clone
        // implementation or production export for a live continuation/nonce.
        let vaults = self.vaults.each_ref().map(|old| {
            let mut fresh = TestNonceVault::default();
            fresh.binding = old.binding.clone();
            fresh.plaintext = old.plaintext;
            fresh.seal_count = old.seal_count;
            fresh.open_count = old.open_count;
            fresh
        });
        Self {
            statement: self.statement.clone(),
            extra: self.extra.clone(),
            vaults,
            commitments: self.commitments,
            reveals: self.reveals.clone(),
        }
    }
}

fn run_real_proof(
    fixture: &mut Fixture,
    reuse: bool,
) -> ([u8; RANGE_PROOF_SIZE], [usize; 2], Duration) {
    let drivers = [fixture.driver(), fixture.driver()];
    let mut retained = [None, None];
    let mut original_locals = [None, None];
    let mut shares: [Option<BpRound1ShareV1>; 2] = [None, None];
    let mut computations = [0; 2];
    let mut elapsed = Duration::ZERO;
    // Exact normal stages: commitment, reveal, then reconstruction before R2.
    for _ in 0..3 {
        for actor in 0..2 {
            let fresh = fixture.fresh(actor);
            let start = Instant::now();
            let share = if reuse {
                drivers[actor]
                    .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained[actor])
                    .unwrap()
            } else {
                let share = drivers[actor].round1(&fixture.statement, &fresh).unwrap();
                computations[actor] += 1;
                original_locals[actor] = Some(fresh);
                share
            };
            elapsed += start.elapsed();
            if let Some(previous) = &shares[actor] {
                assert_eq!(&share, previous);
                assert_eq!(share.reveal_commitment(), previous.reveal_commitment());
            }
            shares[actor] = Some(share);
        }
    }
    for actor in 0..2 {
        assert_eq!(fixture.vaults[actor].open_count, 4);
        if reuse {
            let holder = retained[actor].take().unwrap();
            computations[actor] = holder.original_computations;
            original_locals[actor] = Some(holder.into_local_for_round2_v25());
        }
    }
    let shares = shares.map(Option::unwrap);
    let r1 = AggregateBpRound1::new(
        &fixture.statement,
        &shares.each_ref().map(BpRound1ShareV1::reveal_commitment),
        &shares,
    )
    .unwrap();
    let mut r2_shares = Vec::new();
    for actor in 0..2 {
        let local = original_locals[actor].as_ref().unwrap();
        let durable = drivers[actor]
            .round2_vault_backed_v1(&fixture.statement, local, &r1, &mut fixture.vaults[actor])
            .unwrap();
        assert!(fixture.vaults[actor].plaintext.is_none());
        assert!(fixture.vaults[actor].round2_consumed);
        assert_eq!(fixture.vaults[actor].round2_persist_count, 1);
        assert!(drivers[actor]
            .round2_vault_backed_v1(&fixture.statement, local, &r1, &mut fixture.vaults[actor])
            .is_err());
        let bytes = durable.into_zeroizing_bytes();
        let replay = drivers[actor]
            .resume_persisted_round2_v1(
                &fixture.statement,
                actor as u16,
                &mut fixture.vaults[actor],
            )
            .unwrap()
            .into_zeroizing_bytes();
        assert!(bytes.as_ref() == replay.as_ref());
        r2_shares.push(BpRound2ShareV1::from_bytes(bytes.as_ref(), &fixture.statement).unwrap());
    }
    let r2 = AggregateBpRound2::new(&fixture.statement, r2_shares).unwrap();
    let proof = fixture
        .driver()
        .finalize_vault_backed_v1(&fixture.statement, 0, &r1, &r2, &mut fixture.vaults[0])
        .unwrap()
        .into_proof();
    for driver in &drivers {
        driver.verify_final(&fixture.statement, &proof).unwrap();
    }
    let reopened = fixture
        .driver()
        .resume_persisted_proof_v1(&fixture.statement, 0, &r1, &mut fixture.vaults[0])
        .unwrap()
        .into_proof();
    assert_eq!(reopened.as_bytes(), proof.as_bytes());
    (*proof.as_bytes(), computations, elapsed)
}

#[test]
fn real_two_party_round1_three_to_one_preserves_final_proof_and_durable_round2_v25() {
    let mut reused = Fixture::new(vec![0x5a; 96], 22);
    let mut original = reused.independent_nonce_snapshot();
    let (original_proof, original_counts, original_time) = run_real_proof(&mut original, false);
    let (reused_proof, reused_counts, reused_time) = run_real_proof(&mut reused, true);
    assert_eq!(original_proof, reused_proof);
    assert_eq!(original_counts, [3, 3]);
    assert_eq!(reused_counts, [1, 1]);
    eprintln!(
        "native Round1 continuation v25: two_actors=true original_calls=6 continued_calls=2 \
         original_three_stage_us={} continued_cold_plus_two_reuse_us={} \
         measurement=round1_only_not_swap",
        original_time.as_micros(),
        reused_time.as_micros(),
    );
}

#[test]
fn changed_private_origin_or_participant_refuses_without_replacing_round1_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let driver = fixture.driver();
    let mut retained = None;
    let fresh = fixture.fresh(0);
    let first = driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    for operand in 0..4 {
        let mut fresh = fixture.fresh(0);
        if operand == 3 {
            fresh.participant_index = 1;
        } else {
            let mut stage = fresh.stage.lock().unwrap();
            let LocalStage::Ready {
                blinding,
                common_nonce,
                private_nonce,
            } = &mut *stage
            else {
                panic!("fresh Ready")
            };
            match operand {
                0 => *blinding = BpLocalBlindingV1::from_signing_share(&signing_share(7)).unwrap(),
                1 => {
                    // Isolate only the common nonce using another fully
                    // authenticated commitment/reveal ceremony, same statement.
                    let mut other = Fixture::new(vec![0x5a; 96], 22);
                    let other = other.fresh(0);
                    let LocalStage::Ready {
                        common_nonce: replacement,
                        ..
                    } = other.stage.into_inner().unwrap()
                    else {
                        panic!("fresh other")
                    };
                    *common_nonce = replacement;
                }
                2 => {
                    let mut bytes = Zeroizing::new([0; 32]);
                    bytes[31] = 9;
                    *private_nonce = BpPrivateNonceV1::from_persisted_bytes(bytes).unwrap();
                }
                _ => unreachable!(),
            }
        }
        assert!(matches!(
            driver.round1_with_continuation_v25(&fixture.statement, fresh, &mut retained),
            Err(AdaptorError::AuthorizationMismatch)
        ));
        assert_eq!(retained.as_ref().unwrap().original_computations, 1);
        assert_eq!(retained.as_ref().unwrap().share, first);
        let fresh = fixture.fresh(0);
        assert_eq!(
            driver
                .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
                .unwrap(),
            first
        );
    }
}

#[test]
fn complete_statement_and_raw_extra_are_compared_before_round1_reuse_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let driver = fixture.driver();
    let mut retained = None;
    let fresh = fixture.fresh(0);
    let first = driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    for (extra, session) in [
        (vec![0x5a; 96], 23),
        (vec![0x5b; 96], 22),
        (vec![0x5a; 97], 22),
    ] {
        let mut other = Fixture::new(extra, session);
        let other_driver = other.driver();
        let fresh = other.fresh(0);
        assert!(matches!(
            other_driver.round1_with_continuation_v25(&other.statement, fresh, &mut retained),
            Err(AdaptorError::AuthorizationMismatch)
        ));
        assert_eq!(retained.as_ref().unwrap().original_computations, 1);
        assert_eq!(retained.as_ref().unwrap().share, first);
    }
    // Same driver/statement hash is not a substitute for comparing exact
    // framing. This private test seam alters only the stored public operand.
    for changed in 0..4 {
        let origin = retained.as_mut().unwrap().origin.as_mut().unwrap();
        match changed {
            0 => origin.statement[70] ^= 1,
            1 => origin.statement_len -= 1,
            2 => origin.extra[0] ^= 1,
            3 => origin.extra_len -= 1,
            _ => unreachable!(),
        }
        let fresh = fixture.fresh(0);
        assert!(matches!(
            driver.round1_with_continuation_v25(&fixture.statement, fresh, &mut retained),
            Err(AdaptorError::AuthorizationMismatch)
        ));
        let origin = retained.as_mut().unwrap().origin.as_mut().unwrap();
        match changed {
            0 => origin.statement[70] ^= 1,
            1 => origin.statement_len += 1,
            2 => origin.extra[0] ^= 1,
            3 => origin.extra_len += 1,
            _ => unreachable!(),
        }
    }
}

#[test]
fn fresh_guards_and_consumed_state_never_become_round1_reuse_authority_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let driver = fixture.driver();
    let mut retained = None;
    let fresh = fixture.fresh(0);
    let first = driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    for guard in 0..3 {
        let mut fresh = fixture.fresh(0);
        match guard {
            0 => fresh.statement_hash[0] ^= 1,
            1 => fresh.participant_index = u16::MAX,
            2 => *fresh.stage.lock().unwrap() = LocalStage::Consumed,
            _ => unreachable!(),
        }
        assert!(driver
            .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
            .is_err());
        assert_eq!(retained.as_ref().unwrap().original_computations, 1);
        assert_eq!(retained.as_ref().unwrap().share, first);
    }
    let fresh = fixture.fresh(0);
    assert_eq!(
        driver
            .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
            .unwrap(),
        first
    );
    // An impossible-through-public-API damaged holder still cannot release a
    // cached share, and does not consume the fresh material through a backend.
    *retained.as_ref().unwrap().local.stage.lock().unwrap() = LocalStage::Consumed;
    let fresh = fixture.fresh(0);
    assert!(driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .is_err());
    assert_eq!(retained.as_ref().unwrap().original_computations, 1);
}

#[test]
fn dropping_round1_holder_restarts_original_without_changing_public_share_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let mut retained = None;
    let fresh = fixture.fresh(0);
    let first = fixture
        .driver()
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    assert_eq!(retained.as_ref().unwrap().original_computations, 1);
    drop(retained.take());
    let fresh = fixture.fresh(0);
    let second = fixture
        .driver()
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(retained.as_ref().unwrap().original_computations, 1);
    let local = retained.take().unwrap().into_local_for_round2_v25();
    assert!(fixture.driver().round1(&fixture.statement, &local).is_err());
    assert!(matches!(
        *local.stage.lock().unwrap(),
        LocalStage::Round1Done { .. }
    ));
}

#[test]
fn oversized_extra_always_computes_original_and_never_becomes_round1_memo_v25() {
    let mut fixture = Fixture::new(vec![0x5a; MAX_EXTRA_BYTES_V25 + 1], 22);
    let driver = fixture.driver();
    let mut retained = None;
    let mut previous = None;
    for calls in 1..=3 {
        let fresh = fixture.fresh(0);
        let share = driver
            .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
            .unwrap();
        assert!(retained.as_ref().unwrap().origin.is_none());
        assert_eq!(retained.as_ref().unwrap().original_computations, calls);
        if let Some(previous) = previous {
            assert_eq!(share, previous);
        }
        previous = Some(share);
    }
    let local = retained.take().unwrap().into_local_for_round2_v25();
    assert!(matches!(
        *local.stage.lock().unwrap(),
        LocalStage::Round1Done { .. }
    ));
}

#[test]
fn failed_durable_round2_cannot_reuse_the_moved_round1_state_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let drivers = [fixture.driver(), fixture.driver()];
    let mut retained = [None, None];
    let shares = [0, 1].map(|actor| {
        let fresh = fixture.fresh(actor);
        drivers[actor]
            .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained[actor])
            .unwrap()
    });
    let r1 = AggregateBpRound1::new(
        &fixture.statement,
        &shares.each_ref().map(BpRound1ShareV1::reveal_commitment),
        &shares,
    )
    .unwrap();
    // Preserve the normal R2 gate: another real fresh vault import/finish
    // precedes moving the sole retained state to the original durable boundary.
    let fresh = fixture.fresh(0);
    drivers[0]
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained[0])
        .unwrap();
    let local = retained[0].take().unwrap().into_local_for_round2_v25();
    fixture.vaults[0].binding = None; // Synthetic vault persistence refusal.
    assert!(drivers[0]
        .round2_vault_backed_v1(&fixture.statement, &local, &r1, &mut fixture.vaults[0])
        .is_err());
    assert!(retained[0].is_none());
    assert_eq!(fixture.vaults[0].round2_persist_count, 0);
    assert!(matches!(*local.stage.lock().unwrap(), LocalStage::Consumed));
    assert!(drivers[0]
        .round2_vault_backed_v1(&fixture.statement, &local, &r1, &mut fixture.vaults[0])
        .is_err());
    assert!(drivers[0]
        .round1_with_continuation_v25(&fixture.statement, local, &mut retained[0])
        .is_err());
    assert!(retained[0].is_none());
    assert_eq!(retained[1].as_ref().unwrap().original_computations, 1);
}

#[test]
fn poisoned_fresh_or_retained_round1_state_refuses_without_replacement_v25() {
    let mut fixture = Fixture::new(vec![0x5a; 96], 22);
    let driver = fixture.driver();
    let mut retained = None;
    let fresh = fixture.fresh(0);
    let first = driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .unwrap();
    let fresh = fixture.fresh(0);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = fresh.stage.lock().unwrap();
        panic!("synthetic fresh lock poison");
    }))
    .is_err());
    assert!(driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .is_err());
    assert_eq!(retained.as_ref().unwrap().share, first);
    assert_eq!(retained.as_ref().unwrap().original_computations, 1);
    let fresh = fixture.fresh(0);
    assert_eq!(
        driver
            .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
            .unwrap(),
        first
    );
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = retained.as_ref().unwrap().local.stage.lock().unwrap();
        panic!("synthetic retained lock poison");
    }))
    .is_err());
    let fresh = fixture.fresh(0);
    assert!(driver
        .round1_with_continuation_v25(&fixture.statement, fresh, &mut retained)
        .is_err());
    assert_eq!(retained.as_ref().unwrap().share, first);
    assert_eq!(retained.as_ref().unwrap().original_computations, 1);
}
