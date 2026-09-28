use curve25519_dalek::scalar::Scalar;
use dxp1_clsag_lab::{
    dom_recovery::*, dom_reserve::*, recovery::*, recovery_challenge::RecoveryChallenge,
};
use rand_core::OsRng;

fn setup() -> ([ReserveShare; 2], VerifiedReserve) {
    let shares = [
        ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
        ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
    ];
    let reserve = reserve(&shares, 8);
    (shares, reserve)
}
fn reserve(shares: &[ReserveShare; 2], session: u8) -> VerifiedReserve {
    let intent = ReserveIntent::new(
        100_000_000,
        [7; 32],
        [session; 32],
        [9; 32],
        shares.each_ref().map(|s| s.public_key()),
    )
    .unwrap();
    let proofs = [
        shares[0].prove(&intent, 0).unwrap(),
        shares[1].prove(&intent, 1).unwrap(),
    ];
    intent.authorize(proofs).unwrap()
}
fn window(m: &DomRecoveryMaterial) -> (RecoveryChallenge, RecoveryWindow) {
    // Deliberately synthetic capsule bytes. Tests prove linkage, not delay.
    let challenge = RecoveryChallenge::derive(
        &m.plan,
        b"setup",
        &(0..6).map(|i| vec![i + 1]).collect::<Vec<_>>(),
        b"range-proof",
    )
    .unwrap();
    let opened = challenge
        .opened_indexes()
        .iter()
        .map(|i| m.puzzle_shares[usize::from(*i) - 1].clone())
        .collect();
    let window = challenge.window(&m.plan, opened).unwrap();
    (challenge, window)
}

#[test]
fn recovered_dom_share_matches_both_curves_and_only_its_reservation() {
    let (shares, reservation) = setup();
    for i in 0..2 {
        let material =
            DomRecoveryMaterial::create(&shares[i], &reservation, i as u8, 6, &mut OsRng).unwrap();
        let (challenge, window) = window(&material);
        let link = DomRecoveryLink::new(
            &reservation,
            i as u8,
            &material.plan,
            &material.cross_curve,
            &challenge,
            &window,
        )
        .unwrap();
        for delayed in challenge.delayed_indexes() {
            let opening = material.puzzle_shares[usize::from(*delayed) - 1].clone();
            let recovered = link
                .recover_after_opening(&reservation, i as u8, opening.clone())
                .unwrap();
            assert_eq!(
                recovered.public_key().to_compressed_bytes(),
                shares[i].public_key().to_compressed_bytes()
            );
            assert!(link
                .recover_after_opening(&reservation, 1 - i as u8, opening.clone())
                .is_err());
            assert!(link
                .recover_after_opening(&reserve(&shares, 9), i as u8, opening.clone())
                .is_err());
            let mut wrong = opening;
            wrong.scalar += Scalar::ONE;
            assert!(link
                .recover_after_opening(&reservation, i as u8, wrong)
                .is_err());
        }
        assert!(link
            .recover_after_opening(&reservation, i as u8, window.opened[0].clone())
            .is_err());
    }
}

#[test]
fn key_domain_proof_and_window_substitution_are_rejected() {
    let (shares, reservation) = setup();
    let m = DomRecoveryMaterial::create(&shares[1], &reservation, 1, 6, &mut OsRng).unwrap();
    let (challenge, w) = window(&m);
    assert!(
        DomRecoveryLink::new(&reservation, 0, &m.plan, &m.cross_curve, &challenge, &w).is_err()
    );
    assert!(DomRecoveryLink::new(
        &reserve(&shares, 9),
        1,
        &m.plan,
        &m.cross_curve,
        &challenge,
        &w
    )
    .is_err());
    let mut plan = m.plan.clone();
    plan.domain[0] ^= 1;
    assert!(DomRecoveryLink::new(&reservation, 1, &plan, &m.cross_curve, &challenge, &w).is_err());
    let mut proof = m.cross_curve.clone();
    proof.proof[10] ^= 1;
    assert!(DomRecoveryLink::new(&reservation, 1, &m.plan, &proof, &challenge, &w).is_err());
    let other = DomRecoveryMaterial::create(&shares[0], &reservation, 0, 6, &mut OsRng).unwrap();
    assert!(
        DomRecoveryLink::new(&reservation, 1, &m.plan, &other.cross_curve, &challenge, &w).is_err()
    );
    let mut altered = w.clone();
    altered.opened[0].scalar += Scalar::ONE;
    assert!(DomRecoveryLink::new(
        &reservation,
        1,
        &m.plan,
        &m.cross_curve,
        &challenge,
        &altered
    )
    .is_err());
    let another_challenge = RecoveryChallenge::derive(
        &m.plan,
        b"other setup",
        &(0..6).map(|i| vec![i + 1]).collect::<Vec<_>>(),
        b"range-proof",
    )
    .unwrap();
    let another_window = another_challenge
        .window(
            &m.plan,
            another_challenge
                .opened_indexes()
                .iter()
                .map(|i| m.puzzle_shares[usize::from(*i) - 1].clone())
                .collect(),
        )
        .unwrap();
    let a = DomRecoveryLink::new(&reservation, 1, &m.plan, &m.cross_curve, &challenge, &w).unwrap();
    let b = DomRecoveryLink::new(
        &reservation,
        1,
        &m.plan,
        &m.cross_curve,
        &another_challenge,
        &another_window,
    )
    .unwrap();
    assert_ne!(a.binding(), b.binding());
}

#[test]
fn wrong_dealer_and_unsupported_counts_fail_before_capsule_generation() {
    let (shares, reservation) = setup();
    assert!(DomRecoveryMaterial::create(&shares[0], &reservation, 1, 6, &mut OsRng).is_err());
    for n in [0, 1, 3, 513, 65535] {
        assert!(DomRecoveryMaterial::create(&shares[0], &reservation, 0, n, &mut OsRng).is_err());
    }
}
