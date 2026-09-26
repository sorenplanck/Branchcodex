use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dxp1_clsag_lab::{
    recovery::{RecoveryError, RecoveryPlan, RecoveryShare},
    recovery_challenge::RecoveryChallenge,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

fn fixture() -> (RecoveryPlan, Vec<RecoveryShare>, Vec<Vec<u8>>) {
    let (plan, shares) = RecoveryPlan::from_secret(
        [9; 32],
        &Zeroizing::new(Scalar::from(71u64)),
        4,
        6,
        &mut OsRng,
    )
    .unwrap();
    (plan, shares, (1..=6).map(|i| vec![i; 4]).collect())
}

#[test]
fn exact_challenge_window_recovers_and_rejects_other_indexes() {
    let (plan, shares, puzzles) = fixture();
    let challenge = RecoveryChallenge::derive(&plan, b"setup", &puzzles, b"proof").unwrap();
    let opened = challenge
        .opened_indexes()
        .iter()
        .map(|i| shares[usize::from(*i - 1)].clone())
        .collect::<Vec<_>>();
    let window = challenge.window(&plan, opened.clone()).unwrap();
    let delayed = shares[usize::from(challenge.delayed_indexes()[0] - 1)].clone();
    assert_eq!(
        *window
            .recover_with_delayed_share(&plan, delayed.clone())
            .unwrap(),
        Scalar::from(71u64)
    );
    let mut wrong = opened.clone();
    wrong[0] = delayed;
    assert_eq!(
        challenge.window(&plan, wrong),
        Err(RecoveryError::Parameters)
    );
    let mut forged = opened;
    forged[0].scalar += Scalar::ONE;
    assert_eq!(challenge.window(&plan, forged), Err(RecoveryError::Share));
    let mut other = plan.clone();
    other.domain[0] ^= 1;
    assert_eq!(
        challenge.window(&other, window.opened),
        Err(RecoveryError::Parameters)
    );
}

#[test]
fn selection_is_deterministic_disjoint_and_exhaustive_at_supported_sizes() {
    for n in [2, 6, 132, 166, 198, 512] {
        let plan =
            RecoveryPlan::from_commitments([9; 32], n / 2 + 1, n, vec![G; usize::from(n / 2 + 1)])
                .unwrap();
        let puzzles = (0..n).map(|i| i.to_le_bytes().to_vec()).collect::<Vec<_>>();
        let a = RecoveryChallenge::derive(&plan, b"setup", &puzzles, b"proof").unwrap();
        let b = RecoveryChallenge::derive(&plan, b"setup", &puzzles, b"proof").unwrap();
        assert_eq!(a.binding(), b.binding());
        assert_eq!(a.opened_indexes(), b.opened_indexes());
        assert_eq!(a.opened_indexes().len(), usize::from(n / 2));
        assert!(a.opened_indexes().windows(2).all(|pair| pair[0] < pair[1]));
        assert!(a.delayed_indexes().windows(2).all(|pair| pair[0] < pair[1]));
        let mut union = [a.opened_indexes(), a.delayed_indexes()].concat();
        union.sort_unstable();
        assert_eq!(union, (1..=n).collect::<Vec<_>>());
    }
}

#[test]
fn transcript_binds_order_boundaries_setup_proof_and_plan() {
    let (plan, _, puzzles) = fixture();
    let original = RecoveryChallenge::derive(&plan, b"setup", &puzzles, b"proof")
        .unwrap()
        .binding();
    for change in 0..5 {
        let mut p = plan.clone();
        let mut z = puzzles.clone();
        let mut setup = b"setup".to_vec();
        let mut proof = b"proof".to_vec();
        match change {
            0 => p.domain[0] ^= 1,
            1 => z.swap(0, 1),
            2 => setup.push(1),
            3 => proof.push(1),
            _ => p.commitments[1] += G,
        }
        assert_ne!(
            original,
            RecoveryChallenge::derive(&p, &setup, &z, &proof)
                .unwrap()
                .binding()
        );
    }
    let mut a = puzzles.clone();
    let mut b = puzzles;
    a[0] = vec![1];
    a[1] = vec![2, 3];
    b[0] = vec![1, 2];
    b[1] = vec![3];
    assert_ne!(
        RecoveryChallenge::derive(&plan, b"s", &a, b"p")
            .unwrap()
            .binding(),
        RecoveryChallenge::derive(&plan, b"s", &b, b"p")
            .unwrap()
            .binding()
    );
}

#[test]
fn invalid_shapes_and_oversized_fields_fail_before_sampling() {
    let (plan, _, puzzles) = fixture();
    for change in 0..7 {
        let mut p = plan.clone();
        let mut z = puzzles.clone();
        let mut setup = vec![1];
        let mut proof = vec![1];
        match change {
            0 => {
                p.participants = 5;
            }
            1 => {
                p.threshold = 3;
                p.commitments.pop();
            }
            2 => {
                z.pop();
            }
            3 => {
                z[0].clear();
            }
            4 => {
                setup.clear();
            }
            5 => {
                proof = vec![0; 4 * 1024 * 1024 + 1];
            }
            _ => {
                z[0] = vec![0; 65537];
            }
        }
        assert_eq!(
            RecoveryChallenge::derive(&p, &setup, &z, &proof).err(),
            Some(RecoveryError::Parameters)
        );
    }
}
