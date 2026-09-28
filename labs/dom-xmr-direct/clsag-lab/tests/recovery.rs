use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as G, EIGHT_TORSION},
    scalar::Scalar,
    traits::Identity,
};
use dxp1_clsag_lab::recovery::{RecoveryError, RecoveryPlan, RecoveryWindow};
use rand_core::OsRng;
use zeroize::Zeroizing;

fn fixture() -> (
    RecoveryPlan,
    Vec<dxp1_clsag_lab::recovery::RecoveryShare>,
    Zeroizing<Scalar>,
) {
    let secret = Zeroizing::new(Scalar::random(&mut OsRng));
    let (plan, shares) = RecoveryPlan::from_secret([7; 32], &secret, 3, 5, &mut OsRng).unwrap();
    (plan, shares, secret)
}

#[test]
fn reconstructs_from_any_verified_threshold_subset() {
    let (plan, shares, secret) = fixture();

    for subset in [
        vec![shares[0].clone(), shares[1].clone(), shares[2].clone()],
        vec![shares[0].clone(), shares[2].clone(), shares[4].clone()],
        vec![shares[1].clone(), shares[3].clone(), shares[4].clone()],
    ] {
        for share in &subset {
            plan.verify_share(share).unwrap();
        }
        assert_eq!(*plan.recover(&subset).unwrap(), *secret);
    }
}

#[test]
fn rejects_a_forged_scalar_even_when_other_shares_are_valid() {
    let (plan, mut shares, _) = fixture();
    shares[0].scalar += Scalar::ONE;

    assert_eq!(plan.verify_share(&shares[0]), Err(RecoveryError::Share));
    assert_eq!(
        plan.recover(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
        Err(RecoveryError::Share)
    );
}

#[test]
fn recovery_uses_actual_share_indexes() {
    let (plan, shares, secret) = fixture();
    let non_prefix_subset = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];

    assert_eq!(*plan.recover(&non_prefix_subset).unwrap(), *secret);
}

#[test]
fn rejects_duplicate_or_out_of_range_indexes() {
    let (plan, mut shares, _) = fixture();
    shares[1].index = shares[0].index;
    assert_eq!(
        plan.recover(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
        Err(RecoveryError::Index)
    );

    let (plan, mut shares, _) = fixture();
    shares[0].index = 0;
    assert_eq!(
        plan.recover(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
        Err(RecoveryError::Index)
    );

    let (plan, mut shares, _) = fixture();
    shares[0].index = 6;
    assert_eq!(
        plan.recover(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
        Err(RecoveryError::Index)
    );
}

#[test]
fn rejects_bad_plan_parameters_and_public_points() {
    let (plan, _, _) = fixture();

    assert_eq!(
        RecoveryPlan::from_commitments([0; 32], 3, 5, plan.commitments.clone()),
        Err(RecoveryError::Parameters)
    );
    assert_eq!(
        RecoveryPlan::from_commitments([7; 32], 0, 5, plan.commitments.clone()),
        Err(RecoveryError::Parameters)
    );
    assert_eq!(
        RecoveryPlan::from_commitments([7; 32], 4, 3, plan.commitments.clone()),
        Err(RecoveryError::Parameters)
    );

    let mut bad = plan.commitments.clone();
    bad[0] = curve25519_dalek::edwards::EdwardsPoint::identity();
    assert_eq!(
        RecoveryPlan::from_commitments([7; 32], 3, 5, bad),
        Err(RecoveryError::Point)
    );

    let mut bad = plan.commitments.clone();
    bad[1] += EIGHT_TORSION[1];
    assert_eq!(
        RecoveryPlan::from_commitments([7; 32], 3, 5, bad),
        Err(RecoveryError::Point)
    );
}

#[test]
fn rejects_secret_that_does_not_match_the_public_commitment() {
    let (mut plan, shares, _) = fixture();
    plan.commitments[0] += G;

    assert_eq!(
        plan.recover(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
        Err(RecoveryError::Share)
    );
}

#[test]
fn recovery_window_combines_verified_opened_shares_with_one_delayed_share() {
    let (plan, shares, secret) = fixture();
    let window = RecoveryWindow::new(
        &plan,
        vec![shares[1].clone(), shares[3].clone()],
        vec![1, 3, 5],
    )
    .unwrap();

    assert_eq!(
        *window
            .recover_with_delayed_share(&plan, shares[4].clone())
            .unwrap(),
        *secret
    );
}

#[test]
fn recovery_window_rejects_forged_delayed_share_before_reconstruction() {
    let (plan, mut shares, _) = fixture();
    let window =
        RecoveryWindow::new(&plan, vec![shares[1].clone(), shares[3].clone()], vec![1]).unwrap();
    shares[0].scalar += Scalar::ONE;

    assert_eq!(
        window.recover_with_delayed_share(&plan, shares[0].clone()),
        Err(RecoveryError::Share)
    );
}

#[test]
fn recovery_window_rejects_bad_opened_or_unlisted_delayed_indexes() {
    let (plan, mut shares, _) = fixture();
    shares[1].scalar += Scalar::ONE;
    assert_eq!(
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![3]),
        Err(RecoveryError::Share)
    );

    let (plan, shares, _) = fixture();
    let window =
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![3]).unwrap();
    assert_eq!(
        window.recover_with_delayed_share(&plan, shares[4].clone()),
        Err(RecoveryError::Index)
    );

    assert_eq!(
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![1]),
        Err(RecoveryError::Index)
    );
}

#[test]
fn recovery_bindings_change_with_plan_or_window_material() {
    let (plan, shares, _) = fixture();
    let plan_binding = plan.binding().unwrap();

    let mut changed_domain = plan.clone();
    changed_domain.domain[0] ^= 1;
    assert_ne!(changed_domain.binding().unwrap(), plan_binding);

    let mut changed_commitment = plan.clone();
    changed_commitment.commitments[1] += G;
    assert_ne!(changed_commitment.binding().unwrap(), plan_binding);

    let window =
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![3]).unwrap();
    let window_binding = window.binding(&plan).unwrap();

    let other_window =
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![4]).unwrap();
    assert_ne!(other_window.binding(&plan).unwrap(), window_binding);

    let other_window =
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[2].clone()], vec![4]).unwrap();
    assert_ne!(other_window.binding(&plan).unwrap(), window_binding);
}

#[test]
fn recovery_revalidates_mutated_window_before_consuming_delayed_share() {
    let (plan, shares, _) = fixture();
    let mut window =
        RecoveryWindow::new(&plan, vec![shares[0].clone(), shares[1].clone()], vec![3]).unwrap();
    window.delayed_indexes.push(1);
    assert_eq!(
        window.recover_with_delayed_share(&plan, shares[2].clone()),
        Err(RecoveryError::Index)
    );
}
