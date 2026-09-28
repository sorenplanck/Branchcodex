//! Public-roster fixtures with independent additive shares. No group private key
//! is generated or reconstructed. These fixtures do not implement key setup or
//! authenticate a malicious counterparty's claimed verification key.

use std::collections::HashMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::{
    joint::{InputOpening, JointError, JointParticipant, JointPlan, RoundOne, RoundTwo},
    recovery::{RecoveryPlan, RecoveryShare, RecoveryWindow},
    recovery_challenge::RecoveryChallenge,
    xmr_recovery::{XmrRecoveryLink, XmrRecoveryMaterial, XmrRecoveryRoster},
    Context, Statement, RING_SIZE,
};
use frost::{
    curve::Ed25519, dkg::Interpolation, FrostError, Participant, ThresholdKeys, ThresholdParams,
};
use monero_ed25519::{Commitment, Point, Scalar as MoneroScalar};
use rand_core::OsRng;
use zeroize::Zeroizing;

fn ids() -> [Participant; 2] {
    [Participant::new(1).unwrap(), Participant::new(2).unwrap()]
}

fn independent_keys() -> [ThresholdKeys<Ed25519>; 2] {
    // Only public points are combined. Each scalar is moved into its own keys.
    let shares = [
        Zeroizing::new(Scalar::random(&mut OsRng)),
        Zeroizing::new(Scalar::random(&mut OsRng)),
    ];
    let roster = HashMap::from([
        (ids()[0], GroupPoint(*shares[0] * G)),
        (ids()[1], GroupPoint(*shares[1] * G)),
    ]);
    let [a, b] = shares;
    [a, b]
        .into_iter()
        .enumerate()
        .map(|(i, share)| {
            ThresholdKeys::new(
                ThresholdParams::new(2, 2, ids()[i]).unwrap(),
                Interpolation::Constant(vec![Scalar::ONE; 2]),
                share,
                roster.clone(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

struct Fixture {
    context: Context,
    statement: Statement,
    witness: Zeroizing<Scalar>,
    commitment: Commitment,
    pseudo_mask: Zeroizing<Scalar>,
    keys: [ThresholdKeys<Ed25519>; 2],
}

impl Fixture {
    fn new(real: usize, scale: Scalar, offset: Scalar) -> Self {
        let keys = independent_keys().map(|keys| keys.scale(scale).unwrap().offset(offset));
        let amount = 6_000_000;
        let commitment = Commitment::new(MoneroScalar::random(&mut OsRng), amount);
        let pseudo_mask = Zeroizing::new(Scalar::random(&mut OsRng));
        let mut ring = std::array::from_fn(|i| {
            [
                Scalar::random(&mut OsRng) * G,
                Commitment::new(MoneroScalar::random(&mut OsRng), i as u64 + 70)
                    .commit()
                    .into(),
            ]
        });
        ring[real] = [keys[0].group_key().0, commitment.commit().into()];
        assert_eq!(keys[0].group_key(), keys[1].group_key());
        let h = Point::biased_hash(ring[real][0].compress().to_bytes()).into();
        // Combine public key-image contributions, never the scalars.
        let image = keys
            .iter()
            .map(|key| h * **key.view(ids().to_vec()).unwrap().secret_share())
            .sum();
        let context = Context {
            ring,
            real,
            image,
            message: [55; 32],
            route_binding: [38; 32],
            pseudo_out: Commitment::new(MoneroScalar::from(*pseudo_mask), amount)
                .commit()
                .into(),
        };
        let witness = Zeroizing::new(Scalar::random(&mut OsRng));
        let statement = Statement::prove(&context, &witness, &mut OsRng).unwrap();
        Self {
            context,
            statement,
            witness,
            commitment,
            pseudo_mask,
            keys,
        }
    }

    fn plan(&self, session: u8) -> JointPlan {
        JointPlan::new(
            self.context.clone(),
            self.statement.clone(),
            [session; 32],
            vec![1; RING_SIZE],
        )
        .unwrap()
    }
    fn opening(&self) -> InputOpening {
        InputOpening {
            commitment: self.commitment.clone(),
            pseudo_mask: self.pseudo_mask.clone(),
        }
    }
    fn participant(&self, actor: usize, session: u8) -> JointParticipant {
        JointParticipant::new(self.plan(session), self.opening(), self.keys[actor].clone()).unwrap()
    }
    fn first(&self) -> [(RoundOne, Vec<u8>); 2] {
        [
            self.participant(0, 1).preprocess(&mut OsRng),
            self.participant(1, 1).preprocess(&mut OsRng),
        ]
    }
    fn second(&self) -> [(RoundTwo, Vec<u8>); 2] {
        let [(a, ma), (b, mb)] = self.first();
        [a.sign(&mb).unwrap(), b.sign(&ma).unwrap()]
    }
}

#[test]
fn joint_presignature_at_all_ring_positions_completes_and_extracts() {
    for real in 0..RING_SIZE {
        let f = Fixture::new(real, Scalar::ONE, Scalar::ZERO);
        let [(a, ma), (b, mb)] = f.second();
        let pa = a.complete(&mb).unwrap();
        let pb = b.complete(&ma).unwrap();
        assert_eq!(pa, pb);
        assert!(f.context.verify_native(&pa.signature).is_err());
        let final_signature = pa.complete(&f.context, &f.witness).unwrap();
        f.context.verify_native(&final_signature).unwrap();
        assert_eq!(
            *pb.extract(&f.context, &final_signature).unwrap(),
            *f.witness
        );
    }
}

#[test]
fn recovered_peer_share_signs_after_abandonment_with_scanned_output_offset() {
    for role in 0..2 {
        let offset = Scalar::from(19u64);
        let f = Fixture::new(7, Scalar::ONE, offset);
        let roster = XmrRecoveryRoster::new(
            [91; 32],
            ids().map(|id| f.keys[0].original_verification_share(id).0),
        )
        .unwrap();
        let original = f.keys[role].clone().offset(-offset);
        let material = XmrRecoveryMaterial::create(&original, &roster, 6, &mut OsRng).unwrap();
        drop(original);
        // Synthetic backend bytes test linkage and signing, not a timed puzzle.
        let challenge = RecoveryChallenge::derive(
            &material.plan,
            b"test setup",
            &(0..6).map(|i| vec![i + 1]).collect::<Vec<_>>(),
            b"test range proof",
        )
        .unwrap();
        let window = challenge
            .window(
                &material.plan,
                challenge
                    .opened_indexes()
                    .iter()
                    .map(|i| material.puzzle_shares[usize::from(*i) - 1].clone())
                    .collect(),
            )
            .unwrap();
        let link = XmrRecoveryLink::new(&roster, ids()[role], &material.plan, &challenge, &window)
            .unwrap();
        let delayed =
            material.puzzle_shares[usize::from(challenge.delayed_indexes()[0]) - 1].clone();
        drop(material);
        let plan = f.plan(92);
        let openings = [f.opening(), f.opening()];
        let [a, b] = f.keys;
        let (local, remote) = if role == 0 { (b, a) } else { (a, b) };
        drop(remote);
        let restored = link
            .recover_after_opening(&roster, ids()[role], delayed)
            .unwrap()
            .offset(offset);
        assert_eq!(restored.group_key(), local.group_key());
        let [(a, ma), (b, mb)]: [_; 2] = [local, restored]
            .into_iter()
            .zip(openings)
            .map(|(keys, opening)| {
                JointParticipant::new(plan.clone(), opening, keys)
                    .unwrap()
                    .preprocess(&mut OsRng)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let (a, sa) = a.sign(&mb).unwrap();
        let (b, sb) = b.sign(&ma).unwrap();
        let pre = a.complete(&sb).unwrap();
        assert_eq!(pre, b.complete(&sa).unwrap());
        let final_signature = pre.complete(&f.context, &f.witness).unwrap();
        f.context.verify_native(&final_signature).unwrap();
        assert_eq!(
            *pre.extract(&f.context, &final_signature).unwrap(),
            *f.witness
        );
    }
}

#[test]
fn xmr_share_recovery_rejects_wrong_roster_role_capsule_and_opening() {
    let f = Fixture::new(7, Scalar::ONE, Scalar::ZERO);
    let public = ids().map(|id| f.keys[0].original_verification_share(id).0);
    let roster = XmrRecoveryRoster::new([91; 32], public).unwrap();
    let m = XmrRecoveryMaterial::create(&f.keys[1], &roster, 6, &mut OsRng).unwrap();
    let puzzles = (0..6).map(|i| vec![i + 1]).collect::<Vec<_>>();
    let challenge = RecoveryChallenge::derive(&m.plan, b"setup", &puzzles, b"proof").unwrap();
    let window = challenge
        .window(
            &m.plan,
            challenge
                .opened_indexes()
                .iter()
                .map(|i| m.puzzle_shares[usize::from(*i) - 1].clone())
                .collect(),
        )
        .unwrap();
    let link = XmrRecoveryLink::new(&roster, ids()[1], &m.plan, &challenge, &window).unwrap();
    let delayed = m.puzzle_shares[usize::from(challenge.delayed_indexes()[0]) - 1].clone();
    for wrong in [
        XmrRecoveryRoster::new([92; 32], public).unwrap(),
        XmrRecoveryRoster::new([91; 32], [public[1], public[0]]).unwrap(),
    ] {
        assert!(XmrRecoveryLink::new(&wrong, ids()[1], &m.plan, &challenge, &window).is_err());
        assert!(link
            .recover_after_opening(&wrong, ids()[1], delayed.clone())
            .is_err());
    }
    assert!(XmrRecoveryLink::new(&roster, ids()[0], &m.plan, &challenge, &window).is_err());
    assert!(link
        .recover_after_opening(&roster, ids()[0], delayed.clone())
        .is_err());
    assert!(link
        .recover_after_opening(&roster, ids()[1], window.opened[0].clone())
        .is_err());
    let mut forged = delayed;
    forged.scalar += Scalar::ONE;
    assert!(link
        .recover_after_opening(&roster, ids()[1], forged)
        .is_err());
    let mut bad_window = window.clone();
    bad_window.opened[0].scalar += Scalar::ONE;
    assert!(XmrRecoveryLink::new(&roster, ids()[1], &m.plan, &challenge, &bad_window).is_err());
    let other = RecoveryChallenge::derive(&m.plan, b"different setup", &puzzles, b"proof").unwrap();
    let other_window = other
        .window(
            &m.plan,
            other
                .opened_indexes()
                .iter()
                .map(|i| m.puzzle_shares[usize::from(*i) - 1].clone())
                .collect(),
        )
        .unwrap();
    let other_link =
        XmrRecoveryLink::new(&roster, ids()[1], &m.plan, &other, &other_window).unwrap();
    assert_ne!(link.binding(), other_link.binding());
    let mut plan = m.plan.clone();
    plan.domain[0] ^= 1;
    assert!(XmrRecoveryLink::new(&roster, ids()[1], &plan, &challenge, &window).is_err());
}

#[test]
fn xmr_capsule_requires_original_additive_keys_and_valid_parameters() {
    use curve25519_dalek::constants::EIGHT_TORSION;
    let keys = independent_keys();
    let public = ids().map(|id| keys[0].original_verification_share(id).0);
    let roster = XmrRecoveryRoster::new([91; 32], public).unwrap();
    for malformed in [
        [public[0], public[0]],
        [public[0], -public[0]],
        [public[0], G - G],
        [public[0], G + EIGHT_TORSION[1]],
    ] {
        assert!(XmrRecoveryRoster::new([91; 32], malformed).is_err());
    }
    assert!(XmrRecoveryRoster::new([0; 32], public).is_err());
    assert!(roster.share_key(Participant::new(3).unwrap()).is_err());
    for n in [0, 1, 3, 513, 65535] {
        assert!(XmrRecoveryMaterial::create(&keys[0], &roster, n, &mut OsRng).is_err());
    }
    for modified in [
        keys[0].clone().offset(Scalar::ONE),
        keys[0].clone().scale(Scalar::from(2u64)).unwrap(),
        independent_keys()[0].clone(),
    ] {
        assert!(XmrRecoveryMaterial::create(&modified, &roster, 6, &mut OsRng).is_err());
    }
    let false_secret = ThresholdKeys::new(
        ThresholdParams::new(2, 2, ids()[0]).unwrap(),
        Interpolation::Constant(vec![Scalar::ONE; 2]),
        Zeroizing::new(Scalar::random(&mut OsRng)),
        HashMap::from([
            (ids()[0], GroupPoint(public[0])),
            (ids()[1], GroupPoint(public[1])),
        ]),
    )
    .unwrap();
    assert!(XmrRecoveryMaterial::create(&false_secret, &roster, 6, &mut OsRng).is_err());
    let nonadditive = ThresholdKeys::new(
        ThresholdParams::new(2, 2, ids()[0]).unwrap(),
        Interpolation::Lagrange,
        keys[0].original_secret_share().clone(),
        HashMap::from([
            (ids()[0], GroupPoint(public[0])),
            (ids()[1], GroupPoint(public[1])),
        ]),
    )
    .unwrap();
    assert!(XmrRecoveryMaterial::create(&nonadditive, &roster, 6, &mut OsRng).is_err());
}

// Public-only recovery fixtures: no delayed capsule or private input key is
// created here. These tests exercise the signing transcript binding only.
fn recovery_fixture(
    f: &Fixture,
) -> (
    dxp1_clsag_lab::recovery::RecoveryPlan,
    dxp1_clsag_lab::recovery::RecoveryWindow,
) {
    use dxp1_clsag_lab::recovery::{RecoveryPlan, RecoveryWindow};
    let recovery =
        RecoveryPlan::from_commitments([1; 32], 1, 2, vec![f.context.ring[f.context.real][0]])
            .unwrap();
    let window = RecoveryWindow::new(&recovery, vec![], vec![1]).unwrap();
    (recovery, window)
}

#[test]
fn recovery_bound_joint_signature_completes_and_extracts() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window) = recovery_fixture(&f);
    let make = |actor: usize| {
        let plan = JointPlan::new_with_recovery(
            f.context.clone(),
            f.statement.clone(),
            [1; 32],
            vec![1; RING_SIZE],
            &recovery,
            &window,
        )
        .unwrap();
        JointParticipant::new(plan, f.opening(), f.keys[actor].clone())
            .unwrap()
            .preprocess(&mut OsRng)
    };
    let (a, ma) = make(0);
    let (b, mb) = make(1);
    let (a, sa) = a.sign(&mb).unwrap();
    let (b, sb) = b.sign(&ma).unwrap();
    let pa = a.complete(&sb).unwrap();
    let pb = b.complete(&sa).unwrap();
    assert_eq!(pa, pb);
    let signature = pa.complete(&f.context, &f.witness).unwrap();
    f.context.verify_native(&signature).unwrap();
    assert_eq!(*pb.extract(&f.context, &signature).unwrap(), *f.witness);
}

#[test]
fn recovery_bound_signer_rejects_other_window_and_unbound_peer() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window) = recovery_fixture(&f);
    for bind_peer in [false, true] {
        let make = |actor: usize, window: &dxp1_clsag_lab::recovery::RecoveryWindow| {
            JointParticipant::new(
                JointPlan::new_with_recovery(
                    f.context.clone(),
                    f.statement.clone(),
                    [1; 32],
                    vec![1; RING_SIZE],
                    &recovery,
                    window,
                )
                .unwrap(),
                f.opening(),
                f.keys[actor].clone(),
            )
            .unwrap()
            .preprocess(&mut OsRng)
        };
        let (a, _) = make(0, &window);
        let mut other = window.clone();
        other.delayed_indexes = vec![2];
        let (_, mb) = if bind_peer {
            make(1, &other)
        } else {
            f.participant(1, 1).preprocess(&mut OsRng)
        };
        assert_eq!(a.sign(&mb).err(), Some(JointError::Wire));
    }
}

#[test]
fn recovery_binding_rejects_wrong_input_key_session_or_invalid_window() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    for mutation in 0..3 {
        let (mut recovery, mut window) = recovery_fixture(&f);
        match mutation {
            0 => recovery.commitments[0] += G,
            1 => recovery.domain[0] ^= 1,
            _ => window.delayed_indexes.push(1),
        }
        assert_eq!(
            JointPlan::new_with_recovery(
                f.context.clone(),
                f.statement.clone(),
                [1; 32],
                vec![1; RING_SIZE],
                &recovery,
                &window,
            )
            .err(),
            Some(JointError::Setup)
        );
    }
}

// Two synthetic capsules selecting the SAME known share. Their public
// polynomial has the joint key as C0 without reconstructing its scalar.
// n=2 is deliberately insecure and used only to isolate transcript binding.
fn capsule_fixture(f: &Fixture) -> (RecoveryPlan, RecoveryWindow, [RecoveryChallenge; 2]) {
    let opened = RecoveryShare {
        index: 1,
        scalar: Scalar::from(71u64),
    };
    let key = f.context.ring[f.context.real][0];
    let recovery =
        RecoveryPlan::from_commitments([1; 32], 2, 2, vec![key, opened.scalar * G - key]).unwrap();
    let challenges = (0u16..256)
        .filter_map(|salt| {
            let challenge = RecoveryChallenge::derive(
                &recovery,
                &salt.to_le_bytes(),
                &[vec![1], vec![2]],
                b"synthetic proof",
            )
            .unwrap();
            (challenge.opened_indexes() == [1]).then_some(challenge)
        })
        .take(2)
        .collect::<Vec<_>>();
    let challenges: [RecoveryChallenge; 2] = challenges.try_into().unwrap();
    assert_ne!(challenges[0].binding(), challenges[1].binding());
    let window = challenges[0].window(&recovery, vec![opened]).unwrap();
    challenges[1].validate_window(&recovery, &window).unwrap();
    (recovery, window, challenges)
}

#[test]
fn capsule_bound_joint_signature_completes_and_extracts() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window, challenges) = capsule_fixture(&f);
    let plan = JointPlan::new_with_capsule(
        f.context.clone(),
        f.statement.clone(),
        [1; 32],
        vec![1; RING_SIZE],
        &recovery,
        &challenges[0],
        &window,
    )
    .unwrap();
    let make = |actor: usize| {
        JointParticipant::new(plan.clone(), f.opening(), f.keys[actor].clone())
            .unwrap()
            .preprocess(&mut OsRng)
    };
    let (a, ma) = make(0);
    let (b, mb) = make(1);
    let (a, sa) = a.sign(&mb).unwrap();
    let (b, sb) = b.sign(&ma).unwrap();
    let pa = a.complete(&sb).unwrap();
    let pb = b.complete(&sa).unwrap();
    assert_eq!(pa, pb);
    let signature = pa.complete(&f.context, &f.witness).unwrap();
    f.context.verify_native(&signature).unwrap();
    assert_eq!(*pb.extract(&f.context, &signature).unwrap(), *f.witness);
}

#[test]
fn capsule_binding_rejects_same_window_from_another_capsule_or_legacy_peer() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window, challenges) = capsule_fixture(&f);
    let make_plan = |challenge: &RecoveryChallenge| {
        JointPlan::new_with_capsule(
            f.context.clone(),
            f.statement.clone(),
            [1; 32],
            vec![1; RING_SIZE],
            &recovery,
            challenge,
            &window,
        )
        .unwrap()
    };
    let legacy = JointPlan::new_with_recovery(
        f.context.clone(),
        f.statement.clone(),
        [1; 32],
        vec![1; RING_SIZE],
        &recovery,
        &window,
    )
    .unwrap();
    for peer in [make_plan(&challenges[1]), legacy, f.plan(1)] {
        let (a, _) =
            JointParticipant::new(make_plan(&challenges[0]), f.opening(), f.keys[0].clone())
                .unwrap()
                .preprocess(&mut OsRng);
        let (_, mb) = JointParticipant::new(peer, f.opening(), f.keys[1].clone())
            .unwrap()
            .preprocess(&mut OsRng);
        assert_eq!(a.sign(&mb).err(), Some(JointError::Wire));
    }
}

#[test]
fn capsule_binding_revalidates_mutated_window_and_recovery_plan() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window, challenges) = capsule_fixture(&f);
    for mutation in 0..5 {
        let mut recovery = recovery.clone();
        let mut window = window.clone();
        match mutation {
            0 => window.opened[0].scalar += Scalar::ONE,
            1 => window.opened[0].index = 2,
            2 => window.delayed_indexes.clear(),
            3 => recovery.domain[0] ^= 1,
            _ => recovery.commitments[1] += G,
        }
        assert_eq!(
            JointPlan::new_with_capsule(
                f.context.clone(),
                f.statement.clone(),
                [1; 32],
                vec![1; RING_SIZE],
                &recovery,
                &challenges[0],
                &window,
            )
            .err(),
            Some(JointError::Setup)
        );
    }
}

#[test]
fn forging_wire_tags_cannot_mix_signers_bound_to_different_capsules() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    let (recovery, window, challenges) = capsule_fixture(&f);
    let make = |actor: usize| {
        let plan = JointPlan::new_with_capsule(
            f.context.clone(),
            f.statement.clone(),
            [1; 32],
            vec![1; RING_SIZE],
            &recovery,
            &challenges[actor],
            &window,
        )
        .unwrap();
        JointParticipant::new(plan, f.opening(), f.keys[actor].clone())
            .unwrap()
            .preprocess(&mut OsRng)
    };
    let (a, ma) = make(0);
    let (b, mb) = make(1);
    let mut forged_ma = ma.clone();
    let mut forged_mb = mb.clone();
    forged_ma[11..75].copy_from_slice(&mb[11..75]);
    forged_mb[11..75].copy_from_slice(&ma[11..75]);
    // The sender can rewrite public envelope tags. Cryptographic transcript
    // binding must still prevent a final pre-signature from this exchange.
    if let (Ok((a, sa)), Ok((b, sb))) = (a.sign(&forged_mb), b.sign(&forged_ma)) {
        let mut forged_sa = sa.clone();
        let mut forged_sb = sb.clone();
        forged_sa[11..75].copy_from_slice(&sb[11..75]);
        forged_sb[11..75].copy_from_slice(&sa[11..75]);
        assert!(a.complete(&forged_sb).is_err());
        assert!(b.complete(&forged_sa).is_err());
    }
}

#[test]
fn scaled_and_offset_key_shares_support_stealth_key_arithmetic() {
    for (scale, offset) in [
        (Scalar::ONE, Scalar::from(41u64)),
        (Scalar::from(3u64), Scalar::ZERO),
        (Scalar::from(3u64), Scalar::from(41u64)),
    ] {
        let f = Fixture::new(7, scale, offset);
        let [(a, _), (_, mb)] = f.second();
        let pre = a.complete(&mb).unwrap();
        let final_signature = pre.complete(&f.context, &f.witness).unwrap();
        f.context.verify_native(&final_signature).unwrap();
    }
}

#[test]
fn forged_response_is_rejected_and_identifies_the_bad_peer() {
    let f = Fixture::new(3, Scalar::ONE, Scalar::ZERO);
    for bad_actor in 0..2 {
        let [(a, ma), (b, mb)] = f.second();
        let (honest, mut bad_message) = if bad_actor == 0 { (b, ma) } else { (a, mb) };
        let start = bad_message.len() - 32;
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            bad_message[start..].try_into().unwrap(),
        ))
        .unwrap();
        bad_message[start..].copy_from_slice(&(scalar + Scalar::ONE).to_bytes());
        assert_eq!(
            honest.complete(&bad_message).err(),
            Some(JointError::Signing(FrostError::InvalidShare(
                ids()[bad_actor]
            )))
        );
    }
}

#[test]
fn wire_rejects_wrong_session_sender_kind_length_or_trailing_bytes() {
    let f = Fixture::new(4, Scalar::ONE, Scalar::ZERO);
    for corruption in 0..7 {
        let [(a, ma), (_, mut mb)] = f.first();
        match corruption {
            0 => mb[0] ^= 1,
            1 => mb[8] = 2,
            2 => mb[9] = 1,
            3 => mb[11] ^= 1,
            4 => mb.truncate(mb.len() - 1),
            5 => mb.push(0),
            _ => mb.resize(5000, 0),
        }
        assert_eq!(
            a.sign(&mb).err(),
            Some(JointError::Wire),
            "corruption={corruption}"
        );
        drop(ma);
    }
    let (a, _) = f.participant(0, 1).preprocess(&mut OsRng);
    let (_, other_session) = f.participant(1, 2).preprocess(&mut OsRng);
    assert_eq!(a.sign(&other_session).err(), Some(JointError::Wire));
}

#[test]
fn missing_peer_never_produces_a_signature_share_or_final_offer() {
    let f = Fixture::new(5, Scalar::ONE, Scalar::ZERO);
    let [(a, _), _] = f.first();
    assert_eq!(a.sign(&[]).err(), Some(JointError::Wire));
    let [(a, _), _] = f.second();
    assert_eq!(a.complete(&[]).err(), Some(JointError::Wire));
}

#[test]
fn a_response_from_another_nonce_round_cannot_complete() {
    let f = Fixture::new(6, Scalar::ONE, Scalar::ZERO);
    let [(a, _), _] = f.second();
    let [_, (_, mb)] = f.second();
    assert_eq!(a.complete(&mb).err(), Some(JointError::Wire));
}

#[test]
fn declared_key_image_must_equal_joint_contributions_before_releasing_shares() {
    let mut f = Fixture::new(8, Scalar::ONE, Scalar::ZERO);
    f.context.image += G;
    f.statement = Statement::prove(&f.context, &f.witness, &mut OsRng).unwrap();
    let [(a, ma), (b, mb)] = f.first();
    for failure in [a.sign(&mb).err(), b.sign(&ma).err()] {
        assert_eq!(
            failure,
            Some(JointError::Signing(FrostError::InvalidSigningSet(
                "key image differs from the fixed plan"
            )))
        );
    }
}

#[test]
fn different_message_or_route_cannot_mix_with_an_existing_plan() {
    let mut f = Fixture::new(9, Scalar::ONE, Scalar::ZERO);
    let (a, _) = f.participant(0, 1).preprocess(&mut OsRng);
    f.context.message[0] ^= 1;
    f.context.route_binding[0] ^= 1;
    f.statement = Statement::prove(&f.context, &f.witness, &mut OsRng).unwrap();
    let (_, mb) = f.participant(1, 1).preprocess(&mut OsRng);
    assert_eq!(a.sign(&mb).err(), Some(JointError::Wire));
}

#[test]
fn commitment_pseudo_output_and_spend_key_must_match_before_preprocess() {
    let f = Fixture::new(10, Scalar::ONE, Scalar::ZERO);
    let mut opening = f.opening();
    *opening.pseudo_mask += Scalar::ONE;
    assert_eq!(
        JointParticipant::new(f.plan(1), opening, f.keys[0].clone()).err(),
        Some(JointError::Setup)
    );
    let mut opening = f.opening();
    opening.commitment.mask = MoneroScalar::from(Scalar::ONE);
    assert_eq!(
        JointParticipant::new(f.plan(1), opening, f.keys[0].clone()).err(),
        Some(JointError::Setup)
    );
    let unrelated = independent_keys();
    assert_eq!(
        JointParticipant::new(f.plan(1), f.opening(), unrelated[0].clone()).err(),
        Some(JointError::Setup)
    );
}

#[test]
fn invalid_group_points_and_noncanonical_responses_are_rejected() {
    use curve25519_dalek::{constants::EIGHT_TORSION, traits::Identity};
    const HEADER: usize = 75;
    let f = Fixture::new(11, Scalar::ONE, Scalar::ZERO);
    let invalid = [
        curve25519_dalek::edwards::EdwardsPoint::identity()
            .compress()
            .to_bytes(),
        EIGHT_TORSION[1].compress().to_bytes(),
        [255; 32],
    ];
    // Four nonce commitments plus the key-image contribution.
    for field in 0..5 {
        for bytes in invalid {
            let [(a, _), (_, mut mb)] = f.first();
            assert_eq!(mb.len(), HEADER + 5 * 32);
            mb[HEADER + field * 32..HEADER + (field + 1) * 32].copy_from_slice(&bytes);
            assert!(
                a.sign(&mb).is_err(),
                "accepted invalid point in field {field}"
            );
        }
    }
    let [(a, _), (_, mut mb)] = f.second();
    mb[HEADER..].fill(255);
    assert_eq!(a.complete(&mb).err(), Some(JointError::Wire));
}

#[test]
fn forged_round_tag_does_not_make_an_old_signature_share_valid() {
    let f = Fixture::new(12, Scalar::ONE, Scalar::ZERO);
    let [(a, ma), _] = f.second();
    let [_, (_, mut old_share)] = f.second();
    // Tags are binding labels, not authentication. A malicious sender can
    // copy one; algebraic verification must independently reject the response.
    old_share[11..75].copy_from_slice(&ma[11..75]);
    assert_eq!(
        a.complete(&old_share).err(),
        Some(JointError::Signing(FrostError::InvalidShare(ids()[1])))
    );
}
