use dom_crypto::{pedersen::BlindingFactor, range_proof_verify, SecretKey, MAX_PROVABLE_VALUE};
use dxp1_clsag_lab::dom_reserve::*;
use rand_core::OsRng;
use zeroize::Zeroizing;

fn shares() -> [ReserveShare; 2] {
    [
        ReserveShare::generate(&mut OsRng).unwrap(),
        ReserveShare::generate(&mut OsRng).unwrap(),
    ]
}
fn intent(shares: &[ReserveShare; 2], value: u64, session: u8) -> ReserveIntent {
    ReserveIntent::new(
        value,
        [7; 32],
        [session; 32],
        [9; 32],
        shares.each_ref().map(|s| s.public_key()),
    )
    .unwrap()
}
fn plan(shares: &[ReserveShare; 2], value: u64, session: u8) -> VerifiedReserve {
    let intent = intent(shares, value, session);
    let proofs = [
        shares[0].prove(&intent, 0).unwrap(),
        shares[1].prove(&intent, 1).unwrap(),
    ];
    intent.authorize(proofs).unwrap()
}
fn rounds(
    shares: &[ReserveShare; 2],
    plan: &VerifiedReserve,
    same_seed: bool,
) -> [(ReserveRoundOne, ReserveCommitment); 2] {
    [0, 1].map(|i| {
        shares[i]
            .begin_proof(
                plan.clone(),
                i as u8,
                &Zeroizing::new([if i == 0 || same_seed { 8 } else { 9 }; 32]),
                &mut OsRng,
            )
            .unwrap()
    })
}

#[test]
fn shared_range_proof_passes_the_native_verifier_at_boundary_values() {
    for value in [1, 100_000_000, MAX_PROVABLE_VALUE] {
        let shares = shares();
        let plan = plan(&shares, value, 8);
        let [(a, ma), (b, mb)] = rounds(&shares, &plan, true);
        let (a, sa) = a.respond(&mb).unwrap();
        let (b, sb) = b.respond(&ma).unwrap();
        let proof_a = a.complete(sb).unwrap();
        let proof_b = b.complete(sa).unwrap();
        assert_eq!(proof_a, proof_b);
        assert_eq!(proof_a.len(), dom_crypto::RANGE_PROOF_SIZE);
        assert!(range_proof_verify(plan.commitment().as_bytes(), &proof_a).unwrap());
        let other = dom_crypto::pedersen::Commitment::commit(value, &BlindingFactor::random());
        assert!(!range_proof_verify(other.as_bytes(), &proof_a).unwrap_or(false));
        let mut corrupt = proof_a;
        corrupt[100] ^= 1;
        assert!(!range_proof_verify(plan.commitment().as_bytes(), &corrupt).unwrap_or(false));
    }
}

#[test]
fn possession_and_shape_checks_precede_mpc() {
    let shares = shares();
    let original = intent(&shares, 42, 8);
    let proofs = [
        shares[0].prove(&original, 0).unwrap(),
        shares[1].prove(&original, 1).unwrap(),
    ];
    assert!(shares[0].prove(&original, 1).is_err());
    assert!(shares[0].prove(&original, 2).is_err());
    assert!(intent(&shares, 43, 8).authorize(proofs.clone()).is_err());
    assert!(intent(&shares, 42, 9).authorize(proofs.clone()).is_err());
    assert!(original
        .clone()
        .authorize([proofs[1].clone(), proofs[0].clone()])
        .is_err());
    let p = original.authorize(proofs).unwrap();
    assert!(shares[0]
        .begin_proof(p, 1, &Zeroizing::new([8; 32]), &mut OsRng)
        .is_err());
    let keys = shares.each_ref().map(|s| s.public_key());
    for value in [0, MAX_PROVABLE_VALUE + 1] {
        assert!(ReserveIntent::new(value, [7; 32], [8; 32], [9; 32], keys.clone()).is_err());
    }
    for slot in 0..3 {
        let mut context = [[7; 32], [8; 32], [9; 32]];
        context[slot] = [0; 32];
        assert!(ReserveIntent::new(42, context[0], context[1], context[2], keys.clone()).is_err());
    }
    assert!(ReserveIntent::new(
        42,
        [7; 32],
        [8; 32],
        [9; 32],
        [keys[0].clone(), keys[0].clone()]
    )
    .is_err());
}

#[test]
fn altered_commitments_and_round_responses_do_not_produce_a_proof() {
    let shares = shares();
    let plan = plan(&shares, 42, 8);
    for case in 0..5 {
        let [(a, ma), (_, mut mb)] = rounds(&shares, &plan, true);
        match case {
            0 => mb.plan[0] ^= 1,
            1 => mb.index = 0,
            2 => mb.t_one = [0; 33],
            3 => mb.t_two = [255; 33],
            _ => mb.t_one = ma.t_one,
        }
        assert!(a.respond(&mb).is_err());
    }
    for case in 0..5 {
        let [(a, ma), (b, mb)] = rounds(&shares, &plan, true);
        let (a, _) = a.respond(&mb).unwrap();
        let (_, mut sb) = b.respond(&ma).unwrap();
        match case {
            0 => sb.round[0] ^= 1,
            1 => sb.index = 0,
            2 => *sb.scalar = [255; 32],
            3 => sb.scalar[10] ^= 1,
            _ => {
                let [(_, ma2), (b2, _)] = rounds(&shares, &plan, true);
                let (_, other) = b2.respond(&ma2).unwrap();
                sb.scalar = other.scalar;
            }
        }
        assert!(a.complete(sb).is_err());
    }
}

#[test]
fn different_common_seeds_cannot_form_a_valid_aggregate_proof() {
    let shares = shares();
    let plan = plan(&shares, 42, 8);
    let [(a, ma), (b, mb)] = rounds(&shares, &plan, false);
    let (a, sa) = a.respond(&mb).unwrap();
    let (b, sb) = b.respond(&ma).unwrap();
    assert!(a.complete(sb).is_err());
    assert!(b.complete(sa).is_err());
}

#[test]
fn separate_debit_keys_preserve_the_public_reserve_relation() {
    use dom_scriptless_primitives::{
        scriptless_add_public_points, scriptless_subtract_public_points,
    };
    let shares = shares();
    let masks = [BlindingFactor::random(), BlindingFactor::random()];
    let keys = [
        shares[0].debit_key(&masks[0]).unwrap(),
        shares[1].debit_key(&masks[1]).unwrap(),
    ];
    let reserve = scriptless_add_public_points(&shares.each_ref().map(|s| s.public_key())).unwrap();
    let credits = scriptless_add_public_points(
        &masks
            .each_ref()
            .map(|m| SecretKey::from_bytes(m.as_bytes()).unwrap().public_key()),
    )
    .unwrap();
    let expected = scriptless_subtract_public_points(&credits, &reserve).unwrap();
    assert_eq!(
        scriptless_add_public_points(&keys.each_ref().map(|k| k.public_key()))
            .unwrap()
            .to_compressed_bytes(),
        expected.to_compressed_bytes()
    );
    for key in keys {
        assert_ne!(
            key.public_key().to_compressed_bytes(),
            expected.to_compressed_bytes()
        );
    }
}

#[test]
fn backend_keeps_nonempty_application_binding_mandatory_when_present() {
    use dom_crypto::{pedersen::Commitment, PublicKey};
    use dom_scriptless_bulletproof::*;
    use dom_scriptless_primitives::scriptless_add_public_points;
    let blinds = [BlindingFactor::random(), BlindingFactor::random()];
    let commitment = Commitment::commit(42, &blinds[0])
        .add(&Commitment::commit(0, &blinds[1]))
        .unwrap();
    let capsule = b"DXP1/test-only/nonempty-application-binding";
    let mut states = Vec::new();
    let mut messages = Vec::new();
    for blind in blinds {
        let (state, msg) = bulletproof_mpc_round1(
            42,
            blind,
            *commitment.as_bytes(),
            Zeroizing::new([8; 32]),
            Zeroizing::new(*BlindingFactor::random().as_bytes()),
            capsule,
        )
        .unwrap();
        states.push(state);
        messages.push(msg);
    }
    let t1 = scriptless_add_public_points(
        &messages
            .iter()
            .map(|m| PublicKey::from_compressed_bytes(m.t_one()).unwrap())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let t2 = scriptless_add_public_points(
        &messages
            .iter()
            .map(|m| PublicKey::from_compressed_bytes(m.t_two()).unwrap())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut finalizers = Vec::new();
    let mut shares = Vec::new();
    for state in states {
        let (state, share) =
            bulletproof_mpc_round2(state, &t1.to_compressed_bytes(), &t2.to_compressed_bytes())
                .unwrap();
        finalizers.push(state);
        shares.push(share);
    }
    let proof = bulletproof_mpc_finalize(
        finalizers.remove(0),
        bulletproof_mpc_aggregate_tau_x(shares).unwrap(),
    )
    .unwrap();
    assert!(dom_crypto::range_proof_verify_with_extra_commit(
        commitment.as_bytes(),
        &proof,
        capsule
    )
    .unwrap());
    assert!(!dom_crypto::range_proof_verify_with_extra_commit(
        commitment.as_bytes(),
        &proof,
        b"another capsule"
    )
    .unwrap());
    assert!(!range_proof_verify(commitment.as_bytes(), &proof).unwrap());
}
