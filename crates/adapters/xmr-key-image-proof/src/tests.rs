use super::*;

// Deterministic RNG is confined to mathematical tests. No transaction,
// authorization, daemon fixture, or production witness is generated here.
struct TestRng(u8);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        u32::from(self.next_u64() as u8)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(1);
        u64::from(self.0)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

fn context() -> InputSpendContextV23 {
    InputSpendContextV23 {
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        terms: [4; 32],
        funding_tx: [5; 32],
        output_index: 2,
        sweep_tx: [6; 32],
        destination: [7; 32],
        funded_amount: 1000,
        fee: 10,
        action: InputSpendActionV23::Claim,
    }
}
fn fixture() -> (InputSpendContextV23, [u8; 32], [u8; 32], InputSpendProofV23) {
    let x = Scalar::from(17u64);
    let p = (x * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let i = (x * hash_point(p).unwrap()).compress().to_bytes();
    let ctx = context();
    let proof = prove_input_spend_v23(&ctx, p, i, &x.to_bytes(), &mut TestRng(3)).unwrap();
    (ctx, p, i, proof)
}

#[test]
fn equations_roundtrip_and_fresh_nonce() {
    let (ctx, p, i, proof) = fixture();
    verify_input_spend_v23(&ctx, p, i, &proof).unwrap();
    assert_eq!(InputSpendProofV23::decode(proof.as_bytes()).unwrap(), proof);
    let other = prove_input_spend_v23(
        &ctx,
        p,
        i,
        &Scalar::from(17u64).to_bytes(),
        &mut TestRng(19),
    )
    .unwrap();
    assert_ne!(other, proof);
    verify_input_spend_v23(&ctx, p, i, &other).unwrap();
    assert!(
        prove_input_spend_v23(&ctx, p, i, &Scalar::from(18u64).to_bytes(), &mut TestRng(3))
            .is_err()
    );
}

/// One in-place edit of a scope field, used to prove each one is bound.
type ScopeMutation = Box<dyn Fn(&mut InputSpendContextV23)>;

#[test]
fn every_scope_field_and_both_statement_points_are_bound() {
    let (ctx, p, i, proof) = fixture();
    let mutations: Vec<ScopeMutation> = vec![
        Box::new(|v| v.network_genesis[0] ^= 1),
        Box::new(|v| v.route[0] ^= 1),
        Box::new(|v| v.session[0] ^= 1),
        Box::new(|v| v.terms[0] ^= 1),
        Box::new(|v| v.funding_tx[0] ^= 1),
        Box::new(|v| v.output_index += 1),
        Box::new(|v| v.sweep_tx[0] ^= 1),
        Box::new(|v| v.destination[0] ^= 1),
        Box::new(|v| v.funded_amount += 1),
        Box::new(|v| v.fee += 1),
        Box::new(|v| v.action = InputSpendActionV23::Refund),
    ];
    for mutate in mutations {
        let mut altered = ctx.clone();
        mutate(&mut altered);
        assert!(verify_input_spend_v23(&altered, p, i, &proof).is_err());
    }
    let other = (Scalar::from(19u64) * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    assert!(verify_input_spend_v23(&ctx, other, i, &proof).is_err());
    assert!(verify_input_spend_v23(&ctx, p, other, &proof).is_err());
}

#[test]
fn reject_identity_torsion_noncanonical_scalar_and_wire_lengths() {
    let (ctx, p, i, proof) = fixture();
    for bad in [
        EdwardsPoint::default().compress().to_bytes(),
        curve25519_dalek::constants::EIGHT_TORSION[1]
            .compress()
            .to_bytes(),
        [255; 32],
    ] {
        assert!(verify_input_spend_v23(&ctx, bad, i, &proof).is_err());
        assert!(verify_input_spend_v23(&ctx, p, bad, &proof).is_err());
        let mut encoded = *proof.as_bytes();
        encoded[..32].copy_from_slice(&bad);
        assert!(InputSpendProofV23::decode(&encoded).is_err());
    }
    let mut encoded = *proof.as_bytes();
    encoded[64..].fill(255);
    assert!(InputSpendProofV23::decode(&encoded).is_err());
    assert!(InputSpendProofV23::decode(&proof.as_bytes()[..95]).is_err());
    let mut trailing = proof.as_bytes().to_vec();
    trailing.push(0);
    assert!(InputSpendProofV23::decode(&trailing).is_err());
    for unknown in [0, 3, 255] {
        assert!(InputSpendActionV23::from_wire(unknown).is_err());
    }
}
