use super::*;

struct TestRng;
impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        19
    }
    fn next_u64(&mut self) -> u64 {
        19
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(19);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for TestRng {}

#[test]
fn tx_derivation_proves_real_relation_and_rejects_destination_scope_and_key_swaps() {
    let context = InputSpendContextV23 {
        network_genesis: [1; 32],
        route: [2; 32],
        session: [3; 32],
        terms: [4; 32],
        funding_tx: [5; 32],
        output_index: 1,
        sweep_tx: [6; 32],
        destination: [7; 32],
        funded_amount: 100,
        fee: 2,
        action: InputSpendActionV23::Claim,
    };
    let a = Scalar::from(7u64);
    let r = Scalar::from(11u64);
    let a_public = (a * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let r_public = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let proof =
        prove_tx_key_derivation_v23(&context, a_public, r_public, &r.to_bytes(), &mut TestRng)
            .unwrap();
    assert_eq!(
        verify_tx_key_derivation_v23(&context, a_public, &proof).unwrap(),
        (r * a * ED25519_BASEPOINT_POINT).compress().to_bytes()
    );
    assert_eq!(
        TxKeyDerivationProofV23::decode(&proof.encode()).unwrap(),
        proof
    );
    let wrong_a = (Scalar::from(8u64) * ED25519_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    assert!(verify_tx_key_derivation_v23(&context, wrong_a, &proof).is_err());
    let mut changed = context.clone();
    changed.sweep_tx[0] ^= 1;
    assert!(verify_tx_key_derivation_v23(&changed, a_public, &proof).is_err());
    changed = context.clone();
    changed.destination[0] ^= 1;
    assert!(verify_tx_key_derivation_v23(&changed, a_public, &proof).is_err());
    assert!(
        prove_tx_key_derivation_v23(&context, a_public, r_public, &a.to_bytes(), &mut TestRng)
            .is_err()
    );
    let mut bytes = proof.encode();
    bytes[128..].fill(255);
    assert!(TxKeyDerivationProofV23::decode(&bytes).is_err());
    assert!(TxKeyDerivationProofV23::decode(&proof.encode()[..159]).is_err());
    bytes = proof.encode();
    bytes[32..64].copy_from_slice(&EdwardsPoint::default().compress().to_bytes());
    assert!(TxKeyDerivationProofV23::decode(&bytes).is_err());
}
