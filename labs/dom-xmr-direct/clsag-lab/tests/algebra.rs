use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as G, EIGHT_TORSION},
    scalar::Scalar,
    traits::Identity,
};
use dxp1_clsag_lab::{presign, Context, Error, Statement, RING_SIZE};
use monero_ed25519::{Commitment, Point, Scalar as MoneroScalar};
use rand_core::OsRng;
use zeroize::Zeroizing;

struct Fixture {
    context: Context,
    key: Zeroizing<Scalar>,
    mask_delta: Zeroizing<Scalar>,
    witness: Zeroizing<Scalar>,
}

fn fixture(real: usize) -> Fixture {
    let key = Zeroizing::new(Scalar::random(&mut OsRng));
    let mask = Zeroizing::new(Scalar::random(&mut OsRng));
    let pseudo_mask = Zeroizing::new(Scalar::random(&mut OsRng));
    let amount = 2_000_000u64;
    let mut ring = std::array::from_fn(|i| {
        [
            Scalar::random(&mut OsRng) * G,
            Commitment::new(MoneroScalar::random(&mut OsRng), 50_000 + i as u64)
                .commit()
                .into(),
        ]
    });
    ring[real] = [
        *key * G,
        Commitment::new(MoneroScalar::from(*mask), amount)
            .commit()
            .into(),
    ];
    let image = Point::biased_hash(ring[real][0].compress().to_bytes()).into() * *key;
    Fixture {
        context: Context {
            ring,
            real,
            image,
            pseudo_out: Commitment::new(MoneroScalar::from(*pseudo_mask), amount)
                .commit()
                .into(),
            message: [41; 32],
            route_binding: [29; 32],
        },
        key,
        mask_delta: Zeroizing::new(*mask - *pseudo_mask),
        witness: Zeroizing::new(Scalar::random(&mut OsRng)),
    }
}

impl Fixture {
    fn pre(&self) -> dxp1_clsag_lab::PreSignature {
        let statement = Statement::prove(&self.context, &self.witness, &mut OsRng).unwrap();
        presign(
            &self.context,
            statement,
            &self.key,
            &self.mask_delta,
            &mut OsRng,
        )
        .unwrap()
    }
}

#[test]
fn every_ring_position_completes_to_native_clsag_and_extracts_exact_witness() {
    for real in 0..RING_SIZE {
        let f = fixture(real);
        let pre = f.pre();
        pre.verify(&f.context).unwrap();
        assert_eq!(
            f.context.verify_native(&pre.signature),
            Err(Error::FinalSignature)
        );
        let final_signature = pre.complete(&f.context, &f.witness).unwrap();
        f.context.verify_native(&final_signature).unwrap();
        assert_eq!(
            *pre.extract(&f.context, &final_signature).unwrap(),
            *f.witness
        );
        // Native wire round-trip, without the adaptor points, proof or ring index.
        let mut bytes = Vec::new();
        final_signature.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), (RING_SIZE + 2) * 32);
        let parsed = monero_clsag::Clsag::read(RING_SIZE, &mut bytes.as_slice()).unwrap();
        f.context.verify_native(&parsed).unwrap();
        assert_eq!(parsed, final_signature);
    }
}

#[test]
fn wrong_secret_does_not_complete() {
    let f = fixture(3);
    let wrong = Zeroizing::new(*f.witness + Scalar::ONE);
    assert_eq!(f.pre().complete(&f.context, &wrong), Err(Error::Witness));
}

#[test]
fn statement_proof_binds_both_generators_and_all_its_elements() {
    let f = fixture(4);
    let statement = Statement::prove(&f.context, &f.witness, &mut OsRng).unwrap();
    for field in 0..5 {
        let mut changed = statement.clone();
        match field {
            0 => changed.t_g += G,
            1 => changed.t_h += G,
            2 => changed.r_g += G,
            3 => changed.r_h += G,
            _ => changed.response += Scalar::ONE,
        }
        assert_eq!(changed.verify(&f.context), Err(Error::Statement));
    }
}

#[test]
fn statement_cannot_move_to_another_route_transaction_ring_or_input() {
    let f = fixture(5);
    let pre = f.pre();
    for field in 0..7 {
        let mut context = f.context.clone();
        match field {
            0 => context.route_binding[0] ^= 1,
            1 => context.message[0] ^= 1,
            2 => context.real = 6,
            3 => context.image += G,
            4 => context.pseudo_out += G,
            5 => context.ring[0][0] += G,
            _ => context.ring[0][1] += G,
        }
        assert!(pre.verify(&context).is_err());
        assert!(pre.complete(&context, &f.witness).is_err());
    }
}

#[test]
fn changing_any_presignature_component_is_rejected() {
    let f = fixture(7);
    let pre = f.pre();
    for i in 0..RING_SIZE {
        let mut bad = pre.clone();
        let s: Scalar = bad.signature.s[i].into();
        bad.signature.s[i] = MoneroScalar::from(s + Scalar::ONE);
        assert_eq!(bad.verify(&f.context), Err(Error::PreSignature));
    }
    let mut bad = pre.clone();
    bad.signature.c1 = MoneroScalar::from(Scalar::ONE);
    assert!(bad.verify(&f.context).is_err());
    let mut bad = pre.clone();
    bad.signature.D = monero_ed25519::CompressedPoint::from(G.compress().to_bytes());
    assert!(bad.verify(&f.context).is_err());
    let mut bad = pre.clone();
    bad.signature.s.pop();
    assert_eq!(bad.verify(&f.context), Err(Error::PreSignature));
}

#[test]
fn extraction_checks_final_signature_before_reading_a_scalar_difference() {
    let f = fixture(8);
    let pre = f.pre();
    let mut final_signature = pre.complete(&f.context, &f.witness).unwrap();
    let response: Scalar = final_signature.s[0].into();
    final_signature.s[0] = MoneroScalar::from(response + Scalar::ONE);
    assert_eq!(
        pre.extract(&f.context, &final_signature).err(),
        Some(Error::FinalSignature)
    );
}

#[test]
fn independently_valid_signature_does_not_authorize_extraction_from_another_offer() {
    let f = fixture(9);
    let first = f.pre();
    let second = f.pre();
    let second_final = second.complete(&f.context, &f.witness).unwrap();
    f.context.verify_native(&second_final).unwrap();
    assert_eq!(
        first.extract(&f.context, &second_final).err(),
        Some(Error::DifferentSignature)
    );
}

#[test]
fn statement_rejects_identity_and_torsion_in_each_point() {
    let f = fixture(10);
    let statement = Statement::prove(&f.context, &f.witness, &mut OsRng).unwrap();
    for bad_point in [
        curve25519_dalek::edwards::EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        for field in 0..4 {
            let mut bad = statement.clone();
            match field {
                0 => bad.t_g = bad_point,
                1 => bad.t_h = bad_point,
                2 => bad.r_g = bad_point,
                _ => bad.r_h = bad_point,
            }
            assert_eq!(bad.verify(&f.context), Err(Error::Statement));
        }
    }
}

#[test]
fn invalid_context_and_wrong_key_or_amount_do_not_produce_an_offer() {
    let f = fixture(11);
    let statement = Statement::prove(&f.context, &f.witness, &mut OsRng).unwrap();
    let wrong_key = Zeroizing::new(*f.key + Scalar::ONE);
    assert_eq!(
        presign(
            &f.context,
            statement.clone(),
            &wrong_key,
            &f.mask_delta,
            &mut OsRng
        )
        .err(),
        Some(Error::Key)
    );
    let wrong_mask = Zeroizing::new(*f.mask_delta + Scalar::ONE);
    assert_eq!(
        presign(&f.context, statement, &f.key, &wrong_mask, &mut OsRng).err(),
        Some(Error::Key)
    );
    let mut wrong_amount = f.context.clone();
    wrong_amount.pseudo_out += Commitment::new(MoneroScalar::ZERO, 1).commit().into();
    let statement = Statement::prove(&wrong_amount, &f.witness, &mut OsRng).unwrap();
    assert_eq!(
        presign(&wrong_amount, statement, &f.key, &f.mask_delta, &mut OsRng).err(),
        Some(Error::Key)
    );
    let mut bad = f.context.clone();
    bad.real = RING_SIZE;
    assert_eq!(bad.validate(), Err(Error::Context));
    bad = f.context.clone();
    bad.ring[1] = bad.ring[0];
    assert_eq!(bad.validate(), Err(Error::Context));
    bad = f.context.clone();
    bad.image += EIGHT_TORSION[1];
    assert_eq!(bad.validate(), Err(Error::Point));
    let zero = Zeroizing::new(Scalar::ZERO);
    assert_eq!(
        Statement::prove(&f.context, &zero, &mut OsRng).err(),
        Some(Error::Witness)
    );
}

/// This offer signs fixture bytes. It does NOT construct a DOM transaction.
struct DomOffer {
    pre: dom_crypto::PartialSig,
    nonce: dom_crypto::PublicKey,
    key: dom_crypto::PublicKey,
    adaptor: dom_crypto::PublicKey,
    chain: [u8; 32],
    message: [u8; 32],
}

impl DomOffer {
    fn create(adaptor_bytes: &[u8; 33]) -> Self {
        use dom_scriptless_primitives::*;
        use rand_core::RngCore;
        let random_key = || {
            let mut bytes = Zeroizing::new([0; 32]);
            loop {
                OsRng.fill_bytes(&mut *bytes);
                if let Ok(key) = dom_crypto::SecretKey::from_bytes(&*bytes) {
                    return key;
                }
            }
        };
        let key = random_key();
        let nonce_secret = random_key();
        let adaptor = dom_crypto::PublicKey::from_compressed_bytes(adaptor_bytes).unwrap();
        let nonce =
            scriptless_add_public_points(&[nonce_secret.public_key(), adaptor.clone()]).unwrap();
        let chain = [56; 32];
        let message = [77; 32];
        let pre = dom_crypto::schnorr_partial_sign(
            &key,
            &nonce_secret,
            &nonce,
            &key.public_key(),
            &chain,
            &message,
        )
        .unwrap();
        assert!(scriptless_verify_pre_signature(
            &pre,
            &nonce,
            &key.public_key(),
            &adaptor,
            &chain,
            &message
        )
        .unwrap());
        Self {
            pre,
            nonce,
            key: key.public_key(),
            adaptor,
            chain,
            message,
        }
    }

    fn complete(&self, big_endian: &[u8; 32]) -> dom_crypto::SchnorrSignature {
        use dom_scriptless_primitives::*;
        let witness = SecretScalar::from_be_bytes(*big_endian).unwrap();
        let signature = scriptless_adapt_signature(&self.pre, &self.nonce, &witness).unwrap();
        assert!(scriptless_verify_final_signature(
            &signature,
            &self.key,
            &self.chain,
            &self.message
        )
        .unwrap());
        signature
    }

    fn extract(&self, signature: &dom_crypto::SchnorrSignature) -> Zeroizing<[u8; 32]> {
        use dom_scriptless_primitives::*;
        assert!(scriptless_verify_final_signature(
            signature,
            &self.key,
            &self.chain,
            &self.message
        )
        .unwrap());
        scriptless_extract_adaptor_secret_be_bytes(signature, &self.pre, &self.nonce, &self.adaptor)
            .unwrap()
    }
}

#[test]
fn witness_propagates_directly_xmr_to_dom_and_dom_to_xmr() {
    use xmr_dleq_sigma::{prove, verify, CrossCurveSecret252};

    let shared = CrossCurveSecret252::generate(&mut OsRng);
    let proof = prove(&shared, &mut OsRng).unwrap();
    verify(&proof).unwrap();
    let witness = Zeroizing::new(
        Option::<Scalar>::from(Scalar::from_canonical_bytes(
            shared.xmr_share_little_endian(),
        ))
        .unwrap(),
    );
    let mut f = fixture(12);
    f.witness = witness;
    let xmr_pre = f.pre();
    assert_eq!(
        xmr_pre.statement.t_g.compress().to_bytes(),
        proof.claim.ed_compressed
    );
    let dom = DomOffer::create(&proof.claim.secp_compressed);

    // XMR final signature -> extracted scalar -> DOM final signature.
    let xmr_final = xmr_pre.complete(&f.context, &f.witness).unwrap();
    let extracted_xmr = xmr_pre.extract(&f.context, &xmr_final).unwrap();
    let mut to_dom = Zeroizing::new(extracted_xmr.to_bytes());
    to_dom.reverse();
    let dom_final = dom.complete(&to_dom);
    let from_dom = dom.extract(&dom_final);
    assert_eq!(*from_dom, shared.dom_secret_big_endian());

    // Direct reverse path, with fresh offers and nonces.
    let reverse_dom = DomOffer::create(&proof.claim.secp_compressed);
    let reverse_dom_final = reverse_dom.complete(&shared.dom_secret_big_endian());
    let mut to_xmr = reverse_dom.extract(&reverse_dom_final);
    to_xmr.reverse();
    let extracted =
        Zeroizing::new(Option::<Scalar>::from(Scalar::from_canonical_bytes(*to_xmr)).unwrap());
    let reverse_xmr_pre = f.pre();
    let reverse_xmr_final = reverse_xmr_pre.complete(&f.context, &extracted).unwrap();
    f.context.verify_native(&reverse_xmr_final).unwrap();
    assert_eq!(
        *reverse_xmr_pre
            .extract(&f.context, &reverse_xmr_final)
            .unwrap(),
        *f.witness
    );

    // Equality of two locally chosen scalars alone would not prove the relation.
    let mut mismatched = proof.clone();
    mismatched.claim.ed_compressed = (Scalar::from(123u64) * G).compress().to_bytes();
    assert!(verify(&mismatched).is_err());
}
