//! Native consensus and hostile peer controls; funding remains synthetic here.
use dom_consensus::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{Amount, BlockHeight, Timestamp, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    SchnorrSignature, SecretKey,
};
use dom_scriptless_primitives::{scriptless_add_public_points, SecretScalar};
use dom_serialization::{DomDeserialize, DomSerialize};
use dxp1_clsag_lab::{dom_joint::*, native_dom::PreparedDomClaim};
use rand_core::OsRng;

struct Fixture {
    claim: PreparedDomClaim,
    shares: [BlindingFactor; 2],
    input: BlindingFactor,
    output: BlindingFactor,
    secret: SecretScalar,
}
fn context() -> ValidationContext {
    ValidationContext {
        chain_id: [7; 32],
        current_height: BlockHeight(100),
        now: Timestamp(1_790_000_000),
    }
}

impl Fixture {
    fn new() -> Self {
        let input = BlindingFactor::random();
        let output = BlindingFactor::random();
        let offsets = [BlindingFactor::random(), BlindingFactor::random()];
        let offset = offsets[1].sub_nonzero(&offsets[0]).unwrap();
        let shares = [
            offsets[0].sub_nonzero(&input).unwrap(),
            output.sub_nonzero(&offsets[1]).unwrap(),
        ];
        let keys = shares
            .each_ref()
            .map(|s| SecretKey::from_bytes(s.as_bytes()).unwrap().public_key());
        let excess = scriptless_add_public_points(&keys).unwrap();
        let (proof, commitment) = dom_crypto::range_proof_prove_bytes(7_900_000, &output).unwrap();
        let claim = PreparedDomClaim::new(
            Transaction {
                inputs: vec![TransactionInput {
                    commitment: Commitment::commit(8_000_000, &input),
                }],
                outputs: vec![TransactionOutput {
                    commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
                    proof,
                }],
                kernels: vec![TransactionKernel {
                    features: KERNEL_FEAT_PLAIN,
                    fee: Amount::from_noms(100_000).unwrap(),
                    lock_height: 0,
                    excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes())
                        .unwrap(),
                    excess_signature: [0; 65],
                }],
                offset: *offset.as_bytes(),
            },
            context().chain_id,
        )
        .unwrap();
        Self {
            claim,
            shares,
            input,
            output,
            secret: SecretScalar::from_be_bytes([3; 32]).unwrap(),
        }
    }
    fn keys(&self) -> [SecretKey; 2] {
        self.shares
            .each_ref()
            .map(|s| SecretKey::from_bytes(s.as_bytes()).unwrap())
    }
    fn intent(&self, session: u8) -> DomSigningIntent {
        DomSigningIntent::new(
            self.claim.clone(),
            self.secret.public_key().unwrap(),
            self.keys().each_ref().map(|k| k.public_key()),
            [session; 32],
            [9; 32],
        )
        .unwrap()
    }
    fn plan(&self, session: u8) -> DomSigningPlan {
        let intent = self.intent(session);
        let keys = self.keys();
        let proofs = [
            intent.prove_share(0, &keys[0]).unwrap(),
            intent.prove_share(1, &keys[1]).unwrap(),
        ];
        intent.authorize(proofs).unwrap()
    }
    fn rounds(&self, session: u8) -> [(DomRoundOne, DomCommitment); 2] {
        let plan = self.plan(session);
        self.keys()
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                DomSigner::new(plan.clone(), i as u8, k)
                    .unwrap()
                    .preprocess(&mut OsRng)
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }
}

#[test]
fn joint_dom_claim_is_native_and_both_peers_extract_the_same_secret() {
    let f = Fixture::new();
    let [(a, ma), (b, mb)] = f.rounds(8);
    let (a, sa) = a.sign(&mb).unwrap();
    let (b, sb) = b.sign(&ma).unwrap();
    let a = a.complete(&sb).unwrap();
    let b = b.complete(&sa).unwrap();
    let tx = a.complete(&f.secret, &context()).unwrap();
    assert_eq!(tx, b.complete(&f.secret, &context()).unwrap());
    let tx = Transaction::from_bytes(&tx.to_bytes().unwrap()).unwrap();
    dom_consensus::validate_transaction(&tx, &context()).unwrap();
    assert_eq!(*a.extract(&tx, &context()).unwrap(), [3; 32]);
    assert_eq!(*b.extract(&tx, &context()).unwrap(), [3; 32]);
}

#[test]
fn possession_rejects_relabeling_other_session_and_false_shares() {
    let f = Fixture::new();
    let intent = f.intent(8);
    let keys = f.keys();
    assert!(intent.prove_share(0, &keys[1]).is_err());
    assert!(intent.prove_share(2, &keys[0]).is_err());
    let proofs = [
        intent.prove_share(0, &keys[0]).unwrap(),
        intent.prove_share(1, &keys[1]).unwrap(),
    ];
    assert!(f.intent(9).authorize(proofs.clone()).is_err());
    assert!(intent
        .clone()
        .authorize([proofs[1].clone(), proofs[0].clone()])
        .is_err());
    let mut altered = proofs[0].to_bytes();
    altered[40] ^= 1;
    assert!(intent
        .clone()
        .authorize([
            SchnorrSignature::from_bytes(&altered).unwrap(),
            proofs[1].clone()
        ])
        .is_err());
    let plan = intent.authorize(proofs).unwrap();
    assert!(DomSigner::new(plan.clone(), 0, SecretKey::from_bytes(&[1; 32]).unwrap()).is_err());
    assert!(DomSigner::new(plan, 2, SecretKey::from_bytes(&[1; 32]).unwrap()).is_err());
}

#[test]
fn intent_binds_full_claim_adaptor_roster_session_and_route() {
    let f = Fixture::new();
    let intent = f.intent(8);
    let keys = f.keys();
    let proofs = [
        intent.prove_share(0, &keys[0]).unwrap(),
        intent.prove_share(1, &keys[1]).unwrap(),
    ];
    let public = keys.each_ref().map(|k| k.public_key());
    for case in 0..4 {
        let mut tx = f.claim.unsigned_transaction().clone();
        let mut adaptor = f.secret.public_key().unwrap();
        let mut roster = public.clone();
        let mut route = [9; 32];
        match case {
            0 => {
                // Same native kernel/key, different valid transaction body.
                tx.inputs[0].commitment = Commitment::commit(9_000_000, &f.input);
                let (proof, point) =
                    dom_crypto::range_proof_prove_bytes(8_900_000, &f.output).unwrap();
                tx.outputs[0] = TransactionOutput {
                    commitment: Commitment::from_compressed_bytes(&point).unwrap(),
                    proof,
                };
            }
            1 => adaptor = SecretKey::from_bytes(&[5; 32]).unwrap().public_key(),
            2 => roster.swap(0, 1),
            _ => route[0] ^= 1,
        }
        let claim = PreparedDomClaim::new(tx, context().chain_id).unwrap();
        assert_eq!(claim.message(), f.claim.message());
        let changed = DomSigningIntent::new(claim, adaptor, roster, [8; 32], route).unwrap();
        assert!(changed.authorize(proofs.clone()).is_err());
    }
    assert!(DomSigningIntent::new(
        f.claim.clone(),
        f.secret.public_key().unwrap(),
        public.clone(),
        [0; 32],
        [9; 32]
    )
    .is_err());
    assert!(DomSigningIntent::new(
        f.claim.clone(),
        f.secret.public_key().unwrap(),
        public.clone(),
        [8; 32],
        [0; 32]
    )
    .is_err());
    assert!(DomSigningIntent::new(
        f.claim.clone(),
        f.secret.public_key().unwrap(),
        [public[0].clone(), public[0].clone()],
        [8; 32],
        [9; 32]
    )
    .is_err());
    assert!(DomSigningIntent::new(
        f.claim.clone(),
        f.secret.public_key().unwrap(),
        [
            public[0].clone(),
            SecretKey::from_bytes(&[6; 32]).unwrap().public_key()
        ],
        [8; 32],
        [9; 32]
    )
    .is_err());
}

#[test]
fn hostile_commitments_fail_before_releasing_a_response() {
    let f = Fixture::new();
    for case in 0..6 {
        let [(a, ma), (_, mut mb)] = f.rounds(8);
        match case {
            0 => mb.plan[0] ^= 1,
            1 => mb.signer = 0,
            2 => mb.nonces[0] = [0; 33],
            3 => mb.nonces[1] = [255; 33],
            4 => mb.nonces[1] = mb.nonces[0],
            _ => mb.nonces[0] = ma.nonces[0],
        }
        assert!(a.sign(&mb).is_err(), "case {case}");
    }
}

#[test]
fn hostile_responses_and_retagged_other_round_fail() {
    let f = Fixture::new();
    for case in 0..5 {
        let [(a, ma), (b, mb)] = f.rounds(8);
        let (a, _) = a.sign(&mb).unwrap();
        let (_, mut sb) = b.sign(&ma).unwrap();
        match case {
            0 => sb.round[0] ^= 1,
            1 => sb.signer = 0,
            2 => sb.scalar = [0; 32],
            3 => sb.scalar = [255; 32],
            _ => sb.scalar[8] ^= 1,
        }
        assert!(a.complete(&sb).is_err(), "case {case}");
    }
    let [(a, _), (_, mb)] = f.rounds(8);
    let (a, sa) = a.sign(&mb).unwrap();
    let [(_, ma2), (b2, _)] = f.rounds(8);
    let (_, mut sb2) = b2.sign(&ma2).unwrap();
    sb2.round = sa.round;
    assert!(a.complete(&sb2).is_err());
}

#[test]
fn retagging_a_commitment_from_a_different_plan_does_not_mix_responses() {
    let f = Fixture::new();
    let [(a, mut ma), (_, _)] = f.rounds(8);
    let [(_, _), (b, mut mb)] = f.rounds(9);
    std::mem::swap(&mut ma.plan, &mut mb.plan);
    let (a, sa) = a.sign(&mb).unwrap();
    let (_, mut sb) = b.sign(&ma).unwrap();
    sb.round = sa.round;
    assert!(a.complete(&sb).is_err());
}
