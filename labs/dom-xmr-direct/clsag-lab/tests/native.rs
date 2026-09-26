//! Offline native transaction fixtures. Rings and block containers are synthetic;
//! neither this suite nor a scanner establishes inclusion, maturity or finality.

#[path = "support/dom_claim.rs"]
mod dom_claim;

use std::collections::HashMap;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::{
    joint::{JointParticipant, JointPlan},
    native::{ClaimTerms, NativeError, PreparedClaim},
    PreSignature, Statement, RING_SIZE,
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use monero_clsag::Decoys;
use monero_wallet::{
    address::{AddressType, MoneroAddress, Network},
    block::{Block, BlockHeader},
    ed25519::{Commitment, Point, Scalar as MoneroScalar},
    interface::{FeeRate, ScannableBlock},
    ringct::RctPrunable,
    transaction::{Input, Timelock, Transaction, TransactionPrefix},
    OutputWithDecoys, Scanner, ViewPair,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const INPUT_AMOUNT: u64 = 9_000_000_000;
const PAYMENT_AMOUNT: u64 = 5_000_000_000;

fn ids() -> [Participant; 2] {
    [Participant::new(1).unwrap(), Participant::new(2).unwrap()]
}

fn fresh_secret() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(&mut *bytes);
    bytes
}

struct Fixture {
    keys: [ThresholdKeys<Ed25519>; 2],
    input: OutputWithDecoys,
    image: EdwardsPoint,
    recipient: ViewPair,
    change: ViewPair,
}

impl Fixture {
    fn new(real: usize) -> Self {
        // Independent additive shares; only the public points are aggregated.
        let shares = [
            Zeroizing::new(Scalar::random(&mut OsRng)),
            Zeroizing::new(Scalar::random(&mut OsRng)),
        ];
        let roster = HashMap::from([
            (ids()[0], GroupPoint(*shares[0] * G)),
            (ids()[1], GroupPoint(*shares[1] * G)),
        ]);
        let offset = Scalar::random(&mut OsRng);
        let keys: [ThresholdKeys<Ed25519>; 2] = shares
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
                .offset(offset)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let key = Point::from(keys[0].group_key().0);
        let h = Point::biased_hash(key.compress().to_bytes()).into();
        let image = keys
            .iter()
            .map(|key| h * **key.view(ids().to_vec()).unwrap().secret_share())
            .sum();
        let commitment = Commitment::new(MoneroScalar::random(&mut OsRng), INPUT_AMOUNT);
        let mut ring = (0..RING_SIZE)
            .map(|i| {
                [
                    Point::from(Scalar::random(&mut OsRng) * G),
                    Commitment::new(MoneroScalar::random(&mut OsRng), 700 + i as u64).commit(),
                ]
            })
            .collect::<Vec<_>>();
        ring[real] = [key, commitment.commit()];
        let decoys = Decoys::new(vec![1; RING_SIZE], real as u8, ring).unwrap();
        // Construct the pinned wallet's LOCAL input format only for the fixture.
        // Production must obtain this from a validated scanner and decoy source.
        let mut encoded = Zeroizing::new(key.compress().to_bytes().to_vec());
        MoneroScalar::from(offset).write(&mut *encoded).unwrap();
        commitment.write(&mut *encoded).unwrap();
        decoys.write(&mut *encoded).unwrap();
        let input = OutputWithDecoys::read(&mut encoded.as_slice()).unwrap();
        let view_pair = || {
            ViewPair::new(
                Point::from(Scalar::random(&mut OsRng) * G),
                Zeroizing::new(MoneroScalar::random(&mut OsRng)),
            )
            .unwrap()
        };
        Self {
            keys,
            input,
            image,
            recipient: view_pair(),
            change: view_pair(),
        }
    }

    fn terms(&self) -> ClaimTerms {
        ClaimTerms {
            recipient: self.recipient.legacy_address(Network::Testnet),
            amount: PAYMENT_AMOUNT,
            change: self.change.clone(),
            fee_rate: FeeRate::new(1500, 10000).unwrap(),
            max_fee: 50_000_000,
        }
    }
    fn prepare(&self) -> PreparedClaim {
        self.prepare_for_route([27; 32])
    }
    fn prepare_for_route(&self, route_binding: [u8; 32]) -> PreparedClaim {
        PreparedClaim::new(
            self.input.clone(),
            self.image,
            self.terms(),
            fresh_secret(),
            route_binding,
            &mut OsRng,
        )
        .unwrap()
    }
    fn presign(&self, prepared: &PreparedClaim, witness: &Zeroizing<Scalar>) -> PreSignature {
        let statement = Statement::prove(prepared.context(), witness, &mut OsRng).unwrap();
        let plan = JointPlan::new(
            prepared.context().clone(),
            statement,
            [44; 32],
            prepared.offsets().to_vec(),
        )
        .unwrap();
        let [(a, ma), (b, mb)]: [_; 2] = self
            .keys
            .iter()
            .map(|keys| {
                JointParticipant::new(plan.clone(), prepared.input_opening(), keys.clone())
                    .unwrap()
                    .preprocess(&mut OsRng)
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let (a, sa) = a.sign(&mb).unwrap();
        let (b, sb) = b.sign(&ma).unwrap();
        let pa = a.complete(&sb).unwrap();
        assert_eq!(pa, b.complete(&sa).unwrap());
        pa
    }
}

#[test]
fn native_transactions_propagate_witness_directly_xmr_dom_and_dom_xmr() {
    use dom_scriptless_primitives::SecretScalar;
    use dom_serialization::{DomDeserialize, DomSerialize};
    use sha2::{Digest, Sha256};
    use xmr_dleq_sigma::{prove, verify, CrossCurveSecret252};

    for reverse in [false, true] {
        let secret = CrossCurveSecret252::generate(&mut OsRng);
        let proof = prove(&secret, &mut OsRng).unwrap();
        verify(&proof).unwrap();
        let dom = dom_claim::Fixture::new();
        let mut hash = Sha256::new();
        hash.update(b"DXP1/native-dom-xmr-fixture/v1");
        hash.update([u8::from(reverse)]);
        hash.update(dom.claim.binding().unwrap());
        hash.update(proof.claim.secp_compressed);
        hash.update(proof.claim.ed_compressed);
        let route_binding = hash.finalize().into();
        let f = Fixture::new(7);
        let xmr = f.prepare_for_route(route_binding);
        let witness = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(
                secret.xmr_share_little_endian(),
            ))
            .unwrap(),
        );
        let xmr_pre = f.presign(&xmr, &witness);
        assert_eq!(
            xmr_pre.statement.t_g.compress().to_bytes(),
            proof.claim.ed_compressed
        );
        let dom_offer = dom.offer(&proof.claim.secp_compressed);

        // Only the first leg receives the initiator's original secret.
        // Later legs consume exclusively what was extracted from native bytes.
        if !reverse {
            let final_xmr = xmr.complete(&xmr_pre, &witness, &mut OsRng).unwrap();
            let raw = final_xmr.serialize();
            let parsed = Transaction::read(&mut raw.as_slice()).unwrap();
            let mut to_dom = Zeroizing::new(
                xmr.extract(&xmr_pre, &parsed, &mut OsRng)
                    .unwrap()
                    .to_bytes(),
            );
            to_dom.reverse();
            let final_dom = dom_offer
                .complete(
                    &SecretScalar::from_be_bytes(*to_dom).unwrap(),
                    &dom_claim::context(),
                )
                .unwrap();
            let parsed_dom =
                dom_consensus::Transaction::from_bytes(&final_dom.to_bytes().unwrap()).unwrap();
            let extracted_dom = dom_offer
                .extract(&parsed_dom, &dom_claim::context())
                .unwrap();
            assert_eq!(*extracted_dom, secret.dom_secret_big_endian());
        } else {
            let final_dom = dom_offer
                .complete(
                    &SecretScalar::from_be_bytes(secret.dom_secret_big_endian()).unwrap(),
                    &dom_claim::context(),
                )
                .unwrap();
            let parsed_dom =
                dom_consensus::Transaction::from_bytes(&final_dom.to_bytes().unwrap()).unwrap();
            let mut to_xmr = dom_offer
                .extract(&parsed_dom, &dom_claim::context())
                .unwrap();
            to_xmr.reverse();
            let extracted = Zeroizing::new(
                Option::<Scalar>::from(Scalar::from_canonical_bytes(*to_xmr)).unwrap(),
            );
            let final_xmr = xmr.complete(&xmr_pre, &extracted, &mut OsRng).unwrap();
            let raw = final_xmr.serialize();
            let parsed = Transaction::read(&mut raw.as_slice()).unwrap();
            assert_eq!(
                *xmr.extract(&xmr_pre, &parsed, &mut OsRng).unwrap(),
                *witness
            );
        }
    }
}

fn scanner_container(transaction: &Transaction) -> ScannableBlock {
    let miner = Transaction::V2 {
        prefix: TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::Gen(300)],
            outputs: vec![],
            extra: vec![],
        },
        proofs: None,
    };
    let block = Block::new(
        BlockHeader {
            hardfork_version: 16,
            hardfork_signal: 16,
            timestamp: 1,
            previous: [0; 32],
            nonce: 0,
        },
        miner,
        vec![transaction.hash()],
    )
    .unwrap();
    ScannableBlock {
        block,
        transactions: vec![transaction.clone().into()],
        output_index_for_first_ringct_output: Some(1000),
    }
}

#[test]
fn joint_native_claim_roundtrips_and_both_wallets_scan_the_exact_payments() {
    for real in [0, 7, 15] {
        let f = Fixture::new(real);
        let prepared = f.prepare();
        let witness = Zeroizing::new(Scalar::random(&mut OsRng));
        let pre = f.presign(&prepared, &witness);
        assert!(prepared.context().verify_native(&pre.signature).is_err());
        let transaction = prepared.complete(&pre, &witness, &mut OsRng).unwrap();
        let bytes = transaction.serialize();
        let mut reader = bytes.as_slice();
        let decoded = Transaction::read(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert_eq!(decoded.hash(), transaction.hash());
        assert_eq!(decoded.serialize(), bytes);
        prepared.verify_final(&decoded, &mut OsRng).unwrap();
        assert_eq!(
            *prepared.extract(&pre, &decoded, &mut OsRng).unwrap(),
            *witness
        );
        for (wallet, expected) in [
            (f.recipient, PAYMENT_AMOUNT),
            (f.change, INPUT_AMOUNT - PAYMENT_AMOUNT - prepared.fee()),
        ] {
            let outputs = Scanner::new(wallet.clone())
                .scan(scanner_container(&decoded))
                .unwrap()
                .not_additionally_locked();
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].commitment().amount, expected);
            assert_eq!(
                outputs[0].key().into(),
                outputs[0].key_offset().into() * G + wallet.spend().into()
            );
        }
    }
}

#[test]
fn changed_native_fields_cannot_release_the_extracted_secret() {
    let f = Fixture::new(6);
    let prepared = f.prepare();
    let witness = Zeroizing::new(Scalar::random(&mut OsRng));
    let pre = f.presign(&prepared, &witness);
    let valid = prepared.complete(&pre, &witness, &mut OsRng).unwrap();
    for corruption in 0..12 {
        let mut tx = valid.clone();
        let Transaction::V2 {
            prefix,
            proofs: Some(proofs),
        } = &mut tx
        else {
            unreachable!()
        };
        let RctPrunable::Clsag {
            clsags,
            pseudo_outs,
            ..
        } = &mut proofs.prunable
        else {
            unreachable!()
        };
        match corruption {
            0 => proofs.base.fee += 1,
            1 => proofs.base.commitments[0] = Point::from(G).compress(),
            2 => proofs.base.encrypted_amounts.swap(0, 1),
            3 => prefix.outputs[0].key = Point::from(G).compress(),
            4 => prefix.outputs[0].view_tag = None,
            5 => prefix.additional_timelock = Timelock::Block(400),
            6 => prefix.extra.push(0),
            7 => {
                if let Input::ToKey { key_offsets, .. } = &mut prefix.inputs[0] {
                    key_offsets[0] += 1;
                }
            }
            8 => {
                if let Input::ToKey { key_image, .. } = &mut prefix.inputs[0] {
                    *key_image = Point::from(G).compress();
                }
            }
            9 => pseudo_outs[0] = Point::from(G).compress(),
            10 => clsags.clear(),
            _ => clsags[0].s[0] = MoneroScalar::from(clsags[0].s[0].into() + Scalar::ONE),
        }
        assert!(
            prepared.verify_final(&tx, &mut OsRng).is_err(),
            "corruption={corruption}"
        );
        assert!(
            prepared.extract(&pre, &tx, &mut OsRng).is_err(),
            "corruption={corruption}"
        );
    }
}

#[test]
fn independent_builders_agree_only_on_the_same_approved_payment() {
    let f = Fixture::new(4);
    let outgoing = fresh_secret();
    let a = PreparedClaim::new(
        f.input.clone(),
        f.image,
        f.terms(),
        outgoing.clone(),
        [27; 32],
        &mut OsRng,
    )
    .unwrap();
    let b = PreparedClaim::new(
        f.input.clone(),
        f.image,
        f.terms(),
        outgoing,
        [27; 32],
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(a.context().message, b.context().message);
    assert_eq!(a.context().pseudo_out, b.context().pseudo_out);
    let witness = Zeroizing::new(Scalar::random(&mut OsRng));
    let pre = f.presign(&a, &witness);
    let valid = b.complete(&pre, &witness, &mut OsRng).unwrap();
    let mut terms = f.terms();
    terms.amount -= 1;
    let different = PreparedClaim::new(
        f.input.clone(),
        f.image,
        terms,
        fresh_secret(),
        [27; 32],
        &mut OsRng,
    )
    .unwrap();
    assert!(different.complete(&pre, &witness, &mut OsRng).is_err());
    assert!(different.verify_final(&valid, &mut OsRng).is_err());
}

#[test]
fn unapproved_fees_destinations_and_empty_funds_fail_before_signing() {
    let f = Fixture::new(3);
    for invalid in 0..7 {
        let mut terms = f.terms();
        match invalid {
            0 => terms.max_fee = 1,
            1 => terms.recipient = f.change.legacy_address(Network::Testnet),
            2 => terms.amount = 0,
            3 => terms.amount = INPUT_AMOUNT,
            4 => terms.fee_rate = FeeRate::new(u64::MAX, 1).unwrap(),
            5 => terms.fee_rate = FeeRate::new(1, u64::MAX).unwrap(),
            _ => {
                terms.recipient = MoneroAddress::new(
                    Network::Testnet,
                    AddressType::Subaddress,
                    terms.recipient.spend(),
                    terms.recipient.view(),
                )
            }
        }
        let result = PreparedClaim::new(
            f.input.clone(),
            f.image,
            terms,
            fresh_secret(),
            [27; 32],
            &mut OsRng,
        );
        assert!(
            matches!(
                result.err(),
                Some(NativeError::Terms | NativeError::Builder)
            ),
            "invalid={invalid}"
        );
    }
}
