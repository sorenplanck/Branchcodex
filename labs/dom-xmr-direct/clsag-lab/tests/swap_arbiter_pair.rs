use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use dom_consensus::{
    swap_arbiter_intent, validate_swap_arbiter_input_proofs, SwapArbiterContract, SwapArbiterPath,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, Timestamp, KERNEL_FEAT_SWAP_CLAIM, KERNEL_FEAT_SWAP_PUNISH,
    KERNEL_FEAT_SWAP_REFUND,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::SecretKey;
use dom_scriptless_primitives::SecretScalar;
use dxp1_clsag_lab::{
    arbiter_pair::VerifiedArbiterSharesV1,
    claim_resume::digest,
    dom_joint::{DomCommitment, DomSigner, DomSigningIntent, DomSigningPlan},
    native_dom::{DomClaimOffer, PreparedDomClaim},
};
use monero_clsag::Decoys;
use monero_wallet::{
    address::Network,
    ed25519::{Commitment as XmrCommitment, Point, Scalar as MoneroScalar},
    interface::FeeRate,
    ringct::RctType,
    send::{Change, SignableTransaction},
    OutputWithDecoys, ViewPair,
};
use rand_core::{OsRng, RngCore};
use xmr_dleq_sigma::{
    prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use zeroize::Zeroizing;

const CHAIN_ID: [u8; 32] = [0x61; 32];
const SETTLEMENT_ID: [u8; 32] = [0x62; 32];
const CONTEXT_HASH: [u8; 32] = [0x63; 32];
const INPUT_VALUE: u64 = 5_000_000;
const FEE: u64 = 100_000;

fn scalar(last: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = last;
    BlindingFactor::from_bytes(bytes).unwrap()
}

struct Branch {
    unsigned: Transaction,
    prepared: PreparedDomClaim,
    signing_keys: [SecretKey; 2],
}

fn branch(
    input: Commitment,
    input_blinding: &BlindingFactor,
    feature: u8,
    boundary: u64,
    signing_scalars: [u8; 2],
) -> Branch {
    let signing_blindings = signing_scalars.map(scalar);
    let output_blinding = input_blinding
        .add(&signing_blindings[0])
        .unwrap()
        .add(&signing_blindings[1])
        .unwrap();
    let output_commitment = Commitment::commit(INPUT_VALUE - FEE, &output_blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes(INPUT_VALUE - FEE, &output_blinding).unwrap();
    assert_eq!(proof_commitment, *output_commitment.as_bytes());
    let signing_keys = signing_blindings
        .each_ref()
        .map(|blinding| SecretKey::from_bytes(blinding.as_bytes()).unwrap());
    let excess = dom_scriptless_primitives::scriptless_add_public_points(
        &signing_keys.each_ref().map(SecretKey::public_key),
    )
    .unwrap();
    let unsigned = Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: feature,
            fee: Amount::from_noms(FEE).unwrap(),
            lock_height: boundary,
            excess: Commitment::from_compressed_bytes(&excess.to_compressed_bytes()).unwrap(),
            excess_signature: [0; 65],
        }],
        offset: [0; 32],
    };
    let prepared = PreparedDomClaim::new_swap_arbiter_path(unsigned.clone(), CHAIN_ID).unwrap();
    Branch {
        unsigned,
        prepared,
        signing_keys,
    }
}

fn plan(branch: &Branch, adaptor: dom_crypto::PublicKey, session: u8) -> DomSigningPlan {
    let intent = DomSigningIntent::new(
        branch.prepared.clone(),
        adaptor,
        branch.signing_keys.each_ref().map(SecretKey::public_key),
        [session; 32],
        CONTEXT_HASH,
    )
    .unwrap();
    let proofs = [
        intent.prove_share(0, &branch.signing_keys[0]).unwrap(),
        intent.prove_share(1, &branch.signing_keys[1]).unwrap(),
    ];
    intent.authorize(proofs).unwrap()
}

fn offer(branch: &Branch, adaptor: dom_crypto::PublicKey, session: u8) -> DomClaimOffer {
    let plan = plan(branch, adaptor, session);
    let rounds: Vec<_> = branch
        .signing_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            DomSigner::new(plan.clone(), index as u8, key.clone())
                .unwrap()
                .preprocess(&mut OsRng)
                .unwrap()
        })
        .collect();
    let commitments: [DomCommitment; 2] = [rounds[0].1.clone(), rounds[1].1.clone()];
    let [first, second]: [_; 2] = rounds.try_into().ok().unwrap();
    let (first, first_response) = first.0.sign(&commitments[1]).unwrap();
    let (second, second_response) = second.0.sign(&commitments[0]).unwrap();
    let first = first.complete(&second_response).unwrap();
    let _second = second.complete(&first_response).unwrap();
    first
}

fn context(height: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id: CHAIN_ID,
        now: Timestamp(u64::MAX),
    }
}

fn native_xmr_spend(spend: Scalar) {
    let key = Point::from(spend * ED25519_BASEPOINT_POINT);
    let commitment = XmrCommitment::new(MoneroScalar::random(&mut OsRng), 9_000_000_000);
    let real = 7;
    let mut ring = (0..dxp1_clsag_lab::RING_SIZE)
        .map(|index| {
            [
                Point::from(Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT),
                XmrCommitment::new(MoneroScalar::random(&mut OsRng), 700 + index as u64).commit(),
            ]
        })
        .collect::<Vec<_>>();
    ring[real] = [key, commitment.commit()];
    let decoys = Decoys::new(vec![1; dxp1_clsag_lab::RING_SIZE], real as u8, ring).unwrap();
    let mut encoded = Zeroizing::new(key.compress().to_bytes().to_vec());
    MoneroScalar::ZERO.write(&mut *encoded).unwrap();
    commitment.write(&mut *encoded).unwrap();
    decoys.write(&mut *encoded).unwrap();
    let input = OutputWithDecoys::read(&mut encoded.as_slice()).unwrap();
    let recipient = ViewPair::new(
        Point::from(Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT),
        Zeroizing::new(MoneroScalar::random(&mut OsRng)),
    )
    .unwrap();
    let change = ViewPair::new(key, Zeroizing::new(MoneroScalar::random(&mut OsRng))).unwrap();
    let mut outgoing = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *outgoing);
    let transaction = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing,
        vec![input],
        vec![(recipient.legacy_address(Network::Testnet), 5_000_000_000)],
        Change::new(change, None),
        vec![],
        FeeRate::new(1500, 10_000).unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &Zeroizing::new(MoneroScalar::from(spend)))
    .unwrap();
    assert_eq!(transaction.prefix().inputs.len(), 1);
    assert_eq!(transaction.prefix().outputs.len(), 2);
    assert!(transaction.signature_hash().is_some());
}

#[test]
fn every_terminal_dom_path_reveals_the_xmr_share_for_the_opposite_asset_owner() {
    let dom_owner = CrossCurveSecret252::generate(&mut OsRng);
    let xmr_owner = CrossCurveSecret252::generate(&mut OsRng);
    let dom_owner_proof = prove_bound(
        &dom_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_REFUND_SHARE,
        &mut OsRng,
    )
    .unwrap();
    let xmr_owner_proof = prove_bound(
        &xmr_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_SHARED_SPEND,
        &mut OsRng,
    )
    .unwrap();
    let shares = VerifiedArbiterSharesV1::new(
        SETTLEMENT_ID,
        CONTEXT_HASH,
        &dom_owner_proof,
        &xmr_owner_proof,
    )
    .unwrap();

    let input_blinding = scalar(7);
    let input = Commitment::commit(INPUT_VALUE, &input_blinding);
    let claim = branch(
        input.clone(),
        &input_blinding,
        KERNEL_FEAT_SWAP_CLAIM,
        10,
        [11, 12],
    );
    let refund = branch(
        input.clone(),
        &input_blinding,
        KERNEL_FEAT_SWAP_REFUND,
        11,
        [13, 14],
    );
    let punish = branch(
        input,
        &input_blinding,
        KERNEL_FEAT_SWAP_PUNISH,
        21,
        [15, 16],
    );
    let contract = SwapArbiterContract::new(
        10,
        20,
        swap_arbiter_intent(&claim.unsigned).unwrap(),
        swap_arbiter_intent(&refund.unsigned).unwrap(),
        swap_arbiter_intent(&punish.unsigned).unwrap(),
    )
    .unwrap();
    let contract_bytes = contract.to_bytes();
    let (proof, commitment) = dom_crypto::range_proof_prove_bytes_with_extra_commit(
        INPUT_VALUE,
        &input_blinding,
        &contract_bytes,
    )
    .unwrap();
    let funding = TransactionOutput::with_swap_arbiter(
        Commitment::from_compressed_bytes(&commitment).unwrap(),
        proof,
        &contract,
    )
    .unwrap();

    let dom_xmr = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        dom_owner.xmr_share_little_endian(),
    ))
    .unwrap();
    let xmr_xmr = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        xmr_owner.xmr_share_little_endian(),
    ))
    .unwrap();
    let joint_xmr_key = (dom_xmr + xmr_xmr) * ED25519_BASEPOINT_POINT;
    assert_eq!(
        shares.joint_xmr_spend_key().unwrap(),
        joint_xmr_key.compress().to_bytes()
    );

    for (path, branch, height, secret, local_share, session) in [
        (SwapArbiterPath::Claim, &claim, 10, &xmr_owner, dom_xmr, 71),
        (
            SwapArbiterPath::Refund,
            &refund,
            11,
            &dom_owner,
            xmr_xmr,
            72,
        ),
        (
            SwapArbiterPath::Punish,
            &punish,
            21,
            &xmr_owner,
            dom_xmr,
            73,
        ),
    ] {
        let offer = offer(branch, shares.adaptor_point(path).unwrap(), session);
        let resume = offer.to_swap_arbiter_resume_bytes().unwrap();
        assert!(DomClaimOffer::from_resume_bytes(&resume, digest(&resume)).is_err());
        let offer =
            DomClaimOffer::from_swap_arbiter_resume_bytes(&resume, digest(&resume)).unwrap();
        assert_eq!(offer.to_swap_arbiter_resume_bytes().unwrap(), resume);
        let final_tx = offer
            .complete(
                &SecretScalar::from_be_bytes(secret.dom_secret_big_endian()).unwrap(),
                &context(height),
            )
            .unwrap();
        validate_swap_arbiter_input_proofs(
            &final_tx,
            BlockHeight(height),
            std::slice::from_ref(&funding.proof),
        )
        .unwrap();
        let extracted = offer.extract(&final_tx, &context(height)).unwrap();
        let recovered = shares.xmr_share_from_dom_opening(path, *extracted).unwrap();
        let recovered = Option::<Scalar>::from(Scalar::from_canonical_bytes(*recovered)).unwrap();
        let reconstructed = local_share + recovered;
        assert_eq!(reconstructed * ED25519_BASEPOINT_POINT, joint_xmr_key);
        native_xmr_spend(reconstructed);

        let other_path = if path == SwapArbiterPath::Refund {
            SwapArbiterPath::Claim
        } else {
            SwapArbiterPath::Refund
        };
        assert!(shares
            .xmr_share_from_dom_opening(other_path, *extracted)
            .is_err());
    }
}

#[test]
fn arbiter_resume_rejects_unpinned_or_semantically_changed_offers() {
    let input_blinding = scalar(31);
    let branch = branch(
        Commitment::commit(INPUT_VALUE, &input_blinding),
        &input_blinding,
        KERNEL_FEAT_SWAP_CLAIM,
        40,
        [32, 33],
    );
    let mut secret_bytes = [0; 32];
    secret_bytes[31] = 34;
    let secret = SecretScalar::from_be_bytes(secret_bytes).unwrap();
    let offer = offer(&branch, secret.public_key().unwrap(), 86);
    let bytes = offer.to_swap_arbiter_resume_bytes().unwrap();
    let pinned = digest(&bytes);

    assert!(DomClaimOffer::from_swap_arbiter_resume_bytes(&bytes, [0; 32]).is_err());
    for end in [0, bytes.len() / 2, bytes.len() - 1] {
        assert!(DomClaimOffer::from_swap_arbiter_resume_bytes(&bytes[..end], pinned).is_err());
    }

    let magic_len = b"DXP1/DOM-swap-arbiter-resume/v1\0".len();
    for index in [magic_len, magic_len + 64, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(DomClaimOffer::from_swap_arbiter_resume_bytes(&changed, digest(&changed)).is_err());
    }
}

#[test]
fn share_proofs_cannot_swap_roles_or_settlements() {
    let dom_owner = CrossCurveSecret252::generate(&mut OsRng);
    let xmr_owner = CrossCurveSecret252::generate(&mut OsRng);
    let dom_owner_proof = prove_bound(
        &dom_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_REFUND_SHARE,
        &mut OsRng,
    )
    .unwrap();
    let xmr_owner_proof = prove_bound(
        &xmr_owner,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_SHARED_SPEND,
        &mut OsRng,
    )
    .unwrap();
    assert!(VerifiedArbiterSharesV1::new(
        SETTLEMENT_ID,
        CONTEXT_HASH,
        &xmr_owner_proof,
        &dom_owner_proof,
    )
    .is_err());
    assert!(VerifiedArbiterSharesV1::new(
        [0x64; 32],
        CONTEXT_HASH,
        &dom_owner_proof,
        &xmr_owner_proof,
    )
    .is_err());

    let dom_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        dom_owner.xmr_share_little_endian(),
    ))
    .unwrap();
    let cancelling = CrossCurveSecret252::from_little_endian((-dom_scalar).to_bytes()).unwrap();
    let cancelling_proof = prove_bound(
        &cancelling,
        SETTLEMENT_ID,
        CONTEXT_HASH,
        ROLE_XMR_SHARED_SPEND,
        &mut OsRng,
    )
    .unwrap();
    assert!(VerifiedArbiterSharesV1::new(
        SETTLEMENT_ID,
        CONTEXT_HASH,
        &dom_owner_proof,
        &cancelling_proof,
    )
    .is_err());
}
