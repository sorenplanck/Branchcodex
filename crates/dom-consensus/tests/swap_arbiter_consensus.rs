use dom_consensus::{
    derive_chain_id, is_swap_arbiter_active, swap_arbiter_activation_height, swap_arbiter_intent,
    validate_range_proofs, validate_swap_arbiter_input_proofs, validate_transaction,
    SwapArbiterContract, Transaction, TransactionInput, TransactionKernel, TransactionOutput,
    ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, DomError, Hash256, Timestamp, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST,
    GENESIS_HASH_TESTNET, KERNEL_FEAT_PLAIN, KERNEL_FEAT_SWAP_CLAIM, KERNEL_FEAT_SWAP_PUNISH,
    KERNEL_FEAT_SWAP_REFUND, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
    TAG_KERNEL_MSG,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{range_proof_prove_bytes_with_extra_commit, schnorr_sign, SecretKey};

const INPUT_VALUE: u64 = 50_000;
const OUTPUT_VALUE: u64 = 49_000;

fn chain_id() -> [u8; 32] {
    *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(GENESIS_HASH_REGTEST),
    )
    .as_bytes()
}

fn scalar(last: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = last;
    BlindingFactor::from_bytes(bytes).unwrap()
}

fn kernel_message(features: u8, fee: u64, lock_height: u64) -> [u8; 32] {
    let mut bytes = vec![features];
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &bytes).as_bytes()
}

fn branch(
    input: Commitment,
    input_blinding: &BlindingFactor,
    feature: u8,
    boundary: u64,
    kernel_scalar: u8,
) -> Transaction {
    let kernel_blinding = scalar(kernel_scalar);
    let output_blinding = input_blinding.add(&kernel_blinding).unwrap();
    let output_commitment = Commitment::commit(OUTPUT_VALUE, &output_blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes(OUTPUT_VALUE, &output_blinding).unwrap();
    assert_eq!(proof_commitment, *output_commitment.as_bytes());
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let signature = schnorr_sign(
        &secret,
        &kernel_message(feature, INPUT_VALUE - OUTPUT_VALUE, boundary),
        &chain_id(),
    )
    .unwrap();
    Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: feature,
            fee: Amount::from_noms(INPUT_VALUE - OUTPUT_VALUE).unwrap(),
            lock_height: boundary,
            excess,
            excess_signature: signature.to_bytes(),
        }],
        offset: [0; 32],
    }
}

fn fixture() -> (
    TransactionOutput,
    SwapArbiterContract,
    Transaction,
    Transaction,
    Transaction,
) {
    let input_blinding = scalar(7);
    let input = Commitment::commit(INPUT_VALUE, &input_blinding);
    let claim = branch(
        input.clone(),
        &input_blinding,
        KERNEL_FEAT_SWAP_CLAIM,
        10,
        11,
    );
    let refund = branch(
        input.clone(),
        &input_blinding,
        KERNEL_FEAT_SWAP_REFUND,
        11,
        12,
    );
    let punish = branch(input, &input_blinding, KERNEL_FEAT_SWAP_PUNISH, 21, 13);
    let contract = SwapArbiterContract::new(
        10,
        20,
        swap_arbiter_intent(&claim).unwrap(),
        swap_arbiter_intent(&refund).unwrap(),
        swap_arbiter_intent(&punish).unwrap(),
    )
    .unwrap();
    let contract_bytes = contract.to_bytes();
    let (proof, commitment) =
        range_proof_prove_bytes_with_extra_commit(INPUT_VALUE, &input_blinding, &contract_bytes)
            .unwrap();
    let funding = TransactionOutput::with_swap_arbiter(
        Commitment::from_compressed_bytes(&commitment).unwrap(),
        proof,
        &contract,
    )
    .unwrap();
    (funding, contract, claim, refund, punish)
}

fn context(height: u64) -> ValidationContext {
    ValidationContext {
        current_height: BlockHeight(height),
        chain_id: chain_id(),
        now: Timestamp(u64::MAX),
    }
}

#[test]
fn proof_bound_contract_and_three_exact_branches_validate() {
    let (funding, contract, claim, refund, punish) = fixture();
    assert_eq!(funding.swap_arbiter().unwrap(), Some(contract));
    let funding_tx = Transaction {
        inputs: vec![],
        outputs: vec![funding.clone()],
        kernels: vec![],
        offset: [0; 32],
    };
    validate_range_proofs(&funding_tx).unwrap();

    for (tx, height) in [(&claim, 10), (&refund, 11), (&refund, 20), (&punish, 21)] {
        validate_transaction(tx, &context(height)).unwrap();
        validate_swap_arbiter_input_proofs(
            tx,
            BlockHeight(height),
            &chain_id(),
            std::slice::from_ref(&funding.proof),
        )
        .unwrap();
    }
}

#[test]
fn dxa1_activation_is_regtest_only_and_height_exact() {
    let (funding, _, _, _, _) = fixture();
    let funding_tx = Transaction {
        inputs: vec![],
        outputs: vec![funding],
        kernels: vec![],
        offset: [0; 32],
    };
    let regtest = chain_id();
    assert_eq!(
        swap_arbiter_activation_height(&regtest),
        Some(BlockHeight(1))
    );
    assert!(!is_swap_arbiter_active(&regtest, BlockHeight(0)));
    assert!(is_swap_arbiter_active(&regtest, BlockHeight(1)));
    assert!(matches!(
        validate_swap_arbiter_input_proofs(&funding_tx, BlockHeight(0), &regtest, &[]),
        Err(DomError::Invalid(message)) if message.contains("not active")
    ));
    validate_swap_arbiter_input_proofs(&funding_tx, BlockHeight(1), &regtest, &[]).unwrap();

    for (network_magic, genesis_hash) in [
        (NETWORK_MAGIC_MAINNET, GENESIS_HASH_MAINNET),
        (NETWORK_MAGIC_TESTNET, GENESIS_HASH_TESTNET),
    ] {
        let disabled =
            *derive_chain_id(network_magic, &Hash256::from_bytes(genesis_hash)).as_bytes();
        assert_eq!(swap_arbiter_activation_height(&disabled), None);
        assert!(!is_swap_arbiter_active(&disabled, BlockHeight(u64::MAX)));
        assert!(matches!(
            validate_swap_arbiter_input_proofs(
                &funding_tx,
                BlockHeight(u64::MAX),
                &disabled,
                &[],
            ),
            Err(DomError::Invalid(message)) if message.contains("not active")
        ));
    }

    let unknown = [0x55; 32];
    assert_eq!(swap_arbiter_activation_height(&unknown), None);
    assert!(
        validate_swap_arbiter_input_proofs(&funding_tx, BlockHeight(u64::MAX), &unknown, &[],)
            .is_err()
    );
}

#[test]
fn consensus_phases_are_adjacent_and_never_overlap() {
    let (funding, _, claim, refund, punish) = fixture();
    let proof = std::slice::from_ref(&funding.proof);
    assert!(matches!(
        validate_swap_arbiter_input_proofs(&claim, BlockHeight(11), &chain_id(), proof),
        Err(DomError::Invalid(_))
    ));
    assert!(matches!(
        validate_swap_arbiter_input_proofs(&refund, BlockHeight(10), &chain_id(), proof),
        Err(DomError::TemporarilyInvalid(_))
    ));
    assert!(matches!(
        validate_swap_arbiter_input_proofs(&refund, BlockHeight(21), &chain_id(), proof),
        Err(DomError::Invalid(_))
    ));
    assert!(matches!(
        validate_swap_arbiter_input_proofs(&punish, BlockHeight(20), &chain_id(), proof),
        Err(DomError::TemporarilyInvalid(_))
    ));
}

#[test]
fn exact_intents_and_contract_output_are_enforced() {
    let (funding, _, claim, _, _) = fixture();
    let mut changed = claim.clone();
    changed.offset[0] = 1;
    assert!(matches!(
        validate_swap_arbiter_input_proofs(
            &changed,
            BlockHeight(10),
            &chain_id(),
            std::slice::from_ref(&funding.proof),
        ),
        Err(DomError::Invalid(_))
    ));

    let mut ordinary = claim.clone();
    ordinary.kernels[0].features = KERNEL_FEAT_PLAIN;
    ordinary.kernels[0].lock_height = 0;
    assert!(matches!(
        validate_swap_arbiter_input_proofs(
            &ordinary,
            BlockHeight(10),
            &chain_id(),
            std::slice::from_ref(&funding.proof),
        ),
        Err(DomError::Invalid(_))
    ));

    let plain = vec![0u8; dom_crypto::RANGE_PROOF_SIZE];
    assert!(matches!(
        validate_swap_arbiter_input_proofs(
            &claim,
            BlockHeight(10),
            &chain_id(),
            std::slice::from_ref(&plain),
        ),
        Err(DomError::Invalid(_))
    ));
}

#[test]
fn contract_bytes_are_part_of_the_range_proof_statement() {
    let (mut funding, _, _, _, _) = fixture();
    let contract_byte = dom_crypto::RANGE_PROOF_SIZE + 20;
    funding.proof[contract_byte] ^= 1;
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![funding],
        kernels: vec![],
        offset: [0; 32],
    };
    assert!(validate_range_proofs(&tx).is_err());
}

#[test]
fn generic_extension_support_does_not_admit_malformed_recovery_capsules() {
    let blinding = scalar(31);
    let malformed_capsule = [0u8; dom_core::RECOVERY_CAPSULE_SIZE];
    let (proof, commitment) =
        range_proof_prove_bytes_with_extra_commit(OUTPUT_VALUE, &blinding, &malformed_capsule)
            .unwrap();
    let mut envelope = proof;
    envelope.extend_from_slice(&malformed_capsule);
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: Commitment::from_compressed_bytes(&commitment).unwrap(),
            proof: envelope,
        }],
        kernels: vec![],
        offset: [0; 32],
    };
    assert!(validate_range_proofs(&tx).is_err());
}
