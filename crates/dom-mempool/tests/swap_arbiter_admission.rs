use dom_consensus::{
    derive_chain_id, swap_arbiter_intent, SwapArbiterContract, Transaction, TransactionInput,
    TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, DomError, Hash256, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST, KERNEL_FEAT_SWAP_CLAIM,
    KERNEL_FEAT_SWAP_PUNISH, KERNEL_FEAT_SWAP_REFUND, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST,
    TAG_KERNEL_MSG,
};
use dom_crypto::hash::{blake2b_256, blake2b_256_tagged};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{range_proof_prove_bytes_with_extra_commit, schnorr_sign, SecretKey};
use dom_mempool::Mempool;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;

const INPUT_VALUE: u64 = 500_000;
const FEE: u64 = 100_000;

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

fn branch(
    input: Commitment,
    input_blinding: &BlindingFactor,
    feature: u8,
    boundary: u64,
    kernel_scalar: u8,
) -> Transaction {
    let kernel_blinding = scalar(kernel_scalar);
    let output_blinding = input_blinding.add(&kernel_blinding).unwrap();
    let output_commitment = Commitment::commit(INPUT_VALUE - FEE, &output_blinding);
    let (proof, _) =
        dom_crypto::range_proof_prove_bytes(INPUT_VALUE - FEE, &output_blinding).unwrap();
    let excess = Commitment::commit(0, &kernel_blinding);
    let mut message = vec![feature];
    message.extend_from_slice(&FEE.to_le_bytes());
    message.extend_from_slice(&boundary.to_le_bytes());
    let message = blake2b_256_tagged(TAG_KERNEL_MSG, &message);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).unwrap();
    let signature = schnorr_sign(&secret, message.as_bytes(), &chain_id()).unwrap();
    Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: feature,
            fee: Amount::from_noms(FEE).unwrap(),
            lock_height: boundary,
            excess,
            excess_signature: signature.to_bytes(),
        }],
        offset: [0; 32],
    }
}

fn fixture() -> (UtxoEntry, Transaction, Transaction, Transaction) {
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
    (
        UtxoEntry {
            block_height: 1,
            is_coinbase: false,
            proof: funding.proof,
        },
        claim,
        refund,
        punish,
    )
}

fn admit(tx: Transaction, entry: &UtxoEntry, current_height: u64) -> Result<(), DomError> {
    admit_on_chain(tx, entry, current_height, chain_id())
}

fn admit_on_chain(
    tx: Transaction,
    entry: &UtxoEntry,
    current_height: u64,
    chain_id: [u8; 32],
) -> Result<(), DomError> {
    let hash = *blake2b_256(&tx.to_bytes().unwrap()).as_bytes();
    Mempool::new().accept_tx_with_chain_view(tx, hash, 0, current_height, chain_id, 10, |_| {
        Ok(Some(entry.clone()))
    })
}

#[test]
fn mempool_targets_next_block_and_never_overlaps_swap_phases() {
    let (entry, claim, refund, punish) = fixture();

    admit(claim.clone(), &entry, 9).expect("claim belongs in next block 10");
    assert!(matches!(
        admit(claim, &entry, 10),
        Err(DomError::Invalid(_))
    ));

    assert!(matches!(
        admit(refund.clone(), &entry, 9),
        Err(DomError::TemporarilyInvalid(_))
    ));
    admit(refund.clone(), &entry, 10).expect("refund starts in next block 11");
    assert!(matches!(
        admit(refund, &entry, 20),
        Err(DomError::Invalid(_))
    ));

    assert!(matches!(
        admit(punish.clone(), &entry, 19),
        Err(DomError::TemporarilyInvalid(_))
    ));
    admit(punish, &entry, 20).expect("punish starts in next block 21");
}

#[test]
fn mempool_uses_persisted_contract_instead_of_peer_supplied_shape() {
    let (entry, mut claim, _, _) = fixture();
    claim.offset[0] = 1;
    assert!(matches!(admit(claim, &entry, 9), Err(DomError::Invalid(_))));
}

#[test]
fn mempool_rejects_dxa1_when_the_target_chain_is_not_activated() {
    let (entry, mut claim, _, _) = fixture();
    let mainnet = *derive_chain_id(
        NETWORK_MAGIC_MAINNET,
        &Hash256::from_bytes(GENESIS_HASH_MAINNET),
    )
    .as_bytes();
    let kernel = &mut claim.kernels[0];
    let mut message = vec![kernel.features];
    message.extend_from_slice(&kernel.fee.noms().to_le_bytes());
    message.extend_from_slice(&kernel.lock_height.to_le_bytes());
    let message = blake2b_256_tagged(TAG_KERNEL_MSG, &message);
    let secret = SecretKey::from_bytes(scalar(11).as_bytes()).unwrap();
    kernel.excess_signature = schnorr_sign(&secret, message.as_bytes(), &mainnet)
        .unwrap()
        .to_bytes();
    assert!(matches!(
        admit_on_chain(claim, &entry, 9, mainnet),
        Err(DomError::Invalid(message)) if message.contains("not active")
    ));
}
