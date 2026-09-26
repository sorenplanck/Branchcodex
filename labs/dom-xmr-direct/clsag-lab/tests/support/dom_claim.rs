//! Disposable centralized fixture, with an unfunded input commitment.
use dom_consensus::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput, ValidationContext,
};
use dom_core::{Amount, BlockHeight, Timestamp, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    PublicKey, SecretKey,
};
use dom_scriptless_primitives::scriptless_add_public_points;
use dxp1_clsag_lab::native_dom::{DomClaimOffer, PreparedDomClaim};

pub fn context() -> ValidationContext {
    ValidationContext {
        chain_id: [56; 32],
        current_height: BlockHeight(100),
        now: Timestamp(1_790_000_000),
    }
}

pub struct Fixture {
    pub claim: PreparedDomClaim,
    key: SecretKey,
}

impl Fixture {
    pub fn new() -> Self {
        let input = BlindingFactor::random();
        let output = BlindingFactor::random();
        let offset = BlindingFactor::random();
        let excess = output
            .sub_nonzero(&input)
            .unwrap()
            .sub_nonzero(&offset)
            .unwrap();
        let key = SecretKey::from_bytes(excess.as_bytes()).unwrap();
        let (proof, commitment) = dom_crypto::range_proof_prove_bytes(7_900_000, &output).unwrap();
        let transaction = Transaction {
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
                excess: Commitment::commit(0, &excess),
                excess_signature: [0; 65],
            }],
            offset: *offset.as_bytes(),
        };
        let claim = PreparedDomClaim::new(transaction, context().chain_id).unwrap();
        Self { claim, key }
    }

    pub fn offer(&self, adaptor: &[u8; 33]) -> DomClaimOffer {
        let adaptor = PublicKey::from_compressed_bytes(adaptor).unwrap();
        let nonce_key = SecretKey::from_bytes(BlindingFactor::random().as_bytes()).unwrap();
        let nonce =
            scriptless_add_public_points(&[nonce_key.public_key(), adaptor.clone()]).unwrap();
        let pre = dom_crypto::schnorr_partial_sign(
            &self.key,
            &nonce_key,
            &nonce,
            self.claim.key(),
            self.claim.chain(),
            self.claim.message(),
        )
        .unwrap();
        self.claim
            .clone()
            .bind_presignature(pre, nonce, adaptor)
            .unwrap()
    }
}
