//! Restricted DOM claim binding for the new DXP1 experiment. Consensus checks
//! do not establish input ownership, UTXO membership, maturity or inclusion.
//! Output commitments must be approved with their amounts by the participants.

use dom_consensus::{
    validate_balance_equation, validate_range_proofs, validate_transaction,
    validate_transaction_structure, Transaction, ValidationContext,
};
use dom_core::{DomError, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
use dom_crypto::{hash::blake2b_256_tagged, PartialSig, PublicKey, SchnorrSignature};
use dom_scriptless_primitives::{
    scriptless_adapt_signature, scriptless_extract_adaptor_secret_be_bytes,
    scriptless_verify_pre_signature, SecretScalar,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct PreparedDomClaim {
    transaction: Transaction,
    chain: [u8; 32],
    message: [u8; 32],
    key: PublicKey,
}

fn invalid(message: &str) -> DomError {
    DomError::Invalid(message.into())
}

impl PreparedDomClaim {
    /// Freeze a one-input/one-output plain claim before signing. Zero signature
    /// bytes are a placeholder, never an authorization to publish the claim.
    pub fn new(transaction: Transaction, chain: [u8; 32]) -> Result<Self, DomError> {
        Self::for_kernel(transaction, chain, KERNEL_FEAT_PLAIN, 0)
    }

    /// Freeze an exact height-locked refund. This is only signing preparation:
    /// a future-height validation context does not authorize current admission.
    /// Never pair this protection with disclosure of the reserve's peer share,
    /// which would let its holder sign an unrelated plain transaction instead.
    pub fn new_height_locked_refund(
        transaction: Transaction,
        chain: [u8; 32],
        not_before: u64,
    ) -> Result<Self, DomError> {
        if not_before == 0 {
            return Err(invalid("DOM refund requires a nonzero height"));
        }
        Self::for_kernel(transaction, chain, KERNEL_FEAT_HEIGHT_LOCKED, not_before)
    }

    fn for_kernel(
        transaction: Transaction,
        chain: [u8; 32],
        features: u8,
        lock_height: u64,
    ) -> Result<Self, DomError> {
        if chain == [0; 32]
            || transaction.inputs.len() != 1
            || transaction.outputs.len() != 1
            || transaction.kernels.len() != 1
        {
            return Err(invalid("unsupported DOM claim shape"));
        }
        let kernel = &transaction.kernels[0];
        if kernel.features != features
            || kernel.lock_height != lock_height
            || kernel.excess_signature != [0; 65]
            || kernel.fee.noms() == 0
        {
            return Err(invalid("unsupported DOM claim kernel"));
        }
        validate_transaction_structure(&transaction)?;
        validate_range_proofs(&transaction)?;
        validate_balance_equation(&transaction)?;
        let key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())?;
        // Same native kernel message as dom-consensus; chain is added by its
        // Schnorr challenge. Full transaction equality is enforced separately.
        let mut data = vec![kernel.features];
        data.extend_from_slice(&kernel.fee.noms().to_le_bytes());
        data.extend_from_slice(&kernel.lock_height.to_le_bytes());
        let message = *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes();
        Ok(Self {
            transaction,
            chain,
            message,
            key,
        })
    }

    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }
    pub fn key(&self) -> &PublicKey {
        &self.key
    }
    pub fn chain(&self) -> &[u8; 32] {
        &self.chain
    }
    pub fn unsigned_transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn binding(&self) -> Result<[u8; 32], DomError> {
        let bytes = self.transaction.to_bytes()?;
        let mut hash = Sha256::new();
        hash.update(b"DXP1/native-dom-claim/v1");
        hash.update(self.chain);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    /// Accept public signing material only after validating the native kernel
    /// adaptor equation. Distributed signing and durable nonces are separate.
    pub fn bind_presignature(
        self,
        pre: PartialSig,
        nonce: PublicKey,
        adaptor: PublicKey,
    ) -> Result<DomClaimOffer, DomError> {
        if !scriptless_verify_pre_signature(
            &pre,
            &nonce,
            &self.key,
            &adaptor,
            &self.chain,
            &self.message,
        )? {
            return Err(invalid("invalid DOM claim pre-signature"));
        }
        Ok(DomClaimOffer {
            claim: self,
            pre,
            nonce,
            adaptor,
        })
    }
}

pub struct DomClaimOffer {
    claim: PreparedDomClaim,
    pre: PartialSig,
    nonce: PublicKey,
    adaptor: PublicKey,
}

impl DomClaimOffer {
    /// Participant-private, immutable resumption artifact. No nonce scalar,
    /// reserve share or adaptor witness is stored. Only plain claims supported.
    pub fn to_resume_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.claim.transaction.kernels[0].features != KERNEL_FEAT_PLAIN {
            return Err(invalid("resume envelope only supports plain claims"));
        }
        let mut bytes = b"DXP1/DOM-claim-resume/v1\0".to_vec();
        bytes.extend(self.claim.chain);
        bytes.extend(self.pre.to_bytes());
        bytes.extend(self.nonce.to_compressed_bytes());
        bytes.extend(self.adaptor.to_compressed_bytes());
        let tx = self.claim.transaction.to_bytes()?;
        bytes.extend(
            u32::try_from(tx.len())
                .map_err(|_| invalid("resume body too large"))?
                .to_le_bytes(),
        );
        bytes.extend(tx);
        if bytes.len() > crate::claim_resume::MAX_RECORD_BYTES {
            return Err(invalid("resume body too large"));
        }
        Ok(bytes)
    }

    /// `expected` must be pinned by the original operation; hashing a file
    /// after a restart does not authenticate its payment terms or destination.
    pub fn from_resume_bytes(bytes: &[u8], expected: [u8; 32]) -> Result<Self, DomError> {
        use crate::claim_resume::{checked, take};
        let mut input = checked(bytes, expected, b"DXP1/DOM-claim-resume/v1\0")
            .ok_or_else(|| invalid("resume encoding or binding"))?;
        let chain = take(&mut input).ok_or_else(|| invalid("missing resume chain"))?;
        let pre = PartialSig::from_bytes(
            &take::<32>(&mut input).ok_or_else(|| invalid("missing resume pre-signature"))?,
        )?;
        let nonce = PublicKey::from_compressed_bytes(
            &take::<33>(&mut input).ok_or_else(|| invalid("missing resume nonce"))?,
        )?;
        let adaptor = PublicKey::from_compressed_bytes(
            &take::<33>(&mut input).ok_or_else(|| invalid("missing resume adaptor"))?,
        )?;
        let len =
            u32::from_le_bytes(take(&mut input).ok_or_else(|| invalid("missing resume length"))?)
                as usize;
        if input.len() != len {
            return Err(invalid("resume length mismatch"));
        }
        let tx = Transaction::from_bytes(input)?;
        let result = PreparedDomClaim::new(tx, chain)?.bind_presignature(pre, nonce, adaptor)?;
        if result.to_resume_bytes()? != bytes {
            return Err(invalid("noncanonical resume encoding"));
        }
        Ok(result)
    }

    pub fn complete(
        &self,
        secret: &SecretScalar,
        context: &ValidationContext,
    ) -> Result<Transaction, DomError> {
        if secret.public_key()?.to_compressed_bytes() != self.adaptor.to_compressed_bytes() {
            return Err(invalid("DOM adaptor secret mismatch"));
        }
        let signature = scriptless_adapt_signature(&self.pre, &self.nonce, secret)?;
        let mut tx = self.claim.transaction.clone();
        tx.kernels[0].excess_signature = signature.to_bytes();
        self.validate(&tx, context)?;
        Ok(tx)
    }

    pub fn validate(&self, tx: &Transaction, context: &ValidationContext) -> Result<(), DomError> {
        if context.chain_id != self.claim.chain || tx.kernels.len() != 1 {
            return Err(invalid("different DOM claim context"));
        }
        let mut unsigned = tx.clone();
        unsigned.kernels[0].excess_signature = [0; 65];
        if unsigned != self.claim.transaction {
            return Err(invalid("different DOM transaction"));
        }
        validate_transaction(tx, context)
    }

    pub fn extract(
        &self,
        tx: &Transaction,
        context: &ValidationContext,
    ) -> Result<Zeroizing<[u8; 32]>, DomError> {
        self.validate(tx, context)?;
        let signature = SchnorrSignature::from_bytes(&tx.kernels[0].excess_signature)?;
        scriptless_extract_adaptor_secret_be_bytes(
            &signature,
            &self.pre,
            &self.nonce,
            &self.adaptor,
        )
    }
}
