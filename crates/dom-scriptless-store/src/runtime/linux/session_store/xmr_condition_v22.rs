//! Legacy DOM refund validation. No alternative kernel or certificate path.
use super::*;

pub(super) fn admitted_refund_kernel_v22(tx: &Transaction, _chain: &[u8; 32]) -> bool {
    tx.kernels
        .first()
        .is_some_and(|kernel| kernel.features == KERNEL_FEAT_HEIGHT_LOCKED)
}

pub(super) fn validate_refund_signature_v22(
    tx: &Transaction,
    context: &ValidationContext,
) -> Result<(), SessionStoreError> {
    validate_transaction(tx, context).map_err(|_| SessionStoreError::InvalidDomTransaction)
}

pub(super) fn decode_refund_artifact_v22(
    bytes: &[u8],
    context: DomTransactionValidationContextV1,
) -> Result<Transaction, SessionStoreError> {
    let tx =
        Transaction::from_bytes(bytes).map_err(|_| SessionStoreError::InvalidDomTransaction)?;
    if tx
        .to_bytes()
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?
        != bytes
    {
        return Err(SessionStoreError::InvalidDomTransaction);
    }
    validate_refund_signature_v22(
        &tx,
        &ValidationContext {
            current_height: BlockHeight(context.current_height()),
            chain_id: *context.chain_id(),
            now: Timestamp(context.now_unix_seconds()),
        },
    )?;
    Ok(tx)
}
