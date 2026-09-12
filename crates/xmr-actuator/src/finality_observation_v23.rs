//! A fresh quorum reading can invalidate, but never erase or resurrect, a
//! previously final sweep. Additional confirmations do not change its identity.
use crate::store::StageTransitionV1;
use crate::*;

// Separate from observation/reconciliation: replaying the original successful
// attempt must not suppress later durable evidence that its inclusion was lost.
const MUTATION_INVALIDATE_FINALITY_V23: u8 = 0x23;

impl DurableXmrActuatorV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn adjudicate_prior_finality_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        view: &XmrOperationViewV1,
        attempt_id: Digest32,
        inclusion: Option<XmrTxInclusionV1>,
        minimum: u64,
        now: u64,
    ) -> Result<Option<XmrOperationViewV1>> {
        if view.stage == XmrTxStageV1::FinalityInvalidated {
            return Ok(Some(view.clone()));
        }
        if view.stage != XmrTxStageV1::Final {
            return Ok(None);
        }
        let previous = view.finality.ok_or(XmrActuatorErrorV1::Corrupt)?;
        if inclusion.is_some_and(|current| {
            current.height == previous.final_height
                && current.block_hash == previous.final_block_hash
                && current.confirmations >= minimum
        }) {
            // The original evidence digest includes its observation depth.
            // Do not replace it when only the chain's confirmation count grows.
            return Ok(Some(view.clone()));
        }
        self.store
            .apply_mutation(
                lease,
                view.locator,
                attempt_id,
                MUTATION_INVALIDATE_FINALITY_V23,
                now,
                |current| {
                    if current.stage != XmrTxStageV1::Final
                        || current.tx_hash != view.tx_hash
                        || current.key_image != view.key_image
                        || current.custody_digest != view.custody_digest
                        || current.finality != Some(previous)
                    {
                        return Err(XmrActuatorErrorV1::Conflict);
                    }
                    Ok(StageTransitionV1 {
                        stage: XmrTxStageV1::FinalityInvalidated,
                        finality: Some(previous),
                        reconciliation: Some(XmrReconciliationKindV1::Unknown),
                    })
                },
            )
            .map(Some)
    }
}
