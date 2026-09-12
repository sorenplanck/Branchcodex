//! RPC observations are persisted with a post-RPC clock reading, never the
//! timestamp captured before a potentially slow quorum call. No lease renewal.
use crate::*;

fn require_time(lease: &XmrActuatorLeaseV1, started: u64, now: u64) -> Result<()> {
    if started == 0 || now < started {
        return Err(XmrActuatorErrorV1::InvalidTime);
    }
    if now >= lease.lease_until_unix_ms {
        return Err(XmrActuatorErrorV1::LeaseExpired);
    }
    Ok(())
}

fn require_inclusion(inclusion: Option<XmrTxInclusionV1>) -> Result<()> {
    if inclusion.is_some_and(|value| value.block_hash == [0; 32] || value.confirmations == 0) {
        return Err(XmrActuatorErrorV1::ObservationUnavailable);
    }
    Ok(())
}

// Private, single-use replay into the existing fenced transition engine.
// Only actual responses from the caller's observation port reach this cache.
struct Observed {
    hash: Digest32,
    image: Digest32,
    inclusion: Option<Option<XmrTxInclusionV1>>,
    spent: Option<bool>,
}
impl XmrObservationPortV1 for Observed {
    fn transaction_inclusion(&mut self, hash: Digest32) -> Result<Option<XmrTxInclusionV1>> {
        if hash != self.hash {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        self.inclusion.take().ok_or(XmrActuatorErrorV1::Conflict)
    }
    fn key_image_spent(&mut self, image: Digest32) -> Result<bool> {
        if image != self.image {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        self.spent.take().ok_or(XmrActuatorErrorV1::Conflict)
    }
}

impl DurableXmrActuatorV1 {
    /// Observe through the real port, then obtain trusted time before any write.
    /// The original lease/fence is retained; an elapsed lease is not extended.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_current_with_clock_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        port: &mut dyn XmrObservationPortV1,
        min_confirmations: u64,
        started_unix_ms: u64,
        clock: &mut dyn FnMut() -> Result<u64>,
    ) -> Result<XmrOperationViewV1> {
        if min_confirmations == 0 || attempt_id == [0; 32] {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        require_time(lease, started_unix_ms, started_unix_ms)?;
        let view = self
            .store
            .checked_view_v23(lease, locator, started_unix_ms)?;
        let inclusion = port.transaction_inclusion(view.tx_hash)?;
        let now = clock()?;
        require_time(lease, started_unix_ms, now)?;
        let current = self.store.checked_view_v23(lease, locator, now)?;
        if current.revision != view.revision
            || current.locator != view.locator
            || current.tx_hash != view.tx_hash
            || current.key_image != view.key_image
            || current.custody_digest != view.custody_digest
        {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        require_inclusion(inclusion)?;
        if let Some(current) = self.adjudicate_prior_finality_v23(
            lease,
            &current,
            attempt_id,
            inclusion,
            min_confirmations,
            now,
        )? {
            return Ok(current);
        }
        self.observe_current(
            lease,
            locator,
            attempt_id,
            &mut Observed {
                hash: view.tx_hash,
                image: view.key_image,
                inclusion: Some(inclusion),
                spent: None,
            },
            min_confirmations,
            now,
        )
    }

    /// Reconcile with a post-query clock reading covering both inclusion and,
    /// when necessary, the exact key-image query. Never refreshes the lease.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_takeover_with_clock_v23(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        port: &mut dyn XmrObservationPortV1,
        min_confirmations: u64,
        started_unix_ms: u64,
        clock: &mut dyn FnMut() -> Result<u64>,
    ) -> Result<XmrReconcileOutcomeV1> {
        if min_confirmations == 0 || attempt_id == [0; 32] {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        require_time(lease, started_unix_ms, started_unix_ms)?;
        let view = self
            .store
            .checked_view_v23(lease, locator, started_unix_ms)?;
        let inclusion = port.transaction_inclusion(view.tx_hash)?;
        require_inclusion(inclusion)?;
        let spent = if inclusion.is_none()
            && !matches!(
                view.stage,
                XmrTxStageV1::Final | XmrTxStageV1::FinalityInvalidated
            ) {
            Some(port.key_image_spent(view.key_image)?)
        } else {
            None
        };
        let now = clock()?;
        require_time(lease, started_unix_ms, now)?;
        let current = self.store.checked_view_v23(lease, locator, now)?;
        if current.revision != view.revision
            || current.locator != view.locator
            || current.tx_hash != view.tx_hash
            || current.key_image != view.key_image
            || current.custody_digest != view.custody_digest
        {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        if let Some(current) = self.adjudicate_prior_finality_v23(
            lease,
            &current,
            attempt_id,
            inclusion,
            min_confirmations,
            now,
        )? {
            let kind = if current.stage == XmrTxStageV1::Final {
                XmrReconciliationKindV1::Final
            } else {
                XmrReconciliationKindV1::Unknown
            };
            return Ok(XmrReconcileOutcomeV1 {
                view: current,
                kind,
            });
        }
        self.reconcile_takeover(
            lease,
            locator,
            attempt_id,
            &mut Observed {
                hash: view.tx_hash,
                image: view.key_image,
                inclusion: Some(inclusion),
                spent,
            },
            min_confirmations,
            now,
        )
    }
}
