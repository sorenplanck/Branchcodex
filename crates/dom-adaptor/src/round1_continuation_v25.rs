//! Move-only continuation of the SAME private round-one computation.
//!
//! This is not a proof/nonce cache: one session owner retains at most one
//! unconsumed state, and every lookup consumes newly vault-reopened material
//! whose common-nonce transcript was freshly authenticated by the caller.
//! Nothing here creates that vault/Store authority or survives process exit.
use super::*;
use crate::bulletproof_mpc::BpRound1PrivateOriginV25;

const MAX_STATEMENT_BYTES_V25: usize = 187 + 65 * BpStatementV1::MAX_PARTICIPANTS;
const MAX_EXTRA_BYTES_V25: usize = 4096;

struct OriginV25 {
    statement: [u8; MAX_STATEMENT_BYTES_V25],
    statement_len: usize,
    participant_index: u16,
    extra: [u8; MAX_EXTRA_BYTES_V25],
    extra_len: usize,
    private: BpRound1PrivateOriginV25,
}

impl OriginV25 {
    fn from_fresh(
        statement: &BpStatementV1,
        participant_index: u16,
        extra: &[u8],
        blinding: &BpLocalBlindingV1,
        common_nonce: &BpCommonNonceV1,
        private_nonce: &BpPrivateNonceV1,
    ) -> Option<Self> {
        let statement_bytes = statement.to_bytes();
        if statement_bytes.len() > MAX_STATEMENT_BYTES_V25 || extra.len() > MAX_EXTRA_BYTES_V25 {
            return None;
        }
        let mut origin = Self {
            statement: [0; MAX_STATEMENT_BYTES_V25],
            statement_len: statement_bytes.len(),
            participant_index,
            extra: [0; MAX_EXTRA_BYTES_V25],
            extra_len: extra.len(),
            private: BpRound1PrivateOriginV25::from_fresh(blinding, common_nonce, private_nonce),
        };
        origin.statement[..statement_bytes.len()].copy_from_slice(statement_bytes);
        origin.extra[..extra.len()].copy_from_slice(extra);
        Some(origin)
    }

    fn matches(&self, other: &Self) -> bool {
        // Compare all private bytes in constant time even if public scope is
        // different. Public framing is exact, not digest-only or prefix-only.
        let private_matches = self.private.matches(&other.private);
        private_matches
            && self.participant_index == other.participant_index
            && self.statement_len == other.statement_len
            && self.statement == other.statement
            && self.extra_len == other.extra_len
            && self.extra == other.extra
    }
}

/// A single process-local, non-cloneable round-one continuation.
///
/// The private state is neither a signing authority nor durable nonce custody.
/// It can only be reused after a fresh vault import and authenticated
/// `PendingCommonNonce::finish` reproduce its exact origin. Dropping it
/// zeroizes the private origin and backend-owned secrets; restart uses the
/// original round-one computation. No serialization or private getter exists.
pub struct Round1ContinuationV25 {
    origin: Option<OriginV25>,
    local: LocalBpSecrets,
    share: BpRound1ShareV1,
    #[cfg(test)]
    original_computations: usize,
}

impl Round1ContinuationV25 {
    /// Move the sole existing `Round1Done` state into the unchanged round-two
    /// boundary. Production must call `round2_vault_backed_v1`, preserving
    /// durable consumption before releasing transport bytes. The caller must
    /// freshly authenticate this continuation again immediately before taking
    /// it; this move alone grants no current Store/vault authorization.
    pub fn into_local_for_round2_v25(self) -> LocalBpSecrets {
        self.local
    }
}

impl DomCollaborativeRangeProofV1 {
    /// Reuse one exact round-one computation after fresh private origin
    /// authentication, or run the unchanged original when none was retained.
    ///
    /// `fresh` must come from this tick's authenticated vault reopen followed
    /// by the Store's complete common-nonce commitment/reveal validation. All
    /// existing statement/Ready checks run before reuse. A different origin
    /// refuses without replacing or consuming the valid retained state.
    /// Oversized extra bytes remain valid original inputs, but are never
    /// eligible for reuse; their continuation is held only to move into R2.
    /// Two ineligible origins always recompute using fresh material, replacing
    /// the old holder only after success; they never obtain a memoized result.
    pub fn round1_with_continuation_v25(
        &self,
        statement: &BpStatementV1,
        fresh: LocalBpSecrets,
        retained: &mut Option<Round1ContinuationV25>,
    ) -> Result<BpRound1ShareV1> {
        self.require_statement(statement)?;
        if fresh.statement_hash != self.statement_hash {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        if statement
            .participant_ids()
            .get(usize::from(fresh.participant_index))
            .is_none()
        {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof participant index is outside the roster",
            ));
        }
        let origin = {
            let stage = fresh.stage.lock().map_err(|_| poisoned())?;
            let LocalStage::Ready {
                blinding,
                common_nonce,
                private_nonce,
            } = &*stage
            else {
                return Err(consumed());
            };
            OriginV25::from_fresh(
                statement,
                fresh.participant_index,
                &self.extra_commit,
                blinding,
                common_nonce,
                private_nonce,
            )
        };
        if let Some(previous) = retained.as_ref() {
            let previous_stage = previous.local.stage.lock().map_err(|_| poisoned())?;
            if !matches!(*previous_stage, LocalStage::Round1Done { .. }) {
                return Err(consumed());
            }
            match (&previous.origin, &origin) {
                (Some(previous_origin), Some(fresh_origin)) => {
                    if !previous_origin.matches(fresh_origin) {
                        return Err(AdaptorError::AuthorizationMismatch);
                    }
                    // No backend invocation and no clone of private state.
                    // The freshly imported private material is dropped here.
                    return Ok(previous.share.clone());
                }
                (None, None) => {} // Ineligible: always execute the original.
                _ => return Err(AdaptorError::AuthorizationMismatch),
            }
        }
        // Leave any previous holder intact if the original computation fails.
        // The original method marks fresh Consumed before invoking its backend.
        let share = self.round1(statement, &fresh)?;
        #[cfg(test)]
        let original_computations = retained
            .as_ref()
            .map_or(1, |previous| previous.original_computations + 1);
        *retained = Some(Round1ContinuationV25 {
            origin,
            local: fresh,
            share: share.clone(),
            #[cfg(test)]
            original_computations,
        });
        Ok(share)
    }
}

#[cfg(test)]
#[path = "round1_continuation_v25_tests.rs"]
mod tests;
