//! Native-only route terminal consumer. No JSON/event-digest authority exists.
//! The pure reducer remains chain-free; this optional Linux boundary consumes
//! opaque already-verified evidence without opening an RPC client or signer.

use super::*;
use crate::model::{DomCompensationRecordV12, LegIdV1};
use adapter_dom_real::VerifiedDomCompensationObservationV11;
use dom_scriptless_store::{
    VerifiedXmrRecoveryExecutionAuthorityV12, XmrRecoveryCustodyV11, XmrRecoveryObservedExitV12,
};

impl DurableRouteStoreV1 {
    /// Record the catastrophic DOM payout as its own terminal economic result.
    /// The two signed terms, retained actual graph/funding, fresh native DOM
    /// finality and the route's original per-leg admission must all agree.
    /// A refund share, public digest, plain receipt or decoded event cannot
    /// invoke this boundary. XMR refund is never inferred from compensation.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_dom_compensation_v12(
        &mut self,
        lease: RouteLeaseV1,
        expected_revision: u64,
        leg: LegIdV1,
        authority: &VerifiedXmrRecoveryExecutionAuthorityV12,
        custody: &XmrRecoveryCustodyV11,
        observed: &VerifiedDomCompensationObservationV11,
        now_unix_ms: u64,
    ) -> Result<CommitOutcomeV1, RouteStoreErrorV1> {
        observed
            .require_recent_v12()
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        authority
            .require_custody(custody)
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        authority
            .require_xmr_funding_observed_v12()
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        let finality = observed.finality();
        let policy = authority.policy();
        if finality.chain_id() != authority.chain_id()
            || finality.session_id() != authority.session_id()
            || finality.terms_hash() != authority.terms_hash()
            || finality.graph_digest() != authority.graph_digest()
            || finality.funding_tx_hash() != authority.funding_tx_hash()
            || finality.minimum_confirmations() != authority.minimum_confirmations()
            || finality.max_reorg_depth() != authority.max_reorg_depth()
            || finality.confirmation_depth() < authority.minimum_confirmations()
            || finality.block_height() < policy.policy().compensation_height
        {
            return Err(RouteStoreErrorV1::InvalidMaterial);
        }
        let checkpoint = self.audit_frozen_admission_checkpoint_v2(lease.route_id)?;
        let expected_terms = match leg {
            LegIdV1::Upstream => checkpoint.upstream_terms_digest,
            LegIdV1::Downstream => checkpoint.downstream_terms_digest,
        };
        if expected_terms != authority.terms_hash() {
            return Err(RouteStoreErrorV1::InvalidMaterial);
        }
        let mut record = DomCompensationRecordV12 {
            dom_chain_id: authority.chain_id(),
            session_id: authority.session_id(),
            terms_digest: authority.terms_hash(),
            graph_digest: authority.graph_digest(),
            funding_transaction_id: authority.funding_tx_hash(),
            transaction_id: finality.transaction_hash(),
            evidence_digest: finality.evidence_digest(),
            policy_hash: policy
                .policy()
                .policy_hash()
                .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?,
            custody_id: authority.custody_id(),
            recipient: policy.policy().xmr_funder,
            payout_noms: policy.compensation_payout_noms(),
        };
        let current = self.load_snapshot(lease.route_id)?;
        if let Some(retained) = &current.leg(leg).dom_compensation_v12 {
            let latest_evidence = record.evidence_digest;
            record.evidence_digest = retained.evidence_digest;
            if &record != retained {
                return Err(RouteStoreErrorV1::IdempotencyConflict);
            }
            // A fresh valid observation may have a later tip. Keep the first
            // accepted snapshot digest so exact event retry stays idempotent.
            if latest_evidence == [0; 32] {
                return Err(RouteStoreErrorV1::InvalidMaterial);
            }
        }
        custody
            .retain_recovery_exit_checkpoint_v12(
                authority,
                XmrRecoveryObservedExitV12::DomCompensated,
                finality.transaction_hash(),
                finality.evidence_digest(),
            )
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        let leg_tag = [match leg {
            LegIdV1::Upstream => 1,
            LegIdV1::Downstream => 2,
        }];
        let event_id = domain_digest_v1(
            b"DOM-ROUTE/DOM-COMPENSATED/V12\0",
            &[
                &lease.route_id,
                &leg_tag,
                &record.session_id,
                &record.graph_digest,
                &record.transaction_id,
            ],
        );
        // Recheck monotonic freshness after any disk replay work and before
        // the transactional acceptance/lease validation.
        observed
            .require_recent_v12()
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        authority
            .require_xmr_funding_observed_v12()
            .map_err(|_| RouteStoreErrorV1::InvalidMaterial)?;
        self.apply_event_from_native_owner_v12(
            lease,
            expected_revision,
            event_id,
            &RouteEventV1::DomCompensatedV12 {
                leg,
                compensation: record,
            },
            now_unix_ms,
        )
    }
}
