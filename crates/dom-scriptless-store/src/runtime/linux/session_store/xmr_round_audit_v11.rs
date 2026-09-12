//! Read-only same-Store provenance of ordinary cancel and compensation rounds.
//!
//! Native final Schnorr validity cannot prove whether an adaptor was involved.
//! This audit reconstructs BOTH transactions from retained ordinary Refund
//! nonce commitments, reveals, partial signatures and authenticated transcripts.
//! The auxiliary sessions are distinct from the parent XMR session. They are
//! signing sessions only: none may acquire or have acquired funding authority.
//! Their exact identities/digests must be bound by a future V11 bilateral ready
//! record. This token alone grants no funding, signing or broadcast permission.

use super::super::xmr_recovery::{XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyV11};
use super::*;
use dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11;
use xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11;

/// The two independently owned ordinary signing rounds for one XMR graph.
/// These are full same-Store session IDs, not unverified message digests.
pub struct XmrOrdinaryRecoveryRoundSessionsV11 {
    /// Ordinary height-locked cancel C -> D signing session.
    pub cancel_session: [u8; 32],
    /// Ordinary height-locked compensation D -> XMR-funder signing session.
    pub compensation_session: [u8; 32],
}

/// Read-only proof of two complete ordinary native signing transcripts.
/// No Clone, Debug, decoder or public constructor; it grants no signing action.
pub struct VerifiedXmrOrdinaryRecoveryRoundsV11 {
    parent_session: [u8; 32],
    parent_terms_hash: [u8; 32],
    parent_record_digest: [u8; 32],
    role_digest: [u8; 32],
    graph_digest: [u8; 32],
    custody_id: [u8; 32],
    cancel_session: [u8; 32],
    compensation_session: [u8; 32],
    cancel_round_digest: [u8; 32],
    compensation_round_digest: [u8; 32],
    scope_digest: [u8; 32],
    open_instance_id: [u8; 32],
}

impl VerifiedXmrOrdinaryRecoveryRoundsV11 {
    /// Parent DOM/XMR signing session.
    pub const fn parent_session(&self) -> &[u8; 32] {
        &self.parent_session
    }
    /// Full parent economic terms hash.
    pub const fn parent_terms_hash(&self) -> &[u8; 32] {
        &self.parent_terms_hash
    }
    /// Authenticated parent record: current for legacy, immutable U-round
    /// terminal for the native bounded profile.
    pub const fn parent_record_digest(&self) -> &[u8; 32] {
        &self.parent_record_digest
    }
    /// Complete operational parent role binding digest.
    pub const fn role_digest(&self) -> &[u8; 32] {
        &self.role_digest
    }
    /// Exact five-template native recovery graph digest.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Identity of the retained, locked recovery custody directory.
    pub const fn custody_id(&self) -> &[u8; 32] {
        &self.custody_id
    }
    /// Complete cancel auxiliary session identifier.
    pub const fn cancel_session(&self) -> &[u8; 32] {
        &self.cancel_session
    }
    /// Complete compensation auxiliary session identifier.
    pub const fn compensation_session(&self) -> &[u8; 32] {
        &self.compensation_session
    }
    /// Authenticated ordinary cancel round record digest.
    pub const fn cancel_round_digest(&self) -> &[u8; 32] {
        &self.cancel_round_digest
    }
    /// Authenticated ordinary compensation round record digest.
    pub const fn compensation_round_digest(&self) -> &[u8; 32] {
        &self.compensation_round_digest
    }
    /// Complete parent, graph, custody and two-round scope commitment.
    pub const fn scope_digest(&self) -> &[u8; 32] {
        &self.scope_digest
    }
}

impl ContractsSessionStoreV1 {
    /// Authenticate both ordinary auxiliary signing histories against the
    /// exact native graph held in freshly revalidated encrypted custody.
    ///
    /// This neither upgrades a V2 funding gate nor treats the parent session's
    /// plain FinalRefund as an XMR refund. It reconstructs separate cancel and
    /// compensation signatures from their complete non-adaptor native rounds.
    pub fn audit_xmr_ordinary_recovery_rounds_v11(
        &self,
        role: &FinalClaimRoleBindingV1,
        graph: &VerifiedXmrRecoveryGraphV11,
        policy: &ValidatedXmrCompensationPolicyV11,
        custody: &XmrRecoveryCustodyV11,
        sessions: XmrOrdinaryRecoveryRoundSessionsV11,
    ) -> Result<VerifiedXmrOrdinaryRecoveryRoundsV11, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let terms = role.terms();
        let binding = graph.binding();
        let parent_session = terms.session_id.0;
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| SessionStoreError::Canonical)?;
        let revalidated_policy = policy
            .policy()
            .validate_for(terms)
            .map_err(|_| SessionStoreError::InvalidTransition)?;
        let expected = graph
            .ordinary_recovery_sessions_v23(&revalidated_policy)
            .map_err(|_| SessionStoreError::InvalidTransition)?;
        require_exact_recovery_sessions_v23(parent_session, expected, &sessions)?;
        if terms.counterparty_leg.mechanism
            != kaystra_core::types::LockMechanism::CrossCurveSharedSpend
            || binding.session_id != parent_session
            || binding.terms_hash != terms_hash
            || binding.chain_id != terms.dom_leg.chain_id.0
            || binding.funding_commitment != role.shared_output_commitment()
            || binding.claim_adaptor_point != role.adaptor_point_sec1()
            || terms.assurance_policy_hash.is_none()
            || custody.scope().binding != *binding
            || custody.scope().graph_digest != *graph.graph_digest()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let same_graph = custody
            .with_graph(|retained| {
                retained.graph_digest() == graph.graph_digest() && retained.binding() == binding
            })
            .map_err(|_| SessionStoreError::Quarantined)?;
        if !same_graph {
            return Err(SessionStoreError::Quarantined);
        }
        let current = self.load_session_locked(parent_session)?;
        if current.terms_hash() != terms_hash {
            return Err(SessionStoreError::InvalidTransition);
        }
        let parent = if revalidated_policy
            .policy()
            .bounded_availability_v23
            .is_some()
        {
            // Bind this token to the immutable U terminal, not today's head.
            // Readiness and funding advance the journal without changing these rounds.
            let rebuilt = self.reconstruct_completed_xmr_graph_v23(parent_session)?;
            if rebuilt.graph().binding() != graph.binding()
                || rebuilt.graph().graph_digest() != graph.graph_digest()
                || rebuilt.graph().refund_pre_signature().to_bytes()
                    != graph.refund_pre_signature().to_bytes()
                || rebuilt.graph().cancel_bytes() != graph.cancel_bytes()
                || rebuilt.graph().punish_bytes() != graph.punish_bytes()
                || rebuilt.economic().policy() != &revalidated_policy
            {
                return Err(SessionStoreError::Quarantined);
            }
            let origin = self.authenticate_xmr_graph_signing_session_v23(
                parent_session,
                XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
            )?;
            let revision = origin
                .start
                .revision()
                .checked_add(6)
                .ok_or(SessionStoreError::CapacityExceeded)?;
            let terminal = self.load_session_revision(parent_session, revision)?;
            if current.revision() < revision
                || terminal.phase() != SessionPhaseV1::RefundSigning
                || terminal.irreversible().funding_authorized
                || terminal.irreversible().adaptor_secret_exposed
            {
                return Err(SessionStoreError::Quarantined);
            }
            if current.revision() != revision || current.irreversible().funding_authorized {
                let ready = self.require_xmr_graph_custody_ready_locked_v23(
                    role,
                    &rebuilt,
                    custody.scope().custody_id,
                )?;
                if &ready != custody.scope() {
                    return Err(SessionStoreError::Quarantined);
                }
            }
            terminal
        } else {
            if current.irreversible().funding_authorized
                || !matches!(
                    current.phase(),
                    SessionPhaseV1::TemplatesCommitted
                        | SessionPhaseV1::RefundSigning
                        | SessionPhaseV1::RefundSigned
                )
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            current
        };
        // Every root is the same retained Store, with the same immutable
        // transport identity authority; foreign auxiliary stores cannot mint.
        let parent_roster = self.load_transport_roster(parent_session)?;
        let parent_identities = self.load_transport_identity_binding(parent_session)?;
        require_transport_identity_binding(&parent_roster, &parent_identities)?;
        if parent_roster.chain_id != binding.chain_id
            || parent_roster.participants.len() != 2
            || parent_roster
                .participants
                .iter()
                .enumerate()
                .any(|(index, participant)| participant.participant_id != terms.roster[index].0)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let local = self.authenticate_local_transport_signer_binding(parent_session)?;
        let custody_owner_matches = match custody.scope().role {
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner => {
                local.participant_id == terms.dom_leg.refund_to.0
            }
            XmrRecoveryCustodyRoleV11::PublicCounterparty => {
                local.participant_id == terms.counterparty_leg.refund_to.0
            }
        };
        if !custody_owner_matches {
            return Err(SessionStoreError::InvalidTransition);
        }
        // Both auxiliary rounds sign under the authenticated parent terms.
        // A correct session name cannot excuse a foreign terms transcript.
        for auxiliary in [sessions.cancel_session, sessions.compensation_session] {
            if self.load_session_locked(auxiliary)?.terms_hash() != terms_hash {
                return Err(SessionStoreError::Quarantined);
            }
        }
        let cancel = self.audit_xmr_plain_auxiliary_round_v11(
            &parent_roster,
            sessions.cancel_session,
            graph.cancel_bytes(),
        )?;
        let compensation = self.audit_xmr_plain_auxiliary_round_v11(
            &parent_roster,
            sessions.compensation_session,
            graph.punish_bytes(),
        )?;
        let role_digest = role.digest().map_err(|_| SessionStoreError::Canonical)?;
        let mut bytes = Vec::new();
        for digest in [
            binding.chain_id,
            parent_session,
            terms_hash,
            *parent.digest(),
            role_digest,
            *graph.graph_digest(),
            custody.scope().custody_id,
            sessions.cancel_session,
            sessions.compensation_session,
            cancel,
            compensation,
        ] {
            bytes.extend_from_slice(&digest);
        }
        Ok(VerifiedXmrOrdinaryRecoveryRoundsV11 {
            parent_session,
            parent_terms_hash: terms_hash,
            parent_record_digest: *parent.digest(),
            role_digest,
            graph_digest: *graph.graph_digest(),
            custody_id: custody.scope().custody_id,
            cancel_session: sessions.cancel_session,
            compensation_session: sessions.compensation_session,
            cancel_round_digest: cancel,
            compensation_round_digest: compensation,
            scope_digest: tagged_hash("DOM-INTEROP/XMR-ORDINARY-RECOVERY-ROUNDS/V11\0", &bytes),
            open_instance_id: self.open_instance_id,
        })
    }

    /// Re-audit retained custody and both same-owner histories, requiring the
    /// exact process-local token scope. A restarted process obtains a fresh
    /// audit through `audit_xmr_ordinary_recovery_rounds_v11`; it never restores
    /// this token from caller bytes or a digest alone.
    pub fn revalidate_xmr_ordinary_recovery_rounds_v11(
        &self,
        audited: &VerifiedXmrOrdinaryRecoveryRoundsV11,
        role: &FinalClaimRoleBindingV1,
        graph: &VerifiedXmrRecoveryGraphV11,
        policy: &ValidatedXmrCompensationPolicyV11,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<(), SessionStoreError> {
        if audited.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::InvalidTransition);
        }
        let fresh = self.audit_xmr_ordinary_recovery_rounds_v11(
            role,
            graph,
            policy,
            custody,
            XmrOrdinaryRecoveryRoundSessionsV11 {
                cancel_session: audited.cancel_session,
                compensation_session: audited.compensation_session,
            },
        )?;
        if fresh.scope_digest != audited.scope_digest {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    pub(super) fn audit_xmr_plain_auxiliary_round_v11(
        &self,
        parent_roster: &TransportRosterRecordV1,
        auxiliary_session: [u8; 32],
        expected_transaction: &[u8],
    ) -> Result<[u8; 32], SessionStoreError> {
        if self
            .graph_signing_edge_for_purpose_v23(auxiliary_session, PurposeV1::Refund)?
            .is_some()
        {
            return self.audit_graph_plain_auxiliary_round_v23(
                parent_roster,
                auxiliary_session,
                expected_transaction,
            );
        }
        let current = self.load_session_locked(auxiliary_session)?;
        if current.irreversible().funding_authorized
            || current.phase() != SessionPhaseV1::RefundSigned
            || self.funding_gate_exists(auxiliary_session)?
            || self.m8_funding_gate_v2_exists(auxiliary_session)?
            || self.m8_funding_gate_exists(auxiliary_session)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(auxiliary_session)?;
        if roster.chain_id != parent_roster.chain_id
            || roster.participants.len() != parent_roster.participants.len()
            || roster
                .participants
                .iter()
                .zip(&parent_roster.participants)
                .any(|(actual, expected)| {
                    actual.participant_id != expected.participant_id
                        || actual.identity_key != expected.identity_key
                        || actual.direction != expected.direction
                })
        {
            return Err(SessionStoreError::Quarantined);
        }
        let retained = self.load_operational_final_refund_v2(auxiliary_session)?;
        let derived = self.derive_completed_operational_final_refund_v2_at_terminal(
            &parent_roster.chain_id,
            auxiliary_session,
            retained.terminal_revision,
        )?;
        let reconstructed = OperationalFinalRefundRecordV2::new(derived)?;
        if reconstructed.bytes != retained.bytes
            || retained.exact_transaction_bytes != expected_transaction
            || retained.terms_hash != current.terms_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        // Reconstruct the retained ordinary signature record against its exact
        // native nonce/partial transcript, without issuing any transport.
        self.authenticate_operational_final_refund_v2_at_terminal(
            auxiliary_session,
            retained.terminal_revision,
        )?;
        Ok(retained.digest)
    }
}

fn require_distinct_recovery_sessions(
    parent: [u8; 32],
    cancel: [u8; 32],
    compensation: [u8; 32],
) -> Result<(), SessionStoreError> {
    if [parent, cancel, compensation].contains(&[0; 32])
        || parent == cancel
        || parent == compensation
        || cancel == compensation
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    assert_not_impl_any!(VerifiedXmrOrdinaryRecoveryRoundsV11: Clone, Copy, core::fmt::Debug);
    #[test]
    fn a_parent_plain_refund_or_one_reused_round_cannot_stand_for_two_recovery_rounds() {
        assert!(require_distinct_recovery_sessions([1; 32], [2; 32], [3; 32]).is_ok());
        for (parent, cancel, compensation) in [
            ([1; 32], [1; 32], [3; 32]),
            ([1; 32], [2; 32], [1; 32]),
            ([1; 32], [2; 32], [2; 32]),
            ([1; 32], [0; 32], [3; 32]),
        ] {
            assert!(require_distinct_recovery_sessions(parent, cancel, compensation).is_err());
        }
    }
}

fn require_exact_recovery_sessions_v23(
    parent: [u8; 32],
    expected: ([u8; 32], [u8; 32]),
    sessions: &XmrOrdinaryRecoveryRoundSessionsV11,
) -> Result<(), SessionStoreError> {
    require_distinct_recovery_sessions(
        parent,
        sessions.cancel_session,
        sessions.compensation_session,
    )?;
    if (sessions.cancel_session, sessions.compensation_session) != expected {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}

#[cfg(test)]
mod v23_tests {
    use super::*;
    #[test]
    fn distinct_but_foreign_or_swapped_auxiliary_ids_are_refused() {
        let expected = ([2; 32], [3; 32]);
        assert!(require_exact_recovery_sessions_v23(
            [1; 32],
            expected,
            &XmrOrdinaryRecoveryRoundSessionsV11 {
                cancel_session: expected.0,
                compensation_session: expected.1,
            }
        )
        .is_ok());
        for (cancel, compensation) in [
            ([4; 32], [3; 32]),
            ([2; 32], [4; 32]),
            ([3; 32], [2; 32]),
            ([2; 32], [2; 32]),
            ([1; 32], [3; 32]),
            ([0; 32], [3; 32]),
        ] {
            assert!(require_exact_recovery_sessions_v23(
                [1; 32],
                expected,
                &XmrOrdinaryRecoveryRoundSessionsV11 {
                    cancel_session: cancel,
                    compensation_session: compensation,
                }
            )
            .is_err());
        }
    }
}
