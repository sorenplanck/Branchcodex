//! Native output provenance checks retained independently of retired graph admission.
//! This is not a DSC1 signing request or a durable funding authorization.
use super::*;
#[path = "xmr_graph_message_collect_v25.rs"]
mod message_collect_v25;
#[path = "public_signing_semantics_cache_v25.rs"]
pub(super) mod public_signing_semantics_cache_v25;

#[path = "xmr_refund_template_binding_v23.rs"]
mod refund_template_binding_v23;
pub use refund_template_binding_v23::VerifiedXmrRefundTemplateBindingV23;
#[path = "xmr_graph_completed_reconstruction_v23.rs"]
mod completed_reconstruction_v23;
#[path = "xmr_graph_custody_provisioning_v23.rs"]
mod custody_provisioning_v23;
pub(super) use custody_provisioning_v23::parse_xmr_graph_custody_provisioning_name_v23;
pub use custody_provisioning_v23::{
    PreparedXmrGraphCustodyProvisioningV23, XmrGraphCustodyProvisioningStateV23,
};
#[path = "xmr_graph_commit_context_v23.rs"]
mod commit_context_v23;
#[path = "xmr_graph_commit_issuance_v23.rs"]
mod commit_issuance_v23;
#[path = "xmr_graph_commit_transport_v23.rs"]
mod commit_transport_v23;
pub use commit_issuance_v23::PreparedXmrGraphCommitIngressV23;
#[path = "xmr_graph_commit_authority_v23.rs"]
mod commit_authority_v23;
#[path = "xmr_graph_resource_provisioning_v23.rs"]
mod resource_provisioning_v23;
#[path = "xmr_graph_signing_origin_v23.rs"]
mod signing_origin_v23;
#[path = "xmr_graph_signing_session_v23.rs"]
mod signing_session_v23;
pub(super) use resource_provisioning_v23::parse_xmr_graph_resource_name_v23;
pub use resource_provisioning_v23::{
    PreparedXmrGraphResourceV23, XmrGraphResourceKindV23, XmrGraphResourceStateV23,
};
#[path = "xmr_graph_plain_round_custody_v23.rs"]
mod plain_round_custody_v23;
#[path = "xmr_graph_signing_authority_v23.rs"]
mod signing_authority_v23;
#[path = "xmr_graph_signing_round_v23.rs"]
mod signing_round_v23;
#[path = "xmr_graph_signing_transport_v23.rs"]
mod signing_transport_v23;
#[cfg(test)]
pub(crate) use commit_context_v23::COMMIT_CONTEXT_MAGIC_V23;
pub(crate) use commit_context_v23::COMMIT_CONTEXT_SUFFIX_V23;
pub(super) use signing_origin_v23::parse_xmr_graph_signing_origin_name_v23;
pub use signing_origin_v23::XmrGraphRecoverySigningEdgeV23;
pub(super) use signing_session_v23::parse_xmr_graph_signing_session_name_v23;
pub use signing_transport_v23::PreparedXmrGraphSigningIngressV23;
#[path = "xmr_graph_evidence_v23.rs"]
mod evidence_v23;
#[cfg(test)]
pub(crate) use evidence_v23::EVIDENCE_MAGIC_V23;
pub(crate) use evidence_v23::EVIDENCE_SUFFIX_V23;
#[path = "xmr_graph_pin_v23.rs"]
mod pin_v23;
#[cfg(test)]
pub(super) use pin_v23::PIN_MAGIC_V23;
pub(super) use pin_v23::PIN_SUFFIX_V23;
struct GraphOutputFactsV22 {
    roster: TransportRosterRecordV1,
    identities: TransportIdentityBindingRecordV1,
    proof_digest: [u8; 32],
    journal: Vec<u8>,
    reconstructed: super::xmr_graph_output_journal_v22::ReconstructedXmrGraphOutputV22,
}

impl ContractsSessionStoreV1 {
    #[cfg(test)]
    pub(super) fn audit_graph_output_for_test_v22(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        value: u64,
        expected: &dom_consensus::TransactionOutput,
    ) -> Result<(), SessionStoreError> {
        self.audit_graph_output_v22(chain, session, terms, value, expected)
            .map(|_| ())
    }

    fn audit_graph_output_v22(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: [u8; 32],
        value: u64,
        expected: &dom_consensus::TransactionOutput,
    ) -> Result<GraphOutputFactsV22, SessionStoreError> {
        let (statement, capsule, roster, identities) = {
            let _guard = self.operation_lock()?;
            self.audit_transport()?;
            let current = self.load_session_locked(session)?;
            if current.terms_hash() != terms
                || current.irreversible().funding_authorized
                || matches!(
                    current.phase(),
                    SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
                )
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let roster = self.load_transport_roster(session)?;
            let identities = self.load_transport_identity_binding(session)?;
            require_transport_identity_binding(&roster, &identities)?;
            let bp = self.load_bp_transport_authority(session)?;
            (bp.statement, bp.recovery_capsule, roster, identities)
        };
        let frozen = self
            .retained_shared_output_formation_v22(chain, terms, value, &statement, &capsule)?
            .ok_or(SessionStoreError::InvalidTransition)?;
        let proof = self
            .completed_operational_bp_proof_v16(chain, session, terms, &statement, &capsule)?
            .ok_or(SessionStoreError::InvalidTransition)?;
        let proof_digest = proof.proof_digest();
        let output = dom_consensus::TransactionOutput::with_recovery_capsule(
            dom_crypto::pedersen::Commitment::from_compressed_bytes(frozen.aggregate_commitment())
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?,
            proof.into_proof().as_bytes().to_vec(),
            &capsule,
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        if &output != expected {
            return Err(SessionStoreError::Conflict);
        }
        // A concurrent terminal transition between the separate native audits
        // must not leave apparently live evidence behind. This is still only
        // a snapshot, never a substitute for signing-time revalidation.
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let current = self.load_session_locked(session)?;
        if current.irreversible().funding_authorized
            || matches!(
                current.phase(),
                SessionPhaseV1::Aborted | SessionPhaseV1::FailedClosed
            )
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let journal =
            super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::capture_locked(
                self, session,
            )?
            .encode()?;
        let decoded =
            super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(&journal)?;
        let reconstructed = decoded.reconstruct(chain, session, terms, value, &roster)?;
        if reconstructed.proof_digest != proof_digest || reconstructed.output.output() != expected {
            return Err(SessionStoreError::Conflict);
        }
        Ok(GraphOutputFactsV22 {
            roster,
            identities,
            proof_digest,
            journal,
            reconstructed,
        })
    }
}
