//! Native recovery readiness without publishing the private U refund.
use super::*;

/// Authenticated native graph and local encrypted custody readiness.
/// This is neither a final refund transaction nor a funding/exposure grant.
/// No raw constructor, codec or conversion to legacy final-refund transport.
pub struct VerifiedXmrRefundReadinessV23 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    graph_digest: [u8; 32],
    readiness_digest: [u8; 32],
}

impl VerifiedXmrRefundReadinessV23 {
    /// Exact authenticated DOM chain.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }
    /// Native session whose recovery transcripts were authenticated.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Exact signed terms, including the negotiated bounded-availability policy.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }
    /// Public recovery graph commitment, not the hash of a final U transaction.
    pub const fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }
    /// Domain-separated commitment to native readiness and actual local custody.
    pub const fn readiness_digest(&self) -> &[u8; 32] {
        &self.readiness_digest
    }
}

impl ContractsSessionStoreV1 {
    /// Verify readiness before funding without extracting or publishing U.
    /// Funding separately requires both Ready votes and its live F7 window.
    pub fn verify_xmr_refund_readiness_v23(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<VerifiedXmrRefundReadinessV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        // Ancestry authentication above replays the actual native C/D, Cancel,
        // U and compensation scopes. The inventory disallows missing journals.
        self.audit_f7_artifact_inventory_v12()?;
        self.validate_xmr_recovery_attachment_locked_v23(&gate, custody)?;
        // Reopen/authenticate the encrypted graph through its existing owner.
        // PrivateRefundOwner's revalidation also requires its private final U;
        // PublicCounterparty retains only the graph and ordinary compensation.
        custody
            .with_graph(|graph| {
                if graph.graph_digest() != &gate.graph_digest
                    || graph.binding().chain_id != gate.chain_id
                    || graph.binding().session_id != gate.session_id
                    || graph.binding().terms_hash != gate.terms_hash
                {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(())
            })
            .map_err(|_| SessionStoreError::Quarantined)??;
        let mut bytes = Vec::new();
        for hash in [
            gate.digest,
            gate.ready_digest,
            gate.graph_digest,
            gate.custody_id,
            gate.chain_id,
            gate.session_id,
            gate.terms_hash,
        ] {
            bytes.extend_from_slice(&hash);
        }
        let readiness_digest =
            *dom_crypto::blake2b_256_tagged("DOM-INTEROP/XMR-NATIVE-REFUND-READINESS/V23", &bytes)
                .as_bytes();
        Ok(VerifiedXmrRefundReadinessV23 {
            chain_id: gate.chain_id,
            session_id: gate.session_id,
            terms_hash: gate.terms_hash,
            graph_digest: gate.graph_digest,
            readiness_digest,
        })
    }
}
