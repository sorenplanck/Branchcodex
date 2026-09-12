//! Native bounded recovery evidence is not a publicly signed U refund.
use super::*;

impl BoundDomRefundFaceV1 {
    pub(super) fn verify_native_xmr_refund_v23(
        &self,
    ) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
        let binding = self.inner.authority.binding();
        let ready = self
            .inner
            .authority
            .native_xmr_refund_readiness_v23()
            .map_err(map_dom_error)?
            .ok_or(AuthorityRefusalV1::Unavailable)?;
        if ready.chain_id() != &binding.chain_id()
            || ready.session_id() != &binding.session_id()
            || ready.terms_hash() != &binding.terms_digest()
            || ready.graph_digest() == &ZERO_DIGEST
            || ready.readiness_digest() == &ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let evidence_digest = digest_parts(
            DOM_XMR_NATIVE_FACE_DOMAIN_V23,
            &[
                &self.static_digest,
                ready.graph_digest(),
                ready.readiness_digest(),
            ],
        )?;
        Ok(FaceEvidenceV1 {
            kind: 1,
            route_id: binding.route_id(),
            settlement_id: self.settlement_id,
            session_id: binding.session_id(),
            terms_digest: binding.terms_digest(),
            chain_digest: binding.chain_id(),
            deployment_digest: binding.deployment_digest(),
            // These are graph/custody commitments, never a fabricated final txid
            // or bytes revealing U. The V23 domain distinguishes the protocol.
            primary_artifact_digest: *ready.graph_digest(),
            secondary_artifact_digest: *ready.readiness_digest(),
            evidence_digest,
        })
    }
}
