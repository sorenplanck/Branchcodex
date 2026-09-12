//! Late public DOMRefund binding from retained native signing ancestry.
//! No new durable format: the existing RefundAdaptor origin is authoritative.
use super::*;

#[derive(PartialEq, Eq)]
struct RefundTemplateScopeV23 {
    chain: TrustedChainIdV1,
    route: [u8; 32],
    session: [u8; 32],
    terms: [u8; 32],
    graph_proposal: [u8; 32],
    refund_template: [u8; 32],
    claim_template: [u8; 32],
    refund_point: [u8; 33],
    participants: [[u8; 32]; 2],
    origin: [u8; 32],
}

/// Same-open Store proof that the exact public DOMRefund template and U were
/// reconstructed from canonical C/D, offers, terms, identities and BOTH signed
/// graph commitments. This is not a signature, executable custody, a funding
/// grant, a sweep capability, or proof that a counterparty paid anything.
/// No public constructor, serializer, clone, or conversion into signing grant.
pub struct VerifiedXmrRefundTemplateBindingV23 {
    open_instance_id: [u8; 32],
    scope: RefundTemplateScopeV23,
}

impl VerifiedXmrRefundTemplateBindingV23 {
    /// Chain provenance supplied to and authenticated by this Store opening.
    pub fn trusted_chain_id(&self) -> TrustedChainIdV1 {
        self.scope.chain
    }
    /// Route committed by the native graph origin.
    pub fn route_id(&self) -> [u8; 32] {
        self.scope.route
    }
    /// Parent session of the U-adaptor refund, never a derived Cancel/Comp session.
    pub fn session_id(&self) -> [u8; 32] {
        self.scope.session
    }
    /// Exact immutable settlement terms digest.
    pub fn terms_hash(&self) -> [u8; 32] {
        self.scope.terms
    }
    /// Unsigned graph proposal committed by two authenticated 0x18 messages.
    /// Deliberately NOT the digest of the later fully signed recovery graph.
    pub fn graph_proposal_digest(&self) -> [u8; 32] {
        self.scope.graph_proposal
    }
    /// Hash of the actual canonical DOMRefund transaction template spending D.
    pub fn refund_template_hash(&self) -> [u8; 32] {
        self.scope.refund_template
    }
    /// Canonical DOMClaim template from the same bilateral C/D graph proposal.
    /// Public binding only: no Claim signature or exposure authorization.
    pub fn claim_template_hash(&self) -> [u8; 32] {
        self.scope.claim_template
    }
    /// Verified U adaptor point of that exact template's native signing origin.
    pub fn refund_adaptor_point(&self) -> [u8; 33] {
        self.scope.refund_point
    }
    /// Native signing roster's two distinct identity owners, in roster order.
    pub fn participant_ids(&self) -> [[u8; 32]; 2] {
        self.scope.participants
    }
    /// Immutable native origin digest, including individual signing keys and
    /// identity directions; public data only, never a key-derivation seed.
    pub fn origin_digest(&self) -> [u8; 32] {
        self.scope.origin
    }
}

impl ContractsSessionStoreV1 {
    /// Retain the existing native U origin, then read its public late binding.
    /// First origin creation is permitted only by its existing unchanged
    /// agreement-head gate. Historical replay is allowed only when that exact
    /// origin already exists; a later missing origin is never recreated here.
    pub fn prepare_xmr_refund_template_binding_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<VerifiedXmrRefundTemplateBindingV23, SessionStoreError> {
        self.retain_xmr_graph_signing_origin_v23(
            chain,
            route,
            session,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        self.resume_xmr_refund_template_binding_v23(chain, route, session)
    }

    /// Read only: require the durable origin and reconstruct/authenticate all
    /// its ancestry. Never create an origin, session, signature or journal.
    pub fn resume_xmr_refund_template_binding_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<VerifiedXmrRefundTemplateBindingV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let scope = self.xmr_refund_template_scope_locked_v23(chain, route, session)?;
        Ok(VerifiedXmrRefundTemplateBindingV23 {
            open_instance_id: self.open_instance_id,
            scope,
        })
    }

    /// Read only: reject a token from another Store opening, and reauthenticate
    /// the durable native origin and its entire graph/transport ancestry.
    /// Reopening requires a fresh readback token, never deserializing this one.
    pub fn revalidate_xmr_refund_template_binding_v23(
        &self,
        binding: &VerifiedXmrRefundTemplateBindingV23,
    ) -> Result<(), SessionStoreError> {
        if binding.open_instance_id != self.open_instance_id {
            return Err(SessionStoreError::Conflict);
        }
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let expected = self.xmr_refund_template_scope_locked_v23(
            binding.scope.chain,
            binding.scope.route,
            binding.scope.session,
        )?;
        if expected != binding.scope {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    fn xmr_refund_template_scope_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<RefundTemplateScopeV23, SessionStoreError> {
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        // This method loads the retained bytes, verifies them against full
        // historical reconstruction, and requires precisely two distinct
        // authenticated commitments at the original agreement revision.
        let origin = self.authenticate_xmr_graph_signing_origin_v23(
            session,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        )?;
        if origin.chain != chain
            || origin.route != route
            || origin.parent != session
            || origin.session != session
            || origin.purpose != PurposeV1::RefundAdaptor
            || origin.roster.entries().len() != 2
        {
            return Err(SessionStoreError::Conflict);
        }
        let participants = [
            *origin.roster.entries()[0].participant_id(),
            *origin.roster.entries()[1].participant_id(),
        ];
        if participants[0] == participants[1] {
            return Err(SessionStoreError::Conflict);
        }
        let (_, refund_template) = dom_adaptor::canonical_template_v1(&origin.template)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let refund_point = origin
            .adaptor
            .as_ref()
            .ok_or(SessionStoreError::Conflict)?
            .to_compressed_bytes();
        // Context was already validated by origin authentication above. Its
        // proposal binding is the same one rebuilt from the real offers.
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        if context.chain != *chain.as_bytes()
            || context.route != route
            || context.session != session
            || context.terms != origin.terms
        {
            return Err(SessionStoreError::Conflict);
        }
        let (templates, keys) =
            self.reconstruct_xmr_graph_evidence_core_v23(chain, route, session, false)?;
        if keys
            .proposal()
            .map_err(|_| SessionStoreError::Conflict)?
            .digest()
            != context.bindings[5]
            || templates.binding().session_id != session
            || templates.binding().terms_hash != origin.terms
        {
            return Err(SessionStoreError::Conflict);
        }
        let (_, claim_template) = dom_adaptor::canonical_template_v1(templates.claim())
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        Ok(RefundTemplateScopeV23 {
            chain,
            route,
            session,
            terms: origin.terms,
            graph_proposal: context.bindings[5],
            refund_template,
            claim_template,
            refund_point,
            participants,
            origin: origin.digest,
        })
    }
}
