//! Immutable starting context for the two future graph-commit messages.
//! This record is not a signed agreement or outbound signing request.
use super::*;

pub(crate) const COMMIT_CONTEXT_SUFFIX_V23: &str = ".xmr-graph-commit-context-v23";
pub(crate) const COMMIT_CONTEXT_MAGIC_V23: &[u8; 8] = b"DXGCCT23";
const LEN: usize = 368;
const DOMAIN: &str = "DOM:xmr-graph-commit-context:v23";

pub(super) struct Context {
    pub(super) chain: [u8; 32],
    pub(super) route: [u8; 32],
    pub(super) session: [u8; 32],
    pub(super) terms: [u8; 32],
    pub(super) revision: u64,
    // Starting record, transcript, identity binding, roster, evidence, proposal.
    pub(super) bindings: [[u8; 32]; 6],
}

impl Context {
    pub(super) fn digest(&self) -> [u8; 32] {
        tagged_hash(DOMAIN, &self.encode()[..336])
    }

    fn encode(&self) -> [u8; LEN] {
        let mut bytes = [0; LEN];
        bytes[..8].copy_from_slice(COMMIT_CONTEXT_MAGIC_V23);
        for (index, field) in [self.chain, self.route, self.session, self.terms]
            .iter()
            .enumerate()
        {
            bytes[8 + index * 32..40 + index * 32].copy_from_slice(field);
        }
        bytes[136..144].copy_from_slice(&self.revision.to_le_bytes());
        for (index, field) in self.bindings.iter().enumerate() {
            bytes[144 + index * 32..176 + index * 32].copy_from_slice(field);
        }
        let hash = tagged_hash(DOMAIN, &bytes[..336]);
        bytes[336..].copy_from_slice(&hash);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != LEN
            || &bytes[..8] != COMMIT_CONTEXT_MAGIC_V23
            || tagged_hash(DOMAIN, &bytes[..336]) != bytes[336..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut bindings = [[0; 32]; 6];
        for (index, field) in bindings.iter_mut().enumerate() {
            *field = copy_array(&bytes[144 + index * 32..176 + index * 32])?;
        }
        let context = Self {
            chain: copy_array(&bytes[8..40])?,
            route: copy_array(&bytes[40..72])?,
            session: copy_array(&bytes[72..104])?,
            terms: copy_array(&bytes[104..136])?,
            revision: u64::from_le_bytes(copy_array(&bytes[136..144])?),
            bindings,
        };
        if [context.chain, context.route, context.session, context.terms].contains(&[0; 32])
            || context.bindings.contains(&[0; 32])
            || context.revision != 17
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(context)
    }
}

impl ContractsSessionStoreV1 {
    /// Freeze the exact start of a graph-commit exchange after reconstructing
    /// all retained public evidence. No message, identity signature, nonce or
    /// funding authority is issued. Reissue accepts only identical context.
    pub fn freeze_xmr_graph_commit_context_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let (_, keys) = self.reconstruct_xmr_graph_under_lock_v23(chain, route, session)?;
        let current = self.load_session_locked(session)?;
        if current.revision() != 17 || current.phase() != SessionPhaseV1::OutputFinalized {
            return Err(SessionStoreError::InvalidTransition);
        }
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        let proposal = keys
            .proposal()
            .map_err(|_| SessionStoreError::Conflict)?
            .digest();
        let evidence_digest = self.xmr_graph_evidence_digest_v23(session)?;
        let context = Context {
            chain: *chain.as_bytes(),
            route,
            session,
            terms: current.terms_hash(),
            revision: current.revision(),
            bindings: [
                tagged_hash(DOMAIN, current.as_bytes()),
                current.transcript_hash(),
                tagged_hash(DOMAIN, &identities.bytes),
                tagged_hash(DOMAIN, &roster.bytes),
                evidence_digest,
                proposal,
            ],
        };
        let bytes = context.encode();
        Context::decode(&bytes)?;
        let name = format!("{}{COMMIT_CONTEXT_SUFFIX_V23}", hex_lower(&session));
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)
        {
            Ok(old) if old != bytes => return Err(SessionStoreError::Conflict),
            Ok(_) => {}
            Err(LinuxCapabilityError::NotFound) => {
                publish_immutable(
                    &self.rosters,
                    &format!(".{name}.staging"),
                    &name,
                    &bytes,
                    LEN,
                )?;
            }
            Err(error) => return Err(error.into()),
        }
        self.audit_xmr_graph_commit_context_v23(session)?;
        Ok(proposal)
    }

    // Decode only: callers must authenticate context/evidence before admission.
    pub(super) fn load_xmr_graph_commit_context_v23(
        &self,
        session: [u8; 32],
    ) -> Result<Context, SessionStoreError> {
        let name = format!("{}{COMMIT_CONTEXT_SUFFIX_V23}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)?;
        Context::decode(&bytes)
    }

    // Historical provenance/integrity audit, not graph-commit admission.
    pub(crate) fn audit_xmr_graph_commit_context_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let context = self.load_xmr_graph_commit_context_v23(session)?;
        self.require_xmr_graph_context_evidence_v23(
            session,
            context.chain,
            context.route,
            context.terms,
            context.bindings[5],
        )?;
        let initial = self.load_session_revision(session, context.revision)?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        let identities = self.load_transport_identity_binding(session)?;
        require_transport_identity_binding(&roster, &identities)?;
        if context.session != session
            || context.chain != roster.chain_id
            || context.terms != current.terms_hash()
            || context.terms != initial.terms_hash()
            || initial.phase() != SessionPhaseV1::OutputFinalized
            || initial.irreversible().funding_authorized
            || context.bindings[0] != tagged_hash(DOMAIN, initial.as_bytes())
            || context.bindings[1] != initial.transcript_hash()
            || context.bindings[2] != tagged_hash(DOMAIN, &identities.bytes)
            || context.bindings[3] != tagged_hash(DOMAIN, &roster.bytes)
            || context.bindings[4] != self.xmr_graph_evidence_digest_v23(session)?
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v23_graph_commit_context_binds_exact_start_and_all_six_digests(
    ) -> Result<(), SessionStoreError> {
        let context = Context {
            chain: [1; 32],
            route: [2; 32],
            session: [3; 32],
            terms: [4; 32],
            revision: 17,
            bindings: [[5; 32]; 6],
        };
        let bytes = context.encode();
        assert_eq!(Context::decode(&bytes)?.encode(), bytes);
        for length in 0..LEN {
            assert!(Context::decode(&bytes[..length]).is_err());
        }
        for index in 0..LEN {
            let mut altered = bytes;
            altered[index] ^= 1;
            assert!(Context::decode(&altered).is_err());
        }
        for revision in [0, 16, 18, u64::MAX] {
            let mut altered = Context::decode(&bytes)?;
            altered.revision = revision;
            assert!(Context::decode(&altered.encode()).is_err());
        }
        for index in 0..6 {
            let mut altered = Context::decode(&bytes)?;
            altered.bindings[index] = [0; 32];
            assert!(Context::decode(&altered.encode()).is_err());
        }
        Ok(())
    }
}
