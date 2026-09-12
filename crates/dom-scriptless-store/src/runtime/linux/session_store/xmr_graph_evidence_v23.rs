//! Public reconstruction inputs, never a peer agreement or signing authority.
use super::*;

pub(crate) const EVIDENCE_SUFFIX_V23: &str = ".xmr-graph-evidence-v23";
pub(crate) const EVIDENCE_MAGIC_V23: &[u8; 8] = b"DXGEVI23";
const MAX: usize = 224 * 1024;
const LIMITS: [usize; 6] = [8192, 1024, 32768, 32768, 65536, 65536];
const HEADER: usize = 8 + 8 + 33 + 704;
const DOMAIN: &str = "DOM:public-xmr-graph-evidence:v23";

// All fields remain untrusted after decoding. The owning session supplies scope.
pub(super) struct Evidence {
    pub(super) tip: u64,
    pub(super) refund_point: [u8; 33],
    pub(super) proposal: [u8; 704],
    // Canonical terms, policy, offers in terms order, C journal, D journal.
    pub(super) fields: [Vec<u8>; 6],
}

impl Evidence {
    pub(super) fn encode(&self) -> Result<Vec<u8>, SessionStoreError> {
        let mut bytes = EVIDENCE_MAGIC_V23.to_vec();
        bytes.extend_from_slice(&self.tip.to_le_bytes());
        bytes.extend_from_slice(&self.refund_point);
        bytes.extend_from_slice(&self.proposal);
        for (field, limit) in self.fields.iter().zip(LIMITS) {
            if field.is_empty() || field.len() > limit {
                return Err(SessionStoreError::CapacityExceeded);
            }
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
        let checksum = tagged_hash(DOMAIN, &bytes);
        bytes.extend_from_slice(&checksum);
        if bytes.len() > MAX {
            return Err(SessionStoreError::CapacityExceeded);
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < HEADER + 6 * 5 + 32
            || bytes.len() > MAX
            || bytes.get(..8) != Some(EVIDENCE_MAGIC_V23.as_slice())
        {
            return Err(SessionStoreError::Canonical);
        }
        let body = &bytes[..bytes.len() - 32];
        if tagged_hash(DOMAIN, body) != bytes[body.len()..] {
            return Err(SessionStoreError::Canonical);
        }
        let mut position = HEADER;
        let mut fields = Vec::with_capacity(6);
        for limit in LIMITS {
            let end = position
                .checked_add(4)
                .ok_or(SessionStoreError::Canonical)?;
            let length = u32::from_le_bytes(copy_array(
                body.get(position..end)
                    .ok_or(SessionStoreError::Canonical)?,
            )?) as usize;
            if length == 0 || length > limit {
                return Err(SessionStoreError::Canonical);
            }
            position = end
                .checked_add(length)
                .ok_or(SessionStoreError::Canonical)?;
            fields.push(
                body.get(end..position)
                    .ok_or(SessionStoreError::Canonical)?
                    .to_vec(),
            );
        }
        if position != body.len() {
            return Err(SessionStoreError::Canonical);
        }
        Ok(Self {
            tip: u64::from_le_bytes(copy_array(&body[8..16])?),
            refund_point: copy_array(&body[16..49])?,
            proposal: copy_array(&body[49..HEADER])?,
            fields: fields
                .try_into()
                .map_err(|_| SessionStoreError::Canonical)?,
        })
    }
}

impl ContractsSessionStoreV1 {
    // Historical binding only: do not apply the live phase/funding gate here.
    // Full cryptographic reconstruction is still required by signing admission.
    pub(super) fn require_xmr_graph_context_evidence_v23(
        &self,
        session: [u8; 32],
        chain: [u8; 32],
        route: [u8; 32],
        terms: [u8; 32],
        proposal_digest: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let name = format!("{}{EVIDENCE_SUFFIX_V23}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
        let evidence = Evidence::decode(&bytes)?;
        let proposal = &evidence.proposal;
        let mut framed = b"DOM:XMR:graph-proposal:v22\0".to_vec();
        framed.extend_from_slice(proposal);
        if &proposal[..8] != b"DXGP22\0\x01"
            || proposal[8..40] != chain
            || proposal[40..72] != route
            || proposal[72..104] != session
            || proposal[104..136] != terms
            || dom_crypto::blake2b_256(&framed).as_bytes() != &proposal_digest
        {
            return Err(SessionStoreError::Conflict);
        }
        self.audit_xmr_graph_pin_frame_v23(session)?;
        let pin_name = format!("{}{}", hex_lower(&session), super::pin_v23::PIN_SUFFIX_V23);
        let pin = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&pin_name)?, 808)?;
        if pin.get(8..712) != Some(proposal.as_slice()) {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    // Byte binding only, never reconstruction or authentication of agreement.
    pub(super) fn xmr_graph_evidence_digest_v23(
        &self,
        session: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        let name = format!("{}{EVIDENCE_SUFFIX_V23}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
        Evidence::decode(&bytes)?;
        Ok(tagged_hash(DOMAIN, &bytes))
    }

    // Caller holds operation lock and has revalidated the full live graph.
    pub(super) fn persist_xmr_graph_evidence_v23(
        &self,
        session: [u8; 32],
        evidence: &Evidence,
    ) -> Result<(), SessionStoreError> {
        let name = format!("{}{EVIDENCE_SUFFIX_V23}", hex_lower(&session));
        let bytes = evidence.encode()?;
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)
        {
            Ok(old) if old != bytes => return Err(SessionStoreError::Conflict),
            Ok(_) => return Ok(()),
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            &bytes,
            MAX,
        )?;
        let retained = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
        if retained != bytes {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    /// Reconstruct unsigned templates from retained public evidence. The caller
    /// supplies the expected chain, route and owning session independently.
    /// This is not bilateral agreement, native signing admission or funding.
    pub fn reconstruct_retained_xmr_graph_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<
        (
            xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
            xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22,
        ),
        SessionStoreError,
    > {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.reconstruct_xmr_graph_under_lock_v23(chain, route, session)
    }

    // Internal reconstruction for prepared-transport validation. Caller owns
    // the operation lock; this never recursively audits the whole transport.
    // The live phase/funding gate and every graph/proof/pin check remain here.
    pub(crate) fn reconstruct_xmr_graph_under_lock_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<
        (
            xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
            xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22,
        ),
        SessionStoreError,
    > {
        self.reconstruct_xmr_graph_evidence_core_v23(chain, route, session, true)
    }

    // Historical audit yields only a digest, never a live signing capability.
    pub(in super::super) fn audit_historical_xmr_graph_proposal_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        self.audit_xmr_graph_commit_context_v23(session)?;
        let (_, keys) =
            self.reconstruct_xmr_graph_evidence_core_v23(chain, route, session, false)?;
        Ok(keys
            .proposal()
            .map_err(|_| SessionStoreError::Conflict)?
            .digest())
    }

    pub(in super::super) fn reconstruct_xmr_graph_evidence_core_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        session: [u8; 32],
        require_live: bool,
    ) -> Result<
        (
            xmr_refund_policy::graph_builder::XmrRecoveryGraphTemplatesV12,
            xmr_refund_policy::graph_signing_keys_v22::XmrGraphSigningKeysV22,
        ),
        SessionStoreError,
    > {
        let (evidence, roster, revision, terms_hash) = {
            let current = self.load_session_locked(session)?;
            if require_live
                && (current.irreversible().funding_authorized
                    || !matches!(
                        current.phase(),
                        SessionPhaseV1::OutputFinalized | SessionPhaseV1::TemplatesCommitted
                    ))
            {
                return Err(SessionStoreError::InvalidTransition);
            }
            let roster = self.load_transport_roster(session)?;
            let identities = self.load_transport_identity_binding(session)?;
            require_transport_identity_binding(&roster, &identities)?;
            let name = format!("{}{EVIDENCE_SUFFIX_V23}", hex_lower(&session));
            let bytes = self
                .rosters
                .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
            let evidence = Evidence::decode(&bytes)?;
            if roster.chain_id != *chain.as_bytes()
                || route == [0; 32]
                || &evidence.proposal[..8] != b"DXGP22\0\x01"
                || evidence.proposal[8..40] != *chain.as_bytes()
                || evidence.proposal[40..72] != route
                || evidence.proposal[72..104] != session
                || evidence.proposal[104..136] != current.terms_hash()
            {
                return Err(SessionStoreError::Conflict);
            }
            (evidence, roster, current.revision(), current.terms_hash())
        };
        let terms = kaystra_core::SettlementTermsV1::decode(&evidence.fields[0])
            .map_err(|_| SessionStoreError::Canonical)?;
        let policy = xmr_refund_policy::compensation::XmrCompensationPolicyV11::from_bytes(
            &evidence.fields[1],
        )
        .and_then(|policy| policy.validate_for(&terms))
        .map_err(|_| SessionStoreError::Conflict)?;
        if policy.terms_hash() != &terms_hash {
            return Err(SessionStoreError::Conflict);
        }
        let participants = terms.roster.map(|participant| participant.0);
        let directions = super::pin_v23::directions_in_terms_order(
            participants,
            std::array::from_fn(|index| {
                let participant = &roster.participants[index];
                (participant.participant_id, participant.direction)
            }),
        )?;
        let scopes: [_; 2] = std::array::from_fn(|index| {
            xmr_refund_policy::graph_offer_v22::XmrGraphOfferScopeV22 {
                chain: &chain,
                route_id: route,
                participant: participants[index],
                direction: directions[index],
            }
        });
        let decode = |index: usize| {
            xmr_refund_policy::graph_offer_v22::XmrGraphOfferV22::from_bytes(
                &evidence.fields[index + 2],
                &terms,
                &policy,
                &scopes[index],
            )
            .map_err(|_| SessionStoreError::Conflict)
        };
        let offers = [decode(0)?, decode(1)?];
        let public =
            xmr_refund_policy::graph_public_material_v23::XmrGraphPublicMaterialV23::from_offers(
                &terms,
                &policy,
                [&scopes[0], &scopes[1]],
                [&offers[0], &offers[1]],
            )
            .map_err(|_| SessionStoreError::Conflict)?;
        let reconstruct = |index: usize, output_session, value| {
            super::super::xmr_graph_output_journal_v22::XmrGraphOutputJournalV22::decode(
                &evidence.fields[index + 4],
            )?
            .reconstruct(chain, output_session, terms_hash, value, &roster)
        };
        let c = reconstruct(0, session, policy.collateral_noms())?;
        let d = reconstruct(
            1,
            xmr_refund_policy::graph_builder::xmr_cancelled_output_session_v12(&policy),
            policy.cancelled_noms(),
        )?;
        let formed = public
            .form_templates_v23(
                &terms,
                &policy,
                [(c.formation, c.output), (d.formation, d.output)],
                evidence.tip,
                evidence.refund_point,
            )
            .map_err(|_| SessionStoreError::Conflict)?;
        formed
            .1
            .proposal()
            .and_then(|proposal| proposal.require_matches(&evidence.proposal))
            .map_err(|_| SessionStoreError::Conflict)?;
        // The evidence is not allowed to substitute for this owner's local pin.
        let current = self.load_session_locked(session)?;
        if current.revision() != revision
            || current.terms_hash() != terms_hash
            || (require_live && current.irreversible().funding_authorized)
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.audit_xmr_graph_pin_frame_v23(session)?;
        let pin_name = format!("{}{}", hex_lower(&session), super::pin_v23::PIN_SUFFIX_V23);
        let pin = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&pin_name)?, 808)?;
        if pin.get(8..712) != Some(evidence.proposal.as_slice())
            || pin.get(712..744) != Some(c.proof_digest.as_slice())
            || pin.get(744..776) != Some(d.proof_digest.as_slice())
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(formed)
    }

    /// Startup checks framing and ownership only, never authenticates agreement.
    pub(crate) fn audit_xmr_graph_evidence_frame_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let name = format!("{}{EVIDENCE_SUFFIX_V23}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
        let evidence = Evidence::decode(&bytes)?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        if &evidence.proposal[..8] != b"DXGP22\0\x01"
            || evidence.proposal[8..40] != roster.chain_id
            || evidence.proposal[40..72] == [0; 32]
            || evidence.proposal[72..104] != session
            || evidence.proposal[104..136] != current.terms_hash()
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
    fn v23_public_graph_evidence_frame_is_exact_bounded_and_not_authority(
    ) -> Result<(), SessionStoreError> {
        // Deliberately invalid crypto material: decoding is only framing.
        let evidence = Evidence {
            tip: 10,
            refund_point: [3; 33],
            proposal: [4; 704],
            fields: std::array::from_fn(|i| vec![i as u8 + 1; i + 1]),
        };
        let bytes = evidence.encode()?;
        assert_eq!(Evidence::decode(&bytes)?.encode()?, bytes);
        for cut in 0..bytes.len() {
            assert!(Evidence::decode(&bytes[..cut]).is_err());
        }
        for index in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[index] ^= 1;
            assert!(Evidence::decode(&altered).is_err());
        }
        for size in [0u32, 8193, u32::MAX] {
            let mut altered = bytes.clone();
            altered[HEADER..HEADER + 4].copy_from_slice(&size.to_le_bytes());
            let end = altered.len() - 32;
            let checksum = tagged_hash(DOMAIN, &altered[..end]);
            altered[end..].copy_from_slice(&checksum);
            assert!(Evidence::decode(&altered).is_err());
        }
        for index in 0..6 {
            let mut altered = Evidence::decode(&bytes)?;
            altered.fields[index] = vec![1; LIMITS[index] + 1];
            assert!(altered.encode().is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Evidence::decode(&trailing).is_err());
        Ok(())
    }
}
