//! Immutable local proposal pin, not bilateral agreement or signing authority.
//! Every caller reconstructs the native graph and re-audits both live owners.
use super::*;
use xmr_refund_policy::{
    graph_builder::XmrRecoveryGraphTemplatesV12, graph_signing_keys_v22::XmrGraphSigningKeysV22,
};

pub(crate) const PIN_SUFFIX_V23: &str = ".xmr-graph-pin-v23";
pub(crate) const PIN_MAGIC_V23: &[u8; 8] = b"DXGPIN23";
const LEN: usize = 808;
const DOMAIN: &str = "DOM:local-xmr-graph-pin:v23";

// Transport records use direction order; graph keys use authenticated terms order.
pub(super) fn directions_in_terms_order(
    participants: [[u8; 32]; 2],
    retained: [([u8; 32], DirectionV1); 2],
) -> Result<[DirectionV1; 2], SessionStoreError> {
    if participants.contains(&[0; 32])
        || participants[0] == participants[1]
        || retained[0].1 == retained[1].1
    {
        return Err(SessionStoreError::Conflict);
    }
    if participants == [retained[0].0, retained[1].0] {
        Ok([retained[0].1, retained[1].1])
    } else if participants == [retained[1].0, retained[0].0] {
        Ok([retained[1].1, retained[0].1])
    } else {
        Err(SessionStoreError::Conflict)
    }
}

struct Pin {
    proposal: [u8; 704],
    proofs: [[u8; 32]; 2],
}

impl Pin {
    fn bytes(&self) -> [u8; LEN] {
        let mut bytes = [0; LEN];
        bytes[..8].copy_from_slice(PIN_MAGIC_V23);
        bytes[8..712].copy_from_slice(&self.proposal);
        bytes[712..744].copy_from_slice(&self.proofs[0]);
        bytes[744..776].copy_from_slice(&self.proofs[1]);
        let digest = tagged_hash(DOMAIN, &bytes[..776]);
        bytes[776..].copy_from_slice(&digest);
        bytes
    }

    fn require_matches(&self, retained: &[u8]) -> Result<(), SessionStoreError> {
        Self::parse(retained)?;
        if retained != self.bytes() {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    // Integrity/framing only. Decoding never authenticates a peer or a graph.
    fn parse(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != LEN
            || &bytes[..8] != PIN_MAGIC_V23
            || &bytes[8..16] != b"DXGP22\0\x01"
            || tagged_hash(DOMAIN, &bytes[..776]) != bytes[776..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let pin = Self {
            proposal: copy_array(&bytes[8..712])?,
            proofs: [copy_array(&bytes[712..744])?, copy_array(&bytes[744..776])?],
        };
        if pin.proofs.contains(&[0; 32]) || pin.proposal[672..704] == [0; 32] {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(pin)
    }
}

impl ContractsSessionStoreV1 {
    /// Pin a freshly reconstructed V23 graph before any graph agreement.
    /// Repeating exact bytes is idempotent; a changed proposal is a conflict.
    /// This public digest is not an accepted signing session or funding token.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_xmr_graph_proposal_v23(
        &self,
        cancelled_store: &Self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        terms: &kaystra_core::SettlementTermsV1,
        templates: &XmrRecoveryGraphTemplatesV12,
        keys: &XmrGraphSigningKeysV22,
    ) -> Result<[u8; 32], SessionStoreError> {
        let policy = templates.policy();
        if policy
            .policy()
            .validate_for(terms)
            .map_err(|_| SessionStoreError::Conflict)?
            != *policy
        {
            return Err(SessionStoreError::Conflict);
        }
        templates
            .compensation_session_v23()
            .map_err(|_| SessionStoreError::Conflict)?;
        keys.require_graph(templates)
            .map_err(|_| SessionStoreError::Conflict)?;
        keys.require_route(route)
            .map_err(|_| SessionStoreError::Conflict)?;
        let binding = templates.binding();
        let c_output = templates
            .funding()
            .outputs
            .iter()
            .find(|output| output.commitment.as_bytes() == &binding.funding_commitment)
            .ok_or(SessionStoreError::Conflict)?;
        let d_output = templates
            .cancel()
            .outputs
            .first()
            .ok_or(SessionStoreError::Conflict)?;
        let c = self.audit_graph_output_v22(
            chain,
            binding.session_id,
            binding.terms_hash,
            policy.collateral_noms(),
            c_output,
        )?;
        let d = cancelled_store.audit_graph_output_v22(
            chain,
            xmr_refund_policy::graph_builder::xmr_cancelled_output_session_v12(policy),
            binding.terms_hash,
            policy.cancelled_noms(),
            d_output,
        )?;
        if c.roster.participants != d.roster.participants
            || c.identities.references != d.identities.references
        {
            return Err(SessionStoreError::Conflict);
        }
        let participants = terms.roster.map(|participant| participant.0);
        let directions = directions_in_terms_order(
            participants,
            std::array::from_fn(|index| {
                let participant = &c.roster.participants[index];
                (participant.participant_id, participant.direction)
            }),
        )?;
        keys.require_scope(
            &chain,
            binding.session_id,
            binding.terms_hash,
            participants,
            directions,
        )
        .map_err(|_| SessionStoreError::Conflict)?;
        let proposal = keys.proposal().map_err(|_| SessionStoreError::Conflict)?;
        // Reconstruct from canonical offer packets and the independently
        // replayed native journals, not the caller's in-memory key/template
        // pairing. Tip and U remain proposal inputs, not setup/time authority.
        let scopes: [_; 2] = std::array::from_fn(|index| {
            xmr_refund_policy::graph_offer_v22::XmrGraphOfferScopeV22 {
                chain: &chain,
                route_id: route,
                participant: participants[index],
                direction: directions[index],
            }
        });
        let packets = keys.packets();
        let decode = |index: usize| {
            xmr_refund_policy::graph_offer_v22::XmrGraphOfferV22::from_bytes(
                packets[index],
                terms,
                policy,
                &scopes[index],
            )
            .map_err(|_| SessionStoreError::Conflict)
        };
        let offers = [decode(0)?, decode(1)?];
        let public =
            xmr_refund_policy::graph_public_material_v23::XmrGraphPublicMaterialV23::from_offers(
                terms,
                policy,
                [&scopes[0], &scopes[1]],
                [&offers[0], &offers[1]],
            )
            .map_err(|_| SessionStoreError::Conflict)?;
        let (_, reconstructed_keys) = public
            .form_templates_v23(
                terms,
                policy,
                [
                    (c.reconstructed.formation, c.reconstructed.output),
                    (d.reconstructed.formation, d.reconstructed.output),
                ],
                templates.negotiated_tip_v22(),
                binding.refund_adaptor_point,
            )
            .map_err(|_| SessionStoreError::Conflict)?;
        let reconstructed_proposal = reconstructed_keys
            .proposal()
            .map_err(|_| SessionStoreError::Conflict)?;
        if reconstructed_proposal.as_bytes() != proposal.as_bytes() {
            return Err(SessionStoreError::Conflict);
        }
        let evidence = super::evidence_v23::Evidence {
            tip: templates.negotiated_tip_v22(),
            refund_point: binding.refund_adaptor_point,
            proposal: *proposal.as_bytes(),
            fields: [
                terms
                    .canonical_bytes()
                    .map_err(|_| SessionStoreError::Canonical)?,
                policy
                    .policy()
                    .to_bytes()
                    .map_err(|_| SessionStoreError::Canonical)?,
                packets[0].to_vec(),
                packets[1].to_vec(),
                c.journal,
                d.journal,
            ],
        };
        let pin = Pin {
            proposal: *proposal.as_bytes(),
            proofs: [c.proof_digest, d.proof_digest],
        };
        let bytes = pin.bytes();
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let current = self.load_session_locked(binding.session_id)?;
        if current.terms_hash() != binding.terms_hash || current.irreversible().funding_authorized {
            return Err(SessionStoreError::InvalidTransition);
        }
        let name = format!("{}{PIN_SUFFIX_V23}", hex_lower(&binding.session_id));
        if !matches!(
            current.phase(),
            SessionPhaseV1::OutputFinalized | SessionPhaseV1::TemplatesCommitted
        ) {
            // Reopening a signing parent is a read-only historical reissue,
            // never permission to create or repair either immutable artifact.
            // All offers, both BP journals, individual keys and templates were
            // reconstructed above from the trusted typed chain and live owners.
            let retained = self
                .rosters
                .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)?;
            pin.require_matches(&retained)?;
            let evidence_bytes = evidence.encode()?;
            let evidence_name = format!(
                "{}{}",
                hex_lower(&binding.session_id),
                super::evidence_v23::EVIDENCE_SUFFIX_V23
            );
            let retained_evidence = self.rosters.read_bounded_file(
                &ValidatedComponent::registered(&evidence_name)?,
                evidence_bytes.len(),
            )?;
            if retained_evidence != evidence_bytes {
                return Err(SessionStoreError::Conflict);
            }
            self.audit_xmr_graph_pin_frame_v23(binding.session_id)?;
            self.audit_xmr_graph_evidence_frame_v23(binding.session_id)?;
            return Ok(proposal.digest());
        }
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)
        {
            Ok(old) => {
                pin.require_matches(&old)?;
            }
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
        let reread = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)?;
        if reread != bytes {
            return Err(SessionStoreError::Quarantined);
        }
        self.audit_xmr_graph_pin_frame_v23(binding.session_id)?;
        self.persist_xmr_graph_evidence_v23(binding.session_id, &evidence)?;
        self.audit_xmr_graph_evidence_frame_v23(binding.session_id)?;
        Ok(proposal.digest())
    }

    /// Reopen framing/scope check only; never used as a signing authority.
    pub(crate) fn audit_xmr_graph_pin_frame_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let name = format!("{}{PIN_SUFFIX_V23}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)?;
        let pin = Pin::parse(&bytes)?;
        let roster = self.load_transport_roster(session)?;
        let current = self.load_session_locked(session)?;
        if pin.proposal[8..40] != roster.chain_id
            || pin.proposal[40..72] == [0; 32]
            || pin.proposal[72..104] != session
            || pin.proposal[104..136] != current.terms_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v23_local_graph_pin_maps_both_roster_orders_without_changing_roles() {
        use DirectionV1::{Initiator, Responder};
        let a = [1; 32];
        let b = [2; 32];
        for retained in [
            [(a, Initiator), (b, Responder)],
            [(b, Initiator), (a, Responder)],
        ] {
            let ids = [retained[0].0, retained[1].0];
            assert_eq!(
                directions_in_terms_order(ids, retained).unwrap(),
                [Initiator, Responder]
            );
            assert_eq!(
                directions_in_terms_order([ids[1], ids[0]], retained).unwrap(),
                [Responder, Initiator]
            );
            for bad in [
                [a, a],
                [b, b],
                [[0; 32], b],
                [a, [0; 32]],
                [[3; 32], b],
                [a, [3; 32]],
            ] {
                assert!(matches!(
                    directions_in_terms_order(bad, retained),
                    Err(SessionStoreError::Conflict)
                ));
            }
        }
        assert!(directions_in_terms_order([a, b], [(a, Initiator), (a, Responder)]).is_err());
        assert!(directions_in_terms_order([a, b], [(a, Initiator), (b, Initiator)]).is_err());
    }

    #[test]
    fn v23_local_graph_pin_frame_is_exact_and_binds_both_proofs() {
        let mut proposal = [1; 704];
        proposal[..8].copy_from_slice(b"DXGP22\0\x01");
        let pin = Pin {
            proposal,
            proofs: [[2; 32], [3; 32]],
        };
        let bytes = pin.bytes();
        assert_eq!(Pin::parse(&bytes).unwrap().bytes(), bytes);
        for index in 0..LEN {
            let mut bad = bytes;
            bad[index] ^= 1;
            assert!(Pin::parse(&bad).is_err(), "mutation {index}");
        }
        assert!(Pin::parse(&bytes[..LEN - 1]).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(Pin::parse(&extended).is_err());
        assert!(pin.require_matches(&bytes).is_ok());
        let changed = Pin {
            proposal,
            proofs: [[4; 32], [3; 32]],
        };
        assert!(Pin::parse(&changed.bytes()).is_ok());
        assert!(matches!(
            pin.require_matches(&changed.bytes()),
            Err(SessionStoreError::Conflict)
        ));
        let empty = Pin {
            proposal,
            proofs: [[0; 32], [3; 32]],
        };
        assert!(Pin::parse(&empty.bytes()).is_err());
    }
}
