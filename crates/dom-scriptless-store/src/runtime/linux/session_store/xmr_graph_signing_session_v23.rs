//! Native graph signing bootstrap. No early/BP transcript or legacy template
//! commitment is manufactured here; the immutable origin is the profile tag.
use super::signing_origin_v23::ReconstructedXmrGraphSigningOriginV23;
use super::*;
use crate::{SessionIrreversibleV1, SessionRecordFieldsV1};
#[cfg(test)]
#[path = "xmr_graph_legacy_collision_v23_tests.rs"]
mod legacy_collision_v23_tests;

pub(in super::super) const GRAPH_SIGNING_SESSION_SUFFIX_V23: &str =
    ".xmr-graph-signing-session-v23";
pub(in super::super) const GRAPH_SIGNING_SESSION_LEN_V23: usize = 264;
const MAGIC: &[u8; 8] = b"DXGSBS23";
const BODY: usize = 232;
const DOMAIN: &str = "DOM:xmr-graph-signing-session:v23";

/// Authenticated inputs to the native round dispatcher, not an Accepted handle.
pub(in super::super) struct GraphSigningSessionBindingV23 {
    pub(in super::super) origin: ReconstructedXmrGraphSigningOriginV23,
    pub(in super::super) start: SessionRecordV1,
    pub(in super::super) sender_sequence_bases: [u64; 2],
    pub(in super::super) initial_transcript_hash: [u8; 32],
    pub(in super::super) digest: [u8; 32],
}

impl ContractsSessionStoreV1 {
    /// Reauthenticate the exact auxiliary scope; this grants no F6/funding permit.
    pub fn require_xmr_auxiliary_transport_scope_v23(
        &self,
        parent: [u8; 32],
        route: [u8; 32],
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        if !matches!(
            edge,
            XmrGraphRecoverySigningEdgeV23::Cancel | XmrGraphRecoverySigningEdgeV23::Compensation
        ) || target == parent
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let binding = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        if binding.origin.parent != parent
            || binding.origin.route != route
            || binding.origin.session != target
            || binding.origin.purpose != PurposeV1::Refund
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    /// Initializes a native derived session and freezes its graph-only binding.
    /// This does not release a nonce, signing share or funding capability.
    /// All values are reconstructed from the retained bilateral origin.
    pub fn prepare_xmr_graph_signing_session_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<[u8; 32], SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let origin = self.authenticate_xmr_graph_signing_origin_v23(target, edge)?;
        let name = binding_name(target, edge);
        match self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            GRAPH_SIGNING_SESSION_LEN_V23,
        ) {
            Ok(_) => {
                return Ok(self
                    .authenticate_xmr_graph_signing_session_v23(target, edge)?
                    .digest)
            }
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.require_no_legacy_graph_signing_binding_v23(&origin)?;
        let expected_start = self.graph_signing_initial_record_v23(&origin)?;
        if target != origin.parent {
            match self.load_session_locked(target) {
                Ok(_) => {}
                Err(SessionStoreError::SessionNotFound) => {
                    self.persist_session_record(&expected_start)?;
                }
                Err(error) => return Err(error),
            }
            self.retain_graph_signing_transport_v23(&origin)?;
        }
        let current = self.load_session_locked(target)?;
        // A missing binding cannot be retroactively invented after a nonce or
        // signing message has advanced the native session.
        if current.as_bytes() != expected_start.as_bytes()
            || current.irreversible().funding_authorized
            || current.irreversible().any_signing_share_sent
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let binding = self.reconstruct_graph_signing_binding_v23(origin, expected_start)?;
        let bytes = encode_binding(&binding, edge);
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            &bytes,
            GRAPH_SIGNING_SESSION_LEN_V23,
        )?;
        let authenticated = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        if authenticated.digest != binding.digest {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(authenticated.digest)
    }

    /// Caller owns the operation lock. Reauthenticates origin, native bootstrap,
    /// identities, sequence bases and immutable binding across restarts.
    pub(in super::super) fn authenticate_xmr_graph_signing_session_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<GraphSigningSessionBindingV23, SessionStoreError> {
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&binding_name(target, edge))?,
            GRAPH_SIGNING_SESSION_LEN_V23,
        )?;
        require_binding_frame(&bytes, target, edge)?;
        let origin = self.authenticate_xmr_graph_signing_origin_v23(target, edge)?;
        self.require_no_legacy_graph_signing_binding_v23(&origin)?;
        let start = self.graph_signing_initial_record_v23(&origin)?;
        let durable = self.load_session_revision(target, start.revision())?;
        if durable.as_bytes() != start.as_bytes() {
            return Err(SessionStoreError::Quarantined);
        }
        // Authenticate the contiguous current history without requiring it to
        // remain at the pre-signing head: completed rounds must reopen too.
        self.load_session_locked(target)?;
        let binding = self.reconstruct_graph_signing_binding_v23(origin, start)?;
        if bytes != encode_binding(&binding, edge) {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(binding)
    }

    fn require_no_legacy_graph_signing_binding_v23(
        &self,
        origin: &ReconstructedXmrGraphSigningOriginV23,
    ) -> Result<(), SessionStoreError> {
        // Legacy has no RefundAdaptor (05) filename. Both native recovery
        // purposes must reject an existing ordinary Refund (01) binding;
        // never widen the legacy registry or turn invalid bytes into absence.
        let legacy_purpose = graph_legacy_collision_purpose_v23(origin.purpose)?;
        match self.load_signing_binding(origin.session, legacy_purpose) {
            Err(SessionStoreError::SessionNotFound) => Ok(()),
            Ok(_) => Err(SessionStoreError::Conflict),
            Err(error) => Err(error),
        }
    }

    fn graph_signing_initial_record_v23(
        &self,
        origin: &ReconstructedXmrGraphSigningOriginV23,
    ) -> Result<SessionRecordV1, SessionStoreError> {
        if origin.session == origin.parent {
            let context = self.load_xmr_graph_commit_context_v23(origin.parent)?;
            let start = self.load_session_revision(
                origin.parent,
                context
                    .revision
                    .checked_add(2)
                    .ok_or(SessionStoreError::CapacityExceeded)?,
            )?;
            if origin.purpose != PurposeV1::RefundAdaptor
                || start.phase() != SessionPhaseV1::TemplatesCommitted
                || start.terms_hash() != origin.terms
            {
                return Err(SessionStoreError::Quarantined);
            }
            return Ok(start);
        }
        if origin.purpose != PurposeV1::Refund || origin.adaptor.is_some() {
            return Err(SessionStoreError::Quarantined);
        }
        let parent_initial = self.load_session_revision(origin.parent, 0)?;
        let canonical_initial = initial_transcript_hash_v1(
            &origin.chain,
            &origin.session,
            ContractKindV1::WitnessOrTimeout,
            &origin.roster,
        );
        let mut transcript_material = Vec::with_capacity(64);
        transcript_material.extend_from_slice(&origin.digest);
        transcript_material.extend_from_slice(&canonical_initial);
        // Share only the authenticated chain tip, never a parent's economic
        // observations or its nonce epoch. The derived session has its own ID.
        let parent_chain = parent_initial.chain();
        Ok(SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: origin.session,
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash: origin.terms,
                transcript_hash: tagged_hash(
                    "DOM:xmr-graph-signing-bootstrap:v23",
                    &transcript_material,
                ),
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 0,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: parent_chain.tip_id,
                    tip_height: parent_chain.tip_height,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            &[],
        )?)
    }

    fn retain_graph_signing_transport_v23(
        &self,
        origin: &ReconstructedXmrGraphSigningOriginV23,
    ) -> Result<(), SessionStoreError> {
        let parent = self.load_transport_roster(origin.parent)?;
        let identities = self.load_transport_identity_binding(origin.parent)?;
        require_transport_identity_binding(&parent, &identities)?;
        let roster =
            TransportRosterRecordV1::new(origin.session, parent.chain_id, parent.participants);
        let identity = TransportIdentityBindingRecordV1::new(
            origin.session,
            identities.chain_id,
            identities.references,
        );
        let roster_file = roster_name(origin.session);
        publish_immutable(
            &self.rosters,
            &format!(".{roster_file}.staging"),
            &roster_file,
            &roster.bytes,
            TRANSPORT_ROSTER_LEN,
        )?;
        let identity_file = transport_identity_binding_name(origin.session);
        publish_immutable(
            &self.rosters,
            &format!(".{identity_file}.staging"),
            &identity_file,
            &identity.bytes,
            TRANSPORT_IDENTITY_BINDING_LEN,
        )?;
        Ok(())
    }

    fn reconstruct_graph_signing_binding_v23(
        &self,
        origin: ReconstructedXmrGraphSigningOriginV23,
        start: SessionRecordV1,
    ) -> Result<GraphSigningSessionBindingV23, SessionStoreError> {
        let transport = self.load_transport_roster(origin.session)?;
        let identities = self.load_transport_identity_binding(origin.session)?;
        require_transport_identity_binding(&transport, &identities)?;
        let parent_transport = self.load_transport_roster(origin.parent)?;
        let parent_identities = self.load_transport_identity_binding(origin.parent)?;
        if transport.chain_id != *origin.chain.as_bytes()
            || transport.participants != parent_transport.participants
            || identities.references != parent_identities.references
            || origin.roster.entries().len() != 2
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut bases = [0; 2];
        for (index, participant) in origin.roster.entries().iter().enumerate() {
            if !transport.participants.iter().any(|p| {
                p.participant_id == *participant.participant_id()
                    && p.direction == participant.direction()
            }) {
                return Err(SessionStoreError::Quarantined);
            }
            bases[index] = self.transport_sequence_at_revision(
                origin.session,
                *participant.participant_id(),
                start.revision(),
            )?;
            bases[index]
                .checked_add(2)
                .ok_or(SessionStoreError::CapacityExceeded)?;
        }
        let initial_transcript_hash = initial_transcript_hash_v1(
            &origin.chain,
            &origin.session,
            ContractKindV1::WitnessOrTimeout,
            &origin.roster,
        );
        let edge = if origin.session == origin.parent {
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor
        } else if origin.input_session == origin.parent {
            XmrGraphRecoverySigningEdgeV23::Cancel
        } else {
            XmrGraphRecoverySigningEdgeV23::Compensation
        };
        let mut binding = GraphSigningSessionBindingV23 {
            origin,
            start,
            sender_sequence_bases: bases,
            initial_transcript_hash,
            digest: [0; 32],
        };
        binding.digest = tagged_hash(DOMAIN, &encode_binding(&binding, edge)[..BODY]);
        Ok(binding)
    }
}

fn graph_legacy_collision_purpose_v23(purpose: PurposeV1) -> Result<PurposeV1, SessionStoreError> {
    match purpose {
        PurposeV1::Refund | PurposeV1::RefundAdaptor => Ok(PurposeV1::Refund),
        _ => Err(SessionStoreError::InvalidTransition),
    }
}

fn binding_name(target: [u8; 32], edge: XmrGraphRecoverySigningEdgeV23) -> String {
    format!(
        "{}-{:02x}{GRAPH_SIGNING_SESSION_SUFFIX_V23}",
        hex_lower(&target),
        edge as u8
    )
}

pub(in super::super) fn parse_xmr_graph_signing_session_name_v23(
    name: &str,
) -> Option<([u8; 32], XmrGraphRecoverySigningEdgeV23)> {
    let stem = name.strip_suffix(GRAPH_SIGNING_SESSION_SUFFIX_V23)?;
    // Reuse the exact strict target/edge parser; suffixes are disjoint profiles.
    super::signing_origin_v23::parse_xmr_graph_signing_origin_name_v23(&format!(
        "{stem}{}",
        super::signing_origin_v23::SIGNING_ORIGIN_SUFFIX_V23
    ))
}

fn encode_binding(
    binding: &GraphSigningSessionBindingV23,
    edge: XmrGraphRecoverySigningEdgeV23,
) -> [u8; GRAPH_SIGNING_SESSION_LEN_V23] {
    let mut out = [0; GRAPH_SIGNING_SESSION_LEN_V23];
    out[..8].copy_from_slice(MAGIC);
    out[8] = edge as u8;
    out[16..48].copy_from_slice(binding.origin.chain.as_bytes());
    out[48..80].copy_from_slice(&binding.origin.session);
    out[80..112].copy_from_slice(&binding.origin.digest);
    out[112..120].copy_from_slice(&binding.start.revision().to_le_bytes());
    out[120..152].copy_from_slice(binding.start.digest());
    out[152..184].copy_from_slice(&binding.start.transcript_hash());
    out[184..192].copy_from_slice(&binding.sender_sequence_bases[0].to_le_bytes());
    out[192..200].copy_from_slice(&binding.sender_sequence_bases[1].to_le_bytes());
    out[200..232].copy_from_slice(&binding.initial_transcript_hash);
    let digest = tagged_hash(DOMAIN, &out[..BODY]);
    out[BODY..].copy_from_slice(&digest);
    out
}

fn require_binding_frame(
    bytes: &[u8],
    target: [u8; 32],
    edge: XmrGraphRecoverySigningEdgeV23,
) -> Result<(), SessionStoreError> {
    if bytes.len() != GRAPH_SIGNING_SESSION_LEN_V23
        || &bytes[..8] != MAGIC
        || bytes[8] != edge as u8
        || bytes[9..16] != [0; 7]
        || bytes[48..80] != target
        || target == [0; 32]
        || tagged_hash(DOMAIN, &bytes[..BODY]) != bytes[BODY..]
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}
