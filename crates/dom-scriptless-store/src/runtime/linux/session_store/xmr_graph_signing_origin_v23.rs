//! Recovery signing ancestry from the exact graph and two identity commitments.
//! This is neither an early/BP journal for a derived session nor a signing grant.
use super::*;
use xmr_refund_policy::{
    graph_builder::XmrRecoveryGraphTemplatesV12,
    graph_signing_keys_v22::{XmrGraphSigningKeysV22, XmrGraphSigningStageV22},
};

pub(in super::super) const SIGNING_ORIGIN_SUFFIX_V23: &str = ".xmr-graph-signing-origin-v23";
pub(in super::super) const SIGNING_ORIGIN_MAGIC_V23: &[u8; 8] = b"DXGSOR23";
pub(in super::super) const SIGNING_ORIGIN_LEN_V23: usize = 599;
const BODY: usize = 567;
const DOMAIN: &str = "DOM:xmr-graph-signing-origin:v23";

/// Recovery edges only. No Funding or Claim selector is exposed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrGraphRecoverySigningEdgeV23 {
    /// Ordinary C -> D cancellation in its existing derived signing session.
    Cancel = 2,
    /// U-adaptor D -> DOM refund in the parent signing session.
    RefundAdaptor = 3,
    /// Ordinary bounded V23 D -> XMR compensation in its derived session.
    Compensation = 4,
}

impl XmrGraphRecoverySigningEdgeV23 {
    fn stage(self) -> XmrGraphSigningStageV22 {
        match self {
            Self::Cancel => XmrGraphSigningStageV22::Cancel,
            Self::RefundAdaptor => XmrGraphSigningStageV22::Refund,
            Self::Compensation => XmrGraphSigningStageV22::Compensation,
        }
    }

    fn purpose(self) -> PurposeV1 {
        match self {
            Self::Cancel | Self::Compensation => PurposeV1::Refund,
            Self::RefundAdaptor => PurposeV1::RefundAdaptor,
        }
    }
}

/// Internal reconstructed inputs for the future native signing dispatcher.
/// No external constructor, serialization or AcceptedSigningSession trait.
pub(in super::super) struct ReconstructedXmrGraphSigningOriginV23 {
    pub(in super::super) chain: TrustedChainIdV1,
    pub(in super::super) route: [u8; 32],
    pub(in super::super) parent: [u8; 32],
    pub(in super::super) session: [u8; 32],
    pub(in super::super) terms: [u8; 32],
    pub(in super::super) input_session: [u8; 32],
    pub(in super::super) purpose: PurposeV1,
    pub(in super::super) template: Transaction,
    pub(in super::super) roster: ParticipantRosterV1,
    pub(in super::super) adaptor: Option<PublicKey>,
    pub(in super::super) digest: [u8; 32],
    bytes: [u8; SIGNING_ORIGIN_LEN_V23],
}

struct RetainedOrigin {
    scopes: [[u8; 32]; 6],
    edge: XmrGraphRecoverySigningEdgeV23,
}

impl RetainedOrigin {
    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != SIGNING_ORIGIN_LEN_V23
            || &bytes[..8] != SIGNING_ORIGIN_MAGIC_V23
            || bytes[9..16] != [0; 7]
            || tagged_hash(DOMAIN, &bytes[..BODY]) != bytes[BODY..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let edge = match bytes[8] {
            2 => XmrGraphRecoverySigningEdgeV23::Cancel,
            3 => XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
            4 => XmrGraphRecoverySigningEdgeV23::Compensation,
            _ => return Err(SessionStoreError::Quarantined),
        };
        let mut scopes = [[0; 32]; 6];
        for (index, scope) in scopes.iter_mut().enumerate() {
            *scope = copy_array(&bytes[16 + index * 32..48 + index * 32])?;
        }
        if scopes.contains(&[0; 32])
            || bytes[208..336]
                .chunks_exact(32)
                .any(|digest| digest == [0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(Self { scopes, edge })
    }
}

fn origin_name(session: [u8; 32], edge: XmrGraphRecoverySigningEdgeV23) -> String {
    format!(
        "{}-{:02x}{SIGNING_ORIGIN_SUFFIX_V23}",
        hex_lower(&session),
        edge as u8
    )
}

pub(in super::super) fn parse_xmr_graph_signing_origin_name_v23(
    name: &str,
) -> Option<([u8; 32], XmrGraphRecoverySigningEdgeV23)> {
    let stem = name.strip_suffix(SIGNING_ORIGIN_SUFFIX_V23)?;
    if stem.len() != 67 || stem.as_bytes().get(64) != Some(&b'-') {
        return None;
    }
    let session = decode_hex_32(stem.get(..64)?)?;
    let edge = match stem.get(65..)? {
        "02" => XmrGraphRecoverySigningEdgeV23::Cancel,
        "03" => XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        "04" => XmrGraphRecoverySigningEdgeV23::Compensation,
        _ => return None,
    };
    (session != [0; 32] && origin_name(session, edge) == name).then_some((session, edge))
}

impl ContractsSessionStoreV1 {
    /// Retain an edge's exact native ancestry after both graph commitments.
    /// First issuance requires the unchanged agreement head. Identical reissue
    /// revalidates historical ancestry after progression, without a new grant.
    pub fn retain_xmr_graph_signing_origin_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        parent: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<[u8; 32], SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        let expected = self.reconstruct_graph_signing_origin_v23(chain, route, parent, edge)?;
        let name = origin_name(expected.session, edge);
        match self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            SIGNING_ORIGIN_LEN_V23,
        ) {
            Ok(bytes) => {
                RetainedOrigin::decode(&bytes)?;
                if bytes != expected.bytes {
                    return Err(SessionStoreError::Conflict);
                }
                return Ok(expected.digest);
            }
            Err(LinuxCapabilityError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let current = self.load_session_locked(parent)?;
        let context = self.load_xmr_graph_commit_context_v23(parent)?;
        if current.revision()
            != context
                .revision
                .checked_add(2)
                .ok_or(SessionStoreError::CapacityExceeded)?
            || current.phase() != SessionPhaseV1::TemplatesCommitted
            || current.irreversible().funding_authorized
            || current.irreversible().any_signing_share_sent
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            &expected.bytes,
            SIGNING_ORIGIN_LEN_V23,
        )?;
        let durable = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            SIGNING_ORIGIN_LEN_V23,
        )?;
        if durable != expected.bytes {
            return Err(SessionStoreError::Conflict);
        }
        Ok(expected.digest)
    }

    /// Caller holds the operation lock. Reconstructs unsigned native inputs,
    /// never creates a target session or moves it past a signing gate.
    pub(in super::super) fn authenticate_xmr_graph_signing_origin_v23(
        &self,
        session: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<ReconstructedXmrGraphSigningOriginV23, SessionStoreError> {
        let name = origin_name(session, edge);
        let bytes = self.rosters.read_bounded_file(
            &ValidatedComponent::registered(&name)?,
            SIGNING_ORIGIN_LEN_V23,
        )?;
        let retained = RetainedOrigin::decode(&bytes)?;
        if retained.scopes[3] != session || retained.edge != edge {
            return Err(SessionStoreError::Conflict);
        }
        let chain = self.require_process_trusted_chain_v23(&retained.scopes[0])?;
        let expected = self.reconstruct_graph_signing_origin_v23(
            chain,
            retained.scopes[1],
            retained.scopes[2],
            edge,
        )?;
        if expected.bytes.as_slice() != bytes.as_slice() {
            return Err(SessionStoreError::Conflict);
        }
        Ok(expected)
    }

    fn reconstruct_graph_signing_origin_v23(
        &self,
        chain: TrustedChainIdV1,
        route: [u8; 32],
        parent: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
    ) -> Result<ReconstructedXmrGraphSigningOriginV23, SessionStoreError> {
        self.audit_xmr_graph_commit_context_v23(parent)?;
        let context = self.load_xmr_graph_commit_context_v23(parent)?;
        if context.chain != *chain.as_bytes() || context.route != route || context.session != parent
        {
            return Err(SessionStoreError::Conflict);
        }
        let agreement_revision = context
            .revision
            .checked_add(2)
            .ok_or(SessionStoreError::CapacityExceeded)?;
        let agreement = self.load_session_revision(parent, agreement_revision)?;
        let transport = self.load_transport_roster(parent)?;
        let identities = self.load_transport_identity_binding(parent)?;
        require_transport_identity_binding(&transport, &identities)?;
        if agreement.phase() != SessionPhaseV1::TemplatesCommitted
            || agreement.irreversible().funding_authorized
            || self.audit_xmr_graph_commit_prefix_v23(parent, &agreement, &transport, None)? != 2
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let reconstructed =
            self.reconstruct_xmr_graph_evidence_core_v23(chain, route, parent, false)?;
        let (templates, keys) = (&reconstructed.0, &reconstructed.1);
        let proposal = keys
            .proposal()
            .map_err(|_| SessionStoreError::Conflict)?
            .digest();
        if proposal != context.bindings[5] {
            return Err(SessionStoreError::Conflict);
        }
        build_origin(
            chain,
            route,
            parent,
            edge,
            templates,
            keys,
            &transport,
            [context.digest(), proposal, *agreement.digest()],
        )
    }
}

fn build_origin(
    chain: TrustedChainIdV1,
    route: [u8; 32],
    parent: [u8; 32],
    edge: XmrGraphRecoverySigningEdgeV23,
    templates: &XmrRecoveryGraphTemplatesV12,
    keys: &XmrGraphSigningKeysV22,
    transport: &TransportRosterRecordV1,
    ancestry: [[u8; 32]; 3],
) -> Result<ReconstructedXmrGraphSigningOriginV23, SessionStoreError> {
    keys.require_route(route)
        .and_then(|_| keys.require_graph(templates))
        .map_err(|_| SessionStoreError::Conflict)?;
    let compensation_session = templates
        .compensation_session_v23()
        .map_err(|_| SessionStoreError::Conflict)?;
    let stage = edge.stage();
    let hash = keys.template_hash(stage);
    let cancel_session = dom_scriptless_crypto::xmr_ordinary_recovery_session_v12(
        templates.binding(),
        dom_scriptless_crypto::XmrOrdinaryRecoveryKindV12::Cancel,
        keys.template_hash(XmrGraphSigningStageV22::Cancel),
    );
    if cancel_session == parent
        || compensation_session == parent
        || cancel_session == compensation_session
    {
        return Err(SessionStoreError::Conflict);
    }
    let (session, template, adaptor) = match edge {
        XmrGraphRecoverySigningEdgeV23::Cancel => (cancel_session, templates.cancel(), None),
        XmrGraphRecoverySigningEdgeV23::RefundAdaptor => (
            parent,
            templates.refund(),
            Some(
                PublicKey::from_compressed_bytes(&templates.binding().refund_adaptor_point)
                    .map_err(|_| SessionStoreError::InvalidDomTransaction)?,
            ),
        ),
        XmrGraphRecoverySigningEdgeV23::Compensation => {
            (compensation_session, templates.compensation(), None)
        }
    };
    let input_session = if edge == XmrGraphRecoverySigningEdgeV23::Cancel {
        parent
    } else {
        xmr_refund_policy::graph_builder::xmr_cancelled_output_session_v12(templates.policy())
    };
    let mut participants = Vec::with_capacity(2);
    for identity in &transport.participants {
        let key = keys
            .key(stage, identity.participant_id, hash)
            .map_err(|_| SessionStoreError::Conflict)?
            .clone();
        let participant = ParticipantIdentityV1::new(
            &chain,
            identity.identity_key.clone(),
            key,
            identity.direction,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        if participant.participant_id() != &identity.participant_id {
            return Err(SessionStoreError::Conflict);
        }
        participants.push(participant);
    }
    participants.sort_by_key(|participant| *participant.participant_id());
    let roster =
        ParticipantRosterV1::new(participants).map_err(|_| SessionStoreError::Canonical)?;
    let mut bytes = [0; SIGNING_ORIGIN_LEN_V23];
    bytes[..8].copy_from_slice(SIGNING_ORIGIN_MAGIC_V23);
    bytes[8] = edge as u8;
    let terms = templates.binding().terms_hash;
    for (index, scope) in [
        *chain.as_bytes(),
        route,
        parent,
        session,
        terms,
        input_session,
    ]
    .iter()
    .enumerate()
    {
        bytes[16 + index * 32..48 + index * 32].copy_from_slice(scope);
    }
    for (index, digest) in [ancestry[0], ancestry[1], ancestry[2], hash]
        .iter()
        .enumerate()
    {
        bytes[208 + index * 32..240 + index * 32].copy_from_slice(digest);
    }
    for (index, participant) in roster.entries().iter().enumerate() {
        let offset = 336 + index * 99;
        bytes[offset..offset + 32].copy_from_slice(participant.participant_id());
        bytes[offset + 32..offset + 65]
            .copy_from_slice(&participant.identity_public_key().to_compressed_bytes());
        bytes[offset + 65..offset + 98]
            .copy_from_slice(&participant.signing_public_key().to_compressed_bytes());
        bytes[offset + 98] = participant.direction().to_byte();
    }
    if let Some(adaptor) = &adaptor {
        bytes[534..567].copy_from_slice(&adaptor.to_compressed_bytes());
    }
    let digest = tagged_hash(DOMAIN, &bytes[..BODY]);
    bytes[BODY..].copy_from_slice(&digest);
    RetainedOrigin::decode(&bytes)?;
    Ok(ReconstructedXmrGraphSigningOriginV23 {
        chain,
        route,
        parent,
        session,
        terms,
        input_session,
        purpose: edge.purpose(),
        template: template.clone(),
        roster,
        adaptor,
        digest,
        bytes,
    })
}
