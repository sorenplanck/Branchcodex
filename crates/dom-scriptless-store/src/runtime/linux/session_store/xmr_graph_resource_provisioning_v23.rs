//! Dynamic graph resource tombstones. Started is retained before native root
//! creation; Ready is retained before the opened owner may escape provisioning.
//! Neither record is a nonce, signing authority or proof of filesystem health.
use super::signing_session_v23::GraphSigningSessionBindingV23;
use super::*;

const MAGIC: &[u8; 8] = b"DXGRPV23";
const DOMAIN: &str = "DOM:xmr-graph-resource-provisioning:v23";
const LEN: usize = 240;
const BODY: usize = 208;
const STARTED: &str = ".xmr-graph-resource-started-v23";
const READY: &str = ".xmr-graph-resource-ready-v23";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_names_are_closed_and_edge_separated() {
        let target = [0x71; 32];
        let edges = [
            XmrGraphRecoverySigningEdgeV23::Cancel,
            XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
            XmrGraphRecoverySigningEdgeV23::Compensation,
        ];
        let kinds = [
            XmrGraphResourceKindV23::NonceVault,
            XmrGraphResourceKindV23::AuxiliaryRelay,
        ];
        let states = [
            XmrGraphResourceStateV23::Started,
            XmrGraphResourceStateV23::Ready,
        ];
        let mut names = std::collections::BTreeSet::new();
        for edge in edges {
            for kind in kinds {
                for state in states {
                    let name = resource_name(target, edge, kind, state);
                    let forbidden = edge == XmrGraphRecoverySigningEdgeV23::RefundAdaptor
                        && kind == XmrGraphResourceKindV23::AuxiliaryRelay;
                    assert_eq!(
                        parse_xmr_graph_resource_name_v23(&name),
                        (!forbidden).then_some((target, edge, kind, state))
                    );
                    if !forbidden {
                        assert!(names.insert(name));
                    }
                }
            }
        }
        assert_eq!(names.len(), 10);
        let valid = resource_name(target, edges[0], kinds[0], states[0]);
        for invalid in [
            valid.to_uppercase(),
            format!(".{valid}.staging"),
            format!("{valid}x"),
            valid.replacen("-02-01", "-05-01", 1),
            valid.replacen("-02-01", "-02-00", 1),
            valid.replacen("-02-01", "-02-03", 1),
            resource_name([0; 32], edges[0], kinds[0], states[0]),
        ] {
            assert!(
                parse_xmr_graph_resource_name_v23(&invalid).is_none(),
                "{invalid}"
            );
        }
    }
}

/// The only dynamically provisioned GraphV23 resource families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrGraphResourceKindV23 {
    /// Purpose-separated native nonce vault for this exact recovery edge.
    NonceVault = 1,
    /// Dedicated Cancel or Compensation Relay databases, never a parent Relay.
    AuxiliaryRelay = 2,
}

/// Durable provisioning state, independent of the daemon's startup mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrGraphResourceStateV23 {
    /// No usable owner was returned; exact first creation may still be resumed.
    Started = 1,
    /// An owner crossed provisioning; missing roots must never be recreated.
    Ready = 2,
}

/// Process-local, single-use provisioning handle. No clone, codec or constructor.
/// A caller must open/validate the actual native resource, mark it Ready, then
/// return that owner. The state is not permission to bypass native root checks.
pub struct PreparedXmrGraphResourceV23 {
    store: [u8; 32],
    open_instance: [u8; 32],
    target: [u8; 32],
    edge: XmrGraphRecoverySigningEdgeV23,
    kind: XmrGraphResourceKindV23,
    state: XmrGraphResourceStateV23,
    started: [u8; LEN],
}

impl PreparedXmrGraphResourceV23 {
    /// Ready permits reopening only, regardless of a global Create option.
    pub const fn state(&self) -> XmrGraphResourceStateV23 {
        self.state
    }
}

fn resource_name(
    target: [u8; 32],
    edge: XmrGraphRecoverySigningEdgeV23,
    kind: XmrGraphResourceKindV23,
    state: XmrGraphResourceStateV23,
) -> String {
    let suffix = match state {
        XmrGraphResourceStateV23::Started => STARTED,
        XmrGraphResourceStateV23::Ready => READY,
    };
    format!(
        "{}-{:02x}-{:02x}{suffix}",
        hex_lower(&target),
        edge as u8,
        kind as u8
    )
}

pub(in super::super) fn parse_xmr_graph_resource_name_v23(
    name: &str,
) -> Option<(
    [u8; 32],
    XmrGraphRecoverySigningEdgeV23,
    XmrGraphResourceKindV23,
    XmrGraphResourceStateV23,
)> {
    let (stem, state) = match name.strip_suffix(STARTED) {
        Some(stem) => (stem, XmrGraphResourceStateV23::Started),
        None => (name.strip_suffix(READY)?, XmrGraphResourceStateV23::Ready),
    };
    if stem.len() != 70
        || stem.as_bytes().get(64) != Some(&b'-')
        || stem.as_bytes().get(67) != Some(&b'-')
    {
        return None;
    }
    let target = decode_hex_32(stem.get(..64)?)?;
    let edge = match stem.get(65..67)? {
        "02" => XmrGraphRecoverySigningEdgeV23::Cancel,
        "03" => XmrGraphRecoverySigningEdgeV23::RefundAdaptor,
        "04" => XmrGraphRecoverySigningEdgeV23::Compensation,
        _ => return None,
    };
    let kind = match stem.get(68..70)? {
        "01" => XmrGraphResourceKindV23::NonceVault,
        "02" => XmrGraphResourceKindV23::AuxiliaryRelay,
        _ => return None,
    };
    if target == [0; 32]
        || (edge == XmrGraphRecoverySigningEdgeV23::RefundAdaptor
            && kind == XmrGraphResourceKindV23::AuxiliaryRelay)
        || resource_name(target, edge, kind, state) != name
    {
        return None;
    }
    Some((target, edge, kind, state))
}

fn encode(
    binding: &GraphSigningSessionBindingV23,
    edge: XmrGraphRecoverySigningEdgeV23,
    kind: XmrGraphResourceKindV23,
    state: XmrGraphResourceStateV23,
) -> [u8; LEN] {
    let mut bytes = [0; LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..11].copy_from_slice(&[edge as u8, kind as u8, state as u8]);
    for (index, scope) in [
        *binding.origin.chain.as_bytes(),
        binding.origin.route,
        binding.origin.parent,
        binding.origin.session,
        binding.origin.digest,
        binding.digest,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[16 + index * 32..48 + index * 32].copy_from_slice(&scope);
    }
    let checksum = tagged_hash(DOMAIN, &bytes[..BODY]);
    bytes[BODY..].copy_from_slice(&checksum);
    bytes
}

impl ContractsSessionStoreV1 {
    /// Reauthenticate the native graph and return its exact durable resource
    /// state. First creation is permitted only before any LOCAL nonce lookup or
    /// signing request for this edge. A peer's earlier commitment is harmless.
    pub fn prepare_xmr_graph_resource_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
        kind: XmrGraphResourceKindV23,
    ) -> Result<PreparedXmrGraphResourceV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        if edge == XmrGraphRecoverySigningEdgeV23::RefundAdaptor
            && kind == XmrGraphResourceKindV23::AuxiliaryRelay
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let binding = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        let started = encode(&binding, edge, kind, XmrGraphResourceStateV23::Started);
        let ready = encode(&binding, edge, kind, XmrGraphResourceStateV23::Ready);
        let old_started =
            self.read_graph_resource_v23(target, edge, kind, XmrGraphResourceStateV23::Started)?;
        let old_ready =
            self.read_graph_resource_v23(target, edge, kind, XmrGraphResourceStateV23::Ready)?;
        if old_started.as_ref().is_some_and(|old| old != &started)
            || old_ready.as_ref().is_some_and(|old| old != &ready)
            || (old_ready.is_some() && old_started.is_none())
        {
            return Err(SessionStoreError::Quarantined);
        }
        let state = if old_ready.is_some() {
            XmrGraphResourceStateV23::Ready
        } else {
            match kind {
                XmrGraphResourceKindV23::NonceVault => {
                    self.require_graph_resource_unused_locally_v23(&binding)?;
                }
                XmrGraphResourceKindV23::AuxiliaryRelay => {
                    self.require_graph_auxiliary_relay_unadvanced_v23(&binding)?;
                }
            }
            if old_started.is_none() {
                self.publish_graph_resource_v23(
                    target,
                    edge,
                    kind,
                    XmrGraphResourceStateV23::Started,
                    &started,
                )?;
            }
            XmrGraphResourceStateV23::Started
        };
        Ok(PreparedXmrGraphResourceV23 {
            store: self._store_id,
            open_instance: self.open_instance_id,
            target,
            edge,
            kind,
            state,
            started,
        })
    }

    /// Consume a provisioning handle after the caller has opened and verified
    /// the native resource, but BEFORE it exports that owner to any signer or
    /// transport loop. Ready is immutable: it prevents recreation, not corruption.
    pub fn mark_xmr_graph_resource_ready_v23(
        &self,
        permit: PreparedXmrGraphResourceV23,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        if permit.store != self._store_id || permit.open_instance != self.open_instance_id {
            return Err(SessionStoreError::Conflict);
        }
        let binding =
            self.authenticate_xmr_graph_signing_session_v23(permit.target, permit.edge)?;
        let started = encode(
            &binding,
            permit.edge,
            permit.kind,
            XmrGraphResourceStateV23::Started,
        );
        if permit.started != started
            || self.read_graph_resource_v23(
                permit.target,
                permit.edge,
                permit.kind,
                XmrGraphResourceStateV23::Started,
            )? != Some(started)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let expected = encode(
            &binding,
            permit.edge,
            permit.kind,
            XmrGraphResourceStateV23::Ready,
        );
        match self.read_graph_resource_v23(
            permit.target,
            permit.edge,
            permit.kind,
            XmrGraphResourceStateV23::Ready,
        )? {
            Some(old) if old == expected => return Ok(()),
            Some(_) => return Err(SessionStoreError::Quarantined),
            None if permit.state == XmrGraphResourceStateV23::Ready => {
                return Err(SessionStoreError::Quarantined)
            }
            None => {}
        }
        match permit.kind {
            XmrGraphResourceKindV23::NonceVault => {
                self.require_graph_resource_unused_locally_v23(&binding)?;
            }
            XmrGraphResourceKindV23::AuxiliaryRelay => {
                self.require_graph_auxiliary_relay_unadvanced_v23(&binding)?;
            }
        }
        self.publish_graph_resource_v23(
            permit.target,
            permit.edge,
            permit.kind,
            XmrGraphResourceStateV23::Ready,
            &expected,
        )
    }

    // Called by the Store roster census under its operation lock. Started
    // without Ready may never conceal a previously exposed local nonce.
    pub(in super::super) fn audit_xmr_graph_resource_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
        kind: XmrGraphResourceKindV23,
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_graph_signing_session_v23(target, edge)?;
        let started = encode(&binding, edge, kind, XmrGraphResourceStateV23::Started);
        if self.read_graph_resource_v23(target, edge, kind, XmrGraphResourceStateV23::Started)?
            != Some(started)
        {
            return Err(SessionStoreError::Quarantined);
        }
        match self.read_graph_resource_v23(target, edge, kind, XmrGraphResourceStateV23::Ready)? {
            Some(old) if old == encode(&binding, edge, kind, XmrGraphResourceStateV23::Ready) => {
                Ok(())
            }
            Some(_) => Err(SessionStoreError::Quarantined),
            None => match kind {
                XmrGraphResourceKindV23::NonceVault => {
                    self.require_graph_resource_unused_locally_v23(&binding)
                }
                XmrGraphResourceKindV23::AuxiliaryRelay => {
                    self.require_graph_auxiliary_relay_unadvanced_v23(&binding)
                }
            },
        }
    }

    fn read_graph_resource_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
        kind: XmrGraphResourceKindV23,
        state: XmrGraphResourceStateV23,
    ) -> Result<Option<[u8; LEN]>, SessionStoreError> {
        let name = resource_name(target, edge, kind, state);
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)
        {
            Ok(bytes) => {
                if bytes.len() != LEN
                    || bytes[..8] != MAGIC[..]
                    || bytes[11..16] != [0; 5]
                    || bytes[8..11] != [edge as u8, kind as u8, state as u8]
                    || tagged_hash(DOMAIN, &bytes[..BODY]) != bytes[BODY..]
                {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(Some(copy_array(&bytes)?))
            }
            Err(LinuxCapabilityError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn publish_graph_resource_v23(
        &self,
        target: [u8; 32],
        edge: XmrGraphRecoverySigningEdgeV23,
        kind: XmrGraphResourceKindV23,
        state: XmrGraphResourceStateV23,
        bytes: &[u8; LEN],
    ) -> Result<(), SessionStoreError> {
        let name = resource_name(target, edge, kind, state);
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            bytes,
            LEN,
        )?;
        if self.read_graph_resource_v23(target, edge, kind, state)? != Some(*bytes) {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    fn require_graph_resource_unused_locally_v23(
        &self,
        binding: &GraphSigningSessionBindingV23,
    ) -> Result<(), SessionStoreError> {
        let origin = &binding.origin;
        let local = self.authenticate_local_transport_signer_binding(origin.session)?;
        let index = origin
            .roster
            .entries()
            .iter()
            .position(|entry| entry.participant_id() == &local.participant_id)
            .ok_or(SessionStoreError::Quarantined)?;
        let participant = &origin.roster.entries()[index];
        let mut signing_keys: Vec<_> = origin
            .roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let (_, template_hash) =
            canonical_template_v1(&origin.template).map_err(|_| SessionStoreError::Quarantined)?;
        let kernel = origin
            .template
            .kernels
            .first()
            .ok_or(SessionStoreError::Quarantined)?;
        let context = dom_adaptor::reservation_context_digest_for_graph_v23(
            dom_adaptor::SessionContextInputsV1 {
                chain_id: *origin.chain.as_bytes(),
                session_id: origin.session,
                purpose: origin.purpose,
                direction: participant.direction(),
                signing_phase: SigningPhaseV1::SigNonceCommit,
                template_hash,
                message_digest: *dom_scriptless_consensus::scriptless_kernel_message_digest_v1(
                    kernel,
                )
                .as_bytes(),
                transcript_hash: binding.start.transcript_hash(),
                retry_counter: 0,
                participant_public_keys: signing_keys,
                participant_index: origin
                    .roster
                    .signing_index(&local.participant_id)
                    .map_err(|_| SessionStoreError::Quarantined)?,
                adaptor_point: origin.adaptor.clone(),
            },
            &origin.roster,
            index as u16,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        let mut used = false;
        self.reservation_lookups.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || name.starts_with('.') {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = self.reservation_lookups.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_LOOKUP_RECORD_LEN,
            )?;
            let record = ReservationLookupRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if record.session_id == origin.session && record.context_binding_digest == context {
                used = true; // Includes irreversible abandonment, never a fresh retry.
            }
            Ok(())
        })?;
        self.rosters.scan_lexicographic(|name, _| {
            let Some((session, sender, _, committed)) = parse_outbound_dsc1_name(name) else {
                return Ok(());
            };
            if session != origin.session || sender != local.participant_id || committed {
                return Ok(());
            }
            let bytes = self.rosters.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                OUTBOUND_DSC1_REQUEST_MAX_LEN,
            )?;
            let request = OutboundDsc1SigningRequestRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if request.predecessor_revision >= binding.start.revision()
                && (0x0c..=0x0e).contains(&request.message_type)
                && signing_payload_purpose(request.message_type, &request.payload)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    == origin.purpose
            {
                used = true;
            }
            Ok(())
        })?;
        // All legitimate local consumption/message rows require their native
        // request; the global audit before issuance authenticates that linkage.
        if used {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn require_graph_auxiliary_relay_unadvanced_v23(
        &self,
        binding: &GraphSigningSessionBindingV23,
    ) -> Result<(), SessionStoreError> {
        let current = self.load_session_locked(binding.origin.session)?;
        if current.as_bytes() != binding.start.as_bytes()
            || current.irreversible().funding_authorized
            || current.irreversible().any_signing_share_sent
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(())
    }
}
