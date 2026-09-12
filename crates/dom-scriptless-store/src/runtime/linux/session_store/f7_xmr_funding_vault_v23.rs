//! Separate native F7 Funding vault lifecycle. Ready is a no-recreation
//! tombstone; this does not reuse any recovery edge or create signing authority.
use super::*;

const MAGIC: &[u8; 8] = b"DOMXFV23";
const DOMAIN: &str = "DOM-INTEROP/F7-XMR-FUNDING-VAULT/V23\0";
const BODY: usize = 16 + 9 * 32;
const LEN: usize = BODY + 32;

/// Durable state of the exact parent Funding nonce-vault resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrFundingVaultProvisioningStateV23 {
    /// The owner has not crossed provisioning. Exact empty creation may resume.
    Started = 1,
    /// The owner crossed provisioning; absent roots must never be recreated.
    Ready = 2,
}

/// Single-use process-bound receipt. No constructor, clone or serialization.
pub struct PreparedXmrFundingVaultProvisioningV23 {
    store: [u8; 32],
    opening: [u8; 32],
    session: [u8; 32],
    state: XmrFundingVaultProvisioningStateV23,
    started: [u8; LEN],
}
impl PreparedXmrFundingVaultProvisioningV23 {
    /// Ready always requires opening the existing native Funding root.
    pub const fn state(&self) -> XmrFundingVaultProvisioningStateV23 {
        self.state
    }
}

fn name(session: [u8; 32], state: XmrFundingVaultProvisioningStateV23) -> String {
    format!(
        "{}.xmr-funding-vault-{}-v23",
        hex_lower(&session),
        match state {
            XmrFundingVaultProvisioningStateV23::Started => "started",
            XmrFundingVaultProvisioningStateV23::Ready => "ready",
        }
    )
}
pub(in super::super::super) fn parse_xmr_funding_vault_name_v23(
    value: &str,
) -> Option<([u8; 32], XmrFundingVaultProvisioningStateV23)> {
    let (stem, state) = if let Some(stem) = value.strip_suffix(".xmr-funding-vault-started-v23") {
        (stem, XmrFundingVaultProvisioningStateV23::Started)
    } else {
        (
            value.strip_suffix(".xmr-funding-vault-ready-v23")?,
            XmrFundingVaultProvisioningStateV23::Ready,
        )
    };
    let session = decode_hex_32(stem)?;
    if stem.len() != 64 || session == [0; 32] {
        return None;
    }
    Some((session, state))
}

impl ContractsSessionStoreV1 {
    /// Authenticate native Funding after bilateral readiness, then retain the
    /// resource state. A local nonce lookup/request forbids creation/reissue
    /// without Ready; a peer-only prefix never counts as local use.
    pub fn prepare_xmr_bounded_funding_vault_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedXmrFundingVaultProvisioningV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.prepare_funding_vault_locked_v23(chain, session)
    }

    fn prepare_funding_vault_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<PreparedXmrFundingVaultProvisioningV23, SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(session)?;
        if binding.origin.chain != chain {
            return Err(SessionStoreError::Conflict);
        }
        self.audit_xmr_bounded_funding_round_v23(&binding)?;
        let started =
            self.funding_vault_record_v23(&binding, XmrFundingVaultProvisioningStateV23::Started)?;
        let ready =
            self.funding_vault_record_v23(&binding, XmrFundingVaultProvisioningStateV23::Ready)?;
        let old_started =
            self.read_funding_vault_v23(session, XmrFundingVaultProvisioningStateV23::Started)?;
        let old_ready =
            self.read_funding_vault_v23(session, XmrFundingVaultProvisioningStateV23::Ready)?;
        if old_started.as_ref().is_some_and(|old| old != &started)
            || old_ready.as_ref().is_some_and(|old| old != &ready)
            || (old_ready.is_some() && old_started.is_none())
        {
            return Err(SessionStoreError::Quarantined);
        }
        let state = if old_ready.is_some() {
            XmrFundingVaultProvisioningStateV23::Ready
        } else {
            self.require_funding_vault_unused_locally_v23(&binding)?;
            if old_started.is_none() {
                self.publish_funding_vault_v23(
                    session,
                    XmrFundingVaultProvisioningStateV23::Started,
                    &started,
                )?;
            }
            XmrFundingVaultProvisioningStateV23::Started
        };
        Ok(PreparedXmrFundingVaultProvisioningV23 {
            store: self._store_id,
            opening: self.open_instance_id,
            session,
            state,
            started,
        })
    }

    /// Called after opening/validating the real native vault and before exposing
    /// its owner. Ready is immutable; stale receipts cannot recreate state.
    pub fn mark_xmr_bounded_funding_vault_ready_v23(
        &self,
        permit: PreparedXmrFundingVaultProvisioningV23,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.mark_funding_vault_ready_locked_v23(permit)
    }

    fn mark_funding_vault_ready_locked_v23(
        &self,
        permit: PreparedXmrFundingVaultProvisioningV23,
    ) -> Result<(), SessionStoreError> {
        if permit.store != self._store_id || permit.opening != self.open_instance_id {
            return Err(SessionStoreError::Conflict);
        }
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(permit.session)?;
        self.audit_xmr_bounded_funding_round_v23(&binding)?;
        let started =
            self.funding_vault_record_v23(&binding, XmrFundingVaultProvisioningStateV23::Started)?;
        if permit.started != started
            || self.read_funding_vault_v23(
                permit.session,
                XmrFundingVaultProvisioningStateV23::Started,
            )? != Some(started)
        {
            return Err(SessionStoreError::Quarantined);
        }
        let ready =
            self.funding_vault_record_v23(&binding, XmrFundingVaultProvisioningStateV23::Ready)?;
        match self
            .read_funding_vault_v23(permit.session, XmrFundingVaultProvisioningStateV23::Ready)?
        {
            Some(old) if old == ready => return Ok(()),
            Some(_) => return Err(SessionStoreError::Quarantined),
            None if permit.state == XmrFundingVaultProvisioningStateV23::Ready => {
                return Err(SessionStoreError::Quarantined)
            }
            None => {}
        }
        self.require_funding_vault_unused_locally_v23(&binding)?;
        self.publish_funding_vault_v23(
            permit.session,
            XmrFundingVaultProvisioningStateV23::Ready,
            &ready,
        )
    }

    /// Open the exact native Funding vault while holding this Store's operation
    /// lock through Ready publication. The callback must not call this Contracts
    /// Store; it may only open/create its independent native vault. A Ready
    /// callback must never create an absent root. The owner is returned only
    /// after its immutable Ready record is retained.
    pub fn with_xmr_bounded_funding_vault_v23<T>(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        open: impl FnOnce(XmrFundingVaultProvisioningStateV23) -> Result<T, SessionStoreError>,
    ) -> Result<T, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let permit = self.prepare_funding_vault_locked_v23(chain, session)?;
        let owner = open(permit.state())?;
        self.mark_funding_vault_ready_locked_v23(permit)?;
        Ok(owner)
    }

    pub(in super::super::super) fn audit_xmr_funding_vault_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let binding = self.authenticate_xmr_bounded_funding_binding_v23(session)?;
        self.audit_xmr_bounded_funding_round_v23(&binding)?;
        let started =
            self.funding_vault_record_v23(&binding, XmrFundingVaultProvisioningStateV23::Started)?;
        if self.read_funding_vault_v23(session, XmrFundingVaultProvisioningStateV23::Started)?
            != Some(started)
        {
            return Err(SessionStoreError::Quarantined);
        }
        match self.read_funding_vault_v23(session, XmrFundingVaultProvisioningStateV23::Ready)? {
            Some(old)
                if old
                    == self.funding_vault_record_v23(
                        &binding,
                        XmrFundingVaultProvisioningStateV23::Ready,
                    )? =>
            {
                Ok(())
            }
            Some(_) => Err(SessionStoreError::Quarantined),
            None => self.require_funding_vault_unused_locally_v23(&binding),
        }
    }

    fn funding_vault_record_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
        state: XmrFundingVaultProvisioningStateV23,
    ) -> Result<[u8; LEN], SessionStoreError> {
        let (local, key, template, context) = self.funding_vault_local_context_v23(binding)?;
        let mut bytes = [0; LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = 1;
        bytes[9] = state as u8;
        for (index, hash) in [
            *binding.origin.chain.as_bytes(),
            binding.origin.session,
            binding.start.terms_hash(),
            binding.digest,
            *binding.start.digest(),
            local,
            key,
            template,
            context,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[16 + index * 32..48 + index * 32].copy_from_slice(&hash);
        }
        let digest = tagged_hash(DOMAIN, &bytes[..BODY]);
        bytes[BODY..].copy_from_slice(&digest);
        Ok(bytes)
    }

    fn read_funding_vault_v23(
        &self,
        session: [u8; 32],
        state: XmrFundingVaultProvisioningStateV23,
    ) -> Result<Option<[u8; LEN]>, SessionStoreError> {
        let name = name(session, state);
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, LEN)
        {
            Ok(bytes) => Ok(Some(decode_record(&bytes, state)?)),
            Err(LinuxCapabilityError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn publish_funding_vault_v23(
        &self,
        session: [u8; 32],
        state: XmrFundingVaultProvisioningStateV23,
        bytes: &[u8; LEN],
    ) -> Result<(), SessionStoreError> {
        let name = name(session, state);
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            bytes,
            LEN,
        )?;
        if self.read_funding_vault_v23(session, state)? != Some(*bytes) {
            return Err(SessionStoreError::Quarantined);
        }
        test_crash_hook(match state {
            XmrFundingVaultProvisioningStateV23::Started => "f7-v23-funding-vault-after-started",
            XmrFundingVaultProvisioningStateV23::Ready => "f7-v23-funding-vault-after-ready",
        });
        Ok(())
    }
    fn funding_vault_local_context_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), SessionStoreError> {
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
        let context = dom_adaptor::reservation_context_digest_for_funding_v23(
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

        Ok((
            local.participant_id,
            tagged_hash(
                "DOM-INTEROP/F7-XMR-FUNDING-LOCAL-KEY/V23\0",
                &participant.signing_public_key().to_compressed_bytes(),
            ),
            template_hash,
            context,
        ))
    }
    fn require_funding_vault_unused_locally_v23(
        &self,
        binding: &NativeXmrFundingBindingV23,
    ) -> Result<(), SessionStoreError> {
        let origin = &binding.origin;
        let (local_id, _, _, context) = self.funding_vault_local_context_v23(binding)?;
        let head = self.load_session_locked(origin.session)?;
        if head.phase() != SessionPhaseV1::FundingAuthorized
            || !head.irreversible().funding_authorized
            || head.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
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
            if session != origin.session || sender != local_id || committed {
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
}

fn decode_record(
    bytes: &[u8],
    state: XmrFundingVaultProvisioningStateV23,
) -> Result<[u8; LEN], SessionStoreError> {
    if bytes.len() != LEN
        || bytes[..8] != MAGIC[..]
        || bytes[8] != 1
        || bytes[9] != state as u8
        || bytes[10..16] != [0; 6]
        || tagged_hash(DOMAIN, &bytes[..BODY]) != bytes[BODY..]
    {
        return Err(SessionStoreError::Quarantined);
    }
    copy_array(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_vault_names_have_no_recovery_edge_or_staging_alias() {
        for state in [
            XmrFundingVaultProvisioningStateV23::Started,
            XmrFundingVaultProvisioningStateV23::Ready,
        ] {
            let canonical = name([0x11; 32], state);
            assert_eq!(
                parse_xmr_funding_vault_name_v23(&canonical),
                Some(([0x11; 32], state))
            );
            for bad in [
                format!(".{canonical}.staging"),
                format!("{canonical}x"),
                canonical.replacen("11", "GG", 1),
                canonical.replacen(".xmr-funding", "-03.xmr-funding", 1),
            ] {
                assert!(parse_xmr_funding_vault_name_v23(&bad).is_none());
            }
        }
        assert!(parse_xmr_funding_vault_name_v23(&name(
            [0; 32],
            XmrFundingVaultProvisioningStateV23::Started
        ))
        .is_none());
    }

    // Framing only, not an authenticated scope or a native Funding authority.
    #[test]
    fn funding_vault_framing_rejects_state_version_reserved_and_truncation() {
        let mut bytes = [0; LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = 1;
        bytes[9] = XmrFundingVaultProvisioningStateV23::Started as u8;
        let checksum = tagged_hash(DOMAIN, &bytes[..BODY]);
        bytes[BODY..].copy_from_slice(&checksum);
        assert!(decode_record(&bytes, XmrFundingVaultProvisioningStateV23::Started).is_ok());
        assert!(decode_record(&bytes, XmrFundingVaultProvisioningStateV23::Ready).is_err());
        for length in 0..LEN {
            assert!(decode_record(
                &bytes[..length],
                XmrFundingVaultProvisioningStateV23::Started
            )
            .is_err());
        }
        for index in [0, 8, 10, 15, BODY] {
            let mut changed = bytes;
            changed[index] ^= 1;
            if index < BODY {
                let checksum = tagged_hash(DOMAIN, &changed[..BODY]);
                changed[BODY..].copy_from_slice(&checksum);
            }
            assert!(decode_record(&changed, XmrFundingVaultProvisioningStateV23::Started).is_err());
        }
    }
}
