//! Separate custody provisioning journal. Ready is a no-recreation tombstone;
//! it grants neither funding nor permission to repair an incomplete archive.
use super::super::super::xmr_recovery::{
    XmrRecoveryCustodyRoleV11, XmrRecoveryCustodyScopeV11, XmrRecoveryCustodyV11,
};
use super::*;
use xmr_refund_policy::graph_builder::ProducedXmrRecoveryGraphV12;

const MAGIC: &[u8; 8] = b"DXGCPV23";
const DOMAIN: &str = "DOM:xmr-graph-custody-provisioning:v23";
const MAX: usize = 16_384;
const FIXED: usize = 340;

/// Custody state is independent of nonce-vault and auxiliary-Relay provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrGraphCustodyProvisioningStateV23 {
    /// Exact fresh creation may proceed; partial roots still must fail closed.
    Started,
    /// Only the already opened exact archive may be reopened, never recreated.
    Ready,
}

/// Non-clone process-local receipt for the exact native graph and local role.
pub struct PreparedXmrGraphCustodyProvisioningV23 {
    store: [u8; 32],
    opening: [u8; 32],
    scope: XmrRecoveryCustodyScopeV11,
    state: XmrGraphCustodyProvisioningStateV23,
    started: Vec<u8>,
}
impl PreparedXmrGraphCustodyProvisioningV23 {
    /// Ready means reopen only, even if the archive has since disappeared.
    pub const fn state(&self) -> XmrGraphCustodyProvisioningStateV23 {
        self.state
    }
    /// Exact authenticated graph/identity scope for the native archive opener.
    pub const fn scope(&self) -> XmrRecoveryCustodyScopeV11 {
        self.scope
    }
}

fn name(parent: [u8; 32], ready: bool) -> String {
    format!(
        "{}.xmr-graph-custody-{}-v23",
        hex_lower(&parent),
        if ready { "ready" } else { "started" }
    )
}
pub(in super::super) fn parse_xmr_graph_custody_provisioning_name_v23(
    value: &str,
) -> Option<[u8; 32]> {
    for ready in [false, true] {
        let suffix = if ready {
            ".xmr-graph-custody-ready-v23"
        } else {
            ".xmr-graph-custody-started-v23"
        };
        if let Some(prefix) = value.strip_suffix(suffix) {
            let parent = decode_hex_32(prefix)?;
            return (parent != [0; 32] && name(parent, ready) == value).then_some(parent);
        }
    }
    None
}

impl ContractsSessionStoreV1 {
    /// Publish a complete archive under an exact still-Started receipt while
    /// holding this Store's operation lock. Ready, including a stale receipt
    /// issued before Ready, can never create a replacement archive.
    #[allow(clippy::too_many_arguments)]
    pub fn create_xmr_graph_custody_archive_v23(
        &self,
        permit: PreparedXmrGraphCustodyProvisioningV23,
        parent: cap_std::fs::Dir,
        directory: &str,
        graph: &dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11,
        key: dom_scriptless_crypto::XmrRecoverySealKeyV11,
        private_refund: Option<&dom_scriptless_crypto::PrivateXmrRefundTransactionV11>,
    ) -> Result<
        (
            XmrRecoveryCustodyV11,
            PreparedXmrGraphCustodyProvisioningV23,
        ),
        SessionStoreError,
    > {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let session = permit.scope.binding.session_id;
        let head = self.load_session_locked(session)?;
        if permit.store != self._store_id
            || permit.opening != self.open_instance_id
            || permit.state != XmrGraphCustodyProvisioningStateV23::Started
            || graph.binding() != &permit.scope.binding
            || graph.graph_digest() != &permit.scope.graph_digest
            || head.phase() != SessionPhaseV1::RefundSigning
            || head.irreversible().funding_authorized
            || head.irreversible().adaptor_secret_exposed
            || self.read_graph_custody_record_v23(session, false)?.as_ref() != Some(&permit.started)
            || self.read_graph_custody_record_v23(session, true)?.is_some()
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        self.audit_xmr_graph_custody_provisioning_v23(session)?;
        let custody = XmrRecoveryCustodyV11::create_atomically_v23(
            parent,
            directory,
            permit.scope,
            graph,
            key,
            private_refund,
        )
        .map_err(|_| SessionStoreError::Quarantined)?;
        Ok((custody, permit))
    }

    /// Authenticate an already Ready custody receipt without creating or
    /// repairing any journal or archive artifact, even when a record is absent.
    pub fn retained_xmr_graph_custody_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        custody_id: [u8; 32],
    ) -> Result<Option<(ProducedXmrRecoveryGraphV12, FinalClaimRoleBindingV1)>, SessionStoreError>
    {
        let _guard = self.operation_lock()?;
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        self.audit_transport()?;
        self.retained_xmr_graph_custody_locked_v23(chain, session, Some(custody_id))
    }

    /// Historical activation evidence only; the configured custody identifier
    /// must still be checked when opening the actual archive resources.
    pub fn retained_xmr_graph_ready_for_activation_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<Option<(ProducedXmrRecoveryGraphV12, FinalClaimRoleBindingV1)>, SessionStoreError>
    {
        let _guard = self.operation_lock()?;
        self.require_process_trusted_chain_v23(chain.as_bytes())?;
        self.audit_transport()?;
        self.retained_xmr_graph_custody_locked_v23(chain, session, None)
    }

    fn retained_xmr_graph_custody_locked_v23(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        expected_custody: Option<[u8; 32]>,
    ) -> Result<Option<(ProducedXmrRecoveryGraphV12, FinalClaimRoleBindingV1)>, SessionStoreError>
    {
        let started = self.read_graph_custody_record_v23(session, false)?;
        let ready = self.read_graph_custody_record_v23(session, true)?;
        let current = self.load_session_locked(session)?;
        let Some(started) = started else {
            if ready.is_some() || current.irreversible().funding_authorized {
                return Err(SessionStoreError::Quarantined);
            }
            return Ok(None);
        };
        self.audit_xmr_graph_custody_provisioning_v23(session)?;
        let custody_id = copy_array::<32>(&started[176..208])?;
        if started[16..48] != *chain.as_bytes()
            || expected_custody.is_some_and(|expected| expected != custody_id)
        {
            return Err(SessionStoreError::Conflict);
        }
        let Some(_) = ready else {
            if current.irreversible().funding_authorized {
                return Err(SessionStoreError::Quarantined);
            }
            return Ok(None);
        };
        let role =
            FinalClaimRoleBindingV1::decode_canonical(&chain, &started[FIXED..started.len() - 32])
                .map_err(|_| SessionStoreError::Quarantined)?;
        let produced = self.reconstruct_completed_xmr_graph_v23(session)?;
        self.require_xmr_graph_custody_ready_locked_v23(&role, &produced, custody_id)?;
        Ok(Some((produced, role)))
    }

    // Compare all retained graph transactions, binding, and signatures.
    pub(in super::super) fn require_same_xmr_graph_v25(
        &self,
        rebuilt: &ProducedXmrRecoveryGraphV12,
        retained: &ProducedXmrRecoveryGraphV12,
    ) -> Result<(), SessionStoreError> {
        require_same_graph(rebuilt, retained)
    }

    /// Strictly reauthenticate immutable Ready custody; never create a missing journal.
    pub fn require_xmr_graph_custody_ready_v23(
        &self,
        role: &FinalClaimRoleBindingV1,
        produced: &ProducedXmrRecoveryGraphV12,
        custody_id: [u8; 32],
    ) -> Result<XmrRecoveryCustodyScopeV11, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        self.require_xmr_graph_custody_ready_locked_v23(role, produced, custody_id)
    }

    // Caller holds operation_lock. This is historical and strictly read-only:
    // it authenticates immutable native rounds, not the live prefunding head.
    pub(in super::super) fn require_xmr_graph_custody_ready_locked_v23(
        &self,
        role: &FinalClaimRoleBindingV1,
        produced: &ProducedXmrRecoveryGraphV12,
        custody_id: [u8; 32],
    ) -> Result<XmrRecoveryCustodyScopeV11, SessionStoreError> {
        let (scope, rebuilt) = self.reconstruct_ready_xmr_graph_locked_v25(role, custody_id)?;
        require_same_graph(&rebuilt, produced)?;
        Ok(scope)
    }

    /// Caller holds operation_lock. Reconstruct from native journals and check
    /// both immutable custody markers in this operation. Returning this exact
    /// graph lets gate authentication use it without a second reconstruction;
    /// no caller-supplied graph or cached authority enters this path.
    pub(in super::super) fn reconstruct_ready_xmr_graph_locked_v25(
        &self,
        role: &FinalClaimRoleBindingV1,
        custody_id: [u8; 32],
    ) -> Result<(XmrRecoveryCustodyScopeV11, ProducedXmrRecoveryGraphV12), SessionStoreError> {
        let parent = role.session_id().0;
        let (scope, started, rebuilt) = self.graph_custody_record_v23(role, custody_id, false)?;
        if self.read_graph_custody_record_v23(parent, false)?.as_ref() != Some(&started)
            || self.read_graph_custody_record_v23(parent, true)?.as_ref()
                != Some(&change_state(&started, true))
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok((scope, rebuilt))
    }

    /// Authenticate all three completed native rounds before retaining Started.
    /// This cannot authorize funding or create/repair an archive directory.
    pub fn prepare_xmr_graph_custody_provisioning_v23(
        &self,
        role: &FinalClaimRoleBindingV1,
        produced: &ProducedXmrRecoveryGraphV12,
        custody_id: [u8; 32],
    ) -> Result<PreparedXmrGraphCustodyProvisioningV23, SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let parent = role.session_id().0;
        // This function writes the Started record: drop any audited copy so
        // the next transport audit re-authenticates the new bytes in full
        // instead of quarantining our own legitimate write as tampering.
        if let Ok(mut audited) = self.audited_custody_pairs_v26.lock() {
            audited.remove(&parent);
        }
        let current = self.load_session_locked(parent)?;
        if current.phase() != SessionPhaseV1::RefundSigning
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
            || self.funding_gate_exists(parent)?
            || self.m8_funding_gate_exists(parent)?
            || self.m8_funding_gate_v2_exists(parent)?
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let (scope, started, rebuilt) = self.graph_custody_record_v23(role, custody_id, false)?;
        require_same_graph(&rebuilt, produced)?;
        let ready = change_state(&started, true);
        let old_start = self.read_graph_custody_record_v23(parent, false)?;
        let old_ready = self.read_graph_custody_record_v23(parent, true)?;
        if old_start.as_ref().is_some_and(|old| old != &started)
            || old_ready.as_ref().is_some_and(|old| old != &ready)
            || (old_ready.is_some() && old_start.is_none())
        {
            return Err(SessionStoreError::Quarantined);
        }
        let state = if old_ready.is_some() {
            XmrGraphCustodyProvisioningStateV23::Ready
        } else {
            if old_start.is_none() {
                self.publish_graph_custody_record_v23(parent, false, &started)?;
            }
            XmrGraphCustodyProvisioningStateV23::Started
        };
        Ok(PreparedXmrGraphCustodyProvisioningV23 {
            store: self._store_id,
            opening: self.open_instance_id,
            scope,
            state,
            started,
        })
    }

    /// Consume only after the real encrypted archive has opened and revalidated.
    /// The caller must retain Ready before exporting the archive owner.
    pub fn mark_xmr_graph_custody_ready_v23(
        &self,
        permit: PreparedXmrGraphCustodyProvisioningV23,
        custody: &XmrRecoveryCustodyV11,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        self.audit_transport()?;
        let parent = permit.scope.binding.session_id;
        // This function writes the Ready record over an audited Started pair:
        // invalidate the audited copy for the same reason as in `prepare_...`.
        if let Ok(mut audited) = self.audited_custody_pairs_v26.lock() {
            audited.remove(&parent);
        }
        if permit.store != self._store_id
            || permit.opening != self.open_instance_id
            || custody.scope() != &permit.scope
        {
            return Err(SessionStoreError::Conflict);
        }
        let current = self.load_session_locked(parent)?;
        if current.phase() != SessionPhaseV1::RefundSigning
            || current.irreversible().funding_authorized
            || current.irreversible().adaptor_secret_exposed
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        custody
            .revalidate()
            .map_err(|_| SessionStoreError::Quarantined)?;
        let rebuilt = self.reconstruct_completed_xmr_graph_v23(parent)?;
        let exact = custody
            .with_graph(|graph| {
                graph.binding() == rebuilt.graph().binding()
                    && graph.graph_digest() == rebuilt.graph().graph_digest()
                    && graph.cancel_bytes() == rebuilt.graph().cancel_bytes()
                    && graph.punish_bytes() == rebuilt.graph().punish_bytes()
                    && graph.refund_pre_signature().to_bytes()
                        == rebuilt.graph().refund_pre_signature().to_bytes()
            })
            .map_err(|_| SessionStoreError::Quarantined)?;
        if !exact
            || self.read_graph_custody_record_v23(parent, false)?.as_ref() != Some(&permit.started)
        {
            return Err(SessionStoreError::Quarantined);
        }
        self.audit_xmr_graph_custody_provisioning_v23(parent)?;
        let ready = change_state(&permit.started, true);
        match self.read_graph_custody_record_v23(parent, true)? {
            Some(old) if old == ready => Ok(()),
            Some(_) => Err(SessionStoreError::Quarantined),
            None if permit.state == XmrGraphCustodyProvisioningStateV23::Ready => {
                Err(SessionStoreError::Quarantined)
            }
            None => self.publish_graph_custody_record_v23(parent, true, &ready),
        }
    }

    pub(in super::super) fn audit_xmr_graph_custody_provisioning_v23(
        &self,
        parent: [u8; 32],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), SessionStoreError> {
        let started = self
            .read_graph_custody_record_v23(parent, false)?
            .ok_or(SessionStoreError::Quarantined)?;
        let chain = self.require_process_trusted_chain_v23(&copy_array(&started[16..48])?)?;
        let role =
            FinalClaimRoleBindingV1::decode_canonical(&chain, &started[FIXED..started.len() - 32])
                .map_err(|_| SessionStoreError::Quarantined)?;
        let (_, expected, _) =
            self.graph_custody_record_v23(&role, copy_array(&started[176..208])?, false)?;
        if started != expected || role.session_id().0 != parent {
            return Err(SessionStoreError::Quarantined);
        }
        let ready = self.read_graph_custody_record_v23(parent, true)?;
        if let Some(ready) = ready.as_ref() {
            if ready != &change_state(&started, true) {
                return Err(SessionStoreError::Quarantined);
            }
        }
        Ok((started, ready))
    }

    // Same inventory scan only. Both markers were authenticated together;
    // reread their exact bytes before reusing that reconstruction for the
    // second filename. Nothing survives the enclosing transport audit.
    pub(in super::super) fn recheck_xmr_graph_custody_records_v26(
        &self,
        parent: [u8; 32],
        audited: &(Vec<u8>, Option<Vec<u8>>),
    ) -> Result<(), SessionStoreError> {
        if self.read_graph_custody_record_v23(parent, false)?.as_ref() != Some(&audited.0)
            || self.read_graph_custody_record_v23(parent, true)? != audited.1
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    // Return the graph authenticated for these exact record bytes as well.
    // Callers hold operation_lock and can compare that fresh result without
    // repeating the entire reconstruction. Nothing is cached across calls,
    // and no caller-provided graph replaces native transcript authentication.
    fn graph_custody_record_v23(
        &self,
        role: &FinalClaimRoleBindingV1,
        custody_id: [u8; 32],
        ready: bool,
    ) -> Result<
        (
            XmrRecoveryCustodyScopeV11,
            Vec<u8>,
            ProducedXmrRecoveryGraphV12,
        ),
        SessionStoreError,
    > {
        let parent = role.session_id().0;
        let produced = self.reconstruct_completed_xmr_graph_v23(parent)?;
        let graph = produced.graph();
        let context = self.load_xmr_graph_commit_context_v23(parent)?;
        let policy = produced.economic().policy();
        let validated = policy
            .policy()
            .validate_for(role.terms())
            .map_err(|_| SessionStoreError::Quarantined)?;
        let local = self.authenticate_local_transport_signer_binding(parent)?;
        let terms = role.terms();
        if custody_id == [0; 32]
            || role.route_id() != context.route
            || role.dom_chain_id().0 != context.chain
            || role
                .terms_hash()
                .map_err(|_| SessionStoreError::Quarantined)?
                != context.terms
            || graph.binding().funding_commitment != role.shared_output_commitment()
            || graph.binding().claim_adaptor_point != role.adaptor_point_sec1()
            || policy != &validated
            || policy.policy().bounded_availability_v23.is_none()
            || terms.dom_leg.refund_to == terms.counterparty_leg.refund_to
        {
            return Err(SessionStoreError::Quarantined);
        }
        let custody_role = if local.participant_id == terms.dom_leg.refund_to.0 {
            XmrRecoveryCustodyRoleV11::PrivateRefundOwner
        } else if local.participant_id == terms.counterparty_leg.refund_to.0 {
            XmrRecoveryCustodyRoleV11::PublicCounterparty
        } else {
            return Err(SessionStoreError::Quarantined);
        };
        for (template, hash) in [
            (graph.funding_template(), role.funding_template_hash()),
            (graph.claim_template(), role.claim_template_hash()),
            (graph.refund_template(), role.refund_template_hash()),
        ] {
            if canonical_template_v1(template)
                .map_err(|_| SessionStoreError::Quarantined)?
                .1
                != hash
            {
                return Err(SessionStoreError::Quarantined);
            }
        }
        let (cancel, comp) = produced.ordinary_sessions();
        let mut hashes = vec![
            context.chain,
            parent,
            context.route,
            context.terms,
            *graph.graph_digest(),
            custody_id,
            policy
                .policy()
                .policy_hash()
                .map_err(|_| SessionStoreError::Quarantined)?,
        ];
        for (session, edge) in [
            (cancel, XmrGraphRecoverySigningEdgeV23::Cancel),
            (parent, XmrGraphRecoverySigningEdgeV23::RefundAdaptor),
            (comp, XmrGraphRecoverySigningEdgeV23::Compensation),
        ] {
            hashes.push(
                self.authenticate_xmr_graph_signing_session_v23(session, edge)?
                    .digest,
            );
        }
        let scope = XmrRecoveryCustodyScopeV11 {
            binding: *graph.binding(),
            graph_digest: *graph.graph_digest(),
            custody_id,
            role: custody_role,
        };
        let canonical_role = role
            .canonical_bytes()
            .map_err(|_| SessionStoreError::Quarantined)?;
        if canonical_role.len() > MAX - FIXED - 32 {
            return Err(SessionStoreError::CapacityExceeded);
        }
        let mut bytes = MAGIC.to_vec();
        bytes.push(u8::from(ready));
        bytes.push(
            if custody_role == XmrRecoveryCustodyRoleV11::PrivateRefundOwner {
                1
            } else {
                2
            },
        );
        bytes.extend_from_slice(&[0; 6]);
        for hash in hashes {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&(canonical_role.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&canonical_role);
        bytes.extend_from_slice(&tagged_hash(DOMAIN, &bytes));
        Ok((scope, bytes, produced))
    }

    fn read_graph_custody_record_v23(
        &self,
        parent: [u8; 32],
        ready: bool,
    ) -> Result<Option<Vec<u8>>, SessionStoreError> {
        match self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name(parent, ready))?, MAX)
        {
            Ok(bytes) => {
                if bytes.len() < FIXED + 32
                    || &bytes[..8] != MAGIC
                    || bytes[8] != u8::from(ready)
                    || !matches!(bytes[9], 1 | 2)
                    || bytes[10..16] != [0; 6]
                    || bytes[48..80] != parent
                    || u32::from_le_bytes(copy_array(&bytes[336..340])?) as usize
                        != bytes.len() - FIXED - 32
                    || tagged_hash(DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
                {
                    return Err(SessionStoreError::Quarantined);
                }
                Ok(Some(bytes))
            }
            Err(LinuxCapabilityError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn publish_graph_custody_record_v23(
        &self,
        parent: [u8; 32],
        ready: bool,
        bytes: &[u8],
    ) -> Result<(), SessionStoreError> {
        let target = name(parent, ready);
        publish_immutable(
            &self.rosters,
            &format!(".{target}.staging"),
            &target,
            bytes,
            MAX,
        )?;
        if self
            .read_graph_custody_record_v23(parent, ready)?
            .as_deref()
            != Some(bytes)
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }
}
fn change_state(bytes: &[u8], ready: bool) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[8] = u8::from(ready);
    let end = out.len() - 32;
    let checksum = tagged_hash(DOMAIN, &out[..end]);
    out[end..].copy_from_slice(&checksum);
    out
}
fn require_same_graph(
    a: &ProducedXmrRecoveryGraphV12,
    b: &ProducedXmrRecoveryGraphV12,
) -> Result<(), SessionStoreError> {
    let (a, b) = (a.graph(), b.graph());
    if a.binding() != b.binding()
        || a.graph_digest() != b.graph_digest()
        || a.cancel_bytes() != b.cancel_bytes()
        || a.punish_bytes() != b.punish_bytes()
        || a.refund_pre_signature().to_bytes() != b.refund_pre_signature().to_bytes()
        || canonical_dom_transaction_bytes_v1(a.funding_template())?
            != canonical_dom_transaction_bytes_v1(b.funding_template())?
        || canonical_dom_transaction_bytes_v1(a.claim_template())?
            != canonical_dom_transaction_bytes_v1(b.claim_template())?
        || canonical_dom_transaction_bytes_v1(a.refund_template())?
            != canonical_dom_transaction_bytes_v1(b.refund_template())?
    {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}
