//! Native refund message permission, not a chain or signing authority.
//! The daemon obtains a fresh canonical U observation before calling this
//! producer, and both signer and importer independently repeat that check.
//! This marker binds only the public transport to the actual retained graph.
use super::*;
use xmr_remote_sweep_wire::{RemoteSweepActionV23, RemoteSweepRequestV23};

pub(super) const REFUND_TRANSPORT_LEN_V23: usize = 8 + 9 * 32;
// This new, unpublished transport artifact changed from a local-effect grant
// to shared economic scope. Retain the registered slot but reject all earlier
// prototype bytes explicitly; there is no implicit migration or reinterpretation.
const MAGIC: &[u8; 8] = b"DOMXRT24";
const SUFFIX: &str = "refund-transport-v23";
const DOMAIN: &str = "DOM-INTEROP/XMR-REFUND-TRANSPORT/V24\0";

fn public_refund_evidence(session: [u8; 32], graph: [u8; 32], refund: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&session);
    bytes.extend_from_slice(&graph);
    bytes.extend_from_slice(&refund);
    tagged_hash("DOM-INTEROP/XMR-REFUND-PUBLIC-EVENT/V23\0", &bytes)
}

struct Record {
    store: [u8; 32],
    session: [u8; 32],
    gate: [u8; 32],
    graph: [u8; 32],
    custody: [u8; 32],
    refund: [u8; 32],
    checkpoint: [u8; 32],
    request: [u8; 32],
}
impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        for value in [
            self.store,
            self.session,
            self.gate,
            self.graph,
            self.custody,
            self.refund,
            self.checkpoint,
            self.request,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&tagged_hash(DOMAIN, &bytes));
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() != REFUND_TRANSPORT_LEN_V23
            || &bytes[..8] != MAGIC
            || tagged_hash(DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
            || bytes[8..bytes.len() - 32]
                .chunks_exact(32)
                .any(|value| value == [0; 32])
        {
            return Err(SessionStoreError::Quarantined);
        }
        let field = |index: usize| copy_array(&bytes[8 + index * 32..8 + (index + 1) * 32]);
        Ok(Self {
            store: field(0)?,
            session: field(1)?,
            gate: field(2)?,
            graph: field(3)?,
            custody: field(4)?,
            refund: field(5)?,
            checkpoint: field(6)?,
            request: field(7)?,
        })
    }
}

fn stable_request_digest(request: &RemoteSweepRequestV23) -> Result<[u8; 32], SessionStoreError> {
    if request.action != RemoteSweepActionV23::Refund || request.funding_evidence_digest == [0; 32]
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    // Validate ORIGINAL local identifiers before projecting out only those
    // process-owned fields. The marker authorizes authenticated transport for
    // shared economics, not a peer's effect/lease or economic signing power.
    request.encode().map_err(|_| SessionStoreError::Canonical)?;
    let mut stable = request.clone();
    stable.funding_evidence_digest = [1; 32];
    stable.effect_id = [1; 32];
    stable.fencing_epoch = 1;
    stable.semantic_digest = [1; 32];
    Ok(tagged_hash(
        "DOM-INTEROP/XMR-REFUND-TRANSPORT-ECONOMICS/V24\0",
        &stable.encode().map_err(|_| SessionStoreError::Canonical)?,
    ))
}

// Private read-only boundary shared by the native Store consumer and its
// ordering regressions. `audit` is always the real ancestry/funding audit in
// production; success here grants public transport only, never chain finality.
fn require_refund_transport_record_v23(
    request: &RemoteSweepRequestV23,
    bytes: Result<Vec<u8>, SessionStoreError>,
    audit: impl FnOnce() -> Result<(), SessionStoreError>,
) -> Result<(), SessionStoreError> {
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(SessionStoreError::SessionNotFound) => {
            return Err(SessionStoreError::NativeXmrRefundTransportPendingV23)
        }
        Err(error) => return Err(error),
    };
    let record = Record::decode(&bytes)?;
    audit().map_err(|error| {
        if matches!(error, SessionStoreError::SessionNotFound) {
            SessionStoreError::Quarantined
        } else {
            error
        }
    })?;
    if record.request != stable_request_digest(request)?
        || public_refund_evidence(record.session, record.graph, record.refund)
            != request.public_secret_evidence_digest
    {
        return Err(SessionStoreError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn validate_refund_transport_bytes_v23(
    session: [u8; 32],
    bytes: &[u8],
) -> Result<(), SessionStoreError> {
    if Record::decode(bytes)?.session != session {
        return Err(SessionStoreError::Quarantined);
    }
    Ok(())
}

impl ContractsSessionStoreV1 {
    /// Stable public event identity, not the local scanner's time-sensitive
    /// finality digest. Peers may observe the same U at different tip heights.
    /// The caller still needs the fresh opaque observation for productive use.
    pub fn native_xmr_refund_transport_public_evidence_v23(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
        observed_refund_tx: [u8; 32],
    ) -> Result<[u8; 32], SessionStoreError> {
        let authority = self.authorize_xmr_recovery_execution_v12(handle, custody)?;
        let (refund, _) = custody
            .read_refund_exit_checkpoint_v23(&authority)
            .map_err(|_| SessionStoreError::Quarantined)?;
        if refund != observed_refund_tx {
            return Err(SessionStoreError::InvalidTransition);
        }
        Ok(public_refund_evidence(
            authority.session_id(),
            authority.graph_digest(),
            refund,
        ))
    }

    pub(in super::super) fn native_xmr_refund_transport_applies_v23(
        &self,
        session: [u8; 32],
    ) -> Result<bool, SessionStoreError> {
        let gate = match self.load_f7_gate_v12(session) {
            Ok(gate) => gate,
            Err(SessionStoreError::SessionNotFound) => {
                // A retained native marker never downgrades to the historical
                // phase guard if its gate ancestor disappears after opening.
                return match self.read_f7_v12(session, SUFFIX, REFUND_TRANSPORT_LEN_V23) {
                    Err(SessionStoreError::SessionNotFound) => Ok(false),
                    Ok(_) => Err(SessionStoreError::Quarantined),
                    Err(error) => Err(error),
                };
            }
            Err(error) => return Err(error),
        };
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        Ok(gate.profile == F7RecoveryProfileV23::XmrBounded
            && gate.family == F7ExternalFamilyV11::Monero)
    }

    /// Persist a permission to carry this exact PUBLIC refund request only.
    /// `custody` owns the audit checkpoint written by the native DOM observer;
    /// it does not manufacture finality. The caller must hold the separately
    /// verified recent DOM-U token before entering this transport boundary.
    pub fn retain_native_xmr_refund_transport_v23(
        &self,
        handle: &PreparedF7FundingGateV12,
        custody: &XmrRecoveryCustodyV11,
        request_bytes: &[u8],
        observed_refund_tx: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        // This producer takes the native authority before locking again; its
        // constructor owns the operation lock and must not be nested.
        let authority = self.authorize_xmr_recovery_execution_v12(handle, custody)?;
        let (refund, checkpoint) = custody
            .read_refund_exit_checkpoint_v23(&authority)
            .map_err(|_| SessionStoreError::Quarantined)?;
        let request = RemoteSweepRequestV23::decode_exact(request_bytes)
            .map_err(|_| SessionStoreError::Canonical)?;
        let _guard = self.operation_lock()?;
        let gate = self.authenticate_f7_gate_v12(handle)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
            || request.session_id != gate.session_id
            || request.terms_digest != gate.terms_hash
            || request.funding_tx_hash != gate.xmr_funding_tx_hash
            || request.public_secret_evidence_digest
                != public_refund_evidence(gate.session_id, gate.graph_digest, refund)
            || refund != observed_refund_tx
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        let record = Record {
            store: self._store_id,
            session: gate.session_id,
            gate: gate.digest,
            graph: gate.graph_digest,
            custody: gate.custody_id,
            refund,
            checkpoint,
            request: stable_request_digest(&request)?,
        };
        self.publish_f7_v12(
            gate.session_id,
            SUFFIX,
            &record.encode(),
            REFUND_TRANSPORT_LEN_V23,
        )?;
        self.audit_native_xmr_refund_transport_v23(gate.session_id)?;
        Ok(())
    }

    pub(in super::super) fn audit_native_xmr_refund_transport_v23(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let record =
            Record::decode(&self.read_f7_v12(session, SUFFIX, REFUND_TRANSPORT_LEN_V23)?)?;
        let gate = self.load_f7_gate_v12(session)?;
        self.authenticate_f7_gate_ancestry_v12(&gate)?;
        let _funding = self.load_f7_funding_v12(&gate)?;
        if gate.profile != F7RecoveryProfileV23::XmrBounded
            || gate.family != F7ExternalFamilyV11::Monero
            || record.store != self._store_id
            || record.session != session
            || record.gate != gate.digest
            || record.graph != gate.graph_digest
            || record.custody != gate.custody_id
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(())
    }

    pub(in super::super) fn require_native_xmr_refund_transport_v23(
        &self,
        request: &RemoteSweepRequestV23,
    ) -> Result<(), SessionStoreError> {
        // Classify only this exact missing marker, never absence of a gate,
        // committed funding ancestor, or other authenticated dependency.
        require_refund_transport_record_v23(
            request,
            self.read_f7_v12(request.session_id, SUFFIX, REFUND_TRANSPORT_LEN_V23),
            || self.audit_native_xmr_refund_transport_v23(request.session_id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refund_request() -> RemoteSweepRequestV23 {
        RemoteSweepRequestV23 {
            network_genesis: [1; 32],
            route_id: [2; 32],
            session_id: [3; 32],
            settlement_id: [4; 32],
            terms_digest: [5; 32],
            registry_digest: [6; 32],
            profile_digest: [7; 32],
            deployment_digest: [8; 32],
            route_scope_digest: [9; 32],
            composition_digest: [10; 32],
            role_plan_digest: [11; 32],
            source_scope_digest: [12; 32],
            effect_id: [13; 32],
            semantic_digest: [14; 32],
            public_secret_evidence_digest: public_refund_evidence([3; 32], [4; 32], [6; 32]),
            funding_tx_hash: [16; 32],
            funding_evidence_digest: [17; 32],
            funding_output_index: 1,
            funding_block_height: 2,
            funded_amount_piconero: 10_000,
            max_fee_piconero: 100,
            adapter_max_raw_transaction_bytes: 512 * 1024,
            max_raw_transaction_bytes: 128 * 1024,
            fencing_epoch: 3,
            action: RemoteSweepActionV23::Refund,
            leg: xmr_remote_sweep_wire::RemoteSweepLegV23::Downstream,
            public_spend_share: [18; 32],
            destination: "48productionMainnetDestination".into(),
        }
    }

    fn grant(request: &RemoteSweepRequestV23) -> Vec<u8> {
        Record {
            store: [1; 32],
            session: request.session_id,
            gate: [3; 32],
            graph: [4; 32],
            custody: [5; 32],
            refund: [6; 32],
            checkpoint: [7; 32],
            request: stable_request_digest(request).unwrap(),
        }
        .encode()
    }

    // These exercise the private Store read/audit boundary, not a substitute
    // for the native signed-inbox integration in dom-interopd. No test creates
    // a funding/finality capability from these deliberately synthetic records.
    #[test]
    fn first_refund_waits_before_grant_then_exact_payload_can_retry() {
        let request = refund_request();
        let original = request.encode().unwrap();
        assert!(matches!(
            require_refund_transport_record_v23(
                &request,
                Err(SessionStoreError::SessionNotFound),
                || panic!("missing grant must not invoke the ancestry audit"),
            ),
            Err(SessionStoreError::NativeXmrRefundTransportPendingV23)
        ));
        let bytes = grant(&request);
        let audits = std::cell::Cell::new(0);
        for _ in 0..3 {
            require_refund_transport_record_v23(&request, Ok(bytes.clone()), || {
                audits.set(audits.get() + 1);
                Ok(())
            })
            .unwrap();
            assert_eq!(request.encode().unwrap(), original);
        }
        assert_eq!(audits.get(), 3, "replay must reauthenticate every time");
    }

    #[test]
    fn tampered_grant_and_disappeared_ancestor_never_become_pending() {
        let request = refund_request();
        let bytes = grant(&request);
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(matches!(
                require_refund_transport_record_v23(&request, Ok(changed), || panic!(
                    "corrupt framing must fail before ancestry audit"
                )),
                Err(SessionStoreError::Quarantined)
            ));
        }
        for error in [
            SessionStoreError::SessionNotFound,
            SessionStoreError::Quarantined,
        ] {
            assert!(matches!(
                require_refund_transport_record_v23(&request, Ok(bytes.clone()), || Err(error)),
                Err(SessionStoreError::Quarantined)
            ));
        }
        assert!(matches!(
            require_refund_transport_record_v23(
                &request,
                Err(SessionStoreError::Quarantined),
                || panic!("read failed")
            ),
            Err(SessionStoreError::Quarantined)
        ));
        assert!(matches!(
            require_refund_transport_record_v23(&request, Ok(bytes), || Err(
                SessionStoreError::InvalidTransition
            )),
            Err(SessionStoreError::InvalidTransition)
        ));
    }

    #[test]
    fn grant_covers_shared_economics_but_not_a_local_signing_effect() {
        let request = refund_request();
        let bytes = grant(&request);
        let mut fresh = request.clone();
        fresh.funding_evidence_digest = [42; 32];
        fresh.effect_id = [43; 32];
        fresh.fencing_epoch = 41;
        fresh.semantic_digest = [44; 32];
        require_refund_transport_record_v23(&fresh, Ok(bytes.clone()), || Ok(())).unwrap();
        for field in 0..9 {
            let mut changed = request.clone();
            match field {
                0 => changed.funding_block_height += 1,
                1 => changed.funding_output_index += 1,
                2 => changed.destination.push('1'),
                3 => changed.max_fee_piconero += 1,
                4 => changed.funded_amount_piconero += 1,
                5 => changed.public_secret_evidence_digest[0] ^= 1,
                6 => changed.source_scope_digest[0] ^= 1,
                7 => changed.session_id[0] ^= 1,
                8 => changed.action = RemoteSweepActionV23::Claim,
                _ => unreachable!(),
            }
            assert!(
                require_refund_transport_record_v23(&changed, Ok(bytes.clone()), || Ok(()))
                    .is_err()
            );
        }
    }

    #[test]
    fn unpublished_old_local_effect_marker_is_not_reinterpreted() {
        let mut bytes = grant(&refund_request());
        bytes[..8].copy_from_slice(b"DOMXRT23");
        let end = bytes.len() - 32;
        let old = tagged_hash("DOM-INTEROP/XMR-REFUND-TRANSPORT/V23\0", &bytes[..end]);
        bytes[end..].copy_from_slice(&old);
        assert!(matches!(
            Record::decode(&bytes),
            Err(SessionStoreError::Quarantined)
        ));
    }

    #[test]
    fn transport_record_is_canonical_and_session_bound_not_chain_authority() {
        let record = Record {
            store: [1; 32],
            session: [2; 32],
            gate: [3; 32],
            graph: [4; 32],
            custody: [5; 32],
            refund: [6; 32],
            checkpoint: [7; 32],
            request: [8; 32],
        };
        let bytes = record.encode();
        assert_eq!(bytes.len(), REFUND_TRANSPORT_LEN_V23);
        assert_eq!(Record::decode(&bytes).unwrap().encode(), bytes);
        assert!(validate_refund_transport_bytes_v23([9; 32], &bytes).is_err());
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(Record::decode(&changed).is_err());
        }
        assert!(Record::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
